use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How many requests one client may make in a window.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub requests: u32,
    pub window_secs: u64,
}

fn default_enabled() -> bool {
    true
}

impl RateLimitConfig {
    pub fn window(&self) -> Duration {
        Duration::from_secs(self.window_secs.max(1))
    }
}

/// What the limiter decided about one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allowed { remaining: u32 },
    Limited { retry_after: Duration },
}

#[derive(Debug, Clone, Copy)]
struct Window {
    started: Instant,
    count: u32,
}

/// Fixed-window per-client request counter.
///
/// Fixed windows admit up to 2x the configured rate across a window boundary.
/// That is an accepted trade here: the goal is to make online guessing of a
/// bearer token or an OIDC state parameter impractical, not to smooth traffic,
/// and a burst of twice the budget does not change that.
///
/// State lives in this process, so a horizontally scaled control plane enforces
/// the budget per replica. Deployments that need a global budget should put a
/// shared limiter at the ingress; this one is the floor, not the ceiling.
pub struct RateLimiter {
    config: RateLimitConfig,
    windows: Mutex<HashMap<IpAddr, Window>>,
}

/// Above this many tracked clients, expired entries are swept before inserting.
/// Bounds memory under a spray of unique source addresses.
const SWEEP_THRESHOLD: usize = 10_000;

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            windows: Mutex::new(HashMap::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled && self.config.requests > 0
    }

    /// `now` is a parameter so the window arithmetic can be tested without
    /// sleeping through real time.
    pub fn check_at(&self, key: IpAddr, now: Instant) -> Decision {
        if !self.enabled() {
            return Decision::Allowed {
                remaining: self.config.requests,
            };
        }
        let window = self.config.window();
        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());

        if windows.len() > SWEEP_THRESHOLD {
            windows.retain(|_, w| now.duration_since(w.started) < window);
        }

        let entry = windows.entry(key).or_insert(Window {
            started: now,
            count: 0,
        });
        let elapsed = now.duration_since(entry.started);
        if elapsed >= window {
            entry.started = now;
            entry.count = 0;
        }

        if entry.count >= self.config.requests {
            return Decision::Limited {
                retry_after: window.saturating_sub(now.duration_since(entry.started)),
            };
        }
        entry.count += 1;
        Decision::Allowed {
            remaining: self.config.requests - entry.count,
        }
    }

    pub fn check(&self, key: IpAddr) -> Decision {
        self.check_at(key, Instant::now())
    }
}

/// The address a request is attributed to.
///
/// Only the peer address is trusted. `X-Forwarded-For` is attacker-controlled
/// unless a proxy is known to overwrite it, and honouring it by default would
/// let a single client spread its attempts across unlimited synthetic keys —
/// which is exactly what the limiter exists to prevent. A deployment behind a
/// proxy should enforce its budget at that proxy.
fn client_addr(request: &Request<Body>) -> IpAddr {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

/// Reject a request that is over budget, otherwise pass it on.
///
/// Wired with `from_fn_with_state(limiter, rate_limit)` so each router can carry
/// its own budget.
pub async fn rate_limit(
    axum::extract::State(limiter): axum::extract::State<Arc<RateLimiter>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let key = client_addr(&request);
    match limiter.check(key) {
        Decision::Allowed { .. } => next.run(request).await,
        Decision::Limited { retry_after } => {
            metrics::counter!("wsl_rate_limited_total").increment(1);
            tracing::warn!(client = %key, path = %request.uri().path(), "rate limited");
            (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", retry_after.as_secs().max(1).to_string())],
                axum::Json(serde_json::json!({
                    "error": "rate_limited",
                    "message": "too many requests"
                })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(requests: u32, window_secs: u64) -> RateLimitConfig {
        RateLimitConfig {
            enabled: true,
            requests,
            window_secs,
        }
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn allows_up_to_the_budget_then_limits() {
        let limiter = RateLimiter::new(cfg(3, 60));
        let now = Instant::now();
        assert_eq!(
            limiter.check_at(ip(1), now),
            Decision::Allowed { remaining: 2 }
        );
        assert_eq!(
            limiter.check_at(ip(1), now),
            Decision::Allowed { remaining: 1 }
        );
        assert_eq!(
            limiter.check_at(ip(1), now),
            Decision::Allowed { remaining: 0 }
        );
        assert!(matches!(
            limiter.check_at(ip(1), now),
            Decision::Limited { .. }
        ));
    }

    #[test]
    fn budgets_are_per_client() {
        let limiter = RateLimiter::new(cfg(1, 60));
        let now = Instant::now();
        assert!(matches!(
            limiter.check_at(ip(1), now),
            Decision::Allowed { .. }
        ));
        assert!(matches!(
            limiter.check_at(ip(1), now),
            Decision::Limited { .. }
        ));
        // A different client is unaffected by the first one's exhaustion.
        assert!(matches!(
            limiter.check_at(ip(2), now),
            Decision::Allowed { .. }
        ));
    }

    #[test]
    fn budget_refills_after_the_window() {
        let limiter = RateLimiter::new(cfg(1, 60));
        let now = Instant::now();
        assert!(matches!(
            limiter.check_at(ip(1), now),
            Decision::Allowed { .. }
        ));
        assert!(matches!(
            limiter.check_at(ip(1), now + Duration::from_secs(59)),
            Decision::Limited { .. }
        ));
        assert!(matches!(
            limiter.check_at(ip(1), now + Duration::from_secs(60)),
            Decision::Allowed { .. }
        ));
    }

    #[test]
    fn retry_after_counts_down_within_the_window() {
        let limiter = RateLimiter::new(cfg(1, 60));
        let now = Instant::now();
        limiter.check_at(ip(1), now);
        let Decision::Limited { retry_after } =
            limiter.check_at(ip(1), now + Duration::from_secs(20))
        else {
            panic!("expected the second request to be limited");
        };
        assert_eq!(retry_after, Duration::from_secs(40));
    }

    #[test]
    fn disabled_limiter_always_allows() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enabled: false,
            requests: 1,
            window_secs: 60,
        });
        let now = Instant::now();
        for _ in 0..100 {
            assert!(matches!(
                limiter.check_at(ip(1), now),
                Decision::Allowed { .. }
            ));
        }
    }

    #[test]
    fn zero_budget_is_treated_as_disabled_not_as_a_total_block() {
        // A misconfigured `requests: 0` must not lock every client out of the
        // control plane; it reads as "no limit configured".
        let limiter = RateLimiter::new(cfg(0, 60));
        assert!(!limiter.enabled());
        assert!(matches!(
            limiter.check_at(ip(1), Instant::now()),
            Decision::Allowed { .. }
        ));
    }
}
