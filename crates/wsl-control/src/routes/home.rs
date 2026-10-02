use crate::state::AppState;
use axum::{
    extract::State,
    http::header,
    response::{Html, IntoResponse},
};

const TEMPLATE: &str = include_str!("home.html");

/// No scripts, no remote resources, no framing: the page is a static
/// description with one inline stylesheet, and the policy says exactly that.
const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; \
                   form-action 'none'; frame-ancestors 'none'";

/// The landing page at `/`.
///
/// Someone who types the control plane's address into a browser deserves to
/// learn what it is and how to use it, not a bare 404. The page reports the
/// same readiness `/readyz` does, so it is also the quickest way for a person
/// to tell whether the service is up. It answers 200 either way: it is a page
/// for people, and the probes have their own endpoints.
pub async fn home(State(state): State<AppState>) -> impl IntoResponse {
    let ready = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.db)
        .await
        .is_ok();

    let (status, status_class, status_detail) = if ready {
        (
            "Operational",
            "ok",
            "The control plane is up and sign-in is available.",
        )
    } else {
        (
            "Degraded",
            "degraded",
            "The control plane is running but cannot reach its database; sign-in will fail until it recovers.",
        )
    };

    let body = render(&[
        ("name", &state.config.product.display_name),
        ("url", state.config.server.public_url.trim_end_matches('/')),
        ("status", status),
        ("status_class", status_class),
        ("status_detail", status_detail),
        ("version", env!("CARGO_PKG_VERSION")),
    ]);

    (
        [
            (header::CONTENT_SECURITY_POLICY, CSP),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "no-referrer"),
            // The status line is live; a cached copy would report yesterday's.
            (header::CACHE_CONTROL, "no-store"),
        ],
        Html(body),
    )
}

fn render(values: &[(&str, &str)]) -> String {
    values
        .iter()
        .fold(TEMPLATE.to_string(), |page, (key, value)| {
            page.replace(&format!("{{{{{key}}}}}"), &escape(value))
        })
}

/// The display name and public URL come from configuration, which an operator
/// writes but a browser should never interpret as markup.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_placeholder_is_filled() {
        let page = render(&[
            ("name", "n"),
            ("url", "u"),
            ("status", "s"),
            ("status_class", "c"),
            ("status_detail", "d"),
            ("version", "v"),
        ]);
        assert!(!page.contains("{{"), "unfilled placeholder in landing page");
    }

    #[test]
    fn configured_values_cannot_inject_markup() {
        let page = render(&[("name", "<script>alert(1)</script>")]);
        assert!(!page.contains("<script>"));
        assert!(page.contains("&lt;script&gt;"));
    }
}
