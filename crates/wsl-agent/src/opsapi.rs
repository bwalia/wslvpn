//! Signing in with an OpsAPI account.
//!
//! The password goes to OpsAPI and nowhere else. The control plane only ever
//! sees the OpsAPI session token that comes back, which it hands to OpsAPI to
//! ask whose it is (ADR-0004), and trades for a WSL token of its own.
//!
//! ```text
//! app ──email, password──▶ OpsAPI /auth/login ──▶ token, or "send the code"
//! app ──challenge, code──▶ OpsAPI /auth/2fa/verify ──▶ token
//! app ──token──▶ control plane /auth/opsapi/exchange ──▶ WSL access token
//! ```
//!
//! OpsAPI reads `/auth/login` as a form; a JSON body is silently ignored and
//! the request fails as if the fields were missing (ADR-0003), so both calls
//! here send forms.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::oidc::TokenResponse;
use crate::state::validate_control_url;

const TIMEOUT: Duration = Duration::from_secs(20);

/// What a control plane lets people sign in with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignInMethods {
    pub oidc: bool,
    pub opsapi: Option<OpsApiMethod>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsApiMethod {
    pub url: String,
    pub namespace: String,
}

/// Ask the control plane which sign-in methods it offers. A control plane from
/// before OpsAPI sign-in has no such endpoint, which means browser only.
pub async fn methods(http: &reqwest::Client, control_url: &str) -> Result<SignInMethods> {
    let base = control_url.trim_end_matches('/');
    let response = http
        .get(format!("{base}/auth/methods"))
        .timeout(TIMEOUT)
        .send()
        .await
        .with_context(|| format!("could not reach the control plane at {base}"))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(SignInMethods {
            oidc: true,
            opsapi: None,
        });
    }
    let response = response
        .error_for_status()
        .with_context(|| format!("{base} did not list its sign-in methods"))?;
    response
        .json()
        .await
        .with_context(|| format!("{base} answered, but not with sign-in methods"))
}

/// The OpsAPI address a control plane advertises, or why there is none.
pub async fn opsapi_url(http: &reqwest::Client, control_url: &str) -> Result<String> {
    let Some(method) = methods(http, control_url).await?.opsapi else {
        bail!("this control plane does not offer OpsAPI sign-in; use `wsl login` to sign in in the browser");
    };
    // A password is about to go there: the same rule as the control plane's own
    // address, https or this machine only.
    validate_control_url(&method.url)
        .context("the control plane advertised an unusable OpsAPI address")
}

/// Where a password sign-in got to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Step {
    /// Signed in to OpsAPI. Not serialised: the token goes straight on to the
    /// control plane and is never printed.
    #[serde(skip)]
    Token(String),
    /// OpsAPI emailed a sign-in code. `challenge` proves the password was
    /// right and goes back with the code.
    CodeRequired { challenge: String, email: String },
}

#[derive(Deserialize)]
struct LoginBody {
    #[serde(default)]
    requires_2fa: bool,
    #[serde(default)]
    session_token: Option<String>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

/// OpsAPI's errors come as `{error: {code, message}}` or `{error: "text"}`.
async fn refusal(response: reqwest::Response, what: &str) -> anyhow::Error {
    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap_or_default();
    let code = body["error"]["code"].as_str().unwrap_or_default();
    let message = body["error"]["message"]
        .as_str()
        .or_else(|| body["error"].as_str())
        .or_else(|| body["message"].as_str())
        .unwrap_or_default();
    match (status.as_u16(), code) {
        (_, "AUTH_INVALID_CREDENTIALS") => anyhow::anyhow!("Email or password is incorrect."),
        (429, _) | (423, _) => anyhow::anyhow!(
            "{}",
            if message.is_empty() {
                "Too many attempts. Wait a while and try again."
            } else {
                message
            }
        ),
        (403, _) if message.contains("deactivated") => {
            anyhow::anyhow!("This OpsAPI account has been deactivated.")
        }
        (401, _) if what == "verify" => {
            anyhow::anyhow!("That code was not accepted. Check it, or start again for a new one.")
        }
        _ if !message.is_empty() => anyhow::anyhow!("OpsAPI: {message}"),
        _ => anyhow::anyhow!("OpsAPI refused the sign-in (HTTP {status})"),
    }
}

/// Send email and password to OpsAPI.
pub async fn begin(
    http: &reqwest::Client,
    opsapi_url: &str,
    email: &str,
    password: &str,
) -> Result<Step> {
    let base = opsapi_url.trim_end_matches('/');
    let response = http
        .post(format!("{base}/auth/login"))
        .form(&[
            ("identifier", email.trim()),
            ("password", password),
            ("app_name", "WSL Zero Trust"),
        ])
        .timeout(TIMEOUT)
        .send()
        .await
        .with_context(|| format!("could not reach OpsAPI at {base}"))?;
    if !response.status().is_success() {
        return Err(refusal(response, "login").await);
    }
    let body: LoginBody = response
        .json()
        .await
        .context("OpsAPI's sign-in answer was not readable")?;
    match body {
        LoginBody {
            requires_2fa: true,
            session_token: Some(challenge),
            email: shown,
            ..
        } => Ok(Step::CodeRequired {
            challenge,
            email: shown.unwrap_or_else(|| email.trim().to_string()),
        }),
        LoginBody {
            token: Some(token), ..
        } => Ok(Step::Token(token)),
        _ => bail!("OpsAPI answered the sign-in with neither a token nor a code request"),
    }
}

/// Send the emailed code back with the challenge from [`begin`].
pub async fn verify_code(
    http: &reqwest::Client,
    opsapi_url: &str,
    challenge: &str,
    code: &str,
) -> Result<String> {
    let base = opsapi_url.trim_end_matches('/');
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    let response = http
        .post(format!("{base}/auth/2fa/verify"))
        .form(&[("session_token", challenge.trim()), ("code", code.as_str())])
        .timeout(TIMEOUT)
        .send()
        .await
        .with_context(|| format!("could not reach OpsAPI at {base}"))?;
    if !response.status().is_success() {
        return Err(refusal(response, "verify").await);
    }
    let body: LoginBody = response
        .json()
        .await
        .context("OpsAPI's answer was not readable")?;
    body.token
        .context("OpsAPI accepted the code but returned no token")
}

/// Trade an OpsAPI token for a WSL one.
pub async fn exchange(
    http: &reqwest::Client,
    control_url: &str,
    opsapi_token: &str,
) -> Result<TokenResponse> {
    let base = control_url.trim_end_matches('/');
    let response = http
        .post(format!("{base}/auth/opsapi/exchange"))
        .json(&serde_json::json!({ "token": opsapi_token }))
        .timeout(TIMEOUT)
        .send()
        .await
        .with_context(|| format!("could not reach the control plane at {base}"))?;
    match response.status().as_u16() {
        200..=299 => response
            .json()
            .await
            .context("the control plane's answer was not readable"),
        401 | 403 => bail!(
            "Signed in to OpsAPI, but this account is not allowed to use this VPN. \
             Ask your administrator to add you to the workspace and provision you."
        ),
        404 => bail!("this control plane does not offer OpsAPI sign-in"),
        503 => {
            bail!("the control plane could not check your account with OpsAPI; try again shortly")
        }
        other => bail!("the control plane refused the sign-in (HTTP {other})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Form;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use std::collections::HashMap;

    async fn serve(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        url
    }

    /// OpsAPI as `routes/auth.lua` behaves: forms only, an emailed code for
    /// alice, none for bob, and its error envelope for a wrong password.
    async fn opsapi() -> String {
        async fn login(
            Form(f): Form<HashMap<String, String>>,
        ) -> (axum::http::StatusCode, Json<serde_json::Value>) {
            match (
                f.get("identifier").map(String::as_str),
                f.get("password").map(String::as_str),
            ) {
                (Some("alice@example.com"), Some("right")) => (
                    axum::http::StatusCode::OK,
                    Json(
                        serde_json::json!({ "requires_2fa": true, "session_token": "challenge-1",
                        "email": "alice@example.com", "message": "Verification code sent to your email" }),
                    ),
                ),
                (Some("bob@example.com"), Some("right")) => (
                    axum::http::StatusCode::OK,
                    Json(
                        serde_json::json!({ "token": "bob-jwt", "refresh_token": "r", "user": {} }),
                    ),
                ),
                _ => (
                    axum::http::StatusCode::UNAUTHORIZED,
                    Json(
                        serde_json::json!({ "error": { "code": "AUTH_INVALID_CREDENTIALS",
                        "category": "auth", "message": "Invalid credentials" } }),
                    ),
                ),
            }
        }
        async fn verify(
            Form(f): Form<HashMap<String, String>>,
        ) -> (axum::http::StatusCode, Json<serde_json::Value>) {
            if f.get("session_token").map(String::as_str) == Some("challenge-1")
                && f.get("code").map(String::as_str) == Some("123456")
            {
                (
                    axum::http::StatusCode::OK,
                    Json(serde_json::json!({ "token": "alice-jwt" })),
                )
            } else {
                (
                    axum::http::StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "Invalid code" })),
                )
            }
        }
        serve(
            Router::new()
                .route("/auth/login", post(login))
                .route("/auth/2fa/verify", post(verify)),
        )
        .await
    }

    #[tokio::test]
    async fn a_password_sign_in_with_an_emailed_code() {
        let url = opsapi().await;
        let http = reqwest::Client::new();
        let step = begin(&http, &url, " alice@example.com ", "right")
            .await
            .unwrap();
        let Step::CodeRequired { challenge, email } = step else {
            panic!("expected a code request, got {step:?}");
        };
        assert_eq!(email, "alice@example.com");
        // People paste codes with spaces in them.
        let token = verify_code(&http, &url, &challenge, "123 456")
            .await
            .unwrap();
        assert_eq!(token, "alice-jwt");
    }

    #[tokio::test]
    async fn a_workspace_with_codes_turned_off_signs_in_at_once() {
        let url = opsapi().await;
        let step = begin(&reqwest::Client::new(), &url, "bob@example.com", "right")
            .await
            .unwrap();
        assert_eq!(step, Step::Token("bob-jwt".into()));
    }

    #[tokio::test]
    async fn a_wrong_password_and_a_wrong_code_say_which() {
        let url = opsapi().await;
        let http = reqwest::Client::new();
        let err = begin(&http, &url, "alice@example.com", "wrong")
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "Email or password is incorrect.");
        let err = verify_code(&http, &url, "challenge-1", "000000")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("code was not accepted"), "{err}");
    }

    /// The challenge is printed for the app to hold between two CLI calls; the
    /// token never is.
    #[test]
    fn only_the_code_request_is_ever_serialised() {
        let json = serde_json::to_value(Step::CodeRequired {
            challenge: "c".into(),
            email: "a@example.com".into(),
        })
        .unwrap();
        assert_eq!(json["status"], "code_required");
        assert_eq!(json["challenge"], "c");
    }

    #[tokio::test]
    async fn methods_are_read_and_an_older_control_plane_means_browser_only() {
        let with = serve(Router::new().route(
            "/auth/methods",
            get(|| async {
                Json(serde_json::json!({ "oidc": true,
                    "opsapi": { "url": "https://api.example.com", "namespace": "workstation" } }))
            }),
        ))
        .await;
        let http = reqwest::Client::new();
        let m = methods(&http, &with).await.unwrap();
        assert_eq!(m.opsapi.unwrap().namespace, "workstation");
        assert_eq!(
            opsapi_url(&http, &with).await.unwrap(),
            "https://api.example.com"
        );

        let older = serve(Router::new()).await;
        assert_eq!(methods(&http, &older).await.unwrap().opsapi, None);
        assert!(opsapi_url(&http, &older)
            .await
            .unwrap_err()
            .to_string()
            .contains("does not offer"));
    }

    /// A password must not be sent in the clear to some other machine because
    /// a control plane said so.
    #[tokio::test]
    async fn an_advertised_plain_http_opsapi_is_refused() {
        let cp = serve(Router::new().route(
            "/auth/methods",
            get(|| async {
                Json(serde_json::json!({ "oidc": true,
                    "opsapi": { "url": "http://api.example.com", "namespace": "w" } }))
            }),
        ))
        .await;
        assert!(opsapi_url(&reqwest::Client::new(), &cp).await.is_err());
    }

    #[tokio::test]
    async fn the_control_plane_refusing_is_explained() {
        let cp = serve(Router::new().route(
            "/auth/opsapi/exchange",
            post(|| async { (axum::http::StatusCode::UNAUTHORIZED, "") }),
        ))
        .await;
        let err = exchange(&reqwest::Client::new(), &cp, "t")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("not allowed to use this VPN"),
            "{err}"
        );
    }
}
