//! Signing in through the real identity provider.
//!
//! The CLI used to POST an email address to `/auth/dev/login` and get a token
//! back. That endpoint exists for a Compose demo and the control plane refuses
//! to serve it unless it is bound to loopback, so the client had no way to sign
//! in to an actual deployment at all.
//!
//! This is the native-app flow from RFC 8252. The client opens a browser at the
//! control plane, the control plane runs the OIDC handshake with the identity
//! provider, and the finished login comes back to a listener the client started
//! on loopback. Three things keep that last hop honest:
//!
//! * the listener binds `127.0.0.1` on a port the kernel picks, so nothing off
//!   the machine can reach it and nothing can squat the port in advance;
//! * what comes back is a one-time code, not a token, so nothing durable ends
//!   up in browser history;
//! * the code is only redeemable by presenting a verifier that never left this
//!   process, so a local process that watches the loopback request gains
//!   nothing from it.

use anyhow::{bail, Context, Result};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;
use wsl_crypto::Pkce;

/// The path the control plane is told to send the browser back to.
const CALLBACK_PATH: &str = "/callback";

/// How long to wait for someone to finish signing in. Long enough to find a
/// password and a second factor, short enough that an abandoned attempt does
/// not leave a listener open all day.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, serde::Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub user_id: Uuid,
    pub email: String,
}

/// Run the browser login and return the token it produced.
///
/// `open_browser` is false for environments where launching one is wrong or
/// impossible — a remote shell, a test. The URL is printed either way, so the
/// flow still works by pasting it into a browser elsewhere on the same machine.
pub async fn browser_login(
    http: &reqwest::Client,
    control_url: &str,
    open_browser: bool,
) -> Result<TokenResponse> {
    let pkce = Pkce::generate();

    // Port 0 asks the kernel for a free one. Binding before the browser opens
    // means the redirect can never arrive at a port nothing is listening on.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("binding a loopback listener for the login callback")?;
    let port = listener.local_addr()?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}{CALLBACK_PATH}");

    let authorize = authorize_url(control_url, &redirect_uri, pkce.challenge())?;
    println!("Opening your browser to sign in.");
    println!("If it does not open, visit:\n  {authorize}");
    if open_browser {
        launch_browser(&authorize);
    }

    let code = tokio::time::timeout(LOGIN_TIMEOUT, wait_for_code(&listener))
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "timed out after {} seconds waiting for the browser to come back",
                LOGIN_TIMEOUT.as_secs()
            )
        })??;

    redeem(http, control_url, &code, pkce.verifier()).await
}

pub fn authorize_url(control_url: &str, redirect_uri: &str, challenge: &str) -> Result<String> {
    let mut url = url::Url::parse(&format!(
        "{}/auth/oidc/authorize",
        control_url.trim_end_matches('/')
    ))
    .context("control_url is not a URL")?;
    url.query_pairs_mut()
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("client_challenge", challenge);
    Ok(url.into())
}

async fn redeem(
    http: &reqwest::Client,
    control_url: &str,
    code: &str,
    verifier: &str,
) -> Result<TokenResponse> {
    let response = http
        .post(format!(
            "{}/auth/oidc/exchange",
            control_url.trim_end_matches('/')
        ))
        .json(&serde_json::json!({ "code": code, "verifier": verifier }))
        .send()
        .await
        .context("redeeming the login code")?;
    if !response.status().is_success() {
        bail!(
            "the control plane refused the login code ({}). \
             The code is single-use and expires quickly — try signing in again.",
            response.status()
        );
    }
    response.json().await.context("decoding the token response")
}

/// Serve loopback requests until one carries the callback.
///
/// A browser will ask for things nobody promised it — `/favicon.ico` is the
/// usual one — so anything that is not the callback gets a 404 and the loop
/// keeps waiting rather than failing the login.
async fn wait_for_code(listener: &TcpListener) -> Result<String> {
    loop {
        let (mut socket, _) = listener.accept().await.context("accepting the callback")?;
        let Some(target) = read_request_target(&mut socket).await? else {
            continue;
        };
        match parse_callback(&target) {
            CallbackOutcome::NotTheCallback => {
                let _ = socket
                    .write_all(page(404, "Not found", "This is not the login callback.").as_bytes())
                    .await;
            }
            CallbackOutcome::Code(code) => {
                let _ = socket
                    .write_all(
                        page(
                            200,
                            "Signed in",
                            "You can close this tab and return to the terminal.",
                        )
                        .as_bytes(),
                    )
                    .await;
                let _ = socket.flush().await;
                return Ok(code);
            }
            CallbackOutcome::Error(message) => {
                let _ = socket
                    .write_all(page(400, "Sign-in failed", &message).as_bytes())
                    .await;
                let _ = socket.flush().await;
                bail!("the identity provider reported: {message}");
            }
        }
    }
}

/// Read the request target out of the first line, and no further.
///
/// Nothing in the body or the headers is wanted, and a request that never
/// sends a complete line must not be able to hold the login open: the read is
/// capped at a buffer no legitimate callback comes close to filling.
async fn read_request_target(socket: &mut tokio::net::TcpStream) -> Result<Option<String>> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    loop {
        let read = socket.read(&mut chunk).await?;
        if read == 0 {
            return Ok(None);
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(end) = buffer.windows(2).position(|w| w == b"\r\n") {
            let line = String::from_utf8_lossy(&buffer[..end]).into_owned();
            // "GET /callback?code=... HTTP/1.1"
            return Ok(line.split_whitespace().nth(1).map(|s| s.to_string()));
        }
        if buffer.len() > 8192 {
            return Ok(None);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum CallbackOutcome {
    Code(String),
    Error(String),
    NotTheCallback,
}

fn parse_callback(target: &str) -> CallbackOutcome {
    // The target is origin-form, so it needs a base before it will parse.
    let Ok(url) = url::Url::parse(&format!("http://127.0.0.1{target}")) else {
        return CallbackOutcome::NotTheCallback;
    };
    if url.path() != CALLBACK_PATH {
        return CallbackOutcome::NotTheCallback;
    }
    let mut code = None;
    let mut error = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.into_owned()),
            "error" => error = Some(value.into_owned()),
            _ => {}
        }
    }
    match (code, error) {
        (_, Some(error)) => CallbackOutcome::Error(error),
        (Some(code), None) => CallbackOutcome::Code(code),
        (None, None) => CallbackOutcome::Error("callback carried no code".into()),
    }
}

/// The page shown in the browser. It deliberately contains no code, no token
/// and no email: this document can end up in a screenshot or a shared session.
fn page(status: u16, title: &str, message: &str) -> String {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        _ => "Not Found",
    };
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title>\
         <style>body{{font:15px -apple-system,system-ui,sans-serif;margin:4rem auto;max-width:28rem;\
         color:#222}}h1{{font-size:1.2rem}}</style></head>\
         <body><h1>{title}</h1><p>{message}</p></body></html>"
    );
    format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
}

fn launch_browser(url: &str) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    // A failure here is not fatal: the URL was printed, and pasting it works.
    let _ = std::process::Command::new(opener)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_authorize_url_carries_the_challenge_not_the_verifier() {
        let pkce = Pkce::generate();
        let url = authorize_url(
            "https://vpn.example.com/",
            "http://127.0.0.1:49152/callback",
            pkce.challenge(),
        )
        .expect("url");
        assert!(url.starts_with("https://vpn.example.com/auth/oidc/authorize?"));
        assert!(url.contains("client_challenge="));
        assert!(
            !url.contains(pkce.verifier()),
            "the verifier must never leave the process"
        );
        let parsed = url::Url::parse(&url).expect("parse");
        let redirect = parsed
            .query_pairs()
            .find(|(k, _)| k == "redirect_uri")
            .map(|(_, v)| v.into_owned())
            .expect("redirect_uri");
        assert_eq!(redirect, "http://127.0.0.1:49152/callback");
    }

    #[test]
    fn a_trailing_slash_on_the_control_url_does_not_double_up() {
        let with = authorize_url("http://localhost:8080/", "http://127.0.0.1:1/callback", "c")
            .expect("url");
        let without = authorize_url("http://localhost:8080", "http://127.0.0.1:1/callback", "c")
            .expect("url");
        assert_eq!(with, without);
    }

    #[test]
    fn the_callback_yields_its_code() {
        assert_eq!(
            parse_callback("/callback?code=abc123"),
            CallbackOutcome::Code("abc123".into())
        );
    }

    #[test]
    fn a_provider_error_is_reported_rather_than_treated_as_a_code() {
        assert_eq!(
            parse_callback("/callback?error=access_denied&code=ignored"),
            CallbackOutcome::Error("access_denied".into())
        );
    }

    #[test]
    fn a_callback_without_a_code_is_an_error_not_a_hang() {
        assert!(matches!(
            parse_callback("/callback"),
            CallbackOutcome::Error(_)
        ));
    }

    /// A browser asking for a favicon must not end the login.
    #[test]
    fn other_paths_are_not_the_callback() {
        assert_eq!(
            parse_callback("/favicon.ico"),
            CallbackOutcome::NotTheCallback
        );
        assert_eq!(parse_callback("/"), CallbackOutcome::NotTheCallback);
    }

    #[test]
    fn a_percent_encoded_code_is_decoded_once() {
        assert_eq!(
            parse_callback("/callback?code=a%2Bb%2Fc"),
            CallbackOutcome::Code("a+b/c".into())
        );
    }

    #[test]
    fn the_browser_page_leaks_nothing() {
        let rendered = page(200, "Signed in", "You can close this tab.");
        assert!(rendered.contains("Content-Length:"));
        assert!(rendered.contains("no-store"));
        // The success page is rendered without ever being handed the code.
        assert!(!rendered.contains("code"));
    }
}
