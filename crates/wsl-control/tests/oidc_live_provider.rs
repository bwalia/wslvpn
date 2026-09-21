//! Verification against a real identity provider.
//!
//! The unit tests in `auth::oidc_provider` mint their own tokens, which proves
//! the rules but not that they match what a provider actually sends. A real
//! provider decides its own claim spelling, key rotation and discovery layout,
//! and those are the things that turn a correct implementation into a broken
//! login.
//!
//! Ignored by default because it needs a provider running. With the dev stack up
//! (`make dev`), obtain a token and run:
//!
//! ```text
//! WSL_TEST_ID_TOKEN=<id_token> cargo test -p wsl-control --test oidc_live_provider -- --ignored
//! ```
//!
//! `WSL_TEST_OIDC_ISSUER` and `WSL_TEST_OIDC_AUDIENCE` override the Dex defaults.

use wsl_control::auth::oidc_provider::{peek_key_id, verify_id_token, ProviderKeys};

fn issuer() -> String {
    std::env::var("WSL_TEST_OIDC_ISSUER").unwrap_or_else(|_| "http://localhost:5556/dex".into())
}

fn audience() -> String {
    std::env::var("WSL_TEST_OIDC_AUDIENCE").unwrap_or_else(|_| "wsl-client".into())
}

#[tokio::test]
#[ignore = "needs a running identity provider"]
async fn discovery_reports_the_endpoints_the_provider_actually_serves() {
    let http = reqwest::Client::new();
    let keys = ProviderKeys::new();
    let issuer = issuer();

    let metadata = keys
        .metadata(&http, &issuer, None)
        .await
        .expect("discovery should succeed against a running provider");

    assert_eq!(
        metadata.issuer.trim_end_matches('/'),
        issuer.trim_end_matches('/')
    );
    assert!(!metadata.authorization_endpoint.is_empty());
    assert!(!metadata.token_endpoint.is_empty());
    assert!(!metadata.jwks_uri.is_empty());
}

/// Confirms the provider publishes a key set this code can parse, and that a
/// provider holding several keys at once — Dex keeps its rotation history — is
/// handled rather than assumed to hold exactly one.
#[tokio::test]
#[ignore = "needs a running identity provider"]
async fn the_provider_key_set_is_usable() {
    let http = reqwest::Client::new();
    let keys = ProviderKeys::new();
    let issuer = issuer();

    let metadata = keys
        .metadata(&http, &issuer, None)
        .await
        .expect("discovery");
    let jwks = keys
        .keys_for(&http, &issuer, &metadata.jwks_uri, None)
        .await
        .expect("jwks");

    assert!(!jwks.keys.is_empty(), "provider published no signing keys");
}

/// The end-to-end case: a token this deployment did not mint, verified against
/// keys fetched over the network.
#[tokio::test]
#[ignore = "needs a running identity provider and WSL_TEST_ID_TOKEN"]
async fn a_real_provider_token_verifies() {
    let Ok(token) = std::env::var("WSL_TEST_ID_TOKEN") else {
        panic!("set WSL_TEST_ID_TOKEN to an id_token from the provider");
    };

    let http = reqwest::Client::new();
    let keys = ProviderKeys::new();
    let issuer = issuer();

    let metadata = keys
        .metadata(&http, &issuer, None)
        .await
        .expect("discovery");
    let jwks = keys
        .keys_for(
            &http,
            &issuer,
            &metadata.jwks_uri,
            peek_key_id(&token).as_deref(),
        )
        .await
        .expect("jwks");

    // The nonce is not checked here: this token came from a handshake the test
    // did not start. Every other rule applies.
    let identity = verify_id_token(&token, &jwks, &issuer, &audience(), None, 60)
        .expect("a real provider token should verify");

    assert_eq!(
        identity.issuer.trim_end_matches('/'),
        issuer.trim_end_matches('/')
    );
    assert!(
        !identity.subject.is_empty(),
        "the provider must supply a stable subject"
    );
    // Asserted without printing the value. The address comes out of a real
    // token, and a failing assertion writes its message to the test output —
    // which is a transcript that gets pasted into issues and CI logs. There is no
    // reason for someone's address to travel that far.
    assert!(
        identity.email.contains('@'),
        "the provider must supply an email claim"
    );
}

/// The same token, judged against the wrong audience. Guards the check that made
/// a token minted for another application at the same provider unusable here.
#[tokio::test]
#[ignore = "needs a running identity provider and WSL_TEST_ID_TOKEN"]
async fn a_real_token_is_refused_for_another_audience() {
    let Ok(token) = std::env::var("WSL_TEST_ID_TOKEN") else {
        panic!("set WSL_TEST_ID_TOKEN to an id_token from the provider");
    };

    let http = reqwest::Client::new();
    let keys = ProviderKeys::new();
    let issuer = issuer();

    let metadata = keys
        .metadata(&http, &issuer, None)
        .await
        .expect("discovery");
    let jwks = keys
        .keys_for(
            &http,
            &issuer,
            &metadata.jwks_uri,
            peek_key_id(&token).as_deref(),
        )
        .await
        .expect("jwks");

    assert!(
        verify_id_token(&token, &jwks, &issuer, "some-other-application", None, 60).is_err(),
        "a token minted for this deployment must not verify for another audience"
    );
}
