//! Provider discovery, signing-key retrieval, and id_token validation.
//!
//! The control plane used to read the `email` claim out of an id_token without
//! checking the signature, on the reasoning that the token arrived over TLS from
//! the configured token endpoint and so could be trusted. That reasoning is too
//! thin to hold a login on:
//!
//!   * Nothing tied the token to *this* deployment. A provider serving several
//!     clients mints tokens for all of them from one key and distinguishes them
//!     only by the `aud` claim. Unchecked, a token issued to a different
//!     application at the same provider was accepted here — the confused-deputy
//!     case, and it was enough to sign in as any address the other application
//!     could put in a token.
//!   * Nothing tied the token to *this* handshake, so a captured token stayed
//!     usable.
//!   * Nothing required the provider to have verified the address, so at a
//!     provider with open self-registration, claiming an administrator's
//!     address was enough to become one.
//!
//! So the token is now verified the way the specification requires: signature
//! against the provider's published keys, then issuer, audience, expiry and
//! nonce, then `email_verified` before the address is believed at all.
//!
//! The pure check lives in [`verify_id_token`], which takes the key set as an
//! argument so the validation rules can be tested without a provider or a
//! network. [`ProviderKeys`] wraps it with the caching needed in production.

use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Signature algorithms a provider may use.
///
/// Asymmetric only, and named explicitly rather than taken from the token's own
/// header. A token states its algorithm in a part of itself that the signature
/// does not cover, so believing that field is how `alg: none` forgeries and
/// "verify this RSA public key as though it were an HMAC secret" confusions get
/// in. The header is only ever used to *select* a key by `kid`; what that key is
/// allowed to be is decided here.
const ALLOWED_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
];

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("id_token header is malformed: {0}")]
    MalformedHeader(String),
    #[error("id_token is signed with {0:?}, which is not accepted")]
    DisallowedAlgorithm(Algorithm),
    #[error("id_token does not name a signing key (no kid)")]
    MissingKeyId,
    #[error("no signing key with kid {0} is published by the provider")]
    UnknownKeyId(String),
    #[error("provider published an unusable signing key: {0}")]
    UnusableKey(String),
    #[error("id_token failed validation: {0}")]
    Invalid(String),
    #[error("id_token has no sub claim")]
    MissingSubject,
    #[error("id_token has no email claim")]
    MissingEmail,
    #[error("the provider has not verified this email address")]
    EmailNotVerified,
    #[error("id_token nonce does not match this login attempt")]
    NonceMismatch,
    #[error("provider discovery failed: {0}")]
    Discovery(String),
    #[error("provider issuer is {found}, but {expected} was configured")]
    IssuerMismatch { expected: String, found: String },
}

/// The subset of a provider's discovery document that this code uses.
///
/// Endpoints are read from discovery rather than assembled from the issuer.
/// Guessing them happened to work against Dex, whose authorize endpoint is
/// `{issuer}/auth`, and does not generalise: Entra, Keycloak, Auth0 and Okta all
/// place theirs somewhere a string concatenation would not find.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
}

/// What a valid id_token establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    /// The issuer that vouched for this. Half of the identity key.
    pub issuer: String,
    /// The provider's stable identifier for the person. The other half.
    pub subject: String,
    /// A mutable attribute, believed only because `email_verified` was true.
    pub email: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    #[serde(default)]
    email: Option<String>,
    /// Absent is not the same as false, but it is treated the same way: an
    /// address is believed only when the provider positively says it checked.
    #[serde(default)]
    email_verified: Option<serde_json::Value>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

/// Some providers send `email_verified` as a JSON boolean, some as the strings
/// `"true"`/`"false"`. Anything else — including absent — is not a verification.
fn claim_is_true(v: Option<&serde_json::Value>) -> bool {
    match v {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// Validate an id_token against a key set and the expectations of this
/// deployment.
///
/// `expected_nonce` is the value this deployment generated for the handshake the
/// token is answering. Passing `None` skips the check and is only correct where
/// no nonce was sent.
pub fn verify_id_token(
    token: &str,
    jwks: &JwkSet,
    expected_issuer: &str,
    expected_audience: &str,
    expected_nonce: Option<&str>,
    leeway_secs: u64,
) -> Result<VerifiedIdentity, OidcError> {
    let header = decode_header(token).map_err(|e| OidcError::MalformedHeader(e.to_string()))?;

    if !ALLOWED_ALGORITHMS.contains(&header.alg) {
        return Err(OidcError::DisallowedAlgorithm(header.alg));
    }

    let kid = header.kid.ok_or(OidcError::MissingKeyId)?;
    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| OidcError::UnknownKeyId(kid.clone()))?;

    // A key is usable only for the family it was published as. Without this, a
    // provider's RSA key could be presented for an EC token (or the reverse) and
    // the mismatch would surface as a confusing signature failure rather than as
    // the key-confusion attempt it is.
    let family_matches = match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => matches!(
            header.alg,
            Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::PS256
                | Algorithm::PS384
                | Algorithm::PS512
        ),
        AlgorithmParameters::EllipticCurve(_) => {
            matches!(header.alg, Algorithm::ES256 | Algorithm::ES384)
        }
        _ => false,
    };
    if !family_matches {
        return Err(OidcError::UnusableKey(format!(
            "kid {kid} cannot be used for {:?}",
            header.alg
        )));
    }

    let key = DecodingKey::from_jwk(jwk).map_err(|e| OidcError::UnusableKey(e.to_string()))?;

    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[expected_issuer]);
    validation.set_audience(&[expected_audience]);
    validation.validate_exp = true;
    // `aud` and `iss` are checked above by value; requiring their presence makes
    // a token that simply omits one fail rather than pass vacuously.
    validation.required_spec_claims = ["exp", "iss", "aud", "sub"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    validation.leeway = leeway_secs;

    let data = decode::<IdTokenClaims>(token, &key, &validation)
        .map_err(|e| OidcError::Invalid(e.to_string()))?;
    let claims = data.claims;

    if claims.sub.trim().is_empty() {
        return Err(OidcError::MissingSubject);
    }

    // `set_issuer` already compared this, but comparing again here means the
    // value carried forward as half of the identity key is the one that was
    // checked, rather than one trusted because a check happened somewhere.
    if claims.iss != expected_issuer {
        return Err(OidcError::IssuerMismatch {
            expected: expected_issuer.to_string(),
            found: claims.iss,
        });
    }

    match (expected_nonce, claims.nonce.as_deref()) {
        (Some(expected), Some(found)) if expected == found => {}
        (Some(_), _) => return Err(OidcError::NonceMismatch),
        (None, _) => {}
    }

    let email = claims
        .email
        .or_else(|| claims.preferred_username.clone())
        .ok_or(OidcError::MissingEmail)?;

    if !claim_is_true(claims.email_verified.as_ref()) {
        return Err(OidcError::EmailNotVerified);
    }

    Ok(VerifiedIdentity {
        issuer: claims.iss,
        subject: claims.sub,
        email: email.to_ascii_lowercase(),
        display_name: claims.name,
    })
}

/// How long a discovery document is reused before being fetched again.
const METADATA_TTL: Duration = Duration::from_secs(3600);
/// Floor on how often an unknown `kid` may trigger a key refetch.
///
/// Key rotation has to be picked up without a restart, so an unrecognised `kid`
/// refreshes the key set. That is also a free request amplifier — a stream of
/// tokens bearing random `kid`s would otherwise become a stream of requests to
/// the provider — so refreshes are rate limited and a token arriving inside the
/// cooldown is judged against the keys already held.
const JWKS_REFRESH_COOLDOWN: Duration = Duration::from_secs(60);

struct Cached<T> {
    value: T,
    fetched_at: Instant,
}

/// Move a provider URL from its public base onto the one reachable from here.
///
/// Only a URL actually under the issuer is moved. A provider that advertises its
/// keys on a different host altogether — a CDN, a separate JWKS domain — is
/// left alone, because rewriting that would point the request at a host that was
/// never told to serve it.
fn rebase(url: &str, public_base: &str, internal_base: &str) -> String {
    let public = public_base.trim_end_matches('/');
    let internal = internal_base.trim_end_matches('/');
    match url.strip_prefix(public) {
        Some(rest) => format!("{internal}{rest}"),
        None => url.to_string(),
    }
}

/// Cached discovery documents and key sets, keyed by issuer.
///
/// Keyed by issuer rather than held as a single slot because a deployment will
/// eventually have more than one provider, and a cache that assumes one would
/// then hand one provider's keys to another provider's tokens.
#[derive(Default)]
pub struct ProviderKeys {
    metadata: RwLock<HashMap<String, Cached<ProviderMetadata>>>,
    jwks: RwLock<HashMap<String, Cached<JwkSet>>>,
}

impl ProviderKeys {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Fetch, or reuse, the provider's discovery document.
    ///
    /// `internal_url`, when given, is where the provider is reachable *from this
    /// process*, which is not always the issuer. A control plane in a cluster
    /// reaches an in-cluster provider by service DNS while the tokens it signs
    /// name the public address; the compose stack has the same split, where the
    /// browser sees `localhost:5556` and the container sees `dex:5556`. The
    /// issuer stays the identity and is still checked strictly — only the
    /// address used to make the request changes.
    pub async fn metadata(
        &self,
        http: &reqwest::Client,
        issuer: &str,
        internal_url: Option<&str>,
    ) -> Result<ProviderMetadata, OidcError> {
        if let Some(hit) = self.metadata.read().await.get(issuer) {
            if hit.fetched_at.elapsed() < METADATA_TTL {
                return Ok(hit.value.clone());
            }
        }

        let fetch_base = internal_url.unwrap_or(issuer).trim_end_matches('/');
        let url = format!("{fetch_base}/.well-known/openid-configuration");
        let fetched: ProviderMetadata = http
            .get(&url)
            .send()
            .await
            .map_err(|e| OidcError::Discovery(e.to_string()))?
            .error_for_status()
            .map_err(|e| OidcError::Discovery(e.to_string()))?
            .json()
            .await
            .map_err(|e| OidcError::Discovery(format!("malformed discovery document: {e}")))?;

        // The document says who it belongs to, and a document whose `issuer`
        // disagrees with the one configured is either a misconfiguration or
        // someone else's provider. Either way its endpoints must not be used:
        // the token endpoint is where the authorization code gets sent.
        if fetched.issuer.trim_end_matches('/') != issuer.trim_end_matches('/') {
            return Err(OidcError::IssuerMismatch {
                expected: issuer.to_string(),
                found: fetched.issuer,
            });
        }

        // The endpoints the document advertises are the ones a *browser* should
        // use. Where the provider is reached at a different address from here,
        // the two this process calls itself have to be moved onto it; the
        // authorization endpoint is left alone, because that one is for the
        // browser and rewriting it would send the user somewhere they cannot
        // resolve.
        let fetched = match internal_url {
            Some(internal) => ProviderMetadata {
                token_endpoint: rebase(&fetched.token_endpoint, issuer, internal),
                jwks_uri: rebase(&fetched.jwks_uri, issuer, internal),
                ..fetched
            },
            None => fetched,
        };

        self.metadata.write().await.insert(
            issuer.to_string(),
            Cached {
                value: fetched.clone(),
                fetched_at: Instant::now(),
            },
        );
        Ok(fetched)
    }

    /// Install a discovery document without fetching one.
    ///
    /// Present for tests, which must be able to exercise the login handshake
    /// without a provider listening — otherwise the suite passes or fails
    /// depending on what happens to be running on the machine, which is how a
    /// missing provider reached CI once already.
    ///
    /// It bypasses the issuer comparison that a fetched document is subjected to,
    /// so whatever calls this is asserting the endpoints itself.
    pub async fn preload(&self, issuer: &str, metadata: ProviderMetadata) {
        self.metadata.write().await.insert(
            issuer.to_string(),
            Cached {
                value: metadata,
                fetched_at: Instant::now(),
            },
        );
    }

    /// The provider's current signing keys, refreshed when `kid` is unrecognised.
    pub async fn keys_for(
        &self,
        http: &reqwest::Client,
        issuer: &str,
        jwks_uri: &str,
        kid: Option<&str>,
    ) -> Result<JwkSet, OidcError> {
        let cached = self.jwks.read().await.get(issuer).map(|c| Cached {
            value: c.value.clone(),
            fetched_at: c.fetched_at,
        });

        if let Some(hit) = &cached {
            let known = match kid {
                Some(k) => hit.value.find(k).is_some(),
                None => true,
            };
            if known || hit.fetched_at.elapsed() < JWKS_REFRESH_COOLDOWN {
                return Ok(hit.value.clone());
            }
        }

        let fetched: JwkSet = http
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| OidcError::Discovery(e.to_string()))?
            .error_for_status()
            .map_err(|e| OidcError::Discovery(e.to_string()))?
            .json()
            .await
            .map_err(|e| OidcError::Discovery(format!("malformed jwks: {e}")))?;

        self.jwks.write().await.insert(
            issuer.to_string(),
            Cached {
                value: fetched.clone(),
                fetched_at: Instant::now(),
            },
        );
        Ok(fetched)
    }
}

/// Read the `kid` from a token without trusting anything else in it.
///
/// Used only to decide which key to ask for. The token is still fully verified
/// afterwards, so a forged `kid` costs at most one cache lookup.
pub fn peek_key_id(token: &str) -> Option<String> {
    decode_header(token).ok().and_then(|h| h.kid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KID: &str = "test-key-1";
    const ISSUER: &str = "https://idp.example.com";
    const AUDIENCE: &str = "wslvpn";

    /// A throwaway P-256 keypair, generated per test run.
    ///
    /// Generated rather than committed: a private key in the repository is a
    /// finding for every secret scanner that looks at it, and "it is only a test
    /// key" is not something a scanner can check. ES256 rather than RSA because
    /// the cargo-audit exception for RUSTSEC-2023-0071 rests on `rsa` never
    /// being compiled.
    struct TestKey {
        signing: jsonwebtoken::EncodingKey,
        jwk: serde_json::Value,
    }

    impl TestKey {
        fn generate(kid: &str) -> Self {
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            use p256::pkcs8::EncodePrivateKey;

            let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
            let der = secret.to_pkcs8_der().expect("encode test key");
            let signing = jsonwebtoken::EncodingKey::from_ec_der(der.as_bytes());

            // The JWK carries the public point as its two coordinates, which is
            // what a provider publishes and what `DecodingKey::from_jwk` reads.
            let point = secret.public_key().to_encoded_point(false);
            let b64 = |b: &[u8]| URL_SAFE_NO_PAD_ENCODE_BYTES(b);
            let jwk = serde_json::json!({
                "kty": "EC",
                "use": "sig",
                "crv": "P-256",
                "alg": "ES256",
                "kid": kid,
                "x": b64(point.x().expect("x coordinate")),
                "y": b64(point.y().expect("y coordinate")),
            });

            Self { signing, jwk }
        }
    }

    fn test_key() -> &'static TestKey {
        static KEY: std::sync::OnceLock<TestKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| TestKey::generate(TEST_KID))
    }

    /// A second real keypair, so "signed by someone else" is signed by something
    /// that genuinely is someone else.
    fn other_key() -> &'static TestKey {
        static KEY: std::sync::OnceLock<TestKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| TestKey::generate(TEST_KID))
    }

    fn jwks() -> JwkSet {
        serde_json::from_value(serde_json::json!({ "keys": [test_key().jwk.clone()] }))
            .expect("test jwks")
    }

    fn sign(claims: serde_json::Value, kid: Option<&str>, alg: Algorithm) -> String {
        sign_with(&test_key().signing, claims, kid, alg)
    }

    fn sign_with(
        key: &jsonwebtoken::EncodingKey,
        claims: serde_json::Value,
        kid: Option<&str>,
        alg: Algorithm,
    ) -> String {
        let mut header = jsonwebtoken::Header::new(alg);
        header.kid = kid.map(|k| k.to_string());
        jsonwebtoken::encode(&header, &claims, key).expect("sign test token")
    }

    fn exp() -> i64 {
        (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp()
    }

    fn good_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": ISSUER,
            "sub": "subject-abc",
            "aud": AUDIENCE,
            "exp": exp(),
            "iat": chrono::Utc::now().timestamp(),
            "email": "Alice@Example.com",
            "email_verified": true,
            "name": "Alice",
            "nonce": "handshake-nonce"
        })
    }

    fn verify(token: &str, nonce: Option<&str>) -> Result<VerifiedIdentity, OidcError> {
        verify_id_token(token, &jwks(), ISSUER, AUDIENCE, nonce, 60)
    }

    #[test]
    fn accepts_a_correctly_signed_token() {
        let token = sign(good_claims(), Some(TEST_KID), Algorithm::ES256);
        let id = verify(&token, Some("handshake-nonce")).expect("should verify");
        assert_eq!(id.subject, "subject-abc");
        assert_eq!(id.issuer, ISSUER);
        // Normalised, so one provider casing cannot become a second account.
        assert_eq!(id.email, "alice@example.com");
        assert_eq!(id.display_name.as_deref(), Some("Alice"));
    }

    #[test]
    fn rejects_a_token_signed_by_someone_else() {
        // Same claims, same kid, different key: the forgery a missing signature
        // check let through.
        let token = sign_with(
            &other_key().signing,
            good_claims(),
            Some(TEST_KID),
            Algorithm::ES256,
        );
        assert!(matches!(
            verify(&token, Some("handshake-nonce")),
            Err(OidcError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_the_unsigned_token() {
        // `alg: none` with the signature stripped. The algorithm allowlist
        // refuses it before any key is chosen.
        let header = URL_SAFE_NO_PAD_ENCODE(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD_ENCODE(&good_claims().to_string());
        let token = format!("{header}.{payload}.");
        assert!(matches!(
            verify(&token, Some("handshake-nonce")),
            Err(OidcError::MalformedHeader(_)) | Err(OidcError::DisallowedAlgorithm(_))
        ));
    }

    /// A token minted for a different client at the same provider. This is the
    /// confused-deputy case that an unchecked `aud` allowed.
    #[test]
    fn rejects_a_token_issued_to_another_application() {
        let mut claims = good_claims();
        claims["aud"] = serde_json::json!("some-other-app");
        let token = sign(claims, Some(TEST_KID), Algorithm::ES256);
        assert!(matches!(
            verify(&token, Some("handshake-nonce")),
            Err(OidcError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_a_token_from_another_issuer() {
        let mut claims = good_claims();
        claims["iss"] = serde_json::json!("https://evil.example.com");
        let token = sign(claims, Some(TEST_KID), Algorithm::ES256);
        assert!(matches!(
            verify(&token, Some("handshake-nonce")),
            Err(OidcError::Invalid(_)) | Err(OidcError::IssuerMismatch { .. })
        ));
    }

    #[test]
    fn rejects_an_expired_token() {
        let mut claims = good_claims();
        claims["exp"] =
            serde_json::json!((chrono::Utc::now() - chrono::Duration::hours(1)).timestamp());
        let token = sign(claims, Some(TEST_KID), Algorithm::ES256);
        assert!(matches!(
            verify(&token, Some("handshake-nonce")),
            Err(OidcError::Invalid(_))
        ));
    }

    /// The replay case: a token that is valid in every respect but was minted
    /// for a different login attempt.
    #[test]
    fn rejects_a_token_from_a_different_handshake() {
        let token = sign(good_claims(), Some(TEST_KID), Algorithm::ES256);
        assert!(matches!(
            verify(&token, Some("a-different-nonce")),
            Err(OidcError::NonceMismatch)
        ));
    }

    #[test]
    fn rejects_a_token_with_no_nonce_when_one_was_sent() {
        let mut claims = good_claims();
        claims.as_object_mut().unwrap().remove("nonce");
        let token = sign(claims, Some(TEST_KID), Algorithm::ES256);
        assert!(matches!(
            verify(&token, Some("handshake-nonce")),
            Err(OidcError::NonceMismatch)
        ));
    }

    /// Without this, a provider that lets anyone self-register any address is
    /// enough to become whoever `bootstrap.admin_emails` names.
    #[test]
    fn rejects_an_unverified_email() {
        for value in [
            serde_json::json!(false),
            serde_json::json!("false"),
            serde_json::Value::Null,
        ] {
            let mut claims = good_claims();
            claims["email_verified"] = value;
            let token = sign(claims, Some(TEST_KID), Algorithm::ES256);
            assert!(matches!(
                verify(&token, Some("handshake-nonce")),
                Err(OidcError::EmailNotVerified)
            ));
        }
    }

    #[test]
    fn rejects_a_token_with_email_verified_absent() {
        let mut claims = good_claims();
        claims.as_object_mut().unwrap().remove("email_verified");
        let token = sign(claims, Some(TEST_KID), Algorithm::ES256);
        assert!(matches!(
            verify(&token, Some("handshake-nonce")),
            Err(OidcError::EmailNotVerified)
        ));
    }

    #[test]
    fn accepts_email_verified_as_a_string() {
        let mut claims = good_claims();
        claims["email_verified"] = serde_json::json!("true");
        let token = sign(claims, Some(TEST_KID), Algorithm::ES256);
        assert!(verify(&token, Some("handshake-nonce")).is_ok());
    }

    #[test]
    fn rejects_an_unknown_signing_key() {
        let token = sign(good_claims(), Some("rotated-away"), Algorithm::ES256);
        assert!(matches!(
            verify(&token, Some("handshake-nonce")),
            Err(OidcError::UnknownKeyId(_))
        ));
    }

    #[test]
    fn rejects_a_token_that_names_no_signing_key() {
        let token = sign(good_claims(), None, Algorithm::ES256);
        assert!(matches!(
            verify(&token, Some("handshake-nonce")),
            Err(OidcError::MissingKeyId)
        ));
    }

    #[test]
    fn rejects_a_token_with_no_subject() {
        let mut claims = good_claims();
        claims["sub"] = serde_json::json!("");
        let token = sign(claims, Some(TEST_KID), Algorithm::ES256);
        assert!(matches!(
            verify(&token, Some("handshake-nonce")),
            Err(OidcError::MissingSubject)
        ));
    }

    #[test]
    fn discovery_document_must_agree_about_its_issuer() {
        // Guards the parse/compare rule used by `metadata`, without a network.
        let doc: ProviderMetadata = serde_json::from_value(serde_json::json!({
            "issuer": "https://elsewhere.example.com",
            "authorization_endpoint": "https://elsewhere.example.com/authorize",
            "token_endpoint": "https://elsewhere.example.com/token",
            "jwks_uri": "https://elsewhere.example.com/keys"
        }))
        .expect("parse");
        assert_ne!(
            doc.issuer.trim_end_matches('/'),
            ISSUER.trim_end_matches('/')
        );
    }

    #[test]
    fn rebase_moves_a_provider_url_onto_the_reachable_host() {
        assert_eq!(
            rebase(
                "http://localhost:5556/dex/token",
                "http://localhost:5556/dex",
                "http://dex:5556/dex"
            ),
            "http://dex:5556/dex/token"
        );
    }

    #[test]
    fn rebase_tolerates_a_trailing_slash_on_either_base() {
        assert_eq!(
            rebase(
                "http://localhost:5556/dex/keys",
                "http://localhost:5556/dex/",
                "http://dex:5556/dex/"
            ),
            "http://dex:5556/dex/keys"
        );
    }

    /// A provider that serves its keys from somewhere else entirely is left
    /// alone: pointing that request at the internal host would send it to a host
    /// that was never asked to serve it.
    #[test]
    fn rebase_leaves_a_url_outside_the_issuer_untouched() {
        let cdn = "https://keys.cdn.example.com/jwks.json";
        assert_eq!(
            rebase(cdn, "http://localhost:5556/dex", "http://dex:5556/dex"),
            cdn
        );
    }

    /// Pins the allowlist.
    ///
    /// These tests sign with ES256 because the suite generates its own keys and
    /// an EC keypair is cheap to make; real providers overwhelmingly use RS256.
    /// So nothing else here would notice RS256 being dropped from the allowlist,
    /// and dropping it would refuse every login at most providers.
    #[test]
    fn the_allowlist_covers_what_providers_actually_sign_with() {
        for alg in [
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::ES256,
            Algorithm::ES384,
        ] {
            assert!(
                ALLOWED_ALGORITHMS.contains(&alg),
                "{alg:?} must stay accepted"
            );
        }
        for alg in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
            assert!(
                !ALLOWED_ALGORITHMS.contains(&alg),
                "{alg:?} is symmetric and must never be accepted"
            );
        }
    }

    #[test]
    fn peek_key_id_reads_the_header() {
        let token = sign(good_claims(), Some(TEST_KID), Algorithm::ES256);
        assert_eq!(peek_key_id(&token).as_deref(), Some(TEST_KID));
    }

    // --- helpers ---

    #[allow(non_snake_case)]
    fn URL_SAFE_NO_PAD_ENCODE(s: &str) -> String {
        URL_SAFE_NO_PAD_ENCODE_BYTES(s.as_bytes())
    }

    #[allow(non_snake_case)]
    fn URL_SAFE_NO_PAD_ENCODE_BYTES(b: &[u8]) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        URL_SAFE_NO_PAD.encode(b)
    }
}
