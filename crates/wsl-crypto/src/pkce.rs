//! Proof-of-possession for a login started by one process and finished by
//! another.
//!
//! A native client cannot keep a client secret, and the browser that completes
//! an OIDC handshake is not the process that started it. The way out, from RFC
//! 7636, is for the client to hold a random verifier, publish only its hash
//! when the handshake starts, and present the verifier to redeem the result.
//! Anything that observes the handshake in flight — including another process
//! on the same machine watching loopback — sees the hash and the eventual code,
//! and can do nothing with either.
//!
//! Only the S256 method is offered. `plain` is in the RFC for clients that
//! cannot hash, publishes the verifier, and there is no such client here.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// A verifier and the challenge derived from it.
pub struct Pkce {
    /// Kept locally and presented once, to redeem the result.
    verifier: Zeroizing<String>,
    /// Base64url SHA-256 of the verifier. Safe to send.
    challenge: String,
}

impl Pkce {
    /// 32 bytes of OS randomness, which encodes to a 43-character verifier —
    /// the length RFC 7636 section 4.1 recommends.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let verifier = URL_SAFE_NO_PAD.encode(bytes);
        let challenge = challenge_for(&verifier);
        Self {
            verifier: Zeroizing::new(verifier),
            challenge,
        }
    }

    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    pub fn challenge(&self) -> &str {
        &self.challenge
    }
}

/// The S256 transform: base64url of the SHA-256 of the verifier's ASCII bytes.
pub fn challenge_for(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example from RFC 7636 appendix B, which pins the transform
    /// against the spec rather than against this implementation.
    #[test]
    fn s256_matches_the_rfc_test_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            challenge_for(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn a_generated_verifier_is_43_url_safe_characters() {
        let pkce = Pkce::generate();
        assert_eq!(pkce.verifier().len(), 43);
        assert!(
            pkce.verifier()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "verifier must survive a query string unescaped: {}",
            pkce.verifier()
        );
    }

    #[test]
    fn the_challenge_is_the_hash_of_that_verifier() {
        let pkce = Pkce::generate();
        assert_eq!(pkce.challenge(), challenge_for(pkce.verifier()));
        assert_ne!(pkce.challenge(), pkce.verifier());
    }

    #[test]
    fn two_logins_do_not_share_a_verifier() {
        assert_ne!(Pkce::generate().verifier(), Pkce::generate().verifier());
    }
}
