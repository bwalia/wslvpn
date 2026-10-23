use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct WireGuardKeypair {
    pub private_key_b64: Zeroizing<String>,
    pub public_key_b64: String,
}

pub fn generate_wireguard_keypair() -> WireGuardKeypair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let private_bytes = secret.to_bytes();
    WireGuardKeypair {
        private_key_b64: Zeroizing::new(B64.encode(private_bytes)),
        public_key_b64: B64.encode(public.as_bytes()),
    }
}

/// The public key for a base64 WireGuard private key, as `wg pubkey` prints
/// it. `None` for anything that is not a 32-byte key.
pub fn public_key_from_private(private_b64: &str) -> Option<String> {
    let bytes = Zeroizing::new(B64.decode(private_b64.trim()).ok()?);
    let key: [u8; 32] = bytes.as_slice().try_into().ok()?;
    let secret = StaticSecret::from(key);
    Some(B64.encode(PublicKey::from(&secret).as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pair from the WireGuard quick-start, checked against `wg pubkey`.
    #[test]
    fn the_public_key_matches_wg_pubkey() {
        assert_eq!(
            public_key_from_private("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=").as_deref(),
            Some("HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=")
        );
        assert_eq!(public_key_from_private("not a key"), None);
        let pair = generate_wireguard_keypair();
        assert_eq!(
            public_key_from_private(&pair.private_key_b64).as_deref(),
            Some(pair.public_key_b64.as_str())
        );
    }

    #[test]
    fn generates_distinct_keys() {
        let a = generate_wireguard_keypair();
        let b = generate_wireguard_keypair();
        assert_ne!(a.public_key_b64, b.public_key_b64);
        assert_eq!(a.public_key_b64.len(), 44);
    }
}
