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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_distinct_keys() {
        let a = generate_wireguard_keypair();
        let b = generate_wireguard_keypair();
        assert_ne!(a.public_key_b64, b.public_key_b64);
        assert_eq!(a.public_key_b64.len(), 44);
    }
}
