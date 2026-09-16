import CryptoKit
import Foundation

/// Proof-of-possession for a login started by the app and finished in a browser.
///
/// The same construction as the CLI's, and deliberately the same test vector:
/// the control plane compares `SHA256(verifier)` against what was published at
/// the start of the handshake, so a client that disagrees about the transform
/// simply cannot log in. Only S256 is offered — `plain` publishes the verifier,
/// and there is no client here that cannot hash.
public struct PKCE: Sendable {
    /// Kept in memory only, and presented once to redeem the login.
    public let verifier: String
    /// Base64url SHA-256 of the verifier. Safe to put in a URL.
    public let challenge: String

    public init() {
        var bytes = [UInt8](repeating: 0, count: 32)
        // The system CSPRNG. 32 bytes encodes to the 43-character verifier
        // RFC 7636 section 4.1 asks for.
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        self.init(verifier: Data(bytes).base64URLEncodedString())
    }

    public init(verifier: String) {
        self.verifier = verifier
        self.challenge = PKCE.challenge(for: verifier)
    }

    /// The S256 transform: base64url of the SHA-256 of the verifier's bytes.
    public static func challenge(for verifier: String) -> String {
        let digest = SHA256.hash(data: Data(verifier.utf8))
        return Data(digest).base64URLEncodedString()
    }
}

extension Data {
    /// base64url without padding, per RFC 4648 section 5. The standard alphabet
    /// would put `+` and `/` in a query string, where both need escaping.
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
