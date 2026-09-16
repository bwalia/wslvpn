import CryptoKit
import Foundation

/// A WireGuard keypair.
///
/// WireGuard keys are Curve25519, which is exactly what CryptoKit's
/// `Curve25519.KeyAgreement` produces, so there is no third-party crypto here
/// and no hand-rolled clamping. The private key never leaves the device: what
/// the control plane registers is the public half.
public struct WireGuardKeypair: Sendable {
    /// Base64, standard alphabet — the encoding `wg` itself uses.
    public let privateKey: String
    public let publicKey: String

    public init() {
        let key = Curve25519.KeyAgreement.PrivateKey()
        self.privateKey = key.rawRepresentation.base64EncodedString()
        self.publicKey = key.publicKey.rawRepresentation.base64EncodedString()
    }

    /// Recover the public half from a stored private key.
    ///
    /// Used when a key is read back from the keychain, so the registered public
    /// key can be checked against the one the device would present now.
    public init?(privateKeyBase64: String) {
        guard let raw = Data(base64Encoded: privateKeyBase64),
              let key = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw)
        else { return nil }
        self.privateKey = privateKeyBase64
        self.publicKey = key.publicKey.rawRepresentation.base64EncodedString()
    }
}
