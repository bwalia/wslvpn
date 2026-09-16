import Foundation
import Testing
@testable import WSLKit

@Suite struct WireGuardKeyTests {
    /// WireGuard keys are 32 raw bytes, base64 encoded — 44 characters with
    /// one padding character. A key of any other length is rejected by `wg`
    /// with an error the user never sees, from inside the extension.
    @Test func keysAreThirtyTwoBytesBase64() throws {
        let pair = WireGuardKeypair()
        let priv = try #require(Data(base64Encoded: pair.privateKey))
        let pub = try #require(Data(base64Encoded: pair.publicKey))
        #expect(priv.count == 32)
        #expect(pub.count == 32)
    }

    @Test func theKeypairIsNotTheSameKeyTwice() {
        let pair = WireGuardKeypair()
        #expect(pair.privateKey != pair.publicKey)
        #expect(WireGuardKeypair().privateKey != WireGuardKeypair().privateKey)
    }

    /// Reading a key back from the keychain has to produce the same public half
    /// the gateway was told about, or the device registers a peer that can
    /// never complete a handshake.
    @Test func recoveringAPrivateKeyReproducesItsPublicHalf() throws {
        let original = WireGuardKeypair()
        let recovered = try #require(WireGuardKeypair(privateKeyBase64: original.privateKey))
        #expect(recovered.publicKey == original.publicKey)
    }

    @Test func rubbishIsRejectedRatherThanProducingAKey() {
        #expect(WireGuardKeypair(privateKeyBase64: "not base64!") == nil)
        // Right encoding, wrong length.
        #expect(WireGuardKeypair(privateKeyBase64: Data([1, 2, 3]).base64EncodedString()) == nil)
    }
}
