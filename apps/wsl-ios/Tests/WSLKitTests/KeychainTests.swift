import Foundation
import Testing
@testable import WSLKit

/// The keychain is where the access token and the device private key live, so a
/// failure to write one is a failure to sign in. It is worth testing directly:
/// the symptom otherwise is a sign-in that returns 200 and then stops, with
/// nothing in the network log to explain it.
@Suite struct KeychainTests {
    private func keychain(accessGroup: String?) -> Keychain {
        Keychain(service: "io.wsl.zerotrust.tests.\(UUID().uuidString)", accessGroup: accessGroup)
    }

    @Test func aValueSurvivesBeingWrittenAndReadBack() throws {
        let store = keychain(accessGroup: nil)
        try store.set("a-token", for: .accessToken)
        #expect(store.get(.accessToken) == "a-token")
        store.remove(.accessToken)
        #expect(store.get(.accessToken) == nil)
    }

    @Test func writingTwiceReplacesRatherThanFailing() throws {
        let store = keychain(accessGroup: nil)
        try store.set("first", for: .accessToken)
        try store.set("second", for: .accessToken)
        #expect(store.get(.accessToken) == "second")
        store.remove(.accessToken)
    }

    /// A build without the shared-access-group entitlement — a simulator
    /// preview, a unit test bundle — must still be able to store a token. This
    /// is the case that silently broke sign-in.
    @Test func anUnentitledAccessGroupFallsBackRatherThanThrowing() throws {
        let store = keychain(accessGroup: "io.wsl.zerotrust")
        try store.set("a-token", for: .accessToken)
        #expect(store.get(.accessToken) == "a-token")
        store.remove(.accessToken)
    }

    @Test func aKeypairIsGeneratedOnceAndThenReused() throws {
        let store = keychain(accessGroup: nil)
        let first = try store.wireguardKeypair()
        let second = try store.wireguardKeypair()
        #expect(first.privateKey == second.privateKey)
        #expect(first.publicKey == second.publicKey)
        store.remove(.wireguardPrivateKey)
    }
}
