import Foundation
import Testing
@testable import WSLKit

/// The control plane compares SHA256(verifier) against the challenge published
/// at the start of the handshake. A client that disagrees about the transform
/// cannot log in, so this is pinned to the specification rather than to the
/// implementation — the same vector the Rust side uses.
@Suite struct PKCETests {
    @Test func s256MatchesTheRFCTestVector() {
        // RFC 7636 appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        #expect(PKCE.challenge(for: verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    }

    @Test func aGeneratedVerifierIs43URLSafeCharacters() {
        let pkce = PKCE()
        #expect(pkce.verifier.count == 43)
        let allowed = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        #expect(pkce.verifier.allSatisfy { allowed.contains($0) })
    }

    @Test func theChallengeIsTheHashOfThatVerifier() {
        let pkce = PKCE()
        #expect(pkce.challenge == PKCE.challenge(for: pkce.verifier))
        #expect(pkce.challenge != pkce.verifier)
    }

    @Test func twoLoginsDoNotShareAVerifier() {
        #expect(PKCE().verifier != PKCE().verifier)
    }

    /// base64url, not base64: `+` and `/` both need escaping in a query string,
    /// and a challenge that arrives percent-encoded will not compare equal.
    @Test func theEncodingIsURLSafeAndUnpadded() {
        let encoded = Data([251, 255, 190, 0]).base64URLEncodedString()
        #expect(!encoded.contains("+"))
        #expect(!encoded.contains("/"))
        #expect(!encoded.contains("="))
    }
}
