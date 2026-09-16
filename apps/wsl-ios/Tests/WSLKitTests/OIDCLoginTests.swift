import Foundation
import Testing
@testable import WSLKit

@Suite struct OIDCLoginTests {
    @Test func theAuthorizeURLCarriesTheChallengeAndNotTheVerifier() throws {
        let pkce = PKCE()
        let url = try #require(
            OIDCLogin.authorizeURL(
                controlPlane: URL(string: "https://vpn.example.com")!,
                challenge: pkce.challenge
            )
        )
        let components = try #require(URLComponents(url: url, resolvingAgainstBaseURL: false))
        #expect(components.path == "/auth/oidc/authorize")

        let items = try #require(components.queryItems)
        #expect(items.first { $0.name == "client_challenge" }?.value == pkce.challenge)
        #expect(items.first { $0.name == "redirect_uri" }?.value == "io.wsl.zerotrust://callback")
        #expect(!url.absoluteString.contains(pkce.verifier))
    }

    /// The scheme in the URL has to be the one registered in Info.plist, or the
    /// system routes the callback nowhere and the login silently times out.
    @Test func theRedirectUsesTheRegisteredScheme() {
        #expect(OIDCLogin.callbackURL.hasPrefix(OIDCLogin.callbackScheme + "://"))
    }

    @Test func theCallbackYieldsItsCode() throws {
        let url = URL(string: "io.wsl.zerotrust://callback?code=abc123")!
        #expect(try OIDCLogin.code(fromCallback: url).get() == "abc123")
    }

    /// A provider that sends both is not offering a usable login, and treating
    /// the code as good would redeem something the user did not authorise.
    @Test func aProviderErrorWinsOverACode() {
        let url = URL(string: "io.wsl.zerotrust://callback?error=access_denied&code=ignored")!
        #expect(OIDCLogin.code(fromCallback: url) == .failure(.providerError("access_denied")))
    }

    @Test func aCallbackWithoutACodeIsAnError() {
        let url = URL(string: "io.wsl.zerotrust://callback")!
        #expect(OIDCLogin.code(fromCallback: url) == .failure(.noCode))
    }

    @Test func anEmptyCodeIsNotACode() {
        let url = URL(string: "io.wsl.zerotrust://callback?code=")!
        #expect(OIDCLogin.code(fromCallback: url) == .failure(.noCode))
    }

    @Test func aPercentEncodedCodeIsDecodedOnce() throws {
        let url = URL(string: "io.wsl.zerotrust://callback?code=a%2Bb%2Fc")!
        #expect(try OIDCLogin.code(fromCallback: url).get() == "a+b/c")
    }
}
