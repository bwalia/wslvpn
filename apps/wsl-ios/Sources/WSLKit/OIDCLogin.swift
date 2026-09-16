import AuthenticationServices
import Foundation

/// Signing in through the identity provider.
///
/// The desktop client listens on loopback and has the browser redirected there.
/// A phone cannot: there is no way to hold a listening socket open reliably in
/// the background, and no way to stop another app binding the port first. iOS
/// answers this with a private-use URI scheme the system routes to this app,
/// which is the mechanism RFC 8252 section 7.1 describes — and which the
/// control plane accepts only for schemes the deployment has named in
/// `identity.oidc.native_schemes`.
///
/// `ASWebAuthenticationSession` is what makes it safe on the client side. The
/// browser it opens is outside this app's control: the app cannot read the page,
/// cannot inject script, and cannot see the credentials typed into it. A plain
/// `WKWebView` would give the app all three, which is why an in-app web view is
/// the wrong way to do this even though it looks the same to a user.
public enum OIDCLogin {
    public enum LoginError: Error, LocalizedError, Equatable {
        case cancelled
        case providerError(String)
        case noCode
        case badCallback(String)

        public var errorDescription: String? {
            switch self {
            case .cancelled:
                return "Sign-in was cancelled."
            case .providerError(let value):
                return "The identity provider reported: \(value)"
            case .noCode:
                return "The sign-in came back without a code."
            case .badCallback(let value):
                return "Could not read the sign-in result: \(value)"
            }
        }
    }

    /// The scheme registered in Info.plist. Derived from a domain name, because
    /// private-use schemes are first come, first served and a bare word can be
    /// claimed by anything.
    public static let callbackScheme = "io.wsl.zerotrust"
    public static let callbackURL = "\(callbackScheme)://callback"

    /// Build the URL that starts the handshake.
    ///
    /// The challenge goes in; the verifier does not, and never leaves the
    /// process until it is presented to redeem the code.
    public static func authorizeURL(
        controlPlane: URL,
        challenge: String,
        redirect: String = callbackURL
    ) -> URL? {
        guard var components = URLComponents(
            url: controlPlane.appendingPathComponent("auth/oidc/authorize"),
            resolvingAgainstBaseURL: true
        ) else { return nil }
        components.queryItems = [
            URLQueryItem(name: "redirect_uri", value: redirect),
            URLQueryItem(name: "client_challenge", value: challenge),
        ]
        return components.url
    }

    /// Pull the one-time code out of the URL the system handed back.
    public static func code(fromCallback url: URL) -> Result<String, LoginError> {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return .failure(.badCallback(url.absoluteString))
        }
        let items = components.queryItems ?? []
        // An error is reported even when a code is present: a provider that
        // sends both is not offering a usable login.
        if let error = items.first(where: { $0.name == "error" })?.value {
            return .failure(.providerError(error))
        }
        guard let code = items.first(where: { $0.name == "code" })?.value, !code.isEmpty else {
            return .failure(.noCode)
        }
        return .success(code)
    }
}

/// Runs the browser half of the handshake.
@MainActor
public final class BrowserLogin: NSObject, ASWebAuthenticationPresentationContextProviding {
    private let anchor: ASPresentationAnchor

    public init(anchor: ASPresentationAnchor) {
        self.anchor = anchor
    }

    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        anchor
    }

    /// Open the browser, wait for the callback, and return the token.
    public func signIn(
        controlPlane: URL,
        client: ControlPlaneClient
    ) async throws -> TokenResponse {
        let pkce = PKCE()
        guard let url = OIDCLogin.authorizeURL(controlPlane: controlPlane, challenge: pkce.challenge)
        else {
            throw OIDCLogin.LoginError.badCallback(controlPlane.absoluteString)
        }

        let callback = try await present(url: url)
        switch OIDCLogin.code(fromCallback: callback) {
        case .failure(let error):
            throw error
        case .success(let code):
            return try await client.exchange(code: code, verifier: pkce.verifier)
        }
    }

    private func present(url: URL) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: url,
                callbackURLScheme: OIDCLogin.callbackScheme
            ) { callback, error in
                if let callback {
                    continuation.resume(returning: callback)
                    return
                }
                if let error = error as? ASWebAuthenticationSessionError,
                   error.code == .canceledLogin {
                    continuation.resume(throwing: OIDCLogin.LoginError.cancelled)
                    return
                }
                continuation.resume(
                    throwing: error ?? OIDCLogin.LoginError.noCode
                )
            }
            session.presentationContextProvider = self
            // Deliberately false. A shared cookie jar means a second sign-in
            // silently reuses whoever signed in first, which on a shared or
            // recovered device is the wrong person.
            session.prefersEphemeralWebBrowserSession = true
            session.start()
        }
    }
}
