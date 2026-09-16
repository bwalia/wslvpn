import Foundation

/// The control plane's HTTP API.
///
/// Every call is the same shape the CLI makes, against the same routes, so a
/// change to the wire contract breaks both rather than leaving the phone
/// quietly behind.
public actor ControlPlaneClient {
    public enum ClientError: Error, LocalizedError {
        case notSignedIn
        case http(status: Int, body: String)
        case badURL(String)

        public var errorDescription: String? {
            switch self {
            case .notSignedIn:
                return "Not signed in."
            case .http(let status, let body):
                // The control plane answers errors as JSON with a message; if
                // it did not, the raw body is still better than a bare number.
                let detail = ControlPlaneClient.message(from: body) ?? body
                return detail.isEmpty
                    ? "The control plane returned HTTP \(status)."
                    : "The control plane returned HTTP \(status): \(detail)"
            case .badURL(let value):
                return "Not a usable control plane URL: \(value)"
            }
        }
    }

    private let baseURL: URL
    private let session: URLSession
    private var accessToken: String?

    public init(baseURL: URL, accessToken: String? = nil, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.accessToken = accessToken
        self.session = session
    }

    public func setAccessToken(_ token: String?) {
        accessToken = token
    }

    // MARK: - Sign-in

    /// Redeem a one-time code from the browser handshake.
    ///
    /// The verifier is sent here and nowhere else; it was never in the URL that
    /// opened the browser, so a code observed in transit is not enough.
    public func exchange(code: String, verifier: String) async throws -> TokenResponse {
        try await send(
            "auth/oidc/exchange",
            method: "POST",
            body: ["code": code, "verifier": verifier],
            authenticated: false
        )
    }

    /// The local development login. The control plane refuses to serve this
    /// unless it is bound to loopback, so it can only ever reach a demo.
    public func devLogin(email: String) async throws -> TokenResponse {
        try await send(
            "auth/dev/login",
            method: "POST",
            body: ["email": email],
            authenticated: false
        )
    }

    // MARK: - Device and networks

    public func registerDevice(_ request: RegisterDeviceRequest) async throws
        -> RegisterDeviceResponse
    {
        try await send("api/v1/devices/register", method: "POST", encodable: request)
    }

    public func networks() async throws -> [Network] {
        try await send("api/v1/networks", method: "GET")
    }

    public func createSession(_ request: CreateSessionRequest) async throws
        -> CreateSessionResponse
    {
        try await send("api/v1/sessions", method: "POST", encodable: request)
    }

    public func deleteSession(id: UUID) async throws {
        _ = try await sendRaw("api/v1/sessions/\(id.uuidString.lowercased())", method: "DELETE")
    }

    // MARK: - Plumbing

    private func send<Response: Decodable>(
        _ path: String,
        method: String,
        body: [String: String]? = nil,
        authenticated: Bool = true
    ) async throws -> Response {
        let data = try await sendRaw(
            path,
            method: method,
            payload: body.map { try! JSONSerialization.data(withJSONObject: $0) },
            authenticated: authenticated
        )
        return try Wire.decoder().decode(Response.self, from: data)
    }

    private func send<Request: Encodable, Response: Decodable>(
        _ path: String,
        method: String,
        encodable: Request
    ) async throws -> Response {
        let data = try await sendRaw(
            path,
            method: method,
            payload: try Wire.encoder().encode(encodable)
        )
        return try Wire.decoder().decode(Response.self, from: data)
    }

    @discardableResult
    private func sendRaw(
        _ path: String,
        method: String,
        payload: Data? = nil,
        authenticated: Bool = true
    ) async throws -> Data {
        guard let url = URL(string: path, relativeTo: baseURL) else {
            throw ClientError.badURL(path)
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        if let payload {
            request.httpBody = payload
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        if authenticated {
            guard let accessToken else { throw ClientError.notSignedIn }
            request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        }

        let (data, response) = try await session.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            throw ClientError.http(status: status, body: String(decoding: data, as: UTF8.self))
        }
        return data
    }

    static func message(from body: String) -> String? {
        guard let data = body.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return (object["message"] ?? object["error"]) as? String
    }
}
