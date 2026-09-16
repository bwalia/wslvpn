import Foundation

/// Mirrors of the control plane's wire types.
///
/// These are hand-written rather than generated, so the thing that keeps them
/// honest is `ModelTests`, which decodes captured responses shaped exactly as
/// `wsl-types` serialises them. Rust serialises struct fields as written —
/// snake_case — and enums with `rename_all = "snake_case"`, so the decoder is
/// configured for snake_case throughout and never guesses.

public enum PostureResult: String, Codable, Sendable {
    case pass
    case fail
    case unknown
    case unsupported
}

public struct PostureSignal: Codable, Sendable, Identifiable, Equatable {
    public let name: String
    public let result: PostureResult
    public let detail: String?

    public var id: String { name }

    public init(name: String, result: PostureResult, detail: String? = nil) {
        self.name = name
        self.result = result
        self.detail = detail
    }
}

public struct Device: Codable, Sendable, Identifiable {
    public let id: UUID
    public let userId: UUID
    public let name: String
    public let platform: String
    public let osVersion: String?
    public let agentVersion: String?
    public let wireguardPublicKey: String
    public let revoked: Bool
}

public struct RegisterDeviceRequest: Codable, Sendable {
    public let name: String
    public let platform: String
    public let osVersion: String?
    public let agentVersion: String?
    public let wireguardPublicKey: String
    public let posture: [PostureSignal]

    public init(
        name: String,
        platform: String,
        osVersion: String?,
        agentVersion: String?,
        wireguardPublicKey: String,
        posture: [PostureSignal]
    ) {
        self.name = name
        self.platform = platform
        self.osVersion = osVersion
        self.agentVersion = agentVersion
        self.wireguardPublicKey = wireguardPublicKey
        self.posture = posture
    }
}

public struct RegisterDeviceResponse: Codable, Sendable {
    public let device: Device
}

public struct Network: Codable, Sendable, Identifiable, Hashable {
    public let id: UUID
    public let name: String
    public let cidr: String
    public let dnsServers: [String]
    public let dnsDomains: [String]
}

public enum SessionStatus: String, Codable, Sendable {
    case active
    case expired
    case revoked
}

public struct Session: Codable, Sendable, Identifiable {
    public let id: UUID
    public let userId: UUID
    public let deviceId: UUID
    public let networkId: UUID
    public let assignedIp: String
    public let status: SessionStatus
    public let expiresAt: Date
}

public struct PolicyDecision: Codable, Sendable {
    public let allow: Bool
    public let policyName: String?
    public let policyVersion: Int64?
    public let reason: String
}

/// What the gateway expects this device to configure.
public struct ClientWireGuardConfig: Codable, Sendable, Equatable {
    public let interfaceAddress: String
    public let dns: [String]
    public let peerPublicKey: String
    public let peerEndpoint: String
    public let allowedIps: [String]
    public let persistentKeepalive: UInt16

    public init(
        interfaceAddress: String,
        dns: [String],
        peerPublicKey: String,
        peerEndpoint: String,
        allowedIps: [String],
        persistentKeepalive: UInt16
    ) {
        self.interfaceAddress = interfaceAddress
        self.dns = dns
        self.peerPublicKey = peerPublicKey
        self.peerEndpoint = peerEndpoint
        self.allowedIps = allowedIps
        self.persistentKeepalive = persistentKeepalive
    }
}

public struct CreateSessionRequest: Codable, Sendable {
    public let networkId: UUID
    public let deviceId: UUID
    public let posture: [PostureSignal]

    public init(networkId: UUID, deviceId: UUID, posture: [PostureSignal]) {
        self.networkId = networkId
        self.deviceId = deviceId
        self.posture = posture
    }
}

public struct CreateSessionResponse: Codable, Sendable {
    public let session: Session
    public let decision: PolicyDecision
    public let wireguard: ClientWireGuardConfig
}

public struct TokenResponse: Codable, Sendable {
    public let accessToken: String
    public let userId: UUID
    public let email: String
}

/// JSON coders configured for the control plane's conventions, in one place so
/// a request and a response cannot disagree about them.
public enum Wire {
    public static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        // The control plane emits RFC 3339 with fractional seconds from
        // chrono's `to_rfc3339`. `.iso8601` alone rejects the fraction.
        decoder.dateDecodingStrategy = .custom { decoder in
            let text = try decoder.singleValueContainer().decode(String.self)
            guard let date = RFC3339.date(from: text) else {
                throw DecodingError.dataCorrupted(
                    .init(codingPath: decoder.codingPath,
                          debugDescription: "not an RFC 3339 timestamp: \(text)")
                )
            }
            return date
        }
        return decoder
    }

    public static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        return encoder
    }
}

/// RFC 3339 parsing that accepts a fractional-second part or its absence.
public enum RFC3339 {
    private static let withFraction: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    private static let withoutFraction: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()

    public static func date(from text: String) -> Date? {
        withFraction.date(from: text) ?? withoutFraction.date(from: text)
    }
}
