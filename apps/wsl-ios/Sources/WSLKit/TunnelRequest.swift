import Foundation

/// What the app hands the tunnel extension to bring an interface up.
///
/// The two processes do not share memory, so this is the whole contract between
/// them: the gateway's answer, and the device key that goes with it. It travels
/// as JSON in the tunnel's provider configuration.
///
/// It is validated here rather than in the extension. The extension runs with
/// no user in front of it, sometimes while the screen is locked, and cannot
/// report anything better than a failure to start — whereas the app can say
/// what is wrong at the moment someone pressed Connect. So anything that can be
/// checked before the tunnel starts is checked before the tunnel starts.
///
/// This type deliberately does not mention WireGuardKit. That package links a
/// Go static library with no simulator slice, and keeping it on the far side of
/// this boundary is what lets everything here be tested on a simulator.
public struct TunnelRequest: Codable, Sendable, Equatable {
    public let config: ClientWireGuardConfig
    public let privateKey: String
    public let networkName: String

    /// The key under which this travels in `providerConfiguration`.
    public static let providerConfigurationKey = "tunnel-request"

    public enum ValidationError: Error, LocalizedError, Equatable {
        case missingPrivateKey
        case emptyAllowedIPs
        case emptyEndpoint
        case emptyInterfaceAddress

        public var errorDescription: String? {
            switch self {
            case .missingPrivateKey:
                return "No WireGuard private key for this device."
            case .emptyAllowedIPs:
                // A tunnel with no allowed IPs comes up and routes nothing,
                // which to a user is indistinguishable from a VPN that has
                // broken the network.
                return "The gateway sent no allowed IPs, so the tunnel would carry no traffic."
            case .emptyEndpoint:
                return "The gateway sent no endpoint to connect to."
            case .emptyInterfaceAddress:
                return "The gateway assigned no address to this device."
            }
        }
    }

    public init(
        config: ClientWireGuardConfig,
        privateKey: String,
        networkName: String
    ) throws {
        guard !privateKey.isEmpty else { throw ValidationError.missingPrivateKey }
        guard !config.interfaceAddress.isEmpty else { throw ValidationError.emptyInterfaceAddress }
        guard !config.allowedIps.isEmpty else { throw ValidationError.emptyAllowedIPs }
        guard !config.peerEndpoint.isEmpty else { throw ValidationError.emptyEndpoint }
        self.config = config
        self.privateKey = privateKey
        self.networkName = networkName
    }

    public func encoded() throws -> Data {
        try Wire.encoder().encode(self)
    }

    public static func decode(from data: Data) throws -> TunnelRequest {
        try Wire.decoder().decode(TunnelRequest.self, from: data)
    }
}
