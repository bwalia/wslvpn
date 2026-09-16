import Foundation
import WSLKit
import WireGuardKit

/// Turning the app's request into WireGuard's own types.
///
/// This lives in the extension because it is the only place that links
/// WireGuardKit. Everything the app could check has been checked already —
/// what is left is the parsing that only WireGuard's parsers can do, and each
/// failure names the field rather than the fact that something went wrong.
extension TunnelRequest {
    enum ConversionError: Error, LocalizedError {
        case badPrivateKey
        case badPeerKey
        case badEndpoint(String)
        case badAddress(String)
        case badAllowedIP(String)

        var errorDescription: String? {
            switch self {
            case .badPrivateKey: return "The stored device key is not a WireGuard key."
            case .badPeerKey: return "The gateway's public key is not a WireGuard key."
            case .badEndpoint(let value): return "Not a usable endpoint: \(value)"
            case .badAddress(let value): return "Not a usable interface address: \(value)"
            case .badAllowedIP(let value): return "Not a usable allowed IP: \(value)"
            }
        }
    }

    func wireGuardConfiguration() throws -> TunnelConfiguration {
        guard let privateKey = PrivateKey(base64Key: privateKey) else {
            throw ConversionError.badPrivateKey
        }
        guard let peerKey = PublicKey(base64Key: config.peerPublicKey) else {
            throw ConversionError.badPeerKey
        }

        var interface = InterfaceConfiguration(privateKey: privateKey)
        guard let address = IPAddressRange(from: config.interfaceAddress) else {
            throw ConversionError.badAddress(config.interfaceAddress)
        }
        interface.addresses = [address]
        // A resolver the parser cannot read is dropped rather than failing the
        // tunnel: losing name resolution is bad, and losing the tunnel over it
        // is worse.
        interface.dns = config.dns.compactMap(DNSServer.init(from:))

        var peer = PeerConfiguration(publicKey: peerKey)
        guard let endpoint = Endpoint(from: config.peerEndpoint) else {
            throw ConversionError.badEndpoint(config.peerEndpoint)
        }
        peer.endpoint = endpoint
        peer.allowedIPs = try config.allowedIps.map { value in
            guard let range = IPAddressRange(from: value) else {
                throw ConversionError.badAllowedIP(value)
            }
            return range
        }
        peer.persistentKeepAlive = config.persistentKeepalive

        return TunnelConfiguration(name: networkName, interface: interface, peers: [peer])
    }
}
