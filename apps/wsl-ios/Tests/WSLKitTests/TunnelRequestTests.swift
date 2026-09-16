import Foundation
import Testing
@testable import WSLKit

/// The extension runs with no user in front of it and can report nothing better
/// than a failure to start, so everything checkable is checked in the app.
@Suite struct TunnelRequestTests {
    private func config(
        address: String = "10.88.0.7/32",
        dns: [String] = ["10.88.0.53"],
        allowed: [String] = ["10.88.0.0/24", "10.90.0.0/16"],
        endpoint: String = "gw.example.com:51820"
    ) -> ClientWireGuardConfig {
        ClientWireGuardConfig(
            interfaceAddress: address,
            dns: dns,
            peerPublicKey: "cGVlcmtleQ==",
            peerEndpoint: endpoint,
            allowedIps: allowed,
            persistentKeepalive: 25
        )
    }

    @Test func aCompleteRequestIsAccepted() throws {
        let request = try TunnelRequest(
            config: config(), privateKey: "cHJpdmF0ZQ==", networkName: "development"
        )
        #expect(request.config.allowedIps.count == 2)
        #expect(request.networkName == "development")
    }

    /// A tunnel with no allowed IPs comes up and routes nothing, which looks to
    /// a user exactly like a working VPN that has broken the internet.
    @Test func noAllowedIPsIsRefused() {
        #expect(throws: TunnelRequest.ValidationError.emptyAllowedIPs) {
            try TunnelRequest(config: config(allowed: []), privateKey: "k", networkName: "n")
        }
    }

    @Test func noEndpointIsRefused() {
        #expect(throws: TunnelRequest.ValidationError.emptyEndpoint) {
            try TunnelRequest(config: config(endpoint: ""), privateKey: "k", networkName: "n")
        }
    }

    @Test func noPrivateKeyIsRefused() {
        #expect(throws: TunnelRequest.ValidationError.missingPrivateKey) {
            try TunnelRequest(config: config(), privateKey: "", networkName: "n")
        }
    }

    @Test func noAssignedAddressIsRefused() {
        #expect(throws: TunnelRequest.ValidationError.emptyInterfaceAddress) {
            try TunnelRequest(config: config(address: ""), privateKey: "k", networkName: "n")
        }
    }

    /// The two processes share nothing but these bytes.
    @Test func aRequestSurvivesTheTripToTheExtension() throws {
        let original = try TunnelRequest(
            config: config(), privateKey: "cHJpdmF0ZQ==", networkName: "development"
        )
        let restored = try TunnelRequest.decode(from: original.encoded())
        #expect(restored == original)
    }

    /// No resolvers is a legitimate answer from a gateway, and must survive the
    /// round trip as an empty list rather than becoming a decode failure.
    @Test func aGatewayThatSendsNoResolversRoundTrips() throws {
        let original = try TunnelRequest(
            config: config(dns: []), privateKey: "k", networkName: "n"
        )
        #expect(try TunnelRequest.decode(from: original.encoded()).config.dns.isEmpty)
    }
}
