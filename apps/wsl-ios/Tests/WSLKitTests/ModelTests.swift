import Foundation
import Testing
@testable import WSLKit

/// These fixtures are shaped exactly as `wsl-types` serialises: snake_case
/// fields, snake_case enum variants, RFC 3339 timestamps from chrono. Nothing
/// generates these models from the Rust source, so this is what stops the phone
/// drifting away from the wire contract.
@Suite struct ModelTests {
    @Test func aCreateSessionResponseDecodes() throws {
        let json = """
        {
          "session": {
            "id": "018f0c9e-0000-7000-8000-000000000001",
            "user_id": "018f0c9e-0000-7000-8000-000000000002",
            "device_id": "018f0c9e-0000-7000-8000-000000000003",
            "gateway_id": "018f0c9e-0000-7000-8000-000000000004",
            "network_id": "018f0c9e-0000-7000-8000-000000000005",
            "policy_id": null,
            "policy_version": null,
            "assigned_ip": "10.88.0.7",
            "status": "active",
            "created_at": "2026-09-16T12:00:00.123456Z",
            "expires_at": "2026-09-16T20:00:00.123456Z"
          },
          "decision": {
            "allow": true,
            "policy_id": null,
            "policy_name": "developers-development",
            "policy_version": 3,
            "git_commit": null,
            "reason": "matched access policy",
            "resources": ["development"],
            "session_duration_secs": 28800
          },
          "wireguard": {
            "interface_address": "10.88.0.7/32",
            "dns": ["10.88.0.53"],
            "peer_public_key": "cGVlcmtleQ==",
            "peer_endpoint": "gw.example.com:51820",
            "allowed_ips": ["10.88.0.0/24"],
            "persistent_keepalive": 25
          }
        }
        """
        let decoded = try Wire.decoder().decode(
            CreateSessionResponse.self, from: Data(json.utf8)
        )
        #expect(decoded.session.assignedIp == "10.88.0.7")
        #expect(decoded.session.status == .active)
        #expect(decoded.decision.allow)
        #expect(decoded.decision.policyVersion == 3)
        #expect(decoded.wireguard.persistentKeepalive == 25)
        #expect(decoded.wireguard.allowedIps == ["10.88.0.0/24"])
    }

    /// chrono's `to_rfc3339` emits fractional seconds. `.iso8601` alone rejects
    /// them, which would make every timestamped response fail to decode.
    @Test func timestampsDecodeWithAndWithoutAFraction() throws {
        #expect(RFC3339.date(from: "2026-09-16T20:00:00.123456Z") != nil)
        #expect(RFC3339.date(from: "2026-09-16T20:00:00Z") != nil)
        #expect(RFC3339.date(from: "not a date") == nil)
    }

    @Test func aDeniedDecisionCarriesItsReason() throws {
        let json = """
        {"allow": false, "policy_id": null, "policy_name": null,
         "policy_version": null, "git_commit": null,
         "reason": "device posture or managed requirements not met",
         "resources": [], "session_duration_secs": null}
        """
        let decoded = try Wire.decoder().decode(PolicyDecision.self, from: Data(json.utf8))
        #expect(!decoded.allow)
        #expect(decoded.reason.contains("posture"))
    }

    @Test func networksDecode() throws {
        let json = """
        [{"id": "018f0c9e-0000-7000-8000-000000000005", "name": "development",
          "cidr": "10.88.0.0/24", "dns_servers": ["10.88.0.53"],
          "dns_domains": ["internal.example.com"],
          "created_at": "2026-09-16T12:00:00Z", "updated_at": "2026-09-16T12:00:00Z"}]
        """
        let decoded = try Wire.decoder().decode([Network].self, from: Data(json.utf8))
        #expect(decoded.count == 1)
        #expect(decoded[0].name == "development")
        #expect(decoded[0].dnsDomains == ["internal.example.com"])
    }

    /// Posture goes the other way, and the control plane reads snake_case.
    @Test func postureEncodesAsTheControlPlaneReadsIt() throws {
        let signals = [PostureSignal(name: "disk_encryption", result: .fail, detail: "no passcode")]
        let data = try Wire.encoder().encode(signals)
        let text = String(decoding: data, as: UTF8.self)
        #expect(text.contains("\"disk_encryption\""))
        #expect(text.contains("\"fail\""))
    }

    @Test func aRegisterDeviceRequestRoundTripsThroughSnakeCase() throws {
        let request = RegisterDeviceRequest(
            name: "Test iPhone",
            platform: "ios",
            osVersion: "26.5",
            agentVersion: "0.1.0",
            wireguardPublicKey: "cHVibGlj",
            posture: []
        )
        let text = String(decoding: try Wire.encoder().encode(request), as: UTF8.self)
        #expect(text.contains("\"wireguard_public_key\""))
        #expect(text.contains("\"os_version\""))
        #expect(!text.contains("\"wireguardPublicKey\""))
    }

    @Test func aTokenResponseDecodes() throws {
        let json = """
        {"access_token": "abc", "token_type": "Bearer", "expires_in": 28800,
         "user_id": "018f0c9e-0000-7000-8000-000000000002", "email": "a@example.com"}
        """
        let decoded = try Wire.decoder().decode(TokenResponse.self, from: Data(json.utf8))
        #expect(decoded.accessToken == "abc")
        #expect(decoded.email == "a@example.com")
    }
}
