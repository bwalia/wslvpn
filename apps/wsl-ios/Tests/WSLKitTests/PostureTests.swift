import Testing
@testable import WSLKit

@Suite struct PostureTests {
    /// The names are a contract with the control plane: a policy naming
    /// `disk_encryption` has to mean the same thing whichever client answers.
    @Test func everySignalTheAgentKnowsIsReported() {
        let names = Posture.collect(
            appVersion: "0.1.0", managedConfiguration: nil, passcodeSet: true
        ).map(\.name)
        for expected in [
            Posture.osVersion, Posture.agentVersion, Posture.diskEncryption,
            Posture.deviceManagement, Posture.firewall,
        ] {
            #expect(names.contains(expected), "\(expected) missing from \(names)")
        }
    }

    /// iOS always encrypts the file system, so "is the disk encrypted" is a
    /// question that always answers yes and means nothing. What decides whether
    /// data is protected at rest is the passcode.
    @Test func aPasscodeIsWhatMakesDataProtectionReal() {
        #expect(Posture.diskEncryptionSignal(passcodeSet: true).result == .pass)

        let without = Posture.diskEncryptionSignal(passcodeSet: false)
        #expect(without.result == .fail)
        #expect(without.detail?.contains("passcode") == true)
    }

    /// A managed configuration proves enrolment. Its absence proves nothing —
    /// an enrolled device whose administrator pushed no configuration is
    /// indistinguishable from an unenrolled one — so absence must not be `fail`.
    @Test func absentManagementIsUnknownRatherThanAFailure() {
        #expect(Posture.deviceManagementSignal(managedConfiguration: nil).result == .unknown)
        #expect(Posture.deviceManagementSignal(managedConfiguration: [:]).result == .unknown)
    }

    @Test func aManagedConfigurationProvesEnrolment() {
        let signal = Posture.deviceManagementSignal(
            managedConfiguration: ["control_plane_url": "https://vpn.example.com"]
        )
        #expect(signal.result == .pass)
    }

    /// There is no host firewall on iOS, and claiming otherwise either way
    /// would be inventing an answer.
    @Test func theFirewallIsUnsupportedNotFailing() {
        let signal = Posture.collect(
            appVersion: "0.1.0", managedConfiguration: nil, passcodeSet: true
        ).first { $0.name == Posture.firewall }
        #expect(signal?.result == .unsupported)
    }

    @Test func aFailingCheckIsNamedInTheSummary() {
        let signals = [
            PostureSignal(name: "disk_encryption", result: .fail),
            PostureSignal(name: "firewall", result: .unsupported),
        ]
        #expect(Posture.summarise(signals) == "Failing: disk_encryption")
    }

    @Test func aFailureOutranksAnUnknown() {
        let signals = [
            PostureSignal(name: "device_management", result: .unknown),
            PostureSignal(name: "disk_encryption", result: .fail),
        ]
        #expect(Posture.summarise(signals) == "Failing: disk_encryption")
    }

    @Test func anUnknownCheckIsNotCompliant() {
        let signals = [
            PostureSignal(name: "device_management", result: .unknown),
            PostureSignal(name: "disk_encryption", result: .pass),
        ]
        #expect(Posture.summarise(signals) == "Unknown: device_management")
    }

    @Test func unsupportedAloneStillReadsAsCompliant() {
        let signals = [
            PostureSignal(name: "disk_encryption", result: .pass),
            PostureSignal(name: "firewall", result: .unsupported),
        ]
        #expect(Posture.summarise(signals) == "Compliant")
    }

    @Test func noSignalsIsNotCompliance() {
        #expect(Posture.summarise([]) == "No signals")
    }
}
