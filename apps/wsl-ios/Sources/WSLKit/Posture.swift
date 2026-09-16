import Foundation
import LocalAuthentication
#if canImport(UIKit)
import UIKit
#endif

/// What an iOS device can honestly say about itself.
///
/// The names match the agent's, because a policy naming `disk_encryption` has
/// to mean the same thing whichever client answers it.
///
/// iOS gives an app far less to work with than macOS does, and the gaps are
/// reported as `unknown` or `unsupported` rather than filled in with a guess.
/// There is no public API for MDM enrolment and none for the firewall, because
/// there is no firewall. Saying so is the point: the control plane decides what
/// an unanswered question is worth, and it will not be fooled by a `pass` this
/// framework was not entitled to send.
public enum Posture {
    public static let diskEncryption = "disk_encryption"
    public static let deviceManagement = "device_management"
    public static let firewall = "firewall"
    public static let osVersion = "os_version"
    public static let agentVersion = "agent_version"

    /// The key an MDM server's app configuration arrives under.
    static let managedConfigurationKey = "com.apple.configuration.managed"

    /// Read every signal from the device.
    public static func collect() -> [PostureSignal] {
        collect(
            appVersion: Bundle.main.shortVersion,
            managedConfiguration: UserDefaults.standard.dictionary(forKey: managedConfigurationKey),
            passcodeSet: devicePasscodeIsSet()
        )
    }

    /// The same, from given inputs, so the shape of the report can be asserted
    /// without the simulator the suite runs on deciding it.
    static func collect(
        appVersion: String,
        managedConfiguration: [String: Any]?,
        passcodeSet: Bool
    ) -> [PostureSignal] {
        [
            PostureSignal(name: osVersion, result: .pass, detail: systemVersion()),
            PostureSignal(name: agentVersion, result: .pass, detail: appVersion),
            diskEncryptionSignal(passcodeSet: passcodeSet),
            deviceManagementSignal(managedConfiguration: managedConfiguration),
            PostureSignal(
                name: firewall,
                result: .unsupported,
                detail: "iOS has no host firewall to query"
            ),
        ]
    }

    /// Data Protection is only as good as the passcode behind it.
    ///
    /// iOS encrypts the file system unconditionally, so asking "is the disk
    /// encrypted" always answers yes and means nothing. What actually decides
    /// whether data is protected at rest is whether a passcode is set — without
    /// one the class keys are available whenever the device is powered on. That
    /// is the question this signal answers, and the detail says so, because an
    /// administrator reading an audit log should not think FileVault.
    static func diskEncryptionSignal(passcodeSet: Bool) -> PostureSignal {
        PostureSignal(
            name: diskEncryption,
            result: passcodeSet ? .pass : .fail,
            detail: passcodeSet
                ? "Data Protection active; device passcode is set"
                : "No device passcode, so Data Protection keys are always available"
        )
    }

    /// There is no public API that reports MDM enrolment.
    ///
    /// The closest an app can get is a managed app configuration, which an MDM
    /// server can push. Its presence proves enrolment; its absence proves
    /// nothing — an enrolled device whose administrator never pushed a
    /// configuration looks identical to an unenrolled one. So absence is
    /// `unknown` rather than `fail`, and a policy that needs a real answer
    /// should require the signal by name and have the MDM push a configuration.
    static func deviceManagementSignal(managedConfiguration: [String: Any]?) -> PostureSignal {
        guard let configuration = managedConfiguration, !configuration.isEmpty else {
            return PostureSignal(
                name: deviceManagement,
                result: .unknown,
                detail: "No managed app configuration; iOS exposes no way to ask whether the device is enrolled"
            )
        }
        return PostureSignal(
            name: deviceManagement,
            result: .pass,
            detail: "Managed app configuration present (\(configuration.count) key(s))"
        )
    }

    static func devicePasscodeIsSet() -> Bool {
        var error: NSError?
        // `.deviceOwnerAuthentication` succeeds when a passcode is set, with or
        // without a biometric enrolled. `.deviceOwnerAuthenticationWithBiometrics`
        // would fail on a passcode-only device, which is not what is being asked.
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
    }

    static func systemVersion() -> String {
        #if canImport(UIKit)
        return "\(UIDevice.current.systemName) \(UIDevice.current.systemVersion)"
        #else
        return ProcessInfo.processInfo.operatingSystemVersionString
        #endif
    }

    /// Reduce the signals to one line, the way the agent does.
    ///
    /// A failing check is what a user needs first and an unanswered one second,
    /// and naming them beats counting them: "Failing" on its own tells someone
    /// they are blocked and nothing about what to do next.
    public static func summarise(_ signals: [PostureSignal]) -> String {
        let named = { (result: PostureResult) in
            signals.filter { $0.result == result }.map(\.name)
        }
        let failed = named(.fail)
        if !failed.isEmpty { return "Failing: \(failed.joined(separator: ", "))" }
        let unknown = named(.unknown)
        if !unknown.isEmpty { return "Unknown: \(unknown.joined(separator: ", "))" }
        if signals.isEmpty { return "No signals" }
        return "Compliant"
    }
}

extension Bundle {
    public var shortVersion: String {
        object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.0"
    }
}
