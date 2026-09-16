import Foundation
import NetworkExtension
import WSLKit

/// Owns the system VPN configuration and the tunnel's lifecycle.
///
/// The app does not start a tunnel directly; it installs a configuration into
/// the system's VPN preferences and asks the system to start it. That
/// indirection is the reason a tunnel can come back after a reboot without the
/// app being opened, and the reason the user sees a system prompt the first
/// time rather than the app quietly gaining the ability to see their traffic.
@MainActor
public final class TunnelController {
    public enum ControllerError: Error, LocalizedError {
        case noManager

        public var errorDescription: String? {
            switch self {
            case .noManager:
                return "The VPN configuration has not been installed yet."
            }
        }
    }

    private let tunnelBundleIdentifier = "io.wsl.zerotrust.ios.tunnel"
    private var manager: NETunnelProviderManager?

    public init() {}

    /// The system's view of the tunnel, which is the only view that counts.
    public var status: NEVPNStatus {
        manager?.connection.status ?? .invalid
    }

    public func load() async throws {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        manager = managers.first
    }

    /// Install or update the configuration, then start it.
    ///
    /// The rendered configuration carries the interface private key, so it is
    /// written at the moment of connecting and removed on disconnect rather
    /// than left in the system's VPN preferences between sessions.
    public func start(request: TunnelRequest, serverDescription: String) async throws {
        let manager = try await existingOrNewManager()

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = tunnelBundleIdentifier
        // Shown in Settings › VPN. It has to be non-empty or the configuration
        // is rejected without explanation.
        proto.serverAddress = serverDescription
        proto.providerConfiguration = [
            TunnelRequest.providerConfigurationKey: try request.encoded()
        ]

        manager.protocolConfiguration = proto
        manager.localizedDescription = "WSL Zero Trust"
        manager.isEnabled = true
        // Deliberately not enabling on-demand. A VPN that reconnects itself
        // whenever the phone sees a network is a decision for an administrator
        // pushing a profile, not a default this app should take on a user's
        // behalf.
        manager.isOnDemandEnabled = false

        try await manager.saveToPreferences()
        // Reload after saving: the saved object is stale and starting from it
        // fails with a permission error that reads like an entitlement problem.
        try await manager.loadFromPreferences()

        try manager.connection.startVPNTunnel()
        self.manager = manager
    }

    public func stop() async throws {
        guard let manager else { throw ControllerError.noManager }
        manager.connection.stopVPNTunnel()

        // Clear the key-bearing configuration rather than leaving it installed.
        if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol {
            proto.providerConfiguration = [:]
            manager.protocolConfiguration = proto
            manager.isEnabled = false
            try? await manager.saveToPreferences()
        }
    }

    private func existingOrNewManager() async throws -> NETunnelProviderManager {
        if let manager { return manager }
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        return managers.first ?? NETunnelProviderManager()
    }
}

extension NEVPNStatus {
    public var label: String {
        switch self {
        case .invalid: return "Not installed"
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting"
        case .connected: return "Connected"
        case .reasserting: return "Reconnecting"
        case .disconnecting: return "Disconnecting"
        @unknown default: return "Unknown"
        }
    }

    public var isBusy: Bool {
        self == .connecting || self == .disconnecting || self == .reasserting
    }
}
