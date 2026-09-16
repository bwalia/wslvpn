import Foundation
import NetworkExtension
import WSLKit
import WireGuardKit
import os

/// The packet tunnel.
///
/// This runs in its own process, started by the system — sometimes while the
/// screen is locked, sometimes long after the app was last opened, sometimes
/// because traffic matched an on-demand rule. It cannot assume the app is
/// running, cannot show UI, and is killed without ceremony if it uses too much
/// memory. So it does one thing: read the configuration the app left for it,
/// hand it to WireGuard, and report what happened.
///
/// Everything that needs a decision — signing in, choosing a network, creating
/// a session — happens in the app, which has a user in front of it.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private lazy var adapter: WireGuardAdapter = {
        WireGuardAdapter(with: self) { logLevel, message in
            wg_log(logLevel == .verbose ? .debug : .info, message: message)
        }
    }()

    private let log = Logger(subsystem: "io.wsl.zerotrust.ios.tunnel", category: "tunnel")

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        // The request travels in the provider configuration, which the app
        // wrote into the system's VPN preferences. It carries the interface
        // private key, which is why the app writes it at the moment it starts
        // the tunnel and clears it on stop, rather than leaving it in
        // preferences indefinitely.
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let encoded = proto.providerConfiguration?[
                TunnelRequest.providerConfigurationKey] as? Data
        else {
            log.error("no configuration in the tunnel protocol")
            completionHandler(TunnelError.noConfiguration)
            return
        }

        let configuration: TunnelConfiguration
        do {
            configuration = try TunnelRequest.decode(from: encoded).wireGuardConfiguration()
        } catch {
            // Logged rather than swallowed: this process has no UI, and a
            // failure here is otherwise indistinguishable from the tunnel
            // simply not starting.
            log.error("unusable configuration: \(error.localizedDescription, privacy: .public)")
            completionHandler(error)
            return
        }

        adapter.start(tunnelConfiguration: configuration) { [weak self] error in
            if let error {
                self?.log.error("wireguard failed to start: \(String(describing: error))")
                completionHandler(error)
                return
            }
            self?.log.info("tunnel up")
            completionHandler(nil)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        log.info("stopping: \(String(describing: reason), privacy: .public)")
        adapter.stop { [weak self] error in
            if let error {
                self?.log.error("stop failed: \(String(describing: error))")
            }
            completionHandler()
        }
    }

    /// Answers the app's request for runtime statistics.
    ///
    /// The app cannot read the tunnel's state directly — separate process — so
    /// this is the channel. It returns WireGuard's own transfer counters, which
    /// is how the app can tell a tunnel that is up from one that is up and
    /// actually passing traffic.
    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        guard let completionHandler else { return }
        guard String(decoding: messageData, as: UTF8.self) == "runtime-configuration" else {
            completionHandler(nil)
            return
        }
        adapter.getRuntimeConfiguration { settings in
            completionHandler(settings.map { Data($0.utf8) })
        }
    }

    enum TunnelError: Error, LocalizedError {
        case noConfiguration

        var errorDescription: String? {
            switch self {
            case .noConfiguration:
                return "The tunnel was started without a configuration."
            }
        }
    }
}

private func wg_log(_ level: OSLogType, message: String) {
    os_log(level, log: .default, "%{public}s", message)
}
