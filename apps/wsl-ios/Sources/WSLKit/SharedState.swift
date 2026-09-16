import Foundation

/// The small amount of state the app and the tunnel extension both need.
///
/// Not the private key — that is in the keychain — and not the access token.
/// Only what the extension needs to bring an interface up: the rendered
/// configuration, and which network it belongs to.
///
/// It goes in the app group container rather than being passed in the tunnel's
/// provider configuration, because a provider configuration is written by the
/// app into the system's VPN preferences and is visible there. This is not
/// secret, but it does not need to be published either.
public struct TunnelState: Codable, Sendable, Equatable {
    public let networkName: String
    public let assignedIP: String
    public let expiresAt: Date

    public init(networkName: String, assignedIP: String, expiresAt: Date) {
        self.networkName = networkName
        self.assignedIP = assignedIP
        self.expiresAt = expiresAt
    }
}

/// Not `Sendable`: `UserDefaults` is thread-safe but is not marked as such, and
/// claiming otherwise here would be this type vouching for a promise Foundation
/// has not made. Both callers are main-actor bound.
public struct SharedStore {
    public static let appGroup = "group.io.wsl.zerotrust"

    private let defaults: UserDefaults?

    public init(appGroup: String = SharedStore.appGroup) {
        self.defaults = UserDefaults(suiteName: appGroup)
    }

    /// True when the app group is actually available.
    ///
    /// `UserDefaults(suiteName:)` returns nil when the entitlement is missing,
    /// which on a misconfigured build is silent and looks like "nothing was
    /// ever saved". The app surfaces it instead.
    public var isAvailable: Bool { defaults != nil }

    public var tunnelState: TunnelState? {
        get {
            guard let data = defaults?.data(forKey: "tunnel-state") else { return nil }
            return try? Wire.decoder().decode(TunnelState.self, from: data)
        }
        nonmutating set {
            guard let defaults else { return }
            if let newValue, let data = try? Wire.encoder().encode(newValue) {
                defaults.set(data, forKey: "tunnel-state")
            } else {
                defaults.removeObject(forKey: "tunnel-state")
            }
        }
    }
}
