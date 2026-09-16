import Foundation

/// Storage for the two secrets this app holds: the control-plane access token
/// and the device's WireGuard private key.
///
/// Both live in the keychain rather than `UserDefaults`, and in a shared access
/// group, because the tunnel extension is a separate process and needs the
/// private key. The app group container would also be shared, but it is an
/// ordinary directory: readable by anything that can read the container, and
/// backed up. The keychain is neither.
///
/// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` is the accessibility
/// class. The tunnel has to be able to start on demand while the screen is
/// locked, so `WhenUnlocked` is not usable; `ThisDeviceOnly` keeps the item out
/// of backups and off any other device.
public struct Keychain: Sendable {
    public enum Item: String, Sendable {
        case accessToken = "control-plane-access-token"
        case wireguardPrivateKey = "wireguard-private-key"
    }

    public enum KeychainError: Error, LocalizedError {
        case unexpectedStatus(OSStatus)

        public var errorDescription: String? {
            switch self {
            case .unexpectedStatus(let status):
                let message = SecCopyErrorMessageString(status, nil) as String?
                return "Keychain error \(status): \(message ?? "unknown")"
            }
        }
    }

    private let service: String
    private let accessGroup: String?

    public init(service: String = "io.wsl.zerotrust", accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    private func query(for item: Item) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: item.rawValue,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }

    public func set(_ value: String, for item: Item) throws {
        // Delete first rather than branching on whether it exists: SecItemAdd
        // and SecItemUpdate take different attribute sets, and getting that
        // wrong fails in ways that look like the value was written.
        SecItemDelete(query(for: item) as CFDictionary)

        var attributes = query(for: item)
        attributes[kSecValueData as String] = Data(value.utf8)
        attributes[kSecAttrAccessible as String] =
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.unexpectedStatus(status) }
    }

    public func get(_ item: Item) -> String? {
        var query = query(for: item)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data
        else { return nil }
        return String(data: data, encoding: .utf8)
    }

    public func remove(_ item: Item) {
        SecItemDelete(query(for: item) as CFDictionary)
    }

    /// Return the stored private key, creating one on first use.
    ///
    /// Generating here rather than at registration means the key exists before
    /// anything tries to register its public half, and that a re-registration
    /// reuses the key the gateway already knows.
    public func wireguardKeypair() throws -> WireGuardKeypair {
        if let stored = get(.wireguardPrivateKey),
           let pair = WireGuardKeypair(privateKeyBase64: stored) {
            return pair
        }
        let generated = WireGuardKeypair()
        try set(generated.privateKey, for: .wireguardPrivateKey)
        return generated
    }
}
