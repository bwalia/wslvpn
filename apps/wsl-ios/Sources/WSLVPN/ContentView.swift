import AuthenticationServices
import SwiftUI
import WSLKit

struct ContentView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        NavigationStack {
            Group {
                switch model.phase {
                case .loading:
                    ProgressView("Loading")
                case .signedOut:
                    SignInView()
                case .signedIn:
                    StatusView()
                }
            }
            .navigationTitle("WSL Zero Trust")
        }
    }
}

struct SignInView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "lock.shield")
                .font(.system(size: 56))
                .foregroundStyle(.tint)
            Text("Secure access to your organisation's services")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)

            Button {
                Task { await model.signIn(anchor: ASPresentationAnchor()) }
            } label: {
                Text("Sign in")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(model.busy)

            if model.busy {
                Text("Finish signing in in the browser.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            ErrorText()
            Spacer()
        }
        .padding()
    }
}

struct StatusView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model

        List {
            Section {
                LabeledContent("Status", value: model.tunnelStatus.label)
                if let state = model.sessionState {
                    LabeledContent("Network", value: state.networkName)
                    LabeledContent("Address", value: state.assignedIP)
                    LabeledContent("Expires", value: state.expiresAt.formatted(date: .abbreviated, time: .shortened))
                }
                if let email = model.email {
                    LabeledContent("Signed in", value: email)
                }
            }

            Section("Posture") {
                LabeledContent("Summary", value: model.postureSummary)
                ForEach(model.posture) { signal in
                    PostureRow(signal: signal)
                }
            }

            if model.tunnelStatus != .connected {
                Section("Connect") {
                    if model.networks.count > 1 {
                        Picker("Network", selection: $model.selectedNetwork) {
                            ForEach(model.networks) { network in
                                Text(network.name).tag(Optional(network))
                            }
                        }
                    }
                    Button("Connect") { Task { await model.connect() } }
                        .disabled(model.busy || model.selectedNetwork == nil)
                }
            } else {
                Section {
                    Button("Disconnect", role: .destructive) {
                        Task { await model.disconnect() }
                    }
                    .disabled(model.busy)
                }
            }

            Section {
                Button("Sign out") { Task { await model.signOut() } }
                    .disabled(model.busy)
            } footer: {
                ErrorText()
            }
        }
        .refreshable { await model.refreshNetworks() }
    }
}

struct PostureRow: View {
    let signal: PostureSignal

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Image(systemName: symbol)
                .foregroundStyle(tint)
                .accessibilityLabel(signal.result.rawValue)
            VStack(alignment: .leading, spacing: 2) {
                Text(signal.name.replacingOccurrences(of: "_", with: " ").capitalized)
                if let detail = signal.detail {
                    Text(detail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var symbol: String {
        switch signal.result {
        case .pass: return "checkmark.circle.fill"
        case .fail: return "xmark.circle.fill"
        case .unknown: return "questionmark.circle.fill"
        case .unsupported: return "minus.circle"
        }
    }

    private var tint: Color {
        switch signal.result {
        case .pass: return .green
        case .fail: return .red
        case .unknown: return .orange
        case .unsupported: return .secondary
        }
    }
}

struct ErrorText: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if let message = model.errorMessage {
            Text(message)
                .font(.footnote)
                .foregroundStyle(.red)
        }
    }
}
