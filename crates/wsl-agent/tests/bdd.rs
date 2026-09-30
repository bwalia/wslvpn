//! Step definitions for tests/features/connect.feature.
//!
//! The agent runs for real against two stand-ins:
//!
//! * a control plane — an axum server on loopback speaking the real API types;
//! * `wg-quick` — a shell script that records what it was asked to do, and
//!   "brings up" the loopback interface by writing its name where macOS's
//!   `wg-quick` records the `utun` it picked. The agent then finds that
//!   interface through the same unprivileged check it uses in production.
//!
//! Only the kernel's half of `wg-quick` is faked. Everything the agent does —
//! the privileged command line, the config it writes, the order of teardown
//! and release — is the production path.
//!
//! State lives in a fresh `WSL_DATA_DIR` per scenario, and scenarios run one
//! at a time because the environment is process-wide.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::{Path as UrlPath, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::Utc;
use cucumber::{given, then, when, World};
use uuid::Uuid;
use wsl_agent::tunnel::{self, TunnelState};
use wsl_agent::{profile, AgentState, ControlClient, Escalation, Mode};
use wsl_types::{
    ClientWireGuardConfig, CreateSessionRequest, CreateSessionResponse, Device, Network,
    PolicyDecision, RegisterDeviceRequest, RegisterDeviceResponse, Session, SessionStatus,
};

const PRIVATE: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const SERVER: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

/// The interface the fake brings "up": one that certainly exists.
const LOOPBACK: &str = if cfg!(target_os = "macos") {
    "lo0"
} else {
    "lo"
};

#[derive(Default)]
struct Plane {
    networks: Vec<Network>,
    refuse: Option<String>,
    devices: Vec<RegisterDeviceRequest>,
    sessions: Vec<(Uuid, CreateSessionRequest)>,
    released: Vec<Uuid>,
    /// Shared with the fake wg-quick, so the order of events is observable.
    events: PathBuf,
}

type Shared = Arc<Mutex<Plane>>;

async fn dev_login() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "access_token": "test-token",
        "user_id": Uuid::nil(),
        "email": "alice@example.com",
    }))
}

async fn register(
    State(plane): State<Shared>,
    Json(req): Json<RegisterDeviceRequest>,
) -> Json<RegisterDeviceResponse> {
    let device = Device {
        id: Uuid::new_v4(),
        user_id: Uuid::nil(),
        name: req.name.clone(),
        platform: req.platform.clone(),
        os_version: req.os_version.clone(),
        agent_version: req.agent_version.clone(),
        wireguard_public_key: req.wireguard_public_key.clone(),
        revoked: false,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    plane.lock().unwrap().devices.push(req);
    Json(RegisterDeviceResponse {
        device,
        certificate_pem: String::new(),
        expires_at: Utc::now() + chrono::Duration::days(30),
    })
}

async fn list_networks(State(plane): State<Shared>) -> Json<Vec<Network>> {
    Json(plane.lock().unwrap().networks.clone())
}

async fn create_session(
    State(plane): State<Shared>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<Json<CreateSessionResponse>, (StatusCode, String)> {
    let mut plane = plane.lock().unwrap();
    if let Some(reason) = &plane.refuse {
        return Err((StatusCode::FORBIDDEN, reason.clone()));
    }
    let id = Uuid::new_v4();
    plane.sessions.push((id, req.clone()));
    Ok(Json(CreateSessionResponse {
        session: Session {
            id,
            user_id: Uuid::nil(),
            device_id: req.device_id,
            gateway_id: Uuid::nil(),
            network_id: req.network_id,
            policy_id: None,
            policy_version: Some(3),
            assigned_ip: "10.80.0.7".into(),
            status: SessionStatus::Active,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(8),
        },
        decision: PolicyDecision {
            allow: true,
            policy_id: None,
            policy_name: Some("engineering".into()),
            policy_version: Some(3),
            git_commit: None,
            reason: "allowed".into(),
            resources: vec![],
            session_duration_secs: Some(28800),
        },
        wireguard: ClientWireGuardConfig {
            interface_address: "10.80.0.7/32".into(),
            dns: vec!["10.80.0.1".into()],
            peer_public_key: SERVER.into(),
            peer_endpoint: "gw.example.com:51820".into(),
            allowed_ips: vec!["10.80.0.0/16".into()],
            persistent_keepalive: 25,
        },
    }))
}

async fn release(State(plane): State<Shared>, UrlPath(id): UrlPath<Uuid>) -> StatusCode {
    let mut plane = plane.lock().unwrap();
    plane.released.push(id);
    let line = format!("release {id}\n");
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&plane.events)
        .unwrap();
    f.write_all(line.as_bytes()).unwrap();
    StatusCode::NO_CONTENT
}

#[derive(Debug, World)]
#[world(init = Self::new)]
struct Agent {
    dir: PathBuf,
    plane: Option<(Shared, SocketAddr, tokio::task::JoinHandle<()>)>,
    state: AgentState,
    error: Option<String>,
}

impl std::fmt::Debug for Plane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plane").finish_non_exhaustive()
    }
}

impl Agent {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "wsl-agent-bdd-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(dir.join("run")).unwrap();
        std::env::set_var("WSL_DATA_DIR", &dir);
        std::env::set_var(tunnel::RUN_DIR_ENV, dir.join("run"));
        std::env::set_var(tunnel::PRIVILEGE_ENV, "direct");
        std::env::remove_var(tunnel::WG_QUICK_ENV);
        Self {
            dir,
            plane: None,
            state: AgentState::load().unwrap(),
            error: None,
        }
    }

    fn events(&self) -> PathBuf {
        self.dir.join("events.log")
    }

    fn event_lines(&self) -> Vec<String> {
        std::fs::read_to_string(self.events())
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect()
    }

    fn wg_quick_actions(&self) -> Vec<String> {
        self.event_lines()
            .into_iter()
            .filter_map(|l| {
                l.strip_prefix("wg-quick ")
                    .map(|a| a.split(' ').next().unwrap().to_string())
            })
            .collect()
    }

    fn plane(&self) -> &Shared {
        &self.plane.as_ref().expect("a control plane").0
    }

    fn reload(&mut self) {
        self.state = AgentState::load().unwrap();
    }

    fn status(&self) -> wsl_agent::AgentStatus {
        self.state.status_with_posture(&tunnel::state(), Vec::new())
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        if let Some((_, _, task)) = self.plane.take() {
            task.abort();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn config_with(extra: Option<&str>) -> String {
    let mut text = format!("[Interface]\nPrivateKey = {PRIVATE}\nAddress = 10.8.0.2/32\n");
    if let Some(line) = extra {
        text.push_str(line);
        text.push('\n');
    }
    text.push_str(&format!(
        "DNS = 10.8.0.1\n\n[Peer]\nPublicKey = {SERVER}\nEndpoint = vpn.example.com:51820\nAllowedIPs = 10.8.0.0/24\n"
    ));
    text
}

#[given("wg-quick is installed")]
fn wg_quick_installed(w: &mut Agent) {
    let script = w.dir.join("wg-quick");
    let body = format!(
        r#"#!/bin/sh
# A stand-in for wg-quick: records, then "brings up" loopback.
echo "wg-quick $1 $2" >> "{events}"
case "$1" in
  up)
    if [ -f "{dir}/fail-up" ]; then cat "{dir}/fail-up" >&2; exit 1; fi
    cp "$2" "{dir}/conf-at-up"
    echo {LOOPBACK} > "{run}/wsl.name" ;;
  down)
    rm -f "{run}/wsl.name" ;;
esac
"#,
        events = w.events().display(),
        dir = w.dir.display(),
        run = w.dir.join("run").display(),
    );
    std::fs::write(&script, body).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::env::set_var(tunnel::WG_QUICK_ENV, &script);
}

#[given(expr = "wg-quick will fail with {string}")]
fn wg_quick_fails(w: &mut Agent, message: String) {
    std::fs::write(w.dir.join("fail-up"), message).unwrap();
}

#[given(expr = "I have imported the WireGuard config {string}")]
fn imported(w: &mut Agent, name: String) {
    profile::import(&mut w.state, &config_with(None), &name).expect("import");
}

#[when(expr = "I import a WireGuard config containing {string}")]
fn import_containing(w: &mut Agent, line: String) {
    w.error = profile::import(&mut w.state, &config_with(Some(&line)), "x")
        .err()
        .map(|e| format!("{e:#}"));
}

async fn start_plane(w: &mut Agent, networks: Vec<Network>) {
    let plane: Shared = Arc::new(Mutex::new(Plane {
        networks,
        events: w.events(),
        ..Default::default()
    }));
    let app = Router::new()
        .route("/auth/dev/login", post(dev_login))
        .route("/api/v1/devices/register", post(register))
        .route("/api/v1/networks", get(list_networks))
        .route("/api/v1/sessions", post(create_session))
        .route("/api/v1/sessions/{id}", delete(release))
        .with_state(plane.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    w.plane = Some((plane, addr, task));
}

#[given(expr = "the control plane offers the network {string}")]
async fn plane_offers(w: &mut Agent, name: String) {
    start_plane(
        w,
        vec![Network {
            id: Uuid::new_v4(),
            name,
            cidr: "10.80.0.0/16".into(),
            dns_servers: vec![],
            dns_domains: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }],
    )
    .await;
}

#[given(expr = "I am signed in as {string}")]
async fn signed_in(w: &mut Agent, email: String) {
    let addr = w.plane.as_ref().expect("a control plane").1;
    w.state.set_control_url(&format!("http://{addr}")).unwrap();
    let client = ControlClient::new();
    client.dev_login(&mut w.state, &email).await.expect("login");
    client.ensure_device(&mut w.state).await.expect("register");
}

#[given(expr = "the control plane will refuse sessions with {string}")]
fn plane_refuses(w: &mut Agent, reason: String) {
    w.plane().lock().unwrap().refuse = Some(reason);
}

#[given("the control plane is unreachable")]
fn plane_unreachable(w: &mut Agent) {
    if let Some((_, _, task)) = w.plane.take() {
        task.abort();
    }
    // Port 1 on loopback: nothing listens, so the connection is refused.
    w.state.control_url = "http://127.0.0.1:1".into();
    w.state.save().unwrap();
}

async fn connect(w: &mut Agent) -> Result<(), String> {
    let result = if w.state.mode() == Mode::Direct {
        profile::connect(&w.state, Escalation::None)
            .await
            .map(|_| ())
    } else {
        ControlClient::new()
            .connect_and_bring_up(&mut w.state, None, Escalation::None)
            .await
            .map(|_| ())
    };
    w.reload();
    result.map_err(|e| format!("{e:#}"))
}

#[given("I am connected")]
async fn connected(w: &mut Agent) {
    connect(w).await.expect("connect");
    assert!(tunnel::state().is_up());
}

#[when("I connect")]
async fn when_connect(w: &mut Agent) {
    w.error = connect(w).await.err();
}

#[when("I disconnect")]
async fn when_disconnect(w: &mut Agent) {
    let result = if w.state.mode() == Mode::Direct {
        profile::disconnect(Escalation::None).await
    } else {
        ControlClient::new()
            .disconnect_and_tear_down(&mut w.state, Escalation::None)
            .await
    };
    w.reload();
    w.error = result.err().map(|e| format!("{e:#}"));
}

#[then("the tunnel is up")]
fn tunnel_up(w: &mut Agent) {
    assert_eq!(w.error, None);
    assert_eq!(
        tunnel::state(),
        TunnelState::Up {
            interface: LOOPBACK.into()
        }
    );
}

#[then("the tunnel is down")]
fn tunnel_down(w: &mut Agent) {
    assert_eq!(tunnel::state(), TunnelState::Down, "error: {:?}", w.error);
}

#[then("wg-quick brought up exactly the config I imported")]
fn brought_up_imported(w: &mut Agent) {
    let used = std::fs::read_to_string(w.dir.join("conf-at-up")).unwrap();
    assert_eq!(used, config_with(None));
}

#[then(expr = "the status says {string} is {string}")]
fn status_says(w: &mut Agent, name: String, state: String) {
    let status = w.status();
    let row = status
        .networks
        .iter()
        .find(|n| n.name == name)
        .unwrap_or_else(|| panic!("no network {name} in {:?}", status.networks));
    assert_eq!(row.state, state);
}

#[then(expr = "the status mode is {string}")]
fn status_mode(w: &mut Agent, mode: String) {
    let json = serde_json::to_value(w.status()).unwrap();
    assert_eq!(json["mode"], mode);
}

#[then(expr = "wg-quick ran {string} and then {string}")]
fn ran_in_order(w: &mut Agent, first: String, second: String) {
    let actions = w.wg_quick_actions();
    let tail: Vec<&str> = actions
        .iter()
        .rev()
        .take(2)
        .rev()
        .map(String::as_str)
        .collect();
    assert_eq!(tail, vec![first.as_str(), second.as_str()], "{actions:?}");
}

#[then(expr = "it fails mentioning {string}")]
fn fails_mentioning(w: &mut Agent, text: String) {
    let error = w.error.as_deref().expect("an error");
    assert!(error.contains(&text), "{error:?} does not mention {text:?}");
}

#[then("no profile is imported")]
fn no_profile(w: &mut Agent) {
    w.reload();
    assert!(w.state.profile.is_none());
    assert!(!profile::profile_conf_path().unwrap().exists());
}

#[then("the control plane issued a session for this device")]
fn session_issued(w: &mut Agent) {
    let plane = w.plane().lock().unwrap();
    assert_eq!(plane.sessions.len(), 1);
    assert_eq!(Some(plane.sessions[0].1.device_id), w.state.device_id);
    assert_eq!(
        w.state.session.as_ref().map(|s| s.id),
        Some(plane.sessions[0].0)
    );
}

#[then("the WireGuard config on disk is readable only by me")]
fn config_private(_w: &mut Agent) {
    use std::os::unix::fs::PermissionsExt;
    let path = AgentState::wg_conf_path().unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{:o}", mode);
    let text = std::fs::read_to_string(path).unwrap();
    assert!(text.contains("Endpoint = gw.example.com:51820"), "{text}");
}

#[then("the control plane released the session")]
fn released(w: &mut Agent) {
    let plane = w.plane().lock().unwrap();
    assert_eq!(plane.released.len(), 1);
    assert_eq!(plane.released[0], plane.sessions[0].0);
    assert!(w.state.session.is_none());
}

#[then("the tunnel went down before the session was released")]
fn down_before_release(w: &mut Agent) {
    let lines = w.event_lines();
    let down = lines.iter().position(|l| l.starts_with("wg-quick down"));
    let release = lines.iter().position(|l| l.starts_with("release"));
    assert!(
        matches!((down, release), (Some(d), Some(r)) if d < r),
        "{lines:?}"
    );
}

#[then("wg-quick was never run")]
fn never_ran(w: &mut Agent) {
    assert!(w.wg_quick_actions().is_empty(), "{:?}", w.event_lines());
}

#[tokio::main]
async fn main() {
    Agent::cucumber()
        .max_concurrent_scenarios(1)
        .fail_on_skipped()
        .run_and_exit("tests/features")
        .await;
}
