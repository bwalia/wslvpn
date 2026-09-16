// The window is a view over `wsl status --json`. It holds no state of its own:
// every render is driven by what the agent just reported, so the dot in the
// title bar cannot say "connected" while the interface is down.

const POLL_INTERVAL_MS = 5000;

const el = (id) => document.getElementById(id);
const panels = {
  loading: el("loading"),
  signedOut: el("signed-out"),
  signedIn: el("signed-in"),
  noCli: el("no-cli"),
};

let polling = null;
let busy = false;

async function invoke(command, args = {}) {
  if (!window.__TAURI_INTERNALS__) {
    throw {
      kind: "command_failed",
      message: "This page only works inside the desktop app.",
    };
  }
  const { invoke: tauriInvoke } = await import("@tauri-apps/api/core");
  return tauriInvoke(command, args);
}

function show(panel) {
  for (const [name, node] of Object.entries(panels)) {
    node.hidden = name !== panel;
  }
}

function setError(id, error) {
  const node = el(id);
  if (!error) {
    node.hidden = true;
    node.textContent = "";
    return;
  }
  node.hidden = false;
  node.textContent = error.message ?? String(error);
}

function setFact(id, value, { optional = false } = {}) {
  const node = el(id);
  const label = el(`${id}-label`);
  if (optional) {
    const present = Boolean(value);
    node.hidden = !present;
    if (label) label.hidden = !present;
    if (!present) return;
  }
  node.textContent = value ?? "—";
}

// A session record and a live interface are different things, and the agent
// reports them separately. The UI keeps them separate too: "Session open,
// tunnel down" is a real state a user needs to see, not a rounding error.
function renderNetworks(status) {
  const list = el("networks");
  list.innerHTML = "";
  if (!status.networks || status.networks.length === 0) {
    const row = document.createElement("li");
    row.className = "empty";
    row.innerHTML = "<span>No networks</span>";
    list.append(row);
    return;
  }
  for (const network of status.networks) {
    const row = document.createElement("li");
    const name = document.createElement("span");
    name.textContent = network.name;
    const state = document.createElement("span");
    state.textContent = network.state;
    state.className = network.state === "Connected" ? "ok" : "warn";
    row.append(name, state);
    list.append(row);
  }
}

async function renderNetworkChoices(connected) {
  const field = el("network-field");
  const select = el("network-choice");
  if (connected) {
    field.hidden = true;
    return;
  }
  try {
    const networks = await invoke("networks");
    select.innerHTML = "";
    for (const network of networks) {
      const option = document.createElement("option");
      option.value = network.name;
      option.textContent = `${network.name} — ${network.cidr}`;
      select.append(option);
    }
    // One network is not a choice; offering a picker for it is noise.
    field.hidden = networks.length < 2;
  } catch {
    // Not being able to list networks is not worth a visible error: connect
    // without a name and the agent picks the first one it is entitled to.
    field.hidden = true;
  }
}

function render(status) {
  const connected = Boolean(status.interface);
  const signedIn = status.identity !== "Signed out";

  if (!signedIn) {
    show("signedOut");
    return;
  }

  show("signedIn");
  setFact("email", status.user);
  setFact("device", status.device);
  setFact("identity", status.identity);
  setFact("posture", status.posture);
  setFact("interface", status.interface ?? "Down");
  setFact("gateway", status.gateway, { optional: true });
  setFact(
    "expires",
    status.session_expires
      ? new Date(status.session_expires).toLocaleString()
      : null,
    { optional: true },
  );

  const dot = el("dot");
  dot.classList.toggle("down", !connected);
  el("tunnel-state").textContent = connected ? "Connected" : "Disconnected";

  renderNetworks(status);
  el("connect").hidden = connected;
  el("disconnect").hidden = !connected;
  void renderNetworkChoices(connected);
}

async function refresh() {
  if (busy) return;
  try {
    render(await invoke("status"));
    setError("signed-in-error", null);
  } catch (error) {
    if (error?.kind === "cli_missing") {
      el("no-cli-message").textContent = error.message;
      show("noCli");
      stopPolling();
      return;
    }
    setError("signed-in-error", error);
  }
}

function startPolling() {
  stopPolling();
  polling = setInterval(refresh, POLL_INTERVAL_MS);
}

function stopPolling() {
  if (polling) clearInterval(polling);
  polling = null;
}

/// Run an action that takes a while, keeping the buttons honest meanwhile.
async function act(button, errorId, work) {
  busy = true;
  const label = button.textContent;
  button.disabled = true;
  button.textContent = `${label}…`;
  setError(errorId, null);
  try {
    render(await work());
  } catch (error) {
    if (error?.kind === "cli_missing") {
      el("no-cli-message").textContent = error.message;
      show("noCli");
    } else {
      setError(errorId, error);
    }
  } finally {
    button.disabled = false;
    button.textContent = label;
    busy = false;
  }
}

el("sign-in").addEventListener("click", async (event) => {
  // Signing in opens a browser and waits for the person to finish, which can
  // take minutes. Say so rather than looking hung.
  el("sign-in-hint").hidden = false;
  await act(event.target, "signed-out-error", () => invoke("sign_in"));
  el("sign-in-hint").hidden = true;
});

el("sign-out").addEventListener("click", (event) =>
  act(event.target, "signed-in-error", () => invoke("sign_out")),
);

el("connect").addEventListener("click", (event) => {
  const field = el("network-field");
  const network = field.hidden ? null : el("network-choice").value;
  return act(event.target, "signed-in-error", () =>
    invoke("connect", { network }),
  );
});

el("disconnect").addEventListener("click", (event) =>
  act(event.target, "signed-in-error", () => invoke("disconnect")),
);

el("retry").addEventListener("click", async () => {
  show("loading");
  await refresh();
  startPolling();
});

await refresh();
startPolling();
