// The window is a view over `wsl status --json` and `wsl dns status --json`.
// It holds no state of its own: every render is driven by what the agent just
// reported, so the dot in the title bar cannot say "connected" while the
// interface is down. What to show is decided in view.js; this file only
// applies it to the DOM and wires up the buttons.

import {
  panelFor,
  dashboard,
  dnsView,
  validateOverride,
  controlUrlProblem,
  profileNameFromFile,
} from "./view.js";

const POLL_INTERVAL_MS = 5000;

const el = (id) => document.getElementById(id);
const panels = {
  loading: el("loading"),
  signedOut: el("signed-out"),
  dashboard: el("dashboard"),
  noCli: el("no-cli"),
};

let polling = null;
let busy = false;
let lastStatus = null;

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

function applyFact(id, { value, hidden }) {
  const node = el(id);
  const label = el(`${id}-label`);
  node.hidden = hidden;
  if (label) label.hidden = hidden;
  node.textContent = value;
}

function row(left, right, rightClass) {
  const item = document.createElement("li");
  const a = document.createElement("span");
  a.textContent = left;
  const b = document.createElement("span");
  b.textContent = right;
  if (rightClass) b.className = rightClass;
  item.append(a, b);
  return item;
}

function emptyRow(text) {
  const item = document.createElement("li");
  item.className = "empty";
  item.textContent = text;
  return item;
}

// A session record and a live interface are different things, and the agent
// reports them separately. "Session open, tunnel down" is a real state a user
// needs to see, not a rounding error.
function renderNetworks(status) {
  const list = el("networks");
  list.replaceChildren();
  if (!status.networks?.length) {
    list.append(emptyRow("No networks"));
    return;
  }
  for (const network of status.networks) {
    list.append(
      row(network.name, network.state, network.state === "Connected" ? "ok" : "warn"),
    );
  }
}

async function renderNetworkChoices(show) {
  const field = el("network-field");
  const select = el("network-choice");
  if (!show) {
    field.hidden = true;
    return;
  }
  try {
    const networks = await invoke("networks");
    select.replaceChildren(
      ...networks.map((network) => {
        const option = document.createElement("option");
        option.value = network.name;
        option.textContent = `${network.name} — ${network.cidr}`;
        return option;
      }),
    );
    // One network is not a choice; offering a picker for it is noise.
    field.hidden = networks.length < 2;
  } catch {
    // Not being able to list networks is not worth a visible error: connect
    // without a name and the agent picks the first one it is entitled to.
    field.hidden = true;
  }
}

// Which check is failing matters more than the verdict: "Posture: Failing"
// tells a user they are blocked, and nothing about what to do next.
const POSTURE_CLASS = { pass: "ok", fail: "bad", unknown: "warn", unsupported: "muted" };

function renderPosture(signals) {
  const list = el("posture-signals");
  list.replaceChildren(
    ...(signals ?? []).map((signal) => {
      const item = row(
        signal.name.replace(/_/g, " "),
        signal.detail ?? signal.result,
        POSTURE_CLASS[signal.result] ?? "muted",
      );
      item.firstChild.title = signal.detail ?? "";
      return item;
    }),
  );
}

function render(status) {
  lastStatus = status;
  if (panelFor(status) === "signedOut") {
    show("signedOut");
    const input = el("control-url");
    // Do not overwrite what the person is typing.
    if (document.activeElement !== input) input.value = status.control_url ?? "";
    return;
  }

  show("dashboard");
  const view = dashboard(status);
  for (const [id, fact] of Object.entries(view.facts)) applyFact(id, fact);
  el("dot").classList.toggle("down", !view.connected);
  el("tunnel-state").textContent = view.stateText;
  el("connect").hidden = !view.showConnect;
  el("disconnect").hidden = !view.showDisconnect;
  el("leave").textContent = view.leave.label;
  el("leave").dataset.command = view.leave.command;
  renderPosture(status.posture_signals);
  renderNetworks(status);
  void renderNetworkChoices(view.showNetworkPicker);
}

function renderDns(dns) {
  const view = dnsView(dns);
  const summary = el("dns-summary");
  summary.textContent = view.summary;
  summary.className = view.tone;

  const toggle = el("dns-toggle");
  toggle.hidden = !view.toggle;
  if (view.toggle) {
    toggle.textContent = view.toggle.label;
    toggle.dataset.command = view.toggle.command;
  }

  const list = el("dns-entries");
  list.replaceChildren();
  if (!dns.entries.length) {
    list.append(emptyRow("No overrides"));
    return;
  }
  for (const entry of dns.entries) {
    const item = document.createElement("li");
    const name = document.createElement("span");
    name.textContent = entry.name;
    const right = document.createElement("span");
    right.className = "entry-actions";
    const address = document.createElement("code");
    address.textContent = entry.address;
    const remove = document.createElement("button");
    remove.className = "quiet";
    remove.textContent = "Remove";
    remove.setAttribute("aria-label", `Remove ${entry.name}`);
    remove.addEventListener("click", () =>
      act(remove, "dns-error", () => invoke("dns_remove", { name: entry.name }), renderDns),
    );
    right.append(address, remove);
    item.append(name, right);
    list.append(item);
  }
}

async function refresh() {
  if (busy) return;
  try {
    render(await invoke("status"));
    setError("dashboard-error", null);
    if (!panels.dashboard.hidden) {
      renderDns(await invoke("dns_status"));
    }
  } catch (error) {
    if (error?.kind === "cli_missing") {
      el("no-cli-message").textContent = error.message;
      show("noCli");
      stopPolling();
      return;
    }
    setError(panels.signedOut.hidden ? "dashboard-error" : "signed-out-error", error);
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
async function act(button, errorId, work, apply = render) {
  busy = true;
  const label = button.textContent;
  button.disabled = true;
  button.textContent = `${label}…`;
  setError(errorId, null);
  try {
    apply(await work());
    return true;
  } catch (error) {
    if (error?.kind === "cli_missing") {
      el("no-cli-message").textContent = error.message;
      show("noCli");
    } else {
      setError(errorId, error);
    }
    return false;
  } finally {
    button.disabled = false;
    button.textContent = label;
    busy = false;
    // A status change (connect, import) may have moved us to the dashboard;
    // read DNS for it without waiting for the next poll.
    if (apply === render) void refresh();
  }
}

el("sign-in-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = el("sign-in");
  const url = el("control-url").value.trim();
  const problem = controlUrlProblem(url);
  if (problem) {
    setError("signed-out-error", problem);
    return;
  }
  // Signing in opens a browser and waits for the person to finish, which can
  // take minutes. Say so rather than looking hung.
  el("sign-in-hint").hidden = false;
  await act(button, "signed-out-error", async () => {
    if (url !== lastStatus?.control_url) {
      await invoke("set_control_url", { url });
    }
    return invoke("sign_in");
  });
  el("sign-in-hint").hidden = true;
});

el("import-file").addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  event.target.value = "";
  if (!file) return;
  // WireGuard configs are a few hundred bytes. Anything large is not one.
  if (file.size > 64 * 1024) {
    setError("signed-out-error", "That file is too large to be a WireGuard config.");
    return;
  }
  const text = await file.text();
  await act(el("import-label"), "signed-out-error", () =>
    invoke("import_profile", { text, name: profileNameFromFile(file.name) }),
  );
});

// The label is the visible control; make it work from the keyboard too.
el("import-label").addEventListener("keydown", (event) => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    el("import-file").click();
  }
});

el("leave").addEventListener("click", (event) => {
  const command = event.target.dataset.command ?? "sign_out";
  return act(event.target, "dashboard-error", () => invoke(command));
});

el("connect").addEventListener("click", (event) => {
  const field = el("network-field");
  const network = field.hidden ? null : el("network-choice").value;
  return act(event.target, "dashboard-error", () => invoke("connect", { network }));
});

el("disconnect").addEventListener("click", (event) =>
  act(event.target, "dashboard-error", () => invoke("disconnect")),
);

el("dns-add").addEventListener("submit", async (event) => {
  event.preventDefault();
  const name = el("dns-name").value.trim();
  const address = el("dns-address").value.trim();
  const problem = validateOverride(name, address);
  if (problem) {
    setError("dns-error", problem);
    return;
  }
  const ok = await act(
    event.submitter ?? event.target.querySelector("button"),
    "dns-error",
    () => invoke("dns_set", { name, address }),
    renderDns,
  );
  if (ok) {
    el("dns-name").value = "";
    el("dns-address").value = "";
  }
});

el("dns-toggle").addEventListener("click", (event) =>
  act(event.target, "dns-error", () => invoke(event.target.dataset.command), renderDns),
);

el("retry").addEventListener("click", async () => {
  show("loading");
  await refresh();
  startPolling();
});

await refresh();
startPolling();
