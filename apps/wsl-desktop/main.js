// The window is a view over `wsl status --json` and `wsl dns status --json`.
// It holds no state of its own beyond what is selected and what is being
// edited: every render is driven by what the agent just reported, so a dot
// cannot say "active" while the interface is down. What to show is decided in
// view.js; this file applies it to the DOM and wires up the controls.

import {
  dashboard,
  dnsView,
  validateOverride,
  controlUrlProblem,
  profileNameFromFile,
  signInOptions,
  opsapiProblem,
  afterOpsapiSignIn,
  otherVpnWarning,
  tunnelList,
  tunnelDetail,
  chooseSelection,
} from "./view.js";

const POLL_INTERVAL_MS = 5000;
const el = (id) => document.getElementById(id);

const panels = {
  tunnel: el("tunnel-panel"),
  edit: el("edit-panel"),
  empty: el("empty-panel"),
  organisation: el("organisation-panel"),
  dns: el("dns-panel"),
  posture: el("posture-panel"),
};

let polling = null;
let busy = false;
let lastStatus = null;
// The sidebar selection: a tunnel's name, or `section:<id>`.
let selected = null;
// The tunnel whose config is open in Edit, or null. While editing, refreshes
// leave the editor alone.
let editing = null;
let methodsFor = null;
let pendingChallenge = null;

async function invoke(command, args = {}) {
  if (!window.__TAURI_INTERNALS__) {
    throw { kind: "command_failed", message: "This page only works inside the desktop app." };
  }
  const { invoke: tauriInvoke } = await import("@tauri-apps/api/core");
  return tauriInvoke(command, args);
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

function showOnly(name) {
  for (const [key, node] of Object.entries(panels)) node.hidden = key !== name;
}

function grid(container, rows) {
  container.replaceChildren(
    ...rows.flatMap(([label, value]) => {
      const dt = document.createElement("dt");
      dt.textContent = `${label}:`;
      const dd = document.createElement("dd");
      dd.textContent = value;
      return [dt, dd];
    }),
  );
}

function listRow(left, right, rightClass) {
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

// --- sidebar ---------------------------------------------------------------

function renderSidebar(status) {
  const list = el("tunnel-list");
  list.replaceChildren(
    ...tunnelList(status, selected).map((t) => {
      const li = document.createElement("li");
      li.setAttribute("role", "option");
      li.tabIndex = 0;
      li.dataset.select = t.name;
      li.setAttribute("aria-selected", String(t.selected));
      const dot = document.createElement("span");
      dot.className = `dot${t.up ? " up" : ""}`;
      dot.setAttribute("aria-label", t.up ? "active" : "inactive");
      const name = document.createElement("span");
      name.textContent = t.name;
      li.append(dot, name);
      return li;
    }),
  );
  for (const li of el("section-list").children) {
    li.tabIndex = 0;
    li.setAttribute("aria-selected", String(li.dataset.select === selected));
  }
  el("remove-tunnel").disabled = selected?.startsWith("section:") ?? true;
}

function select(target) {
  if (editing) return; // finish or discard the edit first
  selected = target;
  el("confirm-remove").hidden = true;
  if (lastStatus) renderAll(lastStatus);
}

for (const list of [el("tunnel-list"), el("section-list")]) {
  list.addEventListener("click", (event) => {
    const li = event.target.closest("li[data-select]");
    if (li) select(li.dataset.select);
  });
  list.addEventListener("keydown", (event) => {
    const items = [...document.querySelectorAll(".sidebar li[data-select]")];
    const at = items.findIndex((li) => li.dataset.select === selected);
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const next = items[Math.max(0, Math.min(items.length - 1, at + (event.key === "ArrowDown" ? 1 : -1)))];
      if (next) {
        select(next.dataset.select);
        document.querySelector(`.sidebar li[data-select="${CSS.escape(next.dataset.select)}"]`)?.focus();
      }
    }
  });
}

// --- the selected tunnel ----------------------------------------------------

function renderTunnel(status) {
  const d = tunnelDetail(status, selected);
  if (!d) return false;
  el("tunnel-title").textContent = d.interfaceName ? `${d.title}  (${d.interfaceName})` : d.title;
  el("tunnel-dot").className = `dot${d.up ? " up" : ""}`;
  el("tunnel-status").textContent = d.statusText;
  grid(el("tunnel-rows"), d.interface);
  const peers = el("tunnel-peers");
  peers.replaceChildren(
    ...d.peers.map((rows) => {
      const dl = document.createElement("dl");
      dl.className = "grid peer";
      grid(dl, rows);
      dl.firstChild?.classList.add("strong");
      return dl;
    }),
  );
  const action = el("tunnel-action");
  action.textContent = d.action.label;
  action.dataset.command = d.action.command;
  action.classList.toggle("deactivate", d.up);
  return true;
}

// --- organisation (control plane) -------------------------------------------

async function loadMethods(url) {
  if (!url || url === methodsFor) return;
  methodsFor = url;
  let methods = null;
  try {
    methods = await invoke("sign_in_methods");
  } catch {
    // An unreachable control plane still gets the browser button; signing in
    // says what is wrong with the address.
  }
  const options = signInOptions(methods);
  el("sign-in").hidden = !options.browser;
  el("opsapi-hint").textContent = options.opsapi?.hint ?? "";
  el("opsapi-form").hidden = !options.opsapi || Boolean(pendingChallenge);
}

function showCodeStep(prompt) {
  el("code-prompt").textContent = prompt ?? "";
  el("code-form").hidden = !pendingChallenge;
  el("opsapi-form").hidden = Boolean(pendingChallenge) || !el("opsapi-hint").textContent;
  if (pendingChallenge) el("opsapi-code").focus();
}

async function renderNetworkChoices(show) {
  const field = el("network-field");
  if (!show) {
    field.hidden = true;
    return;
  }
  try {
    const networks = await invoke("networks");
    el("network-choice").replaceChildren(
      ...networks.map((n) => {
        const option = document.createElement("option");
        option.value = n.name;
        option.textContent = `${n.name} — ${n.cidr}`;
        return option;
      }),
    );
    field.hidden = networks.length < 2;
  } catch {
    field.hidden = true;
  }
}

function renderOrganisation(status) {
  const signedIn = Boolean(status.user);
  el("signed-out").hidden = signedIn;
  el("signed-in").hidden = !signedIn;
  if (!signedIn) {
    const input = el("control-url");
    if (document.activeElement !== input) input.value = status.control_url ?? "";
    void loadMethods(status.control_url);
    return;
  }
  pendingChallenge = null;
  const managed = status.mode === "managed";
  const up = managed && Boolean(status.interface);
  const view = dashboard(status);
  for (const id of ["controlUrl", "email", "device", "gateway", "expires"]) {
    const fact = view.facts[id];
    el(id).textContent = fact.value;
    const label = el(`${id}-label`);
    el(id).hidden = fact.hidden;
    if (label) label.hidden = fact.hidden;
  }
  el("org-dot").className = `dot${up ? " up" : ""}`;
  el("org-state").textContent = up ? "Connected" : managed ? "Disconnected" : "Not in use — a tunnel is selected for Connect";
  el("org-connect").hidden = up;
  el("org-disconnect").hidden = !up;
  const list = el("networks");
  list.replaceChildren(
    ...(managed && status.networks?.length
      ? status.networks.map((n) => listRow(n.name, n.state, n.state === "Connected" ? "ok" : "warn"))
      : [emptyRow("No session")]),
  );
  void renderNetworkChoices(!up);
}

// --- DNS and posture ---------------------------------------------------------

const POSTURE_CLASS = { pass: "ok", fail: "bad", unknown: "warn", unsupported: "muted" };

function renderPosture(status) {
  el("posture").textContent = status.posture ? `· ${status.posture}` : "";
  el("posture-signals").replaceChildren(
    ...(status.posture_signals ?? []).map((s) =>
      listRow(s.name.replace(/_/g, " "), s.detail ?? s.result, POSTURE_CLASS[s.result] ?? "muted"),
    ),
  );
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
  if (!dns.entries.length) {
    list.replaceChildren(emptyRow("No overrides"));
    return;
  }
  list.replaceChildren(
    ...dns.entries.map((entry) => {
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
      return item;
    }),
  );
}

// --- the whole window --------------------------------------------------------

function renderAll(status) {
  lastStatus = status;
  el("loading").hidden = true;
  el("no-cli").hidden = true;
  el("app").hidden = false;

  const warning = otherVpnWarning(status);
  el("other-vpn").hidden = !warning;
  el("other-vpn").textContent = warning ?? "";

  if (editing) return; // the editor is the panel until it is saved or discarded
  selected = chooseSelection(status, selected);
  renderSidebar(status);

  if (selected === "section:organisation") {
    renderOrganisation(status);
    showOnly("organisation");
  } else if (selected === "section:dns") {
    showOnly("dns");
  } else if (selected === "section:posture") {
    renderPosture(status);
    showOnly("posture");
  } else if (renderTunnel(status)) {
    showOnly("tunnel");
  } else {
    showOnly("empty");
  }
}

async function refresh() {
  if (busy) return;
  try {
    renderAll(await invoke("status"));
    setError("app-error", null);
    if (selected === "section:dns") renderDns(await invoke("dns_status"));
  } catch (error) {
    if (error?.kind === "cli_missing") {
      el("no-cli-message").textContent = error.message;
      el("loading").hidden = true;
      el("app").hidden = true;
      el("no-cli").hidden = false;
      stopPolling();
      return;
    }
    el("loading").hidden = true;
    el("app").hidden = false;
    setError("app-error", error);
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
async function act(button, errorId, work, apply = renderAll) {
  busy = true;
  const label = button.textContent;
  button.disabled = true;
  button.textContent = `${label}…`;
  setError(errorId, null);
  try {
    apply(await work());
    return true;
  } catch (error) {
    setError(errorId, error);
    return false;
  } finally {
    button.disabled = false;
    button.textContent = label;
    busy = false;
  }
}

// --- tunnels: activate, import, remove, edit ---------------------------------

el("tunnel-action").addEventListener("click", (event) => {
  const command = event.target.dataset.command;
  const name = selected;
  return act(event.target, "app-error", () =>
    command === "activate_profile" ? invoke("activate_profile", { name }) : invoke("disconnect"),
  );
});

el("import-file").addEventListener("change", async (event) => {
  const files = [...(event.target.files ?? [])];
  event.target.value = "";
  for (const file of files) {
    // WireGuard configs are a few hundred bytes. Anything large is not one.
    if (file.size > 64 * 1024) {
      setError("app-error", `${file.name} is too large to be a WireGuard config.`);
      return;
    }
    const name = profileNameFromFile(file.name);
    const text = await file.text();
    const ok = await act(el("import-label"), "app-error", () => invoke("import_profile", { text, name }));
    if (!ok) return;
    selected = name;
  }
  if (lastStatus) renderAll(lastStatus);
});

el("import-label").addEventListener("keydown", (event) => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    el("import-file").click();
  }
});

el("remove-tunnel").addEventListener("click", () => {
  if (!selected || selected.startsWith("section:")) return;
  el("confirm-remove-text").textContent =
    `Remove “${selected}”? Its configuration and private key are deleted from this Mac.`;
  el("confirm-remove").hidden = false;
});
el("confirm-remove-no").addEventListener("click", () => {
  el("confirm-remove").hidden = true;
});
el("confirm-remove-yes").addEventListener("click", async (event) => {
  const name = selected;
  const ok = await act(event.target, "app-error", () => invoke("remove_profile", { name }));
  el("confirm-remove").hidden = true;
  if (ok) {
    selected = null;
    void refresh();
  }
});

el("tunnel-edit").addEventListener("click", async () => {
  const name = selected;
  let text;
  try {
    text = await invoke("profile_config", { name });
  } catch (error) {
    setError("app-error", error);
    return;
  }
  editing = name;
  el("edit-name").value = name;
  el("edit-text").value = text;
  showOnly("edit");
  el("edit-text").focus();
});

function closeEditor() {
  editing = null;
  // The private key is in the text; do not leave it sitting in the page.
  el("edit-text").value = "";
  if (lastStatus) renderAll(lastStatus);
}

el("edit-cancel").addEventListener("click", closeEditor);
el("edit-save").addEventListener("click", async (event) => {
  const from = editing;
  const name = el("edit-name").value.trim();
  const text = el("edit-text").value;
  const ok = await act(event.target, "app-error", async () => {
    const status = await invoke("save_profile", { name, text });
    // Renamed: the old entry goes, once the new one has been saved.
    if (name !== from) return invoke("remove_profile", { name: from });
    return status;
  }, (status) => {
    lastStatus = status;
  });
  if (ok) {
    selected = name;
    closeEditor();
  }
});

// --- organisation -------------------------------------------------------------

el("control-url").addEventListener("change", async () => {
  const url = el("control-url").value.trim();
  if (controlUrlProblem(url) || url === lastStatus?.control_url) return;
  try {
    renderAll(await invoke("set_control_url", { url }));
    setError("app-error", null);
  } catch (error) {
    setError("app-error", error);
  }
});

el("sign-in-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = el("control-url").value.trim();
  const problem = controlUrlProblem(url);
  if (problem) {
    setError("app-error", problem);
    return;
  }
  // Signing in opens a browser and waits, which can take minutes. Say so.
  el("sign-in-hint").hidden = false;
  await act(el("sign-in"), "app-error", async () => {
    if (url !== lastStatus?.control_url) await invoke("set_control_url", { url });
    return invoke("sign_in");
  });
  el("sign-in-hint").hidden = true;
});

el("opsapi-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const email = el("opsapi-email").value.trim();
  const password = el("opsapi-password").value;
  const problem = opsapiProblem(email, password);
  if (problem) {
    setError("app-error", problem);
    return;
  }
  await act(el("opsapi-submit"), "app-error", () => invoke("opsapi_sign_in", { email, password }), (result) => {
    const next = afterOpsapiSignIn(result);
    if (next.step === "code") {
      pendingChallenge = next.challenge;
      showCodeStep(next.prompt);
    }
  });
  // Never left in the field once it has been used, right or wrong.
  el("opsapi-password").value = "";
  void refresh();
});

el("code-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const code = el("opsapi-code").value.trim();
  if (!code) {
    setError("app-error", "Enter the code from the email");
    return;
  }
  const ok = await act(el("code-submit"), "app-error",
    () => invoke("opsapi_verify_code", { challenge: pendingChallenge, code }),
    () => {
      pendingChallenge = null;
      showCodeStep();
    });
  el("opsapi-code").value = "";
  if (ok) void refresh();
});

el("code-cancel").addEventListener("click", () => {
  pendingChallenge = null;
  el("opsapi-code").value = "";
  setError("app-error", null);
  showCodeStep();
});

el("org-connect").addEventListener("click", (event) => {
  const field = el("network-field");
  const network = field.hidden ? null : el("network-choice").value;
  return act(event.target, "app-error", async () => {
    // A tunnel selected for Connect takes precedence; step back from it.
    if (lastStatus?.mode === "direct") await invoke("use_control_plane");
    return invoke("connect", { network });
  });
});

el("org-disconnect").addEventListener("click", (event) =>
  act(event.target, "app-error", () => invoke("disconnect")),
);

el("sign-out").addEventListener("click", (event) =>
  act(event.target, "app-error", () => invoke("sign_out")),
);

// --- DNS -------------------------------------------------------------------------

el("dns-add").addEventListener("submit", async (event) => {
  event.preventDefault();
  const name = el("dns-name").value.trim();
  const address = el("dns-address").value.trim();
  const problem = validateOverride(name, address);
  if (problem) {
    setError("dns-error", problem);
    return;
  }
  const ok = await act(event.submitter ?? event.target.querySelector("button"), "dns-error",
    () => invoke("dns_set", { name, address }), renderDns);
  if (ok) {
    el("dns-name").value = "";
    el("dns-address").value = "";
  }
});

el("dns-toggle").addEventListener("click", (event) =>
  act(event.target, "dns-error", () => invoke(event.target.dataset.command), renderDns),
);

// Opening the DNS section reads DNS status straight away, not on the next poll.
el("section-list").addEventListener("click", async (event) => {
  if (event.target.closest("li")?.dataset.select === "section:dns") {
    try {
      renderDns(await invoke("dns_status"));
    } catch (error) {
      setError("dns-error", error);
    }
  }
});

el("retry").addEventListener("click", async () => {
  el("no-cli").hidden = true;
  el("loading").hidden = false;
  await refresh();
  startPolling();
});

await refresh();
startPolling();
