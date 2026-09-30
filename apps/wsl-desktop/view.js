// What the window shows, decided from what the agent reported.
//
// Pure functions of `wsl status --json` and `wsl dns status --json`, with no
// DOM and no Tauri, so every decision here is tested in view.test.js rather
// than discovered by clicking. main.js only applies the result.

/** Which panel to show. An imported profile needs no sign-in. */
export function panelFor(status) {
  return status.mode === "signed_out" ? "signedOut" : "dashboard";
}

/**
 * The dashboard, for either mode.
 *
 * A session record and a live interface are different things and are kept
 * apart: "connected" means an interface is up, whatever the session says.
 */
export function dashboard(status) {
  const connected = Boolean(status.interface);
  const direct = status.mode === "direct";
  const fact = (value, hidden = false) => ({ value: value ?? "—", hidden });
  const optional = (value) => fact(value, !value);

  return {
    connected,
    stateText: connected ? "Connected" : "Disconnected",
    facts: {
      profile: fact(status.profile?.name, !direct),
      controlUrl: fact(status.control_url, direct),
      email: fact(status.user, direct),
      device: fact(status.device, direct),
      identity: fact(status.identity, direct),
      posture: fact(status.posture),
      interface: fact(status.interface ?? "Down"),
      gateway: optional(status.gateway),
      expires: optional(
        status.session_expires
          ? new Date(status.session_expires).toLocaleString()
          : null,
      ),
    },
    showConnect: !connected,
    showDisconnect: connected,
    showNetworkPicker: !direct && !connected,
    leave: direct
      ? { label: "Remove profile", command: "remove_profile" }
      : { label: "Sign out", command: "sign_out" },
  };
}

/** The DNS overrides section. */
export function dnsView(dns) {
  const count = dns.entries.length;
  const overrides = `${count} override${count === 1 ? "" : "s"}`;
  if (!dns.supported) {
    return { summary: "Not available on this platform", tone: "muted", toggle: null };
  }
  if (dns.error) {
    return { summary: dns.error, tone: "bad", toggle: null };
  }
  if (!dns.enabled) {
    return {
      summary: `Off · ${overrides}`,
      tone: "muted",
      toggle: { label: "Turn on", command: "dns_enable" },
    };
  }
  const off = { label: "Turn off", command: "dns_disable" };
  if (!dns.running) {
    return {
      summary: "On, but the resolver is not answering",
      tone: "bad",
      toggle: { label: "Restart", command: "dns_enable" },
    };
  }
  if (!dns.in_sync) {
    return {
      summary: `On · ${overrides} · new names need applying`,
      tone: "warn",
      toggle: { label: "Apply", command: "dns_enable" },
    };
  }
  return { summary: `On · ${overrides}`, tone: "ok", toggle: off };
}

const LABEL = /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/i;

/**
 * Check an override before sending it. The agent validates again — these
 * names become files under /etc/resolver — but a message here is quicker.
 */
export function validateOverride(name, address) {
  const trimmed = name.trim().replace(/\.$/, "");
  const wild = trimmed.startsWith("*.");
  const host = wild ? trimmed.slice(2) : trimmed;
  const labels = host.split(".");
  if (!host || host.length > 253 || !labels.every((l) => LABEL.test(l))) {
    return "Enter a host name, like intranet.example.com or *.dev.example.com";
  }
  if (wild && labels.length < 2) {
    return "That wildcard is too broad; it needs at least two labels";
  }
  if (!isIp(address.trim())) {
    return "Enter an IPv4 or IPv6 address, like 10.0.0.5";
  }
  return null;
}

function isIp(text) {
  const v4 = text.split(".");
  if (v4.length === 4 && v4.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)) {
    return true;
  }
  if (!text.includes(":") || !/^[0-9a-f:.]+$/i.test(text)) return false;
  try {
    // The URL parser is a strict IPv6 validator that every webview has.
    new URL(`http://[${text}]/`);
    return true;
  } catch {
    return false;
  }
}

/** Mirror of the agent's rule: https, or plain http to this machine only. */
export function controlUrlProblem(text) {
  let url;
  try {
    url = new URL(text.trim());
  } catch {
    return "Enter the control plane's full URL, like https://vpn.example.com";
  }
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const local = host === "localhost" || host === "::1" || host.startsWith("127.");
  if (url.protocol === "https:") return null;
  if (url.protocol === "http:" && local) return null;
  return "The control plane must use https unless it is on this computer";
}

export function profileNameFromFile(fileName) {
  const stem = fileName.replace(/\.conf$/i, "");
  return stem || "WireGuard";
}
