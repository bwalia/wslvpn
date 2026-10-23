// Run with `npm test` (node's built-in runner; no browser needed). Every
// decision about what the window shows lives in view.js, so it is tested here
// against the exact JSON `wsl status --json` and `wsl dns status --json` emit.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  panelFor,
  dashboard,
  dnsView,
  validateOverride,
  controlUrlProblem,
  profileNameFromFile,
  signInOptions,
  opsapiProblem,
  afterOpsapiSignIn,
  otherVpnWarning,
} from "./view.js";

const signedOut = {
  mode: "signed_out",
  control_url: "http://localhost:8080",
  identity: "Signed out",
  networks: [],
  interface: null,
  posture_signals: [],
};

const direct = (up) => ({
  mode: "direct",
  control_url: "http://localhost:8080",
  profile: { name: "office", endpoint: "vpn.example.com:51820" },
  identity: "Signed out",
  user: null,
  device: null,
  posture: "Compliant",
  networks: [{ name: "office", state: up ? "Connected" : "Ready" }],
  gateway: "vpn.example.com:51820",
  interface: up ? "utun4" : null,
  session_expires: null,
  posture_signals: [],
});

const managed = (up, sessionOpen = up) => ({
  mode: "managed",
  control_url: "https://vpn.example.com",
  profile: null,
  identity: "Trusted",
  user: "alice@example.com",
  device: "alices-mbp",
  posture: "Compliant",
  networks: sessionOpen
    ? [{ name: "Development", state: up ? "Connected" : "Session open, tunnel down" }]
    : [],
  gateway: sessionOpen ? "gw.example.com:51820" : null,
  interface: up ? "utun6" : null,
  session_expires: sessionOpen ? "2026-09-30T18:00:00Z" : null,
  posture_signals: [],
});

test("a signed-out agent shows the welcome panel", () => {
  assert.equal(panelFor(signedOut), "signedOut");
});

test("an imported profile goes straight to the dashboard, no sign-in", () => {
  assert.equal(panelFor(direct(false)), "dashboard");
});

test("a direct profile hides the identity rows and offers to remove the profile", () => {
  const v = dashboard(direct(false));
  assert.equal(v.facts.email.hidden, true);
  assert.equal(v.facts.device.hidden, true);
  assert.equal(v.facts.identity.hidden, true);
  assert.equal(v.facts.profile.value, "office");
  assert.equal(v.facts.gateway.value, "vpn.example.com:51820");
  assert.equal(v.leave.label, "Remove profile");
  assert.equal(v.leave.command, "remove_profile");
  assert.equal(v.showNetworkPicker, false);
});

test("the connect and disconnect buttons follow the interface, not the session", () => {
  const down = dashboard(managed(false, true));
  assert.equal(down.connected, false);
  assert.equal(down.showConnect, true);
  assert.equal(down.showDisconnect, false);
  assert.equal(down.stateText, "Disconnected");

  const up = dashboard(managed(true));
  assert.equal(up.connected, true);
  assert.equal(up.showConnect, false);
  assert.equal(up.showDisconnect, true);
  assert.equal(up.stateText, "Connected");
  assert.equal(up.facts.interface.value, "utun6");
});

test("managed mode shows who is signed in and where", () => {
  const v = dashboard(managed(true));
  assert.equal(v.facts.email.value, "alice@example.com");
  assert.equal(v.facts.controlUrl.value, "https://vpn.example.com");
  assert.equal(v.facts.profile.hidden, true);
  assert.equal(v.leave.command, "sign_out");
});

test("a down interface reads as Down rather than blank", () => {
  assert.equal(dashboard(direct(false)).facts.interface.value, "Down");
});

test("the network picker is only offered when signed in and disconnected", () => {
  assert.equal(dashboard(managed(false, false)).showNetworkPicker, true);
  assert.equal(dashboard(managed(true)).showNetworkPicker, false);
  assert.equal(dashboard(direct(false)).showNetworkPicker, false);
});

const dnsOff = {
  supported: true,
  enabled: false,
  running: false,
  listen: "127.0.0.1:15353",
  entries: [],
  wanted: [],
  routed: [],
  in_sync: true,
  error: null,
};

test("DNS overrides that are off say so and offer to turn on", () => {
  const v = dnsView(dnsOff);
  assert.equal(v.toggle.label, "Turn on");
  assert.equal(v.toggle.command, "dns_enable");
  assert.match(v.summary, /off/i);
});

test("DNS overrides that are on and answering read as active", () => {
  const v = dnsView({
    ...dnsOff,
    enabled: true,
    running: true,
    entries: [{ name: "intranet.example.com", address: "10.0.0.5" }],
    wanted: ["intranet.example.com"],
    routed: ["intranet.example.com"],
  });
  assert.equal(v.toggle.label, "Turn off");
  assert.equal(v.summary, "On · 1 override");
  assert.equal(v.tone, "ok");
});

test("an enabled resolver that is not answering is a warning, not 'on'", () => {
  const v = dnsView({ ...dnsOff, enabled: true, running: false });
  assert.equal(v.tone, "bad");
  assert.match(v.summary, /not answering/i);
});

test("routing that is out of date asks to apply", () => {
  const v = dnsView({
    ...dnsOff,
    enabled: true,
    running: true,
    wanted: ["a.example.com"],
    routed: [],
    in_sync: false,
  });
  assert.equal(v.tone, "warn");
  assert.equal(v.toggle.label, "Apply");
  assert.equal(v.toggle.command, "dns_enable");
});

test("an unsupported platform hides the controls", () => {
  const v = dnsView({ ...dnsOff, supported: false });
  assert.equal(v.toggle, null);
});

test("override names are checked before they reach the agent", () => {
  assert.equal(validateOverride("intranet.example.com", "10.0.0.5"), null);
  assert.equal(validateOverride("*.dev.example.com", "fd00::5"), null);
  assert.equal(validateOverride("tracker.example.com", "0.0.0.0"), null);
  assert.match(validateOverride("", "10.0.0.5"), /name/i);
  assert.match(validateOverride("../etc", "10.0.0.5"), /name/i);
  assert.match(validateOverride("a b.example.com", "10.0.0.5"), /name/i);
  assert.match(validateOverride("*.com", "10.0.0.5"), /broad/i);
  assert.match(validateOverride("ok.example.com", "10.0.0"), /address/i);
  assert.match(validateOverride("ok.example.com", "999.1.1.1"), /address/i);
  assert.match(validateOverride("ok.example.com", "not-ip"), /address/i);
});

test("a control plane URL has to be https unless it is local", () => {
  assert.equal(controlUrlProblem("https://vpn.example.com"), null);
  assert.equal(controlUrlProblem("http://localhost:8080"), null);
  assert.equal(controlUrlProblem("http://127.0.0.1:8080"), null);
  assert.match(controlUrlProblem("http://vpn.example.com"), /https/);
  assert.match(controlUrlProblem("vpn.example.com"), /URL/);
});

test("a profile is named after its file", () => {
  assert.equal(profileNameFromFile("office.conf"), "office");
  assert.equal(profileNameFromFile("wg0"), "wg0");
  assert.equal(profileNameFromFile(".conf"), "WireGuard");
});

// --- Signing in with OpsAPI ------------------------------------------------

test("the OpsAPI form appears only when the control plane offers it", () => {
  assert.deepEqual(signInOptions({ oidc: true, opsapi: null }), {
    browser: true,
    opsapi: null,
  });
  const offered = signInOptions({
    oidc: true,
    opsapi: { url: "https://api.example.com", namespace: "workstation" },
  });
  assert.equal(offered.browser, true);
  assert.equal(offered.opsapi.label, "Sign in with OpsAPI");
  assert.match(offered.opsapi.hint, /workstation/);
  assert.match(offered.opsapi.hint, /api\.example\.com/);
});

test("methods that could not be read still leave browser sign-in", () => {
  assert.deepEqual(signInOptions(null), { browser: true, opsapi: null });
});

test("email and password are checked before anything is sent", () => {
  assert.match(opsapiProblem("", "pw"), /email/i);
  assert.match(opsapiProblem("not-an-email", "pw"), /email/i);
  assert.match(opsapiProblem("alice@example.com", ""), /password/i);
  assert.equal(opsapiProblem(" alice@example.com ", "pw"), null);
});

test("an emailed code moves the form to the code step", () => {
  const next = afterOpsapiSignIn({
    status: "code_required",
    challenge: "abc",
    email: "alice@example.com",
  });
  assert.deepEqual(next, {
    step: "code",
    challenge: "abc",
    prompt: "Enter the code sent to alice@example.com",
  });
});

test("a finished sign-in goes back to reading status", () => {
  assert.deepEqual(
    afterOpsapiSignIn({ status: "signed_in", email: "bob@example.com" }),
    { step: "done" },
  );
});

// --- The official WireGuard app ------------------------------------------

test("a tunnel in the WireGuard app is named, because it competes for routes", () => {
  assert.equal(otherVpnWarning({ other_wireguard: [] }), null);
  assert.equal(otherVpnWarning({}), null);
  const one = otherVpnWarning({ other_wireguard: ["office"] });
  assert.match(one, /WireGuard app/);
  assert.match(one, /“office”/);
  const two = otherVpnWarning({ other_wireguard: ["office", "home"] });
  assert.match(two, /“office” and “home”/);
});

test("the dashboard carries the warning", () => {
  const view = dashboard({ ...direct(true), other_wireguard: ["home"] });
  assert.match(view.warning, /“home”/);
  assert.equal(dashboard(direct(true)).warning, null);
});
