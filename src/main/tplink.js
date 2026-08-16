// TP-Link device control.
//
// READ THIS BEFORE IMPLEMENTING.
//
// TP-Link publishes no official local API for consumer routers like the
// Archer BE220. Community libraries reverse-engineer the encrypted local
// endpoint the Tether app uses, and firmware updates break them without
// warning. Phase 3 begins with research, not code: establish which actions are
// genuinely achievable and report honestly, then implement only those.
//
// Where an action is not achievable, expose openAdminPage() instead. A button
// that opens the router web UI is honest; a button that silently fails is not.
//
// The TL-WDR4300 is end-of-support and READ-ONLY. Never attempt a control
// action against it.
//
// config/devices.json has no per-device IP (see CLAUDE.md / discovery.js's
// matchKnown()), so capability info here comes from the *discovered* device
// record - the caller (index.js) looks it up from the last scan by IP and
// passes it in, rather than this module re-deriving it from static config.

const ACTIONS = [
  "reboot", "firmwareCheck", "firmwareUpdate", "ssid", "bandSteering",
  "channel", "clientList", "portForwarding", "speedTest", "led", "backhaul"
];

const DISRUPTIVE = ["reboot", "firmwareUpdate", "ssid", "channel", "bandSteering"];

function isDisruptive(action) {
  return DISRUPTIVE.indexOf(action) !== -1;
}

// What we believe is possible per device. Phase 3 replaces the "unknown"
// values with researched, tested answers.
function capabilities(d) {
  if (!d) return { controllable: false, reason: "device not found in the last scan" };
  const ip = d.ip;
  if (d.control === "readonly") {
    return { ip, controllable: false, reason: "end of support - read only", adminPage: "http://" + ip };
  }
  if (d.control !== "tplink") {
    return { ip, controllable: false, reason: "no management API", adminPage: ip ? "http://" + ip : null };
  }
  return {
    ip,
    model: d.model,
    controllable: true,
    adminPage: "http://" + ip,
    actions: ACTIONS.map(a => ({ action: a, status: "unknown - phase 3 research" }))
  };
}

async function action(d, name, args) {
  if (!d) return { ok: false, reason: "device not found in the last scan" };
  if (d.control === "readonly") return { ok: false, reason: "this device is read-only" };
  // TODO phase 3: real implementation for the actions research proves viable.
  return { ok: false, reason: "not implemented - phase 3", adminPage: "http://" + d.ip, action: name, args };
}

module.exports = { capabilities, action, isDisruptive, ACTIONS };
