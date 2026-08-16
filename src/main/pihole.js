// Pi-hole on a discovered Raspberry Pi (or any host marked dns-dhcp).
//
// Two channels:
//   REST API - statistics, blocked domains, lease table
//   SSH on a user-configurable port (people routinely hide 22) via ssh2
//
// Phase 2 implements both. Credentials must come from the OS credential store,
// never from a file in this repo.
//
// Host IP comes from discovery (remembered in settings). SSH port/user come
// from Preferences — default port is 22, never assume a custom port.

const db = require("./db");

const DISRUPTIVE = [
  { match: /systemctl\s+restart\s+pihole-FTL/, seconds: 5 },
  { match: /pihole\s+restartdns/, seconds: 5 },
  { match: /\breboot\b/, seconds: 45 },
  { match: /shutdown/, seconds: 999 }
];

function isDisruptive(command) {
  return DISRUPTIVE.some(d => d.match.test(command));
}

function disruptionSeconds(command) {
  const hit = DISRUPTIVE.find(d => d.match.test(command));
  return hit ? hit.seconds : 0;
}

function resolveTarget() {
  const state = db.getPiHoleState();
  return {
    host: state.ip || null,
    port: state.sshPort || 22,
    user: state.sshUser || "admin",
    mac: state.mac,
    discovered: state.discovered,
    online: state.online
  };
}

async function stats() {
  const t = resolveTarget();
  if (!t.discovered) {
    return { available: false, reason: "No Pi-hole has been discovered on this network yet" };
  }
  return {
    available: false,
    reason: "Pi-hole API is not connected yet",
    host: t.host,
    sshPort: t.port,
    sshUser: t.user
  };
}

async function leases() {
  return [];
}

async function exec(command) {
  const t = resolveTarget();
  if (!t.host) {
    return { output: ["No Pi-hole host remembered — run a scan first"], code: 1 };
  }
  return {
    output: [
      "SSH commands are not connected yet",
      "Would connect: ssh " + t.user + "@" + t.host + " -p " + t.port,
      "Command: " + command
    ],
    code: 1,
    target: t
  };
}

module.exports = {
  stats,
  leases,
  exec,
  isDisruptive,
  disruptionSeconds,
  resolveTarget,
  get HOST() { return resolveTarget().host; },
  get SSH_PORT() { return resolveTarget().port; }
};
