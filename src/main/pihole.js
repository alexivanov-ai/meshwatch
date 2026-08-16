// Pi-hole on the Raspberry Pi 5.
//
// Two channels:
//   REST API - statistics, blocked domains, lease table
//   SSH :2222 - shell commands, via ssh2 with KEY authentication
//
// Phase 2 implements both. Credentials must come from the OS credential store,
// never from a file in this repo.
//
// HOST comes from config/devices.json's dns-dhcp entry, the one place its
// user-confirmed IP is recorded - never hardcode a second copy here, that's
// exactly how the old .2-vs-.63 mismatch happened.

const config = require("../../config/devices.json");

const piEntry = config.known.find(k => k.role === "dns-dhcp");
const HOST = (piEntry && piEntry.confirmed && piEntry.confirmed.ip) || null;
const SSH_PORT = (piEntry && piEntry.ssh && piEntry.ssh.port) || 2222;

// Commands that stop DNS for the entire network.
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

// --- STUBS for phase 2 -----------------------------------------------------

async function stats() {
  // TODO phase 2: Pi-hole REST API. Authenticate, then return
  // { queriesToday, blockedToday, blockedPercent, blocklistSize, topBlocked: [] }
  return { available: false, reason: "not implemented - phase 2" };
}

async function leases() {
  // TODO phase 2: read the DHCP lease table, either over the API or by
  // reading /etc/pihole/dhcp.leases over SSH.
  // Return [{ mac, ip, hostname, expires }] - the authoritative device names.
  return [];
}

async function exec(command) {
  // TODO phase 2: ssh2 Client, key auth, connect to HOST:SSH_PORT,
  // run the command, return { output: [lines], code }.
  return { output: ["pihole.js exec() is not implemented yet - phase 2"], code: 1 };
}

module.exports = { stats, leases, exec, isDisruptive, disruptionSeconds, HOST, SSH_PORT };
