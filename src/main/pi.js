// src/main/pi.js — generic Raspberry Pi system administration: SSH exec,
// target resolution, disruptive-command gating. DNS-backend-specific logic
// lives in dns/ftl.js and dns/adguard.js (routed by dns/index.js), not here.
const fs = require("fs");
const { Client } = require("ssh2");
const db = require("./db");
const credentials = require("./credentials");
const lan = require("./lanhttp");

const DISRUPTIVE = [
  { match: /systemctl\s+restart\s+(pihole-FTL|AdGuardHome)/, seconds: 5 },
  { match: /pihole\s+restartdns/, seconds: 5 },
  { match: /apt(-get)?\s+(upgrade|dist-upgrade|full-upgrade)/, seconds: 0 },
  { match: /\breboot\b/, seconds: 45 },
  { match: /shutdown/, seconds: 999 }
];

function isDisruptive(command) {
  return DISRUPTIVE.some((d) => d.match.test(command));
}

function disruptionSeconds(command) {
  const hit = DISRUPTIVE.find((d) => d.match.test(command));
  return hit ? hit.seconds : 0;
}

// Packages that are plumbing rather than something the user installed as an
// "app". A bare `^lib` used to be in here, which also hid genuine
// applications whose name happens to start with lib (libreoffice, librespot).
// Shared libraries are the ones carrying a soname digit (libc6, libssl3,
// libgpiod2); dev/debug packages are already covered by the suffix rules.
const APT_SKIP_RE = /(-dev$|^lib\w[\w.+-]*\d$|^firmware|-firmware$|^linux-|raspberrypi-kernel|-dbg$|-dbgsym$)/;

async function aptCheckUpdates() {
  const update = await exec("sudo apt-get update -qq");
  if (update.code) return { ok: false, reason: update.output.join("\n") };
  const list = await exec("apt list --upgradable 2>/dev/null");
  const packages = (list.output || [])
    .filter((l) => l.indexOf("/") !== -1 && l.indexOf("Listing") === -1)
    .map((l) => {
      const name = l.split("/")[0];
      return { name, newVersion: (l.match(/\s(\S+)\s+\[upgradable/) || [])[1] || null };
    });
  return { ok: true, count: packages.length, packages };
}

// Actual upgrade always goes through the pi:exec IPC handler (index.js),
// which gates it behind the disruptive-command confirmation dialog — this
// helper just builds the exact command string used for that.
function aptUpgradeCommand() {
  return "sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y";
}

async function installedApps() {
  const r = await exec("apt-mark showmanual");
  if (r.code) return { ok: false, reason: r.output.join("\n") };
  const apps = (r.output || [])
    .map((l) => l.trim())
    .filter((l) => l && !APT_SKIP_RE.test(l))
    .map((name) => ({ name }));
  return { ok: true, apps };
}

async function rebootRequired() {
  const r = await exec("test -f /var/run/reboot-required && echo yes || echo no");
  if (r.code !== 0) return false;
  return (r.output || []).some((line) => line.trim() === "yes");
}

async function hostStats() {
  const [uptimeR, diskR, cpuR] = await Promise.all([
    exec("uptime -p"),
    exec("df -h / | tail -1"),
    exec("nproc && cat /proc/loadavg")
  ]);
  const disk = (diskR.output && diskR.output[0] || "").trim().split(/\s+/);
  const cpuLines = cpuR.output || [];
  return {
    uptime: (uptimeR.output && uptimeR.output[0] || "").replace(/^up\s+/, "") || null,
    diskUsedPercent: disk[4] ? Number(disk[4].replace("%", "")) : null,
    diskUsed: disk[2] || null,
    diskTotal: disk[1] || null,
    cpuCores: cpuLines[0] ? Number(cpuLines[0]) : null,
    loadAvg: cpuLines[1] ? cpuLines[1].split(" ").slice(0, 3).join(" ") : null
  };
}

function resolveTarget() {
  const state = db.getPiState();
  return {
    host: state.ip || null,
    port: state.sshPort || 22,
    user: state.sshUser || "admin",
    mac: state.mac,
    discovered: state.discovered,
    online: state.online,
    keyPath: db.getSetting("pi_ssh_key") || null
  };
}

function sshConnectOptions(t) {
  const opts = {
    host: t.host,
    port: t.port,
    username: t.user,
    readyTimeout: 8000,
    algorithms: { serverHostKey: ["ssh-ed25519", "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"] }
  };
  if (t.keyPath && fs.existsSync(t.keyPath)) {
    opts.privateKey = fs.readFileSync(t.keyPath);
  } else if (t.mac) {
    const cred = credentials.reveal(t.mac);
    if (cred && cred.password) opts.password = cred.password;
  }
  return opts;
}

function exec(command) {
  const t = resolveTarget();
  if (!t.host) {
    return Promise.resolve({ output: ["No Pi remembered — run a scan first"], code: 1 });
  }
  if (!lan.isPrivateIp(t.host)) {
    return Promise.resolve({ output: ["Refusing SSH to a non-LAN host"], code: 1 });
  }
  const opts = sshConnectOptions(t);
  if (!opts.privateKey && !opts.password) {
    return Promise.resolve({
      output: [
        "SSH is not connected yet.",
        "In Preferences, choose an OpenSSH private key (or save the Pi's login in the credential vault).",
        "Would connect: ssh " + t.user + "@" + t.host + " -p " + t.port,
        "Command: " + command
      ],
      code: 1,
      target: t,
      needsKey: true
    });
  }

  return new Promise((resolve) => {
    const conn = new Client();
    const lines = [];
    let settled = false;
    const done = (result) => {
      if (settled) return;
      settled = true;
      try { conn.end(); } catch (e) { /* ignore */ }
      resolve(result);
    };
    conn.on("ready", () => {
      conn.exec(command, (err, stream) => {
        if (err) return done({ output: [String(err.message || err)], code: 1, target: t });
        stream.on("data", (d) => lines.push(String(d)));
        stream.stderr.on("data", (d) => lines.push(String(d)));
        stream.on("close", (code) => {
          const output = lines.join("").replace(/\r/g, "").split("\n");
          done({ output, code: code == null ? 0 : code, target: t });
        });
      });
    });
    conn.on("error", (e) => done({ output: [String(e.message || e)], code: 1, target: t }));
    try {
      conn.connect(opts);
    } catch (e) {
      done({ output: [String(e.message || e)], code: 1, target: t });
    }
  });
}

const termSessions = new Map(); // sessionId -> { conn, stream }

function termStart(sessionId, { rows, cols }, onData, onClose) {
  const t = resolveTarget();
  // A session ends exactly once, however it ends. Both conn's "error" and the
  // stream's "close" can fire for the same session (a shell dropped by the
  // remote side, say), which used to print "[connection closed]" twice in the
  // renderer — same settled-flag guard as exec() above.
  let settled = false;
  const close = (errorOrNull) => {
    if (settled) return;
    settled = true;
    onClose(errorOrNull);
  };
  if (!t.host) { close("No Pi remembered — run a scan first"); return; }
  if (!lan.isPrivateIp(t.host)) { close("Refusing SSH to a non-LAN host"); return; }
  const opts = sshConnectOptions(t);
  if (!opts.privateKey && !opts.password) { close("SSH is not connected yet — set a key or saved password in Preferences"); return; }

  const conn = new Client();
  termSessions.set(sessionId, { conn, stream: null }); // registered before connecting, so termStop can always find and tear it down

  conn.on("ready", () => {
    conn.shell({ term: "xterm-256color", rows: rows || 24, cols: cols || 80 }, (err, stream) => {
      if (err) { termSessions.delete(sessionId); try { conn.end(); } catch (e) { /* ignore */ } close(String(err.message || err)); return; }
      const session = termSessions.get(sessionId);
      if (!session) { try { stream.close(); } catch (e) { /* ignore */ } return; } // termStop already ran while connecting
      session.stream = stream;
      stream.on("data", (d) => onData(d.toString("utf8")));
      stream.stderr.on("data", (d) => onData(d.toString("utf8")));
      stream.on("close", () => { termSessions.delete(sessionId); close(null); });
    });
  });
  // Clean up on the error path exactly like the normal close path does —
  // otherwise every failed connection leaks a map entry and an open Client.
  conn.on("error", (e) => {
    termSessions.delete(sessionId);
    try { conn.end(); } catch (err) { /* ignore */ }
    close(String(e.message || e));
  });
  try {
    conn.connect(opts);
  } catch (e) {
    termSessions.delete(sessionId);
    try { conn.end(); } catch (err) { /* ignore */ }
    close(String(e.message || e));
  }
}

function termInput(sessionId, data) {
  const s = termSessions.get(sessionId);
  if (s && s.stream) s.stream.write(data);
}

function termResize(sessionId, rows, cols) {
  const s = termSessions.get(sessionId);
  if (s && s.stream) s.stream.setWindow(rows, cols, 0, 0);
}

function termStop(sessionId) {
  const s = termSessions.get(sessionId);
  if (!s) return;
  if (s.stream) { try { s.stream.close(); } catch (e) { /* ignore */ } }
  try { s.conn.end(); } catch (e) { /* ignore */ }
  termSessions.delete(sessionId);
}

module.exports = {
  resolveTarget, sshConnectOptions, exec, isDisruptive, disruptionSeconds,
  aptCheckUpdates, aptUpgradeCommand, installedApps, rebootRequired, hostStats,
  termStart, termInput, termResize, termStop,
  get HOST() { return resolveTarget().host; },
  get SSH_PORT() { return resolveTarget().port; }
};
