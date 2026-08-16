// src/main/pi.js — generic Raspberry Pi system administration: SSH exec,
// target resolution, disruptive-command gating. DNS-backend-specific logic
// lives in dns/pihole.js and dns/adguard.js, not here.
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

module.exports = {
  resolveTarget, sshConnectOptions, exec, isDisruptive, disruptionSeconds,
  get HOST() { return resolveTarget().host; },
  get SSH_PORT() { return resolveTarget().port; }
};
