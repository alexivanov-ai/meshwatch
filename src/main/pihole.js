// Pi-hole REST (v5 token or v6 SID) + SSH via ssh2.
// Secrets live in Electron safeStorage (see credentials.js / db settings).
const fs = require("fs");
const { Client } = require("ssh2");
const db = require("./db");
const credentials = require("./credentials");
const lan = require("./lanhttp");

const DISRUPTIVE = [
  { match: /systemctl\s+restart\s+pihole-FTL/, seconds: 5 },
  { match: /pihole\s+restartdns/, seconds: 5 },
  { match: /\breboot\b/, seconds: 45 },
  { match: /shutdown/, seconds: 999 }
];

const BLOCK_GROUP = "meshwatch-blocked";
const BLOCK_REGEX = ".*";

let v6sid = null;
let v6host = null;

function isDisruptive(command) {
  return DISRUPTIVE.some((d) => d.match.test(command));
}

function disruptionSeconds(command) {
  const hit = DISRUPTIVE.find((d) => d.match.test(command));
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
    online: state.online,
    keyPath: db.getSetting("pihole_ssh_key") || null
  };
}

function apiPassword() {
  return require("./credentials").getAppSecret("pihole_api") || null;
}

function setApiPassword(password) {
  const credentials = require("./credentials");
  if (!password) {
    credentials.deleteAppSecret("pihole_api");
    v6sid = null;
    return { ok: true };
  }
  const r = credentials.setAppSecret("pihole_api", String(password));
  v6sid = null;
  return r;
}

function hasApiPassword() {
  return !!apiPassword();
}

function baseUrls(host) {
  return ["http://" + host, "http://" + host + "/admin"];
}

async function tryJson(url, opts) {
  try {
    const r = await lan.request(Object.assign({ url, timeoutMs: 5000 }, opts));
    return r;
  } catch (e) {
    return null;
  }
}

async function authV6(host, password) {
  const r = await tryJson("http://" + host + "/api/auth", {
    method: "POST",
    body: { password },
    headers: { "Content-Type": "application/json", Accept: "application/json" }
  });
  const sid = r && r.json && r.json.session && r.json.session.sid;
  if (!sid) return null;
  v6sid = sid;
  v6host = host;
  return sid;
}

function v6headers() {
  return {
    Accept: "application/json",
    "X-FTL-SID": v6sid,
    Cookie: "sid=" + v6sid
  };
}

async function v6get(path) {
  const host = v6host || resolveTarget().host;
  if (!host || !v6sid) return null;
  const r = await tryJson("http://" + host + path, { headers: v6headers() });
  if (r && r.status === 401) {
    v6sid = null;
    return null;
  }
  return r;
}

async function v6send(path, method, body) {
  const host = v6host || resolveTarget().host;
  if (!host || !v6sid) return null;
  return tryJson("http://" + host + path, {
    method,
    body,
    headers: Object.assign({ "Content-Type": "application/json" }, v6headers())
  });
}

async function ensureV6() {
  const t = resolveTarget();
  const password = apiPassword();
  if (!t.host || !password) return false;
  if (v6sid && v6host === t.host) {
    const ping = await v6get("/api/auth");
    if (ping && ping.status === 200) return true;
  }
  return !!(await authV6(t.host, password));
}

async function v5summary(host, token) {
  const urls = [
    "http://" + host + "/admin/api.php?summaryRaw&auth=" + encodeURIComponent(token),
    "http://" + host + "/admin/api.php?summaryRaw&auth=" + encodeURIComponent(token) + "&topItems"
  ];
  for (const url of urls) {
    const r = await tryJson(url);
    if (r && r.json && (r.json.dns_queries_today != null || r.json.queries != null)) return r.json;
  }
  return null;
}

function parseLeaseLine(line) {
  const parts = String(line).trim().split(/\s+/);
  if (parts.length < 4) return null;
  const expiry = Number(parts[0]);
  const mac = String(parts[1] || "").replace(/-/g, ":").toUpperCase();
  const ip = parts[2];
  const hostname = parts[3] === "*" ? null : parts[3];
  if (!lan.isPrivateIp(ip)) return null;
  return { expiry, mac, ip, hostname };
}

function leaseExpires(expiry) {
  if (!expiry) return "—";
  const sec = expiry > 1e12 ? Math.round((expiry - Date.now()) / 1000) : expiry - Math.floor(Date.now() / 1000);
  if (!Number.isFinite(sec) || sec < 0) return "expired";
  if (sec < 3600) return Math.round(sec / 60) + " m";
  if (sec < 86400) return Math.round(sec / 3600) + " h";
  return Math.round(sec / 86400) + " d";
}

async function leasesFromApi() {
  if (await ensureV6()) {
    const r = await v6get("/api/dhcp/leases");
    const list = (r && r.json && (r.json.leases || r.json.data)) || [];
    return list.map((l) => {
      const ip = l.ip || l.address;
      const mac = String(l.hwaddr || l.mac || "").replace(/-/g, ":").toUpperCase();
      const hostname = l.name || l.hostname || null;
      const expiry = l.expires || l.expiry || null;
      return { ip, mac, hostname, expiry, expires: leaseExpires(expiry) };
    }).filter((l) => l.ip && lan.isPrivateIp(l.ip));
  }
  return [];
}

async function leasesFromSsh() {
  const r = await exec("cat /etc/pihole/dhcp.leases");
  if (!r || r.code) return [];
  return (r.output || []).map(parseLeaseLine).filter(Boolean).map((l) => Object.assign(l, { expires: leaseExpires(l.expiry) }));
}

async function leases() {
  const api = await leasesFromApi();
  if (api.length) return api;
  return leasesFromSsh();
}

async function stats() {
  const t = resolveTarget();
  if (!t.discovered) {
    return { available: false, reason: "No Pi-hole has been discovered on this network yet", host: t.host };
  }
  const password = apiPassword();
  if (!password) {
    return {
      available: false,
      reason: "Add the Pi-hole API password / app password in Preferences",
      host: t.host,
      sshPort: t.port,
      sshUser: t.user,
      needsPassword: true
    };
  }

  if (await ensureV6()) {
    const summary = await v6get("/api/stats/summary");
    const version = await v6get("/api/info/version");
    const system = await v6get("/api/info/system");
    const blocked = await v6get("/api/stats/top_domains?blocked=true&count=8");
    const clients = await v6get("/api/stats/top_clients?count=8");
    const s = (summary && summary.json) || {};
    const queries = s.queries || {};
    const today = queries.total != null ? queries.total : s.dns_queries_today;
    const blockedN = queries.blocked != null ? queries.blocked : s.ads_blocked_today;
    const pct = queries.percent_blocked != null ? queries.percent_blocked : s.ads_percentage_today;
    const gravity = (s.gravity && s.gravity.domains_being_blocked) || s.domains_being_blocked;
    const fw = version && version.json && (version.json.version || version.json);
    const firmware = (fw && (fw.core && fw.core.local && fw.core.local.version)) || (fw && fw.version) || null;
    const sys = (system && system.json) || {};
    const hostNote = [
      sys.cpu && sys.cpu.nprocs != null ? sys.cpu.nprocs + " cores" : null,
      sys.sensors && sys.sensors.cpu_temp != null ? Number(sys.sensors.cpu_temp).toFixed(1) + " °C" : null,
      sys.memory && sys.memory.used_percent != null ? "RAM " + Math.round(sys.memory.used_percent) + "%" : null
    ].filter(Boolean).join(" · ");

    const blockedList = ((blocked && blocked.json && (blocked.json.domains || blocked.json.top_domains)) || [])
      .map((d) => ({ domain: d.domain || d.name, hits: d.count != null ? d.count : d.hits }))
      .filter((d) => d.domain);

    const talkers = ((clients && clients.json && (clients.json.clients || clients.json.top_clients)) || [])
      .map((c) => ({
        name: c.name || c.client || c.ip,
        ip: c.ip || c.client,
        queries: c.count != null ? c.count : c.hits
      }));

    return {
      available: true,
      version: 6,
      host: t.host,
      sshPort: t.port,
      sshUser: t.user,
      queriesToday: today,
      blockedToday: blockedN,
      blockedPercent: pct != null ? Math.round(Number(pct) * 10) / 10 : null,
      blocklist: gravity,
      firmware,
      hostNote: hostNote || "Pi-hole 6 API connected",
      blocked: blockedList,
      talkers,
      ftlUptime: (s.took != null) ? null : (s.ftl && s.ftl.uptime)
    };
  }

  const v5 = await v5summary(t.host, password);
  if (v5) {
    const top = v5.top_blocked || v5.ads_top || {};
    const blockedList = Object.keys(top).slice(0, 8).map((domain) => ({ domain, hits: top[domain] }));
    const clients = v5.top_sources || {};
    const talkers = Object.keys(clients).slice(0, 8).map((name) => ({ name, queries: clients[name] }));
    return {
      available: true,
      version: 5,
      host: t.host,
      sshPort: t.port,
      sshUser: t.user,
      queriesToday: v5.dns_queries_today,
      blockedToday: v5.ads_blocked_today,
      blockedPercent: v5.ads_percentage_today != null ? Math.round(Number(v5.ads_percentage_today) * 10) / 10 : null,
      blocklist: v5.domains_being_blocked,
      firmware: null,
      hostNote: "Pi-hole 5 API connected",
      blocked: blockedList,
      talkers
    };
  }

  return {
    available: false,
    reason: "Could not reach the Pi-hole API. Check the password and that this PC can open http://" + t.host + "/admin",
    host: t.host,
    sshPort: t.port,
    sshUser: t.user
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
    return Promise.resolve({ output: ["No Pi-hole host remembered — run a scan first"], code: 1 });
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

async function ensureBlockGroup() {
  if (!(await ensureV6())) return null;
  const g = await v6get("/api/groups");
  const groups = (g && g.json && (g.json.groups || g.json.data)) || [];
  let found = groups.find((x) => x.name === BLOCK_GROUP);
  if (!found) {
    await v6send("/api/groups", "POST", { name: BLOCK_GROUP, comment: "Meshwatch per-device internet block", enabled: true });
    const g2 = await v6get("/api/groups");
    const groups2 = (g2 && g2.json && (g2.json.groups || g2.json.data)) || [];
    found = groups2.find((x) => x.name === BLOCK_GROUP);
  }
  if (!found) return null;
  const domains = await v6get("/api/domains?type=deny&kind=regex");
  const list = (domains && domains.json && (domains.json.domains || domains.json.data)) || [];
  const has = list.some((d) => d.domain === BLOCK_REGEX && (d.groups || []).indexOf(found.id) !== -1);
  if (!has) {
    await v6send("/api/domains?type=deny&kind=regex", "POST", {
      domain: BLOCK_REGEX,
      comment: "Meshwatch catch-all for blocked clients",
      groups: [found.id],
      enabled: true
    });
  }
  return found;
}

async function blockClient(ip, { blocked } = { blocked: true }) {
  if (!lan.isPrivateIp(ip)) return { ok: false, reason: "not a LAN address" };
  const group = await ensureBlockGroup();
  if (!group) {
    return {
      ok: false,
      reason: "Internet blocking needs a live Pi-hole 6 API connection. Add the API password in Preferences."
    };
  }
  const clients = await v6get("/api/clients");
  const list = (clients && clients.json && (clients.json.clients || clients.json.data)) || [];
  const existing = list.find((c) => c.client === ip || (c.addresses || []).indexOf(ip) !== -1);
  if (blocked) {
    if (existing) {
      const groups = Array.from(new Set((existing.groups || []).concat([group.id])));
      await v6send("/api/clients/" + encodeURIComponent(existing.client || ip), "PUT", { groups });
    } else {
      await v6send("/api/clients", "POST", { client: ip, comment: "Meshwatch blocked", groups: [group.id] });
    }
    return { ok: true, blocked: true, via: "pihole-group" };
  }
  if (existing) {
    const groups = (existing.groups || []).filter((id) => id !== group.id);
    await v6send("/api/clients/" + encodeURIComponent(existing.client || ip), "PUT", { groups });
  }
  return { ok: true, blocked: false, via: "pihole-group" };
}

module.exports = {
  stats,
  leases,
  exec,
  isDisruptive,
  disruptionSeconds,
  resolveTarget,
  setApiPassword,
  hasApiPassword,
  blockClient,
  get HOST() { return resolveTarget().host; },
  get SSH_PORT() { return resolveTarget().port; }
};
