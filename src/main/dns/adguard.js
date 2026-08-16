// src/main/dns/adguard.js — AdGuard Home REST API adapter.
// Docs: https://github.com/AdguardTeam/AdGuardHome (control API is
// undocumented-but-stable; endpoints below match the app's own web UI).
const pi = require("../pi");
const credentials = require("../credentials");
const lan = require("../lanhttp");

let sessionCookie = null;
let sessionHost = null;

function apiPassword() {
  return credentials.getAppSecret("dns_api") || null;
}

function setApiPassword(password) {
  if (!password) {
    credentials.deleteAppSecret("dns_api");
    sessionCookie = null;
    return { ok: true };
  }
  const r = credentials.setAppSecret("dns_api", String(password));
  sessionCookie = null;
  return r;
}

function hasApiPassword() {
  return !!apiPassword();
}

async function tryJson(host, path, opts) {
  try {
    return await lan.request(Object.assign({ url: "http://" + host + path, timeoutMs: 5000 }, opts));
  } catch (e) {
    return null;
  }
}

// AdGuard's default admin username is "admin" unless the user changed it;
// Meshwatch only ever asks for the password (matching the rest of the app's
// "one saved secret" pattern) and tries the common default username first.
async function login(host, password) {
  const r = await tryJson(host, "/control/login", {
    method: "POST",
    body: { name: "admin", password },
    headers: { "Content-Type": "application/json", Accept: "application/json" }
  });
  if (!r || r.status !== 200) return null;
  const cookie = lan.cookieValue(r.cookies, "agh_session");
  if (!cookie) return null;
  sessionCookie = cookie;
  sessionHost = host;
  return cookie;
}

async function authedGet(host, path) {
  if (!sessionCookie || sessionHost !== host) return null;
  const r = await tryJson(host, path, { headers: { Cookie: "agh_session=" + sessionCookie, Accept: "application/json" } });
  if (r && (r.status === 401 || r.status === 403)) { sessionCookie = null; return null; }
  return r;
}

async function authedPost(host, path, body) {
  if (!sessionCookie || sessionHost !== host) return null;
  return tryJson(host, path, {
    method: "POST",
    body,
    headers: { "Content-Type": "application/json", Cookie: "agh_session=" + sessionCookie }
  });
}

async function ensureAuth() {
  const t = pi.resolveTarget();
  const password = apiPassword();
  if (!t.host || !password) return null;
  if (sessionCookie && sessionHost === t.host) {
    const ping = await authedGet(t.host, "/control/status");
    if (ping && ping.status === 200) return t.host;
  }
  return (await login(t.host, password)) ? t.host : null;
}

async function stats() {
  const t = pi.resolveTarget();
  if (!t.discovered) {
    return { available: false, reason: "No Pi has been discovered on this network yet", host: t.host };
  }
  if (!apiPassword()) {
    return {
      available: false, reason: "Add the AdGuard Home admin password in Preferences",
      host: t.host, sshPort: t.port, sshUser: t.user, needsPassword: true
    };
  }
  const host = await ensureAuth();
  if (!host) {
    return {
      available: false,
      reason: "Could not log in to AdGuard Home. Check the password and that this PC can open http://" + t.host + "/",
      host: t.host, sshPort: t.port, sshUser: t.user
    };
  }
  const [statusR, statsR] = await Promise.all([
    authedGet(host, "/control/status"),
    authedGet(host, "/control/stats")
  ]);
  const status = (statusR && statusR.json) || {};
  const s = (statsR && statsR.json) || {};
  const queries = Array.isArray(s.dns_queries) ? s.dns_queries.reduce((a, b) => a + b, 0) : (s.num_dns_queries || 0);
  const blocked = Array.isArray(s.blocked_filtering) ? s.blocked_filtering.reduce((a, b) => a + b, 0) : (s.num_blocked_filtering || 0);
  const blockedList = (s.top_blocked_domains || []).slice(0, 8)
    .map((row) => { const [domain] = Object.keys(row); return { domain, hits: row[domain] }; });
  const talkers = (s.top_clients || []).slice(0, 8)
    .map((row) => { const [ip] = Object.keys(row); return { name: ip, ip, queries: row[ip] }; });

  return {
    available: true,
    version: "adguard",
    host: t.host,
    sshPort: t.port,
    sshUser: t.user,
    queriesToday: queries,
    blockedToday: blocked,
    blockedPercent: queries ? Math.round((blocked / queries) * 1000) / 10 : 0,
    blocklist: null,
    firmware: status.version || null,
    hostNote: "AdGuard Home " + (status.version || "") + " connected",
    blocked: blockedList,
    talkers
  };
}

async function leases() {
  const host = await ensureAuth();
  if (!host) return [];
  const r = await authedGet(host, "/control/dhcp/status");
  const j = (r && r.json) || {};
  const list = (j.leases || []).concat(j.static_leases || []);
  return list.map((l) => ({
    ip: l.ip,
    mac: String(l.mac || "").toUpperCase(),
    hostname: l.hostname || null,
    expiry: l.expires || null,
    expires: l.expires ? new Date(l.expires).toLocaleString() : "static"
  })).filter((l) => l.ip && lan.isPrivateIp(l.ip));
}

// DNS-level block only — same caveat as the Pi-hole adapter's group-based
// block: a device that switches its DNS server bypasses this. AdGuard's
// access-control list is the only block primitive its API exposes.
async function blockClient(ip, { blocked } = { blocked: true }) {
  if (!lan.isPrivateIp(ip)) return { ok: false, reason: "not a LAN address" };
  const host = await ensureAuth();
  if (!host) {
    return { ok: false, reason: "AdGuard Home internet blocking needs a live API session. Add the admin password in Preferences." };
  }
  const listR = await authedGet(host, "/control/access/list");
  const cur = (listR && listR.json) || { allowed_clients: [], disallowed_clients: [], blocked_hosts: [] };
  const disallowed = new Set(cur.disallowed_clients || []);
  if (blocked) disallowed.add(ip); else disallowed.delete(ip);
  await authedPost(host, "/control/access/set", {
    allowed_clients: cur.allowed_clients || [],
    disallowed_clients: Array.from(disallowed),
    blocked_hosts: cur.blocked_hosts || []
  });
  return { ok: true, blocked, via: "adguard-access-list" };
}

module.exports = { stats, leases, blockClient, setApiPassword, hasApiPassword };
