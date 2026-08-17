// src/main/dns/index.js — detects which DNS/DHCP backend (if any) is
// running on the discovered Pi, caches the result, and routes every call
// to the matching adapter. Never assumes — see CLAUDE.md's rule against
// hardcoding a specific product for this box.
const db = require("../db");
const pi = require("../pi");
const lan = require("../lanhttp");
const ftl = require("./ftl");
const adguard = require("./adguard");

async function probeAdguard(host) {
  try {
    const r = await lan.request({ url: "http://" + host + "/control/status", timeoutMs: 3000 });
    if (!r) return false;
    if (r.status === 401 || r.status === 403) return true; // needs auth, but it's AdGuard
    return r.status === 200 && r.json && Array.isArray(r.json.dns_addresses);
  } catch (e) { return false; }
}

async function probeFtl(host) {
  try {
    const r = await lan.request({ url: "http://" + host + "/admin/api.php?status", timeoutMs: 3000 });
    return !!(r && r.json);
  } catch (e) { return false; }
}

async function detectBackend() {
  const t = pi.resolveTarget();
  if (!t.host) return "unknown";
  const [isAdguard, isFtl] = await Promise.all([probeAdguard(t.host), probeFtl(t.host)]);
  const backend = isAdguard ? "adguard" : (isFtl ? "ftl" : "unknown");
  db.setSetting("pi_dns_backend", backend);
  return backend;
}

function cachedBackend() {
  return db.getSetting("pi_dns_backend") || "unknown";
}

function adapterFor(backend) {
  if (backend === "adguard") return adguard;
  if (backend === "ftl") return ftl;
  return null;
}

// Version string from the most recent stats() call. getBackendInfo() used to
// run a full stats() of its own just to read this, which meant a second
// login + fetch cycle on every Pi tab load right next to the stats() call the
// UI makes anyway. Report what the last fetch saw; the renderer fills the
// version in from its own stats() result when that resolves.
let lastVersion = null;

function getBackendInfo() {
  const backend = cachedBackend();
  if (backend === "unknown") return null;
  return { name: backend === "adguard" ? "AdGuard Home" : "Pi-hole", version: lastVersion };
}

async function stats() {
  const a = adapterFor(cachedBackend());
  if (!a) return { available: false, reason: "No DNS management service detected on this Pi yet" };
  const s = await a.stats();
  if (s && s.available && s.firmware) lastVersion = s.firmware;
  return s;
}

async function leases() {
  const a = adapterFor(cachedBackend());
  return a ? a.leases() : [];
}

async function blockClient(ip, opts) {
  const a = adapterFor(cachedBackend());
  if (!a) return { ok: false, reason: "No DNS backend detected" };
  return a.blockClient(ip, opts);
}

function setApiPassword(password) {
  const a = adapterFor(cachedBackend()) || ftl; // no backend detected yet: still let the user save a password
  return a.setApiPassword(password);
}

function hasApiPassword() {
  const a = adapterFor(cachedBackend()) || ftl;
  return a.hasApiPassword();
}

module.exports = { detectBackend, cachedBackend, getBackendInfo, stats, leases, blockClient, setApiPassword, hasApiPassword };
