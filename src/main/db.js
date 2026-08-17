const path = require("path");
const { app } = require("electron");
const Database = require("better-sqlite3");

let db = null;

function file() {
  // Stored in the OS user-data folder, not in the project.
  return path.join(app.getPath("userData"), "meshwatch.db");
}

// Same path as file() — a stable name for callers outside this module
// (backup/restore in index.js) that shouldn't need to know file() exists.
function filePath() {
  return file();
}

// Flush the WAL file into the main db file. WAL mode (see init() below)
// means recent writes can live only in the -wal sidecar file; a raw copy of
// the main file without this first can silently miss them. Call this right
// before any backup/copy of the db file.
function checkpoint() {
  db.pragma("wal_checkpoint(TRUNCATE)");
}

// Close the live connection. Needed before restore overwrites the db file:
// on Windows, better-sqlite3 keeps an open file handle for as long as the
// connection is open, and fs.rename()/ReplaceFile onto a file with an open
// handle fails with EPERM — so the file must be closed first, after it has
// already been checkpointed. Only ever called right before app.exit(),
// since nothing else in this process can use the db afterward.
function close() {
  if (db) {
    db.close();
    db = null;
  }
}

function init() {
  db = new Database(file());
  db.pragma("journal_mode = WAL");
  db.exec(
    "CREATE TABLE IF NOT EXISTS devices (" +
    "  mac TEXT PRIMARY KEY," +
    "  ip TEXT, name TEXT, vendor TEXT, model TEXT, type TEXT," +
    "  parent_mac TEXT, parent_estimated INTEGER DEFAULT 0," +
    "  link TEXT, signal TEXT," +
    "  firmware TEXT, firmware_latest TEXT, firmware_source TEXT," +
    "  firmware_manual TEXT, end_of_support TEXT," +
    "  control TEXT, estimated INTEGER DEFAULT 0, matched_by TEXT," +
    "  web_reachable INTEGER DEFAULT 0, web_title TEXT, web_server TEXT, web_login_form INTEGER DEFAULT 0," +
    "  note TEXT," +
    "  first_seen INTEGER, last_seen INTEGER" +
    ");" +
    "CREATE TABLE IF NOT EXISTS sightings (" +
    "  id INTEGER PRIMARY KEY AUTOINCREMENT," +
    "  mac TEXT, ip TEXT, seen_at INTEGER, method TEXT" +
    ");" +
    "CREATE INDEX IF NOT EXISTS idx_sightings_mac ON sightings(mac);" +
    "CREATE TABLE IF NOT EXISTS findings (" +
    "  id INTEGER PRIMARY KEY AUTOINCREMENT," +
    "  mac TEXT, severity TEXT, title TEXT, detail TEXT," +
    "  reference TEXT, action TEXT, found_at INTEGER, resolved_at INTEGER" +
    ");" +
    // password_enc is ciphertext from Electron's safeStorage (OS DPAPI on
    // Windows) - see credentials.js. Nothing in this table is ever readable
    // outside this machine, this OS user account.
    "CREATE TABLE IF NOT EXISTS credentials (" +
    "  mac TEXT PRIMARY KEY," +
    "  label TEXT, username TEXT, password_enc BLOB," +
    "  updated_at INTEGER" +
    ");" +
    // App preferences that must survive reinstalls of the UI and travel with
    // the OS user profile (e.g. "we once saw a Pi-hole on this LAN").
    "CREATE TABLE IF NOT EXISTS settings (" +
    "  key TEXT PRIMARY KEY," +
    "  value TEXT" +
    ");" +
    // User-dismissed audit findings (rule:mac). Excluded from posture score
    // until restored. Survives re-runs of the audit.
    "CREATE TABLE IF NOT EXISTS finding_dismissals (" +
    "  key TEXT PRIMARY KEY," +
    "  dismissed_at INTEGER" +
    ");" +
    // Cache of self-hosted services auto-detected on the Pi (open port +
    // title probe + small catalog match, see pi-services.js). Per-MAC so a
    // re-detected Pi's stale ports don't linger.
    "CREATE TABLE IF NOT EXISTS pi_services (" +
    "  mac TEXT, port INTEGER, name TEXT, category TEXT, title TEXT," +
    "  updated_at INTEGER," +
    "  PRIMARY KEY (mac, port)" +
    ");" +
    // One row per audit run, so the Security view can show a posture-score
    // trend line instead of just the latest number.
    "CREATE TABLE IF NOT EXISTS audit_runs (" +
    "  id INTEGER PRIMARY KEY AUTOINCREMENT," +
    "  ts INTEGER, score INTEGER, counts_json TEXT" +
    ");" +
    // Periodic round-trip latency samples to the gateway and (if present)
    // the Pi — see latency.js. ms is NULL when a sample timed out.
    "CREATE TABLE IF NOT EXISTS latency_samples (" +
    "  id INTEGER PRIMARY KEY AUTOINCREMENT," +
    "  ts INTEGER, target TEXT, ms INTEGER" +
    ");" +
    "CREATE INDEX IF NOT EXISTS idx_latency_target ON latency_samples(target, ts);" +
    // Snapshot of Pi-hole/AdGuard "top talkers" taken on every pi:stats
    // call, so the Overview view can show a per-client DNS query trend
    // instead of only the current snapshot. See dns.stats()'s `talkers`.
    "CREATE TABLE IF NOT EXISTS dns_talkers_history (" +
    "  id INTEGER PRIMARY KEY AUTOINCREMENT," +
    "  ts INTEGER, client_ip TEXT, client_name TEXT, queries INTEGER" +
    ");" +
    "CREATE INDEX IF NOT EXISTS idx_talkers_client ON dns_talkers_history(client_ip, ts);"
  );

  // Lightweight migration for a devices.db created before a column existed -
  // CREATE TABLE IF NOT EXISTS above is a no-op against an existing table.
  const existingColumns = new Set(db.prepare("PRAGMA table_info(devices)").all().map(c => c.name));
  const newColumns = {
    model: "TEXT", end_of_support: "TEXT", matched_by: "TEXT",
    web_reachable: "INTEGER DEFAULT 0", web_title: "TEXT", web_server: "TEXT", web_login_form: "INTEGER DEFAULT 0",
    name_override: "TEXT",
    open_ports: "TEXT",
    query_count: "INTEGER",
    clients: "INTEGER",
    watched: "INTEGER DEFAULT 0",
    blocked: "INTEGER DEFAULT 0",
    ssdp_st: "TEXT",
    tags: "TEXT DEFAULT '[]'",
    services: "TEXT DEFAULT '[]'"
  };
  for (const [name, type] of Object.entries(newColumns)) {
    if (!existingColumns.has(name)) db.exec("ALTER TABLE devices ADD COLUMN " + name + " " + type);
  }

  migrateLegacyPiKeys();

  return db;
}

// This install already has pihole_* settings from before the Pi-hole/AdGuard
// rename (the Pi was discovered and confirmed before this rename existed).
// One-time copy so existing users don't lose their remembered Pi.
//
// Strictly once per install: guarded by the pi_keys_migrated marker below.
// This used to re-run on every startup and re-copy any pair whose new key
// read back as null — which silently resurrected a secret (or an SSH
// port/user) the user had deliberately cleared, with no way to remove it
// permanently through the UI. setSetting(key, null) now deletes the row
// rather than writing a NULL value, and the marker means a cleared key stays
// cleared even if a NULL row ever reappears some other way.
function migrateLegacyPiKeys() {
  if (getSetting("pi_keys_migrated") === "1") return;
  const pairs = [
    ["pihole_discovered", "pi_discovered"],
    ["pihole_mac", "pi_mac"],
    ["pihole_ip", "pi_ip"],
    ["pihole_ssh_port", "pi_ssh_port"],
    ["pihole_ssh_user", "pi_ssh_user"],
    ["pihole_ssh_key", "pi_ssh_key"]
  ];
  // Installs that predate the marker but already ran the old, repeating
  // version of this migration: pi_discovered proves the copy happened at
  // least once, so anything missing on the new side now is missing because
  // the user cleared it, not because it was never copied. Mark and stop —
  // re-copying here would resurrect exactly what this guard exists to keep
  // deleted (a fresh post-rename install has nothing to copy either way).
  if (getSetting("pi_discovered", null) != null) {
    setSetting("pi_keys_migrated", "1");
    return;
  }
  for (const [oldKey, newKey] of pairs) {
    const oldVal = getSetting(oldKey, null);
    const newVal = getSetting(newKey, null);
    if (oldVal != null && newVal == null) setSetting(newKey, oldVal);
  }
  // Credential vault secret rename: pihole_api -> dns_api (see credentials.js).
  const oldSecret = getSetting("secret:pihole_api", null);
  const newSecret = getSetting("secret:dns_api", null);
  if (oldSecret != null && newSecret == null) setSetting("secret:dns_api", oldSecret);
  setSetting("pi_keys_migrated", "1");
}

function recordScan(devices) {
  // Drop non-host addresses left from older builds (broadcast .255, network .0).
  db.prepare(
    "DELETE FROM devices WHERE ip GLOB '*.0' OR ip GLOB '*.255' OR ip = '255.255.255.255' OR ip = '0.0.0.0'"
  ).run();

  // Snapshot MACs already known before this scan's upsert, so callers can
  // tell a genuinely-new device (never seen before) from a returning one.
  const existingMacs = new Set(db.prepare("SELECT mac FROM devices").all().map((r) => r.mac));
  const newMacs = devices.filter((d) => d.mac && !existingMacs.has(d.mac)).map((d) => d.mac);

  const now = Date.now();
  const upsert = db.prepare(
    "INSERT INTO devices (mac, ip, name, vendor, model, type, parent_mac, parent_estimated, link, signal," +
    " firmware, firmware_latest, firmware_source, end_of_support, control, estimated, matched_by," +
    " web_reachable, web_title, web_server, web_login_form, open_ports, query_count, clients, ssdp_st, services, first_seen, last_seen)" +
    " VALUES (@mac, @ip, @name, @vendor, @model, @type, @parent_mac, @parent_estimated, @link, @signal," +
    " @firmware, @firmware_latest, @firmware_source, @end_of_support, @control, @estimated, @matched_by," +
    " @web_reachable, @web_title, @web_server, @web_login_form, @open_ports, @query_count, @clients, @ssdp_st, @services, @now, @now)" +
    " ON CONFLICT(mac) DO UPDATE SET" +
    " ip=excluded.ip," +
    // Keep the scanned/discovered name in `name`, but never wipe a user rename.
    " name=excluded.name," +
    " vendor=COALESCE(excluded.vendor, devices.vendor), model=excluded.model, type=COALESCE(excluded.type, devices.type)," +
    " parent_mac=excluded.parent_mac, parent_estimated=excluded.parent_estimated," +
    " link=excluded.link, signal=excluded.signal," +
    " firmware=COALESCE(excluded.firmware, devices.firmware)," +
    " firmware_latest=COALESCE(excluded.firmware_latest, devices.firmware_latest)," +
    " firmware_source=COALESCE(excluded.firmware_source, devices.firmware_source)," +
    " end_of_support=excluded.end_of_support, control=excluded.control, estimated=excluded.estimated," +
    " matched_by=excluded.matched_by," +
    " web_reachable=excluded.web_reachable, web_title=excluded.web_title," +
    " web_server=excluded.web_server, web_login_form=excluded.web_login_form," +
    " open_ports=COALESCE(excluded.open_ports, devices.open_ports)," +
    " query_count=COALESCE(excluded.query_count, devices.query_count)," +
    " clients=COALESCE(excluded.clients, devices.clients)," +
    " ssdp_st=COALESCE(excluded.ssdp_st, devices.ssdp_st)," +
    // Same reasoning as ssdp_st above, but COALESCE can't express it: this
    // column is never NULL, it's an empty JSON array when a scan caught no
    // mDNS/SSDP advertisement. A sweep that sees no multicast (common — it
    // happens on every scan on some LANs) must not wipe the services chips
    // recorded by an earlier sweep that did.
    " services=CASE WHEN excluded.services = '[]' THEN devices.services ELSE excluded.services END," +
    " last_seen=@now"
  );
  const sight = db.prepare("INSERT INTO sightings (mac, ip, seen_at, method) VALUES (?, ?, ?, ?)");

  const tx = db.transaction((list) => {
    for (const d of list) {
      const web = d.web || {};
      upsert.run({
        mac: d.mac, ip: d.ip || null, name: d.name || null, vendor: d.vendor || null,
        model: d.model || null, type: d.type || null, parent_mac: d.parentMac || null,
        parent_estimated: d.parentEstimated ? 1 : 0,
        link: d.link || null, signal: d.signal || null,
        firmware: d.firmware || null, firmware_latest: d.firmwareLatest || null,
        firmware_source: d.firmwareSource || null, end_of_support: d.endOfSupport || null,
        control: d.control || null, estimated: d.estimated ? 1 : 0, matched_by: d.matchedBy || null,
        web_reachable: web.reachable ? 1 : 0, web_title: web.title || null,
        web_server: web.server || null, web_login_form: web.hasLoginForm ? 1 : 0,
        open_ports: d.openPorts ? JSON.stringify(d.openPorts) : null,
        query_count: d.queryCount != null ? d.queryCount : null,
        clients: d.clients != null ? d.clients : null,
        ssdp_st: (d.ssdpHit && d.ssdpHit.st) || d.ssdp_st || null,
        services: JSON.stringify(d.services || []),
        now
      });
      sight.run(d.mac, d.ip || null, now, (d.methods || []).join("+") || "unknown");
    }
  });
  tx(devices);
  notePiDiscovery(devices);
  return { newMacs };
}

// Per-day online ratio for the last N days, from the sightings table. Each
// day's ratio is that day's sighting count relative to the busiest day in
// the window (not a fraction of scans actually run), so a device seen every
// scan reads as a flat high line and a day with no sightings reads as 0.
function deviceUptimeHistory(mac, days = 14) {
  const since = Date.now() - days * 86400000;
  const rows = db.prepare(
    "SELECT seen_at FROM sightings WHERE mac = ? AND seen_at >= ? ORDER BY seen_at"
  ).all(mac, since);
  const byDay = new Map();
  for (const r of rows) {
    const day = new Date(r.seen_at).toISOString().slice(0, 10);
    byDay.set(day, (byDay.get(day) || 0) + 1);
  }
  const maxPerDay = Math.max(1, ...Array.from(byDay.values()));
  const out = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
    out.push({ day: d, onlineRatio: byDay.has(d) ? Math.min(1, byDay.get(d) / maxPerDay) : 0 });
  }
  return out;
}

function listDevices() {
  const devices = db.prepare("SELECT * FROM devices ORDER BY last_seen DESC").all();
  const lastMethod = db.prepare("SELECT method FROM sightings WHERE mac = ? ORDER BY seen_at DESC LIMIT 1");
  return devices
    .filter((d) => {
      if (!d.ip) return true;
      const last = Number(String(d.ip).split(".").pop());
      // Inventory is hosts only — never network (.0) or broadcast (.255).
      return last >= 1 && last <= 254;
    })
    .map((d) => {
    const s = lastMethod.get(d.mac);
    const methods = s && s.method ? String(s.method).split("+").filter(Boolean) : [];
    const discoveredName = d.name;
    const nameOverride = d.name_override || null;
    return Object.assign({}, d, {
      methods,
      discoveredName,
      nameOverride,
      name: nameOverride || discoveredName,
      openPorts: d.open_ports ? safeJson(d.open_ports, []) : [],
      tags: safeJson(d.tags, []) || [],
      services: safeJson(d.services, []) || [],
      watched: !!d.watched,
      blocked: !!d.blocked,
      queryCount: d.query_count,
      clients: d.clients
    });
  });
}

function setNote(mac, note) {
  db.prepare("UPDATE devices SET note = ? WHERE mac = ?").run(note, mac);
  return { ok: true };
}

function setNameOverride(mac, name) {
  const trimmed = name == null ? "" : String(name).trim();
  if (!trimmed) {
    db.prepare("UPDATE devices SET name_override = NULL WHERE mac = ?").run(mac);
    return { ok: true, nameOverride: null };
  }
  if (trimmed.length > 120) return { ok: false, reason: "Name is too long (max 120 characters)" };
  db.prepare("UPDATE devices SET name_override = ? WHERE mac = ?").run(trimmed, mac);
  return { ok: true, nameOverride: trimmed };
}

function setFirmwareManual(mac, version) {
  db.prepare(
    "UPDATE devices SET firmware_manual = ?, firmware = COALESCE(?, firmware), firmware_source = ? WHERE mac = ?"
  ).run(version || null, version || null, version ? "manual" : null, mac);
  return { ok: true };
}

function setOpenPorts(mac, ports) {
  db.prepare("UPDATE devices SET open_ports = ? WHERE mac = ?").run(ports ? JSON.stringify(ports) : null, mac);
  return { ok: true };
}

function setWatched(mac, watched) {
  db.prepare("UPDATE devices SET watched = ? WHERE mac = ?").run(watched ? 1 : 0, mac);
  return { ok: true };
}

function setBlocked(mac, blocked) {
  db.prepare("UPDATE devices SET blocked = ? WHERE mac = ?").run(blocked ? 1 : 0, mac);
  return { ok: true };
}

function setDeviceTags(mac, tags) {
  db.prepare("UPDATE devices SET tags = ? WHERE mac = ?").run(JSON.stringify(tags || []), mac);
  return { ok: true };
}

function setQueryCount(mac, n) {
  db.prepare("UPDATE devices SET query_count = ? WHERE mac = ?").run(n == null ? null : Number(n), mac);
}

function setClients(mac, n) {
  db.prepare("UPDATE devices SET clients = ? WHERE mac = ?").run(n == null ? null : Number(n), mac);
}

function updateDeviceFields(mac, fields) {
  const allowed = {
    parent_mac: "parent_mac", parent_estimated: "parent_estimated",
    link: "link", signal: "signal", firmware: "firmware",
    firmware_latest: "firmware_latest", firmware_source: "firmware_source",
    clients: "clients", query_count: "query_count", open_ports: "open_ports"
  };
  const sets = [];
  const vals = [];
  for (const [k, col] of Object.entries(allowed)) {
    if (Object.prototype.hasOwnProperty.call(fields, k)) {
      sets.push(col + " = ?");
      let v = fields[k];
      if (k === "open_ports" && v && typeof v !== "string") v = JSON.stringify(v);
      if (k === "parent_estimated") v = v ? 1 : 0;
      vals.push(v == null ? null : v);
    }
  }
  if (!sets.length) return { ok: false };
  vals.push(mac);
  db.prepare("UPDATE devices SET " + sets.join(", ") + " WHERE mac = ?").run(...vals);
  return { ok: true };
}

const DEFAULT_PREFS = {
  showOffline: true,
  autoScan: false,
  theme: "system",
  scanIntervalMin: 15,
  notifyNewDevice: true,
  startWithSystem: false,
  deepPortScan: "weekly",
  firmwareSync: true
};

function getPrefs() {
  let parsed = {};
  try { parsed = JSON.parse(getSetting("prefs_json") || "{}"); } catch (e) { parsed = {}; }
  return Object.assign({}, DEFAULT_PREFS, parsed);
}

function setPrefs(patch) {
  const next = Object.assign(getPrefs(), patch || {});
  if (next.scanIntervalMin != null) {
    const n = Number(next.scanIntervalMin);
    next.scanIntervalMin = Number.isFinite(n) ? Math.max(0, Math.min(1440, n)) : 15;
  }
  setSetting("prefs_json", JSON.stringify(next));
  return { ok: true, prefs: next };
}

// --- credentials -------------------------------------------------------
// Encrypt/decrypt happens in credentials.js. This is just encrypted-blob
// storage keyed by MAC, plus metadata (label/username) that's safe to list
// in the renderer without ever touching the plaintext password.

function saveCredential(mac, { label, username, passwordEnc }) {
  db.prepare(
    "INSERT INTO credentials (mac, label, username, password_enc, updated_at) VALUES (?, ?, ?, ?, ?)" +
    " ON CONFLICT(mac) DO UPDATE SET label=excluded.label, username=excluded.username," +
    " password_enc=excluded.password_enc, updated_at=excluded.updated_at"
  ).run(mac, label || null, username || null, passwordEnc, Date.now());
  return { ok: true };
}

function listCredentialMeta() {
  return db.prepare("SELECT mac, label, username, updated_at FROM credentials ORDER BY updated_at DESC").all();
}

function getCredential(mac) {
  return db.prepare("SELECT * FROM credentials WHERE mac = ?").get(mac) || null;
}

function removeCredential(mac) {
  db.prepare("DELETE FROM credentials WHERE mac = ?").run(mac);
  return { ok: true };
}

function getSetting(key, fallback = null) {
  const row = db.prepare("SELECT value FROM settings WHERE key = ?").get(key);
  return row ? row.value : fallback;
}

// A null/empty value REMOVES the row rather than storing a NULL value. A row
// with a NULL value is indistinguishable from "never set" to every reader
// here (getSetting returns null either way) but it is not the same thing to
// a writer testing `== null` before filling a default in — that mismatch is
// what let migrateLegacyPiKeys() resurrect a deleted secret on every launch.
// Clearing means gone.
function setSetting(key, value) {
  if (value == null) {
    db.prepare("DELETE FROM settings WHERE key = ?").run(key);
    return { ok: true };
  }
  db.prepare(
    "INSERT INTO settings (key, value) VALUES (?, ?)" +
    " ON CONFLICT(key) DO UPDATE SET value = excluded.value"
  ).run(key, String(value));
  return { ok: true };
}

function safeJson(text, fallback) {
  try { return JSON.parse(text); } catch (e) { return fallback; }
}

function getSettings(keys) {
  const out = {};
  for (const key of keys) out[key] = getSetting(key, null);
  return out;
}

function looksLikePi(d) {
  if (!d) return false;
  if (d.type === "dns-dhcp" || d.control === "ssh") return true;
  const vendor = String(d.vendor || "").toLowerCase();
  const name = String(d.name || "").toLowerCase();
  const title = String(d.web_title || (d.web && d.web.title) || "").toLowerCase();
  const model = String(d.model || "").toLowerCase();
  if (vendor.indexOf("raspberry") !== -1) return true;
  if (/pi-?hole/.test(name) || /pi-?hole/.test(title)) return true;
  if (/^pi\s*[345]/.test(name) || model.indexOf("pi 5") !== -1 || model.indexOf("pi 4") !== -1) return true;
  return false;
}

// Remember that this machine's LAN once had a Pi / Pi-hole so the sidebar
// entry can stay available even when the Pi is offline on a later scan.
function notePiDiscovery(devices) {
  const hit = (devices || []).find(looksLikePi);
  if (!hit) return getPiState();

  setSetting("pi_discovered", "1");
  if (hit.mac) setSetting("pi_mac", hit.mac);
  if (hit.ip) setSetting("pi_ip", hit.ip);
  return getPiState();
}

function getPiState() {
  const discovered = getSetting("pi_discovered") === "1";
  const mac = getSetting("pi_mac");
  const ip = getSetting("pi_ip");
  const sshPortRaw = getSetting("pi_ssh_port");
  const sshUser = getSetting("pi_ssh_user") || "admin";
  let sshPort = Number(sshPortRaw);
  if (!Number.isFinite(sshPort) || sshPort < 1 || sshPort > 65535) {
    // No user preference yet — standard SSH. Custom ports (2222, etc.) are
    // set in Preferences; never assume one for every install.
    sshPort = 22;
  }

  // Live match from the last scan, if still present.
  const live = listDevices().find((d) =>
    (mac && d.mac === mac) || looksLikePi(d)
  ) || null;

  if (live) {
    setSetting("pi_discovered", "1");
    if (live.mac) setSetting("pi_mac", live.mac);
    if (live.ip) setSetting("pi_ip", live.ip);
  }

  return {
    discovered: discovered || !!live,
    remembered: getSetting("pi_discovered") === "1",
    mac: (live && live.mac) || mac || null,
    ip: (live && live.ip) || ip || null,
    sshPort: sshPort,
    sshUser,
    keyPath: getSetting("pi_ssh_key"),
    online: !!live
  };
}

function setPiPrefs({ sshPort, sshUser } = {}) {
  if (sshPort != null && sshPort !== "") {
    const n = Number(sshPort);
    if (!Number.isFinite(n) || n < 1 || n > 65535) {
      return { ok: false, reason: "SSH port must be between 1 and 65535" };
    }
    setSetting("pi_ssh_port", String(Math.floor(n)));
  }
  if (sshUser != null) {
    const user = String(sshUser).trim();
    if (!user) {
      return { ok: false, reason: "SSH username cannot be empty" };
    }
    setSetting("pi_ssh_user", user);
  }
  return { ok: true, state: getPiState() };
}

function listDismissedFindingKeys() {
  return db.prepare("SELECT key FROM finding_dismissals").all().map((r) => r.key);
}

function dismissFinding(key) {
  db.prepare(
    "INSERT INTO finding_dismissals (key, dismissed_at) VALUES (?, ?)" +
    " ON CONFLICT(key) DO UPDATE SET dismissed_at = excluded.dismissed_at"
  ).run(key, Date.now());
  return { ok: true };
}

function restoreFinding(key) {
  db.prepare("DELETE FROM finding_dismissals WHERE key = ?").run(key);
  return { ok: true };
}

// --- pi_services --------------------------------------------------------
// Cache of auto-detected self-hosted services on the Pi. Full replace per
// mac each time discoverServices() runs, so stale ports don't linger.

function saveServices(mac, services) {
  const now = Date.now();
  const del = db.prepare("DELETE FROM pi_services WHERE mac = ?");
  const ins = db.prepare(
    "INSERT INTO pi_services (mac, port, name, category, title, updated_at) VALUES (?,?,?,?,?,?)"
  );
  const tx = db.transaction((list) => {
    del.run(mac);
    for (const s of list) ins.run(mac, s.port, s.name, s.category, s.title, now);
  });
  tx(services);
  return { ok: true };
}

function getServices(mac) {
  return db.prepare("SELECT port, name, category, title FROM pi_services WHERE mac = ? ORDER BY port").all(mac);
}

// --- audit_runs ---------------------------------------------------------
// One row per Security audit run, so the UI can show a posture-score trend
// line rather than only the latest score.

function recordAuditRun(score, counts) {
  db.prepare("INSERT INTO audit_runs (ts, score, counts_json) VALUES (?, ?, ?)")
    .run(Date.now(), score, JSON.stringify(counts));
}

function auditHistory(limit = 30) {
  return db.prepare("SELECT ts, score, counts_json FROM audit_runs ORDER BY ts DESC LIMIT ?").all(limit)
    .reverse()
    .map((r) => ({ ts: r.ts, score: r.score, counts: safeJson(r.counts_json, {}) }));
}

// --- latency_samples -----------------------------------------------------
// Periodic round-trip latency to the gateway and (if present) the Pi. See
// latency.js's sampleOnce(), which is what actually pings and calls this.

function recordLatency(target, ms) {
  db.prepare("INSERT INTO latency_samples (ts, target, ms) VALUES (?,?,?)").run(Date.now(), target, ms);
}

function latencyHistory(target, limit = 50) {
  return db.prepare("SELECT ts, ms FROM latency_samples WHERE target = ? ORDER BY ts DESC LIMIT ?")
    .all(target, limit)
    .reverse();
}

// --- dns_talkers_history --------------------------------------------------
// One snapshot row per talker per pi:stats call, so the Overview view can
// show a per-client DNS query trend on click. All rows from one call share
// the same ts (Date.now() taken once), so a snapshot's talkers can be
// grouped back together by timestamp if ever needed.

function recordTalkers(talkers) {
  const now = Date.now();
  const ins = db.prepare(
    "INSERT INTO dns_talkers_history (ts, client_ip, client_name, queries) VALUES (?,?,?,?)"
  );
  const tx = db.transaction((list) => {
    for (const t of list) ins.run(now, t.ip || null, t.name || null, t.queries || 0);
  });
  tx(talkers || []);
}

function talkerHistory(clientIp, limit = 20) {
  return db.prepare(
    "SELECT ts, queries FROM dns_talkers_history WHERE client_ip = ? ORDER BY ts DESC LIMIT ?"
  ).all(clientIp, limit).reverse();
}

module.exports = {
  init, filePath, checkpoint, close,
  recordScan, listDevices, deviceUptimeHistory, setNote, setNameOverride, setFirmwareManual,
  setOpenPorts, setWatched, setBlocked, setQueryCount, setClients, setDeviceTags, updateDeviceFields,
  getPrefs, setPrefs, DEFAULT_PREFS,
  saveCredential, listCredentialMeta, getCredential, removeCredential,
  getSetting, setSetting, getSettings,
  looksLikePi, notePiDiscovery, getPiState, setPiPrefs,
  listDismissedFindingKeys, dismissFinding, restoreFinding,
  saveServices, getServices,
  recordAuditRun, auditHistory,
  recordLatency, latencyHistory,
  recordTalkers, talkerHistory,
  handle: () => db
};