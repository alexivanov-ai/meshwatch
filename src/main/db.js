const path = require("path");
const { app } = require("electron");
const Database = require("better-sqlite3");

let db = null;

function file() {
  // Stored in the OS user-data folder, not in the project.
  return path.join(app.getPath("userData"), "meshwatch.db");
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
    ");"
  );

  // Lightweight migration for a devices.db created before a column existed -
  // CREATE TABLE IF NOT EXISTS above is a no-op against an existing table.
  const existingColumns = new Set(db.prepare("PRAGMA table_info(devices)").all().map(c => c.name));
  const newColumns = {
    model: "TEXT", end_of_support: "TEXT", matched_by: "TEXT",
    web_reachable: "INTEGER DEFAULT 0", web_title: "TEXT", web_server: "TEXT", web_login_form: "INTEGER DEFAULT 0",
    name_override: "TEXT"
  };
  for (const [name, type] of Object.entries(newColumns)) {
    if (!existingColumns.has(name)) db.exec("ALTER TABLE devices ADD COLUMN " + name + " " + type);
  }

  return db;
}

function recordScan(devices) {
  // Drop non-host addresses left from older builds (broadcast .255, network .0).
  db.prepare(
    "DELETE FROM devices WHERE ip GLOB '*.0' OR ip GLOB '*.255' OR ip = '255.255.255.255' OR ip = '0.0.0.0'"
  ).run();

  const now = Date.now();
  const upsert = db.prepare(
    "INSERT INTO devices (mac, ip, name, vendor, model, type, parent_mac, parent_estimated, link, signal," +
    " firmware, firmware_latest, firmware_source, end_of_support, control, estimated, matched_by," +
    " web_reachable, web_title, web_server, web_login_form, first_seen, last_seen)" +
    " VALUES (@mac, @ip, @name, @vendor, @model, @type, @parent_mac, @parent_estimated, @link, @signal," +
    " @firmware, @firmware_latest, @firmware_source, @end_of_support, @control, @estimated, @matched_by," +
    " @web_reachable, @web_title, @web_server, @web_login_form, @now, @now)" +
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
        now
      });
      sight.run(d.mac, d.ip || null, now, (d.methods || []).join("+") || "unknown");
    }
  });
  tx(devices);
  notePiHoleDiscovery(devices);
  return devices.length;
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
      // What the UI shows — user rename wins over discovery.
      name: nameOverride || discoveredName
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

function setSetting(key, value) {
  db.prepare(
    "INSERT INTO settings (key, value) VALUES (?, ?)" +
    " ON CONFLICT(key) DO UPDATE SET value = excluded.value"
  ).run(key, value == null ? null : String(value));
  return { ok: true };
}

function getSettings(keys) {
  const out = {};
  for (const key of keys) out[key] = getSetting(key, null);
  return out;
}

function looksLikePiHole(d) {
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
function notePiHoleDiscovery(devices) {
  const hit = (devices || []).find(looksLikePiHole);
  if (!hit) return getPiHoleState();

  setSetting("pihole_discovered", "1");
  if (hit.mac) setSetting("pihole_mac", hit.mac);
  if (hit.ip) setSetting("pihole_ip", hit.ip);
  return getPiHoleState();
}

function getPiHoleState() {
  const discovered = getSetting("pihole_discovered") === "1";
  const mac = getSetting("pihole_mac");
  const ip = getSetting("pihole_ip");
  const sshPortRaw = getSetting("pihole_ssh_port");
  const sshUser = getSetting("pihole_ssh_user") || "admin";
  let sshPort = Number(sshPortRaw);
  if (!Number.isFinite(sshPort) || sshPort < 1 || sshPort > 65535) {
    // No user preference yet — standard SSH. Custom ports (2222, etc.) are
    // set in Preferences; never assume one for every install.
    sshPort = 22;
  }

  // Live match from the last scan, if still present.
  const live = listDevices().find((d) =>
    (mac && d.mac === mac) || looksLikePiHole(d)
  ) || null;

  if (live) {
    setSetting("pihole_discovered", "1");
    if (live.mac) setSetting("pihole_mac", live.mac);
    if (live.ip) setSetting("pihole_ip", live.ip);
  }

  return {
    discovered: discovered || !!live,
    remembered: getSetting("pihole_discovered") === "1",
    mac: (live && live.mac) || mac || null,
    ip: (live && live.ip) || ip || null,
    sshPort: sshPort,
    sshUser,
    online: !!live
  };
}

function setPiHolePrefs({ sshPort, sshUser } = {}) {
  if (sshPort != null && sshPort !== "") {
    const n = Number(sshPort);
    if (!Number.isFinite(n) || n < 1 || n > 65535) {
      return { ok: false, reason: "SSH port must be between 1 and 65535" };
    }
    setSetting("pihole_ssh_port", String(Math.floor(n)));
  }
  if (sshUser != null) {
    const user = String(sshUser).trim();
    if (!user) {
      return { ok: false, reason: "SSH username cannot be empty" };
    }
    setSetting("pihole_ssh_user", user);
  }
  return { ok: true, state: getPiHoleState() };
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

module.exports = {
  init, recordScan, listDevices, setNote, setNameOverride, setFirmwareManual,
  saveCredential, listCredentialMeta, getCredential, removeCredential,
  getSetting, setSetting, getSettings,
  looksLikePiHole, notePiHoleDiscovery, getPiHoleState, setPiHolePrefs,
  listDismissedFindingKeys, dismissFinding, restoreFinding,
  handle: () => db
};