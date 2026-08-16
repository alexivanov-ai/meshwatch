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
    ");"
  );

  // Lightweight migration for a devices.db created before a column existed -
  // CREATE TABLE IF NOT EXISTS above is a no-op against an existing table.
  const existingColumns = new Set(db.prepare("PRAGMA table_info(devices)").all().map(c => c.name));
  const newColumns = {
    model: "TEXT", end_of_support: "TEXT", matched_by: "TEXT",
    web_reachable: "INTEGER DEFAULT 0", web_title: "TEXT", web_server: "TEXT", web_login_form: "INTEGER DEFAULT 0"
  };
  for (const [name, type] of Object.entries(newColumns)) {
    if (!existingColumns.has(name)) db.exec("ALTER TABLE devices ADD COLUMN " + name + " " + type);
  }

  return db;
}

function recordScan(devices) {
  const now = Date.now();
  const upsert = db.prepare(
    "INSERT INTO devices (mac, ip, name, vendor, model, type, parent_mac, parent_estimated, link, signal," +
    " firmware, firmware_latest, firmware_source, end_of_support, control, estimated, matched_by," +
    " web_reachable, web_title, web_server, web_login_form, first_seen, last_seen)" +
    " VALUES (@mac, @ip, @name, @vendor, @model, @type, @parent_mac, @parent_estimated, @link, @signal," +
    " @firmware, @firmware_latest, @firmware_source, @end_of_support, @control, @estimated, @matched_by," +
    " @web_reachable, @web_title, @web_server, @web_login_form, @now, @now)" +
    " ON CONFLICT(mac) DO UPDATE SET" +
    " ip=excluded.ip, name=COALESCE(excluded.name, devices.name)," +
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
  return devices.length;
}

function listDevices() {
  const devices = db.prepare("SELECT * FROM devices ORDER BY last_seen DESC").all();
  const lastMethod = db.prepare("SELECT method FROM sightings WHERE mac = ? ORDER BY seen_at DESC LIMIT 1");
  return devices.map((d) => {
    const s = lastMethod.get(d.mac);
    const methods = s && s.method ? String(s.method).split("+").filter(Boolean) : [];
    return Object.assign({}, d, { methods });
  });
}

function setNote(mac, note) {
  db.prepare("UPDATE devices SET note = ? WHERE mac = ?").run(note, mac);
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

module.exports = {
  init, recordScan, listDevices, setNote,
  saveCredential, listCredentialMeta, getCredential, removeCredential,
  handle: () => db
};
