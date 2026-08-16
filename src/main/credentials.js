// Local credential vault for devices found by discovery - a router admin
// login, a printer's web UI, anything with a login page.
//
// Storage: SQLite (see db.js's `credentials` table), keyed by device MAC.
// Encryption: Electron's safeStorage, which is backed by the OS itself -
// DPAPI on Windows, Keychain on macOS, libsecret on Linux. That satisfies
// CLAUDE.md's rule that credentials never live in a plain file: the blob on
// disk is ciphertext, and it only decrypts under this OS user account, on
// this machine. Nothing here calls out to a network.
//
// The plaintext password only ever exists in memory, transiently, when a
// caller asks to fill a login form (see reveal()). It is never sent back to
// the renderer as a bare string over IPC - see index.js's fill handler.

const { safeStorage } = require("electron");
const db = require("./db");

function available() {
  return safeStorage.isEncryptionAvailable();
}

function save(mac, { label, username, password }) {
  if (!available()) {
    return { ok: false, reason: "OS-level credential encryption isn't available on this machine" };
  }
  if (!mac || !password) return { ok: false, reason: "mac and password are required" };
  const passwordEnc = safeStorage.encryptString(password);
  db.saveCredential(mac, { label, username, passwordEnc });
  return { ok: true };
}

// Metadata only - label/username/when-saved. Safe to send to the renderer
// for a search/list UI; never includes the password.
function list() {
  return db.listCredentialMeta();
}

function has(mac) {
  return !!db.getCredential(mac);
}

// Decrypts and returns the plaintext password. Callers must not forward
// this to the renderer as a plain IPC return value - use it to script a
// same-process action (e.g. filling a webview) and let it go out of scope.
function reveal(mac) {
  const row = db.getCredential(mac);
  if (!row) return null;
  try {
    return {
      username: row.username || null,
      password: safeStorage.decryptString(Buffer.from(row.password_enc))
    };
  } catch (e) {
    return null; // undecryptable (e.g. vault created under a different OS user) - honest null, not a crash
  }
}

function remove(mac) {
  return db.removeCredential(mac);
}

// App-level secrets (Pi-hole API password, etc.) — still OS-encrypted,
// stored as base64 ciphertext in the settings table, never in the repo.
function setAppSecret(key, value) {
  if (!available()) return { ok: false, reason: "OS-level credential encryption isn't available on this machine" };
  if (!key) return { ok: false, reason: "missing key" };
  if (value == null || value === "") {
    db.setSetting("secret:" + key, null);
    return { ok: true };
  }
  const enc = safeStorage.encryptString(String(value));
  db.setSetting("secret:" + key, Buffer.from(enc).toString("base64"));
  return { ok: true };
}

function getAppSecret(key) {
  const b64 = db.getSetting("secret:" + key);
  if (!b64) return null;
  try {
    return safeStorage.decryptString(Buffer.from(b64, "base64"));
  } catch (e) {
    return null;
  }
}

function deleteAppSecret(key) {
  db.setSetting("secret:" + key, null);
  return { ok: true };
}

module.exports = {
  available, save, list, has, reveal, remove,
  setAppSecret, getAppSecret, deleteAppSecret
};
