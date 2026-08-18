const { app, BrowserWindow, ipcMain, dialog, nativeTheme, Tray, Menu, Notification, nativeImage } = require("electron");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");
const fsPromises = require("fs/promises");
const db = require("./db");
const discovery = require("./discovery");
const pi = require("./pi");
const piServices = require("./pi-services");
const dns = require("./dns");
const tplink = require("./tplink");
const audit = require("./audit");
const credentials = require("./credentials");
const updater = require("./updater");
const browser = require("./browser");

let win = null;
let tray = null;
let scanTimer = null;
let scanning = false;
let activeTermSession = null;

const THEME_BG = { light: "#f3f2f2", dark: "#161514" };

function iconPath() {
  return path.join(__dirname, "..", "..", "build", process.platform === "win32" ? "icon.ico" : "icon.png");
}

function resolvedTheme(theme) {
  const mode = theme === "light" || theme === "dark" ? theme : "system";
  if (mode === "light" || mode === "dark") return mode;
  return nativeTheme.shouldUseDarkColors ? "dark" : "light";
}

function applyNativeTheme(theme) {
  const mode = theme === "light" || theme === "dark" ? theme : "system";
  nativeTheme.themeSource = mode;
  if (win && !win.isDestroyed()) {
    win.setBackgroundColor(THEME_BG[resolvedTheme(mode)]);
  }
  return { ok: true, theme: mode, resolved: resolvedTheme(mode) };
}

function showWindow() {
  if (!win || win.isDestroyed()) createWindow();
  if (win.isMinimized()) win.restore();
  win.show();
  win.focus();
}

// Every call site decides for itself whether the user asked for this class of
// notification (see runScan()'s prefs.notifyNewDevice checks and the watched-
// device loops); this just shows one.
function notify(title, body) {
  if (!Notification.isSupported()) return;
  try {
    new Notification({ title, body, icon: iconPath() }).show();
  } catch (e) { /* ignore */ }
}

function imageFromFile(filePath) {
  try {
    const buf = fs.readFileSync(filePath);
    const image = nativeImage.createFromBuffer(buf);
    return image.isEmpty() ? nativeImage.createEmpty() : image;
  } catch (e) {
    return nativeImage.createEmpty();
  }
}

function loadTrayImage() {
  // These PNGs live under src/ so electron-builder packs them (its `files`
  // list does not include `build/`, which is only installer chrome).
  const variant = nativeTheme.shouldUseDarkColors ? "dark" : "light";
  const dir = path.join(__dirname, "assets", "tray");
  let image = imageFromFile(path.join(dir, "tray-" + variant + ".png"));
  const retina = imageFromFile(path.join(dir, "tray-" + variant + "@2x.png"));
  if (!retina.isEmpty()) {
    if (image.isEmpty()) image = retina;
    else image.addRepresentation({ scaleFactor: 2, width: 32, height: 32, buffer: retina.toPNG() });
  }
  if (image.isEmpty()) image = nativeImage.createFromPath(iconPath());
  // Packaged Windows builds carry the app icon on the exe itself.
  if (image.isEmpty() && process.platform === "win32") {
    image = nativeImage.createFromPath(process.execPath);
  }
  return image;
}

function createTray() {
  if (tray) return;
  let image = loadTrayImage();
  if (image.isEmpty()) image = nativeImage.createEmpty();
  tray = new Tray(image);
  tray.setToolTip("Meshwatch");
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: "Open Meshwatch", click: () => showWindow() },
    // .catch(): same rationale as the interval timer above — a tray click
    // isn't routed through ipcMain.handle, so nothing else observes a
    // rejection if this scan is still in flight when a restore closes db.
    { label: "Scan network now", click: () => runScan("tray").catch(() => {}) },
    { type: "separator" },
    { label: "Quit", click: () => { app.quit(); } }
  ]));
  if (process.platform === "win32") tray.setIgnoreDoubleClickEvents(true);
  tray.on("click", () => showWindow());
  nativeTheme.on("updated", () => {
    if (!tray) return;
    const next = loadTrayImage();
    if (!next.isEmpty()) tray.setImage(next);
  });
}

function createWindow() {
  const hidden = process.argv.indexOf("--hidden") !== -1;
  win = new BrowserWindow({
    width: 1480,
    height: 960,
    minWidth: 1100,
    minHeight: 700,
    show: !hidden,
    backgroundColor: THEME_BG[resolvedTheme("system")],
    title: "Meshwatch",
    icon: iconPath(),
    webPreferences: {
      preload: path.join(__dirname, "..", "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });
  win.removeMenu();
  browser.attach(win);
  win.loadFile(path.join(__dirname, "..", "renderer", "index.html"));
  win.on("close", (e) => {
    if (process.platform === "darwin") return;
    if (!app.isQuitting) {
      e.preventDefault();
      win.hide();
    }
  });
}

function applyLoginItem(prefs) {
  try {
    app.setLoginItemSettings({
      openAtLogin: !!prefs.startWithSystem,
      args: ["--hidden"]
    });
  } catch (e) { /* ignore on unsigned builds */ }
}

function scheduleScans() {
  if (scanTimer) {
    clearInterval(scanTimer);
    scanTimer = null;
  }
  const mins = Number((db.getPrefs() || {}).scanIntervalMin);
  if (!mins || mins < 1) return;
  // .catch() below: this fires on a bare interval, not through
  // ipcMain.handle, so nothing else observes a rejection — without it, a
  // scan that's mid-flight when db:restore's db.close() runs would throw
  // an unhandled rejection in the main process. Degrade to a silently
  // skipped cycle instead.
  scanTimer = setInterval(() => runScan("interval").catch(() => {}), Math.max(1, mins) * 60 * 1000);
}

// Independent of the scan-interval preference above — latency sampling is
// cheap (a couple of pings) so it runs on its own fixed 5-minute cadence
// rather than piggybacking on the (optional, user-configurable) full scan.
setInterval(() => { require("./latency").sampleOnce().catch(() => {}); }, 5 * 60 * 1000);

function send(channel, payload) {
  if (win && !win.isDestroyed()) win.webContents.send(channel, payload);
}

const progress = (stage, detail) => send("scan:progress", { stage, detail });

async function runScan(reason) {
  if (scanning) return { ok: false, reason: "already scanning" };
  scanning = true;
  send("scan:started", { reason });
  try {
    const before = new Set(db.listDevices().map((d) => d.mac));
    const devices = await discovery.run({ onProgress: progress });
    const { newMacs } = db.recordScan(devices);
    const after = db.listDevices();
    const prefs = db.getPrefs();
    // Confirmed-IP devices (config/devices.json's known list) that didn't
    // answer at their confirmed address on this sweep. See discovery.js's
    // detectDrift() for exactly what this does and does not check.
    const driftWarnings = discovery.detectDrift(devices);
    // before.size guards against notifying about every device on the very
    // first-ever scan of an empty db, where "new" just means "not scanned yet".
    const hasNew = prefs.notifyNewDevice && before.size && newMacs.length;
    const hasDrift = prefs.notifyNewDevice && driftWarnings.length;
    if (hasNew || hasDrift) {
      const parts = [];
      if (hasNew) {
        const names = newMacs.map((mac) => {
          const d = devices.find((x) => x.mac === mac);
          return (d && d.name) || mac;
        }).slice(0, 3).join(", ");
        parts.push(
          newMacs.length + " new device" + (newMacs.length > 1 ? "s" : "") +
          " (" + names + (newMacs.length > 3 ? " +" + (newMacs.length - 3) : "") + ")"
        );
      }
      if (hasDrift) {
        const names = driftWarnings.map((w) => w.knownName).slice(0, 3).join(", ");
        parts.push(
          driftWarnings.length + " confirmed device" + (driftWarnings.length > 1 ? "s" : "") +
          " unreachable at known address (" + names + (driftWarnings.length > 3 ? " +" + (driftWarnings.length - 3) : "") + ")"
        );
      }
      const title = hasNew && hasDrift ? "Network scan summary"
        : hasNew ? "New device on the network"
        : "Confirmed device unreachable";
      notify(title, parts.join("; "));
    }
    for (const d of after) {
      if (d.watched && !before.has(d.mac)) notify(d.name + " joined", d.ip || d.mac);
    }
    const seenNow = new Set(devices.map((d) => d.mac));
    for (const d of after) {
      if (d.watched && before.has(d.mac) && !seenNow.has(d.mac)) {
        notify(d.name + " left", "Not seen on this sweep");
      }
    }
    send("scan:finished", { count: after.length, newDevices: newMacs.length });
    return after;
  } finally {
    scanning = false;
  }
}

app.whenReady().then(() => {
  db.init();
  const prefs = db.getPrefs();
  applyNativeTheme(prefs.theme || "system");
  applyLoginItem(prefs);
  createWindow();
  createTray();
  scheduleScans();
  updater.setup();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("before-quit", () => {
  app.isQuitting = true;
  // Close any live shell before the process goes away, so the Pi's sshd
  // isn't left holding a session open until its own timeout expires.
  if (activeTermSession) {
    try { pi.termStop(activeTermSession); } catch (e) { /* ignore */ }
    activeTermSession = null;
  }
});
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    // Stay in the tray.
  }
});

const findDevice = (ip) => db.listDevices().find((d) => d.ip === ip) || null;
const findByMac = (mac) => db.listDevices().find((d) => d.mac === mac) || null;

ipcMain.handle("scan:run", () => runScan("manual"));
ipcMain.handle("devices:list", () => db.listDevices());
ipcMain.handle("device:uptimeHistory", (_e, { mac, days }) => db.deviceUptimeHistory(mac, days));
ipcMain.handle("device:wake", (_e, { mac }) => require("./wol").wake(mac));
ipcMain.handle("devices:topology", () => discovery.topology(db.listDevices()));
ipcMain.handle("devices:drift", () => discovery.detectDrift(db.listDevices()));
ipcMain.handle("devices:note", (_e, { mac, note }) => db.setNote(mac, note));
ipcMain.handle("devices:rename", (_e, { mac, name }) => db.setNameOverride(mac, name));
ipcMain.handle("devices:firmwareManual", (_e, { mac, version }) => db.setFirmwareManual(mac, version));
ipcMain.handle("devices:watch", (_e, { mac, watched }) => {
  db.setWatched(mac, !!watched);
  return { ok: true };
});
ipcMain.handle("device:setTags", (_e, { mac, tags }) => { db.setDeviceTags(mac, tags); return { ok: true }; });
ipcMain.handle("audit:run", async () => audit.run(db.listDevices()));
ipcMain.handle("audit:dismiss", (_e, { key }) => audit.dismiss(key));
ipcMain.handle("audit:restore", (_e, { key }) => audit.restore(key));
ipcMain.handle("audit:history", (_e, { limit } = {}) => db.auditHistory(limit));
ipcMain.handle("latency:history", (_e, { target, limit }) => db.latencyHistory(target, limit));
ipcMain.handle("subnet:get", () => discovery.detectSubnet());
ipcMain.handle("credentials:available", () => credentials.available());
ipcMain.handle("pi:state", () => db.getPiState());
ipcMain.handle("pi:prefs", (_e, prefs) => db.setPiPrefs(prefs || {}));
ipcMain.handle("pi:target", () => pi.resolveTarget());
ipcMain.handle("pi:backend", async () => {
  await dns.detectBackend();
  return dns.getBackendInfo();
});
ipcMain.handle("pi:stats", async () => {
  const s = await dns.stats();
  if (s && s.available && Array.isArray(s.talkers)) db.recordTalkers(s.talkers);
  return s;
});
ipcMain.handle("talker:history", (_e, { clientIp, limit }) => db.talkerHistory(clientIp, limit));
ipcMain.handle("pi:leases", () => dns.leases());
ipcMain.handle("pi:hasPassword", () => dns.hasApiPassword());
ipcMain.handle("pi:setPassword", (_e, { password }) => dns.setApiPassword(password));
ipcMain.handle("pi:pickKey", async () => {
  const r = await dialog.showOpenDialog(win, {
    title: "Pi SSH private key",
    properties: ["openFile"],
    filters: [{ name: "OpenSSH private key", extensions: ["", "pem", "key", "pub"] }]
  });
  if (r.canceled || !r.filePaths[0]) return { ok: false, cancelled: true };
  db.setSetting("pi_ssh_key", r.filePaths[0]);
  return { ok: true, path: r.filePaths[0] };
});
async function confirmedExec(command, onChunk) {
  if (pi.isDisruptive(command)) {
    const { response } = await dialog.showMessageBox(win, {
      type: "warning",
      buttons: ["Cancel", "Run it"],
      defaultId: 0,
      cancelId: 0,
      title: "This may interrupt DNS or restart services on the network",
      message: command,
      detail: pi.disruptionSeconds(command)
        ? "Name resolution will stop for roughly " + pi.disruptionSeconds(command) + " seconds. Every device on the network is affected."
        : "This can restart services on the Pi. If it upgrades the kernel or firmware, a manual reboot may be needed afterward."
    });
    if (response !== 1) return { cancelled: true, output: [] };
  }
  return pi.exec(command, onChunk);
}

ipcMain.handle("pi:exec", async (_e, { command }) => confirmedExec(command));
ipcMain.handle("pi:apt:check", () => pi.aptCheckUpdates());
ipcMain.handle("pi:apt:upgrade", async () =>
  confirmedExec(pi.aptUpgradeCommand(), (chunk) => win.webContents.send("pi:apt:progress", { chunk }))
);
ipcMain.handle("pi:apt:apps", () => pi.installedApps());
ipcMain.handle("pi:rebootRequired", () => pi.rebootRequired());
ipcMain.handle("pi:hostStats", () => pi.hostStats());
ipcMain.handle("pi:services:list", () => piServices.cachedServices());
ipcMain.handle("pi:services:rescan", () => piServices.discoverServices());
ipcMain.handle("pi:block", async (_e, { mac, blocked }) => {
  const d = findByMac(mac);
  if (!d || !d.ip) return { ok: false, reason: "device has no address" };
  const r = await dns.blockClient(d.ip, { blocked: blocked !== false });
  if (r && r.ok) db.setBlocked(mac, blocked !== false);
  return r;
});

ipcMain.handle("tplink:capabilities", (_e, { ip }) => tplink.capabilities(findDevice(ip)));
ipcMain.handle("tplink:action", async (_e, { ip, action, args }) => {
  const device = findDevice(ip);
  if (tplink.isDisruptive(action)) {
    const { response } = await dialog.showMessageBox(win, {
      type: "warning",
      buttons: ["Cancel", "Continue"],
      defaultId: 0,
      cancelId: 0,
      title: "This interrupts connectivity",
      message: action + " on " + ip,
      detail: "Devices connected through this node will drop off the network while it restarts."
    });
    if (response !== 1) return { cancelled: true };
  }
  return tplink.action(device, action, args);
});

ipcMain.handle("credentials:save", (_e, { mac, label, username, password }) => {
  const r = credentials.save(mac, { label, username, password });
  if (r.ok && mac === db.getPiState().mac) {
    piServices.discoverServices().catch(() => {}); // best-effort, don't block the save response
  }
  return r;
});
ipcMain.handle("credentials:list", () => credentials.list());
ipcMain.handle("credentials:has", (_e, { mac }) => credentials.has(mac));
ipcMain.handle("credentials:remove", (_e, { mac }) => credentials.remove(mac));
ipcMain.handle("app:theme", (_e, { theme }) => applyNativeTheme(theme));
ipcMain.handle("prefs:get", () => db.getPrefs());
ipcMain.handle("prefs:set", (_e, patch) => {
  const r = db.setPrefs(patch);
  applyLoginItem(r.prefs);
  scheduleScans();
  return r;
});

ipcMain.handle("browser:open", (_e, { url }) => browser.open(url));
ipcMain.handle("browser:close", () => browser.close());
ipcMain.handle("browser:back", () => browser.back());
ipcMain.handle("browser:forward", () => browser.forward());
ipcMain.handle("browser:reload", () => browser.reload());
ipcMain.handle("browser:bounds", (_e, bounds) => browser.setBounds(bounds));
ipcMain.handle("browser:url", () => browser.getUrl());
ipcMain.handle("shell:open", (_e, { url }) => {
  if (!browser.isLanUrl(url)) return { ok: false, reason: "not a local address" };
  return browser.open(url);
});
ipcMain.on("pi:term:start", (event, { rows, cols }) => {
  if (activeTermSession) pi.termStop(activeTermSession); // one session at a time per Pi
  const sessionId = crypto.randomUUID();
  activeTermSession = sessionId;
  event.reply("pi:term:started", { sessionId });
  pi.termStart(
    sessionId,
    { rows, cols },
    (chunk) => event.sender.send("pi:term:data", { sessionId, chunk }),
    (errorOrNull) => {
      event.sender.send("pi:term:closed", { sessionId, error: errorOrNull });
      if (activeTermSession === sessionId) activeTermSession = null;
    }
  );
});
ipcMain.on("pi:term:input", (_e, { sessionId, data }) => pi.termInput(sessionId, data));
ipcMain.on("pi:term:resize", (_e, { sessionId, rows, cols }) => pi.termResize(sessionId, rows, cols));
ipcMain.on("pi:term:stop", (_e, { sessionId }) => pi.termStop(sessionId));

ipcMain.handle("update:check", () => updater.checkNow());
ipcMain.handle("update:install", () => updater.installNow());
ipcMain.handle("app:version", () => app.getVersion());
ipcMain.handle("app:versions", () => process.versions);

ipcMain.handle("db:backup", async (_e, { includeCredentials } = {}) => {
  const r = await dialog.showSaveDialog(win, {
    title: "Backup Meshwatch data",
    defaultPath: "meshwatch-backup.db",
    filters: [{ name: "SQLite DB", extensions: ["db"] }]
  });
  if (r.canceled || !r.filePath) return { ok: false, cancelled: true };
  db.checkpoint(); // flush WAL into the main db file before copying — see db.js
  await fsPromises.copyFile(db.filePath(), r.filePath);
  if (includeCredentials === false) {
    // Strip credentials from the COPY only — the live db and its saved
    // passwords are never touched by a backup.
    const Database = require("better-sqlite3");
    const copy = new Database(r.filePath);
    try {
      copy.exec("DELETE FROM credentials");
      // App-level secrets don't live in the credentials table — the DNS
      // backend API password is settings' `secret:dns_api` (plus the legacy
      // `secret:pihole_api`). Unchecking "include saved credentials" has to
      // mean no saved password is in the file, so clear every secret:* row.
      copy.prepare("DELETE FROM settings WHERE key LIKE 'secret:%'").run();
      // VACUUM rewrites the file so the deleted ciphertext isn't still
      // sitting recoverable in freelist pages.
      copy.exec("VACUUM");
    } finally {
      copy.close();
    }
  }
  return { ok: true, path: r.filePath };
});

ipcMain.handle("db:restore", async () => {
  const r = await dialog.showOpenDialog(win, {
    title: "Restore Meshwatch data",
    properties: ["openFile"],
    filters: [{ name: "SQLite DB", extensions: ["db"] }]
  });
  if (r.canceled || !r.filePaths[0]) return { ok: false, cancelled: true };
  const { response } = await dialog.showMessageBox(win, {
    type: "warning",
    buttons: ["Cancel", "Restore and restart"],
    defaultId: 0,
    cancelId: 0,
    title: "Replace all current data?",
    detail: "This overwrites every device, finding, and note currently stored. The app will restart. Credentials encrypted on a different Windows account/machine will not decrypt here."
  });
  if (response !== 1) return { ok: false, cancelled: true };
  // A scan in flight is mid-way through db.listDevices()/recordScan()/
  // getPrefs() calls on the module-level db reference (see runScan()). If
  // we close() that reference out from under it, its continuation throws
  // on a null db. Refuse to start the destructive sequence while one is
  // running — this is the common case of the race, closed off up front.
  if (scanning) {
    return { ok: false, reason: "A network scan is currently running — wait for it to finish before restoring." };
  }
  // Flush the LIVE db's WAL before it gets orphaned by the incoming file —
  // without this, the stale meshwatch.db-wal sitting next to the freshly
  // restored main file gets replayed on relaunch, silently reintroducing
  // pre-restore data (or worse, corrupting the restored file).
  db.checkpoint();
  // Close the live connection before renaming over its file. On Windows,
  // better-sqlite3 holds an open file handle for as long as the connection
  // is open, and renaming onto a file with an open handle fails with EPERM
  // — confirmed by testing this exact sequence. Safe to close here: the
  // process exits immediately after, nothing else touches the db.
  db.close();
  // Copy to a temp path first and rename into place only on success, so a
  // failed copy (disk full, AV lock, permission error) never leaves the
  // live db half-written. Rename is atomic on the same filesystem/volume,
  // which the temp path shares by construction — the live db file is never
  // at risk of corruption regardless of where a failure happens below.
  //
  // db.close() has already run, though, so this process can no longer touch
  // the db either way — on failure there is no safe way to keep running
  // with a dead handle (db.init() only ever runs once, at startup), so
  // relaunch unconditionally. A fresh process re-opens whatever is actually
  // on disk, which is correct whether the copy/rename succeeded or not.
  const tempPath = db.filePath() + ".restore-tmp";
  try {
    await fsPromises.copyFile(r.filePaths[0], tempPath);
    await fsPromises.rename(tempPath, db.filePath());
  } catch (e) {
    // Live db untouched (see above) — nothing left to do but relaunch.
  }
  app.relaunch();
  app.exit(0);
});
