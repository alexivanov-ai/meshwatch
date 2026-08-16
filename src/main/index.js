const { app, BrowserWindow, ipcMain, dialog, nativeTheme, Tray, Menu, Notification, nativeImage } = require("electron");
const path = require("path");
const db = require("./db");
const discovery = require("./discovery");
const pi = require("./pi");
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

function notify(title, body) {
  const prefs = db.getPrefs();
  if (!prefs.notifyNewDevice && title.indexOf("new") === -1) {
    /* still allow watch alerts */
  }
  if (!Notification.isSupported()) return;
  try {
    new Notification({ title, body, icon: iconPath() }).show();
  } catch (e) { /* ignore */ }
}

function trayIconPath() {
  const variant = nativeTheme.shouldUseDarkColors ? "dark" : "light";
  return path.join(__dirname, "..", "..", "build", "tray", "tray-" + variant + "-2x.png");
}

function createTray() {
  if (tray) return;
  let image = nativeImage.createFromPath(trayIconPath());
  if (image.isEmpty()) image = nativeImage.createFromPath(iconPath());
  if (image.isEmpty()) image = nativeImage.createEmpty();
  tray = new Tray(image.resize({ width: 16, height: 16 }));
  tray.setToolTip("Meshwatch");
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: "Open Meshwatch", click: () => showWindow() },
    { label: "Scan network now", click: () => runScan("tray") },
    { type: "separator" },
    { label: "Quit", click: () => { app.quit(); } }
  ]));
  tray.on("click", () => showWindow());
  nativeTheme.on("updated", () => {
    if (tray) tray.setImage(nativeImage.createFromPath(trayIconPath()).resize({ width: 16, height: 16 }));
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
  scanTimer = setInterval(() => runScan("interval"), Math.max(1, mins) * 60 * 1000);
}

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
    db.recordScan(devices);
    const after = db.listDevices();
    const prefs = db.getPrefs();
    const newcomers = after.filter((d) => !before.has(d.mac));
    if (prefs.notifyNewDevice && before.size && newcomers.length) {
      const names = newcomers.map((d) => d.name || d.ip).slice(0, 3).join(", ");
      notify("New device on the network", names + (newcomers.length > 3 ? " +" + (newcomers.length - 3) : ""));
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
    send("scan:finished", { count: after.length, newDevices: newcomers.length });
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

app.on("before-quit", () => { app.isQuitting = true; });
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    // Stay in the tray.
  }
});

const findDevice = (ip) => db.listDevices().find((d) => d.ip === ip) || null;
const findByMac = (mac) => db.listDevices().find((d) => d.mac === mac) || null;

ipcMain.handle("scan:run", () => runScan("manual"));
ipcMain.handle("devices:list", () => db.listDevices());
ipcMain.handle("devices:topology", () => discovery.topology(db.listDevices()));
ipcMain.handle("devices:drift", () => discovery.detectDrift(db.listDevices()));
ipcMain.handle("devices:note", (_e, { mac, note }) => db.setNote(mac, note));
ipcMain.handle("devices:rename", (_e, { mac, name }) => db.setNameOverride(mac, name));
ipcMain.handle("devices:firmwareManual", (_e, { mac, version }) => db.setFirmwareManual(mac, version));
ipcMain.handle("devices:watch", (_e, { mac, watched }) => {
  db.setWatched(mac, !!watched);
  return { ok: true };
});
ipcMain.handle("audit:run", async () => audit.run(db.listDevices()));
ipcMain.handle("audit:dismiss", (_e, { key }) => audit.dismiss(key));
ipcMain.handle("audit:restore", (_e, { key }) => audit.restore(key));
ipcMain.handle("subnet:get", () => discovery.detectSubnet());
ipcMain.handle("credentials:available", () => credentials.available());
ipcMain.handle("pi:state", () => db.getPiState());
ipcMain.handle("pi:prefs", (_e, prefs) => db.setPiPrefs(prefs || {}));
ipcMain.handle("pi:target", () => pi.resolveTarget());
ipcMain.handle("pi:backend", async () => {
  await dns.detectBackend();
  return dns.getBackendInfo();
});
ipcMain.handle("pi:stats", () => dns.stats());
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
async function confirmedExec(command) {
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
  return pi.exec(command);
}

ipcMain.handle("pi:exec", async (_e, { command }) => confirmedExec(command));
ipcMain.handle("pi:apt:check", () => pi.aptCheckUpdates());
ipcMain.handle("pi:apt:upgrade", async () => confirmedExec(pi.aptUpgradeCommand()));
ipcMain.handle("pi:apt:apps", () => pi.installedApps());
ipcMain.handle("pi:rebootRequired", () => pi.rebootRequired());
ipcMain.handle("pi:hostStats", () => pi.hostStats());
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

ipcMain.handle("credentials:save", (_e, { mac, label, username, password }) => credentials.save(mac, { label, username, password }));
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
ipcMain.handle("update:check", () => updater.checkNow());
ipcMain.handle("update:install", () => updater.installNow());
ipcMain.handle("app:version", () => app.getVersion());
ipcMain.handle("app:versions", () => process.versions);
