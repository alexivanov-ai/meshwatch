const { app, BrowserWindow, ipcMain, dialog, nativeTheme } = require("electron");
const path = require("path");
const db = require("./db");
const discovery = require("./discovery");
const pihole = require("./pihole");
const tplink = require("./tplink");
const audit = require("./audit");
const credentials = require("./credentials");
const updater = require("./updater");
const browser = require("./browser");

let win = null;

const THEME_BG = { light: "#f3f2f2", dark: "#161514" };

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

function createWindow() {
  win = new BrowserWindow({
    width: 1480,
    height: 960,
    minWidth: 1100,
    minHeight: 700,
    backgroundColor: THEME_BG[resolvedTheme("system")],
    title: "Meshwatch",
    icon: path.join(__dirname, "..", "..", "build", process.platform === "win32" ? "icon.ico" : "icon.png"),
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
}

app.whenReady().then(() => {
  db.init();
  createWindow();
  updater.setup();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

// --- IPC -------------------------------------------------------------------

const progress = (stage, detail) => {
  if (win && !win.isDestroyed()) win.webContents.send("scan:progress", { stage, detail });
};

ipcMain.handle("scan:run", async () => {
  const devices = await discovery.run({ onProgress: progress });
  db.recordScan(devices);
  // Return DB rows so user renames (name_override) are applied.
  return db.listDevices();
});

ipcMain.handle("devices:list", () => db.listDevices());
ipcMain.handle("devices:topology", () => discovery.topology(db.listDevices()));
ipcMain.handle("devices:drift", () => discovery.detectDrift(db.listDevices()));
ipcMain.handle("devices:note", (_e, { mac, note }) => db.setNote(mac, note));
ipcMain.handle("devices:rename", (_e, { mac, name }) => db.setNameOverride(mac, name));
ipcMain.handle("devices:firmwareManual", (_e, { mac, version }) => db.setFirmwareManual(mac, version));
ipcMain.handle("audit:run", async () => audit.run(db.listDevices()));
ipcMain.handle("audit:dismiss", (_e, { key }) => audit.dismiss(key));
ipcMain.handle("audit:restore", (_e, { key }) => audit.restore(key));
ipcMain.handle("subnet:get", () => discovery.detectSubnet());
ipcMain.handle("credentials:available", () => credentials.available());
ipcMain.handle("pihole:state", () => db.getPiHoleState());
ipcMain.handle("pihole:prefs", (_e, prefs) => db.setPiHolePrefs(prefs || {}));
ipcMain.handle("pihole:target", () => pihole.resolveTarget());

ipcMain.handle("pihole:stats", () => pihole.stats());
ipcMain.handle("pihole:leases", () => pihole.leases());
ipcMain.handle("pihole:exec", async (_e, { command }) => {
  if (pihole.isDisruptive(command)) {
    const { response } = await dialog.showMessageBox(win, {
      type: "warning",
      buttons: ["Cancel", "Run it"],
      defaultId: 0,
      cancelId: 0,
      title: "This interrupts DNS for the whole network",
      message: command,
      detail: "Name resolution will stop for roughly " + pihole.disruptionSeconds(command) + " seconds. Every device on the network is affected."
    });
    if (response !== 1) return { cancelled: true, output: [] };
  }
  return pihole.exec(command);
});

// tplink.js has no static config to look devices up by IP against anymore
// (config/devices.json carries no per-device IP) - resolve against the last
// scan's results here instead.
const findDevice = (ip) => db.listDevices().find(d => d.ip === ip) || null;

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

// Metadata only (label/username/when-saved) - never the password. The
// plaintext only ever gets decrypted inside the main process, for scripting
// a form-fill into the in-app browser (see credentials.js / browser.js).
ipcMain.handle("credentials:save", (_e, { mac, label, username, password }) => credentials.save(mac, { label, username, password }));
ipcMain.handle("credentials:list", () => credentials.list());
ipcMain.handle("credentials:has", (_e, { mac }) => credentials.has(mac));
ipcMain.handle("credentials:remove", (_e, { mac }) => credentials.remove(mac));
ipcMain.handle("app:theme", (_e, { theme }) => applyNativeTheme(theme));

// In-app Chromium (Electron) — device admin pages stay inside Meshwatch.
ipcMain.handle("browser:open", (_e, { url }) => browser.open(url));
ipcMain.handle("browser:close", () => browser.close());
ipcMain.handle("browser:back", () => browser.back());
ipcMain.handle("browser:forward", () => browser.forward());
ipcMain.handle("browser:reload", () => browser.reload());
ipcMain.handle("browser:bounds", (_e, bounds) => browser.setBounds(bounds));
ipcMain.handle("browser:url", () => browser.getUrl());

// Kept for rare cases that truly need the OS browser — still LAN-only.
ipcMain.handle("shell:open", (_e, { url }) => {
  if (!browser.isLanUrl(url)) return { ok: false, reason: "not a local address" };
  return browser.open(url);
});

ipcMain.handle("update:check", () => updater.checkNow());
ipcMain.handle("update:install", () => updater.installNow());
ipcMain.handle("app:version", () => app.getVersion());
ipcMain.handle("app:versions", () => process.versions);