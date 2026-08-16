const { app, BrowserWindow, ipcMain, shell, dialog } = require("electron");
const path = require("path");
const db = require("./db");
const discovery = require("./discovery");
const pihole = require("./pihole");
const tplink = require("./tplink");
const audit = require("./audit");
const credentials = require("./credentials");
const updater = require("./updater");

let win = null;

function createWindow() {
  win = new BrowserWindow({
    width: 1480,
    height: 960,
    minWidth: 1100,
    minHeight: 700,
    backgroundColor: "#f3f2f2",
    title: "Meshwatch",
    webPreferences: {
      preload: path.join(__dirname, "..", "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });
  win.removeMenu();
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
  return devices;
});

ipcMain.handle("devices:list", () => db.listDevices());
ipcMain.handle("devices:topology", () => discovery.topology(db.listDevices()));
ipcMain.handle("devices:drift", () => discovery.detectDrift(db.listDevices()));
ipcMain.handle("devices:note", (_e, { mac, note }) => db.setNote(mac, note));
ipcMain.handle("audit:run", async () => audit.run(db.listDevices()));
ipcMain.handle("subnet:get", () => discovery.detectSubnet());

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
// a webview fill action - see credentials.js. That fill wiring lands with
// phase 5's real interface, once there's an embedded page for it to fill.
ipcMain.handle("credentials:save", (_e, { mac, label, username, password }) => credentials.save(mac, { label, username, password }));
ipcMain.handle("credentials:list", () => credentials.list());
ipcMain.handle("credentials:has", (_e, { mac }) => credentials.has(mac));
ipcMain.handle("credentials:remove", (_e, { mac }) => credentials.remove(mac));

ipcMain.handle("shell:open", (_e, { url }) => {
  // Only private LAN addresses — never open an arbitrary external URL.
  if (!/^https?:\/\/(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(:\d+)?(\/|$)/.test(url)) {
    return { ok: false, reason: "not a local address" };
  }
  shell.openExternal(url);
  return { ok: true };
});

ipcMain.handle("update:check", () => updater.checkNow());
ipcMain.handle("update:install", () => updater.installNow());
ipcMain.handle("app:version", () => app.getVersion());
