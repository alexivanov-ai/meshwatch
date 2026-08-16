// In-place updates via GitHub Releases + electron-updater.
//
// Running a newer NSIS installer with the same appId already replaces the
// install directory without wiping user data. This module makes that happen
// from inside the app: check latest.yml on the GitHub release, download the
// new installer, and apply it on restart. Dev (`npm start`) skips all of this.

const { app, dialog, BrowserWindow } = require("electron");

let checking = false;

function send(channel, payload) {
  for (const win of BrowserWindow.getAllWindows()) {
    if (!win.isDestroyed()) win.webContents.send(channel, payload);
  }
}

function setup() {
  if (!app.isPackaged) return;

  let autoUpdater;
  try {
    ({ autoUpdater } = require("electron-updater"));
  } catch (e) {
    console.warn("electron-updater not available:", e.message);
    return;
  }

  autoUpdater.autoDownload = true;
  autoUpdater.autoInstallOnAppQuit = true;
  // Repo was renamed from home-monitoring → meshwatch; pin the feed so
  // electron-updater does not follow a stale publish.repo baked into older
  // app-update.yml copies during local testing.
  autoUpdater.setFeedURL({
    provider: "github",
    owner: "alexivanov-ai",
    repo: "meshwatch"
  });

  autoUpdater.on("checking-for-update", () => {
    checking = true;
    send("update:status", { state: "checking" });
  });

  autoUpdater.on("update-available", (info) => {
    send("update:status", { state: "available", version: info.version });
  });

  autoUpdater.on("update-not-available", (info) => {
    checking = false;
    send("update:status", { state: "current", version: info.version });
  });

  autoUpdater.on("download-progress", (p) => {
    send("update:status", {
      state: "downloading",
      percent: Math.round(p.percent),
      transferred: p.transferred,
      total: p.total
    });
  });

  autoUpdater.on("update-downloaded", async (info) => {
    checking = false;
    send("update:status", { state: "ready", version: info.version });

    const win = BrowserWindow.getFocusedWindow() || BrowserWindow.getAllWindows()[0];
    const { response } = await dialog.showMessageBox(win || undefined, {
      type: "info",
      buttons: ["Restart now", "Later"],
      defaultId: 0,
      cancelId: 1,
      title: "Update ready",
      message: "Meshwatch " + info.version + " is ready to install",
      detail: "Your settings, scan history and saved device passwords stay on this PC. Restart to finish the update - no uninstall needed."
    });
    if (response === 0) autoUpdater.quitAndInstall(false, true);
  });

  autoUpdater.on("error", (err) => {
    checking = false;
    send("update:status", { state: "error", message: String(err && err.message || err) });
  });

  // Quiet check a few seconds after launch so it doesn't compete with the
  // first window paint or a user-started scan.
  setTimeout(() => {
    autoUpdater.checkForUpdates().catch(() => {});
  }, 5000);

  module.exports._autoUpdater = autoUpdater;
}

function checkNow() {
  if (!app.isPackaged) return Promise.resolve({ state: "dev", message: "Updates only run in the installed app" });
  const autoUpdater = module.exports._autoUpdater;
  if (!autoUpdater) return Promise.resolve({ state: "unavailable" });
  if (checking) return Promise.resolve({ state: "checking" });
  return autoUpdater.checkForUpdates().then(() => ({ state: "started" })).catch((e) => ({
    state: "error",
    message: String(e && e.message || e)
  }));
}

function installNow() {
  const autoUpdater = module.exports._autoUpdater;
  if (!autoUpdater) return { ok: false };
  autoUpdater.quitAndInstall(false, true);
  return { ok: true };
}

module.exports = { setup, checkNow, installNow };
