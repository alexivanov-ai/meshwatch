// In-app Chromium browser for device admin pages.
//
// Uses Electron's bundled Chromium (WebContentsView) — never the system
// Chrome/Edge. Chromium updates when Electron is bumped in a Meshwatch
// release; end users get that via electron-updater. There is no separate
// Chromium install to maintain.

const { WebContentsView } = require("electron");

const LAN_RE = /^https?:\/\/(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(:\d+)?(\/|$)/i;

let hostWin = null;
let view = null;
let visible = false;

function isLanUrl(url) {
  return typeof url === "string" && LAN_RE.test(url);
}

function send(channel, payload) {
  if (hostWin && !hostWin.isDestroyed()) hostWin.webContents.send(channel, payload);
}

function attach(win) {
  hostWin = win;
  win.on("resize", () => {
    if (visible) send("browser:need-bounds", {});
  });
}

function ensureView() {
  if (view) return view;
  view = new WebContentsView({
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      // Device admin UIs are untrusted local pages — no Node, no preload.
      webSecurity: true
    }
  });

  const wc = view.webContents;
  wc.setWindowOpenHandler(({ url }) => {
    if (isLanUrl(url)) {
      wc.loadURL(url);
      return { action: "deny" };
    }
    return { action: "deny" };
  });

  wc.on("will-navigate", (event, url) => {
    if (!isLanUrl(url)) event.preventDefault();
  });

  // Many router/switch admin UIs (the gateway especially) serve HTTPS with a
  // self-signed cert; Electron rejects that by default and the page silently
  // fails to load (did-fail-load with no obvious cause to a non-developer
  // user). Trust it only for the private-LAN hosts isLanUrl already scopes
  // this whole view to — never for a public address.
  wc.on("certificate-error", (event, url, error, certificate, callback) => {
    if (isLanUrl(url)) {
      event.preventDefault();
      callback(true);
    } else {
      callback(false);
    }
  });

  wc.on("did-navigate", (_e, url) => send("browser:navigated", { url }));
  wc.on("did-navigate-in-page", (_e, url) => send("browser:navigated", { url }));
  wc.on("page-title-updated", (_e, title) => send("browser:title", { title }));
  wc.on("did-start-loading", () => send("browser:loading", { loading: true }));
  wc.on("did-stop-loading", () => send("browser:loading", { loading: false }));
  wc.on("did-fail-load", (_e, code, desc, url) => {
    send("browser:error", { code, desc, url });
  });

  return view;
}

function setBounds(bounds) {
  if (!view || !visible || !hostWin || hostWin.isDestroyed()) return { ok: false };
  const b = bounds || {};
  const x = Math.max(0, Math.round(b.x || 0));
  const y = Math.max(0, Math.round(b.y || 0));
  const width = Math.max(1, Math.round(b.width || 1));
  const height = Math.max(1, Math.round(b.height || 1));
  view.setBounds({ x, y, width, height });
  return { ok: true };
}

function show() {
  if (!hostWin || hostWin.isDestroyed()) return;
  ensureView();
  if (!visible) {
    hostWin.contentView.addChildView(view);
    visible = true;
  }
}

function hide() {
  if (!view || !visible || !hostWin || hostWin.isDestroyed()) {
    visible = false;
    return;
  }
  try {
    hostWin.contentView.removeChildView(view);
  } catch (e) { /* already removed */ }
  visible = false;
}

function open(url) {
  if (!isLanUrl(url)) return { ok: false, reason: "not a local address" };
  if (!hostWin || hostWin.isDestroyed()) return { ok: false, reason: "no window" };

  show();
  ensureView().webContents.loadURL(url);
  send("browser:opened", { url });
  // Renderer lays out chrome then reports bounds.
  setTimeout(() => send("browser:need-bounds", {}), 50);
  return { ok: true, url };
}

function close() {
  hide();
  if (view) {
    try { view.webContents.close(); } catch (e) { /* ignore */ }
    view = null;
  }
  send("browser:closed", {});
  return { ok: true };
}

function back() {
  if (view && view.webContents.canGoBack()) view.webContents.goBack();
  return { ok: true };
}

function forward() {
  if (view && view.webContents.canGoForward()) view.webContents.goForward();
  return { ok: true };
}

function reload() {
  if (view) view.webContents.reload();
  return { ok: true };
}

function getUrl() {
  if (!view) return { url: null };
  return { url: view.webContents.getURL() };
}

module.exports = {
  attach, open, close, back, forward, reload, setBounds, getUrl, isLanUrl
};
