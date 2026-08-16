// The ONLY bridge between the privileged main process and the renderer.
// Keep this surface narrow. Never expose ipcRenderer itself.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("meshwatch", {
  scan: () => ipcRenderer.invoke("scan:run"),
  getDevices: () => ipcRenderer.invoke("devices:list"),
  getTopology: () => ipcRenderer.invoke("devices:topology"),
  getDrift: () => ipcRenderer.invoke("devices:drift"),
  getAudit: () => ipcRenderer.invoke("audit:run"),
  dismissFinding: (key) => ipcRenderer.invoke("audit:dismiss", { key }),
  restoreFinding: (key) => ipcRenderer.invoke("audit:restore", { key }),
  auditHistory: (limit) => ipcRenderer.invoke("audit:history", { limit }),
  getSubnet: () => ipcRenderer.invoke("subnet:get"),
  setNote: (mac, note) => ipcRenderer.invoke("devices:note", { mac, note }),
  renameDevice: (mac, name) => ipcRenderer.invoke("devices:rename", { mac, name }),
  setFirmwareManual: (mac, version) => ipcRenderer.invoke("devices:firmwareManual", { mac, version }),
  watchDevice: (mac, watched) => ipcRenderer.invoke("devices:watch", { mac, watched }),
  uptimeHistory: (mac, days) => ipcRenderer.invoke("device:uptimeHistory", { mac, days }),

  prefs: {
    get: () => ipcRenderer.invoke("prefs:get"),
    set: (patch) => ipcRenderer.invoke("prefs:set", patch)
  },

  pi: {
    stats: () => ipcRenderer.invoke("pi:stats"),
    leases: () => ipcRenderer.invoke("pi:leases"),
    exec: (command) => ipcRenderer.invoke("pi:exec", { command }),
    state: () => ipcRenderer.invoke("pi:state"),
    setPrefs: (prefs) => ipcRenderer.invoke("pi:prefs", prefs),
    target: () => ipcRenderer.invoke("pi:target"),
    backend: () => ipcRenderer.invoke("pi:backend"),
    hasPassword: () => ipcRenderer.invoke("pi:hasPassword"),
    setPassword: (password) => ipcRenderer.invoke("pi:setPassword", { password }),
    pickKey: () => ipcRenderer.invoke("pi:pickKey"),
    block: (mac, blocked) => ipcRenderer.invoke("pi:block", { mac, blocked }),
    aptCheck: () => ipcRenderer.invoke("pi:apt:check"),
    aptUpgrade: () => ipcRenderer.invoke("pi:apt:upgrade"),
    installedApps: () => ipcRenderer.invoke("pi:apt:apps"),
    rebootRequired: () => ipcRenderer.invoke("pi:rebootRequired"),
    hostStats: () => ipcRenderer.invoke("pi:hostStats"),
    servicesList: () => ipcRenderer.invoke("pi:services:list"),
    servicesRescan: () => ipcRenderer.invoke("pi:services:rescan")
  },

  terminal: {
    start: (rows, cols) => ipcRenderer.send("pi:term:start", { rows, cols }),
    input: (sessionId, data) => ipcRenderer.send("pi:term:input", { sessionId, data }),
    resize: (sessionId, rows, cols) => ipcRenderer.send("pi:term:resize", { sessionId, rows, cols }),
    stop: (sessionId) => ipcRenderer.send("pi:term:stop", { sessionId }),
    onStarted: (cb) => ipcRenderer.on("pi:term:started", (_e, payload) => cb(payload)),
    onData: (cb) => ipcRenderer.on("pi:term:data", (_e, payload) => cb(payload)),
    onClosed: (cb) => ipcRenderer.on("pi:term:closed", (_e, payload) => cb(payload))
  },

  tplink: {
    capabilities: (ip) => ipcRenderer.invoke("tplink:capabilities", { ip }),
    action: (ip, action, args) => ipcRenderer.invoke("tplink:action", { ip, action, args })
  },

  // Passwords never cross this bridge - save() sends one down to be
  // encrypted and stored, list() only ever returns label/username metadata.
  credentials: {
    available: () => ipcRenderer.invoke("credentials:available"),
    save: (mac, label, username, password) => ipcRenderer.invoke("credentials:save", { mac, label, username, password }),
    list: () => ipcRenderer.invoke("credentials:list"),
    has: (mac) => ipcRenderer.invoke("credentials:has", { mac }),
    remove: (mac) => ipcRenderer.invoke("credentials:remove", { mac })
  },

  openExternal: (url) => ipcRenderer.invoke("browser:open", { url }),
  browser: {
    open: (url) => ipcRenderer.invoke("browser:open", { url }),
    close: () => ipcRenderer.invoke("browser:close"),
    back: () => ipcRenderer.invoke("browser:back"),
    forward: () => ipcRenderer.invoke("browser:forward"),
    reload: () => ipcRenderer.invoke("browser:reload"),
    setBounds: (bounds) => ipcRenderer.invoke("browser:bounds", bounds),
    getUrl: () => ipcRenderer.invoke("browser:url"),
    on: (channel, cb) => {
      const map = {
        opened: "browser:opened",
        closed: "browser:closed",
        navigated: "browser:navigated",
        title: "browser:title",
        loading: "browser:loading",
        error: "browser:error",
        needBounds: "browser:need-bounds"
      };
      const ch = map[channel];
      if (!ch) return () => {};
      const handler = (_e, payload) => cb(payload);
      ipcRenderer.on(ch, handler);
      return () => ipcRenderer.removeListener(ch, handler);
    }
  },

  version: () => ipcRenderer.invoke("app:version"),
  versions: () => ipcRenderer.invoke("app:versions"),
  setTheme: (theme) => ipcRenderer.invoke("app:theme", { theme }),
  checkForUpdate: () => ipcRenderer.invoke("update:check"),
  installUpdate: () => ipcRenderer.invoke("update:install"),
  onUpdateStatus: (cb) => {
    const handler = (_e, payload) => cb(payload);
    ipcRenderer.on("update:status", handler);
    return () => ipcRenderer.removeListener("update:status", handler);
  },

  onScanProgress: (cb) => {
    const handler = (_e, payload) => cb(payload);
    ipcRenderer.on("scan:progress", handler);
    return () => ipcRenderer.removeListener("scan:progress", handler);
  },
  onScanFinished: (cb) => {
    const handler = (_e, payload) => cb(payload);
    ipcRenderer.on("scan:finished", handler);
    return () => ipcRenderer.removeListener("scan:finished", handler);
  }
});
