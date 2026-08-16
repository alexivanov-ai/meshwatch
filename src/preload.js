// The ONLY bridge between the privileged main process and the renderer.
// Keep this surface narrow. Never expose ipcRenderer itself.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("meshwatch", {
  scan: () => ipcRenderer.invoke("scan:run"),
  getDevices: () => ipcRenderer.invoke("devices:list"),
  getTopology: () => ipcRenderer.invoke("devices:topology"),
  getDrift: () => ipcRenderer.invoke("devices:drift"),
  getAudit: () => ipcRenderer.invoke("audit:run"),
  setNote: (mac, note) => ipcRenderer.invoke("devices:note", { mac, note }),

  pihole: {
    stats: () => ipcRenderer.invoke("pihole:stats"),
    leases: () => ipcRenderer.invoke("pihole:leases"),
    exec: (command) => ipcRenderer.invoke("pihole:exec", { command })
  },

  tplink: {
    capabilities: (ip) => ipcRenderer.invoke("tplink:capabilities", { ip }),
    action: (ip, action, args) => ipcRenderer.invoke("tplink:action", { ip, action, args })
  },

  // Passwords never cross this bridge - save() sends one down to be
  // encrypted and stored, list() only ever returns label/username metadata.
  credentials: {
    save: (mac, label, username, password) => ipcRenderer.invoke("credentials:save", { mac, label, username, password }),
    list: () => ipcRenderer.invoke("credentials:list"),
    has: (mac) => ipcRenderer.invoke("credentials:has", { mac }),
    remove: (mac) => ipcRenderer.invoke("credentials:remove", { mac })
  },

  openExternal: (url) => ipcRenderer.invoke("shell:open", { url }),

  // Progress events during a scan
  onScanProgress: (cb) => {
    const handler = (_e, payload) => cb(payload);
    ipcRenderer.on("scan:progress", handler);
    return () => ipcRenderer.removeListener("scan:progress", handler);
  }
});
