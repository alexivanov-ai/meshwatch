// TP-Link local control. No official API — this talks to the same encrypted
// HTTP endpoint the device web UI uses (Archer AES+RSA, Easy Smart CGI).
// Passwords come from the credential vault. The TL-WDR4300 stays read-only.
const crypto = require("crypto");
const { URLSearchParams } = require("url");
const lan = require("./lanhttp");
const credentials = require("./credentials");
const db = require("./db");

const ACTIONS = [
  "reboot", "firmwareCheck", "firmwareUpdate", "ssid", "bandSteering",
  "channel", "clientList", "portForwarding", "speedTest", "led", "backhaul"
];

const DISRUPTIVE = ["reboot", "firmwareUpdate", "ssid", "channel", "bandSteering"];

function isDisruptive(action) {
  return DISRUPTIVE.indexOf(action) !== -1;
}

function credsFor(device) {
  if (!device || !device.mac) return null;
  return credentials.reveal(device.mac);
}

function rsaKey(nHex, eHex) {
  const n = Buffer.from(nHex.length % 2 ? "0" + nHex : nHex, "hex");
  const e = Buffer.from(eHex.length % 2 ? "0" + eHex : eHex, "hex");
  return crypto.createPublicKey({
    key: {
      kty: "RSA",
      n: n.toString("base64url"),
      e: e.toString("base64url")
    },
    format: "jwk"
  });
}

function rsaEncryptHex(data, nHex, eHex, padding, oaepHash) {
  const key = rsaKey(nHex, eHex);
  const opts = { key, padding };
  if (oaepHash) opts.oaepHash = oaepHash;
  return crypto.publicEncrypt(opts, Buffer.from(data)).toString("hex");
}

function pkcs7Pad(buf) {
  const n = 16 - (buf.length % 16);
  return Buffer.concat([buf, Buffer.alloc(n, n)]);
}

function pkcs7Unpad(buf) {
  if (!buf.length) return buf;
  const n = buf[buf.length - 1];
  if (n < 1 || n > 16) return buf;
  return buf.slice(0, buf.length - n);
}

function aesCbcEncryptB64(plain, keyStr, ivStr) {
  const cipher = crypto.createCipheriv("aes-128-cbc", Buffer.from(keyStr, "utf8"), Buffer.from(ivStr, "utf8"));
  cipher.setAutoPadding(true);
  return Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]).toString("base64");
}

function aesCbcDecryptB64(b64, keyStr, ivStr) {
  const decipher = crypto.createDecipheriv("aes-128-cbc", Buffer.from(keyStr, "utf8"), Buffer.from(ivStr, "utf8"));
  decipher.setAutoPadding(true);
  return Buffer.concat([decipher.update(Buffer.from(b64, "base64")), decipher.final()]).toString("utf8");
}

function md5hex(s) {
  return crypto.createHash("md5").update(s).digest("hex");
}

function sha256hex(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}

function randomHex16() {
  return crypto.randomBytes(8).toString("hex");
}

function randomDigits16() {
  let s = "";
  for (let i = 0; i < 16; i++) s += String(Math.floor(Math.random() * 10));
  return s;
}

function origin(ip) {
  return "http://" + ip;
}

// --- Classic Archer (AX20, many extenders) --------------------------------

class ClassicSession {
  constructor(ip, username, password) {
    this.ip = ip;
    this.username = username || "admin";
    this.password = password;
    this.host = origin(ip);
    this.key = randomHex16();
    this.iv = randomHex16();
    this.stok = "";
    this.sysauth = "";
    this.nn = "";
    this.ee = "";
    this.seq = 0;
    this.pwdNN = "";
    this.pwdEE = "";
    this.logged = false;
  }

  async readJson(path, params) {
    const q = params ? "?" + new URLSearchParams(params).toString() : "";
    return lan.request({ url: this.host + path + q, method: "POST", body: "", timeoutMs: 8000 });
  }

  async fetchKeys() {
    const keys = await this.readJson("/cgi-bin/luci/;stok=/login?form=keys", { operation: "read" });
    const pwd = keys && keys.json && keys.json.data && keys.json.data.password;
    if (!pwd) throw new Error("no password RSA key (this firmware may need a different login)");
    this.pwdNN = pwd[0];
    this.pwdEE = pwd[1];
    const auth = await this.readJson("/cgi-bin/luci/;stok=/login?form=auth", { operation: "read" });
    const data = auth && auth.json && auth.json.data;
    if (!data || data.seq == null || !data.key) throw new Error("no auth sequence");
    this.seq = Number(data.seq);
    this.nn = data.key[0];
    this.ee = data.key[1];
  }

  signature(seq, isLogin, hash) {
    const s = isLogin
      ? "k=" + this.key + "&i=" + this.iv + "&h=" + hash + "&s=" + seq
      : "h=" + hash + "&s=" + seq;
    let sign = "";
    for (let i = 0; i < s.length; i += 53) {
      sign += rsaEncryptHex(s.slice(i, i + 53), this.nn, this.ee, crypto.constants.RSA_PKCS1_PADDING);
    }
    return sign;
  }

  prepare(plain, isLogin) {
    const encrypted = aesCbcEncryptB64(plain, this.key, this.iv);
    const hash = md5hex(this.username + this.password);
    const sign = this.signature(this.seq + encrypted.length, isLogin, hash);
    return "sign=" + sign + "&data=" + encodeURIComponent(encrypted);
  }

  decrypt(json) {
    if (!json || !json.data) return {};
    return JSON.parse(aesCbcDecryptB64(json.data, this.key, this.iv));
  }

  async login() {
    await this.fetchKeys();
    const crypted = rsaEncryptHex(this.password, this.pwdNN, this.pwdEE, crypto.constants.RSA_PKCS1_PADDING);
    const body = this.prepare("operation=login&password=" + crypted + "&confirm=true", true);
    const r = await lan.request({
      url: this.host + "/cgi-bin/luci/;stok=/login?form=login",
      method: "POST",
      body,
      headers: {
        Referer: this.host + "/webpages/index.html",
        Origin: this.host,
        "Content-Type": "application/x-www-form-urlencoded"
      }
    });
    const dec = this.decrypt(r.json);
    const stok = dec && dec.data && dec.data.stok;
    if (!stok) throw new Error((dec && dec.data && dec.data.errorcode) || "login failed");
    this.stok = stok;
    this.sysauth = lan.cookieValue(r.cookies, "sysauth") || "";
    this.logged = true;
    return this;
  }

  async request(path, data, ignore) {
    if (!this.logged) throw new Error("not authorised");
    const body = this.prepare(data, false);
    const r = await lan.request({
      url: this.host + "/cgi-bin/luci/;stok=" + this.stok + "/" + path,
      method: "POST",
      body,
      headers: {
        Referer: this.host + "/webpages/index.html",
        Origin: this.host,
        "Content-Type": "application/x-www-form-urlencoded",
        Cookie: this.sysauth ? "sysauth=" + this.sysauth : ""
      }
    });
    if (ignore) return {};
    const dec = this.decrypt(r.json);
    if (!dec || dec.success === false) throw new Error("router rejected " + path);
    return dec.data || dec;
  }
}

// --- SG / CE-RED (Archer BE220 and other Wi-Fi 7) -------------------------

class SgSession {
  constructor(ip, username, password) {
    this.ip = ip;
    this.username = username || "admin";
    this.password = password;
    this.host = origin(ip);
    this.key = randomDigits16();
    this.iv = randomDigits16();
    this.hash = "";
    this.stok = "";
    this.sysauth = "";
    this.nn = "";
    this.ee = "";
    this.seq = 0;
    this.pwdNN = "";
    this.pwdEE = "";
    this.logged = false;
  }

  async fetchKeys() {
    const keys = await lan.request({
      url: this.host + "/cgi-bin/luci/;stok=/login?form=keys?operation=read",
      method: "POST",
      timeoutMs: 8000
    });
    // Some firmwares want params in the query, some in the body.
    let data = keys && keys.json && keys.json.data;
    if (!data || !data.password) {
      const keys2 = await lan.request({
        url: this.host + "/cgi-bin/luci/;stok=/login?form=keys",
        method: "POST",
        body: "operation=read",
        timeoutMs: 8000
      });
      data = keys2 && keys2.json && keys2.json.data;
    }
    if (!data || !data.password) throw new Error("no SG password key");
    this.pwdNN = data.password[0];
    this.pwdEE = data.password[1];

    const auth = await lan.request({
      url: this.host + "/cgi-bin/luci/;stok=/login?form=auth",
      method: "POST",
      body: "operation=read",
      timeoutMs: 8000
    });
    const ad = auth && auth.json && auth.json.data;
    if (!ad || ad.seq == null || !ad.key) throw new Error("no SG auth key");
    this.seq = Number(ad.seq);
    this.nn = ad.key[0];
    this.ee = ad.key[1];
  }

  aesFmt() { return "k=" + this.key + "&i=" + this.iv; }

  loginSignature(dataLen) {
    const signStr = this.aesFmt() + "&h=" + this.hash + "&s=" + (this.seq + dataLen);
    const rsaByteLen = this.nn.length / 2;
    const step = Math.min(53, rsaByteLen - 2 * 20 - 2);
    let sign = "";
    for (let i = 0; i < signStr.length; i += step) {
      sign += rsaEncryptHex(
        signStr.slice(i, i + step),
        this.nn, this.ee,
        crypto.constants.RSA_PKCS1_OAEP_PADDING,
        "sha1"
      );
    }
    return sign;
  }

  requestSignature(dataLen) {
    const signStr = "h=" + this.hash + "&s=" + (this.seq + dataLen);
    const aesKey = this.aesFmt();
    let sign = "";
    for (let i = 0; i < signStr.length; i += 53) {
      sign += crypto.createHmac("sha256", aesKey).update(signStr.slice(i, i + 53)).digest("hex");
    }
    return sign;
  }

  async login() {
    await this.fetchKeys();
    this.hash = sha256hex(this.username + this.password);
    const encryptedPwd = rsaEncryptHex(this.password, this.pwdNN, this.pwdEE, crypto.constants.RSA_PKCS1_PADDING);
    const loginData = "operation=login&password=" + encryptedPwd + "&confirm=true";
    const encryptedData = aesCbcEncryptB64(loginData, this.key, this.iv);
    const sign = this.loginSignature(encryptedData.length);
    const r = await lan.request({
      url: this.host + "/cgi-bin/luci/;stok=/login?form=login",
      method: "POST",
      body: "sign=" + sign + "&data=" + encodeURIComponent(encryptedData),
      headers: {
        Referer: this.host + "/webpages/index.html",
        "Content-Type": "application/x-www-form-urlencoded"
      }
    });
    const dec = JSON.parse(aesCbcDecryptB64(r.json.data, this.key, this.iv));
    if (!dec.success) throw new Error((dec.data && dec.data.errorcode) || "SG login failed");
    this.stok = dec.data.stok;
    this.sysauth = lan.cookieValue(r.cookies, "sysauth") || "";
    this.logged = true;
    return this;
  }

  async request(path, data, ignore) {
    if (!this.logged) throw new Error("not authorised");
    const encryptedData = aesCbcEncryptB64(data, this.key, this.iv);
    this.hash = sha256hex(encryptedData);
    const sign = this.requestSignature(encryptedData.length);
    const r = await lan.request({
      url: this.host + "/cgi-bin/luci/;stok=" + this.stok + "/" + path,
      method: "POST",
      body: "sign=" + sign + "&data=" + encodeURIComponent(encryptedData),
      headers: {
        Referer: this.host + "/webpages/index.html",
        "Content-Type": "application/x-www-form-urlencoded",
        Cookie: this.sysauth ? "sysauth=" + this.sysauth : ""
      }
    });
    if (ignore) return {};
    const dec = JSON.parse(aesCbcDecryptB64(r.json.data, this.key, this.iv));
    if (!dec.success) throw new Error("router rejected " + path);
    return dec.data || dec;
  }
}

// --- TL-SG108E Easy Smart CGI ---------------------------------------------

class SwitchSession {
  constructor(ip, username, password) {
    this.ip = ip;
    this.username = username || "admin";
    this.password = password;
    this.host = origin(ip);
    this.cookie = "";
  }

  async login() {
    const home = await lan.request({ url: this.host + "/", timeoutMs: 5000 });
    this.cookie = (home.cookies || []).map((c) => String(c).split(";")[0]).join("; ");
    const r = await lan.request({
      url: this.host + "/logon.cgi",
      method: "POST",
      body: new URLSearchParams({
        username: this.username,
        password: this.password,
        cpassword: "",
        logon: "Login"
      }).toString(),
      headers: {
        Referer: this.host + "/",
        Cookie: this.cookie
      }
    });
    if (r.status !== 200) throw new Error("switch login failed");
    this.cookie = (r.cookies || []).map((c) => String(c).split(";")[0]).join("; ") || this.cookie;
    return this;
  }

  async get(path) {
    return lan.request({
      url: this.host + path,
      headers: { Referer: this.host + "/", Cookie: this.cookie },
      timeoutMs: 6000
    });
  }

  async reboot() {
    await lan.request({
      url: this.host + "/reboot.cgi",
      method: "POST",
      body: "reboot_op=reboot&save_op=1&apply=Reboot",
      headers: { Referer: this.host + "/", Cookie: this.cookie }
    });
  }

  async setLed(on) {
    await this.get("/led_on_set.cgi?rd_led=" + (on ? 1 : 0) + "&led_cfg=Apply");
  }

  parseFirmware(html) {
    const fw = html.match(/firmwareStr["'\s:=]+["']?([^"';]+)/i);
    const hw = html.match(/hardwareStr["'\s:=]+["']?([^"';]+)/i);
    const model = html.match(/descriStr["'\s:=]+["']?([^"';]+)/i);
    return {
      firmware: fw ? fw[1].trim() : null,
      hardware: hw ? hw[1].trim() : null,
      model: model ? model[1].trim() : null
    };
  }
}

async function openSession(device) {
  const c = credsFor(device);
  if (!c || !c.password) {
    return { ok: false, reason: "Save this device's admin password in the credential vault first", needsCreds: true };
  }
  const user = c.username || "admin";
  const model = String(device.model || device.name || "");
  const tries = [];
  if (/SG108|SG1\d+E/i.test(model) || device.type === "switch") tries.push("switch");
  if (/BE\d|Wi-?Fi 7/i.test(model) || device.type === "gateway") tries.push("sg", "classic");
  else tries.push("classic", "sg");
  if (tries.indexOf("switch") === -1 && device.web_title && /Easy Smart/i.test(device.web_title)) tries.unshift("switch");

  let last = "login failed";
  for (const kind of tries) {
    try {
      if (kind === "switch") {
        const s = new SwitchSession(device.ip, user, c.password);
        await s.login();
        return { ok: true, kind: "switch", session: s };
      }
      if (kind === "sg") {
        const s = new SgSession(device.ip, user, c.password);
        await s.login();
        return { ok: true, kind: "sg", session: s };
      }
      const s = new ClassicSession(device.ip, user, c.password);
      await s.login();
      return { ok: true, kind: "classic", session: s };
    } catch (e) {
      last = e.message || String(e);
    }
  }
  return { ok: false, reason: last };
}

function mapClients(data) {
  const out = [];
  const take = (list, link) => {
    for (const item of list || []) {
      const mac = String(item.macaddr || item.mac || "").replace(/-/g, ":").toUpperCase();
      const ip = item.ipaddr || item.ip;
      if (!mac && !ip) continue;
      out.push({
        mac,
        ip,
        hostname: item.hostname || item.name || null,
        link: item.wire_type || link || null,
        signal: item.rssi || item.signal || null
      });
    }
  };
  take(data.access_devices_wired, "Ethernet");
  take(data.access_devices_wireless_host, "Wi-Fi");
  take(data.access_devices_wireless_guest, "Wi-Fi guest");
  return out;
}

async function routerStatus(session) {
  return session.request("admin/status?form=all&operation=read", "operation=read");
}

async function routerFirmware(session) {
  try {
    return await session.request("admin/firmware?form=upgrade&operation=read", "operation=read");
  } catch (e) {
    return session.request("admin/firmware?form=upgrade", "operation=read");
  }
}

function capabilities(d) {
  if (!d) return { controllable: false, reason: "device not found in the last scan" };
  const ip = d.ip;
  if (d.control === "readonly") {
    return { ip, controllable: false, reason: "end of support — read only", adminPage: "http://" + ip, actions: [] };
  }
  if (d.control !== "tplink" && d.type !== "switch") {
    return { ip, controllable: false, reason: "no management API", adminPage: ip ? "http://" + ip : null };
  }
  const hasCreds = !!(d.mac && credentials.has(d.mac));
  return {
    ip,
    model: d.model,
    controllable: true,
    adminPage: "http://" + ip,
    needsCreds: !hasCreds,
    actions: ACTIONS.map((a) => ({
      action: a,
      status: hasCreds ? "available" : "needs-password"
    }))
  };
}

async function action(d, name, args) {
  if (!d) return { ok: false, reason: "device not found in the last scan" };
  if (d.control === "readonly") return { ok: false, reason: "this device is read-only", adminPage: "http://" + d.ip };
  if (!d.ip) return { ok: false, reason: "no address" };

  const opened = await openSession(d);
  if (!opened.ok) {
    return {
      ok: false,
      reason: opened.reason,
      adminPage: "http://" + d.ip,
      action: name,
      needsCreds: opened.needsCreds
    };
  }

  const session = opened.session;
  try {
    if (opened.kind === "switch") {
      if (name === "reboot") {
        await session.reboot();
        return { ok: true, action: name, note: "Switch is rebooting — a few seconds of wired drop." };
      }
      if (name === "firmwareCheck" || name === "firmwareUpdate") {
        const page = await session.get("/SystemInfoRpm.htm");
        const info = session.parseFirmware(page.text || "");
        if (name === "firmwareUpdate") {
          return { ok: false, reason: "Firmware files have to be uploaded in the switch web UI", adminPage: "http://" + d.ip, firmware: info.firmware };
        }
        if (info.firmware) db.updateDeviceFields(d.mac, { firmware: info.firmware, firmware_source: "switch web UI" });
        return { ok: true, action: name, firmware: info.firmware, hardware: info.hardware, model: info.model };
      }
      if (name === "led") {
        await session.setLed(!(args && args.off));
        return { ok: true, action: name };
      }
      if (name === "clientList") {
        return { ok: true, action: name, clients: [], note: "The unmanaged-style switch has no client table. Port stats are on its admin page.", adminPage: "http://" + d.ip };
      }
      return { ok: false, reason: name + " is not available on the TL-SG108E", adminPage: "http://" + d.ip };
    }

    if (name === "reboot") {
      await session.request("admin/system?form=reboot", "operation=write", true);
      return { ok: true, action: name, note: "Reboot sent. Wi-Fi and routing will drop for about a minute." };
    }
    if (name === "firmwareCheck" || name === "firmwareUpdate") {
      const fw = await routerFirmware(session);
      const current = fw.firmware_version || fw.firmwareVersion || null;
      const latest = fw.new_version || fw.latest_version || fw.firmware_new_version || null;
      const need = fw.need_upgrade === "on" || fw.need_upgrade === true;
      if (current) {
        db.updateDeviceFields(d.mac, {
          firmware: current,
          firmware_latest: latest || null,
          firmware_source: "device admin API"
        });
      }
      if (name === "firmwareUpdate") {
        if (!need && !latest) {
          return { ok: false, reason: "The router did not advertise an update. Use its admin page to check.", adminPage: "http://" + d.ip, firmware: current };
        }
        try {
          await session.request("admin/firmware?form=upgrade", "operation=write", true);
          return { ok: true, action: name, firmware: current, latest, note: "Update requested. Confirm on the device if it asks." };
        } catch (e) {
          return { ok: false, reason: "Could not start the update from Meshwatch. Open the admin page.", adminPage: "http://" + d.ip, firmware: current, latest };
        }
      }
      return { ok: true, action: name, firmware: current, latest, needUpgrade: need };
    }
    if (name === "clientList") {
      const status = await routerStatus(session);
      const clients = mapClients(status);
      db.updateDeviceFields(d.mac, { clients: clients.length });
      return { ok: true, action: name, clients };
    }
    if (name === "ssid") {
      const bands = ["wireless_2g", "wireless_5g", "wireless_6g"];
      const out = [];
      for (const form of bands) {
        try {
          const w = await session.request("admin/wireless?form=" + form, "operation=read");
          out.push({
            band: form.replace("wireless_", ""),
            ssid: w[form + "_ssid"] || w.ssid,
            enable: w[form + "_enable"] || w.enable
          });
        } catch (e) { /* band may not exist */ }
      }
      if (args && args.ssid && args.band) {
        const form = "wireless_" + args.band;
        let data = "operation=write&" + form + "_ssid=" + encodeURIComponent(args.ssid);
        if (args.psk) data += "&" + form + "_psk_key=" + encodeURIComponent(args.psk);
        await session.request("admin/wireless?form=" + form, data);
        return { ok: true, action: name, note: "SSID written for " + args.band };
      }
      return { ok: true, action: name, bands: out, note: "Read-only here. To change SSID, open the admin page or pass band/ssid." };
    }
    if (name === "bandSteering") {
      try {
        const w = await session.request("admin/wireless?form=smart_connect", "operation=read");
        return { ok: true, action: name, data: w };
      } catch (e) {
        return { ok: false, reason: "This firmware has no smart-connect/band-steering endpoint", adminPage: "http://" + d.ip };
      }
    }
    if (name === "portForwarding") {
      try {
        const nat = await session.request("admin/nat?form=pt&operation=load", "operation=load");
        return { ok: true, action: name, rules: nat };
      } catch (e) {
        return { ok: false, reason: "Port forwarding table not exposed on this firmware", adminPage: "http://" + d.ip };
      }
    }
    if (name === "led") {
      try {
        await session.request("admin/led?form=setting", "operation=write&enable=" + ((args && args.off) ? "off" : "on"));
        return { ok: true, action: name };
      } catch (e) {
        return { ok: false, reason: "LED control is not on this firmware's local API", adminPage: "http://" + d.ip };
      }
    }
    if (name === "backhaul") {
      try {
        const mesh = await session.request("admin/easymesh_network?form=get_mesh_device_list_all&operation=read", "operation=read");
        return { ok: true, action: name, mesh };
      } catch (e) {
        return { ok: false, reason: "No EasyMesh table on this node", adminPage: "http://" + d.ip };
      }
    }
    if (name === "speedTest") {
      try {
        await session.request("admin/speedtest?form=start", "operation=write", true);
        return { ok: true, action: name, note: "Speed test started on the router. Results stay on its admin page." };
      } catch (e) {
        return { ok: false, reason: "This firmware has no local speed-test action", adminPage: "http://" + d.ip };
      }
    }
    if (name === "channel") {
      return { ok: false, reason: "Channel changes are per-band and disruptive — use the admin page so you can see neighbours", adminPage: "http://" + d.ip };
    }
    return { ok: false, reason: "not available on this firmware", adminPage: "http://" + d.ip, action: name };
  } catch (e) {
    return { ok: false, reason: e.message || String(e), adminPage: "http://" + d.ip, action: name };
  }
}

async function enrichDevices(devices) {
  const byMac = new Map();
  for (const d of devices) byMac.set(String(d.mac || "").toUpperCase(), d);
  const infra = devices.filter((d) => d.control === "tplink" || (d.type === "switch" && d.control === "web"));
  for (const d of infra) {
    if (!credentials.has(d.mac)) continue;
    try {
      const opened = await openSession(d);
      if (!opened.ok) continue;
      if (opened.kind === "switch") {
        const page = await opened.session.get("/SystemInfoRpm.htm");
        const info = opened.session.parseFirmware(page.text || "");
        if (info.firmware) {
          d.firmware = info.firmware;
          d.firmwareSource = "switch web UI";
        }
        continue;
      }
      const fw = await routerFirmware(opened.session).catch(() => null);
      if (fw) {
        d.firmware = fw.firmware_version || d.firmware;
        d.firmwareLatest = fw.new_version || fw.latest_version || d.firmwareLatest;
        d.firmwareSource = "device admin API";
      }
      const status = await routerStatus(opened.session).catch(() => null);
      if (status) {
        const clients = mapClients(status);
        d.clients = clients.length;
        d._tplinkClients = clients;
        for (const c of clients) {
          const child = (c.mac && byMac.get(c.mac)) || devices.find((x) => x.ip === c.ip);
          if (!child || child.mac === d.mac) continue;
          child.parentMac = d.mac;
          child.parentEstimated = false;
          child.link = c.link || child.link;
          child.signal = c.signal || child.signal;
        }
      }
    } catch (e) { /* leave estimated topology */ }
  }
  return devices;
}

async function routerConfigFlags(device) {
  const opened = await openSession(device);
  if (!opened.ok || opened.kind === "switch") return { ok: false, reason: opened.reason || "not a router session" };
  const flags = { unverifiable: [] };
  try {
    const wps = await opened.session.request("admin/wireless?form=wps", "operation=read");
    flags.wps = wps.enable === "on" || wps.wps_enable === "on" || wps.enable === true;
  } catch (e) { flags.unverifiable.push("WPS"); }
  try {
    const upnp = await opened.session.request("admin/upnp?form=setting", "operation=read");
    flags.upnp = upnp.enable === "on" || upnp.upnp_enable === "on";
  } catch (e) { flags.unverifiable.push("UPnP"); }
  try {
    const remote = await opened.session.request("admin/system?form=remote", "operation=read");
    flags.remote = remote.enable === "on" || remote.remote === "on";
  } catch (e) { flags.unverifiable.push("WAN remote management"); }
  return { ok: true, flags };
}

module.exports = {
  capabilities, action, isDisruptive, ACTIONS, enrichDevices, routerConfigFlags, openSession
};
