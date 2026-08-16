// Discovery engine.
//
// Methods, merged by MAC address:
//   1. ICMP ping sweep + OS ARP table   - unprivileged, no Npcap required
//   2. mDNS / Bonjour browse
//   3. SSDP / UPnP search
//   4. DHCP leases from Pi-hole         - empty until phase 2 credentials
//   5. HTTP web probe (port 80 title)
//   6. SNMP GET sysName/sysDescr        - managed switches/APs that speak SNMP
//
// Scan boundary comes from the OS's own IPv4 interface (any LAN), not a
// hardcoded 192.168.1.0/24. Only the detected /24 of that interface is swept.

const os = require("os");
const { exec } = require("child_process");
const dgram = require("dgram");
const http = require("http");
const ping = require("ping");
const { Bonjour } = require("bonjour-service");
const { Client: SsdpClient } = require("node-ssdp");
const oui = require("./oui");
const config = require("../../config/devices.json");

const CONCURRENCY = 32;
const IPV4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

// Mutable scan boundary for this process - set by detectSubnet() / run().
let subnet = {
  prefix: "192.168.1.",
  cidr: "192.168.1.0/24",
  localIp: null,
  iface: null
};

function isPrivateIp(ip) {
  if (!IPV4_RE.test(ip)) return false;
  if (ip.indexOf("10.") === 0) return true;
  if (ip.indexOf("192.168.") === 0) return true;
  if (ip.indexOf("169.254.") === 0) return false;
  const m = ip.match(/^172\.(\d+)\./);
  if (m) {
    const n = Number(m[1]);
    return n >= 16 && n <= 31;
  }
  return false;
}

function detectSubnet() {
  const ifaces = os.networkInterfaces();
  const scored = [];

  for (const name of Object.keys(ifaces)) {
    for (const addr of ifaces[name] || []) {
      const family = addr.family;
      if (family !== "IPv4" && family !== 4) continue;
      if (addr.internal) continue;
      if (!isPrivateIp(addr.address)) continue;

      const parts = addr.address.split(".");
      const prefix = parts[0] + "." + parts[1] + "." + parts[2] + ".";
      // Hard boundary: only ever sweep the /24 containing this host.
      // Wider masks would mean scanning thousands of hosts; narrower is rare
      // on home LANs and still safe to probe as a /24 of the third octet.
      const cidr = prefix + "0/24";
      let score = 10;
      if (addr.address.indexOf("192.168.") === 0) score += 5;
      if (/wi-?fi|wlan|ethernet|eth|en0|local/i.test(name)) score += 2;
      scored.push({ prefix, cidr, localIp: addr.address, iface: name, score });
    }
  }

  scored.sort((a, b) => b.score - a.score);
  if (scored[0]) {
    subnet = {
      prefix: scored[0].prefix,
      cidr: scored[0].cidr,
      localIp: scored[0].localIp,
      iface: scored[0].iface
    };
  } else if (config.subnet && /^(\d+\.\d+\.\d+)\.0\/24$/.test(config.subnet)) {
    const m = config.subnet.match(/^(\d+\.\d+\.\d+)\.0\/24$/);
    subnet = { prefix: m[1] + ".", cidr: config.subnet, localIp: null, iface: null };
  }
  return Object.assign({}, subnet);
}

function getSubnet() {
  return Object.assign({}, subnet);
}

function inSubnet(ip) {
  return ip && ip.indexOf(subnet.prefix) === 0;
}

function pingHost(ip) {
  return ping.promise.probe(ip, { timeout: 1, extra: process.platform === "win32" ? ["-n", "1"] : ["-c", "1"] })
    .then(r => (r.alive ? ip : null))
    .catch(() => null);
}

async function pingSweep(onProgress) {
  const ips = [];
  for (let i = 1; i <= 254; i++) ips.push(subnet.prefix + i);
  const alive = [];
  let done = 0;

  for (let i = 0; i < ips.length; i += CONCURRENCY) {
    const batch = ips.slice(i, i + CONCURRENCY);
    const results = await Promise.all(batch.map(pingHost));
    for (const r of results) if (r) alive.push(r);
    done += batch.length;
    if (onProgress) onProgress("ping", { probed: done, total: ips.length, found: alive.length, subnet: subnet.cidr });
  }
  return alive;
}

function arpTable() {
  return new Promise((resolve) => {
    exec("arp -a", { windowsHide: true }, (err, stdout) => {
      if (err) return resolve([]);
      const out = [];
      const lines = String(stdout).split(/\r?\n/);
      for (const line of lines) {
        const ipM = line.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
        const macM = line.match(/([0-9a-f]{2}[:-]){5}[0-9a-f]{2}/i);
        if (!ipM || !macM) continue;
        const ip = ipM[1];
        if (!inSubnet(ip)) continue;
        out.push({ ip, mac: macM[0].replace(/-/g, ":").toUpperCase() });
      }
      resolve(out);
    });
  });
}

function mdnsBrowse(durationMs = 4000) {
  return new Promise((resolve) => {
    let bonjour;
    try {
      bonjour = new Bonjour(undefined, () => {});
    } catch (e) {
      return resolve([]);
    }

    const found = new Map();
    const record = (service) => {
      const ip = (service.addresses || []).find(a => IPV4_RE.test(a) && inSubnet(a))
        || (service.referer && service.referer.address);
      if (!ip || !inSubnet(ip)) return;
      if (!found.has(ip)) found.set(ip, { ip, name: service.name || null, service: service.type || null });
    };

    let browser;
    try {
      browser = bonjour.find({}, record);
    } catch (e) {
      return resolve([]);
    }

    setTimeout(() => {
      try { browser.stop(); } catch (e) { /* already stopped */ }
      try { bonjour.destroy(); } catch (e) { /* socket already closed */ }
      resolve(Array.from(found.values()));
    }, durationMs);
  });
}

function ssdpSearch(durationMs = 4000) {
  return new Promise((resolve) => {
    let client;
    try {
      client = new SsdpClient();
    } catch (e) {
      return resolve([]);
    }

    const found = new Map();
    client.on("response", (headers, _statusCode, rinfo) => {
      const ip = rinfo && rinfo.address;
      if (!ip || !inSubnet(ip)) return;
      if (!found.has(ip)) {
        found.set(ip, {
          ip,
          server: headers.SERVER || null,
          st: headers.ST || null,
          location: headers.LOCATION || null
        });
      }
    });
    client.on("error", () => {});

    try { client.search("ssdp:all"); } catch (e) { /* nothing to search on */ }

    setTimeout(() => {
      try { client.stop(); } catch (e) { /* already stopped */ }
      resolve(Array.from(found.values()));
    }, durationMs);
  });
}

async function dhcpLeases() {
  try {
    return await require("./pihole").leases();
  } catch (e) {
    return [];
  }
}

function defaultGateway() {
  return new Promise((resolve) => {
    if (process.platform === "win32") {
      exec("ipconfig", { windowsHide: true }, (err, stdout) => {
        if (err) return resolve(null);
        let fallback = null;
        for (const line of String(stdout).split(/\r?\n/)) {
          const m = line.match(/Default Gateway[.\s]*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i);
          if (!m) continue;
          if (inSubnet(m[1])) return resolve(m[1]);
          if (!fallback && isPrivateIp(m[1])) fallback = m[1];
        }
        resolve(fallback);
      });
      return;
    }
    if (process.platform === "darwin") {
      exec("route -n get default", { windowsHide: true }, (err, stdout) => {
        if (err) return resolve(null);
        const m = String(stdout).match(/gateway:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i);
        resolve(m && isPrivateIp(m[1]) ? m[1] : null);
      });
      return;
    }
    exec("ip route show default", { windowsHide: true }, (err, stdout) => {
      if (err) return resolve(null);
      const m = String(stdout).match(/default via (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i);
      resolve(m && isPrivateIp(m[1]) ? m[1] : null);
    });
  });
}

function webProbe(ip, port = 80, timeoutMs = 1500) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (result) => { if (!settled) { settled = true; resolve(result); } };

    const req = http.get({ host: ip, port, path: "/", timeout: timeoutMs }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        body += chunk;
        if (body.length > 20000) res.destroy();
      });
      const finish = () => {
        const titleM = body.match(/<title[^>]*>([^<]*)<\/title>/i);
        done({
          reachable: true,
          port,
          status: res.statusCode,
          server: res.headers.server || null,
          title: titleM ? titleM[1].trim().slice(0, 120) : null,
          hasLoginForm: /type=["']?password["']?/i.test(body) || /\blogin\b/i.test(body)
        });
      };
      res.on("end", finish);
      res.on("close", finish);
      res.on("error", () => done({ reachable: false, port }));
    });
    req.on("timeout", () => { req.destroy(); done({ reachable: false, port }); });
    req.on("error", () => done({ reachable: false, port }));
  });
}

// --- SNMP (minimal v2c GET for sysDescr / sysName) -------------------------
// Managed switches (TL-SG108E etc.) often answer this even when the web UI
// title is generic. Community "public" only - never a login attempt.

function berLen(n) {
  if (n < 0x80) return Buffer.from([n]);
  if (n < 0x100) return Buffer.from([0x81, n]);
  return Buffer.from([0x82, (n >> 8) & 0xff, n & 0xff]);
}

function berOid(oidStr) {
  const parts = oidStr.split(".").map(Number);
  const body = [];
  body.push(40 * parts[0] + parts[1]);
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i];
    if (v < 128) body.push(v);
    else {
      const stack = [];
      stack.push(v & 0x7f);
      v >>= 7;
      while (v > 0) {
        stack.push(0x80 | (v & 0x7f));
        v >>= 7;
      }
      for (let j = stack.length - 1; j >= 0; j--) body.push(stack[j]);
    }
  }
  return Buffer.concat([Buffer.from([0x06]), berLen(body.length), Buffer.from(body)]);
}

function snmpGetPacket(community, oidStr) {
  const communityBuf = Buffer.from(String(community), "utf8");
  const oid = berOid(oidStr);
  const nullVal = Buffer.from([0x05, 0x00]);
  const varbind = Buffer.concat([
    Buffer.from([0x30]), berLen(oid.length + nullVal.length), oid, nullVal
  ]);
  const varbindList = Buffer.concat([Buffer.from([0x30]), berLen(varbind.length), varbind]);
  const reqId = Buffer.from([0x02, 0x01, 0x01]);
  const errStat = Buffer.from([0x02, 0x01, 0x00]);
  const errIdx = Buffer.from([0x02, 0x01, 0x00]);
  const pduBody = Buffer.concat([reqId, errStat, errIdx, varbindList]);
  const pdu = Buffer.concat([Buffer.from([0xa0]), berLen(pduBody.length), pduBody]);
  const version = Buffer.from([0x02, 0x01, 0x01]); // SNMPv2c
  const comm = Buffer.concat([Buffer.from([0x04]), berLen(communityBuf.length), communityBuf]);
  const inner = Buffer.concat([version, comm, pdu]);
  return Buffer.concat([Buffer.from([0x30]), berLen(inner.length), inner]);
}

function parseSnmpOctetString(buf) {
  // Walk for the first OCTET STRING (0x04) after the PDU - good enough for
  // sysName/sysDescr responses from consumer gear.
  for (let i = 0; i < buf.length - 2; i++) {
    if (buf[i] !== 0x04) continue;
    let len = buf[i + 1];
    let hdr = 2;
    if (len & 0x80) {
      const n = len & 0x7f;
      len = 0;
      for (let k = 0; k < n; k++) len = (len << 8) | buf[i + 2 + k];
      hdr = 2 + n;
    }
    if (len <= 0 || i + hdr + len > buf.length) continue;
    const s = buf.slice(i + hdr, i + hdr + len).toString("utf8").replace(/\0/g, "").trim();
    if (s) return s.slice(0, 200);
  }
  return null;
}

function snmpGet(ip, oid, community = "public", timeoutMs = 1200) {
  return new Promise((resolve) => {
    const socket = dgram.createSocket("udp4");
    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      try { socket.close(); } catch (e) { /* ignore */ }
      resolve(value);
    };
    const t = setTimeout(() => done(null), timeoutMs);
    socket.on("message", (msg) => {
      clearTimeout(t);
      done(parseSnmpOctetString(msg));
    });
    socket.on("error", () => {
      clearTimeout(t);
      done(null);
    });
    try {
      socket.send(snmpGetPacket(community, oid), 161, ip);
    } catch (e) {
      clearTimeout(t);
      done(null);
    }
  });
}

async function snmpProbe(ip) {
  const sysName = await snmpGet(ip, "1.3.6.1.2.1.1.5.0");
  const sysDescr = sysName ? await snmpGet(ip, "1.3.6.1.2.1.1.1.0") : await snmpGet(ip, "1.3.6.1.2.1.1.1.0");
  if (!sysName && !sysDescr) return null;
  return { sysName: sysName || null, sysDescr: sysDescr || null };
}

function matchKnown(device, gatewayIp) {
  const confirmed = config.known.find(k => k.confirmed && k.confirmed.ip === device.ip);
  if (confirmed) return { entry: confirmed, how: "ip confirmed by you" };

  if (gatewayIp && device.ip === gatewayIp) {
    const gw = config.known.find(k => k.role === "gateway");
    if (gw) return { entry: gw, how: "default gateway (from OS routing table)" };
  }

  const haystacks = [];
  if (device.web && device.web.title) haystacks.push(device.web.title);
  if (device.snmp && device.snmp.sysName) haystacks.push(device.snmp.sysName);
  if (device.snmp && device.snmp.sysDescr) haystacks.push(device.snmp.sysDescr);

  for (const hay of haystacks) {
    const lower = hay.toLowerCase();
    const byModel = config.known.find(k => k.model && k.model !== "unknown" && lower.indexOf(k.model.toLowerCase()) !== -1);
    if (byModel) return { entry: byModel, how: "model named by the device itself" };
  }

  return null;
}

function usableDeviceTitle(title) {
  if (!title) return null;
  if (/unauthorized|forbidden|not found|bad request|error \d{3}|login|sign in/i.test(title)) return null;
  // Generic vendor-only titles are not a device name.
  if (/^(tp-?link|netgear|d-?link|asus|cisco|apple|samsung|sony|microsoft)$/i.test(title.trim())) return null;
  return title.trim();
}

function pickName(d, k) {
  // Prefer real host/device names. Never fall back to the OUI vendor string —
  // that belongs in the Vendor column.
  const dhcp = d.lease && d.lease.hostname;
  const mdns = d.mdnsHit && d.mdnsHit.name;
  const known = k && k.name;
  const snmpName = d.snmp && d.snmp.sysName;
  const title = usableDeviceTitle(d.web && d.web.title);
  const model = (k && k.model && k.model !== "unknown") ? k.model : null;
  const snmpModel = d.snmp && d.snmp.sysDescr && (d.snmp.sysDescr.match(/\b(TL-[A-Z0-9]+|Archer\s+\w+|RE\d+|SG\d+\w*)\b/i) || [])[0];

  return dhcp || mdns || known || snmpName || title || model || snmpModel || "Unidentified host";
}

async function run({ onProgress } = {}) {
  const report = (stage, detail) => { if (onProgress) onProgress(stage, detail); };

  const detected = detectSubnet();
  report("start", { subnet: detected.cidr, localIp: detected.localIp, iface: detected.iface });

  const alive = await pingSweep((s, d) => report(s, d));

  report("mdns", { note: "browsing mDNS" });
  const mdns = await mdnsBrowse();

  report("ssdp", { note: "SSDP search" });
  const ssdp = await ssdpSearch();

  report("dhcp", { note: "reading Pi-hole leases" });
  const leases = await dhcpLeases();

  report("arp", { note: "reading OS ARP table" });
  const arp = await arpTable();

  report("gateway", { note: "reading OS routing table" });
  const gatewayIp = await defaultGateway();

  const byMac = new Map();
  for (const entry of arp) {
    const lease = leases.find(l => l.ip === entry.ip || l.mac === entry.mac);
    const m = mdns.find(x => x.ip === entry.ip);
    const s = ssdp.find(x => x.ip === entry.ip);

    byMac.set(entry.mac, {
      mac: entry.mac,
      ip: entry.ip,
      lease, mdnsHit: m, ssdpHit: s,
      vendor: oui.vendor(entry.mac) || null,
      web: null,
      snmp: null,
      methods: ["arp"]
        .concat(alive.indexOf(entry.ip) !== -1 ? ["ping"] : [])
        .concat(lease ? ["dhcp"] : [])
        .concat(m ? ["mdns"] : [])
        .concat(s ? ["ssdp"] : [])
    });
  }

  // Hosts that answered ping/mDNS/SSDP but aren't in ARP yet (rare) - skip;
  // without a MAC we can't key the inventory.

  const devices = Array.from(byMac.values());

  report("webprobe", { note: "checking each device for an admin web page", count: devices.length });
  await Promise.all(devices.map(async (d) => { d.web = await webProbe(d.ip); }));

  report("snmp", { note: "SNMP sysName/sysDescr where answered", count: devices.length });
  await Promise.all(devices.map(async (d) => {
    d.snmp = await snmpProbe(d.ip);
    if (d.snmp) d.methods.push("snmp");
  }));

  for (const d of devices) {
    const match = matchKnown(d, gatewayIp);
    const k = match && match.entry;

    d.name = pickName(d, k);
    d.vendor = (k && k.vendor) || d.vendor;
    d.type = (k && k.role) || null;
    d.model = (k && k.model && k.model !== "unknown")
      ? k.model
      : (d.snmp && d.snmp.sysDescr && (d.snmp.sysDescr.match(/\b(TL-[A-Z0-9]+[A-Z]?)\b/i) || [])[0]) || null;
    d.control = k ? k.control : "none";
    d.endOfSupport = (k && k.endOfSupport) || null;
    d.matchedBy = match ? match.how : null;
    d.estimated = !k;
    d.firmware = null;
    d.firmwareLatest = null;
    d.firmwareSource = d.control === "none" ? "no API" : null;
    d.subnet = subnet.cidr;

    delete d.lease; delete d.mdnsHit; delete d.ssdpHit;
  }

  const gatewayDevice = devices.find(d => d.ip === gatewayIp);
  for (const d of devices) {
    d.parentMac = (gatewayDevice && d.mac !== gatewayDevice.mac) ? gatewayDevice.mac : null;
    d.parentEstimated = true;
  }

  report("done", { found: devices.length, subnet: subnet.cidr });
  return devices;
}

function topology(devices) {
  const nodes = devices.map(d => ({
    mac: d.mac, ip: d.ip, name: d.name, type: d.type,
    parent: d.parent_mac || d.parentMac || null,
    estimated: !!(d.parent_estimated !== undefined ? d.parent_estimated : d.parentEstimated)
  }));
  const build = (parentMac) => nodes
    .filter(n => n.parent === parentMac)
    .map(n => Object.assign({}, n, { children: build(n.mac) }));
  const gateway = nodes.find(n => n.type === "gateway");
  if (!gateway) return build(null);
  return [Object.assign({}, gateway, { estimated: false, children: build(gateway.mac) })];
}

function detectDrift(devices) {
  const foundIps = new Set(devices.map(d => d.ip));
  const warnings = [];

  for (const k of config.known) {
    if (!k.confirmed || !k.confirmed.ip || foundIps.has(k.confirmed.ip)) continue;
    warnings.push({
      knownName: k.name,
      expectedIp: k.confirmed.ip,
      estimated: true,
      detail: k.name + " was confirmed at " + k.confirmed.ip + " (" + k.confirmed.source + ") " +
        "but didn't answer there this scan. It may be offline, or its address may have changed - " +
        "if so, update config/devices.json's confirmed.ip."
    });
  }
  return warnings;
}

module.exports = {
  run, topology, detectDrift, webProbe, defaultGateway, pingSweep, arpTable,
  detectSubnet, getSubnet, snmpProbe
};
