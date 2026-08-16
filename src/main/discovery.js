// Discovery engine.
//
// Methods, merged by MAC address:
//   1. ICMP ping sweep + OS ARP table   - unprivileged, no Npcap required
//   2. mDNS / Bonjour browse
//   3. SSDP / UPnP search
//   4. DHCP leases from Pi-hole         - API or SSH once credentials are saved
//   5. HTTP web probe (port 80 title)
//   6. SNMP GET sysName/sysDescr        - managed switches/APs that speak SNMP
//
// Scan boundary comes from the OS's own IPv4 interface (any LAN), not a
// hardcoded 192.168.1.0/24. Only the detected /24 of that interface is swept.

const os = require("os");
const { exec } = require("child_process");
const dgram = require("dgram");
const net = require("net");
const dns = require("dns").promises;
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

function parseIpv4(ip) {
  if (!IPV4_RE.test(ip)) return null;
  const parts = ip.split(".").map(Number);
  if (parts.some((n) => n < 0 || n > 255)) return null;
  return parts;
}

// Addresses that can be real hosts on a home LAN — not network, broadcast,
// multicast, loopback, or link-local. Our scan is /24, so .0 and .255 are out.
function isUsableHostIp(ip) {
  const parts = parseIpv4(ip);
  if (!parts) return false;
  const a = parts[0];
  const d = parts[3];

  if (a === 0 || a === 127 || a >= 224) return false; // this-net, loopback, multicast/reserved
  if (a === 169 && parts[1] === 254) return false; // APIPA / link-local
  if (!isPrivateIp(ip)) return false;

  // /24 host range is 1–254. .0 = network, .255 = subnet broadcast (e.g. 192.168.1.255).
  if (d === 0 || d === 255) return false;

  return true;
}

function isBroadcastMac(mac) {
  if (!mac) return true;
  const n = String(mac).toUpperCase().replace(/-/g, ":");
  return n === "FF:FF:FF:FF:FF:FF" || n === "00:00:00:00:00:00";
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

function isDiscoverableHost(ip) {
  return inSubnet(ip) && isUsableHostIp(ip);
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
        if (!isDiscoverableHost(ip)) continue;
        const mac = macM[0].replace(/-/g, ":").toUpperCase();
        if (isBroadcastMac(mac)) continue;
        out.push({ ip, mac });
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
      const ip = (service.addresses || []).find(a => IPV4_RE.test(a) && isDiscoverableHost(a))
        || (service.referer && service.referer.address);
      if (!ip || !isDiscoverableHost(ip)) return;
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
      if (!ip || !isDiscoverableHost(ip)) return;
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
    return await require("./dns").leases();
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
  const sysDescr = await snmpGet(ip, "1.3.6.1.2.1.1.1.0");
  if (!sysName && !sysDescr) return null;
  return { sysName: sysName || null, sysDescr: sysDescr || null };
}

function parseSnmpInteger(buf) {
  for (let i = 0; i < buf.length - 2; i++) {
    if (buf[i] !== 0x02) continue;
    const len = buf[i + 1];
    if (len < 1 || len > 4 || i + 2 + len > buf.length) continue;
    let v = 0;
    for (let k = 0; k < len; k++) v = (v << 8) | buf[i + 2 + k];
    return v;
  }
  return null;
}

function snmpGetRaw(ip, oid, community, timeoutMs) {
  return new Promise((resolve) => {
    const socket = dgram.createSocket("udp4");
    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      try { socket.close(); } catch (e) { /* ignore */ }
      resolve(value);
    };
    const t = setTimeout(() => done(null), timeoutMs || 1200);
    socket.on("message", (msg) => {
      clearTimeout(t);
      done(msg);
    });
    socket.on("error", () => {
      clearTimeout(t);
      done(null);
    });
    try {
      socket.send(snmpGetPacket(community || "public", oid), 161, ip);
    } catch (e) {
      clearTimeout(t);
      done(null);
    }
  });
}

function macToOid(mac) {
  return String(mac).split(":").map((h) => parseInt(h, 16)).join(".");
}

async function switchFdbParents(devices, gatewayMac) {
  const switches = devices.filter((d) => d.type === "switch" && d.ip);
  if (!switches.length) return;
  for (const sw of switches) {
    for (const d of devices) {
      if (!d.mac || d.mac === sw.mac) continue;
      const oid = "1.3.6.1.2.1.17.4.3.1.2." + macToOid(d.mac);
      const raw = await snmpGetRaw(sw.ip, oid);
      if (!raw) continue;
      const port = parseSnmpInteger(raw);
      if (!port) continue;
      // Gateway MAC on the switch is the uplink — leave those hanging off the gateway.
      if (gatewayMac && d.mac === gatewayMac) continue;
      d.parentMac = sw.mac;
      d.parentEstimated = true;
      d.link = d.link || ("Ethernet · port " + port + " est.");
    }
  }
}

// Reverse DNS (PTR) against whatever resolver this PC uses — often the
// Pi-hole / router, which may already know a hostname for the lease.
async function dnsReverse(ip) {
  try {
    const names = await dns.reverse(ip);
    const name = (names || []).find(Boolean);
    return name ? String(name).replace(/\.$/, "").split(".")[0] : null;
  } catch (e) {
    return null;
  }
}

// Brief TCP connect — populates the OS ARP cache for hosts that ignore ICMP
// but still have a listening service (or reject the connect).
function touchHost(ip, port = 80, timeoutMs = 400) {
  return new Promise((resolve) => {
    const socket = net.connect({ host: ip, port, timeout: timeoutMs }, () => {
      socket.destroy();
      resolve(true);
    });
    socket.on("error", () => resolve(false));
    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });
  });
}

// NetBIOS Node Status (NBSTAT) — Windows / Samba hosts often answer with
// their computer name even when ping is blocked.
function encodeNetbiosName(name) {
  const padded = (name + "                ").slice(0, 16);
  const out = Buffer.alloc(34);
  out[0] = 32;
  for (let i = 0; i < 16; i++) {
    const c = padded.charCodeAt(i);
    out[1 + i * 2] = 0x41 + ((c >> 4) & 0x0f);
    out[2 + i * 2] = 0x41 + (c & 0x0f);
  }
  out[33] = 0;
  return out;
}

function netbiosStatus(ip, timeoutMs = 900) {
  return new Promise((resolve) => {
    const socket = dgram.createSocket("udp4");
    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      try { socket.close(); } catch (e) { /* ignore */ }
      resolve(value);
    };

    const txn = Math.floor(Math.random() * 0xffff);
    const header = Buffer.alloc(12);
    header.writeUInt16BE(txn, 0);
    header.writeUInt16BE(0x0000, 2);
    header.writeUInt16BE(1, 4); // questions
    const qname = encodeNetbiosName("*");
    const qtail = Buffer.alloc(4);
    qtail.writeUInt16BE(0x0021, 0); // NBSTAT
    qtail.writeUInt16BE(0x0001, 2); // IN
    const packet = Buffer.concat([header, qname, qtail]);

    const t = setTimeout(() => done(null), timeoutMs);
    socket.on("message", (msg) => {
      clearTimeout(t);
      // After question echo, names block: count at offset, then 18-byte records.
      try {
        let offset = 12;
        if (msg[offset] === 0x20) offset += 34;
        else {
          while (offset < msg.length && msg[offset] !== 0) offset += 1 + msg[offset];
          offset += 1;
        }
        offset += 4; // type + class
        if (offset + 2 > msg.length) return done(null);
        // TTL(4) + data len(2) + name count(1)
        offset += 4;
        const dataLen = msg.readUInt16BE(offset); offset += 2;
        if (dataLen < 1 || offset >= msg.length) return done(null);
        const count = msg[offset]; offset += 1;
        for (let i = 0; i < count && offset + 18 <= msg.length; i++) {
          const raw = msg.slice(offset, offset + 15).toString("ascii").replace(/\0/g, "").trim();
          const nameType = msg[offset + 15];
          offset += 18;
          // 0x00 workstation, 0x20 file server — skip group names (bit in flags)
          const flags = msg[offset - 2];
          const isGroup = (flags & 0x80) !== 0;
          if (!isGroup && raw && (nameType === 0x00 || nameType === 0x20)) {
            return done(raw);
          }
        }
      } catch (e) { /* ignore */ }
      done(null);
    });
    socket.on("error", () => {
      clearTimeout(t);
      done(null);
    });
    try {
      socket.send(packet, 137, ip);
    } catch (e) {
      clearTimeout(t);
      done(null);
    }
  });
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
  // that belongs in the Vendor column. User renames live in DB as name_override
  // and are applied after the scan in listDevices().
  const dhcp = d.lease && d.lease.hostname;
  const mdns = d.mdnsHit && d.mdnsHit.name;
  const dnsName = d.dnsName || null;
  const netbios = d.netbiosName || null;
  const known = k && k.name;
  const snmpName = d.snmp && d.snmp.sysName;
  const title = usableDeviceTitle(d.web && d.web.title);
  const model = (k && k.model && k.model !== "unknown") ? k.model : null;
  const snmpModel = d.snmp && d.snmp.sysDescr && (d.snmp.sysDescr.match(/\b(TL-[A-Z0-9]+|Archer\s+\w+|RE\d+|SG\d+\w*)\b/i) || [])[0];

  return dhcp || mdns || dnsName || netbios || known || snmpName || title || model || snmpModel || "Unidentified host";
}

async function run({ onProgress } = {}) {
  const report = (stage, detail) => { if (onProgress) onProgress(stage, detail); };

  const detected = detectSubnet();
  report("start", { subnet: detected.cidr, localIp: detected.localIp, iface: detected.iface });

  const alive = await pingSweep((s, d) => report(s, d));

  report("mdns", { note: "browsing mDNS / Bonjour" });
  const mdns = await mdnsBrowse();

  report("ssdp", { note: "SSDP / UPnP search" });
  const ssdp = await ssdpSearch();

  report("dhcp", { note: "reading Pi-hole leases" });
  const leases = await dhcpLeases();

  // Touch mDNS/SSDP/DHCP IPs so quiet hosts still land in the OS ARP table.
  const extraIps = new Set();
  for (const x of mdns) if (x.ip && isDiscoverableHost(x.ip)) extraIps.add(x.ip);
  for (const x of ssdp) if (x.ip && isDiscoverableHost(x.ip)) extraIps.add(x.ip);
  for (const x of leases) if (x.ip && isDiscoverableHost(x.ip)) extraIps.add(x.ip);
  for (const ip of alive) if (isDiscoverableHost(ip)) extraIps.add(ip);

  report("touch", { note: "waking ARP via short TCP probes", count: extraIps.size });
  await Promise.all(Array.from(extraIps).map((ip) =>
    touchHost(ip, 80).then((ok) => ok || touchHost(ip, 443)).then((ok) => ok || touchHost(ip, 445))
  ));

  report("arp", { note: "reading OS ARP table" });
  let arp = await arpTable();

  // Second ARP pass after a brief settle for late replies.
  if (extraIps.size && arp.length < extraIps.size) {
    await new Promise((r) => setTimeout(r, 300));
    arp = await arpTable();
  }

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
      dnsName: null,
      netbiosName: null,
      methods: ["arp"]
        .concat(alive.indexOf(entry.ip) !== -1 ? ["ping"] : [])
        .concat(lease ? ["dhcp"] : [])
        .concat(m ? ["mdns"] : [])
        .concat(s ? ["ssdp"] : [])
    });
  }

  const devices = Array.from(byMac.values());

  report("dns", { note: "reverse DNS (PTR) lookups", count: devices.length });
  await Promise.all(devices.map(async (d) => {
    d.dnsName = await dnsReverse(d.ip);
    if (d.dnsName) d.methods.push("dns");
  }));

  report("netbios", { note: "NetBIOS name status", count: devices.length });
  await Promise.all(devices.map(async (d) => {
    d.netbiosName = await netbiosStatus(d.ip);
    if (d.netbiosName) d.methods.push("netbios");
  }));

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
    d.ssdp_st = d.ssdpHit && d.ssdpHit.st;

    const titleFw = d.web && d.web.title && d.web.title.match(/(\d+\.\d+(?:\.\d+)?(?:\s*Build\s*\d+)?)/i);
    if (titleFw && !d.firmware) {
      d.firmware = titleFw[1];
      d.firmwareSource = "web title";
    }
  }

  const gatewayDevice = devices.find(d => d.ip === gatewayIp);
  const gatewayMac = gatewayDevice ? gatewayDevice.mac : null;
  for (const d of devices) {
    d.parentMac = (gatewayMac && d.mac !== gatewayMac) ? gatewayMac : null;
    d.parentEstimated = true;
    if (d.type === "gateway") {
      d.parentMac = null;
      d.parentEstimated = false;
      d.link = d.link || "WAN";
    }
  }

  report("fdb", { note: "SNMP forwarding table on managed switches" });
  await switchFdbParents(devices, gatewayMac);

  report("tplink", { note: "reading TP-Link client lists where a password is saved" });
  try {
    await require("./tplink").enrichDevices(devices);
  } catch (e) { /* topology stays estimated */ }

  try {
    const stats = await require("./dns").stats();
    if (stats && stats.available && Array.isArray(stats.talkers)) {
      for (const t of stats.talkers) {
        const hit = devices.find((d) => d.ip === t.ip || d.name === t.name);
        if (hit) hit.queryCount = t.queries;
      }
    }
    if (stats && stats.available && stats.firmware) {
      const pi = devices.find((d) => d.type === "dns-dhcp");
      if (pi) {
        pi.firmware = stats.firmware;
        pi.firmwareSource = "dns backend API";
      }
    }
  } catch (e) { /* optional */ }

  for (const d of devices) {
    const kids = devices.filter((x) => x.parentMac === d.mac).length;
    if (kids) d.clients = kids;
  }

  for (const d of devices) {
    delete d.lease; delete d.mdnsHit; delete d.ssdpHit;
    delete d.dnsName; delete d.netbiosName;
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
  detectSubnet, getSubnet, snmpProbe, isUsableHostIp, isDiscoverableHost
};
