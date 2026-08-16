// Discovery engine.
//
// Four methods, merged by MAC address:
//   1. ICMP ping sweep + OS ARP table   - unprivileged, no Npcap required
//   2. mDNS / Bonjour browse            - bonjour-service, wildcard browse
//   3. SSDP / UPnP search               - node-ssdp, ssdp:all M-SEARCH
//   4. DHCP leases from Pi-hole         - see pihole.js; empty until phase 2
//                                          wires up credentials
//
// Raw ARP via Npcap finds hosts that ignore ping. If you add it, keep this
// path as the unprivileged fallback.

const { exec } = require("child_process");
const http = require("http");
const ping = require("ping");
const { Bonjour } = require("bonjour-service");
const { Client: SsdpClient } = require("node-ssdp");
const oui = require("./oui");
const config = require("../../config/devices.json");

const SUBNET_PREFIX = "192.168.1.";
const CONCURRENCY = 32;
const IPV4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

function pingHost(ip) {
  return ping.promise.probe(ip, { timeout: 1, extra: process.platform === "win32" ? ["-n", "1"] : ["-c", "1"] })
    .then(r => (r.alive ? ip : null))
    .catch(() => null);
}

async function pingSweep(onProgress) {
  const ips = [];
  for (let i = 1; i <= 254; i++) ips.push(SUBNET_PREFIX + i);
  const alive = [];
  let done = 0;

  for (let i = 0; i < ips.length; i += CONCURRENCY) {
    const batch = ips.slice(i, i + CONCURRENCY);
    const results = await Promise.all(batch.map(pingHost));
    for (const r of results) if (r) alive.push(r);
    done += batch.length;
    if (onProgress) onProgress("ping", { probed: done, total: ips.length, found: alive.length });
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
        // Matches both Windows "192.168.1.1  9c-53-22-1a-0b-44  dynamic"
        // and unix "? (192.168.1.1) at 9c:53:22:1a:0b:44 on en0".
        const ipM = line.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
        const macM = line.match(/([0-9a-f]{2}[:-]){5}[0-9a-f]{2}/i);
        if (!ipM || !macM) continue;
        const ip = ipM[1];
        if (ip.indexOf(SUBNET_PREFIX) !== 0) continue;
        out.push({ ip, mac: macM[0].replace(/-/g, ":").toUpperCase() });
      }
      resolve(out);
    });
  });
}

// --- mDNS / Bonjour ---------------------------------------------------------

// Wildcard browse (_services._dns-sd._udp.local) picks up every advertised
// service type in one pass - AirPlay, Google Cast, IPP printers, AirTunes,
// Sonos, SMB workstations and anything else a device on this network
// announces - rather than guessing a fixed list of types up front.
function mdnsBrowse(durationMs = 4000) {
  return new Promise((resolve) => {
    let bonjour;
    try {
      bonjour = new Bonjour(undefined, () => {}); // swallow mdns socket errors
    } catch (e) {
      return resolve([]);
    }

    const found = new Map(); // ip -> { ip, name, service }
    const record = (service) => {
      const ip = (service.addresses || []).find(a => IPV4_RE.test(a) && a.indexOf(SUBNET_PREFIX) === 0)
        || (service.referer && service.referer.address);
      if (!ip || ip.indexOf(SUBNET_PREFIX) !== 0) return;
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

// --- SSDP / UPnP -------------------------------------------------------------

// This is how the GREE air conditioner, the PS4 and the Bravia TV announce
// themselves - they answer an ssdp:all M-SEARCH even without a full UPnP
// media stack.
function ssdpSearch(durationMs = 4000) {
  return new Promise((resolve) => {
    let client;
    try {
      client = new SsdpClient();
    } catch (e) {
      return resolve([]);
    }

    const found = new Map(); // ip -> { ip, server, st, location }
    client.on("response", (headers, _statusCode, rinfo) => {
      const ip = rinfo && rinfo.address;
      if (!ip || ip.indexOf(SUBNET_PREFIX) !== 0) return;
      if (!found.has(ip)) {
        found.set(ip, {
          ip,
          server: headers.SERVER || null,
          st: headers.ST || null,
          location: headers.LOCATION || null
        });
      }
    });
    client.on("error", () => {}); // network is quiet - not a failure

    try { client.search("ssdp:all"); } catch (e) { /* nothing to search on */ }

    setTimeout(() => {
      try { client.stop(); } catch (e) { /* already stopped */ }
      resolve(Array.from(found.values()));
    }, durationMs);
  });
}

// The Pi-hole lease table is the authoritative source of hostnames - see
// CLAUDE.md. Reading it needs the Pi-hole API/SSH credentials, which phase 2
// pulls from the OS credential store; until that runs, pihole.leases()
// honestly returns an empty list rather than fabricating hostnames.
async function dhcpLeases() {
  try {
    return await require("./pihole").leases();
  } catch (e) {
    return [];
  }
}

// --- default gateway ---------------------------------------------------

// Which discovered IP is actually the router is a fact the OS already knows
// from its own routing table - asking it beats hardcoding an address and
// hoping. Windows only for now; mac/linux route parsing is an honest gap,
// not a guess (TODO: `route -n get default` / `ip route show default`).
function defaultGateway() {
  return new Promise((resolve) => {
    if (process.platform !== "win32") return resolve(null);
    exec("ipconfig", { windowsHide: true }, (err, stdout) => {
      if (err) return resolve(null);
      let fallback = null;
      for (const line of String(stdout).split(/\r?\n/)) {
        const m = line.match(/Default Gateway[.\s]*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i);
        if (!m) continue;
        if (m[1].indexOf(SUBNET_PREFIX) === 0) return resolve(m[1]); // the adapter on our configured subnet
        if (!fallback) fallback = m[1]; // some other adapter's gateway - last resort
      }
      resolve(fallback);
    });
  });
}

// --- web probe -----------------------------------------------------------

// What CLAUDE.md calls "see what it can access": a plain GET, never a login
// attempt, never a form submission. Records whether something answers on
// port 80, what it calls itself in <title> (routers routinely put their own
// model name there, unauthenticated) and whether the page looks like a
// login form - real, observed facts, not guesses.
function webProbe(ip, port = 80, timeoutMs = 1500) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (result) => { if (!settled) { settled = true; resolve(result); } };

    const req = http.get({ host: ip, port, path: "/", timeout: timeoutMs }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        body += chunk;
        if (body.length > 20000) res.destroy(); // enough to have seen a <title>
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

// --- merge -----------------------------------------------------------------

// Attaches config/devices.json's friendly name/role/control info to a
// discovered device, but only on evidence that is itself discovered, never
// a positional guess:
//   1. an IP the user explicitly confirmed (`confirmed.ip` in the config)
//   2. the role "gateway", matched against the OS's own default-gateway IP
//   3. the device's own admin page naming its model in <title>
// Anything else stays unmatched rather than being mislabelled - several
// known devices share a vendor (TP-Link) with no way to tell them apart
// from ARP/mDNS/SSDP alone.
function matchKnown(device, gatewayIp) {
  const confirmed = config.known.find(k => k.confirmed && k.confirmed.ip === device.ip);
  if (confirmed) return { entry: confirmed, how: "ip confirmed by you" };

  if (gatewayIp && device.ip === gatewayIp) {
    const gw = config.known.find(k => k.role === "gateway");
    if (gw) return { entry: gw, how: "default gateway (from OS routing table)" };
  }

  if (device.web && device.web.title) {
    const title = device.web.title.toLowerCase();
    const byModel = config.known.find(k => k.model && k.model !== "unknown" && title.indexOf(k.model.toLowerCase()) !== -1);
    if (byModel) return { entry: byModel, how: "model named in its own web UI title" };
  }

  return null;
}

async function run({ onProgress } = {}) {
  const report = (stage, detail) => { if (onProgress) onProgress(stage, detail); };

  report("start", { subnet: config.subnet });
  const alive = await pingSweep((s, d) => report(s, d));

  report("mdns", { note: "browsing mDNS" });
  const mdns = await mdnsBrowse();

  report("ssdp", { note: "SSDP search" });
  const ssdp = await ssdpSearch();

  report("dhcp", { note: "reading Pi-hole leases" });
  const leases = await dhcpLeases();

  // Read the ARP table last. The ping sweep, mDNS browse and SSDP search all
  // make the OS talk to these hosts over UDP/ICMP, which populates its ARP
  // cache as a side effect - so a device that ignores ping but answers mDNS
  // or SSDP still ends up here with a resolvable MAC.
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
      lease, mdnsHit: m, ssdpHit: s, // kept only to finish naming after the web probe below
      vendor: oui.vendor(entry.mac) || null,
      web: null,
      methods: ["arp"]
        .concat(alive.indexOf(entry.ip) !== -1 ? ["ping"] : [])
        .concat(lease ? ["dhcp"] : [])
        .concat(m ? ["mdns"] : [])
        .concat(s ? ["ssdp"] : [])
    });
  }

  const devices = Array.from(byMac.values());

  report("webprobe", { note: "checking each device for an admin web page", count: devices.length });
  await Promise.all(devices.map(async (d) => { d.web = await webProbe(d.ip); }));

  for (const d of devices) {
    const match = matchKnown(d, gatewayIp);
    const k = match && match.entry;

    // An HTTP error page's title ("401 Unauthorized") is real data - kept in
    // d.web.title - but it identifies the response, not the device, so it's
    // not useful as a display name.
    const usableTitle = d.web && d.web.title && !/unauthorized|forbidden|not found|bad request|error \d{3}/i.test(d.web.title)
      ? d.web.title : null;

    // Name priority: DHCP hostname, mDNS name, a confirmed/matched config
    // name, the page's own <title>, OUI vendor, then honestly "Unidentified".
    d.name = (d.lease && d.lease.hostname) || (d.mdnsHit && d.mdnsHit.name) || (k && k.name)
      || usableTitle || d.vendor || "Unidentified host";
    d.vendor = (k && k.vendor) || d.vendor;
    d.type = (k && k.role) || (d.ssdpHit && d.ssdpHit.st) || null;
    d.model = (k && k.model && k.model !== "unknown") ? k.model : null;
    d.control = k ? k.control : "none";
    d.endOfSupport = (k && k.endOfSupport) || null;
    d.matchedBy = match ? match.how : null;
    d.estimated = !k; // unmatched identity beyond OUI vendor / web title is unconfirmed
    d.firmware = null;
    d.firmwareLatest = null;
    d.firmwareSource = d.control === "none" ? "no API" : null;

    delete d.lease; delete d.mdnsHit; delete d.ssdpHit;
  }

  // No per-node client table exists until phase 3 gives TP-Link control, so
  // there is no real way to know which extender a client sits behind.
  // Everything hangs off the detected gateway by default - always an
  // estimate - except the gateway itself, which is the tree's root.
  const gatewayDevice = devices.find(d => d.ip === gatewayIp);
  for (const d of devices) {
    d.parentMac = (gatewayDevice && d.mac !== gatewayDevice.mac) ? gatewayDevice.mac : null;
    d.parentEstimated = true;
  }

  report("done", { found: devices.length });
  return devices;
}

// Tree: gateway at the root, everything else hanging off a parent.
// No per-node client table exists until phase 3 gives TP-Link control, so
// every parent link here is a default guess (everyone behind the gateway)
// and always marked as an estimate. The gateway itself is identified by its
// role, which run() only ever assigns from the OS's own default-gateway IP.
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

// --- config drift ------------------------------------------------------

// The only fact config/devices.json asserts about an address is a
// user-confirmed one (`confirmed.ip`) - see matchKnown() above for how
// sparingly those get used. If that address stops answering, say so instead
// of quietly losing the label; don't try to guess where it went; that's how
// the Pi-hole's old (wrong) .2 entry went unnoticed for as long as it did.
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

module.exports = { run, topology, detectDrift, webProbe, defaultGateway, pingSweep, arpTable };
