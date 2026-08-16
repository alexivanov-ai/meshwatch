// Security audit. Never invent a CVE. Inferred values are labelled estimates.
const oui = require("./oui");
const db = require("./db");
const ports = require("./ports");
const tplink = require("./tplink");
const credentials = require("./credentials");

const SEVERITY_WEIGHT = { critical: 18, high: 10, medium: 5, low: 2 };

function findingKey(rule, mac) {
  return rule + ":" + String(mac || "").toLowerCase();
}

function endOfSupport(device) {
  return device.end_of_support || device.endOfSupport || null;
}

function openPortsOf(d) {
  if (Array.isArray(d.openPorts) && d.openPorts.length) return d.openPorts;
  if (d.open_ports) {
    try { return JSON.parse(d.open_ports); } catch (e) { return []; }
  }
  return [];
}

function collect(devices, extras) {
  const findings = [];
  const extra = extras || {};
  const list = devices || [];
  const dnsNodes = list.filter((d) => d.type === "dns-dhcp" || d.control === "ssh");

  for (const d of list) {
    const eos = endOfSupport(d);
    if (eos) {
      findings.push({
        key: findingKey("eos", d.mac),
        rule: "eos",
        mac: d.mac, device: d.name, ip: d.ip,
        severity: "critical",
        title: d.name + " is past end of support",
        detail: "The vendor stopped issuing firmware in " + eos + ". No future fix will arrive for any flaw found in it.",
        reference: "unverifiable - check the vendor advisory archive",
        action: "Retire or replace this device",
        estimated: false
      });
    }

    if (d.firmware && d.firmware_latest && d.firmware !== d.firmware_latest) {
      findings.push({
        key: findingKey("firmware-behind", d.mac),
        rule: "firmware-behind",
        mac: d.mac, device: d.name, ip: d.ip,
        severity: "high",
        title: d.name + " firmware is behind",
        detail: "Running " + d.firmware + ", latest reported by the device is " + d.firmware_latest + ".",
        reference: "unverifiable until the release notes are checked",
        action: "Update firmware",
        estimated: false
      });
    }

    const noVendor = !d.vendor || !oui.vendor(d.mac);
    const noHostname = !d.name || d.name === "Unidentified host";
    if (noVendor && noHostname) {
      findings.push({
        key: findingKey("unrecognised", d.mac),
        rule: "unrecognised",
        mac: d.mac, device: d.name || "Unidentified host", ip: d.ip,
        severity: "critical",
        title: "Unrecognised host on the network",
        detail: "No vendor prefix match and no DHCP hostname" + (oui.isRandomised(d.mac) ? ", and the MAC is randomised" : "") + ".",
        reference: "unclassified",
        action: "Identify it, or block its internet access",
        estimated: false
      });
    }

    if (d.estimated && !d.firmware && !d.firmware_manual) {
      findings.push({
        key: findingKey("no-firmware", d.mac),
        rule: "no-firmware",
        mac: d.mac, device: d.name, ip: d.ip,
        severity: "medium",
        title: d.name + " reports no firmware version",
        detail: "No management API, no version banner and no vendor feed. Firmware age cannot be established.",
        reference: "unverifiable",
        action: "Record the version manually from the device itself, or dismiss if you accept the gap",
        estimated: true
      });
    }

    if (d.web_reachable && d.web_login_form) {
      findings.push({
        key: findingKey("http-admin", d.mac),
        rule: "http-admin",
        mac: d.mac, device: d.name, ip: d.ip,
        severity: "medium",
        title: d.name + " serves its admin page over plain HTTP",
        detail: "Anyone on the LAN who can watch traffic can see the login. Prefer HTTPS if the device offers it.",
        reference: "local exposure",
        action: "Open device",
        estimated: false
      });
    }

    for (const p of openPortsOf(d)) {
      if (p.port === 80 && d.web_login_form) continue;
      findings.push({
        key: findingKey("port-" + p.port, d.mac),
        rule: "open-port",
        mac: d.mac, device: d.name, ip: d.ip,
        severity: p.severity || "medium",
        title: d.name + " has " + (p.label || ("port " + p.port)) + " open",
        detail: (p.proto || "tcp").toUpperCase() + " " + p.port +
          (p.inferred ? " (inferred from SSDP — not a fresh probe)" : " answered a connect from this PC.") +
          (p.port === 7000 ? " The GREE local API accepts commands with no key." : ""),
        reference: p.port === 7000 ? "local exposure" : "local scan",
        action: p.port === 7000 || p.port === 23 ? "Block internet access" : "Open device",
        estimated: !!p.inferred
      });
    }
  }

  if (dnsNodes.length === 1) {
    const d = dnsNodes[0];
    findings.push({
      key: findingKey("dns-spof", d.mac),
      rule: "dns-spof",
      mac: d.mac, device: d.name, ip: d.ip,
      severity: "high",
      title: "Pi-hole is your single point of DNS failure",
      detail: "Every lookup on the network resolves through " + (d.ip || "the Pi") + ", and no secondary DNS is advertised. If it reboots, the whole network loses name resolution.",
      reference: "availability",
      action: "Set fallback DNS",
      estimated: false
    });
  }

  const flags = extra.routerFlags || {};
  const gw = list.find((d) => d.type === "gateway") || null;
  if (gw && flags.ok) {
    if (flags.flags && flags.flags.wps) {
      findings.push({
        key: findingKey("wps", gw.mac),
        rule: "wps",
        mac: gw.mac, device: gw.name, ip: gw.ip,
        severity: "high",
        title: "WPS is enabled on the gateway",
        detail: "WPS PINs are brute-forceable. Turn it off in the router admin page unless you are using it right now.",
        reference: "local config",
        action: "Open device",
        estimated: false
      });
    }
    if (flags.flags && flags.flags.upnp) {
      findings.push({
        key: findingKey("upnp-wan", gw.mac),
        rule: "upnp",
        mac: gw.mac, device: gw.name, ip: gw.ip,
        severity: "medium",
        title: "UPnP is enabled on the gateway",
        detail: "Devices on the LAN can open inbound ports without asking you. Handy for consoles, noisy for everything else.",
        reference: "local config",
        action: "Open device",
        estimated: false
      });
    }
    if (flags.flags && flags.flags.remote) {
      findings.push({
        key: findingKey("wan-remote", gw.mac),
        rule: "remote",
        mac: gw.mac, device: gw.name, ip: gw.ip,
        severity: "critical",
        title: "Remote management is exposed on the WAN",
        detail: "The gateway admin page is reachable from the internet. Turn this off unless you have a specific, firewalled reason.",
        reference: "local config",
        action: "Open device",
        estimated: false
      });
    }
    for (const item of (flags.flags && flags.flags.unverifiable) || []) {
      findings.push({
        key: findingKey("cfg-" + item, gw.mac),
        rule: "unverifiable-config",
        mac: gw.mac, device: gw.name, ip: gw.ip,
        severity: "low",
        title: item + " could not be checked",
        detail: "The router did not expose this setting on the local API. Open the admin page and look it up yourself.",
        reference: "unverifiable",
        action: "Open device",
        estimated: true
      });
    }
  } else if (gw && gw.control === "tplink" && !credentials.has(gw.mac)) {
    findings.push({
      key: findingKey("router-unread", gw.mac),
      rule: "router-unread",
      mac: gw.mac, device: gw.name, ip: gw.ip,
      severity: "low",
      title: "Gateway config (WPS, UPnP, remote admin) not read",
      detail: "Save the gateway admin password in the credential vault so Meshwatch can check these without inventing an answer.",
      reference: "unverifiable",
      action: "Open device",
      estimated: true
    });
  }

  return findings;
}

function scoreFindings(findings) {
  const penalty = findings.reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] || 0), 0);
  const score = Math.max(0, 100 - penalty);
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  return { score, counts };
}

async function gatherExtras(devices) {
  const gw = (devices || []).find((d) => d.type === "gateway");
  let routerFlags = { ok: false };
  if (gw && gw.control === "tplink" && credentials.has(gw.mac)) {
    try { routerFlags = await tplink.routerConfigFlags(gw); } catch (e) { routerFlags = { ok: false }; }
  }
  return { routerFlags };
}

function packageResult(all) {
  const dismissed = new Set(db.listDismissedFindingKeys());
  const findings = [];
  const dismissedFindings = [];
  for (const f of all) {
    if (dismissed.has(f.key)) dismissedFindings.push(Object.assign({}, f, { dismissed: true }));
    else findings.push(Object.assign({}, f, { dismissed: false }));
  }
  const { score, counts } = scoreFindings(findings);
  return {
    score,
    counts,
    findings,
    dismissedFindings,
    dismissedCount: dismissedFindings.length,
    ranAt: Date.now()
  };
}

async function run(devices, opts) {
  const list = devices || db.listDevices();
  const prefs = db.getPrefs();
  const wantPorts = !opts || opts.scanPorts !== false;
  if (wantPorts) {
    const scanned = await ports.scanDevices(list);
    for (const d of list) {
      const found = scanned[d.mac] || [];
      d.openPorts = found;
      db.setOpenPorts(d.mac, found);
    }
    db.setSetting("last_port_scan", String(Date.now()));
  }
  const extras = await gatherExtras(list);
  const result = packageResult(collect(list, extras));
  db.recordAuditRun(result.score, result.counts);
  return result;
}

function dismiss(key) {
  if (!key || typeof key !== "string") return { ok: false, reason: "Missing finding key" };
  db.dismissFinding(key);
  return { ok: true, audit: packageResult(collect(db.listDevices(), {})) };
}

function restore(key) {
  if (!key || typeof key !== "string") return { ok: false, reason: "Missing finding key" };
  db.restoreFinding(key);
  return { ok: true, audit: packageResult(collect(db.listDevices(), {})) };
}

module.exports = { run, dismiss, restore, findingKey, collect };
