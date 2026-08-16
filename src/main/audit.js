// Security audit.
//
// Rules, in order of usefulness:
//   1. Firmware behind the latest release (needs a vendor feed)
//   2. Firmware past end of support - the TL-WDR4300 is one
//   3. Risky open ports - see config/devices.json riskyPorts
//   4. Unidentified device: no vendor match AND no DHCP hostname
//   5. Router config: WPS on, UPnP on, WAN remote management, admin over HTTP
//   6. Single point of DNS failure: everything resolves through the Pi
//
// Two absolute rules:
//   - Never invent a CVE. Real reference or "unverifiable".
//   - Anything inferred is labelled an estimate in the output.

const config = require("../../config/devices.json");
const oui = require("./oui");

const SEVERITY_WEIGHT = { critical: 18, high: 10, medium: 5, low: 2 };

// discovery.js's matchKnown() already resolves this onto the device record
// at scan time (config/devices.json has no per-device IP to look up by).
function endOfSupport(device) {
  return device.end_of_support || device.endOfSupport || null;
}

function run(devices) {
  const findings = [];

  for (const d of devices) {
    const eos = endOfSupport(d);
    if (eos) {
      findings.push({
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
        mac: d.mac, device: d.name, ip: d.ip,
        severity: "high",
        title: d.name + " firmware is behind",
        detail: "Running " + d.firmware + ", latest is " + d.firmware_latest + ".",
        reference: "unverifiable until the release notes are checked",
        action: "Update firmware",
        estimated: false
      });
    }

    const noVendor = !d.vendor || !oui.vendor(d.mac);
    const noHostname = !d.name || d.name === "Unidentified host";
    if (noVendor && noHostname) {
      findings.push({
        mac: d.mac, device: d.name || "Unidentified host", ip: d.ip,
        severity: "critical",
        title: "Unrecognised host on the network",
        detail: "No vendor prefix match and no DHCP hostname" + (oui.isRandomised(d.mac) ? ", and the MAC is randomised" : "") + ".",
        reference: "unclassified",
        action: "Identify it, or block its internet access",
        estimated: false
      });
    }

    if (d.estimated) {
      findings.push({
        mac: d.mac, device: d.name, ip: d.ip,
        severity: "medium",
        title: d.name + " reports no firmware version",
        detail: "No management API, no version banner and no vendor feed. Firmware age cannot be established.",
        reference: "unverifiable",
        action: "Record the version manually from the device itself",
        estimated: true
      });
    }
  }

  // TODO phase 4: port scanning against config.riskyPorts,
  // router configuration checks, and the DNS single-point-of-failure check.

  const penalty = findings.reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] || 0), 0);
  const score = Math.max(0, 100 - penalty);

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  return { score, counts, findings, ranAt: Date.now() };
}

module.exports = { run };
