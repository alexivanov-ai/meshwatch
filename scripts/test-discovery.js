// Run discovery from the terminal without launching the app:
//   npm run test:discovery
//
// Compare the output against the devices you know are on your network. If
// something is missing, that is the bug to chase before building anything else.

const path = require("path");

const discovery = require(path.join(__dirname, "..", "src", "main", "discovery.js"));

(async () => {
  const net = discovery.detectSubnet();
  console.log("Scanning " + net.cidr + (net.localIp ? " from " + net.localIp : "") + (net.iface ? " (" + net.iface + ")" : "") + " ...\n");
  const started = Date.now();

  const devices = await discovery.run({
    onProgress: (stage, detail) => {
      if (stage === "ping" && detail.probed % 64 !== 0) return;
      console.log("  [" + stage + "] " + JSON.stringify(detail));
    }
  });

  console.log("\nFound " + devices.length + " devices in " + ((Date.now() - started) / 1000).toFixed(1) + "s\n");

  const pad = (s, n) => String(s == null ? "-" : s).padEnd(n).slice(0, n);
  console.log(pad("IP", 16) + pad("NAME", 28) + pad("VENDOR", 22) + pad("ROLE", 14) + pad("MATCHED BY", 28) + pad("WEB", 8) + "VIA");
  console.log("-".repeat(140));
  const sorted = devices.sort((a, b) => {
    const na = Number(String(a.ip).split(".")[3] || 0);
    const nb = Number(String(b.ip).split(".")[3] || 0);
    return na - nb;
  });
  for (const d of sorted) {
    const web = d.web && d.web.reachable ? (d.web.hasLoginForm ? "login" : "yes") : "-";
    console.log(
      pad(d.ip, 16) + pad(d.name, 28) + pad(d.vendor, 22) + pad(d.type, 14) +
      pad(d.matchedBy || (d.estimated ? "unconfirmed" : "-"), 28) + pad(web, 8) + (d.methods || []).join(",")
    );
  }

  const unmatched = sorted.filter(d => d.estimated);
  if (unmatched.length) {
    console.log("\n" + unmatched.length + " device(s) found but not confidently identified:");
    for (const d of unmatched) {
      const extra = [
        d.web && d.web.title ? 'web="' + d.web.title + '"' : null,
        d.snmp && d.snmp.sysName ? 'snmp=' + d.snmp.sysName : null
      ].filter(Boolean).join(" ");
      console.log("  " + d.ip + "  " + (d.name || "-") + "  " + (d.vendor || "-") + (extra ? "  (" + extra + ")" : ""));
    }
  }

  const drift = discovery.detectDrift(devices);
  if (drift.length) {
    console.log("\nPossible config/devices.json drift:");
    for (const w of drift) console.log("  [estimate] " + w.detail);
  }
})().catch(e => { console.error(e); process.exit(1); });
