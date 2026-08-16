// Run discovery from the terminal without launching the app:
//   npm run test:discovery
//
// Compare the output against the devices you know are on your network. If
// something is missing, that is the bug to chase before building anything else.

const path = require("path");

// discovery.js pulls in electron indirectly through nothing, but db.js does -
// so require discovery directly and never touch the database here.
const discovery = require(path.join(__dirname, "..", "src", "main", "discovery.js"));

(async () => {
  console.log("Scanning 192.168.1.0/24 ...\n");
  const started = Date.now();

  const devices = await discovery.run({
    onProgress: (stage, detail) => {
      if (stage === "ping" && detail.probed % 64 !== 0) return;
      console.log("  [" + stage + "] " + JSON.stringify(detail));
    }
  });

  console.log("\nFound " + devices.length + " devices in " + ((Date.now() - started) / 1000).toFixed(1) + "s\n");

  const pad = (s, n) => String(s == null ? "-" : s).padEnd(n).slice(0, n);
  console.log(pad("IP", 16) + pad("NAME", 24) + pad("VENDOR", 22) + pad("ROLE", 14) + pad("MATCHED BY", 24) + pad("WEB", 8) + "VIA");
  console.log("-".repeat(130));
  const sorted = devices.sort((a, b) => {
    const na = Number(String(a.ip).split(".")[3] || 0);
    const nb = Number(String(b.ip).split(".")[3] || 0);
    return na - nb;
  });
  for (const d of sorted) {
    const web = d.web && d.web.reachable ? (d.web.hasLoginForm ? "login" : "yes") : "-";
    console.log(
      pad(d.ip, 16) + pad(d.name, 24) + pad(d.vendor, 22) + pad(d.type, 14) +
      pad(d.matchedBy || (d.estimated ? "unconfirmed" : "-"), 24) + pad(web, 8) + (d.methods || []).join(",")
    );
  }

  const unmatched = sorted.filter(d => d.estimated && d.vendor);
  if (unmatched.length) {
    console.log("\n" + unmatched.length + " device(s) found but not confidently identified beyond OUI vendor / web title:");
    for (const d of unmatched) console.log("  " + d.ip + "  " + d.vendor + (d.web && d.web.title ? "  (\"" + d.web.title + "\")" : ""));
    console.log("These are real devices - visit each one's own admin page to tell them apart, or check its label.");
  }

  const drift = discovery.detectDrift(devices);
  if (drift.length) {
    console.log("\nPossible config/devices.json drift:");
    for (const w of drift) console.log("  [estimate] " + w.detail);
  }

  console.log("\nconfig/devices.json only asserts what's user-confirmed or self-evident (the OS's own");
  console.log("default-gateway route, a device's own web UI title) - it does not assume which IP any");
  console.log("device is at. The unmanaged switch has no IP and will never appear here.");
})().catch(e => { console.error(e); process.exit(1); });
