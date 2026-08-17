// Lightweight round-trip latency sampling to the gateway and (if present)
// the Pi — not a full speed test, just enough to catch a degrading
// extender/AP before it fully drops.
const ping = require("ping");
const db = require("./db");
const discovery = require("./discovery");

async function sampleOnce() {
  const targets = [];
  const gatewayIp = await discovery.defaultGateway();
  if (gatewayIp) targets.push({ label: "gateway", ip: gatewayIp });
  const piState = db.getPiState();
  if (piState.ip) targets.push({ label: "pi", ip: piState.ip });

  for (const t of targets) {
    try {
      const r = await ping.promise.probe(t.ip, { timeout: 2 });
      db.recordLatency(t.label, r.alive ? Math.round(Number(r.time)) : null);
    } catch (e) { /* skip this sample */ }
  }
}

module.exports = { sampleOnce };
