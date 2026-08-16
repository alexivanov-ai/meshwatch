// TCP connect scan of known-risky ports on this machine's private /24.
// UDP 7000: GREE local API probe (own LAN only). UDP 1900 is inferred
// from SSDP responses already collected during discovery — we do not
// blast SSDP here.
const net = require("net");
const dgram = require("dgram");
const config = require("../../config/devices.json");
const { isPrivateIp } = require("./lanhttp");

const TCP_TIMEOUT = 450;
const CONCURRENCY = 24;

function tcpOpen(ip, port, timeoutMs = TCP_TIMEOUT) {
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

function greeUdp(ip, timeoutMs = 900) {
  return new Promise((resolve) => {
    const socket = dgram.createSocket("udp4");
    let settled = false;
    const done = (hit) => {
      if (settled) return;
      settled = true;
      try { socket.close(); } catch (e) { /* ignore */ }
      resolve(hit);
    };
    const t = setTimeout(() => done(false), timeoutMs);
    socket.on("message", () => {
      clearTimeout(t);
      done(true);
    });
    socket.on("error", () => {
      clearTimeout(t);
      done(false);
    });
    try {
      const msg = Buffer.from(JSON.stringify({ t: "scan" }));
      socket.send(msg, 7000, ip);
    } catch (e) {
      clearTimeout(t);
      done(false);
    }
  });
}

function riskyList() {
  return (config.riskyPorts || []).filter((p) => p && p.port);
}

async function scanHost(ip, { methods } = {}) {
  if (!isPrivateIp(ip)) return [];
  const found = [];
  const tcp = riskyList().filter((p) => p.proto === "tcp");
  for (let i = 0; i < tcp.length; i += CONCURRENCY) {
    const batch = tcp.slice(i, i + CONCURRENCY);
    const results = await Promise.all(batch.map(async (p) => {
      const open = await tcpOpen(ip, p.port);
      return open ? p : null;
    }));
    for (const p of results) if (p) found.push(Object.assign({ open: true }, p));
  }

  const hasSsdp = Array.isArray(methods) && methods.indexOf("ssdp") !== -1;
  if (hasSsdp) {
    const upnp = riskyList().find((p) => p.port === 1900);
    if (upnp) found.push(Object.assign({ open: true, inferred: true }, upnp));
  }

  const gree = riskyList().find((p) => p.port === 7000 && p.proto === "udp");
  if (gree) {
    const hit = await greeUdp(ip);
    if (hit) found.push(Object.assign({ open: true }, gree));
  }
  return found;
}

async function scanDevices(devices, onProgress) {
  const out = {};
  let done = 0;
  const list = (devices || []).filter((d) => d && d.ip);
  for (let i = 0; i < list.length; i += CONCURRENCY) {
    const batch = list.slice(i, i + CONCURRENCY);
    const results = await Promise.all(batch.map(async (d) => {
      const ports = await scanHost(d.ip, { methods: d.methods });
      return { mac: d.mac, ip: d.ip, ports };
    }));
    for (const r of results) {
      out[r.mac] = r.ports;
      done++;
      if (onProgress) onProgress({ probed: done, total: list.length, ip: r.ip, open: r.ports.length });
    }
  }
  return out;
}

module.exports = { scanHost, scanDevices, tcpOpen, riskyList };
