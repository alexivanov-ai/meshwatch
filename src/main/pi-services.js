// src/main/pi-services.js — generic detection of self-hosted services
// running on the Pi: list its listening ports over SSH, probe each with a
// plain GET (same rule as discovery.js's webProbe: read the title, never
// guess a login), match against a small catalog for a friendly name.
// Anything unmatched still shows up — never hidden, never invented (Hard
// Rule 4). The catalog is illustrative, not authoritative: a real, observed
// title always wins over an assumption.
const pi = require("./pi");
const db = require("./db");
const lan = require("./lanhttp");

const KNOWN_SERVICES = [
  { port: 32400, name: "Plex", category: "media" },
  { port: 8080, titleRe: /qbittorrent/i, name: "qBittorrent", category: "downloads" },
  { port: 9091, titleRe: /transmission/i, name: "Transmission", category: "downloads" },
  { port: 8112, name: "Deluge", category: "downloads" },
  { port: 9000, titleRe: /portainer/i, name: "Portainer", category: "management" },
  { port: 8123, titleRe: /home assistant/i, name: "Home Assistant", category: "home-automation" },
  { port: 8989, titleRe: /sonarr/i, name: "Sonarr", category: "media" },
  { port: 7878, titleRe: /radarr/i, name: "Radarr", category: "media" },
  { port: 6767, titleRe: /bazarr/i, name: "Bazarr", category: "media" },
  { port: 8096, titleRe: /jellyfin/i, name: "Jellyfin", category: "media" },
  { port: 3000, titleRe: /grafana/i, name: "Grafana", category: "monitoring" },
  { port: 8384, titleRe: /syncthing/i, name: "Syncthing", category: "sync" },
  { port: 3001, titleRe: /uptime kuma/i, name: "Uptime Kuma", category: "monitoring" }
];

// Match by port first (optionally confirmed by title when the catalog entry
// specifies one), then fall back to a title-only match (a service moved off
// its default port but still self-identifies). No match at all is expected
// and fine — the caller labels it "Unknown service" rather than guessing.
function matchCatalog(port, title) {
  const hit = KNOWN_SERVICES.find((k) =>
    k.port === port && (!k.titleRe || (title && k.titleRe.test(title)))
  ) || KNOWN_SERVICES.find((k) => k.titleRe && title && k.titleRe.test(title));
  return hit || null;
}

// `ss -tln` (State, Recv-Q, Send-Q, Local Address:Port, Peer Address:Port)
// puts the LISTEN state *before* the local address; `netstat -tln` (the
// fallback where `ss` is missing) puts it *after*, as the last column. To
// handle both column orders without depending on which one ran, scan each
// LISTEN line's whitespace-separated tokens for the first one shaped like
// host:port with a numeric port (works for "0.0.0.0:22", "[::]:8080", and
// netstat's IPv6 ":::8080" alike) — that's always the local address, since
// a listening socket's peer column is "*", never a number.
async function listListeningPorts() {
  const r = await pi.exec("ss -tln 2>/dev/null || netstat -tln 2>/dev/null");
  if (r.code) return [];
  const ports = new Set();
  for (const line of r.output || []) {
    if (!/\bLISTEN\b/.test(line)) continue;
    for (const tok of line.trim().split(/\s+/)) {
      const m = tok.match(/^\[?[0-9a-fA-F:.]+\]?:(\d{1,5})$/);
      if (m) { ports.add(Number(m[1])); break; }
    }
  }
  return Array.from(ports);
}

async function probeTitle(host, port) {
  try {
    const r = await lan.request({ url: "http://" + host + ":" + port + "/", timeoutMs: 3000 });
    const m = r && r.text && r.text.match(/<title[^>]*>([^<]*)<\/title>/i);
    return m ? m[1].trim() : null;
  } catch (e) { return null; }
}

// Ports already accounted for elsewhere in the app — never listed as an
// "unknown service".
// 80/443 are excluded as the usual home of a web admin UI — the DNS backend's
// own panel is already in the Pi tab header, and neither port ever identifies
// a self-hosted service worth listing separately. (AdGuard Home's setup wizard
// defaults its admin UI to port 3000, not 80/443; 3000 is deliberately NOT
// excluded, since the catalog above also maps it to Grafana and a real
// observed page title is what tells them apart.)
async function excludedPorts() {
  const t = pi.resolveTarget();
  return new Set([t.port, 22, 53, 80, 443]); // configured SSH port, default SSH, DNS, web admin
}

async function discoverServices() {
  const t = pi.resolveTarget();
  if (!t.host) return [];
  const [ports, skip] = await Promise.all([listListeningPorts(), excludedPorts()]);
  const candidates = ports.filter((p) => !skip.has(p));
  const results = [];
  await Promise.all(candidates.map(async (port) => {
    const title = await probeTitle(t.host, port);
    const known = matchCatalog(port, title);
    results.push({
      port,
      name: known ? known.name : "Unknown service",
      category: known ? known.category : "unknown",
      title: title || null,
      url: "http://" + t.host + ":" + port + "/"
    });
  }));
  results.sort((a, b) => a.port - b.port);
  if (t.mac) db.saveServices(t.mac, results);
  return results;
}

function cachedServices() {
  const t = pi.resolveTarget();
  if (!t.mac) return [];
  return db.getServices(t.mac).map((s) => Object.assign({}, s, { url: "http://" + t.host + ":" + s.port + "/" }));
}

module.exports = { discoverServices, cachedServices, matchCatalog, KNOWN_SERVICES };
