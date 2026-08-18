# Meshwatch

Guidance for Claude Code working in this repo.

## What this repo is

A local network monitoring desktop app: Electron, plain HTML/CSS/JS in the
renderer, no build step, no framework. It discovers whatever is on the
host's own private LAN, tracks it over time in SQLite, audits it for
security findings, and — where the LAN runs a DNS/DHCP box (a Raspberry Pi
running Pi-hole or AdGuard Home, most commonly) — gives it its own tab:
live stats, DHCP leases, an embedded SSH terminal, package updates, and
auto-detected self-hosted services.

Canonical docs — read these, don't duplicate their content here:

- [`docs/HLD.md`](docs/HLD.md) — process model, subsystem boundaries, data
  flow end to end, and the reasoning behind every hard rule below.
- [`docs/LLD.md`](docs/LLD.md) — the complete SQLite schema, the full IPC
  channel catalog, the DNS-backend adapter contract, the Pi terminal
  protocol, and the service-detection catalog format.
- [`README.md`](README.md) — the human-facing entry point: features,
  privacy posture, install/build instructions.
- [`CHANGELOG.md`](CHANGELOG.md) — add a line under `## [Unreleased]` for
  any user-facing change (new feature, fixed bug, changed behavior); skip
  it for pure internal refactors with no visible effect.

The person you're working with is not a developer. They can copy/paste a
command and read its output, but not debug JavaScript or read a stack
trace. Explain what you're doing only when they need to act or decide
something. Never leave the app in a broken state at the end of a work
session.

## Hard rules

These hold across every change. Break them only with explicit user
authorization in the same conversation turn.

1. `contextIsolation: true`, `nodeIntegration: false`. All privileged work
   happens in the main process and crosses to the renderer through the
   narrow API in `src/preload.js`. Never widen it to expose `ipcRenderer`
   directly. Device admin pages open in the in-app Chromium view
   (`src/main/browser.js`), never as a system browser tab. That view only
   loads private LAN URLs.
2. Credentials (router passwords, DNS backend API token, SSH key path, any
   device login saved via the credential vault) go through OS-backed
   encryption (Electron `safeStorage` — see "Credential vault" below),
   never a plain file in this repo. `config/devices.json` holds models and
   roles, plus the rare explicitly user-confirmed address — see
   "`config/devices.json` is a hint, not ground truth" below.
3. Never invent a CVE, a firmware version, or a vendor advisory. If
   something cannot be verified, label it `unverifiable` and say why.
4. Inferred values must be visibly marked as estimates in the UI. Many
   consumer devices (unmanaged switches, APs, smart-home gear) have no API
   at all — a wrong confident answer is worse than an honest gap.
5. Any action that interrupts connectivity — rebooting a router, restarting
   the DNS backend service, rebooting the Pi — requires explicit
   confirmation and must warn how long the network will be down.
6. Only ever scan this machine's local private `/24` (detected at runtime).
   No scanning of external hosts or other subnets.

## Discovery scope

Scan boundary is detected at runtime from the OS network interface
(`os.networkInterfaces()` → the host's private IPv4 `/24`). Never hardcode
a subnet in discovery — the same build must work on any LAN. Hard rule 6
still requires an explicit boundary; that boundary is whatever `/24` this
PC is on.

Whichever DNS/DHCP backend is running on the discovered Pi (Pi-hole or
AdGuard Home, auto-detected — see `src/main/dns/`) is the authoritative
source of device hostnames when it's also acting as DHCP server. Always
prefer a DHCP hostname over an mDNS name or an OUI vendor guess. Never put
the OUI vendor string in the Name column — that belongs in Vendor.

## `config/devices.json` is a hint, not ground truth

Early on, `config/devices.json` had a specific IP hardcoded for every
device in its `known` list — most of them never confirmed by the user,
just assumed sequentially (`.3`, `.4`, `.5`...). One was wrong, and it went
unnoticed because nothing was re-deriving it from a live scan; another
device on that network got mislabelled with a fabricated model name as a
direct result. Don't repeat this. The rule now:

- `config/devices.json`'s `known` list may name a **model, vendor and
  role** the user has told us about. It must never assert an **IP** unless
  it's under a `confirmed: { ip, source }` key — meaning the user
  explicitly stated it, not something extrapolated from a pattern or a
  default convention.
- `discovery.js`'s `matchKnown()` is the only place a discovered device
  gets labelled with one of these entries, and only on evidence that is
  itself discovered: an exact `confirmed.ip` match, the OS's own
  default-gateway route (for the `gateway` role), or the device naming its
  model in a web `<title>` or SNMP sysName/sysDescr. Vendor-only matching
  is deliberately not enough to assign a specific model — several known
  devices can share a single vendor, with no way to tell them apart from
  ARP/mDNS/SSDP alone.
- A device that doesn't match any of those stays labelled by DHCP hostname
  / mDNS / SNMP sysName / web title / model, with `estimated: true` — never
  silently assigned a guessed identity, and never named after the OUI
  vendor.
- The scan is expected to surface devices that aren't in this file at all.
  That's not a bug to fix by adding them to config; it's the discovery
  engine doing its job.

## Web probe

Part of every scan (`discovery.js`'s `webProbe()`): a plain GET on port 80
for each discovered IP, never a login attempt. Records whether something
answers, its `<title>` (routers/printers/cameras routinely self-identify
there, unauthenticated) and whether the page looks like a login form. This
is real, observed data — it feeds both device naming (see above) and the
"does this have a login page" signal for the credential vault below.

## SNMP probe

Also part of every scan: an unauthenticated SNMPv2c GET for
`sysName`/`sysDescr` (community `public` only). Managed switches often
answer here when the web title is generic. No write community, no
credential guessing.

## Credential vault

Local password storage for any discovered device with a login page, keyed
by MAC (`src/main/credentials.js` + `db.js`'s `credentials` table).
Encryption is Electron's `safeStorage` — OS-backed (DPAPI on Windows), no
separate master password, no third-party native dependency. Only encrypted
bytes ever touch disk; the plaintext password is decrypted in the main
process only, at the moment of scripting a form-fill, and is never sent to
the renderer as a bare IPC return value. The renderer only ever sees
label/username/when-saved metadata for its search UI. Auto-fill into an
embedded device admin page needs the in-app browser's own `<webview>` to
fill into; the vault itself is usable independently of that via IPC
(`credentials:save/list/has/remove`).

## Discovery approach, and why

The scaffold uses an unprivileged ICMP ping sweep followed by a read of the
OS ARP table (`arp -a`). This works without Npcap and without
administrator rights, and finds most hosts. Raw ARP via Npcap finds more —
devices that ignore ping — so treat it as an upgrade, not the starting
point. If you add it, keep the ping+ARP path as a fallback so the app
still works unprivileged.

## Where things live

```text
src/main/index.js       Electron entry, window, IPC handlers
src/main/db.js          SQLite: devices (incl. tags), sightings, findings, credentials,
                         settings, Pi services, audit history, latency samples, DNS talker history
src/main/discovery.js   Ping/ARP, mDNS, SSDP, SNMP, subnet+gateway, web probe, merge
src/main/oui.js         MAC prefix to vendor lookup (src/main/oui-data.json)
src/main/pi.js          Generic Pi system admin: SSH exec, target resolution, disruptive-command gating
src/main/dns/index.js   Detects which DNS/DHCP backend runs on the Pi, caches it, routes calls to the adapter
src/main/dns/ftl.js     REST adapter for the Pi-hole (FTL) backend
src/main/dns/adguard.js REST adapter for the AdGuard Home backend
src/main/pi-services.js Generic self-hosted service detection on the Pi (open ports + title probe + small catalog)
src/main/wol.js         Wake-on-LAN magic packet
src/main/latency.js     Periodic round-trip latency sampling to the gateway and Pi
src/main/lanhttp.js     Shared HTTP(S) client restricted to private LAN hosts
src/main/ports.js       TCP/UDP connect scan of known-risky ports on the local /24 (security audit)
src/main/tplink.js      TP-Link control. Mostly unimplemented by design
src/main/audit.js       Security findings and scoring
src/main/credentials.js Local credential vault (safeStorage-encrypted, keyed by MAC)
src/main/updater.js     In-app updates from GitHub Releases (installed builds only)
src/main/browser.js     In-app Chromium (WebContentsView) for device admin pages
src/preload.js          The only bridge to the renderer
src/renderer/           Renderer UI (HTML, CSS, JS) — no framework, no build step
config/devices.json     Known models/roles — see "config/devices.json is a hint" above
scripts/test-discovery.js  Run discovery from the terminal, print results
scripts/build-oui.js    Regenerate oui-data.json from the IEEE registry (offline)
```

See `docs/LLD.md` §1 for the full schema those tables back, §2 for the
complete IPC catalog `index.js`/`preload.js` implement, and §3–§5 for the
DNS adapter, terminal, and service-catalog contracts.

Local planning notes for multi-step work live under `docs/superpowers/` —
gitignored, never committed, safe to read or write freely.

## When to ask before acting

Beyond Hard Rule 5 (disruptive network actions) and Hard Rule 2
(credentials):

- Adding a new runtime dependency. This app is deliberately
  dependency-light — no UI framework, no build step for the renderer —
  reach for a platform or Node API first, and check with the user before
  adding a package.
- Changing anything under the `build` key in `package.json` or the
  `scripts/` build helpers (`ensure-electron.js`, `make-icon.js`) — it
  affects what actually gets installed on a real machine via the packaged
  installer.

You can freely, without asking:

- Read or edit any file, run `npm start` to launch the app, run
  `node scripts/test-discovery.js` to exercise discovery from the terminal
  without opening the UI.
- Add a new adapter under `src/main/dns/` or a new catalog entry in
  `src/main/pi-services.js` — both are designed to grow this way.

## Key docs to read on first contact

1. `docs/HLD.md` — architecture: process model, subsystem boundaries, data
   flow.
2. `docs/LLD.md` — module-level detail: schema, IPC catalog, adapter
   contracts.
3. This file — hard rules and behavioral guardrails.
4. The subsystem you're about to touch, under `src/main/` — see "Where
   things live" above.
