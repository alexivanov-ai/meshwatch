# Meshwatch

A local network monitoring desktop app. Electron, plain HTML/CSS/JS in the
renderer, no build step for the UI, no framework.

The person you are working with is NOT a developer. They can copy and paste
commands and read output. Explain what you are doing only when they need to act
or decide something. Never leave a broken state at the end of a phase.

## Discovery scope

Scan boundary is detected at runtime from the OS network interface
(`os.networkInterfaces()` → the host's private IPv4 /24). Never hardcode a
subnet in discovery — the same build must work on any LAN. Hard rule 6 still
requires an explicit boundary; that boundary is whatever /24 this PC is on.

Whichever DNS/DHCP backend is running on the discovered Pi (Pi-hole or
AdGuard Home, auto-detected — see `src/main/dns/`) is the authoritative
source of device hostnames when it's also acting as DHCP server. Always
prefer a DHCP hostname over an mDNS name or an OUI vendor guess. Never put
the OUI vendor string in the Name column — that belongs in Vendor.

## config/devices.json is a hint, not ground truth

Early in phase 1, `config/devices.json` had a specific IP hardcoded for every
device in its `known` list - most of them never confirmed by the user, just
assumed sequentially (.3, .4, .5...). One was wrong, and it went unnoticed
because nothing was re-deriving it from a live scan; another device on that
network got mislabelled with a fabricated model name as a direct result.
Don't repeat this. The rule now:

- `config/devices.json`'s `known` list may name a **model, vendor and role**
  the user has told us about. It must never assert an **IP** unless it's
  under a `confirmed: { ip, source }` key - meaning the user explicitly stated
  it, not something extrapolated from a pattern or a default convention.
- `discovery.js`'s `matchKnown()` is the only place a discovered device gets
  labelled with one of these entries, and only on evidence that is itself
  discovered: an exact `confirmed.ip` match, the OS's own default-gateway
  route (for the `gateway` role), or the device naming its model in a web
  `<title>` or SNMP sysName/sysDescr. Vendor-only matching is deliberately
  not enough to assign a specific model - several known devices can share a
  single vendor, with no way to tell them apart from ARP/mDNS/SSDP alone.
- A device that doesn't match any of those stays labelled by DHCP hostname /
  mDNS / SNMP sysName / web title / model, with `estimated: true` - never
  silently assigned a guessed identity, and never named after the OUI vendor.
- The scan is expected to surface devices that aren't in this file at all.
  That's not a bug to fix by adding them to config; it's the discovery engine
  doing its job.

## Web probe

Part of every scan (`discovery.js`'s `webProbe()`): a plain GET on port 80 for
each discovered IP, never a login attempt. Records whether something answers,
its `<title>` (routers/printers/cameras routinely self-identify there,
unauthenticated) and whether the page looks like a login form. This is real,
observed data - it feeds both device naming (see above) and the "does this
have a login page" signal for the credential vault below.

## SNMP probe

Also part of every scan: an unauthenticated SNMPv2c GET for `sysName` and
`sysDescr` (community `public` only). Managed switches often answer here
when the web title is generic. No write community, no credential guessing.

## Credential vault

Local password storage for any discovered device with a login page, keyed by
MAC (`src/main/credentials.js` + db.js's `credentials` table). Encryption is
Electron's `safeStorage` - OS-backed (DPAPI on Windows), no separate master
password, no third-party native dependency. Only encrypted bytes ever touch
disk; the plaintext password is decrypted in the main process only, at the
moment of scripting a form-fill, and is never sent to the renderer as a bare
IPC return value. The renderer only ever sees label/username/when-saved
metadata for its search UI. Auto-fill into an embedded device admin page is a
phase 5 concern (needs the real interface's `<webview>` to fill into); the
vault itself is phase-1 infrastructure and already usable via IPC
(`credentials:save/list/has/remove`).

## Hard rules

1. `contextIsolation: true`, `nodeIntegration: false`. All privileged work
   happens in the main process and crosses to the renderer through the narrow
   API in `src/preload.js`. Never widen it to expose `ipcRenderer` directly.
   Device admin pages open in the in-app Chromium view (`src/main/browser.js`),
   never as a system browser tab. That view only loads private LAN URLs.
2. Credentials (router passwords, DNS backend API token, SSH key path, any
   device login saved via the credential vault) go through OS-backed encryption
   (Electron `safeStorage` - see "Credential vault" below), never in a plain
   file in this repo. `config/devices.json` holds models and roles, plus the
   rare explicitly user-confirmed address - see "config/devices.json is a
   hint, not ground truth" below.
3. Never invent a CVE, a firmware version, or a vendor advisory. If something
   cannot be verified, label it `unverifiable` and say why.
4. Inferred values must be visibly marked as estimates in the UI. Many
   consumer devices (unmanaged switches, APs, smart-home gear) have no API at
   all - a wrong confident answer is worse than an honest gap.
5. Any action that interrupts connectivity - rebooting a router, restarting
   the DNS backend service, rebooting the Pi - requires explicit confirmation
   and must warn how long the network will be down.
6. Only ever scan this machine's local private /24 (detected at runtime). No
   scanning of external hosts or other subnets.

## Build order

Discovery first, interface last. If the scan does not reliably find the devices
actually present on the LAN, nothing built on top of it matters.

- [x] Phase 0 - Electron scaffold, IPC, SQLite, minimal renderer
- [x] Phase 1 - Discovery engine: ping sweep + ARP table, mDNS, SSDP, DNS PTR,
  NetBIOS, web probe, SNMP sysName/sysDescr, OS subnet + default-gateway
  detection, config-drift check, local credential vault, user device renames.
  DHCP leases come from the Pi-hole API (or SSH `dhcp.leases`) once credentials are saved.
- [x] Phase 2 - Pi-hole: REST stats, SSH console on a user-set port
- [x] Phase 3 - TP-Link control. Local web API where a password is saved; otherwise the in-app admin page
- [x] Phase 4 - Security audit: firmware from device APIs, open ports, config weaknesses
- [x] Phase 5 - Rebuild the UI to match `design/Network Dashboard.dc.html`
  (overview, inventory with filters/click/context menu, topology, audit,
  Pi-hole, Discovery progress, Preferences + credential vault + CSV export)
- [x] Phase 6 - Installers: NSIS on Windows (dmg is macOS-only and built on a Mac)
- [x] Phase 7 - Pi tab redesign: the Pi-hole-specific module split into a
  generic, auto-detected DNS/DHCP backend system (`src/main/dns/`, routed
  through `src/main/pi.js` for SSH/target/disruptive-command concerns and
  an embedded SSH terminal), generic advertised-service discovery
  (`src/main/pi-services.js`), plus ten promoted features: per-device
  online/offline history sparkline, new-device desktop notification,
  posture-score history, full DB backup/restore, scan-diff digest
  notification, Wake-on-LAN, device tags/groups, advertised-services list
  per device, LAN latency/health sampling (`src/main/latency.js`), and
  per-client DNS query trend.

## Discovery approach, and why

The scaffold uses an unprivileged ICMP ping sweep followed by a read of the OS
ARP table (`arp -a`). This works without Npcap and without administrator
rights, and finds most hosts. Raw ARP via Npcap finds more - devices that
ignore ping - so treat it as an upgrade, not the starting point. If you add it,
keep the ping+ARP path as a fallback so the app still works unprivileged.

## Files

```
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
config/devices.json     Known models/roles - see "config/devices.json is a hint" above
scripts/test-discovery.js  Run discovery from the terminal, print results
scripts/build-oui.js    Regenerate oui-data.json from the IEEE registry (offline)
```
