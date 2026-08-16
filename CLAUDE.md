# Meshwatch

A local network monitoring desktop app. Electron, plain HTML/CSS/JS in the
renderer, no build step for the UI, no framework.

The person you are working with is NOT a developer. They can copy and paste
commands and read output. Explain what you are doing only when they need to act
or decide something. Never leave a broken state at the end of a phase.

## The network this app monitors

Scan boundary is detected at runtime from the OS network interface
(`os.networkInterfaces()` → the host's private IPv4 /24). Never hardcode a
subnet in discovery — the same build must work on any LAN. Hard rule 6 still
requires an explicit boundary; that boundary is whatever /24 this PC is on.

This developer's home LAN (example only — not asserted by the scanner):

Known models the user has told us about - **not** a claim about which IP each
one is at. Only the gateway (found via the OS's own default-gateway route)
and addresses under a `confirmed: { ip, source }` key have a known address;
see "config/devices.json is a hint, not ground truth" below.
There may be more devices on the network than this list, or fewer - the scan
finds what's actually there, this list only helps label it once found.

| Device | Role | Manageable |
| --- | --- | --- |
| TP-Link Archer BE220 | Gateway router | Local API, unofficial |
| Raspberry Pi 5 | Pi-hole: DNS + DHCP for the whole network, confirmed at `192.168.1.63` | REST API + SSH (port set in Preferences; this LAN uses 2222) |
| TP-Link TL-SG108E | Managed 8-port switch, confirmed at `192.168.1.24` | Web UI (+ SNMP where enabled) |
| 8-port switch (unmanaged) | Unmanaged switch | No. Infer only |
| TP-Link Archer AX20 | Router in AP mode | Local API, unofficial |
| TP-Link RE450 | Range extender | Local API, unofficial |
| TP-Link TL-WA1201 | Range extender | Local API, unofficial |
| TP-Link TL-WDR4300 | Legacy router, EOL 2016 | Read-only. Do not attempt control |
| Broadcom AP | Access point | No. Infer only |

Clients seen before: MacBook Pro, a desktop, two laptops, OnePlus Nord 4,
PlayStation 4 Pro, Sony Bravia TV, GREE air conditioner - again, not an
exhaustive or authoritative list.

The Pi-hole is the DHCP server, so its lease table is the authoritative source
of device hostnames. Always prefer a DHCP hostname over an mDNS name or an OUI
vendor guess. Never put the OUI vendor string in the Name column — that belongs
in Vendor.

## config/devices.json is a hint, not ground truth

Early in phase 1, `config/devices.json` had a specific IP hardcoded for every
device in the table above - most of them never confirmed by the user, just
assumed sequentially (.3, .4, .5...). One was wrong (the Pi-hole), and it went
unnoticed because nothing was re-deriving it from a live scan; another device
on this network got mislabelled with a fabricated model name as a direct
result. Don't repeat this. The rule now:

- `config/devices.json`'s `known` list may name a **model, vendor and role**
  the user has told us about. It must never assert an **IP** unless it's
  under a `confirmed: { ip, source }` key - meaning the user explicitly stated
  it, not something extrapolated from a pattern or a default convention.
- `discovery.js`'s `matchKnown()` is the only place a discovered device gets
  labelled with one of these entries, and only on evidence that is itself
  discovered: an exact `confirmed.ip` match, the OS's own default-gateway
  route (for the `gateway` role), or the device naming its model in a web
  `<title>` or SNMP sysName/sysDescr. Vendor-only matching is deliberately
  not enough to assign a specific model - several known devices share a
  vendor (TP-Link) with no way to tell them apart from ARP/mDNS/SSDP alone.
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
`sysDescr` (community `public` only). Managed switches like the TL-SG108E
often answer here when the web title is generic. No write community, no
credential guessing.

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
2. Credentials (router passwords, Pi-hole API token, SSH key path, any device
   login saved via the credential vault) go through OS-backed encryption
   (Electron `safeStorage` - see "Credential vault" below), never in a plain
   file in this repo. `config/devices.json` holds models and roles, plus the
   rare explicitly user-confirmed address - see "config/devices.json is a
   hint, not ground truth" below.
3. Never invent a CVE, a firmware version, or a vendor advisory. If something
   cannot be verified, label it `unverifiable` and say why.
4. Inferred values must be visibly marked as estimates in the UI. The switch,
   the Broadcom AP and the GREE unit have no API - a wrong confident answer is
   worse than an honest gap.
5. Any action that interrupts connectivity - rebooting a router, restarting
   pihole-FTL, rebooting the Pi - requires explicit confirmation and must warn
   how long the network will be down.
6. Only ever scan this machine's local private /24 (detected at runtime). No
   scanning of external hosts or other subnets.

## Build order

Discovery first, interface last. If the scan does not reliably find the devices
listed above, nothing built on top of it matters.

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

The copy-paste prompt for each phase is in `PROMPTS.md`.

## Discovery approach, and why

The scaffold uses an unprivileged ICMP ping sweep followed by a read of the OS
ARP table (`arp -a`). This works without Npcap and without administrator
rights, and finds most hosts. Raw ARP via Npcap finds more - devices that
ignore ping - so treat it as an upgrade, not the starting point. If you add it,
keep the ping+ARP path as a fallback so the app still works unprivileged.

## Files

```
src/main/index.js       Electron entry, window, IPC handlers
src/main/db.js          SQLite: devices, sightings, findings, notes, credentials
src/main/discovery.js   Ping/ARP, mDNS, SSDP, SNMP, subnet+gateway, web probe, merge
src/main/oui.js         MAC prefix to vendor lookup (src/main/oui-data.json)
src/main/pihole.js      Pi-hole REST API and SSH on 2222
src/main/tplink.js      TP-Link control. Mostly unimplemented by design
src/main/audit.js       Security findings and scoring
src/main/credentials.js Local credential vault (safeStorage-encrypted, keyed by MAC)
src/main/updater.js     In-app updates from GitHub Releases (installed builds only)
src/main/browser.js     In-app Chromium (WebContentsView) for device admin pages
src/preload.js          The only bridge to the renderer
src/renderer/           Interface matched to design/Network Dashboard.dc.html
config/devices.json     Known models/roles - see "config/devices.json is a hint" above
design/                 Network Dashboard + Build Guide design sources
scripts/test-discovery.js  Run discovery from the terminal, print results
scripts/build-oui.js    Regenerate oui-data.json from the IEEE registry (offline)
```
