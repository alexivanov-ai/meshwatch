# Meshwatch — High-Level Design

This document describes the architecture of Meshwatch: the process model, the
major subsystems, how data moves through the app, and the reasoning behind
its hard constraints. It describes the *shape* of the system — nothing here
is specific to any one contributor's network. Meshwatch detects its scan
boundary at runtime from the host OS and works the same way on any private
LAN.

## 1. Process model

Meshwatch is an Electron app, which means it always runs as (at least) three
separate processes with different privilege levels:

```text
┌───────────────────────────────┐        ┌────────────────────────────────┐
│  Main process (Node.js)       │        │  Renderer process (Chromium)   │
│  src/main/*.js                │  IPC   │  src/renderer/*                │
│  - full OS access             │◄──────►│  - plain HTML/CSS/JS UI        │
│  - network sockets, SSH, SNMP │        │  - contextIsolation: true      │
│  - SQLite, safeStorage        │        │  - nodeIntegration: false      │
│  - owns all subsystems below  │        │  - no Node/Electron APIs       │
└──────────────┬────────────────┘        └───────────────┬────────────────┘
               │                                          │
               │              src/preload.js              │
               └──────────── (contextBridge) ─────────────┘
                        the only crossing point

┌────────────────────────────────────────┐
│  Admin-page view (Chromium, isolated)  │
│  src/main/browser.js — WebContentsView │
│  - no preload, sandboxed               │
│  - LAN URLs only                       │
└────────────────────────────────────────┘
```

**Main process.** Everything privileged lives here: network scanning, SSH
sessions, SNMP/mDNS/SSDP sockets, the SQLite database, and the OS-backed
credential store. This is plain Node.js with full OS access, so it is also
the only place that is allowed to hold that access.

**Renderer process.** The UI — plain HTML/CSS/JS, no framework, no build
step. It runs with `contextIsolation: true` and `nodeIntegration: false`,
meaning it cannot reach Node.js APIs, the filesystem, or child processes even
if a bug or a compromised dependency injected arbitrary JavaScript into the
page. It can only ask the main process to do things, through the narrow
bridge described below.

**Preload script.** `src/preload.js` runs in a special context that can see
both worlds but exposes only what it explicitly chooses to. It is the seam
between the two processes — see section 4.

This split exists because a network scanner necessarily touches raw sockets,
runs shell/SSH commands, and stores secrets — capabilities that must never be
reachable from a process that also renders arbitrary text pulled from the
network (device hostnames, web page titles, mDNS names, etc., all of which
end up in the renderer's DOM). If the renderer were allowed direct Node
access, a hostile device on the LAN that got a crafted string into a title or
name field would have a path to code execution on the host. Keeping that
process sandboxed means the worst a malicious device can do is show up with a
misleading label.

## 2. The in-app admin-page browser

Many LAN devices (routers, switches, access points, printers) only expose a
web-based admin UI, and Meshwatch wants to bring that UI into the app rather
than sending the user out to a system browser tab. `src/main/browser.js`
implements this as a second, separate Chromium surface — a `WebContentsView`
layered into the main window — rather than reusing the app's own renderer.

This view is deliberately more locked down than the main renderer, not less:
it has **no preload script at all** (so it exposes nothing from Electron or
Node into the page, not even the narrow bridge the main UI gets), it runs
with Chromium's `sandbox: true`, and navigation is filtered through a
LAN-only allowlist — only private IPv4 ranges are permitted, and any
attempt to navigate or open a window to a non-LAN URL is denied outright.

The reasoning: a device admin page is inherently untrusted content — it's
served by hardware the user doesn't necessarily control the firmware of, and
Meshwatch has no way to vet what that page will try to do. Isolating it in
its own view with no privileged bridge means that even a fully compromised
admin page can't reach anything outside itself: it can't call back into
Meshwatch's IPC surface, can't read the credential vault, and can't navigate
itself out to the open internet to exfiltrate anything, because the
navigation filter only allows it to stay on the LAN. This view uses
Electron's bundled Chromium (not the system browser), so its capabilities
and patch level track Electron/Meshwatch releases rather than whatever
browser happens to be installed on the host.

The view's address bar is user-editable, not just a display of whatever URL
opened it — the same LAN-only allowlist gates a typed address exactly like
a button-opened one, so making it editable widens what the user can *reach*
without widening what the view will *accept*. The view also trusts a
self-signed TLS certificate, but again only for a host that already passes
the LAN-only check: router and switch admin UIs are the class of device
most likely to force HTTPS with a cert nothing will ever have signed, and
Electron's default (silently refuse the connection) turned that into a
page that just wouldn't load, with no indication why. Accepting the cert
here doesn't relax the trust boundary — a self-signed cert on a LAN address
Meshwatch already restricted itself to is a materially different risk than
accepting one for an arbitrary internet host, which this code path can
never reach in the first place.

## 3. Major subsystems

Each of these lives in its own module under `src/main/` with a single,
narrow responsibility. Keeping them separate means a change to one (say,
switching which DNS server product is detected) never has to touch
unrelated code (say, SSH terminal handling).

**Discovery —** `src/main/discovery.js`**.** The core of the app: finds what's
on the LAN and merges results by MAC address across several independent
signals — an unprivileged ICMP ping sweep followed by a read of the OS ARP
table (works without elevated privileges or a packet-capture driver), mDNS/
Bonjour browsing, SSDP/UPnP search, an HTTP probe of port 80 for a page
title, and an unauthenticated SNMP GET for `sysName`/`sysDescr`. It also
detects the scan boundary itself, at runtime, from the OS's own network
interface list and default-gateway route — never a hardcoded subnet — so the
same build works unmodified on any user's LAN. It is a separate module
because it is the one piece every other subsystem in the app depends on:
nothing else has an opinion about what's out there until discovery has run.

**DNS backend adapters —** `src/main/dns/`**.** Many home networks run their DNS
and DHCP service on a Raspberry Pi. Rather than assuming which DNS/DHCP
product runs on it, `dns/index.js` probes for the handful of server products
Meshwatch knows how to talk to, caches which one (if any) answered, and
routes every subsequent call — stats, DHCP lease list, block/unblock — to the
matching adapter module. This indirection exists so that adding support for
another backend is a new adapter file, not a rewrite of every caller, and so
the rest of the app never has to special-case "which DNS product is this."

**Pi system administration + terminal —** `src/main/pi.js`**.** Generic SSH
plumbing for a Raspberry Pi acting as the network's DNS/DHCP host: resolving
the SSH target, running remote commands, package-update checks, and a live
interactive terminal session bridged to the renderer. Meshwatch recognizes a
Raspberry Pi specifically — by its vendor string, by a `Pi-hole`-style name
or title, or by a model string matching the Pi's own model numbering — not
any single-board computer in general; a device that doesn't match one of
those signals is never assumed to be the DNS/DHCP host. This module is
deliberately separate from the DNS-backend logic in `dns/` — `pi.js` knows
how to run a command over SSH and gate disruptive ones behind confirmation,
but has no opinion about which DNS product is installed; `dns/` has that
opinion but never opens its own SSH connection. It also maintains an
explicit list of disruptive commands (service restarts, package upgrades,
reboot, shutdown) so those can be intercepted and confirmed before they run,
rather than trusting every caller to remember.

**Generic service discovery —** `src/main/pi-services.js`**.** Once connected
over SSH, this lists whatever ports the box is actually listening on and
probes each with a plain HTTP GET, matching the response against a small
catalog of common self-hosted services (media servers, download clients,
monitoring dashboards, and the like) purely to attach a friendly name.
An unmatched port is still shown — never hidden and never guessed at —
because the catalog is illustrative, not authoritative, and a real observed
page title always wins over an assumption. It is separate from `pi.js`
because it is optional, best-effort labelling on top of the SSH access
`pi.js` already provides, not a required part of reaching the box.

**Credential vault —** `src/main/credentials.js`**.** Local, encrypted storage
for any device login the user chooses to save, keyed by device MAC.
Encryption uses Electron's `safeStorage`, which defers to the operating
system's own credential protection rather than a bespoke scheme or a
separate master password. Plaintext only ever exists transiently, in main-
process memory, at the moment it's needed to script a form-fill or an
authenticated API call — it is never handed to the renderer as a bare IPC
return value; the renderer only ever sees label/username/when-saved
metadata. This is its own module, rather than folded into whichever
subsystem needs a password, because every subsystem that needs credentials
(TP-Link control, DNS backend auth, the admin-page browser) should go
through the same storage and disclosure discipline instead of each
inventing its own.

**Security audit —** `src/main/audit.js`**.** Turns the current device
inventory into a list of findings — end-of-support hardware, firmware
behind the vendor's latest, open ports, weak or default-feeling
configuration — with a severity and a plain-language explanation for each.
It never asserts a CVE, firmware version, or vendor advisory it hasn't
actually observed from a device response; anything it can't verify is
labelled `unverifiable` rather than guessed. Findings can be dismissed and
restored, and history is kept so the score is a signal over time rather
than a one-off snapshot. It lives apart from discovery because it is a pure
function of the inventory discovery already produced — it consumes device
records, it doesn't gather them.

**TP-Link control —** `src/main/tplink.js`**.** Talks to TP-Link consumer
router/extender hardware over the same unofficial encrypted local endpoint
their own web UI uses (there is no public API), using credentials pulled
from the vault. Actions are split into safe (status, client list) and
disruptive (reboot, firmware update, SSID/channel changes) categories, with
the disruptive ones gated the same way as the Pi's disruptive commands. This
is vendor-specific reverse-engineered protocol logic, encryption handshake
included, and keeping it in its own module means that logic is fully
contained and doesn't leak into the generic discovery or audit code, and
that a device the app can't actually control (older, unsupported hardware)
can be explicitly left read-only within this one file rather than the app
silently assuming otherwise.

## 4. Data flow: a scan, end to end

A scan is the central data-flow event in the app; everything else in the
renderer is a view over its results.

```text
 renderer                 preload            main process
 ────────                 ───────            ────────────
 "Scan" click
    │  meshwatch.scan() ────────► ipcRenderer.invoke("scan:run")
    │                                              │
    │                                              ▼
    │                                     runScan() in index.js
    │                                              │
    │                              discovery.run({ onProgress })
    │                                   │  ping sweep + ARP
    │                                   │  mDNS / SSDP
    │                                   │  DHCP leases (via dns/ adapter)
    │                                   │  web probe (port 80 title)
    │                                   │  SNMP sysName/sysDescr
    │                                   │  merge by MAC, match against
    │                                   │  config/devices.json (only on
    │                                   │  discovered evidence, never a guess)
    │  ◄── scan:progress events ────────┤ (per-stage, streamed as it runs)
    │                                              │
    │                                     db.recordScan(devices)
    │                                     (upsert devices, log a sighting,
    │                                      diff for newly-seen MACs)
    │                                              │
    │                                     discovery.detectDrift(devices)
    │                                     (confirmed-IP devices that didn't
    │                                      answer where expected)
    │  ◄── scan:finished event ─────────────────────┘
    │
    │  meshwatch.getDevices() ──────────► db.listDevices()
    ▼
 renderer re-renders inventory / topology / overview from the returned rows
```

The database (`src/main/db.js`, SQLite via `better-sqlite3`, stored in the
OS user-data folder — never inside the project) is the single source of
truth the renderer reads from; discovery never talks to the renderer
directly. Live progress during a long-running scan streams over a separate
`scan:progress` event so the UI can show stage-by-stage status without
polling. Everything downstream of discovery — inventory, topology, audit
findings, drift warnings — is derived by reading the same device rows back
out of the database, not by holding a separate copy of scan state.

## 5. The IPC boundary

`src/preload.js` is the *only* file allowed to `require("electron")` for
`contextBridge`/`ipcRenderer` and hand anything across into the renderer's
world. The renderer never imports Electron, never sees `ipcRenderer`, and
never receives a raw handle onto anything privileged.

What crosses the bridge is a flat object of named, single-purpose methods —
`scan()`, `getDevices()`, `pi.exec(command)`, `credentials.save(...)` — each
wrapping exactly one `ipcRenderer.invoke`/`.send` call to one correspondingly
named handler in the main process. There is no generic "send any IPC
message" escape hatch. This shape is deliberate for two reasons: it keeps
the attack surface enumerable (every capability the renderer can invoke is
visible in one file, in one place, rather than scattered), and it lets each
handler apply its own rules at the boundary — e.g. the credential handlers
only ever return metadata (label/username/timestamp), never a password,
because the wrapping method for "list credentials" was written to shape its
return value that way rather than passing a raw row straight through.

## 6. Why each Hard Rule exists

The rules below are enforced throughout the codebase (see `CLAUDE.md` for
the authoritative list); this section explains the reasoning behind each.

**Process isolation (**`contextIsolation: true`**,** `nodeIntegration: false`**,
narrow preload bridge).** The renderer routinely displays strings that
originate from other devices on the network — hostnames, mDNS names, web
page titles picked up by the probe. None of that is trusted input. If the
renderer could reach Node.js APIs directly, a hostile or compromised device
crafting a malicious string into one of those fields would have a path from
"gets rendered in the UI" to "runs code with filesystem/process access."
Isolating the renderer means that failure mode is capped at a bad-looking
label, not a compromised machine.

**Credentials never touch disk unencrypted.** Router and device passwords,
SSH targets, and API tokens are exactly the kind of thing a casual repo
clone, a backup upload, or a stolen laptop disk would otherwise leak in
plain text. Using the OS's own credential encryption (rather than a
homegrown scheme or a bundled secret) means the ciphertext is worthless
without the same OS user account on the same machine, and the app never has
to invent or audit its own crypto.

`config/devices.json` **never asserts an IP unless the user confirmed it.**
This file previously hardcoded addresses for devices the user had only
described in general terms (make/model), and one of those guesses was wrong
in a way that silently mislabeled a real device on a real scan. IP
addresses drift — DHCP reassigns them, hardware gets swapped — so treating a
remembered address as ground truth is a standing source of false confidence.
Only evidence gathered *by the current scan* (an exact confirmed-IP match,
the OS's own default-gateway route, or a device naming itself in a web
title or SNMP response) is allowed to attach a specific identity to a
specific address.

**Never invent a CVE, firmware version, or vendor advisory.** A security
tool that fabricates plausible-sounding findings is worse than one that
says nothing, because a fabricated finding either sends the user chasing a
problem that doesn't exist or, worse, teaches them to distrust real
findings later. Anything the audit subsystem can't verify from an actual
device response is labelled `unverifiable` rather than presented with false
confidence.

**Inferred values are visibly marked as estimates.** Several devices on any
given LAN have no management API at all — the app can only guess their role
or model from indirect signals (vendor OUI, port behavior, timing). A
guess that looks identical to a confirmed fact in the UI is a trap: the user
has no way to tell which pieces of information to actually trust. Marking
estimates as estimates keeps that judgment call with the user instead of
hiding it from them.

**Disruptive actions require explicit confirmation and a stated downtime.**
Rebooting a router, restarting a DNS service, or rebooting the box serving
DHCP for the whole network doesn't just affect the one device being acted
on — it can take the user's own internet access down, sometimes for longer
than expected. Gating these behind an explicit confirmation that states how
long the disruption will last turns "oops, I clicked the wrong button" from
a network outage into a decision the user consciously made.

**Scanning is confined to the local private** `/24`**, detected at runtime.**
A network monitor with no boundary is a scanning tool that could be pointed
at other people's infrastructure, intentionally or by a bug. Deriving the
boundary from the OS's own interface configuration at runtime — rather than
a hardcoded range — means the app only ever touches the network segment
it's actually installed on, on any machine, without the maintainer having
to special-case a subnet, and it structurally cannot be aimed at an external
host.
