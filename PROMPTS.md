# Copy-paste prompts

Run `claude` in this folder, then paste these one at a time. Let each phase
finish and check it works before moving to the next. The full explanation of
each phase is in `build-guide.html`.

---

## Phase 1 - Discovery engine

Read CLAUDE.md, then finish the discovery engine in src/main/discovery.js. The
scaffold has the structure and a working ping sweep plus ARP table read; the
mDNS, SSDP and Pi-hole DHCP lease functions are stubs.

Complete all four discovery methods and merge their results into one device
list keyed by MAC address. Resolve vendors from the IEEE OUI prefix list -
bundle the list locally in src/main/oui.js, do not call a web service. Name
priority: DHCP hostname, then mDNS name, then OUI vendor, then "Unidentified
host".

Then infer the topology as a tree with the BE220 at the root, per the device
table in CLAUDE.md. Get parentage from each TP-Link node client table where
possible and from RSSI plus lease origin where not. Mark every inferred link as
an estimate.

Save each scan to SQLite with a timestamp so first-seen and last-seen work.
Then run npm run test:discovery and show me the output so I can check it
against the devices I know are on my network.

---

## Phase 2 - Pi-hole and SSH

Implement src/main/pihole.js. Two channels: the Pi-hole REST API for statistics
- query totals, percent blocked, top blocked domains, the DHCP lease table -
and SSH on port 2222 via ssh2 for shell commands.

Use key-based SSH authentication, not a password. Walk me through generating
the key here and installing it on the Pi, one command at a time, and verify it
works before continuing. Store the key path and the API token in the OS
credential store.

Give me a panel with terminal-style output and buttons for: pihole status,
pihole -g, restart pihole-FTL, list DHCP leases, top clients, CPU temperature
and disk space, and apt updates available. Let me also type an arbitrary
command. Anything that interrupts DNS for the whole house must confirm first
and tell me how long resolution will be down.

---

## Phase 3 - TP-Link control

Before writing any code: research and tell me honestly which of my TP-Link
devices can be controlled locally and which cannot. There is no official local
API, so tell me which community library you propose, how actively it is
maintained, and what breaks when TP-Link ships new firmware. I would rather
have five working actions and honest gaps than nine that fail silently.

Then implement what is genuinely possible in src/main/tplink.js, aiming for:
reboot, firmware version check and update, SSID and password per band, band
steering and channel selection, per-node client list, port forwarding, WAN
speed test, LED on/off with a schedule, and mesh backhaul signal health.

Where an action is not achievable through an API, give me a button that opens
that device own admin page in my browser rather than one that pretends to work.
Treat the TL-WDR4300 as read-only and end-of-support.

---

## Phase 4 - Security audit

Implement src/main/audit.js. For every discovered device, check what can be
checked and be explicit about what cannot.

Compare running firmware against the latest release where a vendor feed exists.
Flag devices past end of support - the TL-WDR4300 is one. Scan common service
ports and flag risky ones: telnet 23, raw print 9100, unauthenticated UPnP, and
the GREE air conditioner UDP 7000 local API. Flag any device whose MAC matches
no vendor and that has no DHCP hostname. Check the router for WPS enabled, UPnP
enabled, WAN-side remote management, and admin interfaces over plain HTTP.

For the devices with no management API, infer what you can from ARP timing and
lease history and label every inferred value as an estimate. Let me hand-record
a firmware version I have read off the device myself so age warnings still work.

Each finding gets a severity, a plain-English explanation of the real risk, and
one concrete action. Compute an overall score. Cite a CVE only where a real one
applies; say unverifiable otherwise.

Add per-device internet blocking through Pi-hole for DNS-level blocking and
through the router where a MAC filter exists.

---

## Phase 5 - The interface

Read prototype.html in this folder and rebuild the renderer to match it exactly
- same layout, spacing, type, colours and interaction structure: sidebar nav,
overview with statistics and a needs-attention list, inventory table with
filters, topology tree, security audit, the Pi-hole and SSH view, discovery
progress with a live log, and preferences.

Wire every part to real data from the engine. The prototype data is invented -
replace all of it, keep the design. Keep the renderer as plain HTML, CSS and JS
with no build step.

---

## Phase 6 - Installers

Verify the electron-builder config, then build the Windows installer with
npm run build:win and tell me where the file lands. Remind me that the macOS dmg
must be built on my MacBook with npm run build:mac, and that both will warn on
first launch because the app is unsigned.
