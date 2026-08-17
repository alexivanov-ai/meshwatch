# Meshwatch

Meshwatch is a desktop app for monitoring your own local network. It runs on
your machine, scans the private LAN it's installed on, and gives you a single
dashboard for what's connected, how it's laid out, and whether anything about
it looks like a security concern. It's built with Electron and a plain
HTML/CSS/JS renderer — no frontend framework, no build step for the UI.

Everything Meshwatch does is local: it talks to devices already on your
network (routers, switches, a Pi-hole/AdGuard box, and anything else that
answers), it never phones home, and there's nothing to sign up for.

## Features

- **Device discovery** — an unprivileged ICMP ping sweep plus the OS ARP
  table, combined with mDNS, SSDP, DNS PTR lookups, and NetBIOS name
  queries, merged into one device list by MAC address. The sweep itself
  needs no packet-capture driver (no Npcap) and no elevated privilege to
  find most hosts — note that the packaged Windows installer still declares
  `requireAdministrator`, so an installed build does prompt for elevation on
  launch; run `npm start` from a checkout for an unelevated session.
- **Automatic scan boundary** — the subnet to scan is detected at runtime
  from the host's own network interface and default-gateway route. There's
  nothing to configure and nothing hardcoded; the same build works on
  whatever /24 it's installed on.
- **Topology view** — a visual layout of what's connected to what, built
  from the same discovery data as the inventory.
- **Inventory** with filters, click-through device details, and a
  right-click context menu.
- **Security audit** — flags end-of-support hardware, open ports, and
  weak or default-feeling configuration, with a plain-language explanation
  for each finding. Nothing is asserted that wasn't actually observed from a
  device response; anything that can't be verified is labeled
  `unverifiable` instead of guessed at.
- **DNS backend integration** — auto-detects whether your network's DNS/DHCP
  box is running Pi-hole or AdGuard Home and talks to whichever one answers,
  including live stats and the DHCP lease table (the most reliable source of
  device hostnames on the network).
- **Embedded SSH terminal** — a live, interactive terminal session to a
  Raspberry Pi or similar box acting as your DNS/DHCP host, right inside the
  app.
- **Credential vault** — local, OS-encrypted storage for any device login
  you choose to save, so you're not retyping router or dashboard passwords.
- **In-app device admin browser** — open a device's own web admin page
  inside Meshwatch (in an isolated, sandboxed view), instead of jumping out
  to a system browser tab.
- **Wake-on-LAN** — wake a sleeping device from the inventory.
- **Device tags** — label and group devices in your own words, with
  tag-based filtering in the inventory and coloring in the topology view.
- **Latency monitoring** — lightweight round-trip latency sampling with
  history, so you can see when something on the network started acting up.
- **CSV export** — pull the device inventory out as a CSV file.
- **Database backup & restore** — export everything Meshwatch has stored
  (optionally including saved credentials) to a file, and restore from one.
- **Config-drift detection** — flags when a device you've explicitly
  confirmed the address of stops answering where expected.

## Privacy and security posture

Meshwatch is built for a category of app that normally asks for a lot of
trust — network scanning and device credentials — so its default posture is
deliberately conservative:

- **LAN-only, always.** Meshwatch only ever scans the private `/24` it
  detects itself installed on. There's no way to point it at another subnet
  or an external host — that boundary isn't a setting, it's how discovery is
  built.
- **No telemetry, no cloud dependency.** Nothing about your network, your
  devices, or how you use the app is sent anywhere. Everything Meshwatch
  knows lives in a local SQLite database on your machine.
- **OS-backed credential encryption.** Any device password you save goes
  through Electron's `safeStorage`, which defers to your operating system's
  own credential protection (e.g. DPAPI on Windows) rather than a bespoke
  encryption scheme or a separate master password. Only encrypted bytes ever
  touch disk.
- **Process isolation.** The UI runs with `contextIsolation: true` and
  `nodeIntegration: false` and never gets direct access to Node.js or the
  filesystem — it can only ask the privileged main process to do things,
  through a narrow, explicit bridge. This matters because the UI routinely
  displays strings that come from other devices on your network (hostnames,
  page titles), and none of that is trusted input.
- **Disruptive actions require confirmation.** Rebooting a router or
  restarting a DNS service can take your network down; Meshwatch always asks
  first and tells you how long the disruption is expected to last.

## Getting started

Requires Node.js 24 or newer.

```bash
npm install
npm start
```

To build an installer:

```bash
npm run build:win     # Windows installer (NSIS), output in dist/
npm run build:mac     # macOS .dmg — only works when run on a Mac
```

## Documentation

For architecture and implementation details, see:

- [`docs/HLD.md`](docs/HLD.md) — high-level design: process model, major
  subsystems, and the reasoning behind the app's hard constraints.
- [`docs/LLD.md`](docs/LLD.md) — low-level design: database schema and the
  full IPC surface between the renderer and the main process.

## License

GPL-3.0. See [`LICENSE`](LICENSE).
