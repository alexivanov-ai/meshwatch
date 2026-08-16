# Pi tab redesign: dynamic DNS backend, system admin, embedded terminal, service discovery

Status: approved for implementation (2026-08-16)

## Why

The "Pi-hole · SSH" tab was built assuming the Raspberry Pi runs Pi-hole. It
actually runs **AdGuard Home**. Several buttons run Pi-hole-only commands
(`pihole status`, `pihole -g`, `cat /etc/pihole/dhcp.leases`, `pihole -c -e`)
that don't exist on this box — the same class of hardcoded-assumption bug
CLAUDE.md already warns about for `config/devices.json`. The tab needs to
become generic and dynamically detect what's actually running, the same way
device identity elsewhere in the app is only ever asserted from live
evidence (Hard Rules 3–4).

Along the way the user asked for three real feature additions to the same
page: apt update/upgrade + installed-app listing, an embedded interactive
SSH terminal, and auto-detection of other self-hosted services running on
the Pi (Plex, qBittorrent, and anything else — generically, not a fixed
list).

## Scope

**In scope (this pass):**
- Auto-detect DNS backend (Pi-hole or AdGuard Home) per Pi, route all DNS
  stats/leases/block-device calls through a backend-agnostic adapter.
- Rename the tab/IPC/element surface from `pihole:*`/"Pi-hole" to `pi:*`/"Pi".
- Tab (nav + view) only renders when a Pi has actually been discovered on a
  scan.
- Pi system panel: CPU/disk/uptime, reboot-required flag, apt
  update/upgrade, installed-apps list.
- Embedded interactive SSH terminal (real PTY, not one-shot commands).
- Generic service auto-detection on the Pi (open ports + web-probe titles),
  shown as a "Detected services" list with one-click open in the in-app
  browser view.
- CLAUDE.md corrections (Pi row, "Pi-hole is the DHCP server" paragraph).

**Update 2026-08-16: all 10 backlog ideas below are promoted into this same
build pass** (user directive: "promote all to the current build and
implement"). The "Phase 8 backlog" section at the bottom is no longer
backlog — it is in scope, with implementation notes added inline below each
item. Nothing in this spec remains deferred.

## Architecture

### Module split

`src/main/pihole.js` currently mixes three concerns. Split it:

- **`src/main/pi.js`** — generic Pi concerns, backend-agnostic:
  - SSH connect/exec (moved from `pihole.js` as-is — already generic).
  - Interactive PTY terminal: `ssh2` `Client.shell()`, streamed to the
    renderer over IPC (see "Terminal" below).
  - apt: `checkUpdates()` (`apt-get update` then parse `apt list
    --upgradable`), `upgrade()` (`apt-get upgrade -y`, added to the
    disruptive-command list — can restart services), `installedApps()`
    (`apt-mark showmanual`, filtered to drop `-dev`/`lib*`/firmware/
    kernel-pattern package names).
  - `rebootRequired()` — checks `/var/run/reboot-required`.
  - Target resolution (moved from `pihole.js`'s `resolveTarget()`), now
    reading the renamed `pi_*` settings keys.

- **`src/main/dns/pihole.js`** and **`src/main/dns/adguard.js`** —
  backend-specific adapters, same shape: `stats()`, `leases()`,
  `blockClient(ip, {blocked})`. `dns/pihole.js` is the existing Pi-hole
  logic moved unchanged. `dns/adguard.js` is new: AdGuard Home REST API
  (`/control/login` for session, `/control/stats`, `/control/dhcp/status`
  for leases, `/control/access/set` with `disallowed_clients` for
  block/unblock).

- **`src/main/dns/index.js`** — detector + router:
  - `detectBackend(host)`: probe `GET /control/status` (AdGuard,
    unauthenticated) and the existing Pi-hole probe in parallel; whichever
    responds wins. Falls back to the web-title heuristic
    (`looksLikePiHole`-style, extended with an AdGuard title regex) if both
    need auth first. Result cached as a new `pi_dns_backend` setting
    (`"pihole" | "adguard" | "unknown"`), re-checked each scan.
  - Exposes the same `stats()`/`leases()`/`blockClient()` shape, dispatched
    to whichever adapter matches the cached backend.

- **`src/main/pi-services.js`** — new module, generic service discovery
  (see below).

### IPC/renderer rename

`pihole:*` IPC channels → `pi:*`. `#pihole-*` element ids → `#pi-*`.
Nav label "Pi-hole · SSH" → "Pi". Mechanical, not a logic change — done via
careful find/replace across `preload.js`, `src/main/index.js`,
`src/renderer/index.html`, `src/renderer/app.js`.

### Settings migration

Existing settings keys (`pihole_discovered`, `pihole_mac`, `pihole_ip`,
`pihole_ssh_port`, `pihole_ssh_user`, `pihole_ssh_key`) and the credential
vault secret name `pihole_api` predate this rename and are already set on
this machine (the Pi was already discovered and confirmed at
`192.168.1.63`). A one-time migration in `db.js`, run at startup: for each
renamed key, if the new key (`pi_discovered`, `pi_mac`, `pi_ip`,
`pi_ssh_port`, `pi_ssh_user`, `pi_ssh_key`) is unset and the old key has a
value, copy it over. Same for the `pihole_api` → `dns_api` credential vault
secret. This is not hypothetical — it's this install's actual current
state — so the migration is required, not speculative.

## DNS backend adapters

Both adapters expose:
- `stats()` → `{available, reason?, host, version, queriesToday,
  blockedToday, blockedPercent, blocklist, firmware, hostNote, blocked[],
  talkers[]}` — same shape the renderer already consumes, unchanged.
- `leases()` → array of `{ip, mac, hostname, expiry, expires}`.
- `blockClient(ip, {blocked})` → `{ok, blocked, via, reason?}`.

`dns/pihole.js` is the existing logic, moved. `dns/adguard.js` is new:
- Auth: `POST /control/login {name, password}` → session cookie, retried
  like the existing Pi-hole v6 SID flow (re-auth on 401/403).
- `stats()`: `GET /control/stats` (queries, blocked, top domains, top
  clients), `GET /control/status` (version).
- `leases()`: `GET /control/dhcp/status` → `leases` array (AdGuard's own
  DHCP, when enabled) — if AdGuard isn't running its own DHCP (e.g. router
  does DHCP and AdGuard is DNS-only), returns empty and the UI shows the
  existing "no leases available" empty state, never a fabricated list.
- `blockClient()`: `GET /control/access/list` to read current
  `disallowed_clients`, then `POST /control/access/set` with the IP
  added/removed. Same DNS-level-only caveat as the Pi-hole implementation —
  surfaced with the same UI copy ("this blocks DNS resolution for this
  device; a device that changes its DNS server can bypass it").
- Header/response shape probing (AdGuard has changed field names across
  versions) mirrors the defensive `.a || .b || []` pattern already used in
  `pihole.js`.

## Pi system panel

- Stats: CPU/disk/uptime pulled via a small set of SSH one-liners (`uptime`,
  `df -h /`, `nproc`, reuse of the existing system-info parsing pattern from
  `stats()`'s `system` block where the DNS API already exposes it).
- `rebootRequired()`: `test -f /var/run/reboot-required && echo yes`. Shown
  as a banner if true.
- apt actions: "Check for updates" (safe, not disruptive — runs `apt-get
  update`, then parses `apt list --upgradable` output into a count + list),
  "Upgrade all" (`apt-get upgrade -y`, added to `pi.js`'s disruptive-command
  list next to `reboot`/`shutdown`/FTL-restart — confirmation dialog warns
  it may restart services and, if a kernel/firmware package is included,
  that a manual reboot may be needed afterward per the reboot-required
  check).
- Installed apps: `apt-mark showmanual`, filtered client-side to drop
  package names matching `-dev$`, `^lib`, `firmware`, `linux-`, `raspberrypi-
  kernel`, etc. — a best-effort "things you asked for" list, not a claim of
  completeness. Each row can show version via `dpkg -s <pkg>` on demand
  (not batched, to keep the default view fast).

## Terminal

Real interactive PTY, not the existing one-shot command box (kept as a
fallback for headless/scripted use — not removed, still useful for quick
one-liners).

- Main process: `ssh2` `Client.exec()` → replaced/joined by `Client.shell()`
  for the terminal path specifically, requesting a PTY
  (`{term: "xterm-256color", rows, cols}`). Data events streamed to the
  renderer via `webContents.send("pi:term:data", {sessionId, chunk})`.
  Renderer keystrokes go the other way via `ipcRenderer.send("pi:term:input",
  {sessionId, data})` (fire-and-forget, not `invoke` — it's a stream, not a
  request/response).
- New IPC: `pi:term:start` (opens the shell, returns `sessionId`),
  `pi:term:input`, `pi:term:resize`, `pi:term:stop`.
- Renderer: `xterm.js` (+ `xterm-addon-fit`) — new dependency, MIT licensed,
  no native code, safe in the sandboxed renderer (contextIsolation stays on;
  xterm.js only needs the DOM, no Node access — it just renders bytes
  in/out over the existing narrow preload bridge).
- Connects only to the private-LAN Pi IP, using the same saved
  credentials/key as the existing exec path (`sshConnectOptions` in `pi.js`,
  moved unchanged) — Hard Rule 1 (contextIsolation/no nodeIntegration) and
  Hard Rule 6 (LAN-only) both already enforced by the existing `isPrivateIp`
  check, reused here.
- One session at a time per Pi; starting a new one closes the previous.

## Service auto-detection (generic, not a fixed app catalog)

Goal: surface *whatever* is actually running on the Pi (Plex, qBittorrent,
"openclaw," anything), not a hardcoded list. Detection is evidence-first,
same principle as `webProbe()` for LAN devices.

- `src/main/pi-services.js`:
  - `listListeningPorts()`: SSH `ss -tln` (no sudo required for the port
    list itself), parsed for local listening TCP ports. Ports already
    accounted for elsewhere are excluded (SSH port, the detected DNS
    backend's port(s)).
  - For each remaining port: a plain `GET http://<pi-ip>:<port>/` (same
    `lan.request` used by `webProbe()`), reading `<title>` if it answers.
    Never a login attempt, never credential guessing — identical rule to
    the existing web probe.
  - `KNOWN_SERVICES` catalog (small, illustrative, not exhaustive): common
    self-hosted ports/titles for Plex, qBittorrent WebUI, Portainer,
    Sonarr/Radarr/Bazarr, Home Assistant, Jellyfin, Nextcloud, Grafana,
    Syncthing, Uptime Kuma. A match gives a friendly name/category. No
    match still surfaces the service as **"Unknown service · port N ·
    `<observed title or blank>`"** — never hidden, never invented (Hard
    Rules 3–4). This is how something like "openclaw" (not in any catalog)
    still shows up correctly.
  - Cached per-Pi (keyed by MAC), refreshed:
    1. automatically, once, right after Pi SSH credentials are saved and
       verified for the first time;
    2. on demand via a "Rescan services" button in the tab;
    3. opportunistically on each full network scan (cheap: one SSH call +
       a handful of GETs).
- UI: "Detected services" section in the Pi tab — one row per service,
  name/category (or "Unknown service"), port, and an "Open" button that
  loads it in the existing in-app Chromium view (`browser.js`), same
  mechanism already used for TP-Link admin pages.

## UI layout (Pi tab)

Nav item and view render **only when `pi:state().discovered === true`**
(re-evaluated after every scan). Sections, top to bottom:

1. **Header** — detected DNS backend + version, host, "Open admin UI"
   (in-app browser to the backend's root URL), and when the backend is
   AdGuard, a "View query log" shortcut deep-linking to
   `#logs?response_status=all`.
2. **DNS stats** — queries/blocked/blocklist size, top blocked domains, top
   talkers — same shape as today, sourced from whichever adapter is active;
   "unavailable" with a stated reason when no backend is detected or no API
   password is saved (Hard Rule 4).
3. **DHCP leases** — via the adapter; empty state if the active backend
   doesn't run DHCP.
4. **Block device** — unchanged mechanism, routed through the adapter, same
   DNS-level-only caveat surfaced in copy.
5. **Detected services** — the new generic list described above.
6. **Pi system** — CPU/disk/uptime, reboot-required banner, apt
   update/upgrade, installed apps.
7. **Terminal** — the embedded xterm.js session.
8. **Command runner** — existing one-shot command box, kept as a fallback.
9. **Preferences** — same SSH port/user/key fields as today, generalized
   copy ("DNS service API password" instead of "Pi-hole API password").

## Documentation

Update CLAUDE.md:
- Device table row for the Raspberry Pi 5: "Pi-hole: DNS + DHCP for the
  whole network" → "DNS/DHCP service (Pi-hole or AdGuard Home, whichever is
  running — auto-detected), confirmed at `192.168.1.63`".
- "The Pi-hole is the DHCP server, so its lease table is..." paragraph →
  reworded to name whichever backend is active generically.
- `Files` section: add `src/main/pi.js`, `src/main/dns/`,
  `src/main/pi-services.js`; update the `pihole.js` line to reflect the
  split (or remove it if the file is fully absorbed — confirm during
  implementation which pieces remain, if any, under the old filename).

## Testing

- `scripts/test-discovery.js`-style manual run isn't applicable here (no
  network scan changes); verification is manual, against the real Pi:
  DNS backend detection picks AdGuard Home correctly; DHCP leases pull from
  AdGuard's own status endpoint (or show the correct empty state if AdGuard
  isn't running DHCP); apt check/upgrade run and their disruptive-action
  confirmation fires; terminal connects, runs `htop`, resizes correctly,
  Ctrl-C works; service detection surfaces Plex/qBittorrent (and anything
  unrecognized) after credentials are saved and after a manual rescan; tab
  is absent when no Pi has been discovered (test by clearing `pi_discovered`
  or on a fresh profile).
- No automated test suite exists in this repo today; this doesn't introduce
  one — consistent with the project's current practice.

## Icon replacement (separate, bounded — not part of this spec)

Handled directly, no design doc: copy `option-a-grid/build/icon.png` →
`build/icon.png`, `favicon/favicon-32.png` → `src/renderer/favicon-32.png`
(+ `<link rel="icon">` in `index.html`), `tray/` → `build/tray/`, update
`trayIconPath()`/`createTray()` in `src/main/index.js` for light/dark tray
art. Verified with `npm run build:win`.

## Phase 8 items — promoted, now in scope

Implementation notes for each, grounded in the actual current schema
(`src/main/db.js`) and discovery pipeline (`src/main/discovery.js`):

1. **Online/offline history sparkline per device.** `sightings` already
   logs seen/unseen events with timestamps — no schema change. New query
   `db.js#deviceUptimeHistory(mac, days)` bucketing sightings into
   online-ratio-per-day; render as a small inline SVG sparkline in the
   detail panel (no charting library needed for this shape).
2. **New-device desktop notification.** Hook into the existing scan merge
   in `discovery.js`/`db.js` (wherever a device row is first inserted —
   i.e. no prior `sightings` row for that MAC): fire the already-imported
   `Notification` API. Respect the existing "notify" preference toggle.
3. **Posture-score history.** New table `audit_runs (id INTEGER PRIMARY
   KEY, ts INTEGER, score INTEGER, counts_json TEXT)`, one row inserted at
   the end of `audit.run()`. Security view adds a small trend line (reuse
   the sparkline approach from #1) above the current score.
4. **Full DB backup/restore.** New IPC `db:backup` (→
   `dialog.showSaveDialog`, copy the sqlite file), `db:restore` (→
   `dialog.showOpenDialog`, copy over, then relaunch). Credentials table:
   included by default but flagged in the UI that `safeStorage` ciphertext
   only decrypts on the same Windows account/machine it was created on —
   restoring onto a different PC will show those credentials as
   present-but-undecryptable, not silently wrong. A checkbox lets the user
   exclude the credentials table from the backup instead.
5. **Scan-diff digest notification.** The existing config-drift check
   already computes what changed between scans; add a `Notification` call
   summarizing counts ("3 new, 1 vanished, 2 ports changed") gated by the
   same "notify" preference as #2, fired once per scan when the diff is
   non-empty.
6. **Wake-on-LAN.** New `src/main/wol.js`: build the standard 102-byte
   magic packet (6×`0xFF` + target MAC×16) and send via a UDP `dgram`
   socket to the LAN broadcast address, port 9. New IPC `device:wake`;
   button appears in the detail panel for any device with a known MAC,
   disabled with a tooltip explaining WOL must be enabled in that device's
   own BIOS/OS to work (can't be verified remotely, so not claimed).
7. **Device tags/groups.** New column `devices.tags TEXT` (JSON array,
   default `[]`). Small tag editor in the detail panel (add/remove
   free-text tags, no fixed vocabulary — user's own words). Inventory gets
   a tag filter chip row (same pattern as the existing type/status
   filters); Topology colors device dots by first tag when present.
8. **Advertised-services list per device.** Today `discovery.js` keeps only
   the single best `mdnsHit`/`ssdpHit` per IP for naming purposes and
   discards the rest (`delete d.mdnsHit; delete d.ssdpHit` at merge time).
   Change the merge to also collect *all* mDNS service types and SSDP ST
   values seen for that IP into an array, stored as new column
   `devices.services TEXT` (JSON array of `{type, source}`, e.g.
   `{"type":"_airplay._tcp","source":"mdns"}`). Detail panel renders this
   as a chip list. Directly reuses the parsing this build already does for
   the new generic Pi-services detector — same "list what's actually
   advertised, don't guess" principle, just applied to every device instead
   of only the Pi.
9. **LAN latency/health sample.** Lightweight interval timer (default 5
   min, follows the existing auto-scan preference pattern) pinging the
   gateway IP (already known via `detectSubnet()`'s default-gateway route)
   and the Pi if present; store last N samples in a new table
   `latency_samples (ts, target, ms)`; Overview gets a small sparkline per
   target. Not a full network speed test — round-trip latency only, which
   is what actually catches a degrading extender/AP.
10. **Per-client traffic/query trend.** The DNS adapters (`dns/pihole.js`,
    `dns/adguard.js`) already return `talkers[]` per call; persist each
    scan's snapshot into a new table `dns_talkers_history (ts, client_ip,
    client_name, queries)`. Pi tab's DNS stats section adds a trend view
    over the stored history. Explicitly labeled "DNS queries, not
    bandwidth" in the UI — this is a proxy metric, not real traffic, unless
    a future router API supplies actual byte counters (not attempted here;
    the TP-Link local APIs in `tplink.js` don't expose per-client traffic
    today).
