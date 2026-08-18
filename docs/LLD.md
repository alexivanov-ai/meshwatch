# Meshwatch — Low-Level Design

This document is module-level detail for contributors extending Meshwatch:
the complete SQLite schema, the complete IPC channel catalog, the DNS
backend adapter contract, the Pi terminal protocol, and the service-detection
catalog format. Everything here was derived by reading the current source
files listed under each section — not from planning documents, which
describe intent at the time a task was written and do not reflect
self-corrections made during implementation. See `docs/HLD.md` for the
architecture-level picture this document assumes.

Nothing below names an IP, hostname, device model, or other detail specific
to any one contributor's network.

## 1. Database schema

Source: `src/main/db.js`. SQLite via `better-sqlite3`, opened with
`journal_mode = WAL`, stored at `app.getPath("userData")/meshwatch.db` — never
inside the project tree. `init()` runs `CREATE TABLE IF NOT EXISTS` for every
table below, then a lightweight column migration for `devices` (`ALTER TABLE
... ADD COLUMN` for any of a fixed list of columns not already present — safe
to run against both a fresh database and one created before those columns
existed), then a one-time settings-key migration (`migrateLegacyPiKeys()`,
see §1.9).

`checkpoint()` flushes the WAL sidecar into the main db file
(`wal_checkpoint(TRUNCATE)`) before a backup or restore copies the file
directly. `close()` closes the connection; it is only ever called
immediately before `app.exit()` during a restore, since nothing else in the
process can use `db` once closed.

### 1.1 `devices`

Primary key `mac`. One row per device ever seen; `recordScan()` upserts on
every scan rather than replacing the table, so history-bearing columns
(`first_seen`, `note`, `name_override`, `tags`, `watched`) survive a device
going briefly offline.

| Column | Type | Purpose |
| --- | --- | --- |
| `mac` | TEXT PK | Device MAC address — the identity every subsystem merges on. |
| `ip` | TEXT | Most recently observed IPv4 address. |
| `name` | TEXT | Discovered display name (DHCP hostname / mDNS / SNMP `sysName` / web title / model) — never the OUI vendor string. Overwritten by every scan; see `name_override` for the user-controlled version. |
| `vendor` | TEXT | OUI vendor lookup. Preserved across scans if a later scan yields none (`COALESCE`). |
| `model` | TEXT | Matched known model, only ever set via `discovery.js`'s `matchKnown()` on discovered evidence — never a guess. |
| `type` | TEXT | Inferred device role (e.g. gateway, dns-dhcp, switch, client). Preserved across scans if a later scan yields none. |
| `parent_mac` | TEXT | MAC of the topology parent (uplink) this device was attributed to. |
| `parent_estimated` | INTEGER DEFAULT 0 | 1 if `parent_mac` is inferred rather than confirmed (e.g. SNMP forwarding-table match). |
| `link` | TEXT | Link description used by the topology view (e.g. `"WAN"` for the gateway). |
| `signal` | TEXT | Signal-strength/link-quality string, where available. |
| `firmware` | TEXT | Current firmware version, if read from a device API. Preserved across scans if a later scan yields none. |
| `firmware_latest` | TEXT | Latest known firmware version for comparison, where available. |
| `firmware_source` | TEXT | Where `firmware` came from (e.g. `"dns backend API"`, `"manual"`) — never fabricated. |
| `firmware_manual` | TEXT | User-entered firmware override, set via `devices:firmwareManual`. |
| `end_of_support` | TEXT | End-of-support label for known legacy hardware. |
| `control` | TEXT | How this device can be managed (e.g. `"ssh"`), or null. |
| `estimated` | INTEGER DEFAULT 0 | 1 if the device's identity/label is an estimate — the UI-visible marker required by Hard Rule 4. |
| `matched_by` | TEXT | Which discovered signal justified a `config/devices.json` match (confirmed IP, default-gateway route, web title, SNMP sysName/sysDescr). |
| `web_reachable` | INTEGER DEFAULT 0 | 1 if the port-80 web probe got a response. |
| `web_title` | TEXT | `<title>` observed by the web probe. |
| `web_server` | TEXT | `Server` header observed by the web probe. |
| `web_login_form` | INTEGER DEFAULT 0 | 1 if the probed page looked like a login form (feeds the credential-vault "has login page" signal). |
| `note` | TEXT | Free-text user note, set via `devices:note`. |
| `first_seen` | INTEGER | Epoch ms of the first scan that recorded this MAC. |
| `last_seen` | INTEGER | Epoch ms of the most recent scan that saw this MAC. |
| `name_override` | TEXT | User rename (`devices:rename`); takes precedence over the discovered `name` wherever the app displays a device. |
| `open_ports` | TEXT (JSON) | JSON array of discovered open ports. Preserved across scans if a later scan yields none. |
| `query_count` | INTEGER | DNS queries attributed to this device, matched from the DNS backend's "top talkers" by IP or name during discovery. |
| `clients` | INTEGER | Count of other devices whose `parent_mac` points at this one — a topology child count, meaningful for switches/APs. |
| `watched` | INTEGER DEFAULT 0 | 1 if the user toggled "watch" on this device — join/leave events for a watched device trigger a desktop notification. |
| `blocked` | INTEGER DEFAULT 0 | 1 if this device's internet access is currently blocked via the DNS backend (`pi:block`). |
| `ssdp_st` | TEXT | SSDP search-target string observed for this device, if any. |
| `tags` | TEXT (JSON) DEFAULT `'[]'` | JSON array of user-assigned tags (`device:setTags`). |
| `services` | TEXT (JSON) DEFAULT `'[]'` | JSON array of `{type, source}` records deduplicated from this device's own mDNS service types and SSDP search targets — **not** the same thing as the `pi_services` table (§1.6), which is a self-hosted-service catalog match specific to the Pi's open ports. |

`recordScan()` also deletes any row whose `ip` is a broadcast/network address
(`*.0`, `*.255`, `255.255.255.255`, `0.0.0.0`) left by older builds, and
`listDevices()` additionally filters those out of its result set as a second
safety net.

### 1.2 `sightings`

| Column | Type | Purpose |
| --- | --- | --- |
| `id` | INTEGER PK AUTOINCREMENT | Row id. |
| `mac` | TEXT | Device MAC. |
| `ip` | TEXT | IP at the time of this sighting. |
| `seen_at` | INTEGER | Epoch ms. |
| `method` | TEXT | `+`-joined list of discovery methods that saw it this scan (e.g. `"arp+mdns"`). |

Indexed on `mac`. One row is inserted per device per scan; `deviceUptimeHistory()`
buckets these by day to drive the per-device uptime sparkline, and
`listDevices()` reads the most recent row per MAC to populate each device's
`methods` array.

### 1.3 `findings`

| Column | Type | Purpose |
| --- | --- | --- |
| `id` | INTEGER PK AUTOINCREMENT | Row id. |
| `mac` | TEXT | Device the finding is about. |
| `severity` | TEXT | Finding severity. |
| `title` | TEXT | Short finding title. |
| `detail` | TEXT | Longer explanation. |
| `reference` | TEXT | Reference/citation, if any (never a fabricated CVE — see Hard Rule 3). |
| `action` | TEXT | Suggested remediation. |
| `found_at` | INTEGER | Epoch ms. |
| `resolved_at` | INTEGER | Epoch ms, or null while open. |

This table is written by `src/main/audit.js` (not read in this pass); it is
listed here for schema completeness since `audit.js` is part of the same
subsystem as `audit_runs` and `finding_dismissals` below.

### 1.4 `credentials`

| Column | Type | Purpose |
| --- | --- | --- |
| `mac` | TEXT PK | Device MAC the login belongs to. |
| `label` | TEXT | User-facing label. |
| `username` | TEXT | Saved username (plaintext — usernames are not secret). |
| `password_enc` | BLOB | Ciphertext from Electron's `safeStorage` (OS DPAPI on Windows). Never plaintext at rest. |
| `updated_at` | INTEGER | Epoch ms. |

Encryption/decryption lives in `src/main/credentials.js`; `db.js` only stores
and retrieves the blob. `listCredentialMeta()` deliberately selects
`mac, label, username, updated_at` — never `password_enc` — so the renderer's
metadata-only view can be backed directly by that query.

### 1.5 `settings`

| Column | Type | Purpose |
| --- | --- | --- |
| `key` | TEXT PK | Setting name. |
| `value` | TEXT | Setting value, always stored as text. |

Generic key/value store. Holds app preferences (`prefs_json`), remembered Pi
state (`pi_discovered`, `pi_mac`, `pi_ip`, `pi_ssh_port`, `pi_ssh_user`,
`pi_ssh_key`), the cached DNS backend name (`pi_dns_backend`), and
base64-encoded encrypted app-level secrets (`secret:<key>`, e.g.
`secret:dns_api` — see `credentials.js`'s `setAppSecret`/`getAppSecret`).

### 1.6 `finding_dismissals`

| Column | Type | Purpose |
| --- | --- | --- |
| `key` | TEXT PK | `rule:mac` composite key identifying one finding instance. |
| `dismissed_at` | INTEGER | Epoch ms. |

A dismissed finding is excluded from the posture score until
`audit:restore` deletes its row here. Survives re-runs of the audit, since
the same `rule:mac` key recurs across runs.

### 1.7 `pi_services`

| Column | Type | Purpose |
| --- | --- | --- |
| `mac` | TEXT | Part of composite PK. The Pi's MAC. |
| `port` | INTEGER | Part of composite PK. Listening port discovered on the Pi. |
| `name` | TEXT | Matched service name, or `"Unknown service"`. |
| `category` | TEXT | Matched service category, or `"unknown"`. |
| `title` | TEXT | Observed HTTP `<title>` for that port, if any. |
| `updated_at` | INTEGER | Epoch ms. |

Composite primary key `(mac, port)`. `saveServices()` does a full
delete-then-insert per MAC on every `discoverServices()` run (see §5), so a
port that stops listening between scans doesn't linger as a stale entry.

### 1.8 `audit_runs`

| Column | Type | Purpose |
| --- | --- | --- |
| `id` | INTEGER PK AUTOINCREMENT | Row id. |
| `ts` | INTEGER | Epoch ms of the run. |
| `score` | INTEGER | Posture score for that run. |
| `counts_json` | TEXT (JSON) | Severity-bucketed finding counts for that run. |

One row per `audit:run` invocation, so the Security view can plot a score
trend rather than only the latest number.

### 1.9 `latency_samples`

| Column | Type | Purpose |
| --- | --- | --- |
| `id` | INTEGER PK AUTOINCREMENT | Row id. |
| `ts` | INTEGER | Epoch ms. |
| `target` | TEXT | What was pinged (e.g. the gateway, the Pi). |
| `ms` | INTEGER | Round-trip time in milliseconds; null if the sample timed out. |

Indexed on `(target, ts)`. Written on a fixed 5-minute interval by
`latency.js`'s `sampleOnce()` (independent of the user-configurable scan
interval), read by `latency:history`.

### 1.10 `dns_talkers_history`

| Column | Type | Purpose |
| --- | --- | --- |
| `id` | INTEGER PK AUTOINCREMENT | Row id. |
| `ts` | INTEGER | Epoch ms — shared by every row inserted from the same `pi:stats` call, so a snapshot's talkers can be regrouped by timestamp. |
| `client_ip` | TEXT | Talker's IP. |
| `client_name` | TEXT | Talker's name, if the DNS backend reported one. |
| `queries` | INTEGER | Query count in that snapshot. |

Indexed on `(client_ip, ts)`. One snapshot is recorded on every successful
`pi:stats` call (see §2.6), driving the per-client DNS query trend on click
in the Overview view.

### 1.11 Legacy-key migration (`migrateLegacyPiKeys`)

Runs once at every `init()`. Copies six `pihole_*` setting keys to their
`pi_*` equivalents (`pihole_discovered`→`pi_discovered`,
`pihole_mac`→`pi_mac`, `pihole_ip`→`pi_ip`, `pihole_ssh_port`→`pi_ssh_port`,
`pihole_ssh_user`→`pi_ssh_user`, `pihole_ssh_key`→`pi_ssh_key`) and one
credential-vault secret key (`secret:pihole_api`→`secret:dns_api`), but only
when the new key doesn't already exist — so installs that predate the
Pi-hole→AdGuard-agnostic rename keep their remembered Pi/DNS-backend state,
and the migration is a no-op on every subsequent launch.

## 2. IPC channel catalog

Source of truth: every `ipcMain.handle(...)` / `ipcMain.on(...)` call in
`src/main/index.js` (64 registrations, confirmed by direct count against
this document — see §2.9 for the cross-check) and every corresponding method
in `src/preload.js`. All `invoke` channels are request/response; `pi:term:*`
and `shell:open` are noted individually where they deviate from that shape.

Renderer access is always via `window.meshwatch.<method>()`, never a raw
channel name — the preload column below is the method name, or "—" if no
preload wrapper exists (renderer cannot reach that channel today).

### 2.1 Scan

| Channel | Type | Request | Response | Preload |
| --- | --- | --- | --- | --- |
| `scan:run` | invoke | none | `Device[]` (final `listDevices()` result) | `scan()` |

Push events (not `ipcMain` channels — `win.webContents.send`, subscribed via
`onScanProgress`/`onScanFinished`):

- `scan:started` — `{ reason }`
- `scan:progress` — `{ stage, detail }`, streamed per discovery stage
- `scan:finished` — `{ count, newDevices }`

### 2.2 Devices / device

| Channel | Type | Request | Response | Preload |
| --- | --- | --- | --- | --- |
| `devices:list` | invoke | none | `Device[]` | `getDevices()` |
| `devices:topology` | invoke | none | topology graph from `discovery.topology()` | `getTopology()` |
| `devices:drift` | invoke | none | drift-warning array from `discovery.detectDrift()` | `getDrift()` |
| `devices:note` | invoke | `{ mac, note }` | `{ ok: true }` | `setNote(mac, note)` |
| `devices:rename` | invoke | `{ mac, name }` | `{ ok, nameOverride? , reason? }` | `renameDevice(mac, name)` |
| `devices:firmwareManual` | invoke | `{ mac, version }` | `{ ok: true }` | `setFirmwareManual(mac, version)` |
| `devices:watch` | invoke | `{ mac, watched }` | `{ ok: true }` | `watchDevice(mac, watched)` |
| `device:setTags` | invoke | `{ mac, tags }` | `{ ok: true }` | `setDeviceTags(mac, tags)` |
| `device:uptimeHistory` | invoke | `{ mac, days }` | `{ day, onlineRatio }[]` | `uptimeHistory(mac, days)` |
| `device:wake` | invoke | `{ mac }` | `wol.wake()` result | `wakeDevice(mac)` |

### 2.3 Audit

| Channel | Type | Request | Response | Preload |
| --- | --- | --- | --- | --- |
| `audit:run` | invoke | none | `audit.run(devices)` result (findings + score) | `getAudit()` |
| `audit:dismiss` | invoke | `{ key }` | `audit.dismiss()` result | `dismissFinding(key)` |
| `audit:restore` | invoke | `{ key }` | `audit.restore()` result | `restoreFinding(key)` |
| `audit:history` | invoke | `{ limit }` | `{ ts, score, counts }[]` | `auditHistory(limit)` |

### 2.4 Latency / talkers

| Channel | Type | Request | Response | Preload |
| --- | --- | --- | --- | --- |
| `latency:history` | invoke | `{ target, limit }` | `{ ts, ms }[]` | `latencyHistory(target, limit)` |
| `talker:history` | invoke | `{ clientIp, limit }` | `{ ts, queries }[]` | `talkerHistory(clientIp, limit)` |

### 2.5 Subnet / preferences / theme

| Channel | Type | Request | Response | Preload |
| --- | --- | --- | --- | --- |
| `subnet:get` | invoke | none | `discovery.detectSubnet()` result | `getSubnet()` |
| `prefs:get` | invoke | none | prefs object (see `DEFAULT_PREFS` in `db.js`) | `prefs.get()` |
| `prefs:set` | invoke | prefs patch | `{ ok: true, prefs }` | `prefs.set(patch)` |
| `app:theme` | invoke | `{ theme }` | `{ ok: true, theme, resolved }` | `setTheme(theme)` |

### 2.6 Pi (SSH host, DNS backend, admin)

| Channel | Type | Request | Response | Preload |
| --- | --- | --- | --- | --- |
| `pi:state` | invoke | none | `db.getPiState()` result | `pi.state()` |
| `pi:prefs` | invoke | `{ sshPort?, sshUser? }` | `{ ok, state? , reason? }` | `pi.setPrefs(prefs)` |
| `pi:target` | invoke | none | `pi.resolveTarget()` result (`host, port, user, mac, discovered, online, keyPath`) | `pi.target()` |
| `pi:backend` | invoke | none | `{ name, version }` or null (`dns.getBackendInfo()`) | `pi.backend()` |
| `pi:stats` | invoke | none | DNS backend stats shape (§3); also records talkers into `dns_talkers_history` | `pi.stats()` |
| `pi:leases` | invoke | none | `{ ip, mac, hostname, expiry, expires }[]` | `pi.leases()` |
| `pi:hasPassword` | invoke | none | boolean | `pi.hasPassword()` |
| `pi:setPassword` | invoke | `{ password }` | `{ ok: true }` / `{ ok: false, reason }` | `pi.setPassword(password)` |
| `pi:pickKey` | invoke | none | `{ ok, path? , cancelled? }` (opens a native file dialog) | `pi.pickKey()` |
| `pi:exec` | invoke | `{ command }` | `{ output: string[], code, target? }` (via `confirmedExec()` in `index.js` — runs `pi.isDisruptive(command)` against `pi.js`'s `DISRUPTIVE` list first and shows a confirmation dialog before executing if it matches, per Hard Rule 5) | `pi.exec(command)` — not currently called from any renderer UI (the one-shot command-runner form that used it was removed; the embedded terminal, §4, is the interactive replacement) but still reachable through the bridge |
| `pi:apt:check` | invoke | none | `{ ok, count, packages }` / `{ ok: false, reason }` | `pi.aptCheck()` |
| `pi:apt:upgrade` | invoke | none | same shape as `pi:exec`, gated behind the disruptive-command dialog; streams live output as it runs (see push events below) before resolving with the full buffered result | `pi.aptUpgrade()` |
| `pi:apt:apps` | invoke | none | `{ ok, apps }` / `{ ok: false, reason }` | `pi.installedApps()` |
| `pi:rebootRequired` | invoke | none | boolean | `pi.rebootRequired()` |
| `pi:hostStats` | invoke | none | `{ uptime, diskUsedPercent, diskUsed, diskTotal, cpuCores, loadAvg }` | `pi.hostStats()` |
| `pi:services:list` | invoke | none | cached `pi_services` rows (§1.7) with `url` added | `pi.servicesList()` |
| `pi:services:rescan` | invoke | none | fresh `discoverServices()` result, also persisted | `pi.servicesRescan()` |
| `pi:block` | invoke | `{ mac, blocked }` | `dns.blockClient()` result; sets `devices.blocked` on success | `pi.block(mac, blocked)` |

Push event (not an `ipcMain` channel — `win.webContents.send`, subscribed via `pi.onAptProgress`): `pi:apt:progress` — `{ chunk }`, one per raw stdout/stderr chunk received over SSH while `pi:apt:upgrade` is running, fired from the `onChunk` callback threaded through `confirmedExec()` → `pi.exec()`. `pi:exec` itself accepts the same `onChunk` parameter in `pi.js` but `index.js` only wires it up for the apt-upgrade call today.

Terminal channels (`pi:term:*`) are documented separately in §4.

### 2.7 TP-Link

| Channel | Type | Request | Response | Preload |
| --- | --- | --- | --- | --- |
| `tplink:capabilities` | invoke | `{ ip }` | `tplink.capabilities()` result for the device at that IP | `tplink.capabilities(ip)` |
| `tplink:action` | invoke | `{ ip, action, args }` | `tplink.action()` result, gated behind a disruptive-action confirmation dialog when `tplink.isDisruptive(action)` | `tplink.action(ip, action, args)` |

### 2.8 Credentials

| Channel | Type | Request | Response | Preload |
| --- | --- | --- | --- | --- |
| `credentials:available` | invoke | none | boolean (`safeStorage.isEncryptionAvailable()`) | `credentials.available()` |
| `credentials:save` | invoke | `{ mac, label, username, password }` | `{ ok, reason? }`; also best-effort triggers a Pi service rescan if the saved MAC is the remembered Pi | `credentials.save(mac, label, username, password)` |
| `credentials:list` | invoke | none | `{ mac, label, username, updated_at }[]` — never a password | `credentials.list()` |
| `credentials:has` | invoke | `{ mac }` | boolean | `credentials.has(mac)` |
| `credentials:remove` | invoke | `{ mac }` | `{ ok: true }` | `credentials.remove(mac)` |

### 2.9 Browser (in-app admin-page view) / shell

| Channel | Type | Request | Response | Preload |
| --- | --- | --- | --- | --- |
| `browser:open` | invoke | `{ url }` | `browser.open()` result | `browser.open(url)` and `openExternal(url)` (both wrap this same channel) |
| `browser:close` | invoke | none | `browser.close()` result | `browser.close()` |
| `browser:back` | invoke | none | `browser.back()` result | `browser.back()` |
| `browser:forward` | invoke | none | `browser.forward()` result | `browser.forward()` |
| `browser:reload` | invoke | none | `browser.reload()` result | `browser.reload()` |
| `browser:bounds` | invoke | bounds object | `browser.setBounds()` result | `browser.setBounds(bounds)` |
| `browser:url` | invoke | none | `browser.getUrl()` result | `browser.getUrl()` |
| `shell:open` | invoke | `{ url }` | `{ ok: false, reason: "not a local address" }` if not a LAN URL, else `browser.open()` result | **none** — registered in `index.js` but not wrapped in `preload.js`, and not called anywhere in `src/renderer/`. Currently dead from the renderer's side; `openExternal`/`browser.open` are the reachable equivalent. |

Push events for the browser view (`win.webContents.send`, subscribed via
`browser.on(channel, cb)` in preload, which maps friendly names to the
`browser:*` event channels): `opened`→`browser:opened`,
`closed`→`browser:closed`, `navigated`→`browser:navigated`,
`title`→`browser:title`, `loading`→`browser:loading`, `error`→`browser:error`,
`needBounds`→`browser:need-bounds`. The `error` payload is
`{ code, desc, url }` from Chromium's `did-fail-load`; the renderer ignores
`code === -3` (`ERR_ABORTED`, fired on ordinary redirects/cancellations, not
a real failure) and otherwise toasts `desc` plus the numeric `code`.

`browser:open` is reachable two ways from the renderer: the buttons/links
that open a device's admin page, and the in-app browser's own address-bar
input (`#browser-url`) — editable, not read-only — which normalizes a typed
value to `http://` if no scheme was given and calls the same channel on
Enter. Either path is subject to the same `isLanUrl()` allowlist in
`browser.js`; a rejected address reverts the field to the real current URL.

`browser.js`'s `WebContentsView` also accepts a self-signed TLS certificate
on `certificate-error`, but only when the navigating URL passes the same
`isLanUrl()` check — never for a public address. This exists because
router/switch admin UIs (the gateway most of all) commonly force HTTPS with
a self-signed cert, which Electron rejects by default with no visible
explanation to the user beyond a failed load.

### 2.10 Update / app info

| Channel | Type | Request | Response | Preload |
| --- | --- | --- | --- | --- |
| `update:check` | invoke | none | `updater.checkNow()` result | `checkForUpdate()` |
| `update:install` | invoke | none | `updater.installNow()` result | `installUpdate()` |
| `app:version` | invoke | none | `app.getVersion()` string | `version()` |
| `app:versions` | invoke | none | `process.versions` object | `versions()` |

Push event: `update:status` — `{ state: "checking"|"available"|"current"|"downloading"|"ready"|"error", ... }`, subscribed via `onUpdateStatus`.

### 2.11 Database backup / restore

| Channel | Type | Request | Response | Preload |
| --- | --- | --- | --- | --- |
| `db:backup` | invoke | `{ includeCredentials }` | `{ ok, path? , cancelled? }`; opens a native save dialog, checkpoints the WAL, copies the db file, optionally strips `credentials` from the copy only | `db.backup(includeCredentials)` |
| `db:restore` | invoke | none | `{ ok: false, cancelled?/reason? }` on any non-success path; on success the process relaunches and never returns a response | `db.restore()` |

`db:restore` refuses while a scan is in progress, checkpoints and closes the
live connection, copies the chosen file to a temp path and renames it into
place (atomic on the same volume), then unconditionally calls
`app.relaunch()` + `app.exit(0)` — a fresh process re-opens whatever ended up
on disk whether the copy succeeded or not, since the live connection is
already closed either way.

## 3. DNS backend adapter contract

Source: `src/main/dns/index.js`, `src/main/dns/ftl.js`, `src/main/dns/adguard.js`.

`dns/index.js` never assumes which DNS/DHCP product runs on the discovered
Pi. `detectBackend()` probes both concurrently:

- `probeAdguard(host)` — GET `http://<host>/control/status`; treats a 200
  with a `dns_addresses` array, or a bare 401/403 (needs auth but is
  recognizably AdGuard), as a hit.
- `probeFtl(host)` — GET `http://<host>/admin/api.php?status`; any JSON
  response is a hit.

The winner (`"adguard"`, `"ftl"`, or `"unknown"`) is cached in
`settings.pi_dns_backend`. Every subsequent call goes through
`adapterFor(cachedBackend())`, which returns the matching adapter module or
null — so adding a third backend is a new adapter file plus one branch in
`adapterFor()`, not a change to any caller.

Both adapter modules export the same five-function shape:

| Function | Shape | Notes |
| --- | --- | --- |
| `stats()` | `async () => StatsResult` | See below. |
| `leases()` | `async () => Lease[]` | DHCP lease list. |
| `blockClient(ip, { blocked })` | `async (string, {blocked: boolean}) => { ok, blocked?, via?, reason? }` | Per-client internet block/unblock. |
| `setApiPassword(password)` | `(string\|null\|"") => { ok, reason? }` | Stores/clears the backend's app secret (`secret:dns_api`) via `credentials.js`. |
| `hasApiPassword()` | `() => boolean` | Whether a password is currently saved. |

**`StatsResult` shape**, common to both adapters (fields vary slightly —
noted where they differ):

```text
{
  available: boolean,
  reason?: string,            // present when available: false
  needsPassword?: boolean,
  host, sshPort, sshUser,
  version?: 5 | 6 | "adguard",
  queriesToday, blockedToday, blockedPercent,
  blocklist,                  // gravity domain count (ftl only; null for adguard)
  firmware,                   // backend version string, where known
  hostNote,                   // short human-readable status line
  blocked: [{ domain, hits }],
  talkers: [{ name, ip?, queries }],
  ftlUptime?                  // ftl v6 only
}
```

**`Lease` shape**, common to both adapters:

```text
{ ip, mac, hostname, expiry, expires }
```

`expiry` is the raw backend value (epoch seconds/ms, or an ISO date for
AdGuard's static leases); `expires` is a pre-formatted human string
(`"expired"`, `"12 m"`, `"3 h"`, `"static"`, etc.).

**`dns/ftl.js`** supports both Pi-hole API generations: v6 (session-based,
`X-FTL-SID` header + cookie, obtained via `POST /api/auth`) is tried first
via `ensureV6()`; if no password/session is available it falls back to the
v5 token-based `summaryRaw` endpoint. Leases come from the v6 API first
(`GET /api/dhcp/leases`), falling back to `cat /etc/pihole/dhcp.leases` over
SSH (via `pi.exec`) if the API path yields nothing. `blockClient()` on v6
maintains a dedicated `meshwatch-blocked` group with a catch-all deny regex,
adding/removing the target client from that group — a DNS-level block only;
it does not affect a device that changes its configured DNS server.

**`dns/adguard.js`** authenticates via `POST /control/login` with a fixed
username (`"admin"`) and the saved password, storing the resulting
`agh_session` cookie. Leases come from `GET /control/dhcp/status` (both
`leases` and `static_leases`). `blockClient()` edits AdGuard's
allow/disallow access list (`GET`/`POST /control/access/*`) — the only block
primitive its API exposes, with the same DNS-level caveat as the Pi-hole
adapter.

## 4. Terminal protocol (`pi:term:*`)

Source: `src/main/pi.js` (`termStart`/`termInput`/`termResize`/`termStop`)
and the four `pi:term:*` registrations in `src/main/index.js`.

Unlike every other Pi channel, terminal channels are `ipcMain.on`/
`ipcRenderer.send` (fire-and-forget), not `invoke`/`handle` — a shell is a
stream, not a request/response call.

**Session lifecycle:**

1. Renderer calls `meshwatch.terminal.start(rows, cols)` →
   `ipcRenderer.send("pi:term:start", { rows, cols })`.
2. In `index.js`'s handler: if `activeTermSession` is already set, it is
   stopped first (`pi.termStop(activeTermSession)`) — **only one terminal
   session may be open at a time**, established during this session's
   security review so a stray or forgotten tab can't leave a second SSH
   shell connected in the background. A fresh `sessionId`
   (`crypto.randomUUID()`) is generated and immediately stored as the new
   `activeTermSession` before the SSH connection even starts.
3. The handler replies with `event.reply("pi:term:started", { sessionId })`
   and calls `pi.termStart(sessionId, { rows, cols }, onData, onClose)`.
4. `pi.termStart()` resolves the SSH target (`pi.resolveTarget()`), refuses
   a non-LAN host (`lan.isPrivateIp`) or a missing key/password exactly like
   `pi.exec()`, then opens an `ssh2` `Client`, registers the session in an
   in-module `Map` **before** connecting (so a `termStop` that arrives while
   still connecting can still find and tear it down), and on `"ready"`
   requests a `shell` PTY (`term: "xterm-256color"`, requested `rows`/`cols`).
5. Every chunk of shell output/stderr is forwarded via the `onData` callback,
   which `index.js` wires to `event.sender.send("pi:term:data", { sessionId, chunk })`.
6. `meshwatch.terminal.input(sessionId, data)` →
   `ipcRenderer.send("pi:term:input", { sessionId, data })` → `pi.termInput()`
   writes raw bytes to the stream.
7. `meshwatch.terminal.resize(sessionId, rows, cols)` →
   `ipcRenderer.send("pi:term:resize", ...)` → `pi.termResize()` calls the
   stream's `setWindow(rows, cols, 0, 0)`.
8. Session end, either from the remote side closing the stream or from
   `meshwatch.terminal.stop(sessionId)` (`ipcRenderer.send("pi:term:stop", { sessionId })`
   → `pi.termStop()`, which closes the stream and ends the connection):
   the `onClose` callback fires with an error string or `null`, which
   `index.js` forwards as `event.sender.send("pi:term:closed", { sessionId, error })`
   and clears `activeTermSession` if it still matches this session's id.

**Message shapes:**

| Direction | Channel | Payload |
| --- | --- | --- |
| renderer → main | `pi:term:start` | `{ rows, cols }` |
| main → renderer | `pi:term:started` | `{ sessionId }` |
| renderer → main | `pi:term:input` | `{ sessionId, data }` (raw keystrokes/paste) |
| renderer → main | `pi:term:resize` | `{ sessionId, rows, cols }` |
| main → renderer | `pi:term:data` | `{ sessionId, chunk }` (stdout+stderr interleaved, UTF-8) |
| renderer → main | `pi:term:stop` | `{ sessionId }` |
| main → renderer | `pi:term:closed` | `{ sessionId, error: string \| null }` |

## 5. Service-detection catalog (`pi-services.js`)

Source: `src/main/pi-services.js`.

`discoverServices()` runs `ss -tln` over SSH (falling back to `netstat -tln`
if `ss` is missing), extracts every locally-listening `host:port` from lines
containing `LISTEN`, filters out ports already accounted for elsewhere in
the app (`excludedPorts()` — the configured SSH port, 22, 53, 80, 443), then
for each remaining port does a plain GET (`probeTitle()`, 3s timeout,
`<title>` extraction only — same non-invasive rule as `discovery.js`'s
`webProbe()`) and matches the result against `KNOWN_SERVICES` via
`matchCatalog()`.

**`KNOWN_SERVICES` entry shape:**

```text
{
  port: number,        // default port the service listens on
  titleRe?: RegExp,     // optional: confirm/override by observed <title>
  name: string,         // friendly display name
  category: string       // e.g. "media", "downloads", "monitoring", "sync", "management", "home-automation"
}
```

Thirteen entries as of this pass (Plex, qBittorrent, Transmission, Deluge,
Portainer, Home Assistant, Sonarr, Radarr, Bazarr, Jellyfin, Grafana,
Syncthing, Uptime Kuma).

**Matching order** (`matchCatalog(port, title)`): an exact port match whose
entry has no `titleRe`, or whose `titleRe` matches the observed title, wins
first; failing that, any entry whose `titleRe` matches the observed title
wins regardless of port (a service moved off its default port but still
self-identifies). No match is an expected, ordinary outcome, not an error.

**Unmatched representation** — a listening port with no catalog hit is still
returned and persisted, never dropped and never guessed at (Hard Rule 4):

```text
{ port, name: "Unknown service", category: "unknown", title: <observed title or null>, url }
```

A matched port has the same shape with `name`/`category` from the catalog
entry and `title` still set to whatever was actually observed (a real
observed title is not replaced by the catalog's assumption). Results are
sorted by port, persisted per-Pi-MAC via `db.saveServices()` (full
delete-then-insert, so a port that stops listening doesn't linger — see
§1.7), and exposed to the renderer via `pi:services:list` (cached) and
`pi:services:rescan` (fresh).
