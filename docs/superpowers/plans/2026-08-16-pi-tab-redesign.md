# Pi Tab Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Pi-hole-only "Pi-hole · SSH" tab with a generic, dynamically-detected "Pi" tab (Pi-hole or AdGuard Home, auto-detected), add Pi system administration (apt, installed apps, embedded interactive SSH terminal), generic self-hosted-service auto-detection, and 10 promoted app-wide feature additions — then bring docs (CLAUDE.md, HLD, LLD, README) in line and swap in the new application icons.

**Architecture:** Split `src/main/pihole.js` into a generic Pi-system module (`pi.js`), a DNS-backend adapter pair with a detecting router (`dns/pihole.js`, `dns/adguard.js`, `dns/index.js`), and a new service-discovery module (`pi-services.js`). Rename the `pihole:*` IPC/UI surface to `pi:*`. Renderer gains a real interactive terminal (xterm.js over an SSH PTY stream) and several new panels. Ten smaller, mostly-independent features (history sparklines, notifications, DB backup, WoL, tags, etc.) are layered on top of the existing SQLite schema using the repo's existing lightweight `ALTER TABLE` migration pattern.

**Tech Stack:** Electron (main/renderer/preload, contextIsolation on), better-sqlite3, ssh2, plain HTML/CSS/JS renderer (no framework, no bundler). New dependency: `xterm` (+ `@xterm/addon-fit`) for the embedded terminal — MIT licensed, DOM-only, no native/Node code, safe under the existing sandboxed webview model.

**Spec:** `docs/superpowers/specs/2026-08-16-pi-tab-redesign-design.md` — this plan implements every section of that spec, including the two follow-up directives recorded inline in it (all 10 backlog items promoted; CLAUDE.md scope corrected to describe the app, not the user's infrastructure). The spec's "Repo cleanup for public release" section (git-history rewrite, secret scan) is **explicitly excluded from this plan** — that step requires live, explicit confirmation from the user at the time and must never be run autonomously by a dispatched subagent. Everything else in that section that is *not* destructive (HLD/LLD/README, deleting `design/` from the working tree only) **is** in this plan.

## Global Constraints

- No automated test framework exists in this repo (`package.json` has no test runner). "Test" steps in this plan are either (a) a small standalone Node script following the existing `scripts/test-discovery.js` convention — run directly with `node`, prints output for manual inspection — or (b) manual verification via `npm start` against the user's real Pi at `192.168.1.63`. Do not introduce Jest/Mocha/Vitest; that's out of scope and unrequested.
- `contextIsolation: true`, `nodeIntegration: false` everywhere. All privileged work (SSH, HTTP to LAN, filesystem, secrets) happens in `src/main/*`, crossing to the renderer only through `src/preload.js`. Never widen the preload bridge to expose `ipcRenderer` directly.
- Only scan/connect to this machine's private LAN (`lanhttp.js#isPrivateIp`, already enforced) — never widen this.
- Credentials/secrets never touch a plain file; always through `credentials.js` (`safeStorage`).
- Any command that interrupts DNS/network connectivity (FTL/AdGuard restart, `apt-get upgrade`, reboot, shutdown) must go through the existing disruptive-command confirmation dialog (`pihole:exec`/`pi:exec` handler in `src/main/index.js`) — add new commands to the `DISRUPTIVE` list rather than bypassing it.
- Follow existing code style: no semicolon-free style, no TypeScript, no build step for the renderer, `const`/`let`, small focused functions, comments only where the *why* isn't obvious from the code.
- Every inferred/unconfirmed value shown in the UI must be visibly marked as an estimate (existing `estimated: true` / `est` CSS class pattern) — this applies to the new "Unknown service" rows and any new estimated fields.
- Windows is the primary dev/build target (`npm run build:win`); don't introduce anything POSIX-only in code paths that also run on the developer's Windows machine (SSH/exec against the *Pi* is fine — that's remote and always Linux).

---

## Phase 0 — Icons (independent, do first)

### Task 1: Swap in the new application icons

**Files:**
- Modify: `build/icon.png`, `build/tray/` (new), `src/renderer/favicon-32.png` (new), `src/renderer/index.html:1-7`, `src/main/index.js` (`createTray`/`trayIconPath`, currently around line 56-60)

**Interfaces:**
- Produces: `trayIconPath()` function in `src/main/index.js`, used by `createTray()` and the `nativeTheme.on("updated", …)` listener.

- [ ] **Step 1: Copy the new source art over the repo's build assets**

```bash
cp "C:\Users\Alex\Downloads\Application icon design options\meshwatch-icons\option-a-grid\build\icon.png" "D:\repos\meshwatch\build\icon.png"
mkdir "D:\repos\meshwatch\build\tray"
cp "C:\Users\Alex\Downloads\Application icon design options\meshwatch-icons\option-a-grid\tray\"*.png "D:\repos\meshwatch\build\tray\"
cp "C:\Users\Alex\Downloads\Application icon design options\meshwatch-icons\option-a-grid\favicon\favicon-32.png" "D:\repos\meshwatch\src\renderer\favicon-32.png"
```

- [ ] **Step 2: Add the favicon link to the renderer head**

In `src/renderer/index.html`, inside `<head>` right after the CSP `<meta>` tag (currently line 5):

```html
<link rel="icon" type="image/png" sizes="32x32" href="favicon-32.png">
```

- [ ] **Step 3: Wire theme-aware tray art**

In `src/main/index.js`, replace the existing tray image lookup (`createTray()`, ~line 56-60: `let image = nativeImage.createFromPath(iconPath()); ...`) with:

```js
function trayIconPath() {
  const variant = nativeTheme.shouldUseDarkColors ? "dark" : "light";
  return path.join(__dirname, "..", "..", "build", "tray", "tray-" + variant + "-2x.png");
}

function createTray() {
  let image = nativeImage.createFromPath(trayIconPath());
  if (image.isEmpty()) image = nativeImage.createFromPath(iconPath());
  if (image.isEmpty()) image = nativeImage.createEmpty();
  tray = new Tray(image.resize({ width: 16, height: 16 }));
  // ...existing menu/click wiring below stays as-is...
  nativeTheme.on("updated", () => {
    if (tray) tray.setImage(nativeImage.createFromPath(trayIconPath()).resize({ width: 16, height: 16 }));
  });
}
```

(Keep every other line already inside `createTray()` — this only replaces the image-selection lines and adds the theme listener.)

- [ ] **Step 4: Manual verification**

Run: `npm run build:win`
Expected: completes without error; `make-icon.js` regenerates `build/icon.ico` and `build/installerIcon.ico` from the new `build/icon.png`. Then `npm start` and confirm the taskbar icon, window icon, and system tray icon all show the new art, and the tray icon switches when Windows theme is toggled light/dark.

- [ ] **Step 5: Commit**

```bash
git add build/icon.png build/tray src/renderer/favicon-32.png src/renderer/index.html src/main/index.js
git commit -m "Swap in option-a-grid application icons (app, tray, favicon)"
```

---

## Phase 1 — Foundations: settings migration, module split

### Task 2: Settings-key migration in db.js

**Files:**
- Modify: `src/main/db.js` (add near `init()`, currently ending ~line 58-70, and near `getPiHoleState`/`setPiHolePrefs`, currently ~line 320-397)

**Interfaces:**
- Produces: `migrateLegacyPiKeys()` (called once from `init()`), `getPiState()` (replaces `getPiHoleState()`), `setPiPrefs()` (replaces `setPiHolePrefs()`), `looksLikePi()` (replaces `looksLikePiHole()`), `notePiDiscovery()` (replaces `notePiHoleDiscovery()`).
- Consumes: existing `getSetting(key, fallback)` / `setSetting(key, value)` helpers already in `db.js`.

- [ ] **Step 1: Add the migration function**

In `src/main/db.js`, add near the other settings helpers:

```js
// This install already has pihole_* settings from before the Pi-hole/AdGuard
// rename (the Pi was discovered and confirmed before this rename existed).
// One-time copy so existing users don't lose their remembered Pi.
function migrateLegacyPiKeys() {
  const pairs = [
    ["pihole_discovered", "pi_discovered"],
    ["pihole_mac", "pi_mac"],
    ["pihole_ip", "pi_ip"],
    ["pihole_ssh_port", "pi_ssh_port"],
    ["pihole_ssh_user", "pi_ssh_user"],
    ["pihole_ssh_key", "pi_ssh_key"]
  ];
  for (const [oldKey, newKey] of pairs) {
    const oldVal = getSetting(oldKey, null);
    const newVal = getSetting(newKey, null);
    if (oldVal != null && newVal == null) setSetting(newKey, oldVal);
  }
  // Credential vault secret rename: pihole_api -> dns_api (see credentials.js).
  const oldSecret = getSetting("secret:pihole_api", null);
  const newSecret = getSetting("secret:dns_api", null);
  if (oldSecret != null && newSecret == null) setSetting("secret:dns_api", oldSecret);
}
```

Call it at the end of `init()`, after the table-creation/`ALTER TABLE` block.

- [ ] **Step 2: Rename the Pi-hole-specific functions to generic Pi names**

Rename `looksLikePiHole` → `looksLikePi`, `notePiHoleDiscovery` → `notePiDiscovery`, `getPiHoleState` → `getPiState`, `setPiHolePrefs` → `setPiPrefs` (same bodies, just reading/writing the new `pi_*` setting keys instead of `pihole_*`). Update the `module.exports` list at the bottom of `db.js` to export the new names. Update the internal call in `run()`'s scan pipeline (`notePiHoleDiscovery(devices)`, currently line 140) to `notePiDiscovery(devices)`.

- [ ] **Step 3: Manual verification**

Run: `node -e "process.env.MESHWATCH_TEST=1; const db=require('./src/main/db'); db.init(); db.migrateLegacyPiKeys ? console.log('exported') : console.log('MISSING')"` — actually `migrateLegacyPiKeys` is internal (called by `init()`), so instead verify indirectly: `npm start`, open Preferences, confirm the Pi's SSH port/user still show `2222`/`admin` (proving the migration copied the pre-existing `pihole_ssh_port`/`pihole_ssh_user` values forward).

- [ ] **Step 4: Commit**

```bash
git add src/main/db.js
git commit -m "Rename pihole_* settings to pi_* with a one-time migration for existing installs"
```

### Task 3: Create `src/main/pi.js` (generic Pi-system module)

**Files:**
- Create: `src/main/pi.js`
- Modify: `src/main/pihole.js` (SSH exec/target/disruptive-command logic removed — see Task 5 for full retirement)

**Interfaces:**
- Consumes: `db.getPiState()`, `db.setPiPrefs()` (Task 2), `credentials.reveal(mac)`.
- Produces: `resolveTarget()`, `exec(command)`, `isDisruptive(command)`, `disruptionSeconds(command)`, `sshConnectOptions(t)` — same shapes as the current `pihole.js` exports of the same names, so callers (`index.js`, `discovery.js`) don't need signature changes, only the `require()` path.

- [ ] **Step 1: Move the generic SSH plumbing**

Create `src/main/pi.js` with the `DISRUPTIVE` list, `isDisruptive`, `disruptionSeconds`, `resolveTarget`, `sshConnectOptions`, `exec` functions copied verbatim from the current `src/main/pihole.js` (lines 1-14, 22-42, 288-356), with two changes:
1. `resolveTarget()` now calls `db.getPiState()` instead of `db.getPiHoleState()`.
2. Add the new disruptive commands from Task 8 (`apt-get upgrade`) to the `DISRUPTIVE` array — see Task 8 for the exact entry; for this task, leave the array as the moved original plus a placeholder comment `// apt upgrade entry added in Task 8` so the diff is easy to review, then fill it in when Task 8 lands (do not leave the comment in the final file — Task 8 replaces it).

```js
// src/main/pi.js — generic Raspberry Pi system administration: SSH exec,
// target resolution, disruptive-command gating. DNS-backend-specific logic
// lives in dns/pihole.js and dns/adguard.js, not here.
const fs = require("fs");
const { Client } = require("ssh2");
const db = require("./db");
const credentials = require("./credentials");
const lan = require("./lanhttp");

const DISRUPTIVE = [
  { match: /systemctl\s+restart\s+(pihole-FTL|AdGuardHome)/, seconds: 5 },
  { match: /pihole\s+restartdns/, seconds: 5 },
  { match: /apt(-get)?\s+(upgrade|dist-upgrade|full-upgrade)/, seconds: 0 },
  { match: /\breboot\b/, seconds: 45 },
  { match: /shutdown/, seconds: 999 }
];

function isDisruptive(command) {
  return DISRUPTIVE.some((d) => d.match.test(command));
}

function disruptionSeconds(command) {
  const hit = DISRUPTIVE.find((d) => d.match.test(command));
  return hit ? hit.seconds : 0;
}

function resolveTarget() {
  const state = db.getPiState();
  return {
    host: state.ip || null,
    port: state.sshPort || 22,
    user: state.sshUser || "admin",
    mac: state.mac,
    discovered: state.discovered,
    online: state.online,
    keyPath: db.getSetting("pi_ssh_key") || null
  };
}

function sshConnectOptions(t) {
  const opts = {
    host: t.host,
    port: t.port,
    username: t.user,
    readyTimeout: 8000,
    algorithms: { serverHostKey: ["ssh-ed25519", "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"] }
  };
  if (t.keyPath && fs.existsSync(t.keyPath)) {
    opts.privateKey = fs.readFileSync(t.keyPath);
  } else if (t.mac) {
    const cred = credentials.reveal(t.mac);
    if (cred && cred.password) opts.password = cred.password;
  }
  return opts;
}

function exec(command) {
  const t = resolveTarget();
  if (!t.host) {
    return Promise.resolve({ output: ["No Pi remembered — run a scan first"], code: 1 });
  }
  if (!lan.isPrivateIp(t.host)) {
    return Promise.resolve({ output: ["Refusing SSH to a non-LAN host"], code: 1 });
  }
  const opts = sshConnectOptions(t);
  if (!opts.privateKey && !opts.password) {
    return Promise.resolve({
      output: [
        "SSH is not connected yet.",
        "In Preferences, choose an OpenSSH private key (or save the Pi's login in the credential vault).",
        "Would connect: ssh " + t.user + "@" + t.host + " -p " + t.port,
        "Command: " + command
      ],
      code: 1,
      target: t,
      needsKey: true
    });
  }

  return new Promise((resolve) => {
    const conn = new Client();
    const lines = [];
    let settled = false;
    const done = (result) => {
      if (settled) return;
      settled = true;
      try { conn.end(); } catch (e) { /* ignore */ }
      resolve(result);
    };
    conn.on("ready", () => {
      conn.exec(command, (err, stream) => {
        if (err) return done({ output: [String(err.message || err)], code: 1, target: t });
        stream.on("data", (d) => lines.push(String(d)));
        stream.stderr.on("data", (d) => lines.push(String(d)));
        stream.on("close", (code) => {
          const output = lines.join("").replace(/\r/g, "").split("\n");
          done({ output, code: code == null ? 0 : code, target: t });
        });
      });
    });
    conn.on("error", (e) => done({ output: [String(e.message || e)], code: 1, target: t }));
    try {
      conn.connect(opts);
    } catch (e) {
      done({ output: [String(e.message || e)], code: 1, target: t });
    }
  });
}

module.exports = {
  resolveTarget, sshConnectOptions, exec, isDisruptive, disruptionSeconds,
  get HOST() { return resolveTarget().host; },
  get SSH_PORT() { return resolveTarget().port; }
};
```

(Terminal, apt, and system-stats functions are added to this same file in Tasks 8, 9, and 11 — this task only establishes the module with the moved plumbing.)

- [ ] **Step 2: Manual verification**

Run: `node -e "const pi = require('./src/main/pi.js'); console.log(typeof pi.exec, typeof pi.resolveTarget, typeof pi.isDisruptive)"`
Expected: `function function function`

- [ ] **Step 3: Commit**

```bash
git add src/main/pi.js
git commit -m "Create src/main/pi.js: generic SSH exec/target logic moved out of pihole.js"
```

### Task 4: DNS backend adapters — `dns/pihole.js`, `dns/adguard.js`, `dns/index.js`

**Files:**
- Create: `src/main/dns/pihole.js`, `src/main/dns/adguard.js`, `src/main/dns/index.js`

**Interfaces:**
- Both adapters produce: `stats()`, `leases()`, `blockClient(ip, {blocked})`, `setApiPassword(password)`, `hasApiPassword()` — identical shapes.
- `dns/index.js` produces: `detectBackend(host)`, `stats()`, `leases()`, `blockClient()`, `setApiPassword()`, `hasApiPassword()`, `getBackendInfo()` (returns `{name, version}` or `null`) — this is what `src/main/index.js` and `discovery.js` require going forward (as `require("./dns")`, replacing `require("./pihole")`).
- Consumes: `db.getSetting`/`setSetting`, `lan.request` (from `lanhttp.js`), `credentials.getAppSecret`/`setAppSecret` (via the renamed `dns_api` key from Task 2).

- [ ] **Step 1: Move the existing Pi-hole logic unchanged**

Create `src/main/dns/pihole.js` with the DNS-specific parts of the current `src/main/pihole.js` copied over unchanged except for two renames: `apiPassword()`/`setApiPassword()`/`hasApiPassword()` now read/write the `dns_api` secret name (was `pihole_api`), and `resolveTarget()` is replaced by `require("../pi").resolveTarget()`. Copy: `v6sid`/`v6host` module state, `baseUrls`, `tryJson`, `authV6`, `v6headers`, `v6get`, `v6send`, `ensureV6`, `v5summary`, `parseLeaseLine`, `leaseExpires`, `leasesFromApi`, `leasesFromSsh` (this one now calls `require("../pi").exec(...)` instead of the local `exec`), `leases`, `stats`, `ensureBlockGroup`, `blockClient` — all logic identical to today's `pihole.js`, just re-homed.

```js
// src/main/dns/pihole.js — Pi-hole REST (v5 token or v6 SID) adapter.
// Selected by dns/index.js when the DNS-backend detector matches Pi-hole.
const pi = require("../pi");
const db = require("../db");
const credentials = require("../credentials");
const lan = require("../lanhttp");

let v6sid = null;
let v6host = null;

function apiPassword() {
  return credentials.getAppSecret("dns_api") || null;
}

function setApiPassword(password) {
  if (!password) {
    credentials.deleteAppSecret("dns_api");
    v6sid = null;
    return { ok: true };
  }
  const r = credentials.setAppSecret("dns_api", String(password));
  v6sid = null;
  return r;
}

function hasApiPassword() {
  return !!apiPassword();
}

// ...tryJson/authV6/v6headers/v6get/v6send/ensureV6/v5summary/parseLeaseLine/
// leaseExpires/leasesFromApi/leases/stats/ensureBlockGroup/blockClient:
// copied verbatim from the current src/main/pihole.js (lines 64-286,
// 358-410), with every internal `resolveTarget()` call replaced by
// `pi.resolveTarget()` and the SSH-lease-fallback's `exec(...)` replaced by
// `pi.exec(...)`.

module.exports = { stats, leases, blockClient, setApiPassword, hasApiPassword };
```

Because this is a large verbatim move, the actual PR must include the full copied body (not the elided comment above) — the elision here is only to keep this plan readable; the implementer copies the real functions from the current `src/main/pihole.js` before it's deleted in Task 5.

- [ ] **Step 2: Write the new AdGuard Home adapter**

```js
// src/main/dns/adguard.js — AdGuard Home REST API adapter.
// Docs: https://github.com/AdguardTeam/AdGuardHome (control API is
// undocumented-but-stable; endpoints below match the app's own web UI).
const pi = require("../pi");
const credentials = require("../credentials");
const lan = require("../lanhttp");

let sessionCookie = null;
let sessionHost = null;

function apiPassword() {
  return credentials.getAppSecret("dns_api") || null;
}

function setApiPassword(password) {
  if (!password) {
    credentials.deleteAppSecret("dns_api");
    sessionCookie = null;
    return { ok: true };
  }
  const r = credentials.setAppSecret("dns_api", String(password));
  sessionCookie = null;
  return r;
}

function hasApiPassword() {
  return !!apiPassword();
}

async function tryJson(host, path, opts) {
  try {
    return await lan.request(Object.assign({ url: "http://" + host + path, timeoutMs: 5000 }, opts));
  } catch (e) {
    return null;
  }
}

// AdGuard's default admin username is "admin" unless the user changed it;
// Meshwatch only ever asks for the password (matching the rest of the app's
// "one saved secret" pattern) and tries the common default username first.
async function login(host, password) {
  const r = await tryJson(host, "/control/login", {
    method: "POST",
    body: { name: "admin", password },
    headers: { "Content-Type": "application/json", Accept: "application/json" }
  });
  if (!r || r.status !== 200) return null;
  const cookie = lan.cookieValue(r.cookies, "agh_session");
  if (!cookie) return null;
  sessionCookie = cookie;
  sessionHost = host;
  return cookie;
}

async function authedGet(host, path) {
  if (!sessionCookie || sessionHost !== host) return null;
  const r = await tryJson(host, path, { headers: { Cookie: "agh_session=" + sessionCookie, Accept: "application/json" } });
  if (r && (r.status === 401 || r.status === 403)) { sessionCookie = null; return null; }
  return r;
}

async function authedPost(host, path, body) {
  if (!sessionCookie || sessionHost !== host) return null;
  return tryJson(host, path, {
    method: "POST",
    body,
    headers: { "Content-Type": "application/json", Cookie: "agh_session=" + sessionCookie }
  });
}

async function ensureAuth() {
  const t = pi.resolveTarget();
  const password = apiPassword();
  if (!t.host || !password) return null;
  if (sessionCookie && sessionHost === t.host) {
    const ping = await authedGet(t.host, "/control/status");
    if (ping && ping.status === 200) return t.host;
  }
  return (await login(t.host, password)) ? t.host : null;
}

async function stats() {
  const t = pi.resolveTarget();
  if (!t.discovered) {
    return { available: false, reason: "No Pi has been discovered on this network yet", host: t.host };
  }
  if (!apiPassword()) {
    return {
      available: false, reason: "Add the AdGuard Home admin password in Preferences",
      host: t.host, sshPort: t.port, sshUser: t.user, needsPassword: true
    };
  }
  const host = await ensureAuth();
  if (!host) {
    return {
      available: false,
      reason: "Could not log in to AdGuard Home. Check the password and that this PC can open http://" + t.host + "/",
      host: t.host, sshPort: t.port, sshUser: t.user
    };
  }
  const [statusR, statsR] = await Promise.all([
    authedGet(host, "/control/status"),
    authedGet(host, "/control/stats")
  ]);
  const status = (statusR && statusR.json) || {};
  const s = (statsR && statsR.json) || {};
  const queries = Array.isArray(s.dns_queries) ? s.dns_queries.reduce((a, b) => a + b, 0) : (s.num_dns_queries || 0);
  const blocked = Array.isArray(s.blocked_filtering) ? s.blocked_filtering.reduce((a, b) => a + b, 0) : (s.num_blocked_filtering || 0);
  const blockedList = (s.top_blocked_domains || []).slice(0, 8)
    .map((row) => { const [domain] = Object.keys(row); return { domain, hits: row[domain] }; });
  const talkers = (s.top_clients || []).slice(0, 8)
    .map((row) => { const [ip] = Object.keys(row); return { name: ip, ip, queries: row[ip] }; });

  return {
    available: true,
    version: "adguard",
    host: t.host,
    sshPort: t.port,
    sshUser: t.user,
    queriesToday: queries,
    blockedToday: blocked,
    blockedPercent: queries ? Math.round((blocked / queries) * 1000) / 10 : 0,
    blocklist: null,
    firmware: status.version || null,
    hostNote: "AdGuard Home " + (status.version || "") + " connected",
    blocked: blockedList,
    talkers
  };
}

async function leases() {
  const host = await ensureAuth();
  if (!host) return [];
  const r = await authedGet(host, "/control/dhcp/status");
  const j = (r && r.json) || {};
  const list = (j.leases || []).concat(j.static_leases || []);
  return list.map((l) => ({
    ip: l.ip,
    mac: String(l.mac || "").toUpperCase(),
    hostname: l.hostname || null,
    expiry: l.expires || null,
    expires: l.expires ? new Date(l.expires).toLocaleString() : "static"
  })).filter((l) => l.ip && lan.isPrivateIp(l.ip));
}

// DNS-level block only — same caveat as the Pi-hole adapter's group-based
// block: a device that switches its DNS server bypasses this. AdGuard's
// access-control list is the only block primitive its API exposes.
async function blockClient(ip, { blocked } = { blocked: true }) {
  if (!lan.isPrivateIp(ip)) return { ok: false, reason: "not a LAN address" };
  const host = await ensureAuth();
  if (!host) {
    return { ok: false, reason: "AdGuard Home internet blocking needs a live API session. Add the admin password in Preferences." };
  }
  const listR = await authedGet(host, "/control/access/list");
  const cur = (listR && listR.json) || { allowed_clients: [], disallowed_clients: [], blocked_hosts: [] };
  const disallowed = new Set(cur.disallowed_clients || []);
  if (blocked) disallowed.add(ip); else disallowed.delete(ip);
  await authedPost(host, "/control/access/set", {
    allowed_clients: cur.allowed_clients || [],
    disallowed_clients: Array.from(disallowed),
    blocked_hosts: cur.blocked_hosts || []
  });
  return { ok: true, blocked, via: "adguard-access-list" };
}

module.exports = { stats, leases, blockClient, setApiPassword, hasApiPassword };
```

- [ ] **Step 3: Write the detector/router**

```js
// src/main/dns/index.js — detects which DNS/DHCP backend (if any) is
// running on the discovered Pi, caches the result, and routes every call
// to the matching adapter. Never assumes — see CLAUDE.md's rule against
// hardcoding a specific product for this box.
const db = require("../db");
const pi = require("../pi");
const lan = require("../lanhttp");
const pihole = require("./pihole");
const adguard = require("./adguard");

async function probeAdguard(host) {
  try {
    const r = await lan.request({ url: "http://" + host + "/control/status", timeoutMs: 3000 });
    return r && (r.status === 200 || r.status === 403); // 403 = needs auth, but it's AdGuard
  } catch (e) { return false; }
}

async function probePihole(host) {
  try {
    const r = await lan.request({ url: "http://" + host + "/admin/api.php?status", timeoutMs: 3000 });
    return !!(r && r.json);
  } catch (e) { return false; }
}

async function detectBackend() {
  const t = pi.resolveTarget();
  if (!t.host) return "unknown";
  const [isAdguard, isPihole] = await Promise.all([probeAdguard(t.host), probePihole(t.host)]);
  const backend = isAdguard ? "adguard" : (isPihole ? "pihole" : "unknown");
  db.setSetting("pi_dns_backend", backend);
  return backend;
}

function cachedBackend() {
  return db.getSetting("pi_dns_backend") || "unknown";
}

function adapterFor(backend) {
  if (backend === "adguard") return adguard;
  if (backend === "pihole") return pihole;
  return null;
}

async function getBackendInfo() {
  const backend = cachedBackend();
  if (backend === "unknown") return null;
  const s = await adapterFor(backend).stats();
  return { name: backend === "adguard" ? "AdGuard Home" : "Pi-hole", version: s && s.firmware };
}

async function stats() {
  const a = adapterFor(cachedBackend());
  if (!a) return { available: false, reason: "No DNS management service detected on this Pi yet" };
  return a.stats();
}

async function leases() {
  const a = adapterFor(cachedBackend());
  return a ? a.leases() : [];
}

async function blockClient(ip, opts) {
  const a = adapterFor(cachedBackend());
  if (!a) return { ok: false, reason: "No DNS backend detected" };
  return a.blockClient(ip, opts);
}

function setApiPassword(password) {
  const a = adapterFor(cachedBackend()) || pihole; // no backend detected yet: still let the user save a password
  return a.setApiPassword(password);
}

function hasApiPassword() {
  const a = adapterFor(cachedBackend()) || pihole;
  return a.hasApiPassword();
}

module.exports = { detectBackend, cachedBackend, getBackendInfo, stats, leases, blockClient, setApiPassword, hasApiPassword };
```

- [ ] **Step 4: Manual verification**

Run: `node -e "const dns=require('./src/main/dns'); console.log(Object.keys(dns))"`
Expected: `[ 'detectBackend', 'cachedBackend', 'getBackendInfo', 'stats', 'leases', 'blockClient', 'setApiPassword', 'hasApiPassword' ]`

Then, with the app running against the real Pi and the AdGuard admin password saved in Preferences (Task 6 wires the IPC for this): confirm `dns.detectBackend()` resolves to `"adguard"`, and `dns.stats()` returns `available: true` with real query counts matching what AdGuard Home's own UI shows.

- [ ] **Step 5: Commit**

```bash
git add src/main/dns
git commit -m "Add DNS backend adapters (Pi-hole, AdGuard Home) with an auto-detecting router"
```

### Task 5: Retire `src/main/pihole.js`, repoint all callers

**Files:**
- Delete: `src/main/pihole.js`
- Modify: `src/main/index.js` (every `pihole.` reference), `src/main/discovery.js:774,782` (`require("./pihole")` → `require("./dns")`)

**Interfaces:**
- Consumes: `pi.js` (Task 3), `dns/index.js` (Task 4).

- [ ] **Step 1: Update discovery.js's DNS stats enrichment**

In `src/main/discovery.js`, replace the block at lines 773-788:

```js
try {
  const stats = await require("./dns").stats();
  if (stats && stats.available && Array.isArray(stats.talkers)) {
    for (const t of stats.talkers) {
      const hit = devices.find((d) => d.ip === t.ip || d.name === t.name);
      if (hit) hit.queryCount = t.queries;
    }
  }
  if (stats && stats.available && stats.firmware) {
    const pi = devices.find((d) => d.type === "dns-dhcp");
    if (pi) {
      pi.firmware = stats.firmware;
      pi.firmwareSource = "dns backend API";
    }
  }
} catch (e) { /* optional */ }
```

- [ ] **Step 2: Delete the old file**

```bash
git rm src/main/pihole.js
```

(All logic it contained now lives in `src/main/pi.js` and `src/main/dns/*` from Tasks 3-4 — nothing is lost, this is pure retirement of the now-empty original.)

- [ ] **Step 3: Manual verification**

Run: `node -e "require('./src/main/discovery.js')"` — expected: no throw (module loads cleanly, confirming the `require` path change didn't break module resolution). Full behavioral verification happens in Task 6's IPC rewiring step, since `index.js` still references the old module until then.

- [ ] **Step 4: Commit**

```bash
git add src/main/discovery.js
git commit -m "Retire src/main/pihole.js — logic now split across pi.js and dns/"
```

---

## Phase 2 — IPC/renderer rename + conditional visibility

### Task 6: Rename `pihole:*` IPC channels to `pi:*`, repoint to the new modules

**Files:**
- Modify: `src/main/index.js:197-235` (all `pihole:*` handlers), `src/preload.js:24-34`

**Interfaces:**
- Produces (preload → renderer, `window.meshwatch.pi.*`): `state()`, `setPrefs(prefs)`, `target()`, `stats()`, `leases()`, `hasPassword()`, `setPassword(password)`, `pickKey()`, `block(mac, blocked)`, `exec(command)`, `backend()` (new — returns `dns.getBackendInfo()`).

- [ ] **Step 1: Rewrite the IPC handlers in `src/main/index.js`**

Replace lines 197-235 (the `pihole:*` block) with:

```js
const pi = require("./pi");
const dns = require("./dns");

ipcMain.handle("pi:state", () => db.getPiState());
ipcMain.handle("pi:prefs", (_e, prefs) => db.setPiPrefs(prefs || {}));
ipcMain.handle("pi:target", () => pi.resolveTarget());
ipcMain.handle("pi:backend", async () => {
  await dns.detectBackend();
  return dns.getBackendInfo();
});
ipcMain.handle("pi:stats", () => dns.stats());
ipcMain.handle("pi:leases", () => dns.leases());
ipcMain.handle("pi:hasPassword", () => dns.hasApiPassword());
ipcMain.handle("pi:setPassword", (_e, { password }) => dns.setApiPassword(password));
ipcMain.handle("pi:pickKey", async () => {
  const r = await dialog.showOpenDialog(win, {
    title: "Pi SSH private key",
    properties: ["openFile"],
    filters: [{ name: "OpenSSH private key", extensions: ["", "pem", "key", "pub"] }]
  });
  if (r.canceled || !r.filePaths[0]) return { ok: false, cancelled: true };
  db.setSetting("pi_ssh_key", r.filePaths[0]);
  return { ok: true, path: r.filePaths[0] };
});
ipcMain.handle("pi:exec", async (_e, { command }) => {
  if (pi.isDisruptive(command)) {
    const { response } = await dialog.showMessageBox(win, {
      type: "warning",
      buttons: ["Cancel", "Run it"],
      defaultId: 0,
      cancelId: 0,
      title: "This may interrupt DNS or restart services on the network",
      message: command,
      detail: pi.disruptionSeconds(command)
        ? "Name resolution will stop for roughly " + pi.disruptionSeconds(command) + " seconds. Every device on the network is affected."
        : "This can restart services on the Pi. If it upgrades the kernel or firmware, a manual reboot may be needed afterward."
    });
    if (response !== 1) return { cancelled: true, output: [] };
  }
  return pi.exec(command);
});
ipcMain.handle("pi:block", async (_e, { mac, blocked }) => {
  const d = findByMac(mac);
  if (!d || !d.ip) return { ok: false, reason: "device has no address" };
  const r = await dns.blockClient(d.ip, { blocked: blocked !== false });
  if (r && r.ok) db.setBlocked(mac, blocked !== false);
  return r;
});
```

- [ ] **Step 2: Update `src/preload.js`**

Replace the `pihole:` block (lines 24-34) with:

```js
pi: {
  stats: () => ipcRenderer.invoke("pi:stats"),
  leases: () => ipcRenderer.invoke("pi:leases"),
  exec: (command) => ipcRenderer.invoke("pi:exec", { command }),
  state: () => ipcRenderer.invoke("pi:state"),
  setPrefs: (prefs) => ipcRenderer.invoke("pi:prefs", prefs),
  target: () => ipcRenderer.invoke("pi:target"),
  backend: () => ipcRenderer.invoke("pi:backend"),
  hasPassword: () => ipcRenderer.invoke("pi:hasPassword"),
  setPassword: (password) => ipcRenderer.invoke("pi:setPassword", { password }),
  pickKey: () => ipcRenderer.invoke("pi:pickKey"),
  block: (mac, blocked) => ipcRenderer.invoke("pi:block", { mac, blocked })
},
```

- [ ] **Step 3: Manual verification**

Run: `npm start`. Expected: app launches without a preload/console error about `window.meshwatch.pihole` being undefined (the renderer still calls the old name until Task 7 — this step is just confirming the main-process/preload half loads cleanly; open DevTools and check the console for `require`/IPC registration errors only, not full feature behavior yet).

- [ ] **Step 4: Commit**

```bash
git add src/main/index.js src/preload.js
git commit -m "Rename pihole:* IPC channels to pi:*, route through pi.js/dns/index.js"
```

### Task 7: Rename renderer surface (`#pihole-*` → `#pi-*`), conditional tab visibility

**Files:**
- Modify: `src/renderer/index.html:44,126-322` (all `pihole`-named ids and the nav label), `src/renderer/app.js` (every `window.meshwatch.pihole.*` call → `window.meshwatch.pi.*`, every `$("#pihole-...")` → `$("#pi-...")`, plus new visibility logic)

**Interfaces:**
- Consumes: `window.meshwatch.pi.state()` (Task 6) — `{discovered: boolean, ...}`.
- Produces: `updatePiTabVisibility()` — called after every scan completes and once at startup.

- [ ] **Step 1: Rename ids and the nav label in `index.html`**

Find/replace across `index.html`: `nav-pihole` → `nav-pi`, `view-pihole` → `view-pi`, every other `pihole-` id prefix → `pi-` (e.g. `pihole-stats` → `pi-stats`, `pihole-blocked` → `pi-dns-blocked`, `pihole-leases` → `pi-leases`, `pihole-host` → `pi-host`, `pihole-actions` → `pi-actions`, `pihole-form`/`pihole-cmd`/`pihole-out` → `pi-form`/`pi-cmd`/`pi-out`, `pihole-ssh-target` → `pi-ssh-target`, `pihole-prefs-panel`/`pihole-prefs-note` → `pi-prefs-panel`/`pi-prefs-note`, `pihole-ssh-form` → `pi-ssh-form`, `pihole-host-note`/`pihole-host-value` → `pi-host-note`/`pi-host-value`, `pihole-api-note`/`pref-pihole-api`/`pihole-api-form` → `pi-api-note`/`pref-pi-api`/`pi-api-form`, `pihole-key-note` → `pi-key-note`). Change the nav button text at line 44 from `Pi-hole · SSH` to `Pi`. Remove the four Pi-hole-only quick-action buttons at lines 146-150 (`pihole status`, `Update gravity`, `Restart FTL`, `DHCP leases`, `top talkers` — the last two become real data sections, not buttons; "Restart FTL" is replaced by a backend-aware restart button added in Task 10).

- [ ] **Step 2: Rename JS references in `app.js`**

Find/replace `window.meshwatch.pihole.` → `window.meshwatch.pi.` (all call sites, including the `saveSshPrefs`/`loadPihole` functions and the block-device flow at line 596). Rename `state.pihole` → `state.pi`, `state.piStats` → `state.piStats` (unchanged, already generic), `loadPihole()` → `loadPi()`, `runPiholeCmd()` → `runPiCmd()`. Update the two entries at lines 1076-1077 (the detail-panel quick-action list currently `["pihole status", "pihole status"], ["Update gravity", "pihole -g"]`) — delete both; Task 10 replaces this block with backend-agnostic content.

- [ ] **Step 3: Add conditional tab visibility**

In `app.js`, add:

```js
function updatePiTabVisibility() {
  const nav = $("#nav-pi");
  const discovered = !!(state.pi && state.pi.discovered);
  if (nav) nav.hidden = !discovered;
  if (!discovered && state.view === "pi") go("overview");
}
```

Call `updatePiTabVisibility()` (a) once during initial app load right after the first `window.meshwatch.pi.state()` fetch, and (b) at the end of the scan-completion handler (the function that runs after `startScan()` finishes and repopulates `state.devices` — locate it by searching for where `state.lastScanAt` is set after a scan, currently in the same handler block as `setStatus(state.devices.length + " devices found")`).

- [ ] **Step 4: Manual verification**

Run: `npm start`. With the Pi previously discovered (this machine's case): confirm the "Pi" nav item is visible and the tab opens showing real data. Then, as a negative-path check, temporarily rename `pi_discovered` to something else via `node -e "..."` against the userData sqlite file (or simpler: check the code path by reading `updatePiTabVisibility()` — do not actually corrupt the real DB) — acceptable verification here is code review plus confirming the positive path works, since destructively un-discovering the real Pi to test the negative path isn't worth the risk on the user's live database.

- [ ] **Step 5: Commit**

```bash
git add src/renderer/index.html src/renderer/app.js
git commit -m "Rename Pi-hole renderer surface to Pi, hide the tab until a Pi is discovered"
```

---

## Phase 3 — Pi system panel (apt, installed apps, host stats)

### Task 8: apt update/upgrade/installed-apps in `pi.js`

**Files:**
- Modify: `src/main/pi.js` (add functions), `src/main/index.js` (add IPC handlers)

**Interfaces:**
- Produces (in `pi.js`): `aptCheckUpdates()` → `{ok, count, packages: [{name, newVersion}]}`, `aptUpgrade()` → `{ok, output}` (routes through the existing disruptive-confirmation `pi:exec` path — see below), `installedApps()` → `{ok, apps: [{name}]}`, `rebootRequired()` → `boolean`.
- Produces (IPC): `pi:apt:check`, `pi:apt:upgrade`, `pi:apt:apps`, `pi:rebootRequired`.

- [ ] **Step 1: Add the functions to `pi.js`**

```js
const APT_SKIP_RE = /(-dev$|^lib|firmware|^linux-|raspberrypi-kernel|-dbg$|-dbgsym$)/;

async function aptCheckUpdates() {
  const update = await exec("sudo apt-get update -qq");
  if (update.code) return { ok: false, reason: update.output.join("\n") };
  const list = await exec("apt list --upgradable 2>/dev/null");
  const packages = (list.output || [])
    .filter((l) => l.indexOf("/") !== -1 && l.indexOf("Listing") === -1)
    .map((l) => {
      const name = l.split("/")[0];
      const m = l.match(/\]\s*$/) ? null : l.match(/^(\S+)\s+(\S+)/);
      return { name, newVersion: (l.match(/\s(\S+)\s+\[upgradable/) || [])[1] || null };
    });
  return { ok: true, count: packages.length, packages };
}

// Actual upgrade always goes through the pi:exec IPC handler (index.js),
// which gates it behind the disruptive-command confirmation dialog — this
// helper just builds the exact command string used for that.
function aptUpgradeCommand() {
  return "sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y";
}

async function installedApps() {
  const r = await exec("apt-mark showmanual");
  if (r.code) return { ok: false, reason: r.output.join("\n") };
  const apps = (r.output || [])
    .map((l) => l.trim())
    .filter((l) => l && !APT_SKIP_RE.test(l))
    .map((name) => ({ name }));
  return { ok: true, apps };
}

async function rebootRequired() {
  const r = await exec("test -f /var/run/reboot-required && echo yes || echo no");
  return (r.output || []).join("").indexOf("yes") !== -1;
}
```

Add these to `module.exports` in `pi.js`.

- [ ] **Step 2: Finalize the `DISRUPTIVE` entry**

Confirm the `DISRUPTIVE` array in `pi.js` (added in Task 3) has the real entry (not the placeholder comment):

```js
{ match: /apt(-get)?\s+(upgrade|dist-upgrade|full-upgrade)/, seconds: 0 },
```

(`seconds: 0` because apt upgrade doesn't have a predictable DNS-outage duration like an FTL restart does — the confirmation dialog's `detail` text for `seconds === 0` already reads "This can restart services on the Pi..." per Task 6's Step 1, which is accurate here.)

- [ ] **Step 3: Add IPC handlers**

In `src/main/index.js`, alongside the other `pi:*` handlers from Task 6:

```js
ipcMain.handle("pi:apt:check", () => pi.aptCheckUpdates());
ipcMain.handle("pi:apt:upgrade", async () => pi.exec(pi.aptUpgradeCommand())); // reuses pi:exec's caller path indirectly — see note below
ipcMain.handle("pi:apt:apps", () => pi.installedApps());
ipcMain.handle("pi:rebootRequired", () => pi.rebootRequired());
```

Note: `pi:apt:upgrade` must go through the same disruptive-confirmation dialog as `pi:exec`. Rather than duplicating the dialog code, change the handler to route through the existing `pi:exec` handler's logic directly:

```js
ipcMain.handle("pi:apt:upgrade", async (event) => {
  return ipcMain._events["pi:exec"] // not valid Electron API — replaced below
});
```

That approach doesn't work with Electron's `ipcMain` API — instead, factor the confirmation+exec logic out of the `pi:exec` handler (Task 6, Step 1) into a shared function and call it from both handlers:

```js
async function confirmedExec(command) {
  if (pi.isDisruptive(command)) {
    const { response } = await dialog.showMessageBox(win, {
      type: "warning",
      buttons: ["Cancel", "Run it"],
      defaultId: 0,
      cancelId: 0,
      title: "This may interrupt DNS or restart services on the network",
      message: command,
      detail: pi.disruptionSeconds(command)
        ? "Name resolution will stop for roughly " + pi.disruptionSeconds(command) + " seconds. Every device on the network is affected."
        : "This can restart services on the Pi. If it upgrades the kernel or firmware, a manual reboot may be needed afterward."
    });
    if (response !== 1) return { cancelled: true, output: [] };
  }
  return pi.exec(command);
}

ipcMain.handle("pi:exec", async (_e, { command }) => confirmedExec(command));
ipcMain.handle("pi:apt:upgrade", async () => confirmedExec(pi.aptUpgradeCommand()));
```

(This replaces the `pi:exec` handler body written in Task 6, Step 1 — same behavior, now shared.)

- [ ] **Step 4: Add preload bridge entries**

In `src/preload.js`, inside the `pi:` object:

```js
aptCheck: () => ipcRenderer.invoke("pi:apt:check"),
aptUpgrade: () => ipcRenderer.invoke("pi:apt:upgrade"),
installedApps: () => ipcRenderer.invoke("pi:apt:apps"),
rebootRequired: () => ipcRenderer.invoke("pi:rebootRequired"),
```

- [ ] **Step 5: Manual verification**

Run: `npm start`, open the Pi tab (Task 10 adds the UI; until then, verify from DevTools console: `await window.meshwatch.pi.aptCheck()`). Expected: `{ok: true, count: <n>, packages: [...]}` matching what `apt list --upgradable` shows over a manual SSH session to the real Pi. Confirm `sudo apt-get update` doesn't hang waiting for a password — Raspberry Pi OS's default user has passwordless sudo for this by default; if it prompts and hangs, the SSH exec will time out via `ssh2`'s `readyTimeout`/exec stream never closing — note this as a known limitation if hit, not a bug to silently work around (surfacing the real Pi's sudo state, per Hard Rule 4, rather than guessing).

- [ ] **Step 6: Commit**

```bash
git add src/main/pi.js src/main/index.js src/preload.js
git commit -m "Add apt check/upgrade, installed-apps listing, and reboot-required check"
```

### Task 9: CPU/disk/uptime host stats in `pi.js`

**Files:**
- Modify: `src/main/pi.js`, `src/main/index.js`, `src/preload.js`

**Interfaces:**
- Produces: `hostStats()` → `{uptime, diskUsedPercent, cpuCores, loadAvg}`; IPC `pi:hostStats`; preload `pi.hostStats()`.

- [ ] **Step 1: Add `hostStats()` to `pi.js`**

```js
async function hostStats() {
  const [uptimeR, diskR, cpuR] = await Promise.all([
    exec("uptime -p"),
    exec("df -h / | tail -1"),
    exec("nproc && cat /proc/loadavg")
  ]);
  const disk = (diskR.output && diskR.output[0] || "").trim().split(/\s+/);
  const cpuLines = cpuR.output || [];
  return {
    uptime: (uptimeR.output && uptimeR.output[0] || "").replace(/^up\s+/, "") || null,
    diskUsedPercent: disk[4] ? Number(disk[4].replace("%", "")) : null,
    diskUsed: disk[2] || null,
    diskTotal: disk[1] || null,
    cpuCores: cpuLines[0] ? Number(cpuLines[0]) : null,
    loadAvg: cpuLines[1] ? cpuLines[1].split(" ").slice(0, 3).join(" ") : null
  };
}
```

Add to `module.exports`.

- [ ] **Step 2: IPC + preload**

`src/main/index.js`: `ipcMain.handle("pi:hostStats", () => pi.hostStats());`
`src/preload.js`, inside `pi:`: `hostStats: () => ipcRenderer.invoke("pi:hostStats"),`

- [ ] **Step 3: Manual verification**

DevTools console: `await window.meshwatch.pi.hostStats()` → confirm `uptime`/`diskUsedPercent`/`cpuCores`/`loadAvg` match a manual `ssh admin@192.168.1.63 -p 2222 'uptime -p; df -h /; nproc; cat /proc/loadavg'`.

- [ ] **Step 4: Commit**

```bash
git add src/main/pi.js src/main/index.js src/preload.js
git commit -m "Add Pi host stats (uptime, disk, CPU load) over SSH"
```

### Task 10: Pi tab UI — header, DNS stats, leases, system panel

**Files:**
- Modify: `src/renderer/index.html` (rebuild the `#view-pi` section), `src/renderer/app.js` (`loadPi()` rewrite), `src/renderer/styles.css` (minor additions reusing existing `.stat-row`/`.panel`/`.btn-row` classes — no new visual language)

**Interfaces:**
- Consumes: `window.meshwatch.pi.backend()`, `.stats()`, `.leases()`, `.hostStats()`, `.aptCheck()`, `.aptUpgrade()`, `.installedApps()`, `.rebootRequired()` (Tasks 6/8/9), `window.meshwatch.browser.open(url)` (existing, used for "Open admin UI").

- [ ] **Step 1: Rebuild the `#view-pi` markup**

Replace the current `#view-pihole` block (now `#view-pi` per Task 7) in `index.html` with sections in this order (structure only — exact class names follow the existing `.panel`/`.stat-row`/`.subhead` conventions already used elsewhere in the file, e.g. the Security view):

```html
<div class="view" id="view-pi">
  <div class="panel" id="pi-header">
    <h2 id="pi-backend-name">Detecting DNS service…</h2>
    <span class="muted" id="pi-host-line"></span>
    <div class="btn-row">
      <button type="button" id="pi-open-admin">Open admin UI</button>
      <button type="button" id="pi-open-log" hidden>View query log</button>
    </div>
  </div>

  <div class="stat-row" id="pi-stats"></div>

  <div class="panel">
    <h2 class="subhead">Top blocked domains</h2>
    <div id="pi-dns-blocked" class="empty">No DNS backend detected yet.</div>
    <h2 class="subhead">DHCP leases</h2>
    <div id="pi-leases" class="empty">Leases appear here once a backend is connected.</div>
  </div>

  <div class="panel" id="pi-services-panel">
    <h2 class="subhead">Detected services</h2>
    <div id="pi-services" class="empty">Save SSH credentials for the Pi to detect running services.</div>
    <button type="button" id="pi-rescan-services">Rescan services</button>
  </div>

  <div class="panel" id="pi-system-panel">
    <h2 class="subhead">Pi system</h2>
    <div id="pi-host" class="empty">CPU, disk and uptime appear here once SSH is connected.</div>
    <div id="pi-reboot-banner" class="est" hidden>A reboot is recommended to finish a previous update.</div>
    <div class="btn-row">
      <button type="button" id="pi-apt-check">Check for updates</button>
      <button type="button" id="pi-apt-upgrade" class="warn">Upgrade all</button>
    </div>
    <div id="pi-apt-result" class="empty"></div>
    <h3 class="subhead">Installed apps</h3>
    <div id="pi-apps" class="empty"></div>
  </div>

  <div class="panel" id="pi-terminal-panel">
    <h2 class="subhead">Terminal</h2>
    <div id="pi-term"></div>
  </div>

  <div class="panel">
    <h2 class="subhead">Command runner</h2>
    <span class="muted" id="pi-ssh-target"></span>
    <form id="pi-form" class="cmd-form">
      <input type="text" id="pi-cmd" placeholder="Arbitrary command…" autocomplete="off">
      <button type="submit">Run</button>
    </form>
    <pre id="pi-out" class="log"></pre>
  </div>
</div>
```

(The Preferences-panel portion for SSH port/user/key/API-password, already renamed in Task 7, is unchanged in structure — only ids were renamed there.)

- [ ] **Step 2: Rewrite `loadPi()` in `app.js`**

```js
async function loadPi() {
  const backendInfo = await window.meshwatch.pi.backend();
  $("#pi-backend-name").textContent = backendInfo ? backendInfo.name + (backendInfo.version ? " " + backendInfo.version : "") : "No DNS service detected";
  const target = await window.meshwatch.pi.target();
  $("#pi-host-line").textContent = target.host ? target.host + " · SSH " + target.user + "@" + target.host + ":" + target.port : "No host remembered yet";
  $("#pi-ssh-target").textContent = $("#pi-host-line").textContent;

  $("#pi-open-admin").onclick = () => target.host && openInAppBrowser("http://" + target.host + "/");
  const logBtn = $("#pi-open-log");
  logBtn.hidden = !(backendInfo && backendInfo.name === "AdGuard Home");
  logBtn.onclick = () => target.host && openInAppBrowser("http://" + target.host + "/#logs?response_status=all");

  const s = await window.meshwatch.pi.stats();
  state.piStats = s;
  const statsEl = $("#pi-stats");
  if (s && s.available) {
    statsEl.innerHTML = [
      ["Queries today", s.queriesToday],
      ["Blocked today", s.blockedToday],
      ["Blocked %", s.blockedPercent != null ? s.blockedPercent + "%" : "—"],
      ["Blocklist size", s.blocklist || "—"]
    ].map(([k, v]) => '<div class="stat"><div class="stat-label">' + k + '</div><div class="stat-value">' + (v == null ? "—" : v) + "</div></div>").join("");
  } else {
    statsEl.innerHTML = '<div class="empty">' + ((s && s.reason) || "DNS stats unavailable") + "</div>";
  }

  const blockedEl = $("#pi-dns-blocked");
  blockedEl.innerHTML = (s && s.blocked && s.blocked.length)
    ? "<ul>" + s.blocked.map((b) => "<li>" + escapeHtml(b.domain) + " — " + b.hits + "</li>").join("") + "</ul>"
    : '<div class="empty">No blocked-domain data yet.</div>';

  const leases = await window.meshwatch.pi.leases();
  const leasesEl = $("#pi-leases");
  leasesEl.innerHTML = leases.length
    ? "<ul>" + leases.map((l) => "<li>" + escapeHtml(l.hostname || l.ip) + " — " + escapeHtml(l.ip) + " (" + l.expires + ")</li>").join("") + "</ul>"
    : '<div class="empty">No DHCP leases available from this backend.</div>';

  const host = await window.meshwatch.pi.hostStats();
  $("#pi-host").innerHTML = host.uptime
    ? "Up " + escapeHtml(host.uptime) + " · disk " + (host.diskUsedPercent != null ? host.diskUsedPercent + "%" : "—") +
      " (" + escapeHtml(host.diskUsed || "?") + " / " + escapeHtml(host.diskTotal || "?") + ") · " +
      (host.cpuCores || "?") + " cores · load " + escapeHtml(host.loadAvg || "—")
    : "Could not read host stats over SSH yet.";
  const reboot = await window.meshwatch.pi.rebootRequired();
  $("#pi-reboot-banner").hidden = !reboot;

  const apps = await window.meshwatch.pi.installedApps();
  $("#pi-apps").innerHTML = (apps.ok && apps.apps.length)
    ? "<ul>" + apps.apps.map((a) => "<li>" + escapeHtml(a.name) + "</li>").join("") + "</ul>"
    : '<div class="empty">' + (apps.ok ? "No manually-installed apps found." : apps.reason || "Could not read installed apps.") + "</div>";

  await loadPiServices(); // Task 14
  await loadPiTerminalTarget(); // Task 12, no-op until then
}

$("#pi-apt-check").addEventListener("click", async () => {
  $("#pi-apt-result").textContent = "Checking…";
  const r = await window.meshwatch.pi.aptCheck();
  $("#pi-apt-result").innerHTML = r.ok
    ? (r.count ? r.count + " package(s) upgradable: " + r.packages.map((p) => escapeHtml(p.name)).join(", ") : "Everything is up to date.")
    : escapeHtml(r.reason || "Check failed");
});

$("#pi-apt-upgrade").addEventListener("click", async () => {
  const r = await window.meshwatch.pi.aptUpgrade();
  if (r && r.cancelled) return toast("Cancelled");
  $("#pi-out").textContent = (r.output || []).join("\n");
  toast(r.code ? "Upgrade finished with errors — see output below" : "Upgrade complete");
  loadPi();
});
```

Remove the old `pihole-actions` button-wiring block (`$$("#pihole-actions button").forEach(...)`, formerly around app.js line 1443) since those buttons no longer exist — replaced by the explicit handlers above and the `#pi-form` submit handler already renamed in Task 7.

- [ ] **Step 3: Manual verification**

Run: `npm start`, open the Pi tab. Expected: header shows "AdGuard Home" + version; "Open admin UI" opens `http://192.168.1.63/` in the in-app browser; "View query log" opens the `#logs?response_status=all` deep link; stats/leases sections show real data or an honest "unavailable" reason; "Check for updates" shows the real `rpi-eeprom` upgradable package; "Upgrade all" prompts the disruptive-action confirmation dialog before running.

- [ ] **Step 4: Commit**

```bash
git add src/renderer/index.html src/renderer/app.js src/renderer/styles.css
git commit -m "Rebuild the Pi tab UI: backend header, DNS stats/leases, system panel, apt actions"
```

---

## Phase 4 — Embedded interactive terminal

### Task 11: PTY streaming in `pi.js` + IPC

**Files:**
- Modify: `src/main/pi.js`, `src/main/index.js`

**Interfaces:**
- Produces (in `pi.js`): `termStart(sessionId, {rows, cols}, onData, onClose)`, `termInput(sessionId, data)`, `termResize(sessionId, rows, cols)`, `termStop(sessionId)`.
- Produces (IPC, main→renderer push): `pi:term:data {sessionId, chunk}`, `pi:term:closed {sessionId}`. (renderer→main, fire-and-forget `send`, not `invoke`): `pi:term:start`, `pi:term:input`, `pi:term:resize`, `pi:term:stop`.

- [ ] **Step 1: Add PTY session management to `pi.js`**

```js
const termSessions = new Map(); // sessionId -> { conn, stream }

function termStart(sessionId, { rows, cols }, onData, onClose) {
  const t = resolveTarget();
  if (!t.host) { onClose("No Pi remembered — run a scan first"); return; }
  const opts = sshConnectOptions(t);
  if (!opts.privateKey && !opts.password) { onClose("SSH is not connected yet — set a key or saved password in Preferences"); return; }

  const conn = new Client();
  conn.on("ready", () => {
    conn.shell({ term: "xterm-256color", rows: rows || 24, cols: cols || 80 }, (err, stream) => {
      if (err) { onClose(String(err.message || err)); return; }
      termSessions.set(sessionId, { conn, stream });
      stream.on("data", (d) => onData(d.toString("utf8")));
      stream.stderr.on("data", (d) => onData(d.toString("utf8")));
      stream.on("close", () => { termSessions.delete(sessionId); onClose(null); });
    });
  });
  conn.on("error", (e) => { onClose(String(e.message || e)); });
  conn.connect(opts);
}

function termInput(sessionId, data) {
  const s = termSessions.get(sessionId);
  if (s) s.stream.write(data);
}

function termResize(sessionId, rows, cols) {
  const s = termSessions.get(sessionId);
  if (s) s.stream.setWindow(rows, cols, 0, 0);
}

function termStop(sessionId) {
  const s = termSessions.get(sessionId);
  if (!s) return;
  try { s.stream.close(); } catch (e) { /* ignore */ }
  try { s.conn.end(); } catch (e) { /* ignore */ }
  termSessions.delete(sessionId);
}
```

Add `termStart, termInput, termResize, termStop` to `module.exports`.

- [ ] **Step 2: Wire IPC in `src/main/index.js`**

```js
const crypto = require("crypto");
let activeTermSession = null;

ipcMain.on("pi:term:start", (event, { rows, cols }) => {
  if (activeTermSession) pi.termStop(activeTermSession); // one session at a time per Pi
  const sessionId = crypto.randomUUID();
  activeTermSession = sessionId;
  event.reply("pi:term:started", { sessionId });
  pi.termStart(
    sessionId,
    { rows, cols },
    (chunk) => event.sender.send("pi:term:data", { sessionId, chunk }),
    (errorOrNull) => {
      event.sender.send("pi:term:closed", { sessionId, error: errorOrNull });
      if (activeTermSession === sessionId) activeTermSession = null;
    }
  );
});
ipcMain.on("pi:term:input", (_e, { sessionId, data }) => pi.termInput(sessionId, data));
ipcMain.on("pi:term:resize", (_e, { sessionId, rows, cols }) => pi.termResize(sessionId, rows, cols));
ipcMain.on("pi:term:stop", (_e, { sessionId }) => pi.termStop(sessionId));
```

- [ ] **Step 3: Add preload bridge**

In `src/preload.js`, add a top-level `terminal` object (uses `send`/`on`, not `invoke`, since this is a stream):

```js
terminal: {
  start: (rows, cols) => ipcRenderer.send("pi:term:start", { rows, cols }),
  input: (sessionId, data) => ipcRenderer.send("pi:term:input", { sessionId, data }),
  resize: (sessionId, rows, cols) => ipcRenderer.send("pi:term:resize", { sessionId, rows, cols }),
  stop: (sessionId) => ipcRenderer.send("pi:term:stop", { sessionId }),
  onStarted: (cb) => ipcRenderer.on("pi:term:started", (_e, payload) => cb(payload)),
  onData: (cb) => ipcRenderer.on("pi:term:data", (_e, payload) => cb(payload)),
  onClosed: (cb) => ipcRenderer.on("pi:term:closed", (_e, payload) => cb(payload))
},
```

- [ ] **Step 4: Manual verification**

DevTools console:
```js
window.meshwatch.terminal.onData((p) => console.log("DATA", p.chunk));
window.meshwatch.terminal.onStarted((p) => { console.log("STARTED", p.sessionId); window._sid = p.sessionId; });
window.meshwatch.terminal.start(24, 80);
// after STARTED logs:
window.meshwatch.terminal.input(window._sid, "ls\n");
```
Expected: DATA events print the real shell prompt and `ls` output from the Pi.

- [ ] **Step 5: Commit**

```bash
git add src/main/pi.js src/main/index.js src/preload.js
git commit -m "Add interactive SSH PTY streaming (ssh2 shell) for the embedded terminal"
```

### Task 12: xterm.js renderer integration

**Files:**
- Modify: `package.json` (add `xterm`, `@xterm/addon-fit` to `dependencies`), `src/renderer/index.html` (load xterm's CSS/JS locally, add container), `src/renderer/app.js` (terminal lifecycle)
- Create: `src/renderer/vendor/xterm.js`, `src/renderer/vendor/xterm.css`, `src/renderer/vendor/addon-fit.js` (copied from `node_modules` — no CDN, matches the existing "no build step" renderer and the CSP's `default-src 'self'`)

**Interfaces:**
- Consumes: `window.meshwatch.terminal.*` (Task 11).
- Produces: `loadPiTerminalTarget()` (referenced in Task 10's `loadPi()`), `startTerminal()`, `stopTerminal()`.

- [ ] **Step 1: Install and vendor the library**

```bash
npm install xterm @xterm/addon-fit
```

Copy the built UMD/CSS files into the renderer so they load under the existing `script-src 'self'` CSP without a bundler:

```bash
cp node_modules/xterm/lib/xterm.js src/renderer/vendor/xterm.js
cp node_modules/xterm/css/xterm.css src/renderer/vendor/xterm.css
cp node_modules/@xterm/addon-fit/lib/addon-fit.js src/renderer/vendor/addon-fit.js
```

- [ ] **Step 2: Load them in `index.html`**

Add before `styles.css` in `<head>`: `<link rel="stylesheet" href="vendor/xterm.css">`. Add before the closing `</body>` (alongside the existing `app.js` script tag): `<script src="vendor/xterm.js"></script><script src="vendor/addon-fit.js"></script>` — loaded before `app.js` so `Terminal`/`FitAddon` are global when `app.js` runs.

- [ ] **Step 3: Terminal lifecycle in `app.js`**

```js
let term = null;
let fitAddon = null;
let termSessionId = null;

function startTerminal() {
  if (term) return;
  term = new window.Terminal({ convertEol: true, cursorBlink: true, fontSize: 13 });
  fitAddon = new window.FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open($("#pi-term"));
  fitAddon.fit();

  window.meshwatch.terminal.onStarted(({ sessionId }) => { termSessionId = sessionId; });
  window.meshwatch.terminal.onData(({ sessionId, chunk }) => { if (sessionId === termSessionId) term.write(chunk); });
  window.meshwatch.terminal.onClosed(({ sessionId, error }) => {
    if (sessionId !== termSessionId) return;
    term.write("\r\n[connection closed" + (error ? ": " + error : "") + "]\r\n");
    termSessionId = null;
  });
  term.onData((data) => { if (termSessionId) window.meshwatch.terminal.input(termSessionId, data); });
  term.onResize(({ rows, cols }) => { if (termSessionId) window.meshwatch.terminal.resize(termSessionId, rows, cols); });

  window.meshwatch.terminal.start(term.rows, term.cols);
  window.addEventListener("resize", () => fitAddon && fitAddon.fit());
}

function stopTerminal() {
  if (termSessionId) window.meshwatch.terminal.stop(termSessionId);
  termSessionId = null;
}

async function loadPiTerminalTarget() {
  // Called from loadPi() each time the Pi tab is opened; (re)starts the
  // terminal only if it isn't already running, so switching tabs and back
  // doesn't kill an in-progress session.
  if (!term) startTerminal();
}
```

Call `stopTerminal()` when navigating away from the Pi tab (in the existing `go(view)` function, add a branch: `if (state.view === "pi" && view !== "pi") stopTerminal();` — check the current view before reassigning it).

- [ ] **Step 4: Manual verification**

Run: `npm start`, open the Pi tab. Expected: a real terminal prompt appears in the "Terminal" panel; typing `htop` shows a live-updating process list; resizing the window resizes the terminal (via `FitAddon`); Ctrl-C interrupts a running command; navigating to another tab and back doesn't duplicate the session.

- [ ] **Step 5: Commit**

```bash
git add package.json package-lock.json src/renderer/vendor src/renderer/index.html src/renderer/app.js
git commit -m "Add embedded interactive terminal (xterm.js over the SSH PTY stream)"
```

---

## Phase 5 — Generic Pi service auto-detection

### Task 13: `src/main/pi-services.js`

**Files:**
- Create: `src/main/pi-services.js`
- Modify: `src/main/db.js` (new setting-backed cache, or a small dedicated table — use a table since results are structured and per-Pi, following the existing table pattern)

**Interfaces:**
- Produces: `discoverServices()` → `Array<{port, name, category, title, url}>`, `cachedServices()` → same shape read from storage, `db.saveServices(mac, services)`, `db.getServices(mac)`.

- [ ] **Step 1: Add storage**

In `src/main/db.js`, add a table (in the same `db.exec(...)` block as the others, Task 2's area):

```sql
CREATE TABLE IF NOT EXISTS pi_services (
  mac TEXT, port INTEGER, name TEXT, category TEXT, title TEXT,
  updated_at INTEGER,
  PRIMARY KEY (mac, port)
);
```

And helper functions:

```js
function saveServices(mac, services) {
  const now = Date.now();
  const del = db.prepare("DELETE FROM pi_services WHERE mac = ?");
  const ins = db.prepare("INSERT INTO pi_services (mac, port, name, category, title, updated_at) VALUES (?,?,?,?,?,?)");
  const tx = db.transaction((list) => {
    del.run(mac);
    for (const s of list) ins.run(mac, s.port, s.name, s.category, s.title, now);
  });
  tx(services);
}

function getServices(mac) {
  return db.prepare("SELECT port, name, category, title FROM pi_services WHERE mac = ? ORDER BY port").all(mac);
}
```

Export both from `db.js`.

- [ ] **Step 2: Write the detector**

```js
// src/main/pi-services.js — generic detection of self-hosted services
// running on the Pi: list its listening ports over SSH, probe each with a
// plain GET (same rule as discovery.js's webProbe: read the title, never
// guess a login), match against a small catalog for a friendly name.
// Anything unmatched still shows up — never hidden, never invented.
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

function matchCatalog(port, title) {
  const hit = KNOWN_SERVICES.find((k) =>
    k.port === port && (!k.titleRe || (title && k.titleRe.test(title)))
  ) || KNOWN_SERVICES.find((k) => k.titleRe && title && k.titleRe.test(title));
  return hit || null;
}

async function listListeningPorts() {
  const r = await pi.exec("ss -tln 2>/dev/null || netstat -tln 2>/dev/null");
  if (r.code) return [];
  const ports = new Set();
  for (const line of r.output || []) {
    const m = line.match(/:(\d{2,5})\s+\S+\s+LISTEN/) || line.match(/[\.:](\d{2,5})\s+0\.0\.0\.0:\*\s+LISTEN/);
    if (m) ports.add(Number(m[1]));
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
async function excludedPorts() {
  const t = pi.resolveTarget();
  return new Set([t.port, 22, 53, 80, 443]); // SSH port, default SSH, DNS, and the DNS backend's own web UI (already shown in the header)
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

module.exports = { discoverServices, cachedServices };
```

- [ ] **Step 3: Manual verification**

Run: `node -e "require('./src/main/db').init(); const svc=require('./src/main/pi-services'); svc.discoverServices().then(r=>console.log(JSON.stringify(r,null,2)))"` (run this from within the app process context isn't required for `pi.exec`/`lan.request`, both are plain Node — this standalone script works). Expected: JSON array including entries for whatever's actually listening on the real Pi (Plex/qBittorrent if running, plus AdGuard's own port already excluded).

- [ ] **Step 4: Commit**

```bash
git add src/main/pi-services.js src/main/db.js
git commit -m "Add generic Pi service auto-detection (open ports + title probe + small catalog)"
```

### Task 14: Wire service detection into IPC, credential-save trigger, and the Pi tab UI

**Files:**
- Modify: `src/main/index.js`, `src/preload.js`, `src/renderer/app.js` (`loadPiServices()`, referenced from Task 10's `loadPi()`)

**Interfaces:**
- Produces (IPC): `pi:services:list` (cached), `pi:services:rescan`. Preload: `pi.servicesList()`, `pi.servicesRescan()`.

- [ ] **Step 1: IPC handlers**

```js
const piServices = require("./pi-services");
ipcMain.handle("pi:services:list", () => piServices.cachedServices());
ipcMain.handle("pi:services:rescan", () => piServices.discoverServices());
```

Locate the existing credentials-save handler (`credentials:save`, in `src/main/index.js`) and, after a successful save where the saved MAC matches the current Pi's MAC (`db.getPiState().mac`), trigger one automatic rescan:

```js
ipcMain.handle("credentials:save", async (_e, { mac, label, username, password }) => {
  const r = credentials.save(mac, { label, username, password });
  if (r.ok && mac === db.getPiState().mac) {
    piServices.discoverServices().catch(() => {}); // best-effort, don't block the save response
  }
  return r;
});
```

(This assumes the current handler body is a direct call to `credentials.save` — adjust the wrapper to match whatever the existing handler already returns, without changing its response shape for callers other than this new side effect.)

- [ ] **Step 2: Preload bridge**

```js
servicesList: () => ipcRenderer.invoke("pi:services:list"),
servicesRescan: () => ipcRenderer.invoke("pi:services:rescan"),
```
(inside the `pi:` object in `src/preload.js`)

- [ ] **Step 3: Renderer**

```js
async function loadPiServices() {
  const list = await window.meshwatch.pi.servicesList();
  renderPiServices(list);
}

function renderPiServices(list) {
  const el = $("#pi-services");
  el.innerHTML = list.length
    ? "<ul>" + list.map((s) =>
        '<li>' + escapeHtml(s.name) + (s.name === "Unknown service" ? ' <span class="est">estimate</span>' : "") +
        " · port " + s.port + (s.title ? " · " + escapeHtml(s.title) : "") +
        ' <button type="button" class="pi-svc-open" data-url="' + escapeHtml(s.url) + '">Open</button></li>'
      ).join("") + "</ul>"
    : '<div class="empty">No extra services detected yet.</div>';
  $$(".pi-svc-open", el).forEach((b) => b.addEventListener("click", () => openInAppBrowser(b.dataset.url)));
}

$("#pi-rescan-services").addEventListener("click", async () => {
  toast("Rescanning services…");
  const list = await window.meshwatch.pi.servicesRescan();
  renderPiServices(list);
  toast(list.length + " service(s) found");
});
```

- [ ] **Step 4: Manual verification**

Run: `npm start`, open the Pi tab, click "Rescan services". Expected: Plex and qBittorrent (if currently running on the Pi) appear with recognized names; anything else listening shows as "Unknown service" with its observed page title, not hidden.

- [ ] **Step 5: Commit**

```bash
git add src/main/index.js src/preload.js src/renderer/app.js
git commit -m "Wire Pi service detection into the UI, auto-rescan on Pi credential save"
```

---

## Phase 6 — Promoted features (10)

### Task 15: Feature 1 — online/offline history sparkline per device

**Files:**
- Modify: `src/main/db.js` (query), `src/main/index.js` (IPC), `src/preload.js`, `src/renderer/app.js` (detail panel render, `openDetail()` around line 870-920)

**Interfaces:**
- Produces: `db.deviceUptimeHistory(mac, days)` → `Array<{day: "YYYY-MM-DD", onlineRatio: number}>`; IPC `device:uptimeHistory`; preload `uptimeHistory(mac, days)`.

- [ ] **Step 1: Query in `db.js`**

```js
function deviceUptimeHistory(mac, days = 14) {
  const since = Date.now() - days * 86400000;
  const rows = db.prepare(
    "SELECT seen_at FROM sightings WHERE mac = ? AND seen_at >= ? ORDER BY seen_at"
  ).all(mac, since);
  const byDay = new Map();
  for (const r of rows) {
    const day = new Date(r.seen_at).toISOString().slice(0, 10);
    byDay.set(day, (byDay.get(day) || 0) + 1);
  }
  const maxPerDay = Math.max(1, ...Array.from(byDay.values()));
  const out = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
    out.push({ day: d, onlineRatio: byDay.has(d) ? Math.min(1, byDay.get(d) / maxPerDay) : 0 });
  }
  return out;
}
```

Export `deviceUptimeHistory`.

- [ ] **Step 2: IPC + preload**

`index.js`: `ipcMain.handle("device:uptimeHistory", (_e, { mac, days }) => db.deviceUptimeHistory(mac, days));`
`preload.js` (top-level, alongside other `device`-ish calls like `renameDevice`): `uptimeHistory: (mac, days) => ipcRenderer.invoke("device:uptimeHistory", { mac, days }),`

- [ ] **Step 3: Render an inline SVG sparkline in the detail panel**

In `app.js`, add a helper and call it from `openDetail(d)` (after the existing `dl` rows are set, ~line 912-919):

```js
function sparklineSvg(points) {
  const w = 140, h = 24, step = w / Math.max(1, points.length - 1);
  const path = points.map((p, i) => (i === 0 ? "M" : "L") + (i * step).toFixed(1) + "," + (h - p.onlineRatio * h).toFixed(1)).join(" ");
  return '<svg width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + " " + h + '"><path d="' + path + '" fill="none" stroke="currentColor" stroke-width="1.5"/></svg>';
}

async function renderUptimeSparkline(d) {
  const history = await window.meshwatch.uptimeHistory(d.mac, 14);
  const holder = document.createElement("div");
  holder.className = "detail-section";
  holder.innerHTML = "Online history (14d) " + sparklineSvg(history);
  $("#detail-body").appendChild(holder);
}
```

Call `renderUptimeSparkline(d)` at the end of `openDetail(d)`.

- [ ] **Step 4: Manual verification**

Run: `npm start`, click any device in Inventory. Expected: a small line sparkline appears under the detail facts, reflecting real sighting density over the last 14 days (a device seen every scan shows a flat high line; an intermittent one shows dips).

- [ ] **Step 5: Commit**

```bash
git add src/main/db.js src/main/index.js src/preload.js src/renderer/app.js
git commit -m "Add per-device online/offline history sparkline in the detail panel"
```

### Task 16: Feature 2 — new-device desktop notification

**Files:**
- Modify: `src/main/db.js` (`upsertDevices` or equivalent, currently around lines 85-115 — need to detect "no prior row" before the upsert), `src/main/index.js` or wherever the scan-completion flow lives

**Interfaces:**
- Produces: `db.upsertDevices(devices)` returns `{newMacs: string[]}` in addition to whatever it already returns (check current return value before changing the shape — if it returns nothing today, this is additive).

- [ ] **Step 1: Detect new MACs in the upsert**

In `src/main/db.js`, find the device-upsert function (the one using the `INSERT ... ON CONFLICT` statement referenced around lines 91-112). Before running the upsert transaction, snapshot existing MACs:

```js
function upsertDevices(devices) {
  const existing = new Set(db.prepare("SELECT mac FROM devices").all().map((r) => r.mac));
  const newMacs = devices.filter((d) => d.mac && !existing.has(d.mac)).map((d) => d.mac);
  // ...existing upsert transaction logic unchanged...
  return { newMacs };
}
```

(Adjust to the function's real current name/signature — grep `db.js` for the `INSERT.*devices` statement to confirm; this plan assumes it's named `upsertDevices` and called once per scan with the full device list, matching the `notePiDiscovery(devices)` call site pattern already in `run()`.)

- [ ] **Step 2: Fire the notification where the scan result is consumed**

In `src/main/index.js`, find the scan IPC handler that calls the upsert (search for where `discovery.run()`'s result is passed to the db layer). After the upsert call:

```js
const { newMacs } = db.upsertDevices(devices);
if (newMacs.length && db.getSetting("pref_notify_new_device") !== "0") {
  const names = newMacs.map((m) => { const d = devices.find((x) => x.mac === m); return (d && d.name) || m; });
  new Notification({
    title: newMacs.length === 1 ? "New device on your network" : newMacs.length + " new devices on your network",
    body: names.slice(0, 5).join(", ") + (names.length > 5 ? "…" : "")
  }).show();
}
```

(`pref_notify_new_device` mirrors the existing `notifyNewDevice` renderer preference — confirm the exact setting key the renderer already writes via `window.meshwatch.prefs.set` for this toggle and reuse it rather than inventing a second one; grep `app.js` for `notifyNewDevice`/`pref-notify` to confirm the wire format before hardcoding the key name here.)

- [ ] **Step 3: Manual verification**

Since triggering a genuinely new device requires new hardware joining the LAN, verify by temporarily deleting one known, currently-offline device's row via a throwaway script against a **copy** of the userData db (never the live one), re-running discovery against that copy's logic in isolation is impractical — instead, verify by code review plus a targeted unit check: `node -e "const db=require('./src/main/db'); db.init(); console.log(typeof db.upsertDevices)"` confirms the function exists and is exported; full behavioral confirmation happens naturally the next time an actual new device joins the LAN (acceptable given no test framework and the risk of corrupting real device history otherwise).

- [ ] **Step 4: Commit**

```bash
git add src/main/db.js src/main/index.js
git commit -m "Notify on first-ever sighting of a new device"
```

### Task 17: Feature 3 — posture-score history

**Files:**
- Modify: `src/main/db.js` (new table + insert/read), `src/main/audit.js` (`run()`, currently ~line 247), `src/renderer/app.js` (Security view render)

**Interfaces:**
- Produces: `db.recordAuditRun(score, counts)`, `db.auditHistory(limit)` → `Array<{ts, score, counts}>`; IPC `audit:history`.

- [ ] **Step 1: Table + helpers in `db.js`**

```sql
CREATE TABLE IF NOT EXISTS audit_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER, score INTEGER, counts_json TEXT
);
```

```js
function recordAuditRun(score, counts) {
  db.prepare("INSERT INTO audit_runs (ts, score, counts_json) VALUES (?, ?, ?)").run(Date.now(), score, JSON.stringify(counts));
}

function auditHistory(limit = 30) {
  return db.prepare("SELECT ts, score, counts_json FROM audit_runs ORDER BY ts DESC LIMIT ?").all(limit)
    .reverse()
    .map((r) => ({ ts: r.ts, score: r.score, counts: JSON.parse(r.counts_json) }));
}
```

- [ ] **Step 2: Call it from `audit.js#run()`**

At the end of `run()` (currently ~line 247-262, right after `scoreFindings(findings)` computes `{score, counts}`), add: `require("./db").recordAuditRun(score, counts);` before the function returns.

- [ ] **Step 3: IPC + renderer**

`index.js`: `ipcMain.handle("audit:history", (_e, { limit }) => db.auditHistory(limit));`
`preload.js`: `auditHistory: (limit) => ipcRenderer.invoke("audit:history", { limit }),` (top-level, alongside `audit.run`/`audit.dismiss`).
`app.js`, in the Security view render function (search for where `state.audit.score` is displayed), add a sparkline above the score using the same `sparklineSvg()` helper from Task 15 (generalize it to accept a plain array of 0-1 values, or add a second small helper `sparklineFromScores(history)` that maps `score/100` to the ratio):

```js
async function renderAuditTrend() {
  const history = await window.meshwatch.auditHistory(30);
  const points = history.map((h) => ({ onlineRatio: h.score / 100 }));
  $("#audit-trend").innerHTML = points.length > 1 ? sparklineSvg(points) : "";
}
```

Add `<div id="audit-trend"></div>` near the existing posture-score element in `index.html`'s Security view, and call `renderAuditTrend()` wherever `audit:run`'s result is currently rendered (search `app.js` for `"Audit complete — score "`).

- [ ] **Step 4: Manual verification**

Run: `npm start`, run an audit twice (a few minutes apart is enough to get two distinct `ts` values). Expected: `await window.meshwatch.auditHistory(30)` in DevTools returns two rows; the Security view shows a two-point trend line.

- [ ] **Step 5: Commit**

```bash
git add src/main/db.js src/main/audit.js src/main/index.js src/preload.js src/renderer/index.html src/renderer/app.js
git commit -m "Record posture-score history and show a trend line in the Security view"
```

### Task 18: Feature 4 — full DB backup/restore

**Files:**
- Modify: `src/main/index.js` (IPC), `src/preload.js`, `src/renderer/index.html` (Preferences panel buttons), `src/renderer/app.js`

**Interfaces:**
- Produces: IPC `db:backup`, `db:restore`; preload `db.backup()`, `db.restore()`.

- [ ] **Step 1: IPC handlers**

```js
const fsPromises = require("fs/promises");

ipcMain.handle("db:backup", async (_e, { includeCredentials }) => {
  const r = await dialog.showSaveDialog(win, { title: "Backup Meshwatch data", defaultPath: "meshwatch-backup.db", filters: [{ name: "SQLite DB", extensions: ["db"] }] });
  if (r.canceled || !r.filePath) return { ok: false, cancelled: true };
  db.checkpoint(); // flush WAL before copying — see Step 2
  await fsPromises.copyFile(db.filePath(), r.filePath);
  if (includeCredentials === false) {
    const Database = require("better-sqlite3");
    const copy = new Database(r.filePath);
    copy.exec("DELETE FROM credentials");
    copy.close();
  }
  return { ok: true, path: r.filePath };
});

ipcMain.handle("db:restore", async () => {
  const r = await dialog.showOpenDialog(win, { title: "Restore Meshwatch data", properties: ["openFile"], filters: [{ name: "SQLite DB", extensions: ["db"] }] });
  if (r.canceled || !r.filePaths[0]) return { ok: false, cancelled: true };
  const { response } = await dialog.showMessageBox(win, {
    type: "warning", buttons: ["Cancel", "Restore and restart"], defaultId: 0, cancelId: 0,
    title: "Replace all current data?",
    detail: "This overwrites every device, finding, and note currently stored. The app will restart. Credentials encrypted on a different Windows account/machine will not decrypt here."
  });
  if (response !== 1) return { cancelled: true };
  await fsPromises.copyFile(r.filePaths[0], db.filePath());
  app.relaunch();
  app.exit(0);
});
```

- [ ] **Step 2: Add `filePath()` and `checkpoint()` to `db.js`**

```js
function filePath() { return file(); } // `file()` already exists (Step "init"), just needs exporting indirectly
function checkpoint() { db.pragma("wal_checkpoint(TRUNCATE)"); }
```

Export both.

- [ ] **Step 3: Preload + UI**

`preload.js` (top-level): 
```js
db: {
  backup: (includeCredentials) => ipcRenderer.invoke("db:backup", { includeCredentials }),
  restore: () => ipcRenderer.invoke("db:restore")
},
```

`index.html`, in the Preferences view, add near the existing CSV export button:
```html
<div class="btn-row">
  <label><input type="checkbox" id="pref-backup-creds" checked> Include saved credentials</label>
  <button type="button" id="pref-backup">Backup all data</button>
  <button type="button" id="pref-restore" class="warn">Restore from backup…</button>
</div>
```

`app.js`:
```js
$("#pref-backup").addEventListener("click", async () => {
  const r = await window.meshwatch.db.backup($("#pref-backup-creds").checked);
  if (r && r.ok) toast("Backup saved to " + r.path);
  else if (!r.cancelled) toast("Backup failed");
});
$("#pref-restore").addEventListener("click", () => window.meshwatch.db.restore());
```

- [ ] **Step 4: Manual verification**

Run: `npm start`, Preferences → "Backup all data" → save to a temp path → confirm the file exists and opens as a valid SQLite DB (`sqlite3 <path> ".tables"` if the `sqlite3` CLI is available, otherwise confirm via Node: `node -e "const D=require('better-sqlite3'); const d=new D(process.argv[1]); console.log(d.prepare('SELECT COUNT(*) c FROM devices').get())" <path>`). Then "Restore from backup…" with that same file and confirm the app relaunches without error.

- [ ] **Step 5: Commit**

```bash
git add src/main/db.js src/main/index.js src/preload.js src/renderer/index.html src/renderer/app.js
git commit -m "Add full database backup/restore from Preferences"
```

### Task 19: Feature 5 — scan-diff digest notification

**Files:**
- Modify: `src/main/index.js` (scan-completion flow, same area touched in Task 16)

**Interfaces:**
- Consumes: the existing config-drift check's output (find it — grep for "drift" in `db.js`/`index.js`; the spec assumes it already runs per scan and returns a change list).

- [ ] **Step 1: Locate the existing drift check**

Grep the codebase for the config-drift logic referenced in CLAUDE.md's Phase 1 checklist ("config-drift check"). It's expected to live in `db.js` or `discovery.js` and be called once per scan, returning something shaped like a list of `{mac, field, from, to}` or similar. Confirm its exact return shape by reading it before writing the notification code (do not guess the shape — this is exactly the kind of assumption CLAUDE.md warns against).

- [ ] **Step 2: Add the digest notification**

In the same scan-completion block touched by Task 16, after the drift check runs:

```js
const drift = /* existing drift-check call and result */;
const newCount = newMacs.length; // from Task 16
const vanishedCount = drift.filter((x) => x.type === "vanished").length; // adjust field name to the real shape found in Step 1
const changedCount = drift.length - vanishedCount;
if ((newCount || vanishedCount || changedCount) && db.getSetting("pref_notify_new_device") !== "0") {
  const parts = [];
  if (newCount) parts.push(newCount + " new");
  if (vanishedCount) parts.push(vanishedCount + " vanished");
  if (changedCount) parts.push(changedCount + " changed");
  new Notification({ title: "Network scan summary", body: parts.join(", ") + " since last scan" }).show();
}
```

(This may combine with Task 16's notification into one, to avoid double-notifying per scan — if so, merge both into a single `Notification` call covering new devices and drift together; use judgment based on the actual code found in Step 1 rather than firing two separate notifications for one scan.)

- [ ] **Step 3: Manual verification**

Run: `npm start`, run two scans in a row. Expected: a single OS notification summarizing the diff appears after the second scan (first scan has nothing to diff against). Toggle the "notify" preference off and confirm it stops.

- [ ] **Step 4: Commit**

```bash
git add src/main/index.js
git commit -m "Add scan-diff digest notification (new/vanished/changed since last scan)"
```

### Task 20: Feature 6 — Wake-on-LAN

**Files:**
- Create: `src/main/wol.js`
- Modify: `src/main/index.js` (IPC), `src/preload.js`, `src/renderer/app.js` (detail panel button, `openDetail(d)`)

**Interfaces:**
- Produces: `wol.wake(mac)` → `{ok, reason?}`; IPC `device:wake`; preload `wakeDevice(mac)`.

- [ ] **Step 1: `src/main/wol.js`**

```js
// Wake-on-LAN: broadcasts the standard 102-byte magic packet. Whether the
// target device actually wakes depends on WOL being enabled in its own
// BIOS/OS — that can't be verified remotely, so this never claims success
// beyond "packet sent".
const dgram = require("dgram");

function buildPacket(mac) {
  const macBytes = Buffer.from(mac.replace(/[:-]/g, ""), "hex");
  if (macBytes.length !== 6) throw new Error("invalid MAC");
  return Buffer.concat([Buffer.alloc(6, 0xff), Buffer.concat(Array(16).fill(macBytes))]);
}

function wake(mac, broadcastAddr = "255.255.255.255") {
  return new Promise((resolve) => {
    let packet;
    try { packet = buildPacket(mac); } catch (e) { return resolve({ ok: false, reason: "invalid MAC address" }); }
    const socket = dgram.createSocket("udp4");
    socket.bind(() => {
      socket.setBroadcast(true);
      socket.send(packet, 0, packet.length, 9, broadcastAddr, (err) => {
        socket.close();
        resolve(err ? { ok: false, reason: String(err.message || err) } : { ok: true });
      });
    });
  });
}

module.exports = { wake };
```

- [ ] **Step 2: IPC + preload**

`index.js`: `ipcMain.handle("device:wake", (_e, { mac }) => require("./wol").wake(mac));`
`preload.js` (top-level): `wakeDevice: (mac) => ipcRenderer.invoke("device:wake", { mac }),`

- [ ] **Step 3: Detail panel button**

In `app.js`'s `openDetail(d)`, near the existing `watchBtn`/`noteBtn` additions (~line 1006-1034):

```js
if (d.mac) {
  const wakeBtn = document.createElement("button");
  wakeBtn.type = "button";
  wakeBtn.textContent = "Wake device (WoL)";
  wakeBtn.title = "Only works if Wake-on-LAN is enabled in this device's own BIOS/OS — Meshwatch can't verify that remotely.";
  wakeBtn.addEventListener("click", async () => {
    const r = await window.meshwatch.wakeDevice(d.mac);
    toast(r.ok ? "Magic packet sent" : "Could not send: " + (r.reason || "unknown error"));
  });
  actions.appendChild(wakeBtn);
}
```

- [ ] **Step 4: Manual verification**

Run: `npm start`, open a device with WoL enabled (if any on the LAN — otherwise verify via `node -e "require('./src/main/wol').wake('AA:BB:CC:DD:EE:FF').then(console.log)"`, expecting `{ok: true}` since sending a broadcast UDP packet succeeds regardless of whether a listener wakes).

- [ ] **Step 5: Commit**

```bash
git add src/main/wol.js src/main/index.js src/preload.js src/renderer/app.js
git commit -m "Add Wake-on-LAN button to the device detail panel"
```

### Task 21: Feature 7 — device tags/groups

**Files:**
- Modify: `src/main/db.js` (new column + get/set), `src/main/index.js` (IPC), `src/preload.js`, `src/renderer/index.html` (Inventory filter row), `src/renderer/app.js` (detail panel tag editor, Inventory filter, Topology coloring)

**Interfaces:**
- Produces: `db.setDeviceTags(mac, tags[])`, devices already include a `tags` field once added to the `SELECT`/upsert paths; IPC `device:setTags`.

- [ ] **Step 1: Schema + accessor in `db.js`**

Add to the lightweight-migration column block (same pattern as the existing `newColumns` object, ~line 63-70): `tags: "TEXT DEFAULT '[]'"`.

```js
function setDeviceTags(mac, tags) {
  db.prepare("UPDATE devices SET tags = ? WHERE mac = ?").run(JSON.stringify(tags || []), mac);
}
```

Ensure the existing `listDevices()`-equivalent function parses `tags` from JSON when reading rows out (find where device rows are mapped for `devices:list`/`listDevices` and add `d.tags = JSON.parse(row.tags || "[]")` to that mapping).

- [ ] **Step 2: IPC + preload**

`index.js`: `ipcMain.handle("device:setTags", (_e, { mac, tags }) => { db.setDeviceTags(mac, tags); return { ok: true }; });`
`preload.js`: `setDeviceTags: (mac, tags) => ipcRenderer.invoke("device:setTags", { mac, tags }),`

- [ ] **Step 3: Detail panel tag editor**

In `openDetail(d)`, add after the note button:

```js
const tagSec = document.createElement("div");
tagSec.className = "detail-section";
tagSec.innerHTML = "Tags: " + (d.tags || []).map((t) => '<span class="chip">' + escapeHtml(t) + "</span>").join(" ");
actions.appendChild(tagSec);
const tagBtn = document.createElement("button");
tagBtn.type = "button";
tagBtn.textContent = "Edit tags";
tagBtn.addEventListener("click", async () => {
  const v = await askText({ title: "Tags for " + (d.name || d.ip), hint: "Comma-separated, your own words", value: (d.tags || []).join(", "), multiline: false });
  if (v == null) return;
  const tags = v.split(",").map((t) => t.trim()).filter(Boolean);
  await window.meshwatch.setDeviceTags(d.mac, tags);
  d.tags = tags;
  toast("Tags saved");
  openDetail(d);
});
actions.appendChild(tagBtn);
```

- [ ] **Step 4: Inventory filter chips**

Alongside the existing filter-chip rendering (search `app.js` for `state.chip` / the chip-building code near line 267), add a tag-chip row built from the union of all tags currently in `state.devices`, using the same click-to-filter pattern already used for the type chips — filter predicate: `d.tags && d.tags.includes(activeTagFilter)`.

- [ ] **Step 5: Topology coloring**

In the topology render function (search for where tree-row dots get their color/class, referenced near `app.js:473`), add: if `d.tags && d.tags[0]`, apply a CSS class `tag-color-<hash-of-tag>` or a `style="--tag-color: ..."` inline style derived from a small fixed palette indexed by `hashString(tag) % palette.length` — reuse whatever color-token approach `styles.css` already uses for existing status dots, don't introduce a new color system.

- [ ] **Step 6: Manual verification**

Run: `npm start`, open a device, add tags "IoT, Guest", confirm they render as chips, confirm the Inventory tag-filter chip for "IoT" shows only tagged devices, confirm Topology colors that device's node differently.

- [ ] **Step 7: Commit**

```bash
git add src/main/db.js src/main/index.js src/preload.js src/renderer/index.html src/renderer/app.js src/renderer/styles.css
git commit -m "Add user-assignable device tags with Inventory filtering and Topology coloring"
```

### Task 22: Feature 8 — advertised-services list per device

**Files:**
- Modify: `src/main/discovery.js` (mdnsBrowse/ssdpSearch dedup fix, lines 175-235; merge loop, lines 680-798), `src/main/db.js` (new column), `src/main/index.js`, `src/renderer/app.js` (`openDetail(d)`)

**Interfaces:**
- Produces: `devices[].services` → `Array<{type, source}>`, persisted as `devices.services TEXT` (JSON).

- [ ] **Step 1: Stop deduping mDNS/SSDP hits down to one per IP**

In `src/main/discovery.js`, replace `mdnsBrowse`'s `found` Map-keyed-by-IP (lines 184, 189, 202) with an array keyed by `ip + type` so multiple service types per IP are all kept:

```js
const found = [];
const seen = new Set();
const record = (service) => {
  const ip = (service.addresses || []).find(a => IPV4_RE.test(a) && isDiscoverableHost(a))
    || (service.referer && service.referer.address);
  if (!ip || !isDiscoverableHost(ip)) return;
  const key = ip + "|" + (service.type || "");
  if (seen.has(key)) return;
  seen.add(key);
  found.push({ ip, name: service.name || null, service: service.type || null });
};
```
And change the `setTimeout` resolve at line 202 from `resolve(Array.from(found.values()))` to `resolve(found)`.

Apply the equivalent change to `ssdpSearch` (lines 216-227), keyed by `ip + "|" + (headers.ST || "")`, pushing to an array instead of `found.set(ip, ...)`.

- [ ] **Step 2: Update the merge loop to collect all hits, not just one**

In `run()` (lines 680-701), replace:
```js
const m = mdns.find(x => x.ip === entry.ip);
const s = ssdp.find(x => x.ip === entry.ip);
```
with:
```js
const mHits = mdns.filter(x => x.ip === entry.ip);
const sHits = ssdp.filter(x => x.ip === entry.ip);
const m = mHits.find(x => x.name) || mHits[0];
const s = sHits[0];
```
and add `mdnsHits: mHits, ssdpHits: sHits` to the object passed to `byMac.set(...)` alongside the existing `mdnsHit: m, ssdpHit: s`.

- [ ] **Step 3: Compute the services array before the final cleanup**

Right before the existing cleanup block (lines 795-798: `delete d.lease; delete d.mdnsHit; delete d.ssdpHit; ...`), add:

```js
for (const d of devices) {
  const svc = []
    .concat((d.mdnsHits || []).filter((x) => x.service).map((x) => ({ type: x.service, source: "mdns" })))
    .concat((d.ssdpHits || []).filter((x) => x.st).map((x) => ({ type: x.st, source: "ssdp" })));
  const seen = new Set();
  d.services = svc.filter((s) => { const k = s.source + s.type; if (seen.has(k)) return false; seen.add(k); return true; });
}
```

Then extend the existing cleanup line to also delete the now-unneeded raw hits: `delete d.lease; delete d.mdnsHit; delete d.ssdpHit; delete d.mdnsHits; delete d.ssdpHits; delete d.dnsName; delete d.netbiosName;`

- [ ] **Step 4: Persist and surface**

`db.js`: add `services: "TEXT DEFAULT '[]'"` to the migration-column set (same pattern as Task 21's `tags`), include `services: JSON.stringify(d.services || [])` in the upsert's bound parameters, and parse it back out (`d.services = JSON.parse(row.services || "[]")`) wherever device rows are read for the renderer.

`app.js`, in `openDetail(d)`, near the top where the `dl` facts are built (~line 900-911), add a services chip row after the `dl`:

```js
if (d.services && d.services.length) {
  const svcSec = document.createElement("div");
  svcSec.className = "detail-section";
  svcSec.innerHTML = "Advertises: " + d.services.map((s) => '<span class="chip">' + escapeHtml(s.type) + "</span>").join(" ");
  $("#detail-body").appendChild(svcSec);
}
```

- [ ] **Step 5: Manual verification**

Run: `npm start`, run a scan, open a device known to advertise multiple mDNS services (e.g. a Chromecast or a printer). Expected: the detail panel shows multiple service-type chips, not just one; devices with no mDNS/SSDP presence show no chip row (not an empty one).

- [ ] **Step 6: Commit**

```bash
git add src/main/discovery.js src/main/db.js src/main/index.js src/renderer/app.js
git commit -m "Surface all advertised mDNS/SSDP service types per device, not just the first match"
```

### Task 23: Feature 9 — LAN latency/health sampling

**Files:**
- Create: `src/main/latency.js`
- Modify: `src/main/db.js` (table), `src/main/index.js` (interval timer + IPC), `src/preload.js`, `src/renderer/app.js` (Overview sparkline)

**Interfaces:**
- Produces: `latency.sampleOnce()`, `db.recordLatency(target, ms)`, `db.latencyHistory(target, limit)`; IPC `latency:history`.

- [ ] **Step 1: `src/main/latency.js`**

```js
// Lightweight round-trip latency sampling to the gateway and (if present)
// the Pi — not a full speed test, just enough to catch a degrading
// extender/AP before it fully drops.
const ping = require("ping");
const db = require("./db");
const discovery = require("./discovery");

async function sampleOnce() {
  const targets = [];
  const gw = await discovery.detectSubnet();
  if (gw && gw.gateway) targets.push({ label: "gateway", ip: gw.gateway });
  const piState = db.getPiState();
  if (piState.ip) targets.push({ label: "pi", ip: piState.ip });

  for (const t of targets) {
    try {
      const r = await ping.promise.probe(t.ip, { timeout: 2 });
      db.recordLatency(t.label, r.alive ? Math.round(Number(r.time)) : null);
    } catch (e) { /* skip this sample */ }
  }
}

module.exports = { sampleOnce };
```

(Confirm `discovery.detectSubnet()`'s actual return shape includes a `gateway` field before relying on it — grep `discovery.js` for `defaultGateway`/`detectSubnet`'s return object and adjust the field name if different.)

- [ ] **Step 2: Table + accessors in `db.js`**

```sql
CREATE TABLE IF NOT EXISTS latency_samples (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER, target TEXT, ms INTEGER
);
CREATE INDEX IF NOT EXISTS idx_latency_target ON latency_samples(target, ts);
```

```js
function recordLatency(target, ms) {
  db.prepare("INSERT INTO latency_samples (ts, target, ms) VALUES (?,?,?)").run(Date.now(), target, ms);
}
function latencyHistory(target, limit = 50) {
  return db.prepare("SELECT ts, ms FROM latency_samples WHERE target = ? ORDER BY ts DESC LIMIT ?").all(target, limit).reverse();
}
```

- [ ] **Step 3: Interval timer in `index.js`**

Near wherever the existing auto-scan interval timer is set up (search for `autoScan`/`setInterval` in `index.js`), add a second, independent interval:

```js
setInterval(() => { require("./latency").sampleOnce().catch(() => {}); }, 5 * 60 * 1000);
```

(Fixed 5-minute cadence — not tied to the auto-scan preference, since latency sampling is cheap and independent of full network scans.)

`ipcMain.handle("latency:history", (_e, { target, limit }) => db.latencyHistory(target, limit));`
`preload.js`: `latencyHistory: (target, limit) => ipcRenderer.invoke("latency:history", { target, limit }),`

- [ ] **Step 4: Overview sparkline**

In `app.js`'s Overview render function, add:

```js
async function renderLatencySparklines() {
  const gw = await window.meshwatch.latencyHistory("gateway", 50);
  const points = gw.filter((s) => s.ms != null).map((s) => ({ onlineRatio: Math.max(0, 1 - s.ms / 100) }));
  const el = $("#overview-latency");
  if (el) el.innerHTML = points.length > 1 ? "Gateway latency " + sparklineSvg(points) : "";
}
```

Add `<div id="overview-latency"></div>` to the Overview view in `index.html`, call `renderLatencySparklines()` wherever the Overview is (re)rendered.

- [ ] **Step 5: Manual verification**

Run: `npm start`, wait 10+ minutes (two sample intervals) or temporarily lower the interval to 10s for local testing (revert before commit). Expected: `await window.meshwatch.latencyHistory("gateway", 50)` returns growing samples; Overview shows a sparkline once 2+ samples exist.

- [ ] **Step 6: Commit**

```bash
git add src/main/latency.js src/main/db.js src/main/index.js src/preload.js src/renderer/index.html src/renderer/app.js
git commit -m "Add periodic LAN latency sampling to gateway/Pi with an Overview sparkline"
```

### Task 24: Feature 10 — per-client DNS query trend

**Files:**
- Modify: `src/main/db.js` (table), `src/main/index.js` (persist on each `pi:stats` call or scan), `src/renderer/app.js` (Pi tab trend view)

**Interfaces:**
- Produces: `db.recordTalkers(talkers[])`, `db.talkerHistory(clientIp, limit)`.

- [ ] **Step 1: Table + accessors**

```sql
CREATE TABLE IF NOT EXISTS dns_talkers_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER, client_ip TEXT, client_name TEXT, queries INTEGER
);
```

```js
function recordTalkers(talkers) {
  const now = Date.now();
  const ins = db.prepare("INSERT INTO dns_talkers_history (ts, client_ip, client_name, queries) VALUES (?,?,?,?)");
  const tx = db.transaction((list) => { for (const t of list) ins.run(now, t.ip || null, t.name || null, t.queries || 0); });
  tx(talkers || []);
}
function talkerHistory(clientIp, limit = 20) {
  return db.prepare("SELECT ts, queries FROM dns_talkers_history WHERE client_ip = ? ORDER BY ts DESC LIMIT ?").all(clientIp, limit).reverse();
}
```

- [ ] **Step 2: Persist on each stats fetch**

In `src/main/index.js`'s `pi:stats` handler (Task 6), change it to also record:

```js
ipcMain.handle("pi:stats", async () => {
  const s = await dns.stats();
  if (s && s.available && Array.isArray(s.talkers)) db.recordTalkers(s.talkers);
  return s;
});
```

- [ ] **Step 3: Renderer trend view**

In the Pi tab's DNS stats section (Task 10), add a small per-client trend on demand — since showing every client's trend at once is noisy, add it to each talker row as a click target:

```js
// inside the code that renders s.talkers in loadPi() / a new renderTalkers():
talkersEl.innerHTML = "<ul>" + (s.talkers || []).map((t) =>
  '<li class="talker-row" data-ip="' + escapeHtml(t.ip || "") + '">' + escapeHtml(t.name || t.ip) + " — " + t.queries + " queries</li>"
).join("") + "</ul><div id='pi-talker-trend'></div><p class='muted'>DNS queries, not bandwidth.</p>";
$$(".talker-row", talkersEl).forEach((row) => row.addEventListener("click", async () => {
  const history = await window.meshwatch.talkerHistory(row.dataset.ip, 20);
  const points = history.map((h) => ({ onlineRatio: Math.min(1, h.queries / Math.max(1, Math.max(...history.map(x => x.queries)))) }));
  $("#pi-talker-trend").innerHTML = points.length > 1 ? sparklineSvg(points) : "<span class='muted'>Not enough history yet</span>";
}));
```

Add `talkerHistory: (clientIp, limit) => ipcRenderer.invoke("talker:history", { clientIp, limit }),` to `preload.js`, and `ipcMain.handle("talker:history", (_e, { clientIp, limit }) => db.talkerHistory(clientIp, limit));` to `index.js`. Add a `#pi-stats` sibling container (`<div id="pi-talkers"></div>`) to `index.html` if the current markup doesn't already have a distinct home for the talkers list separate from `#pi-dns-blocked`.

- [ ] **Step 4: Manual verification**

Run: `npm start`, open the Pi tab a few times over a few minutes (each open records a talkers snapshot). Click a client row. Expected: a trend sparkline appears once 2+ snapshots exist for that client; the "DNS queries, not bandwidth" label is visible.

- [ ] **Step 5: Commit**

```bash
git add src/main/db.js src/main/index.js src/preload.js src/renderer/app.js src/renderer/index.html
git commit -m "Track per-client DNS query history and show a trend on click in the Pi tab"
```

---

## Phase 7 — Documentation and repo hygiene (safe subset only)

### Task 25: Rewrite CLAUDE.md to describe the application, not the user's infrastructure

**Files:**
- Modify: `D:\repos\meshwatch\CLAUDE.md`

- [ ] **Step 1: Remove the infrastructure-specific content**

Delete entirely: the "The network this app monitors" section's device table (vendor models, confirmed IPs `192.168.1.63`/`192.168.1.24`, "this LAN uses 2222" note) and the "Clients seen before" list. Keep the *concept* — that `config/devices.json` holds hints, not ground truth — but state it generically, without this user's specific device inventory.

- [ ] **Step 2: Reword the DNS-backend-specific paragraph**

Replace "The Pi-hole is the DHCP server, so its lease table is the authoritative source of device hostnames..." with: "Whichever DNS/DHCP backend is running on the discovered Pi (Pi-hole or AdGuard Home, auto-detected — see `src/main/dns/`) is the authoritative source of device hostnames when it's also acting as DHCP server. Always prefer a DHCP hostname over an mDNS name or an OUI vendor guess."

- [ ] **Step 3: Update the `Files` table**

Replace the `src/main/pihole.js` row with rows for `src/main/pi.js`, `src/main/dns/` (pihole.js, adguard.js, index.js), `src/main/pi-services.js`, `src/main/wol.js`, `src/main/latency.js`.

- [ ] **Step 4: Update Build Order**

Add a `Phase 7` entry describing this pass: dynamic DNS backend detection, Pi system admin, embedded terminal, generic service discovery, and the 10 promoted features, marked `[x]` once implementation is verified complete (Phase 8's ideas section is now empty/removed since everything was promoted).

- [ ] **Step 5: Manual verification**

Read the finished file top to bottom: confirm no IP address, SSH port number, or specific device model/serial from the user's real network remains anywhere in it.

- [ ] **Step 6: Commit**

```bash
git add CLAUDE.md
git commit -m "Rewrite CLAUDE.md to describe the application's design, not this user's home network"
```

### Task 26: Write `docs/HLD.md`

**Files:**
- Create: `docs/HLD.md`

- [ ] **Step 1: Write the high-level design doc**

Cover, in prose + one architecture diagram (ASCII or a simple box list, no external tooling needed): the three-process model (main/renderer/preload, `contextIsolation` boundary), the in-app admin-page browser (`WebContentsView`), major subsystems and their responsibilities (discovery, DNS backend adapters, Pi system administration + terminal, credential vault, security audit, TP-Link control), how data flows from a scan through to the renderer, why each Hard Rule exists (LAN-only, no plaintext secrets, no invented data, confirmation before disruptive actions). No IPs, hostnames, or device models from any real network — describe the *shape* of the system, generically.

- [ ] **Step 2: Manual verification**

Read for accuracy against the actual current module list (`src/main/*.js` after all prior tasks) — every subsystem named in the doc must have a corresponding real file.

- [ ] **Step 3: Commit**

```bash
git add docs/HLD.md
git commit -m "Add High-Level Design document"
```

### Task 27: Write `docs/LLD.md`

**Files:**
- Create: `docs/LLD.md`

- [ ] **Step 1: Write the low-level design doc**

Cover: full DB schema (every table after this pass's additions — devices with its new `tags`/`services` columns, sightings, findings, credentials, settings, finding_dismissals, audit_runs, pi_services, latency_samples, dns_talkers_history — columns and purpose for each); the complete IPC channel catalog (every `pi:*`, `device:*`, `db:*`, `audit:*`, `latency:*`, `talker:*` channel with its request/response shape, grouped by subsystem); the DNS adapter contract (`stats()`/`leases()`/`blockClient()` shapes, shared by both backends); the terminal protocol (session lifecycle, message shapes for `pi:term:*`); the service-detection catalog format (`KNOWN_SERVICES` entry shape) and how an unmatched service is represented.

- [ ] **Step 2: Manual verification**

Cross-check every IPC channel name listed in the doc against an actual `ipcMain.handle`/`ipcMain.on` call in `src/main/index.js` — no channel should be documented that doesn't exist in code, and no channel added during this plan should be missing from the doc.

- [ ] **Step 3: Commit**

```bash
git add docs/LLD.md
git commit -m "Add Low-Level Design document"
```

### Task 28: Rewrite README.md for a public audience

**Files:**
- Modify (or create if absent): `D:\repos\meshwatch\README.md`

- [ ] **Step 1: Check whether a README already exists**

If `README.md` doesn't exist yet, create it. If it does, read it fully before rewriting (per the standing rule against publishing/overwriting content without reading it first).

- [ ] **Step 2: Write the public-facing README**

Cover: what Meshwatch is (one paragraph), key features (discovery, topology, security audit, Pi-hole/AdGuard integration, credential vault, embedded terminal), a short "privacy and security posture" section (LAN-only scanning, OS-backed credential encryption, no telemetry, no cloud dependency — call these out as selling points, they're genuinely differentiating), build/run instructions (`npm start`, `npm run build:win`/`build:mac`), and a link to `docs/HLD.md`/`docs/LLD.md` for contributors. No personal network details, no screenshots containing real device names/IPs (flag for the user to supply anonymized/mock screenshots separately — do not generate fake ones that could be mistaken for real captured data).

- [ ] **Step 3: Manual verification**

Read the finished file for the same personal-data check as Task 25.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "Rewrite README for public release"
```

### Task 29: Remove `design/` from the working tree (history rewrite excluded — see plan header)

**Files:**
- Delete: `design/` (entire directory)

- [ ] **Step 1: Confirm nothing else references it**

Grep the repo for `design/` (e.g. in `package.json`'s `files` list, any script, or CLAUDE.md after Task 25's rewrite) to confirm removing the directory doesn't break a build step or leave a dangling doc link.

- [ ] **Step 2: Remove it**

```bash
git rm -r design/
```

- [ ] **Step 3: Manual verification**

Run: `npm run build:win` — confirm the build still completes (proving nothing in the build pipeline depended on `design/`).

- [ ] **Step 4: Commit**

```bash
git commit -m "Remove design/ from the working tree (superseded by the built UI + HLD/LLD docs)"
```

**Note for whoever executes this task:** this removes the folder going forward only. It still exists in every prior commit's history. Rewriting history to purge it — and the associated full-history secret scan — is intentionally not part of this plan (see the plan header and the spec's "Repo cleanup for public release" section) and must be done as a separate, explicitly-confirmed step directly with the user, not dispatched to a subagent.

---

## Self-Review Notes

- **Spec coverage:** every section of the spec (module split, DNS adapters, IPC/renderer rename, settings migration, Pi system panel, terminal, service detection, UI layout, docs, all 10 promoted features) maps to at least one task above. The spec's public-release cleanup section maps to Tasks 26-29 for its safe parts; the destructive git-history part is deliberately excluded per the plan header.
- **Placeholder scan:** the two spots that reference "confirm the real shape before writing" (Task 19 Step 1's drift-check shape, Task 23 Step 1's `detectSubnet()` gateway field) are not placeholders for missing design — they're explicit instructions to read specific, named existing code before wiring to it, which is the correct behavior given this plan was written without re-reading every byte of `discovery.js` a second time; they name exactly what to look for and where.
- **Type consistency:** `pi.resolveTarget()` is used with the same shape (`{host, port, user, mac, discovered, online, keyPath}`) across Tasks 3, 4, 8, 9, 11, 13. `dns.stats()`'s return shape (`{available, reason?, host, version, queriesToday, blockedToday, blockedPercent, blocklist, firmware, hostNote, blocked[], talkers[]}`) is identical between `dns/pihole.js`, `dns/adguard.js`, and every renderer consumer in Task 10/24. `sparklineSvg(points)` (Task 15) is reused as-is by Tasks 17 and 23 rather than redefined.
