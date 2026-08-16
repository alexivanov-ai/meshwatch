# home-monitoring

Home monitoring app for all your devices.

Meshwatch: a desktop dashboard for the local network - device discovery,
topology, firmware auditing, TP-Link control and Pi-hole management.

## Start here

1. Open `build-guide.html` in a browser and read sections 1 and 2.
2. Install Node.js LTS, Git, VS Code and Npcap as the guide describes.
3. In this folder, run the three commands below.
4. Phase 1 (discovery) is done - open `PROMPTS.md` and paste phase 2 into Claude Code next.

```
npm install
npm start            # an app window should open
npm run test:discovery   # prints what it finds on your network
```

If `npm start` opens a window and the scan button lists devices, the scaffold
is working and you can begin phase 1.

## What is already built

Phase 0 and phase 1 are done: Electron shell with secure IPC, SQLite storage,
electron-builder configured for both installers, and a working discovery
engine - ping sweep + ARP, mDNS, SSDP, a plain HTTP probe of each device's own
admin page, OS default-gateway detection, and a local encrypted credential
vault for any device with a login page. `npm run test:discovery` prints what
it actually finds; `config/devices.json` only labels a device once discovery
has found it (see CLAUDE.md - it never asserts an address it hasn't confirmed).

Everything from phase 2 onward is deliberately stubbed with `TODO phase N`
comments marking exactly where the work goes. The stubs return honest "not
implemented" values rather than fake data.

## Files

| File | What it is |
| --- | --- |
| `build-guide.html` | The full build guide. Read this first |
| `PROMPTS.md` | Six copy-paste prompts, one per phase |
| `CLAUDE.md` | Project facts and rules. Claude Code reads this every session |
| `prototype.html` | The interactive design prototype. Phase 5 rebuilds the UI from it |
| `src/main/` | Discovery, database, Pi-hole, TP-Link, audit |
| `src/preload.js` | The only bridge to the renderer |
| `src/renderer/` | Interface. Replaced in phase 5 |
| `config/devices.json` | Known models/roles - not a source of truth for addresses |
| `scripts/test-discovery.js` | Run discovery from the terminal |

## The network this is built for

- Gateway: TP-Link Archer BE220 at `192.168.1.1`
- DNS + DHCP: Raspberry Pi 5 at `192.168.1.63` running Pi-hole, SSH on port `2222`
- Subnet: `192.168.1.0/24`
- Wi-Fi nodes: Archer AX20 (AP mode), RE450 extender, TL-WA1201 extender
- Unmanaged: 8-port switch, Broadcom access point, TL-WDR4300 (end of support)
- Clients: MacBook Pro, desktop, two laptops, OnePlus Nord 4, PlayStation 4 Pro,
  Sony Bravia, GREE air conditioner

## Build order

Discovery first, interface last. If the scan does not reliably find your
devices, nothing built on top of it is worth anything.

1. Electron scaffold - done
2. Discovery engine - ARP, mDNS, SSDP, DHCP leases from Pi-hole
3. Pi-hole integration and the SSH console
4. TP-Link control
5. Security audit
6. The interface, matched to the prototype
7. Installers

## Output

`npm run build:win` produces a Windows installer in `dist/`.
`npm run build:mac` produces a macOS `.dmg` - this only works on a Mac.
Both are unsigned, so the first launch shows a warning you can click past.

## Updates

Same `appId` means a newer Windows installer upgrades the existing install in
place - no uninstall first. Scan history, notes and saved device passwords live
under the OS user-data folder and are kept across upgrades.

Installed builds also check GitHub Releases on launch (`electron-updater`).
When a newer release is ready they offer Restart now; that applies the update
without you downloading the installer by hand. Dev mode (`npm start`) skips
update checks.
