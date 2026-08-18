# Changelog

All notable changes to Meshwatch are documented here. The format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); releases
are tagged `vYYYY.M.D[-N]` rather than semantic versions — see
[`.github/workflows/release.yml`](.github/workflows/release.yml) for why.
Every tagged release is also published on the
[Releases page](https://github.com/alexivanov-ai/meshwatch/releases), with
notes generated from merged pull requests
(see [`.github/release.yml`](.github/release.yml) for how those are
categorized).

## [Unreleased]

- Windows installer now shows the file list and install steps on the
  Installing page instead of a blank progress screen.
- Fixed light text showing up in light theme (and dark text in dark
  theme) on dropdowns, search boxes and checkboxes — they were following
  Windows' theme instead of Meshwatch's.
- Hid "Scan network now" on the Discovery page after a sweep has already
  run; Rescan on that page is the same action.
- Fixed the system tray icon missing from installed Windows builds. The
  tray pictures were never included in the installer, so the tray slot
  was blank.
- Added a linting workflow: ESLint for the JS (main process, preload,
  renderer, scripts), markdownlint-cli2 for the docs, PSScriptAnalyzer for
  `scripts/make-icon.ps1`, and general repo hygiene (trailing whitespace,
  EOF newline, JSON/YAML syntax, merge-conflict markers, line endings) —
  all wired through a `.pre-commit-config.yaml` and run on every PR via
  `.github/workflows/lint.yml`.
- Normalized line endings to LF repo-wide and added a `.gitattributes` so
  that doesn't drift again between contributors' local Git settings.
- Pinned every GitHub Actions step to a commit SHA (with a version comment)
  instead of a floating tag, and added a `github-actions` Dependabot
  ecosystem so those pins get bumped automatically.
- Categorized the auto-generated release notes by PR label
  (`.github/release.yml`).
- Rewrote `CLAUDE.md` as durable project guidance (hard rules, module map,
  when to ask before acting) instead of a phase-by-phase build log.
- Pi tab polish: readable "Open" buttons on Detected services rows, a
  clearer "not identified" label (with a tooltip) instead of a bare
  "estimate" chip, a search/collapse UI for the installed-apps list, live
  streamed output for "Upgrade all" instead of a bare progress bar, removal
  of the redundant one-shot command runner now that the embedded terminal
  exists, real visual hierarchy for the apt-check result, an editable
  address bar in the in-app device-admin browser, and a fix for admin
  pages served over HTTPS with a self-signed certificate (the gateway
  router, most notably).

## [2026.8.17-2] - 2026-08-17

Initial public release. See [`README.md`](README.md#features) for the full
feature set at this point: device discovery (ping sweep + ARP, mDNS, SSDP,
DNS PTR, NetBIOS), automatic scan-boundary detection, topology and
inventory views, a security audit, Pi-hole/AdGuard Home DNS backend
integration, an embedded SSH terminal, an OS-encrypted credential vault, an
in-app device-admin browser, Wake-on-LAN, device tags, latency monitoring,
CSV export, database backup/restore, and config-drift detection.
