# DeleteMSWindowsTraces

[![License](https://img.shields.io/github/license/Hawkynt/DeleteMSWindowsTraces)](https://github.com/Hawkynt/DeleteMSWindowsTraces/blob/main/LICENSE)
[![Language](https://img.shields.io/github/languages/top/Hawkynt/DeleteMSWindowsTraces?color=8957D5)](https://github.com/Hawkynt/DeleteMSWindowsTraces)

[![CI](https://github.com/Hawkynt/DeleteMSWindowsTraces/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Hawkynt/DeleteMSWindowsTraces/actions/workflows/ci.yml)
![Last Commit](https://img.shields.io/github/last-commit/Hawkynt/DeleteMSWindowsTraces?branch=main)
![Activity](https://img.shields.io/github/commit-activity/m/Hawkynt/DeleteMSWindowsTraces)

[![Stars](https://img.shields.io/github/stars/Hawkynt/DeleteMSWindowsTraces?color=FFD700)](https://github.com/Hawkynt/DeleteMSWindowsTraces/stargazers)
[![Forks](https://img.shields.io/github/forks/Hawkynt/DeleteMSWindowsTraces?color=008080)](https://github.com/Hawkynt/DeleteMSWindowsTraces/network/members)
[![Issues](https://img.shields.io/github/issues/Hawkynt/DeleteMSWindowsTraces)](https://github.com/Hawkynt/DeleteMSWindowsTraces/issues)
![Code Size](https://img.shields.io/github/languages/code-size/Hawkynt/DeleteMSWindowsTraces?color=4CAF50)
![Repo Size](https://img.shields.io/github/repo-size/Hawkynt/DeleteMSWindowsTraces?color=FF9800)

[![Release](https://img.shields.io/github/v/release/Hawkynt/DeleteMSWindowsTraces)](https://github.com/Hawkynt/DeleteMSWindowsTraces/releases/latest)
[![Nightly](https://img.shields.io/github/v/release/Hawkynt/DeleteMSWindowsTraces?include_prereleases&sort=date&label=nightly&color=FF9800)](https://github.com/Hawkynt/DeleteMSWindowsTraces/releases)
[![Downloads](https://img.shields.io/github/downloads/Hawkynt/DeleteMSWindowsTraces/total)](https://github.com/Hawkynt/DeleteMSWindowsTraces/releases)

> A single Windows batch script that removes the crap tracking what you do under Windows — it disables telemetry and data collection, strips bundled bloatware like Edge, Cortana, Maps and Bing apps, and wipes the usage traces (temp files, MRUs, jumplists, prefetch, event logs, recycle bins) that accumulate during daily work; useful when you want a machine to stop phoning home and to stop remembering, without installing yet another cleaner suite.

## 📦 Install

Download `DeleteTraces.bat` from the [latest release](https://github.com/Hawkynt/DeleteMSWindowsTraces/releases/latest) (or a [nightly](https://github.com/Hawkynt/DeleteMSWindowsTraces/releases)), or clone the repository. Place `install_wim_tweak.exe` in the folder **above** the script — the script aborts safely when it is missing.

## 🚀 Usage

Run from an elevated command prompt (registry, services and scheduled tasks are modified):

```text
DeleteTraces.bat
```

Every action announces itself with an `[Info]` line; anything not present on your system is skipped.

**Warning** — this script is intentionally destructive: it permanently deletes temp files, MRU lists, recycle bin contents and **all event logs**, removes Windows components that are hard to get back without reinstalling, restarts `explorer.exe` to flush the icon caches, and encrypting the paging file requires a reboot to take effect. Run it on systems you own and understand; there is no undo.

## ✨ Features

- **Silences telemetry and data collection** — Windows Error Reporting, Customer Experience Improvement Program, Application Experience tasks, Defender SpyNet reporting and sample submission, Windows Tips/Spotlight/consumer features
- **Blocks Microsoft account logons** and setting synchronization, and encrypts the paging file so swapped-out secrets stay secret
- **Removes bloatware** — Edge / Internet Explorer (executables get neutralized too), Cortana (including a firewall block for SearchUI), Maps, Sticky Notes, Bing apps, Get Help / Contact Support, Hello Face, Biometrics, Geolocation, Quick Assist, Retail Demo and Troubleshooting packages
- **Disables the search indexer** and a pile of unneeded scheduled tasks
- **Wipes usage traces** for **every** user profile — temp folders, crash dumps, prefetch files, recent files, jumplists, Office MRUs, typed addresses, Run dialog history, Visual Studio MRU lists, recycle bins on all drives, all event logs and the icon caches
- Optional: re-enable the commented-out CCleaner step if `CCleaner\CCleaner.exe` sits in the parent folder

## 🛠️ Building

There is nothing to compile — the batch file is the artifact. The [Pester](https://pester.dev/) test suite statically analyzes the script (encoding, line endings, label/call/goto resolution, `setlocal` scoping) and smoke-tests the prerequisite abort path:

```bash
pwsh -Command "Invoke-Pester -Path tests"
```

The same suite runs in CI on every push and gates every release; see [.github/workflows](.github/workflows/README.md) for the full pipeline.

## ❤️ Support

If this project saves you time or money, consider supporting its development:

[![GitHub Sponsors](https://img.shields.io/badge/GitHub-Sponsor-EA4AAA?logo=githubsponsors)](https://github.com/sponsors/Hawkynt)
[![PayPal](https://img.shields.io/badge/PayPal-Donate-00457C?logo=paypal)](https://www.paypal.me/hawkynt)

## 📜 License

Licensed under LGPL-3.0-or-later — see [LICENSE](LICENSE).
