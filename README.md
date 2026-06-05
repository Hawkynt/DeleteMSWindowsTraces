# 🧹 DeleteMSWindowsTraces

[![License](https://img.shields.io/github/license/Hawkynt/DeleteMSWindowsTraces)](https://github.com/Hawkynt/DeleteMSWindowsTraces/blob/master/LICENSE)
[![Language](https://img.shields.io/github/languages/top/Hawkynt/DeleteMSWindowsTraces?color=8957D5)](https://github.com/Hawkynt/DeleteMSWindowsTraces)

[![CI](https://github.com/Hawkynt/DeleteMSWindowsTraces/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/Hawkynt/DeleteMSWindowsTraces/actions/workflows/ci.yml)
![Last Commit](https://img.shields.io/github/last-commit/Hawkynt/DeleteMSWindowsTraces?branch=master)
![Activity](https://img.shields.io/github/commit-activity/m/Hawkynt/DeleteMSWindowsTraces)

[![Stars](https://img.shields.io/github/stars/Hawkynt/DeleteMSWindowsTraces?color=FFD700)](https://github.com/Hawkynt/DeleteMSWindowsTraces/stargazers)
[![Forks](https://img.shields.io/github/forks/Hawkynt/DeleteMSWindowsTraces?color=008080)](https://github.com/Hawkynt/DeleteMSWindowsTraces/network/members)
[![Issues](https://img.shields.io/github/issues/Hawkynt/DeleteMSWindowsTraces)](https://github.com/Hawkynt/DeleteMSWindowsTraces/issues)
![Code Size](https://img.shields.io/github/languages/code-size/Hawkynt/DeleteMSWindowsTraces?color=4CAF50)
![Repo Size](https://img.shields.io/github/repo-size/Hawkynt/DeleteMSWindowsTraces?color=FF9800)

[![Release](https://img.shields.io/github/v/release/Hawkynt/DeleteMSWindowsTraces?sort=semver)](https://github.com/Hawkynt/DeleteMSWindowsTraces/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/Hawkynt/DeleteMSWindowsTraces/total)](https://github.com/Hawkynt/DeleteMSWindowsTraces/releases)

> Tired of Windows phoning home and remembering everything you do? 🕵️ This script removes all the crap that tracks what you do under Windows - telemetry, traces, MRUs, bloatware and more - in one go.

## 🤔 What is it?

DeleteMSWindowsTraces is a plain Windows batch script that hardens a Windows installation against Microsoft's data collection and wipes the usage traces that accumulate during daily work. No installation, no dependencies on exotic runtimes - just `cmd.exe` doing the dirty work.

## ✨ Features

### 🔇 Silence Telemetry & Data Collection

* Disables Windows Error Reporting, Customer Experience Improvement Program and Application Experience tasks
* Tweaks Defender settings to stop SpyNet reporting and sample submission
* Turns off Windows Tips, Spotlight and consumer features
* Blocks Microsoft account logons and setting synchronization
* Encrypts the paging file so swapped-out secrets stay secret

### 🗑️ Remove Bloatware

* Edge / Internet Explorer (executables get neutralized too)
* Cortana including its firewall-blocked SearchUI
* Maps, Sticky Notes, Bing apps (News, Weather), Get Help / Contact Support
* Hello Face, Biometrics, Geolocation, Quick Assist, Retail Demo and Troubleshooting packages
* Disables the search indexer and a pile of unneeded scheduled tasks

### 🧽 Wipe Usage Traces

* Temp folders, crash dumps and prefetch files
* Recent files, jumplists and Office MRUs for **every** user profile
* Typed addresses, Run dialog history and Visual Studio MRU lists
* Recycle bins on all drives, all event logs and the icon caches

## 📋 Prerequisites

* Administrator privileges (registry, services and scheduled tasks are modified)
* `install_wim_tweak.exe` located in the **parent folder** of the script - the script aborts safely when it is missing
* Optional: `CCleaner\CCleaner.exe` in the parent folder if you re-enable the CCleaner step

## 🚀 Usage

1. Download `DeleteTraces.bat` from the [latest release](https://github.com/Hawkynt/DeleteMSWindowsTraces/releases/latest) or clone the repository.
2. Place `install_wim_tweak.exe` in the folder **above** the script.
3. Run from an elevated command prompt:

   ```batch
   DeleteTraces.bat
   ```

The script announces every action it takes with an `[Info]` line and skips anything that is not present on your system.

## ⚠️ Warning

This script is intentionally destructive:

* It permanently deletes temp files, MRU lists, recycle bin contents and **all event logs**.
* It removes Windows components - some of them are hard to get back without reinstalling.
* It restarts `explorer.exe` to flush the icon caches.
* Encrypting the paging file requires a reboot to take effect.

Run it on systems you own and understand. There is no undo. 💣

## 🧪 Tests

The repository ships a [Pester](https://pester.dev/) test suite that statically analyzes the batch file (labels, call targets, scoping, encoding) and smoke-tests the prerequisite check:

```powershell
Invoke-Pester -Path tests
```

The same suite runs in CI on every push and gates every release.

## 🤝 Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request. Some ideas for improvement:

* Make the trace categories selectable via command line switches
* Add support for newer Windows 11 telemetry endpoints
* Detect localized administrator group names automatically

## 📜 License

This project is licensed under the GPL-3.0 license. See the [LICENSE](LICENSE) file for details.

## 🙏 Credits

* **Author:** Hawkynt
