# Agent guide — DeleteMSWindowsTraces

Working agreement for **all** coding agents (Claude Code, Codex, Copilot, …)
and human contributors working in this repository. These rules are not
optional. The full house spec lives in the `Hawkynt/project-template` repo
(`STANDARD.md`); this file is the per-repo distillation.

## What this is

A single Windows **batch script** (`DeleteTraces.bat`) that disables
telemetry, strips bloatware and wipes usage traces. Tests are **Pester**
(`tests/DeleteTraces.Tests.ps1`). This is a destructive-by-design system tool
— changes must be conservative and reviewable line by line.

## Commits

- **Group changes semantically/logically** — one concern per commit
  (one telemetry source, one cleanup target, one parser fix).
- **Every subject line starts with a prefix**: `+` added · `-` removed ·
  `*` changed · `#` bug fixed · `!` critical todo.
- Never start a subject with "fix"/"bugfix"/"changed"/"modified".
- **No AI traces anywhere**: no `Co-Authored-By` AI lines, no "Generated
  with" footers, no agent mentions in messages, comments, or authorship.

## The loop (always, in this order)

1. **Before committing**: run the Pester suite locally —
   `pwsh -c "Invoke-Pester tests"` — and smoke-parse the script
   (`cmd /c DeleteTraces.bat /?` or the dry-run path if present). Update the
   README Features list when capabilities change; `CHANGELOG.md` is
   generated — never edit it by hand.
2. **Commit** (rules above) and **push**.
3. **Wait for CI**; on the default branch a green CI triggers the nightly
   (prerelease + GFS prune). Fix and loop until everything is green.

Stable releases are **manual** (`gh workflow run release.yml`) — never cut
one unless explicitly asked.

## Script conventions

- The batch file must keep running on stock `cmd.exe` of supported Windows
  versions — no PowerShell-only constructs inside the `.bat`.
- Every destructive operation needs a clear comment saying *what* it removes
  and *why* that is safe; group operations by subsystem.
- CRLF line endings for `.bat`/`.cmd`/`.ps1` (enforced via `.editorconfig` /
  `.gitattributes`).

## README & repo conventions

- Standard frame: title → badges → one-line `>` blockquote; fixed emoji
  mapping for the standard sections (`## 📦 Install`, `## 🚀 Usage`,
  `## ✨ Features`, `## 🛠️ Building`, `## ❤️ Support`, `## 📜 License`).
- License is LGPL-3.0-or-later; the `## ❤️ Support` section and
  `.github/FUNDING.yml` stay intact.
