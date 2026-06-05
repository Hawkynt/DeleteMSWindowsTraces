# CI/CD Pipeline — DeleteMSWindowsTraces

> Everything in this folder is the automated pipeline for this repository.
> Workflows live here, their helper scripts live in `scripts/`.
>
> Instantiated from the shared Hawkynt template (`hawkynt-standard`), generic
> (non-.NET) variant: the product is a single batch file, so "build" is
> packaging and the test suite is Pester-based static analysis plus a smoke
> test. The NuGet blocks of the template are deleted — this repo ships no
> packages.

## What this does

Four workflows, three helper scripts:

| File                            | Trigger                             | Purpose                                   |
|---------------------------------|-------------------------------------|-------------------------------------------|
| `ci.yml`                        | push + PR + `workflow_call`         | Pester test suite on ubuntu + windows     |
| `release.yml`                   | **manual dispatch**                 | Package + publish, then tag `vyyyyMMdd` |
| `nightly.yml`                   | successful CI run on `main`/`master`| Publish `nightly-yyyyMMdd` prerelease   |
| `_build.yml`                    | `workflow_call` (internal)          | Collects `DeleteTraces.bat` + `LICENSE` into the `app-artifacts` artifact |
| `scripts/version.pl`            | invoked by the workflows            | No-op here (no package manifest); kept template-identical |
| `scripts/update-changelog.mjs`  | invoked by the workflows            | Bucketise commits into CHANGELOG.md       |
| `scripts/prune-nightlies.mjs`   | invoked by the workflows            | 3-gen (GFS) retention of nightlies        |

## How it works

```
                push / PR
                    │
                    ▼
            ┌───────────────┐
            │    ci.yml     │──► Pester tests on ubuntu + windows
            └───┬───────┬───┘    (cmd.exe smoke test self-skips on ubuntu)
                │       │
   dispatch ────┤       │  on success on main/master
                ▼       ▼
        ┌──────────┐  ┌─────────────┐
        │ release  │  │  nightly    │
        │  .yml    │  │   .yml      │
        └────┬─────┘  └─────┬───────┘
             │              │
             ▼              ▼
        (both call _build.yml)
             │              │
             │   Packages DeleteTraces.bat + LICENSE into ./dist
             ▼              ▼
  publish + tag vyyyyMMdd  nightly-yyyyMMdd (prerelease)
                                │
                                ▼
                       scripts/prune-nightlies.mjs
                       (GFS: 7 daily + 4 weekly + 3 monthly)
```

## Test tiers

There is no compiler for batch files, so the required tier is the Pester suite
in `tests/`:

| Tier               | Runs on every PR?      | Purpose                              |
|--------------------|------------------------|--------------------------------------|
| Static analysis    | ✓ (must pass, both OS) | Encoding, CRLF, label/call/goto resolution, setlocal scoping |
| Smoke test         | ✓ (must pass, windows) | Prerequisite check aborts safely without doing any work; self-skips where no `cmd.exe` exists |

## What it's for

- Every PR is tested on ubuntu + windows before it can merge.
- Every merge to `main`/`master` produces a **tested** nightly prerelease.
- A **manual dispatch** cuts a stable release from artifacts built by `_build.yml`, then tags the dated `vyyyyMMdd` Release at that commit.
- Old nightlies are auto-pruned on a **Grandfather-Father-Son** schedule.

## Why it's built this way

- **No cron triggers.** Event-driven only — CI fires on PRs, nightlies fire when CI passes on main, stable releases fire on manual dispatch.
- **Files drive versions, never tags.** This repo carries no package manifest, so there is no version to stamp; the repo-level Release/tag is the date marker `vyyyyMMdd`.
- **Release calls CI via `workflow_call`.** Calling ci.yml explicitly keeps tests and releases in lockstep with zero copy-paste.
- **Nightly builds from the `workflow_run` payload's SHA**, not branch tip — so a nightly is always a build of code CI actually validated.
- **`_build.yml` is the single packaging block**, shared by release and nightly so they never diverge.
- **3-generation (GFS) retention**, not "keep last N". GFS guarantees at least one build per week for a month and one per month for a quarter.

## Scripts

The scripts are kept byte-identical to the shared template — when changing
them, prototype in `hawkynt-standard` and mirror the change here.

### `version.pl`

Scans for package manifests and stamps each independently. This repo has none
(a batch file is its own artifact), so the script intentionally leaves it
untouched — releases are identified by the dated tag only.

### `update-changelog.mjs`

Prepends a new section to `CHANGELOG.md`. Commit-subject convention: `+` Added, `*` Changed, `#` Fixed, `-` Removed, `!` TODO, anything else → Other.

### `prune-nightlies.mjs`

GFS retention with `DAILY_KEEP=7`, `WEEKLY_KEEP=4`, `MONTHLY_KEEP=3`. Dry-run with `--dry-run`.

## Release artifacts

| Artifact                                   | Produced by          |
|--------------------------------------------|----------------------|
| `app-artifacts` (`DeleteTraces.bat`, `LICENSE`) | release + nightly |
| `test-results-<os>` (NUnit XML)            | ci.yml               |
