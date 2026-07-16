# Phase 6 CI - the automated gate

Two gates, split by speed. The **scripts** are the single source of truth (they run on your machine
today); the **`.github/workflows/`** YAML are thin wrappers that just call them, so cloud CI works the
instant this repo gets a GitHub remote - with zero rework. This repo is local-only + offline-by-
construction, so nothing here needs the internet to *run the app*; the build/restore step uses NuGet
like any .NET build.

| Gate | Script | Runs | Needs | Speed |
|------|--------|------|-------|-------|
| **Per-PR** | [`ci.ps1`](ci.ps1) | every change (`.github/workflows/ci.yml`: push / PR) | just the .NET 8 SDK | minutes |
| **Nightly** | [`ci-nightly.ps1`](ci-nightly.ps1) | scheduled + on demand (`.github/workflows/nightly.yml`) | SDK + pinned driver + SharpFuzz tool + BenchmarkDotNet | ~hours |

This matches the phase-6 design's locked decisions: **OQ3** - fuzz *smoke* gates every PR via
`dotnet test`, deep coverage-guided fuzzing + perf-gate run *nightly*; **OQ6** - the perf baseline is
calibrated on the dev machine now, re-baselined on the CI runner later.

## Per-PR gate - `ci.ps1`

```powershell
pwsh tools/ci/ci.ps1
# or:  powershell -ExecutionPolicy Bypass -File tools/ci/ci.ps1
```

1. **Strict build (`Release`)** - proves the *shipped* configuration compiles with **zero warnings**.
   The strict gate (`TreatWarningsAsErrors` + .NET analyzers + `BannedApiAnalyzers` + `NuGetAudit`) is
   unconditional in the root `Directory.Build.props`, and Release is the config that gets signed +
   packaged next, so the gate proves it clean and fails fast before the longer test run.
2. **Tests (`Debug`)** - `dotnet test DnsCryptControl.sln --filter Category!=ManualIntegration`, the
   established ~2000-test green baseline (Platform / Core / Ipc / Service / Fuzzing / UI).

**The per-PR fuzz coverage is already inside `dotnet test`** - no instrumentation, no native driver, no
Go, no BenchmarkDotNet. The `DnsCryptControl.Fuzzing` project contains:
- **CsCheck property fuzzing** (`Category=Fuzz`) - 6a,
- the **differential-oracle** frozen golden-vector replays - 6b,
- **`CrashCorpusReplayTests`** - re-feeds every committed corpus input (seeds + captured crashes) - 6c.

So any bug the heavy nightly tools ever found becomes a permanent, instrumentation-free regression test
that this fast gate enforces forever.

Useful switches: `-TestConfiguration Release` (also test the shipped config), `-SkipBuild` / `-SkipTests`
(iterate), `-Filter <expr>`.

### Optional: run it automatically on `git push`

```powershell
# from the repo root - opt-in local pre-push hook
Set-Content .git/hooks/pre-push "#!/bin/sh`nexec pwsh tools/ci/ci.ps1" -Encoding ascii
```

## Nightly gate - `ci-nightly.ps1`

```powershell
dotnet tool restore                 # once per checkout: provides `dotnet sharpfuzz`
pwsh tools/ci/ci-nightly.ps1        # driver-fetch -> fuzz -> perf-gate -> debounce soak
```

Each step is isolated (one failure does not abort the rest - you always get a full report), and the
script exits non-zero if any step failed:

0. **`get-driver.ps1`** - fetch + SHA-256-verify the pinned `libfuzzer-dotnet-windows.exe` (network;
   idempotent). Not committed; CI never needs it for the per-PR gate.
1. **`run-fuzz.ps1 -Mode nightly`** - coverage-guided fuzzing of the 7 byte-decoders. A NEW crash is
   auto-minimized into `tests/DnsCryptControl.Fuzzing/Corpus/<target>/crashes/` (where the per-PR
   `CrashCorpusReplayTests` then fails until it's fixed) and this step reports failure.
2. **`perf-gate.ps1 -Job short`** - BenchmarkDotNet hard budgets + the **deterministic allocation**
   regression vs the committed `perf-baseline.json`. `-Job short` matches the baseline's calibration;
   the (noisy) timing-regression check stays advisory until the baseline is re-calibrated on the runner.
3. **debounce soak** - `... -- soak 1000`: the 6d flake fix under ~2x thread-pool oversubscription
   (0 flakes expected).

Switches: `-FuzzMode smoke|nightly|custom`, `-FuzzMaxTotalTime <sec>`, `-PerfJob short|default`,
`-SoakIterations <n>`, `-SkipFuzz` / `-SkipPerf` / `-SkipSoak`.

## Notes

- **`dotnet` resolution:** both scripts prefer a `dotnet` on `PATH` (GitHub runner / a dev who has it),
  else fall back to `C:\Program Files\dotnet\dotnet.exe` (this dev machine keeps it off `PATH`).
- **PowerShell:** written to `#requires -Version 5.1` and run identically under PowerShell 7 (`pwsh`,
  the GitHub `windows-latest` default). Native tool stderr is handled so it never trips PS 5.1's
  terminating `NativeCommandError`.
- **The heavy tools are not in `DnsCryptControl.sln`** (the SharpFuzz harness and the BenchmarkDotNet
  arm), so the per-PR gate never builds them.
