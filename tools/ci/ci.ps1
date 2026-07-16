#requires -Version 5.1
<#
.SYNOPSIS
  Phase 6 CI - the PER-PR gate. Offline, toolchain-free: a strict Release build + the full
  non-manual test suite (which already includes the fuzz smoke, the offline crash-replay, the
  differential-oracle frozen vectors, and the frozen-wire vocabulary pins (FrozenWireDiffGateTests)).

.DESCRIPTION
  This is the fast gate that must pass before any change lands. It needs NOTHING beyond the .NET
  SDK - no SharpFuzz instrumentation, no native libfuzzer-dotnet driver, no Go toolchain, no
  BenchmarkDotNet. Those heavy discovery tools run in the NIGHTLY gate (ci-nightly.ps1); their
  findings are already frozen into the committed corpus + golden vectors that `dotnet test` replays
  here with zero instrumentation.

  Two steps, each in the configuration that is right for it:
    1. Strict build (Release)  - proves the SHIPPED configuration compiles with zero warnings
       (TreatWarningsAsErrors + .NET analyzers + BannedApiAnalyzers + NuGetAudit are all unconditional
       in Directory.Build.props). Release is the config that gets signed + packaged next, so the gate
       proves it clean. Fails fast before the (longer) test run.
    2. Test (default/Debug)    - runs DnsCryptControl.sln with `Category!=ManualIntegration`, the exact
       established green baseline (~2000 tests across Platform/Core/Ipc/Service/Fuzzing/UI). The Fuzzing
       project's tests ARE the per-PR fuzz smoke: CsCheck property fuzzing (Category=Fuzz), the
       CrashCorpusReplayTests offline replay, and the differential-oracle vector replays.

  The SharpFuzz harness (tools/fuzz-harnesses) and the BenchmarkDotNet arm (tools/benchmarks) are
  deliberately NOT in DnsCryptControl.sln, so this gate never touches them.

  Exit code: 0 if the build and the tests all pass; 1 otherwise (so a PR job / pre-push hook fails).

.PARAMETER Filter
  The `dotnet test` filter. Default 'Category!=ManualIntegration' (excludes live-VM integration tests).

.PARAMETER BuildConfiguration
  Configuration for the strict build step. Default 'Release' (the shipped config).

.PARAMETER TestConfiguration
  Configuration for the test step. Default 'Debug' (the established baseline; TreatWarningsAsErrors is
  unconditional so Debug still enforces the strict gate). Pass 'Release' to test the shipped config too.

.PARAMETER MinTests
  Fail the gate if fewer than this many tests actually executed (default 1). `dotnet test` exits 0 on a
  zero-match filter (.NET 8 has no --fail-on-no-tests), so this floor is the tamper-evidence that the
  suite genuinely ran and the gate is not a silent green having tested nothing.

.PARAMETER SkipBuild   Skip the strict build step (iterate on tests only).
.PARAMETER SkipTests   Skip the test step (check the strict build only).

.EXAMPLE
  pwsh tools/ci/ci.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools/ci/ci.ps1 -TestConfiguration Release
#>
[CmdletBinding()]
param(
    [string]$Filter = 'Category!=ManualIntegration',
    [ValidateSet('Debug', 'Release')]
    [string]$BuildConfiguration = 'Release',
    [ValidateSet('Debug', 'Release')]
    [string]$TestConfiguration = 'Debug',
    [int]$MinTests = 1,
    [switch]$SkipBuild,
    [switch]$SkipTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Paths -----------------------------------------------------------------------------------------
$ciDir    = $PSScriptRoot
$repoRoot = Split-Path (Split-Path $ciDir)                      # tools/ci -> tools -> repo
$solution = Join-Path $repoRoot 'DnsCryptControl.sln'
if (-not (Test-Path $solution)) { throw "solution not found: $solution" }

# Prefer a `dotnet` already on PATH (GitHub runner / a dev who has it), else the known local install
# (this repo's dev machine keeps dotnet OFF PATH at C:\Program Files\dotnet\dotnet.exe).
$dotnetCmd = Get-Command dotnet -ErrorAction SilentlyContinue
$dotnet = if ($dotnetCmd) { $dotnetCmd.Source } else { 'C:\Program Files\dotnet\dotnet.exe' }
if (-not (Test-Path $dotnet) -and -not $dotnetCmd) {
    throw "dotnet not found on PATH or at 'C:\Program Files\dotnet\dotnet.exe'. Install the .NET 8 SDK."
}

# Run a native command WITHOUT PS 5.1 turning its stderr into a terminating NativeCommandError (that
# quirk fires under $ErrorActionPreference='Stop'). We drop to 'Continue' for the call, let the tool's
# output stream to the console for visibility, and gate purely on $LASTEXITCODE.
function Invoke-Step {
    param([Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string[]]$Arguments)
    Write-Host ""
    Write-Host "== $Title" -ForegroundColor Cyan
    Write-Host "   $dotnet $($Arguments -join ' ')" -ForegroundColor DarkGray
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $dotnet @Arguments
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $prev
    }
    $sw.Stop()
    if ($code -ne 0) { throw "$Title FAILED (exit $code) after $([int]$sw.Elapsed.TotalSeconds)s" }
    Write-Host "   ok ($([int]$sw.Elapsed.TotalSeconds)s)" -ForegroundColor DarkGreen
}

$overall = [System.Diagnostics.Stopwatch]::StartNew()
Write-Host "############ Phase 6 CI - per-PR gate ############" -ForegroundColor Yellow
Write-Host "repo:     $repoRoot"
Write-Host "solution: DnsCryptControl.sln"
Write-Host "dotnet:   $dotnet"

try {
    # --- 1. Strict build (shipped config) ---------------------------------------------------------
    if (-not $SkipBuild) {
        Invoke-Step -Title "Strict build ($BuildConfiguration) - 0 warnings / analyzers / BannedApi / NuGetAudit" `
            -Arguments @('build', $solution, '-c', $BuildConfiguration, '--nologo')
    }
    else { Write-Host "`n(skipped strict build)" -ForegroundColor DarkYellow }

    # --- 2. Test (fuzz smoke + offline replay + frozen-wire gate + all unit/integration tests) ----
    if (-not $SkipTests) {
        # Emit a trx per project so we can PROVE the suite ran: `dotnet test` exits 0 even when a --filter
        # matches ZERO tests (.NET 8 has no --fail-on-no-tests), so a bad filter or a discovery failure
        # could otherwise report a green gate having run nothing. We sum the executed count and fail below
        # -MinTests - tamper-evidence against a silent "passed 0 tests" gate.
        $trxDir = Join-Path ([IO.Path]::GetTempPath()) "dcc-ci-trx-$PID"
        if (Test-Path $trxDir) { Remove-Item -Recurse -Force $trxDir }
        New-Item -ItemType Directory -Force -Path $trxDir | Out-Null
        Invoke-Step -Title "Test ($TestConfiguration) - filter '$Filter'" `
            -Arguments @('test', $solution, '-c', $TestConfiguration, '--filter', $Filter, '--nologo',
                '--logger', 'trx', '--results-directory', $trxDir)

        $total = 0
        foreach ($trx in @(Get-ChildItem -Path $trxDir -Filter '*.trx' -ErrorAction SilentlyContinue)) {
            try {
                [xml]$doc = Get-Content -Raw -LiteralPath $trx.FullName
                $counters = $doc.TestRun.ResultSummary.Counters   # dotted XML access is namespace-agnostic
                if ($counters -and $counters.total) { $total += [int]$counters.total }
            }
            catch { Write-Host "   (warning: could not parse $($trx.Name): $($_.Exception.Message))" -ForegroundColor DarkYellow }
        }
        Remove-Item -Recurse -Force $trxDir -ErrorAction SilentlyContinue
        Write-Host "   executed $total test(s)" -ForegroundColor DarkGreen
        if ($total -lt $MinTests) {
            throw "Test gate executed $total test(s) - below the -MinTests floor of $MinTests. The filter matched nothing or discovery failed; refusing to report PASS on a suite that did not run."
        }
    }
    else { Write-Host "`n(skipped tests)" -ForegroundColor DarkYellow }
}
catch {
    $overall.Stop()
    Write-Host ""
    Write-Host "==================== CI GATE FAILED ($([int]$overall.Elapsed.TotalSeconds)s) ====================" -ForegroundColor Red
    Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$overall.Stop()
Write-Host ""
Write-Host "==================== CI GATE PASSED ($([int]$overall.Elapsed.TotalSeconds)s) ====================" -ForegroundColor Green
exit 0
