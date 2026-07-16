#requires -Version 5.1
<#
.SYNOPSIS
  MSI install custom action (runs deferred, as SYSTEM): the imperative install steps that WiX can't do
  declaratively as cleanly - the exact proven commands from the dev Setup script.
    1. ACL %ProgramData%\DnsCryptControl (+state): SYSTEM+Admins Full (OI)(CI), Users Read (the helper
       verifies these on boot).
    2. Import the public release cert into LocalMachine Root + TrustedPublisher (so the caller-gate's
       WinVerifyTrust reads a trusted chain -> the helper accepts the signed UI, no "unknown publisher").
    3. Register the dnscrypt-proxy service and force DEMAND_START (the SCM must never launch the proxy
       ahead of the helper's BinaryIntegrityGate).
  Self-locating: $PSScriptRoot is <InstallDir>\scripts, so InstallDir = its parent. Exits NON-ZERO on a
  load-bearing failure so the MSI custom action (Return=check) fails the install fail-closed rather than
  leaving a broken install.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$installDir = Split-Path $PSScriptRoot
$cer        = Join-Path $installDir 'DnsCryptControl-Release.cer'
$data       = Join-Path $env:ProgramData 'DnsCryptControl'
$state      = Join-Path $data 'state'
$proxyExe   = Join-Path $data 'dnscrypt-proxy.exe'
$log        = Join-Path $data 'install-actions.log'
$fail       = $false

function Note([string]$m) { try { Add-Content -LiteralPath $log -Value "$((Get-Date).ToString('o')) $m" -ErrorAction SilentlyContinue } catch { }; Write-Host $m }
function Run([string]$exe, [string[]]$a) { & $exe @a 2>&1 | ForEach-Object { Note "  $_" }; return $LASTEXITCODE }

New-Item -ItemType Directory -Force -Path $data, $state -ErrorAction SilentlyContinue | Out-Null
Note "install-actions: InstallDir=$installDir Data=$data"

# 1. ACLs (must match AclHelper / the helper's boot-time ACL check).
foreach ($dir in @($data, $state)) {
    [void](Run 'icacls.exe' @($dir, '/inheritance:r'))
    [void](Run 'icacls.exe' @($dir, '/grant:r', 'SYSTEM:(OI)(CI)F'))
    [void](Run 'icacls.exe' @($dir, '/grant:r', 'BUILTIN\Administrators:(OI)(CI)F'))
    $rc = Run 'icacls.exe' @($dir, '/grant:r', 'BUILTIN\Users:(OI)(CI)R')
    if ($rc -ne 0) { Note "ACL FAILED on $dir (icacls exit $rc)"; $fail = $true }
}

# 2. Cert -> machine trust stores (load-bearing: without it the caller-gate rejects the UI).
if (-not (Test-Path $cer)) { Note "cert MISSING: $cer"; $fail = $true }
else {
    foreach ($store in @('Root', 'TrustedPublisher')) {
        $rc = Run 'certutil.exe' @('-addstore', '-f', $store, $cer)
        if ($rc -ne 0) { Note "certutil -addstore $store FAILED (exit $rc)"; $fail = $true }
    }
}

# 3. dnscrypt-proxy service: register (from the data dir so it picks up the toml) then force DEMAND_START.
if (-not (Test-Path $proxyExe)) { Note "proxy MISSING: $proxyExe"; $fail = $true }
else {
    # IDEMPOTENT: `-service install` FAILS if the service already exists. During a major UPGRADE the teardown
    # that would remove it (CA_UninstallActions) is deliberately skipped to preserve protection, so the old
    # proxy service persists - register only when absent; always (re)assert DEMAND_START below.
    if (Get-Service dnscrypt-proxy -ErrorAction SilentlyContinue) {
        Note 'dnscrypt-proxy service already present - skipping -service install (upgrade/repair)'
    }
    else {
        Push-Location $data
        try {
            $rc = Run $proxyExe @('-service', 'install')
            if ($rc -ne 0) { Note "dnscrypt-proxy -service install FAILED (exit $rc)"; $fail = $true }
        }
        finally { Pop-Location }
    }
    # DEMAND_START is load-bearing: the SCM must never launch the proxy ahead of the helper's
    # BinaryIntegrityGate. A failed demotion (proxy left AUTO_START) is a real supply-chain gap, so treat
    # it as a fail-closed failure rather than fire-and-forget.
    $rcDemand = Run 'sc.exe' @('config', 'dnscrypt-proxy', 'start=', 'demand')
    if ($rcDemand -ne 0) { Note "sc config start=demand FAILED (exit $rcDemand) - proxy left non-demand"; $fail = $true }
}

if ($fail) { Note 'install-actions: FAILED'; exit 1 }
Note 'install-actions: OK'
exit 0
