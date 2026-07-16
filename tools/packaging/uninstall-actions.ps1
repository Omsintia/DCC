#requires -Version 5.1
<#
.SYNOPSIS
  MSI uninstall custom action (runs deferred, as SYSTEM, BEFORE files are removed): the IC-PKG fail-safe
  teardown so an uninstall can NEVER leave the machine without DNS. Best-effort throughout (never blocks
  the uninstall) - always exits 0; the ProgramData purge is a separate MSI action gated on true-uninstall.

  Order:
    1. `helper.exe --teardown` - reverts protection via the helper's own tested code (DNS restore from
       backup, kill-switch rules, registry leak-mitigation + browser-DoH exact-revert, proxy stop).
    2. uninstall-fallback.ps1 - the dumb net (delete KillSwitch* rules, loopback-DNS adapters -> DHCP) in
       case the helper exe was broken/missing.
    3. Remove the dnscrypt-proxy service.
    4. Remove the release cert from LocalMachine Root + TrustedPublisher (by thumbprint).
  The MSI stops the helper service (ServiceControl Stop=both) BEFORE this runs, so the --teardown process
  has exclusive access to the state stores.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$installDir = Split-Path $PSScriptRoot
$helperExe  = Join-Path $installDir 'helper\DnsCryptControl.Service.exe'
$fallback   = Join-Path $PSScriptRoot 'uninstall-fallback.ps1'
$cer        = Join-Path $installDir 'DnsCryptControl-Release.cer'
$data       = Join-Path $env:ProgramData 'DnsCryptControl'
$log        = Join-Path $env:TEMP 'dnscc-uninstall-actions.log'

function Note([string]$m) { try { Add-Content -LiteralPath $log -Value "$((Get-Date).ToString('o')) $m" -ErrorAction SilentlyContinue } catch { }; Write-Host $m }

Note "uninstall-actions: InstallDir=$installDir"

# 1. Primary: the helper's own tested revert.
if (Test-Path $helperExe) {
    try { & $helperExe --teardown 2>&1 | ForEach-Object { Note "  teardown: $_" }; Note "  teardown exit=$LASTEXITCODE" }
    catch { Note "  teardown threw: $($_.Exception.Message)" }
}
else { Note "  helper exe missing ($helperExe) - relying on the fallback" }

# 2. Fallback net (idempotent; a no-op if teardown already cleaned up).
if (Test-Path $fallback) {
    try { & powershell.exe -ExecutionPolicy Bypass -NonInteractive -NoProfile -File $fallback 2>&1 | ForEach-Object { Note "  fallback: $_" } }
    catch { Note "  fallback threw: $($_.Exception.Message)" }
}

# 3. Remove the dnscrypt-proxy service.
try { & sc.exe stop dnscrypt-proxy 2>&1 | Out-Null; Start-Sleep -Milliseconds 500; & sc.exe delete dnscrypt-proxy 2>&1 | ForEach-Object { Note "  sc: $_" } } catch { }

# 4. Remove the release cert from the machine trust stores (by thumbprint if the .cer is still present).
try {
    if (Test-Path $cer) {
        $thumb = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cer).Thumbprint
        foreach ($store in @('Root', 'TrustedPublisher')) {
            & certutil.exe -delstore $store $thumb 2>&1 | ForEach-Object { Note "  certutil -delstore ${store}: $_" }
        }
    }
    else { Note "  cert file gone; skipping cert removal (harmless residue)" }
}
catch { Note "  cert removal threw: $($_.Exception.Message)" }

Note 'uninstall-actions: done (best-effort)'
exit 0
