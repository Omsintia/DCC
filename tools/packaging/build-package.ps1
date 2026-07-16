#requires -Version 5.1
<#
.SYNOPSIS
  Build the signed DnsCryptControl MSI end-to-end: signed publishes (build-release) + pinned proxy
  (get-proxy) + generated installed-binary.json -> WiX -> sign the MSI -> SHA256SUMS over dist/.

.PARAMETER Version            Product version (MSI ProductVersion). Default 1.0.0.
.PARAMETER Subject            Signing cert subject. Default 'CN=DnsCryptControl'.
.PARAMETER FrameworkDependent Forward to build-release (fast; needs .NET 8 on the target) instead of self-contained.
.PARAMETER SkipBuildRelease   Reuse an existing tools/signing/release/ instead of rebuilding + re-signing.
#>
[CmdletBinding()]
param(
    [string]$Version = '1.0.0',
    [string]$Subject = 'CN=DnsCryptControl',
    [switch]$FrameworkDependent,
    [switch]$SkipBuildRelease
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$pkgDir     = $PSScriptRoot
$repoRoot   = Split-Path (Split-Path $pkgDir)
$signingDir = Join-Path $repoRoot 'tools\signing'
$releaseDir = Join-Path $signingDir 'release'
$distDir    = Join-Path $pkgDir 'dist'
$cacheDir   = Join-Path $pkgDir '.cache'
$wxs        = Join-Path $pkgDir 'Product.wxs'
$cer        = Join-Path $signingDir 'DnsCryptControl-Release.cer'

$dotnetCmd = Get-Command dotnet -ErrorAction SilentlyContinue
$dotnet = if ($dotnetCmd) { $dotnetCmd.Source } else { 'C:\Program Files\dotnet\dotnet.exe' }
if (-not (Test-Path $dotnet) -and -not $dotnetCmd) { throw "dotnet not found." }

function Invoke-Native { param([string]$Exe, [string[]]$Arguments, [string]$Title)
    if ($Title) { Write-Host "== $Title" -ForegroundColor Cyan }
    $p = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & $Exe @Arguments; $c = $LASTEXITCODE } finally { $ErrorActionPreference = $p }
    if ($c -ne 0) { throw "$Title failed (exit $c)" }
}

# --- 1. Signed publishes ---------------------------------------------------------------------------
if (-not $SkipBuildRelease) {
    # build-release builds from `git archive HEAD`, so the MSI's PRIMARY IC-PKG teardown layer
    # (helper.exe --teardown) only ships if its source is COMMITTED + the Service tree is clean. Refuse
    # otherwise, or the MSI would silently ship a helper whose --teardown is a no-op.
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & git -C $repoRoot ls-files --error-unmatch 'src/DnsCryptControl.Service/UninstallTeardown.cs' 2>&1 | Out-Null
    $tracked = ($LASTEXITCODE -eq 0)
    # build-release archives HEAD for the WHOLE tree, so ANY uncommitted change under src/ is silently
    # excluded from the MSI (this shipped a stale UI once - the Edit/tray commit landed AFTER the build).
    # Guard the entire src/ tree, not just the Service, so the packaged binaries always reflect HEAD.
    $dirty = & git -C $repoRoot status --porcelain -- 'src' 2>&1
    $ErrorActionPreference = $prev
    if (-not $tracked) { throw "UninstallTeardown.cs is not committed to HEAD - the packaged helper would lack --teardown. Commit the Service source first (or use tools/signing/build-release.ps1 -FromWorkingTree for a dev build)." }
    if ($dirty) { throw "src/ has uncommitted changes - commit them so the packaged binaries reflect HEAD (build-release archives HEAD, not the working tree):`n$dirty" }

    $brArgs = @{ Subject = $Subject }                       # hashtable splat -> unambiguous named binding
    if ($FrameworkDependent) { $brArgs.FrameworkDependent = $true }
    & (Join-Path $signingDir 'build-release.ps1') @brArgs   # throws (EAP=Stop) on failure
}
$uiDir     = Join-Path $releaseDir 'ui'
$helperDir = Join-Path $releaseDir 'helper'
foreach ($d in @($uiDir, $helperDir)) { if (-not (Test-Path $d)) { throw "missing publish: $d (run without -SkipBuildRelease)" } }

# Positively confirm the packaged helper actually CONTAINS the teardown branch (defence-in-depth vs the git
# guard): its absence would make the MSI's --teardown fail-safe a silent no-op.
$helperDll = Join-Path $helperDir 'DnsCryptControl.Service.dll'
if (Test-Path $helperDll) {
    $b = [IO.File]::ReadAllBytes($helperDll)
    if (-not ([Text.Encoding]::Unicode.GetString($b).Contains('UninstallTeardown'))) {
        throw "Packaged helper does not contain UninstallTeardown - the --teardown fail-safe would be a no-op. Rebuild from committed source."
    }
}

# --- 2. Pinned proxy + generated installed-binary.json ---------------------------------------------
$proxyExe = & (Join-Path $pkgDir 'get-proxy.ps1') | Select-Object -Last 1
if (-not (Test-Path $proxyExe)) { throw "get-proxy did not produce an exe" }
$sha = (Get-FileHash -LiteralPath $proxyExe -Algorithm SHA256).Hash.ToLowerInvariant()
$installedUtc = (Get-Date).ToUniversalTime().ToString('o')
$binJson = Join-Path $cacheDir 'installed-binary.json'
# Exact camelCase keys + LOWERCASE hash that BinaryIntegrityGate compares.
# The "2.1.16" tag literal mirrors get-proxy.ps1's $Tag pin - bump both together when upgrading the proxy.
"{`r`n  `"sha256Hex`": `"$sha`",`r`n  `"tag`": `"2.1.16`",`r`n  `"installedUtc`": `"$installedUtc`"`r`n}" |
    Set-Content -LiteralPath $binJson -Encoding ASCII
Write-Host "installed-binary.json sha256Hex=$sha" -ForegroundColor DarkGreen

# --- 3. WiX build ----------------------------------------------------------------------------------
if (Test-Path $distDir) { Remove-Item -Recurse -Force $distDir }
New-Item -ItemType Directory -Force -Path $distDir | Out-Null
$msi = Join-Path $distDir "DnsCryptControl-$Version.msi"
Invoke-Native -Title "WiX build -> $msi" -Exe $dotnet -Arguments @(
    'wix', 'build', $wxs, '-ext', 'WixToolset.Util.wixext', '-ext', 'WixToolset.UI.wixext',
    '-arch', 'x64', '-pdbtype', 'none',
    '-d', "Version=$Version", '-d', "UiDir=$uiDir", '-d', "HelperDir=$helperDir", '-d', "ProxyExe=$proxyExe",
    '-d', "CerFile=$cer", '-d', "TomlFile=$(Join-Path $pkgDir 'assets\dnscrypt-proxy.toml')",
    '-d', "LicenseRtf=$(Join-Path $pkgDir 'assets\license.rtf')",
    '-d', "DialogBmp=$(Join-Path $pkgDir 'assets\WixUIDialogBmp.bmp')",
    '-d', "BannerBmp=$(Join-Path $pkgDir 'assets\WixUIBannerBmp.bmp')",
    '-d', "BinaryJson=$binJson", '-d', "ScriptsDir=$pkgDir", '-o', $msi)

# --- 4. Sign the MSI -------------------------------------------------------------------------------
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq $Subject } | Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) { throw "No signing cert '$Subject' - run tools/signing/new-signing-cert.ps1." }
$sig = Set-AuthenticodeSignature -FilePath $msi -Certificate $cert -HashAlgorithm SHA256
$sigThumb = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { $null }
if ($sigThumb -ne $cert.Thumbprint) {
    throw "MSI signing FAILED: signer '$sigThumb' != '$($cert.Thumbprint)' (status $($sig.Status)). If the MSI SIP is unavailable, sign with signtool instead."
}
Write-Host "  MSI signed by $($cert.Thumbprint) (status $($sig.Status))" -ForegroundColor DarkGreen

# --- 5. Ship the public cert + SHA256SUMS over dist/ ----------------------------------------------
Copy-Item $cer (Join-Path $distDir 'DnsCryptControl-Release.cer') -Force
& (Join-Path $signingDir 'make-sha256sums.ps1') -Path $distDir -Quiet

Write-Host ""
Write-Host "==================== MSI BUILT ====================" -ForegroundColor Green
Write-Host "  $msi"
Write-Host "  dist: $distDir (msi + .cer + SHA256SUMS)"
Write-Host "  Install on a THROWAWAY VM only (registers a LocalSystem service + imports a machine cert)."
