#requires -Version 5.1
<#
.SYNOPSIS
  Verify a built release directory: the SHA256SUMS manifest matches every file, and the shipped exes are
  Authenticode-signed by the expected release cert. What a careful downloader (or CI) runs.

.DESCRIPTION
  Two independent checks:
    1. Integrity - recompute each file's SHA-256 and compare to SHA256SUMS (report any mismatch/missing/extra).
    2. Authenticode - for each shipped exe, assert the embedded signer thumbprint equals the expected release
       thumbprint. Status 'Valid' means the cert is trusted on this machine; 'UnknownError' means the
       signature is intact but the self-signed cert is not chain-trusted here (expected off the maintainer's
       box / before the installer imports the .cer) - reported as a note, not a failure. Any other status
       (NotSigned / HashMismatch / NotTrusted) FAILS.

  Exit 0 iff integrity holds AND every exe is signed by the expected cert.

.PARAMETER Path                Release directory (contains SHA256SUMS + the signed exes).
.PARAMETER ExpectedThumbprint  Expected signer thumbprint. Default: read tools/signing/DnsCryptControl-Release.thumbprint.txt.
.PARAMETER Exe                 Relative paths of exes to check. Default the UI + helper.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [string]$ExpectedThumbprint = '',
    [string[]]$Exe = @('helper/DnsCryptControl.Service.exe', 'ui/DnsCryptControl.UI.exe')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$signingDir = $PSScriptRoot
if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "Not a directory: $Path" }
$root = (Resolve-Path -LiteralPath $Path).Path

if (-not $ExpectedThumbprint) {
    $tf = Join-Path $signingDir 'DnsCryptControl-Release.thumbprint.txt'
    if (-not (Test-Path $tf)) { throw "No -ExpectedThumbprint and no reference file $tf. Run new-signing-cert.ps1." }
    $ExpectedThumbprint = (Get-Content -LiteralPath $tf -Raw).Trim()
}
$ExpectedThumbprint = $ExpectedThumbprint.Trim()

$failures = New-Object System.Collections.Generic.List[string]

# --- 1. SHA256SUMS integrity ----------------------------------------------------------------------
Write-Host "== Integrity (SHA256SUMS)" -ForegroundColor Cyan
$sumsFile = Join-Path $root 'SHA256SUMS'
if (-not (Test-Path $sumsFile)) {
    $failures.Add("SHA256SUMS not found in $root")
}
else {
    $checked = 0
    $listed = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($line in [IO.File]::ReadAllLines($sumsFile)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line.Length -lt 67) { $failures.Add("malformed SHA256SUMS line: $line"); continue }
        $expected = $line.Substring(0, 64).ToLowerInvariant()
        $rel = $line.Substring(66).Trim()
        [void]$listed.Add($rel)
        $full = Join-Path $root ($rel -replace '/', [IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $full)) { $failures.Add("missing: $rel"); continue }
        $actual = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $expected) { $failures.Add("hash mismatch: $rel") }
        $checked++
    }
    # The manifest is unauthenticated, so a tamperer could SHRINK it. Refuse to pass on an empty manifest,
    # and require it to be an EXACT whitelist: every on-disk file (except the manifest itself) must be listed,
    # so a planted/extra file (e.g. a swapped unsigned managed DLL that the signed apphost would load) is caught.
    if ($checked -eq 0) { $failures.Add("SHA256SUMS lists no files - refusing to pass vacuously (truncated/empty manifest?)") }
    Push-Location $root
    try {
        foreach ($f in Get-ChildItem -Recurse -File) {
            $rel = (Resolve-Path -Relative -LiteralPath $f.FullName) -replace '^\.[\\/]', '' -replace '\\', '/'
            if ($rel -eq 'SHA256SUMS') { continue }
            if (-not $listed.Contains($rel)) { $failures.Add("unlisted file present (not in SHA256SUMS): $rel") }
        }
    }
    finally { Pop-Location }
    Write-Host "  checked $checked listed file(s); confirmed no unlisted files present" -ForegroundColor DarkGreen
}

# --- 2. Authenticode signatures -------------------------------------------------------------------
Write-Host "== Authenticode (expect signer $ExpectedThumbprint)" -ForegroundColor Cyan
foreach ($rel in $Exe) {
    $full = Join-Path $root ($rel -replace '/', [IO.Path]::DirectorySeparatorChar)
    if (-not (Test-Path -LiteralPath $full)) { $failures.Add("exe missing: $rel"); continue }
    $sig = Get-AuthenticodeSignature -LiteralPath $full
    $thumb = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { $null }
    if ($thumb -ne $ExpectedThumbprint) {
        $failures.Add("$rel signed by '$thumb', expected '$ExpectedThumbprint' (status $($sig.Status))")
        continue
    }
    if ($sig.Status -eq 'Valid') { Write-Host "  $rel : Valid, signer matches" -ForegroundColor Green }
    elseif ($sig.Status -eq 'UnknownError') { Write-Host "  $rel : signer matches; cert not chain-trusted here (import the .cer to trust) - OK" -ForegroundColor DarkYellow }
    else { $failures.Add("$rel unexpected signature status '$($sig.Status)': $($sig.StatusMessage)") }
}

# --- Report ---------------------------------------------------------------------------------------
Write-Host ""
if ($failures.Count -gt 0) {
    Write-Host "VERIFY FAILED:" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}
Write-Host "VERIFY PASSED - integrity intact + every exe signed by $ExpectedThumbprint." -ForegroundColor Green
exit 0
