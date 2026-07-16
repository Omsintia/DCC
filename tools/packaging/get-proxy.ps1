#requires -Version 5.1
<#
.SYNOPSIS
  Download + SHA-256-verify the pinned dnscrypt-proxy 2.1.16 (win64) and extract dnscrypt-proxy.exe for
  packaging. Fail-closed on a hash mismatch (delete + throw) - the supply-chain pin, same posture as
  tools/fuzz-harnesses/get-driver.ps1.

.DESCRIPTION
  The proxy is a third-party VENDOR-signed binary we bundle as-is (dnscrypt-proxy 2.1.16 confirmed the
  latest stable). It is NOT committed (a ~4.6 MB blob); this script fetches the official GitHub release
  zip, verifies the pinned hash, and extracts just dnscrypt-proxy.exe. Idempotent: a cached, hash-verified
  zip is reused with no network.

.PARAMETER Dest   Path to write dnscrypt-proxy.exe. Default tools/packaging/.cache/dnscrypt-proxy.exe.
.PARAMETER Force  Re-download even if the cached zip verifies.

.NOTES  Requires network on first run (dev/build machine). Bump $Tag + $Sha256 together to update;
        also update the tag literal in tools/packaging/build-package.ps1 (installed-binary.json).
#>
[CmdletBinding()]
param(
    [string]$Dest = '',
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Pin (bump both together when upgrading the proxy) ---------------------------------------------
$Tag     = '2.1.16'
$ZipName = "dnscrypt-proxy-win64-$Tag.zip"
$Sha256  = '4373C380B0E261D6D511B299FB4EDCE99F13D0D86A7DB7E2EE4CAD0FA1CE0078'
$Url     = "https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/$Tag/$ZipName"
# --------------------------------------------------------------------------------------------------

$here     = $PSScriptRoot
$cacheDir = Join-Path $here '.cache'
$zipPath  = Join-Path $cacheDir $ZipName
if (-not $Dest) { $Dest = Join-Path $cacheDir 'dnscrypt-proxy.exe' }

function Test-Hash([string]$path) {
    if (-not (Test-Path $path)) { return $false }
    return (Get-FileHash -Algorithm SHA256 -Path $path).Hash -eq $Sha256
}

New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null

if ($Force -or -not (Test-Hash $zipPath)) {
    Write-Host "Downloading dnscrypt-proxy $Tag ..." -ForegroundColor Cyan
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Url -OutFile $zipPath -UseBasicParsing
    if (-not (Test-Hash $zipPath)) {
        $actual = (Get-FileHash -Algorithm SHA256 -Path $zipPath).Hash
        Remove-Item -Force $zipPath
        throw "SHA-256 mismatch for $ZipName. Expected $Sha256 but got $actual. Deleted the file; not trusting it."
    }
}
else { Write-Host "Cached zip verified: $zipPath ($Tag)" -ForegroundColor Green }

# Extract dnscrypt-proxy.exe (the release nests it under win64/).
$extractDir = Join-Path $cacheDir "extract-$Tag"
if (Test-Path $extractDir) { Remove-Item -Recurse -Force $extractDir }
Expand-Archive -LiteralPath $zipPath -DestinationPath $extractDir -Force
$exe = Get-ChildItem -Path $extractDir -Recurse -Filter 'dnscrypt-proxy.exe' | Select-Object -First 1
if (-not $exe) { throw "dnscrypt-proxy.exe not found inside $ZipName." }

New-Item -ItemType Directory -Force -Path (Split-Path $Dest) | Out-Null
Copy-Item -LiteralPath $exe.FullName -Destination $Dest -Force
Remove-Item -Recurse -Force $extractDir

Write-Host "dnscrypt-proxy.exe ($Tag) -> $Dest" -ForegroundColor Green
Write-Output $Dest
