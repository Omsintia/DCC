#requires -Version 5.1
<#
.SYNOPSIS
  Write a SHA256SUMS manifest (coreutils `sha256sum` format) over a directory - the release integrity
  artifact a downloader checks. Reusable by build-release.ps1 and by packaging.

.DESCRIPTION
  Emits `<lowercase-hex-sha256>  <relative/forward-slash/path>` per file (two spaces, the `sha256sum`
  convention, so `sha256sum -c SHA256SUMS` works on Linux / git-bash). The manifest itself is excluded.

.PARAMETER Path     Directory to hash (recursively).
.PARAMETER OutFile  Manifest path. Default <Path>/SHA256SUMS.
.PARAMETER Quiet    Suppress the per-file listing.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [string]$OutFile = '',
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "Not a directory: $Path" }
$root = (Resolve-Path -LiteralPath $Path).Path
if (-not $OutFile) { $OutFile = Join-Path $root 'SHA256SUMS' }
$outFull = [IO.Path]::GetFullPath($OutFile)

$lines = New-Object System.Collections.Generic.List[string]
$count = 0
Push-Location $root
try {
    foreach ($f in Get-ChildItem -Recurse -File) {
        if ($f.FullName -eq $outFull) { continue }                       # never hash the manifest itself
        $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $rel = (Resolve-Path -Relative -LiteralPath $f.FullName) -replace '^\.[\\/]', '' -replace '\\', '/'
        $lines.Add("$hash  $rel")
        $count++
    }
}
finally { Pop-Location }

$lines.Sort([System.StringComparer]::Ordinal)                            # deterministic order (reproducible manifest)
# LF newlines, UTF-8 without BOM - portable for `sha256sum -c`.
[IO.File]::WriteAllText($outFull, ($lines -join "`n") + "`n", (New-Object System.Text.UTF8Encoding($false)))

if (-not $Quiet) { $lines | ForEach-Object { Write-Host "  $_" } }
Write-Host "SHA256SUMS ($count file(s)) -> $outFull" -ForegroundColor Green
