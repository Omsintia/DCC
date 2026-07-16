#requires -Version 5.1
<#
.SYNOPSIS
  Cut a signed DnsCryptControl release: from a CLEAN committed source tree, inject the signing cert's
  thumbprint into the helper's SignerAllowList, publish the UI + helper, SHA-256 Authenticode-sign both,
  and write a SHA256SUMS manifest.

.DESCRIPTION
  The "inject at release-build" model: the committed ServiceComposition.cs keeps the neutral placeholder
  (a plain source build warns + rejects callers by design); this script bakes the REAL thumbprint in only
  for the release, so the shipped helper trusts the shipped UI. The working tree is never mutated - the
  build runs from a disposable `git archive` export.

  Steps:
    1. Find the signing cert (Cert:\CurrentUser\My, code-signing, -Subject). Run new-signing-cert.ps1 first.
    2. Export the committed source (git archive HEAD, or the working tree with -FromWorkingTree) to a temp tree.
    3. Patch the helper's SignerAllowList placeholder -> the cert thumbprint (assert the placeholder was there).
    4. `dotnet publish` the helper + UI (Release, win-x64, self-contained by default) into <OutDir>.
    5. `Set-AuthenticodeSignature -HashAlgorithm SHA256` both exes; assert each is signed by our exact cert.
    6. Copy the public .cer into the release + write SHA256SUMS over the whole release dir.

  Signature validity note: a self-signed cert not chain-trusted on THIS machine reads as Status
  'UnknownError' (NOT a signing defect - the signature is complete and becomes 'Valid' wherever the cert is
  trusted, e.g. after the installer imports the .cer). The gate therefore asserts signer-thumbprint-match,
  and treats 'UnknownError' as signed-but-locally-untrusted (a note); 'Valid' is ideal.

.PARAMETER Subject           Cert subject to sign with. Default 'CN=DnsCryptControl'.
.PARAMETER OutDir            Release output dir. Default tools/signing/release (gitignored).
.PARAMETER Runtime           RID. Default 'win-x64'.
.PARAMETER FrameworkDependent  Publish framework-dependent (fast; needs .NET 8 on the target) instead of self-contained.
.PARAMETER FromWorkingTree   Build the current working tree (incl. uncommitted tracked changes) instead of HEAD.
.PARAMETER TimestampUrl      RFC-3161 timestamp server (e.g. http://timestamp.digicert.com). Omitted by default
                             (offline-friendly), but untimestamped signatures expire with the cert - see the
                             end-of-run warning.
#>
[CmdletBinding()]
param(
    [string]$Subject = 'CN=DnsCryptControl',
    [string]$OutDir = '',
    [string]$Runtime = 'win-x64',
    [switch]$FrameworkDependent,
    [switch]$FromWorkingTree,
    [string]$TimestampUrl = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$signingDir = $PSScriptRoot
$repoRoot   = Split-Path (Split-Path $signingDir)                     # tools/signing -> tools -> repo
$cerPath    = Join-Path $signingDir 'DnsCryptControl-Release.cer'
if (-not $OutDir) { $OutDir = Join-Path $signingDir 'release' }
$makeSums   = Join-Path $signingDir 'make-sha256sums.ps1'
$placeholder = 'REPLACE_WITH_OUR_AUTHENTICODE_THUMBPRINT'

$dotnetCmd = Get-Command dotnet -ErrorAction SilentlyContinue
$dotnet = if ($dotnetCmd) { $dotnetCmd.Source } else { 'C:\Program Files\dotnet\dotnet.exe' }
if (-not (Test-Path $dotnet) -and -not $dotnetCmd) { throw "dotnet not found on PATH or at 'C:\Program Files\dotnet\dotnet.exe'." }

# Run a native tool without PS 5.1 turning its stderr into a terminating NativeCommandError; gate on exit code.
function Invoke-Native {
    param([Parameter(Mandatory)][string]$Exe, [Parameter(Mandatory)][string[]]$Arguments, [string]$Title = '')
    if ($Title) { Write-Host "== $Title" -ForegroundColor Cyan }
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & $Exe @Arguments; $code = $LASTEXITCODE } finally { $ErrorActionPreference = $prev }
    if ($code -ne 0) { throw "$Title failed (exit $code): $Exe" }
}

# --- 1. Signing cert ------------------------------------------------------------------------------
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq $Subject } | Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) { throw "No code-signing cert for '$Subject' in Cert:\CurrentUser\My. Run .\new-signing-cert.ps1 first." }
$thumbprint = $cert.Thumbprint
Write-Host "Signing cert: $Subject  thumbprint $thumbprint  (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))" -ForegroundColor Green

# The committed public reference (.cer + thumbprint) MUST match the signing cert: the release ships that
# .cer as its trust anchor and verify-release/downloaders check against the committed thumbprint. If they
# diverge (e.g. the cert was rotated with -Force but new-signing-cert.ps1 was not re-run, or a stale
# same-subject cert was picked), fail fast rather than ship a release whose anchor mismatches its signer.
$thumbFile = Join-Path $signingDir 'DnsCryptControl-Release.thumbprint.txt'
if (Test-Path $thumbFile) {
    $refThumb = (Get-Content -LiteralPath $thumbFile -Raw).Trim()
    if ($refThumb -ne $thumbprint) {
        throw "Committed thumbprint reference ($refThumb) != signing cert ($thumbprint). Re-run .\new-signing-cert.ps1 to refresh the committed .cer/thumbprint for this cert."
    }
}
if (-not (Test-Path $cerPath)) { throw "Public cert $cerPath not found - run .\new-signing-cert.ps1 first (the release must ship the matching .cer)." }
$cerThumb = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cerPath).Thumbprint
if ($cerThumb -ne $thumbprint) { throw "Committed .cer thumbprint ($cerThumb) != signing cert ($thumbprint). Re-run .\new-signing-cert.ps1." }

# --- 2. Export a disposable source tree (working tree never touched) -------------------------------
$ref = 'HEAD'
if ($FromWorkingTree) {
    $stash = (& git -C $repoRoot stash create) | Select-Object -First 1
    if (-not [string]::IsNullOrWhiteSpace($stash)) { $ref = $stash.Trim() } # else nothing uncommitted -> HEAD
}
$buildTree = Join-Path ([IO.Path]::GetTempPath()) "dcc-release-$PID"
$buildZip  = "$buildTree.zip"
if (Test-Path $buildTree) { Remove-Item -Recurse -Force $buildTree }
if (Test-Path $buildZip)  { Remove-Item -Force $buildZip }
Invoke-Native -Title "Exporting source ($ref) -> $buildTree" -Exe 'git' -Arguments @('-C', $repoRoot, 'archive', '--format=zip', $ref, '-o', $buildZip)
Expand-Archive -LiteralPath $buildZip -DestinationPath $buildTree -Force
Remove-Item -Force $buildZip

try {
    # --- 3. Inject the thumbprint into the helper allow-list --------------------------------------
    $compo = Join-Path $buildTree 'src\DnsCryptControl.Service\ServiceComposition.cs'
    if (-not (Test-Path $compo)) { throw "Not found in the export: $compo" }
    $text = [IO.File]::ReadAllText($compo)
    if ($text -notlike "*$placeholder*") {
        throw "Placeholder '$placeholder' not found in ServiceComposition.cs - the committed source must keep the placeholder (inject-at-release model)."
    }
    [IO.File]::WriteAllText($compo, $text.Replace($placeholder, $thumbprint), (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "Injected allow-list thumbprint $thumbprint" -ForegroundColor DarkGreen

    # --- 4. Publish helper + UI -------------------------------------------------------------------
    if (Test-Path $OutDir) { Remove-Item -Recurse -Force $OutDir }
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $scArgs = if ($FrameworkDependent) { @('--no-self-contained') } else { @('--self-contained') }

    $targets = @(
        @{ Name = 'helper'; Proj = 'src\DnsCryptControl.Service\DnsCryptControl.Service.csproj'; Exe = 'DnsCryptControl.Service.exe' },
        @{ Name = 'ui';     Proj = 'src\DnsCryptControl.UI\DnsCryptControl.UI.csproj';           Exe = 'DnsCryptControl.UI.exe' }
    )
    $signed = @()
    foreach ($t in $targets) {
        $proj = Join-Path $buildTree $t.Proj
        $dest = Join-Path $OutDir $t.Name
        # PublishReadyToRun: precompile to native code at publish time. The COLD first launch after a
        # Windows restart otherwise JIT-compiles the whole dependency graph on a cold disk - VM-measured
        # ~10s of white unpainted window between Show() and the first presented frame. R2R trades a
        # larger binary for that JIT work happening at build time.
        Invoke-Native -Title "Publishing $($t.Name) ($Runtime, $(if($FrameworkDependent){'framework-dependent'}else{'self-contained'}), R2R)" `
            -Exe $dotnet -Arguments (@('publish', $proj, '-c', 'Release', '-r', $Runtime, '-p:PublishReadyToRun=true', '--nologo', '-o', $dest) + $scArgs)
        $exe = Join-Path $dest $t.Exe
        if (-not (Test-Path $exe)) { throw "publish succeeded but $exe not found." }

        # --- 5. Sign + assert -----------------------------------------------------------------------
        $signArgs = @{ FilePath = $exe; Certificate = $cert; HashAlgorithm = 'SHA256' }
        if ($TimestampUrl) { $signArgs.TimestampServer = $TimestampUrl }
        $sig = Set-AuthenticodeSignature @signArgs
        $sigThumb = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { $null }
        if ($sigThumb -ne $thumbprint) {
            throw "Signing $($t.Exe) FAILED: signer thumbprint '$sigThumb' != expected '$thumbprint' (status $($sig.Status))."
        }
        if ($sig.Status -eq 'Valid') { Write-Host "  signed $($t.Exe): Valid" -ForegroundColor Green }
        elseif ($sig.Status -eq 'UnknownError') { Write-Host "  signed $($t.Exe): signature OK (cert not chain-trusted on this machine; end users trust it via the installer)" -ForegroundColor DarkYellow }
        else { throw "Signing $($t.Exe) produced an unexpected status '$($sig.Status)': $($sig.StatusMessage)" }
        $signed += $exe
    }

    # --- 6. Public cert + SHA256SUMS --------------------------------------------------------------
    Copy-Item $cerPath (Join-Path $OutDir 'DnsCryptControl-Release.cer') -Force   # asserted present + matching above
    # make-sha256sums is pure PowerShell (no native call) so it never sets $LASTEXITCODE; it runs under
    # $ErrorActionPreference='Stop' and THROWS on failure, which propagates here. Do NOT gate on $LASTEXITCODE
    # (it would read a stale value from the last dotnet publish).
    & $makeSums -Path $OutDir -Quiet
}
finally {
    Remove-Item -Recurse -Force $buildTree -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "==================== RELEASE BUILT ====================" -ForegroundColor Green
Write-Host "  Output:     $OutDir"
Write-Host "  Signed by:  $Subject ($thumbprint)"
Write-Host "  Verify:     .\verify-release.ps1 -Path `"$OutDir`""
if (-not $TimestampUrl) {
    Write-Warning ("Signatures are NOT RFC-3161 timestamped: they become INVALID after the cert expires " +
        "($($cert.NotAfter.ToString('yyyy-MM-dd'))) - which also breaks the helper's caller-gate against the UI. " +
        "Pass -TimestampUrl <rfc3161-server> to countersign for longevity (a release-time network call only).")
}
