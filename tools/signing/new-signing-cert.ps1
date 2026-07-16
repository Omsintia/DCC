#requires -Version 5.1
<#
.SYNOPSIS
  Create (or reuse) the STABLE self-signed SHA-256 code-signing certificate that signs DnsCryptControl
  releases, and export its PUBLIC half (.cer) + thumbprint as committed reference.

.DESCRIPTION
  Phase 6 "zero-cost signing": the release binaries are Authenticode-signed with a self-signed cert. It
  does the security-critical job - the helper<->UI trust gate (the LocalSystem helper only accepts a
  UI signed by an allow-listed thumbprint; self-signed has identical cryptographic strength). The
  cosmetic SmartScreen job is the only thing money buys and stays DEFERRED - a self-signed cert does
  NOT clear the Windows "unknown publisher" banner (only a public CA / SignPath does, deferred until
  the repo is public).

  The private key stays on THIS machine (Cert:\CurrentUser\My, DPAPI-protected; optionally backed up to a
  gitignored .pfx). Only the public .cer + the thumbprint are committed - a self-signed public cert is safe
  to share and lets downloaders/verify-release confirm a release was signed by this exact key.

  Idempotent: if a code-signing cert with -Subject already exists it is reused (unless -Force). The cert
  thumbprint is what build-release.ps1 injects into the helper's SignerAllowList and what verify-release.ps1
  checks. Rotating the cert (-Force) means re-cutting every release so the shipped helper trusts the shipped UI.

.PARAMETER Subject       Cert subject / publisher name shown to users. Default 'CN=DnsCryptControl'.
.PARAMETER Years         Validity in years. Default 10 (a self-signed release key; long-lived on purpose).
.PARAMETER Force         Regenerate even if a matching cert already exists (rotates the release identity).
.PARAMETER Trust         Also add the cert to Cert:\CurrentUser\Root + \TrustedPublisher so Authenticode
                         reads 'Valid' (instead of the accepted 'UnknownError') on THIS machine and the
                         caller-gate can be exercised locally. Not required to cut a release - build-release
                         gates on the signer thumbprint. End-user machines get this via the installer.
.PARAMETER ExportPfx     Optional path to back up the FULL cert (private key) as a password-protected .pfx.
                         Keep it OUT of the repo (the tools/signing/.gitignore already ignores *.pfx).
.PARAMETER PfxPassword   SecureString password for -ExportPfx. Prompted if -ExportPfx is set without it.
#>
[CmdletBinding()]
param(
    [string]$Subject = 'CN=DnsCryptControl',
    [int]$Years = 10,
    [switch]$Force,
    [switch]$Trust,
    [string]$ExportPfx = '',
    [System.Security.SecureString]$PfxPassword
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$signingDir = $PSScriptRoot
$cerPath    = Join-Path $signingDir 'DnsCryptControl-Release.cer'
$thumbFile  = Join-Path $signingDir 'DnsCryptControl-Release.thumbprint.txt'

# --- Find an existing code-signing cert with this subject -------------------------------------------
function Get-ExistingSigningCert {
    Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq $Subject } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
}

$cert = Get-ExistingSigningCert
if ($cert -and -not $Force) {
    Write-Host "Reusing existing code-signing cert for '$Subject'." -ForegroundColor Green
}
else {
    if ($cert -and $Force) { Write-Host "-Force: minting a NEW cert (the old one stays in the store; releases must be re-cut)." -ForegroundColor Yellow }
    Write-Host "Creating a self-signed SHA-256 code-signing cert '$Subject' (valid $Years years)..." -ForegroundColor Cyan
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject `
        -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy Exportable `
        -HashAlgorithm SHA256 -KeyAlgorithm RSA -KeyLength 3072 `
        -NotBefore (Get-Date).AddDays(-1) -NotAfter (Get-Date).AddYears($Years)
}

$thumbprint = $cert.Thumbprint      # uppercase SHA-1 hex, no spaces - exactly what SignerAllowList compares
if ([string]::IsNullOrWhiteSpace($thumbprint)) { throw "Failed to obtain a thumbprint from the certificate." }

# --- Export the PUBLIC cert + thumbprint as committed reference ------------------------------------
Export-Certificate -Cert $cert -FilePath $cerPath -Type CERT -Force | Out-Null
Set-Content -LiteralPath $thumbFile -Value $thumbprint -Encoding ASCII
Write-Host "Public cert  -> $cerPath" -ForegroundColor DarkGreen
Write-Host "Thumbprint   -> $thumbFile" -ForegroundColor DarkGreen

# --- Optional: trust it locally so Authenticode validates as 'Valid' on this machine ---------------
if ($Trust) {
    foreach ($store in @('Cert:\CurrentUser\Root', 'Cert:\CurrentUser\TrustedPublisher')) {
        try {
            Import-Certificate -FilePath $cerPath -CertStoreLocation $store -ErrorAction Stop | Out-Null
            Write-Host "Trusted in $store" -ForegroundColor DarkGreen
        }
        catch { Write-Warning "Could not add to ${store}: $($_.Exception.Message)" }
    }
}

# --- Optional: back up the private key to a gitignored .pfx ----------------------------------------
if ($ExportPfx) {
    # This .pfx is the sole portable copy of the release private key: never write it unprotected, and never
    # silently clobber an existing backup.
    if (Test-Path $ExportPfx) { throw "PFX '$ExportPfx' already exists - refusing to overwrite (delete it or choose another path)." }
    if (-not $PfxPassword) { $PfxPassword = Read-Host -AsSecureString "Password for the .pfx backup (min 8 chars)" }
    if ($PfxPassword.Length -lt 8) { throw "Refusing to export the private key with a password under 8 characters." }
    Export-PfxCertificate -Cert $cert -FilePath $ExportPfx -Password $PfxPassword | Out-Null
    Write-Host "Private-key backup -> $ExportPfx  (keep OUT of the repo)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "==================== SIGNING CERT READY ====================" -ForegroundColor Green
Write-Host "  Subject:    $Subject"
Write-Host "  Thumbprint: $thumbprint"
Write-Host "  Not after:  $($cert.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host "  Store:      Cert:\CurrentUser\My  (private key stays here)"
if (-not $Trust) { Write-Host "  (run again with -Trust to validate signatures as 'Valid' on this machine)" -ForegroundColor DarkYellow }
