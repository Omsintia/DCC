# Signing — zero-cost self-signed release signing

Phase 6 formalizes DnsCryptControl's code signing into a repeatable **release** step, decoupled from the
throwaway-VM dev script. It is **self-signed** (zero cost) and **SHA-256**.

## What the signature does (and doesn't)

A code-signing certificate does two unrelated jobs here:

1. **The security-critical job — the helper↔UI trust gate — needs NO public CA.** The LocalSystem helper
   only accepts commands from a UI whose Authenticode signer thumbprint is on its allow-list
   (`SignerAllowList` + `WinVerifyTrustCallerVerifier`). A self-signed cert does this with **identical
   cryptographic strength** to a paid one.
2. **The cosmetic job — clearing the SmartScreen "unknown publisher" banner — is the only thing money
   buys, and it stays DEFERRED.** A self-signed cert does *not* clear it. The plan: ship self-signed now;
   once the repo is public, apply to **[SignPath Foundation](https://signpath.org/)** (free Authenticode
   signing for accepted open-source projects) to clear SmartScreen at $0. Until then, downloaders see the
   "unknown publisher" prompt on first launch — a cosmetic warning, not a functional problem.

The private key lives only on the maintainer's machine (`Cert:\CurrentUser\My`, DPAPI-protected). Only the
**public** cert (`DnsCryptControl-Release.cer`) and its `DnsCryptControl-Release.thumbprint.txt` are
committed — a public cert is safe to share and lets anyone verify a release was signed by this exact key.

## Design: inject the thumbprint at release time

The committed `ServiceComposition.cs` keeps a neutral placeholder
(`REPLACE_WITH_OUR_AUTHENTICODE_THUMBPRINT`); a plain source build warns at startup and rejects callers by
design. `build-release.ps1` bakes the **real** thumbprint into the helper's allow-list only for the
release — from a disposable `git archive` export, so the working tree is never mutated. This keeps the
public repo environment-neutral (not hard-wired to one machine's cert).

## Cut a release (maintainer)

```powershell
# One-time: create the stable release cert (10-yr self-signed SHA-256). -Trust makes signatures read
# 'Valid' on THIS machine (adds it to your user trust stores; may need an elevated shell for the Root store).
pwsh tools/signing/new-signing-cert.ps1 -Trust
#   optional key backup (keep OUT of the repo):  -ExportPfx C:\keys\dnscc.pfx

# Cut the signed release (self-contained win-x64 by default) into tools/signing/release/:
pwsh tools/signing/build-release.ps1

# Verify what you just built:
pwsh tools/signing/verify-release.ps1 -Path tools/signing/release
```

`build-release.ps1` publishes the helper + UI, SHA-256-signs both exes, copies the public `.cer`, and
writes `SHA256SUMS`. It asserts each exe is signed by the exact release cert; a `Status` of
`UnknownError` just means the self-signed cert isn't chain-trusted on the build machine (the signature is
complete and becomes `Valid` wherever the cert is trusted). Useful switches: `-FrameworkDependent` (fast,
needs .NET 8 on the target), `-Runtime`, `-FromWorkingTree`, `-TimestampUrl`.

> Scope: this step signs **our** two exes and writes `SHA256SUMS`. Bundling `dnscrypt-proxy.exe` (kept
> vendor-signed), the configs, and building the installer is the **packaging** step, which reuses
> `make-sha256sums.ps1` over the final artifact.

## Verify a download (user)

Every release ships `SHA256SUMS` and `DnsCryptControl-Release.cer`.

```powershell
# 1. Integrity + signer check in one go:
pwsh tools/signing/verify-release.ps1 -Path <extracted-release-dir>

# ...or by hand:
#   Get-FileHash .\ui\DnsCryptControl.UI.exe -Algorithm SHA256      # compare to SHA256SUMS
#   Get-AuthenticodeSignature .\ui\DnsCryptControl.UI.exe           # SignerCertificate.Thumbprint == the published one
```

To make the signature read **Valid** on your machine (and silence the "unknown publisher" prompt yourself),
import the public cert into your Trusted Root + Trusted Publishers. The installer does this for you.

## What this protects — and what packaging must add

- **The exe Authenticode signature** binds each shipped `.exe` to your release key: a rogue process can't
  impersonate the signed UI to the helper (it can't reproduce your signature), and a tampered `.exe` fails
  verification. This is the real helper↔UI trust gate.
- **`SHA256SUMS` is not itself cryptographically signed** (we chose plain SHA256SUMS); its origin trust comes
  from GitHub (HTTPS + the release page). `verify-release.ps1` treats the manifest as an **exact whitelist** —
  every shipped file must be listed and the manifest may not be empty — so a shrunk or planted manifest
  **fails** rather than passing vacuously.
- **Managed DLLs are not individually signed** (a signed .NET apphost `.exe` loads unsigned `*.dll`; the CLR
  does not Authenticode-check them at load). At-rest integrity of the app's real code therefore relies on a
  write-protected install directory. **Packaging must install to a protected location (e.g. Program Files,
  admin-only)** and import the `.cer` into the machine trust stores so the caller-gate reads `Valid`. A future
  hardening is a single-file publish (`PublishSingleFile=true`) so the managed code is embedded in the one
  signed `.exe` — deferred to packaging (needs a full GUI/VM test).
- **Signatures are not timestamped by default** (`-TimestampUrl` countersigns): they become invalid when the
  10-year cert expires, which also breaks the caller-gate — re-cut releases before then, or timestamp.

## Build from source (contributor)

A plain `dotnet build` produces an **unsigned** UI, which the committed helper (placeholder allow-list)
will reject — by design. To get a working local build, mint your own dev cert and cut a dev release:

```powershell
pwsh tools/signing/new-signing-cert.ps1 -Subject "CN=YourName Dev" -Trust
pwsh tools/signing/build-release.ps1 -Subject "CN=YourName Dev" -FrameworkDependent
```

(The throwaway-VM script `tools/dev-install/Setup-Phase5aVM.ps1` does the same thing end-to-end for a full
VM install.)

## Rotating / backing up the key

- **Backup:** `new-signing-cert.ps1 -ExportPfx <path> ` writes a password-protected `.pfx` (gitignored).
  Store it safely; it's the only copy of your release identity.
- **Rotate:** `new-signing-cert.ps1 -Force` mints a new cert (new thumbprint). You must then re-cut every
  release so the shipped helper trusts the shipped UI, and re-publish the new `.cer` / `SHA256SUMS`.

## Files

| File | Purpose |
|------|---------|
| `new-signing-cert.ps1` | create/reuse the stable self-signed SHA-256 cert; export public `.cer` + thumbprint |
| `build-release.ps1` | inject thumbprint → publish → SHA-256 sign → `SHA256SUMS` (from a clean `git archive`) |
| `make-sha256sums.ps1` | write a `sha256sum`-format manifest over a directory (reused by packaging) |
| `verify-release.ps1` | check `SHA256SUMS` + assert each exe is signed by the expected cert |
| `DnsCryptControl-Release.cer` | the committed **public** release cert (safe to share) |
| `DnsCryptControl-Release.thumbprint.txt` | the committed thumbprint reference |
| `.gitignore` | never commit `*.pfx`/key material or `release/` output |
