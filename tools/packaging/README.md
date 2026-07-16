# Packaging — the DnsCryptControl MSI

A per-machine `.msi` (WiX v5) that installs the signed UI + LocalSystem helper + staged dnscrypt-proxy.

## Build a release MSI

```powershell
dotnet tool restore                        # WiX v5.0.2, pinned in .config/dotnet-tools.json
dotnet wix extension add -g WixToolset.Util.wixext/5.0.2   # once per machine
pwsh tools/packaging/build-package.ps1 -Version 1.0.0
# -> tools/packaging/dist/  :  DnsCryptControl-1.0.0.msi (signed) + DnsCryptControl-Release.cer + SHA256SUMS
```

`build-package.ps1` chains the existing pieces: `build-release.ps1` (signed, thumbprint-injected UI +
helper) → `get-proxy.ps1` (pinned-SHA-256 dnscrypt-proxy 2.1.16) → generate `installed-binary.json` →
`wix build` → SHA-256-sign the MSI → `make-sha256sums.ps1` over `dist/`. Switches: `-FrameworkDependent`
(fast dev build), `-SkipBuildRelease` (reuse an existing `tools/signing/release/`), `-Subject`.

> Cut releases from a clean commit: `build-release.ps1` builds from `git archive HEAD`, so the packaged
> helper reflects **committed** source (incl. the `--teardown` mode). Commit first, then package.

## WiX v5, not v7 (deliberate)

WiX v7 requires accepting the paid **Open Source Maintenance Fee** EULA (`WIX7015`). v5 is the last
fully-free major and does everything here; pinning it keeps the zero-cost posture. Revisit if the project
adopts the OSMF later.

## What the MSI does

| Area | How |
|------|-----|
| Files | Signed UI → `%ProgramFiles%\DnsCryptControl\ui`, helper → `\helper`, scripts → `\scripts`, `.cer` at root (write-protected = the at-rest integrity story for the unsigned managed DLLs). Proxy + default `dnscrypt-proxy.toml` → `%ProgramData%\DnsCryptControl`; `installed-binary.json` → `\state`. |
| Helper service | WiX `ServiceInstall`/`ServiceControl` — `DnsCryptControlHelper`, LocalSystem, auto-start; stopped + removed on uninstall. |
| Cert trust | `install-actions.ps1` imports the release `.cer` into LocalMachine **Root + TrustedPublisher** so the caller-gate reads a trusted chain (no "unknown publisher" from the app's own gate). |
| ProgramData ACLs | `install-actions.ps1` runs the exact proven `icacls` (SYSTEM + Admins Full `(OI)(CI)`, Users Read). |
| Proxy service | `install-actions.ps1` registers `dnscrypt-proxy` and forces **DEMAND_START** (the SCM must never launch it ahead of the helper's `BinaryIntegrityGate`). |
| Uninstall safety (IC-PKG) | Before files are removed: `uninstall-actions.ps1` runs `helper.exe --teardown` (the helper's own tested revert) then `uninstall-fallback.ps1` (dumb net: delete `KillSwitch*` rules, loopback-DNS adapters → DHCP), then removes the proxy service + the cert. **An uninstall — even mid-protection, even with a broken helper — always leaves working DNS.** |
| Data | Purged on a **true** uninstall only (`REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE`); a major-upgrade keeps the user's config. |

## Acceptance — throwaway VM ONLY

Never install this on a real machine (it registers a LocalSystem service, imports a machine-root cert,
sets ACLs, and can touch the firewall/DNS). On a disposable VM:

1. Double-click the MSI → elevation prompt only → installs.
2. Launch **DnsCryptControl** from the Start Menu as a **normal** user → the UI comes up and the helper is
   reachable (cert trusted → caller-gate passes).
3. Toggle protection **on** → green end-to-end (proxy passes the integrity gate; DNS via `127.0.0.1`);
   arm the kill switch (3 `DnsCryptControl KillSwitch*` rules).
4. **Uninstall from Add/Remove Programs WHILE protection is ON.**
5. Confirm: DNS resolves; **zero** `DnsCryptControl KillSwitch*` rules; `DnsCryptControlHelper` +
   `dnscrypt-proxy` services gone; `%ProgramData%\DnsCryptControl` purged; cert removed from the machine
   stores; `%ProgramFiles%\DnsCryptControl` gone.
6. Upgrade smoke: install a higher `-Version` over the first → config/state preserved.

## SmartScreen

Self-signed → the MSI shows one "unknown publisher" prompt. Deferred fix: **SignPath Foundation** once the
repo is public (free Authenticode for OSS). See `tools/signing/README.md`.
