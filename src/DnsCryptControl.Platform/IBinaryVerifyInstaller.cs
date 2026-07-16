namespace DnsCryptControl.Platform;

/// <summary>
/// Verifies a UI-downloaded dnscrypt-proxy release zip against the PINNED minisign release key
/// (prehashed ED only) and, on success, atomically installs the proxy binary from the VERIFIED
/// bytes (stop+uninstall the service, extract from memory, reinstall+start). All input is
/// untrusted and fully re-validated; the operation is fail-closed and NEVER throws. Defined as an
/// interface so the VerifyAndInstallBinary handler is unit-testable with a fake.
/// </summary>
public interface IBinaryVerifyInstaller
{
    /// <summary>Verify <paramref name="tempZipPath"/> (and its sibling .minisig) against the pinned
    /// key with the <paramref name="expectedTag"/> downgrade policy, then install on success.</summary>
    PlatformResult VerifyAndInstall(string tempZipPath, string expectedTag);
}
