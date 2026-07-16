using System.Runtime.Versioning;
using DnsCryptControl.Ipc.Security;

namespace DnsCryptControl.Service.Windows;

/// <summary>
/// Real caller verifier: validates the client image's Authenticode signature with
/// WinVerifyTrust, then confirms the signer thumbprint is on the publisher allow-list.
/// Fails closed on any uncertainty. The decision logic given (valid, thumbprint) is exposed
/// as Decide for unit testing; the native validity check is a guarded manual integration.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WinVerifyTrustCallerVerifier : ICallerVerifier
{
    private readonly SignerAllowList _allowList;

    public WinVerifyTrustCallerVerifier(SignerAllowList allowList)
    {
        ArgumentNullException.ThrowIfNull(allowList);
        _allowList = allowList;
    }

    public bool IsTrusted(CallerIdentity caller)
    {
        try
        {
            if (string.IsNullOrEmpty(caller.ImagePath)) return false;
            // Pin the on-disk image for the whole check: FileShare.Read denies Write AND Delete,
            // so the bytes WinVerifyTrust validates are the same bytes whose signer we extract
            // (closes the verify-by-path / extract-by-path TOCTOU the security review found).
            // Fails safe: any failure to open (missing/locked/denied) returns false via the catch.
            using var pin = new System.IO.FileStream(
                caller.ImagePath, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.Read);
            var valid = NativeMethods.VerifyAuthenticode(caller.ImagePath);
            var thumbprint = valid ? NativeMethods.ExtractSignerThumbprint(caller.ImagePath) : null;
            return Decide(valid, thumbprint);
        }
        catch (System.Exception)
        {
            return false; // any failure => not trusted (fail closed; suppressed in .editorconfig)
        }
    }

    /// <summary>Pure decision: trusted iff the signature is valid AND the extracted signer
    /// thumbprint is on the allow-list.</summary>
    internal bool Decide(bool valid, string? thumbprint) =>
        valid && thumbprint is not null && _allowList.IsAllowed(thumbprint);
}
