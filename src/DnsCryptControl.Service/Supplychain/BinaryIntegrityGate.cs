using System;
using System.IO;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.State;

namespace DnsCryptControl.Service.Supplychain;

/// <summary>Launch-time integrity gate (IC-10): re-hashes the installed dnscrypt-proxy.exe from a
/// pinned handle (FileShare.Read — no TOCTOU) and compares against the recorded post-verify SHA-256
/// with a fixed-time compare. Fail-closed: an exe with no record, or a hash mismatch, is REFUSED.
/// A fresh machine (no exe AND no record) passes — there is nothing to protect yet.</summary>
[SupportedOSPlatform("windows")]
public sealed class BinaryIntegrityGate
{
    private readonly ProtectedPaths _paths;
    private readonly InstalledBinaryRecordStore _record;

    public BinaryIntegrityGate(ProtectedPaths paths, InstalledBinaryRecordStore record)
    {
        ArgumentNullException.ThrowIfNull(paths);
        ArgumentNullException.ThrowIfNull(record);
        _paths = paths; _record = record;
    }

    public PlatformResult Verify()
    {
        try
        {
            var exeExists = File.Exists(_paths.ProxyExeFile);
            var rec = _record.Load();

            if (!exeExists && rec is null)
                return PlatformResult.Ok(); // fresh: nothing installed yet.
            if (!exeExists)
                return PlatformResult.Fail(PlatformErrorKind.NotFound, "recorded binary is missing.");
            if (rec is null)
                return PlatformResult.Fail(PlatformErrorKind.OperationFailed, "installed binary has no integrity record (refusing to launch unverified exe).");

            string actual;
            using (var fs = new FileStream(_paths.ProxyExeFile, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var sha = SHA256.Create())
                actual = Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();

            var expected = rec.Sha256Hex.ToLowerInvariant();
            var equal = CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.ASCII.GetBytes(actual),
                System.Text.Encoding.ASCII.GetBytes(expected));

            return equal
                ? PlatformResult.Ok()
                : PlatformResult.Fail(PlatformErrorKind.OperationFailed, "installed binary hash does not match the verified record.");
        }
        catch (IOException ex) { return PlatformResult.Fail(PlatformErrorKind.OperationFailed, ex.Message); }
        catch (UnauthorizedAccessException ex) { return PlatformResult.Fail(PlatformErrorKind.OperationFailed, ex.Message); }
    }
}
