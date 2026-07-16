using System;
using System.IO;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using DnsCryptControl.Core.Security;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.State;
using DnsCryptControl.Service.Windows;

namespace DnsCryptControl.Service.Supplychain;

/// <summary>
/// The privileged VerifyAndInstallBinary orchestration. Validates the untrusted temp path + tag,
/// pins the zip + sibling .minisig (FileShare.Read deny-write/delete), minisign-verifies over the
/// pinned bytes against the pinned release key, and ONLY on success stops+uninstalls the proxy
/// service, extracts dnscrypt-proxy.exe (+ example toml if absent) from the VERIFIED bytes into the
/// protected dir, records the installed exe's SHA-256, then reinstalls+starts. Fail-closed: any
/// failure returns PlatformResult.Fail and NEVER throws past this method (IC-12). Verification
/// failures touch NOTHING.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class BinaryVerifyInstaller : IBinaryVerifyInstaller
{
    private static readonly Regex TagPattern = new(@"^[0-9]+(\.[0-9]+){1,3}$", RegexOptions.CultureInvariant);

    private readonly ProtectedPaths _paths;
    private readonly IProxyServiceController _proxy;
    private readonly InstalledBinaryRecordStore _record;
    private readonly Func<byte[], string, string, MinisignVerifyResult> _verify;

    /// <summary>Production ctor: binds the real Group-B verifier with the pinned release key.</summary>
    public BinaryVerifyInstaller(ProtectedPaths paths, IProxyServiceController proxy, InstalledBinaryRecordStore record)
        : this(paths, proxy, record, BindVerifier()) { }

    /// <summary>Test ctor: inject a verify delegate so the install path is provable without a private key.</summary>
    internal BinaryVerifyInstaller(ProtectedPaths paths, IProxyServiceController proxy, InstalledBinaryRecordStore record,
        Func<byte[], string, string, MinisignVerifyResult> verify)
    {
        ArgumentNullException.ThrowIfNull(paths);
        ArgumentNullException.ThrowIfNull(proxy);
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(verify);
        _paths = paths; _proxy = proxy; _record = record; _verify = verify;
    }

    private static Func<byte[], string, string, MinisignVerifyResult> BindVerifier()
    {
        var key = PinnedReleaseKey.Get();
        return (zip, minisig, asset) => MinisignVerifier.Verify(zip, minisig, key, asset);
    }

    public PlatformResult VerifyAndInstall(string tempZipPath, string expectedTag)
    {
        try
        {
            // 1. Validate the tag (CWE-20) BEFORE any I/O.
            if (string.IsNullOrEmpty(expectedTag) || !TagPattern.IsMatch(expectedTag))
                return PlatformResult.Fail(PlatformErrorKind.InvalidArgument, "expectedTag is not a valid version.");

            // 2. Validate + confine the untrusted temp path (CWE-22, IC-8).
            if (string.IsNullOrEmpty(tempZipPath)
                || !Path.IsPathFullyQualified(tempZipPath)
                || tempZipPath.Contains("..", StringComparison.Ordinal)
                || tempZipPath.StartsWith(@"\\", StringComparison.Ordinal)        // UNC / device
                || !SafePath.IsWithinBase(_paths.DownloadStagingDir, tempZipPath))
                return PlatformResult.Fail(PlatformErrorKind.InvalidArgument, "tempZipPath is outside the allowed staging directory.");

            var expectedAsset = $"dnscrypt-proxy-win64-{expectedTag}.zip";

            // 3. Pin the zip + .minisig and read all bytes from the pinned handles (TOCTOU, IC-7).
            byte[] zipBytes;
            string minisigText;
            try
            {
                zipBytes = ReadPinned(tempZipPath);
                minisigText = System.Text.Encoding.UTF8.GetString(ReadPinned(tempZipPath + ".minisig"));
            }
            catch (FileNotFoundException ex) { return PlatformResult.Fail(PlatformErrorKind.NotFound, ex.Message); }
            catch (DirectoryNotFoundException ex) { return PlatformResult.Fail(PlatformErrorKind.NotFound, ex.Message); }
            catch (IOException ex) { return PlatformResult.Fail(PlatformErrorKind.OperationFailed, ex.Message); }
            catch (UnauthorizedAccessException ex) { return PlatformResult.Fail(PlatformErrorKind.OperationFailed, ex.Message); }

            // 4. Verify over the PINNED bytes. Verification failure touches NOTHING (fail-closed).
            var verdict = _verify(zipBytes, minisigText, expectedAsset);
            if (!verdict.Ok)
                return PlatformResult.Fail(PlatformErrorKind.OperationFailed, $"signature verification failed: {verdict.Error}");

            // 5. The running service locks the exe — stop + uninstall before replacing.
            var stop = _proxy.Stop();
            if (!stop.Success && stop.Error != PlatformErrorKind.NotFound)
                return PlatformResult.Fail(stop.Error, stop.Message ?? "stop failed before install.");
            var uninstall = _proxy.Uninstall();
            if (!uninstall.Success && uninstall.Error != PlatformErrorKind.NotFound)
                return PlatformResult.Fail(uninstall.Error, uninstall.Message ?? "uninstall failed before install.");

            // 6. Extract from the VERIFIED bytes (IC-7,8). Proxy exe is mandatory; example toml only if absent.
            Directory.CreateDirectory(_paths.BaseDir);
            // ACL-harden the install dir FIRST (Users read-only; SYSTEM/Admins full) so the exe lands in a
            // tamper-resistant directory — this is the primary tamper prevention (an unprivileged user must
            // not be able to replace the SYSTEM DNS proxy on disk).
            AclHelper.TryHardenAcl(_paths.BaseDir);
            var ex2 = ZipBinaryExtractor.ExtractEntry(zipBytes, "dnscrypt-proxy.exe", _paths.ProxyExeFile, _paths.BaseDir);
            if (!ex2.Ok)
                return PlatformResult.Fail(PlatformErrorKind.OperationFailed, ex2.Error ?? "exe extraction failed.");
            AclHelper.TryHardenAcl(_paths.ProxyExeFile);
            if (!File.Exists(_paths.ConfigFile))
            {
                // Best-effort seed: if the archive lacks the example, leave it; the proxy ships its own default.
                _ = ZipBinaryExtractor.ExtractEntry(zipBytes, "example-dnscrypt-proxy.toml", _paths.ExampleConfigFile, _paths.BaseDir);
            }

            // 7. Record the installed exe's SHA-256 for launch-time integrity (IC-10). Use the hash the
            // extractor computed over the EXACT bytes it streamed to disk — not a disk re-read an attacker
            // could swap between write and read (closes the install TOCTOU).
            _record.Record(ex2.Sha256Hex ?? throw new InvalidOperationException("extractor returned no hash on success."), expectedTag);

            // 8. Reinstall + start.
            var install = _proxy.Install();
            if (!install.Success)
                return PlatformResult.Fail(install.Error, install.Message ?? "reinstall failed.");
            var start = _proxy.Start();
            if (!start.Success)
                return PlatformResult.Fail(start.Error, start.Message ?? "start failed after install.");

            return PlatformResult.Ok();
        }
        catch (Exception ex)
        {
            // IC-12: never throw past the boundary. Map any unexpected fault to fail-closed.
            return PlatformResult.Fail(PlatformErrorKind.OperationFailed, $"verify/install faulted: {ex.GetType().Name}.");
        }
    }

    private static byte[] ReadPinned(string path)
    {
        // FileShare.Read denies concurrent Write AND Delete: the bytes we verify are the bytes we extract.
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var ms = new MemoryStream();
        fs.CopyTo(ms);
        return ms.ToArray();
    }
}
