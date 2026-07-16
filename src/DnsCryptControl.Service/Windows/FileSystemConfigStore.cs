using System.IO;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using DnsCryptControl.Core.Security;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.Supplychain;

namespace DnsCryptControl.Service.Windows;

/// <summary>
/// Real IConfigStore: writes dnscrypt-proxy's config + rule files into the protected dir
/// transactionally — back up the prior file, write a temp file in the same directory, then
/// atomically commit with File.Replace/File.Move; restore the backup on failure (CWE-367).
/// Every path is SafePath-confined to the base dir, and the directory/file ACLs are tightened
/// to SYSTEM/Admins-write before content is written (CWE-276).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class FileSystemConfigStore : IConfigStore
{
    private readonly ProtectedPaths _paths;

    public FileSystemConfigStore(ProtectedPaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        _paths = paths;
    }

    public PlatformResult<string> ReadConfig()
    {
        try
        {
            if (!File.Exists(_paths.ConfigFile))
                return PlatformResult<string>.Fail(PlatformErrorKind.NotFound, "config not found");
            return PlatformResult<string>.Ok(File.ReadAllText(_paths.ConfigFile));
        }
        catch (IOException ex) { return PlatformResult<string>.Fail(PlatformErrorKind.OperationFailed, ex.Message); }
        catch (UnauthorizedAccessException ex) { return PlatformResult<string>.Fail(PlatformErrorKind.OperationFailed, ex.Message); }
    }

    public PlatformResult WriteConfig(string tomlText)
    {
        ArgumentNullException.ThrowIfNull(tomlText);
        return AtomicWrite(_paths.ConfigFile, tomlText);
    }

    public PlatformResult WriteConfigIfBaseMatches(string tomlText, string expectedBaseSha256)
    {
        ArgumentNullException.ThrowIfNull(tomlText);
        ArgumentNullException.ThrowIfNull(expectedBaseSha256);

        // A malformed sha is a caller bug, not a concurrency event — InvalidArgument
        // (→ ValidationFailed on the wire), never a misleading Conflict.
        if (!IsSha256Hex(expectedBaseSha256))
        {
            return PlatformResult.Fail(
                PlatformErrorKind.InvalidArgument,
                "expectedBaseSha256 must be a 64-character hex SHA-256");
        }

        string currentSha;
        try
        {
            if (!File.Exists(_paths.ConfigFile))
            {
                return PlatformResult.Fail(
                    PlatformErrorKind.Conflict,
                    $"config file missing — reload before saving: {Path.GetFileName(_paths.ConfigFile)}");
            }
            // IC-9: hash the exact current on-disk BYTES (never a re-encoded string), so
            // BOM/encoding differences can never produce a false match or false conflict.
            currentSha = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(_paths.ConfigFile))).ToLowerInvariant();
        }
        catch (IOException ex) { return PlatformResult.Fail(PlatformErrorKind.OperationFailed, ex.Message); }
        catch (UnauthorizedAccessException ex) { return PlatformResult.Fail(PlatformErrorKind.OperationFailed, ex.Message); }

        // IC-9: lowercase-normalize the caller's hex, then ordinal compare.
        if (!string.Equals(currentSha, expectedBaseSha256.ToLowerInvariant(), StringComparison.Ordinal))
        {
            // IC-10: the UI shows this verbatim.
            return PlatformResult.Fail(
                PlatformErrorKind.Conflict,
                "config file changed on disk since it was loaded — reload before saving");
        }

        // TOCTOU: the pipe server is a serial one-shot loop, so no concurrent IPC writes
        // exist; the compare-then-write window only races EXTERNAL writers (e.g. an admin
        // editing the file directly), which is exactly what the NEXT save's Conflict
        // catches. Deliberately no file locking.
        return AtomicWrite(_paths.ConfigFile, tomlText);
    }

    public PlatformResult WriteRuleFile(RuleFileKind kind, string content)
    {
        ArgumentNullException.ThrowIfNull(content);
        if (!System.Enum.IsDefined(kind))
            return PlatformResult.Fail(PlatformErrorKind.InvalidArgument, "unknown rule-file kind");
        try
        {
            var path = _paths.RuleFilePath(kind);
            return AtomicWrite(path, content);
        }
        catch (ArgumentException ex)
        {
            return PlatformResult.Fail(PlatformErrorKind.InvalidArgument, ex.Message);
        }
    }

    /// <summary>The fixed set of bundled ODoH source-cache assets, embedded in THIS assembly
    /// (see the .csproj EmbeddedResource entries with matching LogicalNames). The logical name
    /// is also the target filename in the base dir. The .md files carry the resolver stamps; the
    /// .minisig files are their detached signatures — the proxy verifies each .md against the
    /// pinned minisign key on load, so these bytes must be placed EXACTLY as shipped.</summary>
    private static readonly string[] OdohCacheAssetNames =
    {
        "odoh-servers.md",
        "odoh-servers.md.minisig",
        "odoh-relays.md",
        "odoh-relays.md.minisig",
    };

    /// <summary>The bundled default source-cache assets (fresh-install brick fix), embedded in THIS
    /// assembly exactly like <see cref="OdohCacheAssetNames"/>: LogicalName = target filename, bytes
    /// placed EXACTLY as shipped so the detached .minisig verifies against the pinned key.</summary>
    private static readonly string[] DefaultListCacheAssetNames =
    {
        "public-resolvers.md",
        "public-resolvers.md.minisig",
    };

    // DNSCrypt anonymization relays live in a SEPARATE list (relays.md) — they are NOT in
    // public-resolvers.md — so anonymized DNSCrypt has NO relay to route through until this cache is
    // seeded. Seeded byte-exact + signature-verified exactly like the default list, and referenced by
    // a [sources.'relays'] entry in the shipped toml so the proxy loads it from cache (never the
    // boot-time download that would be FATAL off-53). The ODoH relays are the on-demand analogue
    // (PlaceOdohSourceCaches); this pair ships enabled so anonymized DNS works out of the box.
    private static readonly string[] RelaysCacheAssetNames =
    {
        "relays.md",
        "relays.md.minisig",
    };

    public PlatformResult EnsureDefaultSourceCaches()
    {
        // Seed-unless-VERIFIED, PER PAIR: an existing pair is kept only when the .md verifies against
        // its detached .minisig with the pinned resolver-list key — a fresher cache the proxy
        // downloaded itself always passes (the proxy pins the SAME key in the shipped config), while a
        // missing, half-missing, truncated, torn, or mismatched pair is restored whole from the
        // bundled copy. A mere existence check would preserve a corrupt pair, which is as FATAL to
        // the proxy as no cache at all — a recurring brick with no self-heal. Both the resolver list
        // AND the relays list are seeded (the relays list independently, so a valid public-resolvers
        // cache never masks a missing relays cache).
        var listResult = EnsurePairSeeded(DefaultListCacheAssetNames);
        if (!listResult.Success) return listResult;
        return EnsurePairSeeded(RelaysCacheAssetNames);
    }

    private PlatformResult EnsurePairSeeded(string[] pair)
        => PairVerifies(pair) ? PlatformResult.Ok() : PlaceEmbeddedAssets(pair);

    private bool PairVerifies(string[] pair)
    {
        try
        {
            var mdPath = SafePath.ResolveWithinBase(_paths.BaseDir, pair[0]);
            var sigPath = SafePath.ResolveWithinBase(_paths.BaseDir, pair[1]);
            if (!File.Exists(mdPath) || !File.Exists(sigPath)) return false;
            return ResolverListSignature.VerifiesWithPinnedKey(
                File.ReadAllBytes(mdPath),
                File.ReadAllText(sigPath),
                pair[0]);
        }
        catch (ArgumentException) { return false; }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    public PlatformResult PlaceOdohSourceCaches() => PlaceEmbeddedAssets(OdohCacheAssetNames);

    private PlatformResult PlaceEmbeddedAssets(string[] assetNames)
    {
        foreach (var name in assetNames)
        {
            byte[] bytes;
            try
            {
                using var stream = typeof(FileSystemConfigStore).Assembly.GetManifestResourceStream(name);
                if (stream is null)
                {
                    // A missing embedded asset is a build/packaging fault, not a runtime input error —
                    // fail closed so the caller never references sources whose cache we couldn't place.
                    return PlatformResult.Fail(
                        PlatformErrorKind.OperationFailed, $"bundled cache asset missing: {name}");
                }

                using var buffer = new MemoryStream();
                stream.CopyTo(buffer);
                bytes = buffer.ToArray();
            }
            catch (IOException ex)
            {
                return PlatformResult.Fail(PlatformErrorKind.OperationFailed, ex.Message);
            }

            // Byte-exact write (File.WriteAllBytes) — a re-encode would break the minisig signature.
            var write = AtomicWriteBytes(name, bytes);
            if (!write.Success)
            {
                return write;
            }
        }

        return PlatformResult.Ok();
    }

    private PlatformResult AtomicWrite(string targetPath, string content) =>
        AtomicWriteCore(targetPath, temp => File.WriteAllText(temp, content));

    private PlatformResult AtomicWriteBytes(string targetPath, byte[] content) =>
        AtomicWriteCore(targetPath, temp => File.WriteAllBytes(temp, content));

    private PlatformResult AtomicWriteCore(string targetPath, Action<string> writeTemp)
    {
        // Defense-in-depth: confine the resolved file name to the base dir even though the
        // caller computed it from a closed enum / fixed asset name.
        string confined;
        try
        {
            confined = SafePath.ResolveWithinBase(_paths.BaseDir, Path.GetFileName(targetPath));
        }
        catch (ArgumentException ex)
        {
            return PlatformResult.Fail(PlatformErrorKind.InvalidArgument, ex.Message);
        }

        string? backupPath = null;
        try
        {
            Directory.CreateDirectory(_paths.BaseDir);
            Directory.CreateDirectory(_paths.BackupsDir);
            AclHelper.TryHardenAcl(_paths.BaseDir);

            if (File.Exists(confined))
            {
                backupPath = Path.Combine(
                    _paths.BackupsDir,
                    $"{Path.GetFileName(confined)}.{System.DateTime.UtcNow:yyyyMMddHHmmssfff}.bak");
                File.Copy(confined, backupPath, overwrite: true);
                // Strip any ReadOnly attribute from the backup so it can always be deleted.
                File.SetAttributes(backupPath, File.GetAttributes(backupPath) & ~FileAttributes.ReadOnly);
            }

            var temp = confined + ".tmp";
            writeTemp(temp);
            AclHelper.TryHardenAcl(temp);

            if (File.Exists(confined))
                File.Replace(temp, confined, destinationBackupFileName: null);
            else
                File.Move(temp, confined, overwrite: true);

            return PlatformResult.Ok();
        }
        catch (IOException ex)
        {
            RollBack(confined, backupPath);
            return PlatformResult.Fail(PlatformErrorKind.OperationFailed, ex.Message);
        }
        catch (UnauthorizedAccessException ex)
        {
            RollBack(confined, backupPath);
            return PlatformResult.Fail(PlatformErrorKind.OperationFailed, ex.Message);
        }
    }

    private static bool IsSha256Hex(string s)
    {
        if (s.Length != 64) return false;
        foreach (var c in s)
        {
            if (!Uri.IsHexDigit(c)) return false;
        }
        return true;
    }

    private static void RollBack(string targetPath, string? backupPath)
    {
        try
        {
            var temp = targetPath + ".tmp";
            if (File.Exists(temp)) File.Delete(temp);
            if (backupPath is not null && File.Exists(backupPath))
                File.Copy(backupPath, targetPath, overwrite: true);
        }
        catch (IOException) { /* best-effort restore; original is intact if replace never ran */ }
        catch (UnauthorizedAccessException) { }
    }

}
