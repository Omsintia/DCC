using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using DnsCryptControl.Platform;
using DnsCryptControl.Service;
using DnsCryptControl.Service.Windows;
using Xunit;

namespace DnsCryptControl.Service.Tests;

public class FileSystemConfigStoreTests : IDisposable
{
    private readonly string _temp = Path.Combine(Path.GetTempPath(), "DnsCryptCtlTest_" + Guid.NewGuid().ToString("N"));
    private readonly FileSystemConfigStore _store;
    private readonly ProtectedPaths _paths;

    public FileSystemConfigStoreTests()
    {
        _paths = new ProtectedPaths(_temp);
        _store = new FileSystemConfigStore(_paths);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_temp)) Directory.Delete(_temp, recursive: true); } catch (IOException) { }
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void WriteConfig_thenRead_roundTrips()
    {
        Assert.True(_store.WriteConfig("max_clients = 1\n").Success);
        var read = _store.ReadConfig();
        Assert.True(read.Success);
        Assert.Equal("max_clients = 1\n", read.Value);
    }

    [Fact]
    public void ReadConfig_whenAbsent_returnsNotFound()
    {
        var read = _store.ReadConfig();
        Assert.False(read.Success);
        Assert.Equal(PlatformErrorKind.NotFound, read.Error);
    }

    [Fact]
    public void WriteConfig_overExisting_createsBackupOfPrevious()
    {
        _store.WriteConfig("first = 1\n");
        _store.WriteConfig("second = 2\n");

        Assert.Equal("second = 2\n", File.ReadAllText(_paths.ConfigFile));
        var backups = Directory.GetFiles(_paths.BackupsDir);
        Assert.NotEmpty(backups);
        Assert.Contains(backups, b => File.ReadAllText(b) == "first = 1\n");
    }

    [Fact]
    public void PlaceOdohSourceCaches_writesAllFourFiles_byteExact_matchingTheEmbeddedAssets()
    {
        // The proxy verifies each .md against its detached .minisig with the pinned key, so the placed
        // bytes MUST equal the embedded copy exactly — a single re-encoded byte breaks the signature.
        Assert.True(_store.PlaceOdohSourceCaches().Success);

        var asm = typeof(FileSystemConfigStore).Assembly;
        foreach (var name in new[] { "odoh-servers.md", "odoh-servers.md.minisig", "odoh-relays.md", "odoh-relays.md.minisig" })
        {
            var placed = Path.Combine(_temp, name);
            Assert.True(File.Exists(placed), $"{name} was not placed");

            using var stream = asm.GetManifestResourceStream(name);
            Assert.NotNull(stream);
            using var ms = new MemoryStream();
            stream!.CopyTo(ms);
            var expected = ms.ToArray();

            Assert.NotEmpty(expected);
            Assert.Equal(expected, File.ReadAllBytes(placed)); // BYTE-EXACT
        }
    }

    [Fact]
    public void PlaceOdohSourceCaches_placesTheSignedOdohLists_withTheirExpectedContent()
    {
        Assert.True(_store.PlaceOdohSourceCaches().Success);
        Assert.Contains("Oblivious DoH servers", File.ReadAllText(Path.Combine(_temp, "odoh-servers.md")), StringComparison.Ordinal);
        Assert.Contains("Oblivious DoH relays", File.ReadAllText(Path.Combine(_temp, "odoh-relays.md")), StringComparison.Ordinal);
        Assert.True(File.Exists(Path.Combine(_temp, "odoh-servers.md.minisig")));
        Assert.True(File.Exists(Path.Combine(_temp, "odoh-relays.md.minisig")));
    }

    // ── EnsureDefaultSourceCaches (fresh-install brick fix) ───────────────────

    [Fact]
    public void EnsureDefaultSourceCaches_whenAbsent_placesBothFiles_byteExact_matchingTheEmbeddedAssets()
    {
        Assert.True(_store.EnsureDefaultSourceCaches().Success);

        var asm = typeof(FileSystemConfigStore).Assembly;
        foreach (var name in new[] { "public-resolvers.md", "public-resolvers.md.minisig" })
        {
            var placed = Path.Combine(_temp, name);
            Assert.True(File.Exists(placed), $"{name} was not placed");

            using var stream = asm.GetManifestResourceStream(name);
            Assert.NotNull(stream);
            using var ms = new MemoryStream();
            stream!.CopyTo(ms);
            var expected = ms.ToArray();

            Assert.NotEmpty(expected);
            Assert.Equal(expected, File.ReadAllBytes(placed)); // BYTE-EXACT
        }
    }

    [Fact]
    public void EnsureDefaultSourceCaches_alsoSeedsTheRelaysList_byteExact()
    {
        // Anonymized DNSCrypt has NO relays without this: relays.md is a separate list from
        // public-resolvers.md, so it must be seeded too or the Anonymized DNS relay picker is empty.
        Assert.True(_store.EnsureDefaultSourceCaches().Success);

        var asm = typeof(FileSystemConfigStore).Assembly;
        foreach (var name in new[] { "relays.md", "relays.md.minisig" })
        {
            var placed = Path.Combine(_temp, name);
            Assert.True(File.Exists(placed), $"{name} was not seeded");

            using var stream = asm.GetManifestResourceStream(name);
            Assert.NotNull(stream);
            using var ms = new MemoryStream();
            stream!.CopyTo(ms);
            Assert.Equal(ms.ToArray(), File.ReadAllBytes(placed)); // BYTE-EXACT
        }
    }

    [Fact]
    public void EnsureDefaultSourceCaches_reseedsRelays_evenWhenTheResolverListAlreadyVerifies()
    {
        // Independence lock: a valid public-resolvers cache must NOT mask a missing relays cache —
        // otherwise an install that lost only relays.md would silently have no anonymization relays,
        // with no self-heal. Each pair is verified and seeded on its own.
        Assert.True(_store.EnsureDefaultSourceCaches().Success); // seeds both pairs
        File.Delete(Path.Combine(_temp, "relays.md"));           // lose ONLY the relays cache
        File.Delete(Path.Combine(_temp, "relays.md.minisig"));

        Assert.True(_store.EnsureDefaultSourceCaches().Success); // public-resolvers still verifies...

        Assert.True(File.Exists(Path.Combine(_temp, "relays.md")), "relays.md must be re-seeded");
        Assert.True(File.Exists(Path.Combine(_temp, "relays.md.minisig")), "relays.md.minisig must be re-seeded");
    }

    [Fact]
    public void EnsureDefaultSourceCaches_whenPairVerifies_isANoOp_andNeverOverwrites()
    {
        // A VERIFYING existing pair is typically a fresher cache the proxy downloaded itself (the
        // proxy pins the same key) — seeding must never rewrite it. Seed the bundled pair first,
        // then prove a second ensure does not touch the files (no rewrite => mtime unchanged and
        // no new backups).
        Assert.True(_store.EnsureDefaultSourceCaches().Success);
        var md = Path.Combine(_temp, "public-resolvers.md");
        var stamp = new DateTime(2020, 1, 2, 3, 4, 5, DateTimeKind.Utc);
        File.SetLastWriteTimeUtc(md, stamp);

        Assert.True(_store.EnsureDefaultSourceCaches().Success);

        Assert.Equal(stamp, File.GetLastWriteTimeUtc(md)); // untouched, not re-placed
    }

    [Fact]
    public void EnsureDefaultSourceCaches_whenHalfThePairIsMissing_replacesBothFiles()
    {
        // A lone .md without its .minisig is as FATAL to the proxy as no cache at all, so an
        // incomplete pair is restored to the consistent bundled copy.
        Directory.CreateDirectory(_temp);
        File.WriteAllText(Path.Combine(_temp, "public-resolvers.md"), "orphaned-md-without-signature\n");

        Assert.True(_store.EnsureDefaultSourceCaches().Success);

        Assert.True(File.Exists(Path.Combine(_temp, "public-resolvers.md.minisig")));
        Assert.DoesNotContain("orphaned-md-without-signature",
            File.ReadAllText(Path.Combine(_temp, "public-resolvers.md")), StringComparison.Ordinal);
        Assert.Contains("# public-resolvers", File.ReadAllText(Path.Combine(_temp, "public-resolvers.md")), StringComparison.Ordinal);
    }

    [Fact]
    public void EnsureDefaultSourceCaches_whenPairIsPresentButCorrupt_restoresTheBundledCopy()
    {
        // A complete-but-INVALID pair (truncated/torn .md, mismatched .minisig) is behaviorally
        // identical to no cache for the proxy — a mere existence check would preserve it forever
        // (a recurring brick with no self-heal), so the health check is signature verification.
        Assert.True(_store.EnsureDefaultSourceCaches().Success);
        var md = Path.Combine(_temp, "public-resolvers.md");
        File.WriteAllText(md, "truncated garbage that no longer matches the signature\n");

        Assert.True(_store.EnsureDefaultSourceCaches().Success);

        Assert.Contains("# public-resolvers", File.ReadAllText(md), StringComparison.Ordinal); // restored
    }

    [Fact]
    public void WriteRuleFile_writesToFixedName()
    {
        Assert.True(_store.WriteRuleFile(RuleFileKind.BlockedNames, "ads.example\n").Success);
        Assert.Equal("ads.example\n", File.ReadAllText(_paths.RuleFilePath(RuleFileKind.BlockedNames)));
    }

    // ---- E1(c): real-filesystem WriteRuleFile — backup / atomic replace / SafePath / rollback ----
    //
    // IC-15c: the rule-file WRITE path must be exercised on a real disk, never validated through the
    // in-memory FakeConfigStore alone (the 5c bug-#2 faked-seam trap). These pin the same
    // transactional guarantees the config write has, but for the .txt write the Filtering tab rides.

    [Fact]
    public void WriteRuleFile_overExisting_backsUpThePrevious_andReplacesAtomically()
    {
        var path = _paths.RuleFilePath(RuleFileKind.BlockedNames);

        Assert.True(_store.WriteRuleFile(RuleFileKind.BlockedNames, "old.example\n").Success);
        Assert.True(_store.WriteRuleFile(RuleFileKind.BlockedNames, "new.example\n").Success);

        // The atomic replace committed the new content...
        Assert.Equal("new.example\n", File.ReadAllText(path));
        // ...and the prior content was backed up (never lost), exactly like the config path.
        var backups = Directory.GetFiles(_paths.BackupsDir);
        Assert.NotEmpty(backups);
        Assert.Contains(backups, b => File.ReadAllText(b) == "old.example\n");
        // No .tmp file is left behind after a successful commit.
        Assert.False(File.Exists(path + ".tmp"));
    }

    [Fact]
    public void WriteRuleFile_firstWrite_whenNoPreviousFile_makesNoBackup()
    {
        // The very first write has nothing to back up (File.Move path, not File.Replace).
        Assert.True(_store.WriteRuleFile(RuleFileKind.Cloaking, "example.com 10.0.0.1\n").Success);

        Assert.Equal("example.com 10.0.0.1\n", File.ReadAllText(_paths.RuleFilePath(RuleFileKind.Cloaking)));
        // BackupsDir is created but holds nothing for a first-write.
        var backups = Directory.Exists(_paths.BackupsDir) ? Directory.GetFiles(_paths.BackupsDir) : Array.Empty<string>();
        Assert.Empty(backups);
    }

    [Fact]
    public void WriteRuleFile_confinesEveryKindToTheBaseDir_noTraversal()
    {
        // SafePath confinement: every closed-enum kind resolves to a fixed leaf DIRECTLY under BaseDir
        // (never a subdirectory, never an escape). This proves the kind→name map can't smuggle a path
        // component — the CWE-22-by-construction guarantee, verified against the real resolved paths.
        foreach (RuleFileKind kind in Enum.GetValues<RuleFileKind>())
        {
            var resolved = Path.GetFullPath(_paths.RuleFilePath(kind));
            var parent = Path.GetDirectoryName(resolved);
            Assert.Equal(Path.GetFullPath(_temp), parent); // leaf sits exactly in BaseDir
            Assert.StartsWith(Path.GetFullPath(_temp) + Path.DirectorySeparatorChar, resolved, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void WriteRuleFile_whenCommitFails_rollsBackToThePreviousContent()
    {
        var path = _paths.RuleFilePath(RuleFileKind.BlockedIps);
        Assert.True(_store.WriteRuleFile(RuleFileKind.BlockedIps, "10.0.0.0/8\n").Success);

        // Force the atomic replace to fail by making the committed target read-only, then confirm the
        // rollback restored the previous content (CWE-367: a failed write never corrupts the live file).
        File.SetAttributes(path, FileAttributes.ReadOnly);
        try
        {
            var result = _store.WriteRuleFile(RuleFileKind.BlockedIps, "192.168.0.0/16\n");
            Assert.False(result.Success);
            Assert.Equal(PlatformErrorKind.OperationFailed, result.Error);
        }
        finally
        {
            File.SetAttributes(path, FileAttributes.Normal);
        }

        Assert.Equal("10.0.0.0/8\n", File.ReadAllText(path)); // unchanged — rolled back
        Assert.False(File.Exists(path + ".tmp")); // the temp was cleaned up by RollBack
    }

    [Fact]
    public void WriteRuleFile_null_content_throwsArgumentNull()
    {
        // IC-3: the store guards its own argument (a null body is a caller bug, never a partial write).
        Assert.Throws<ArgumentNullException>(() => _store.WriteRuleFile(RuleFileKind.AllowedNames, null!));
    }

    [Fact]
    public void WriteConfig_whenTempCommitFails_rollsBackToPrevious()
    {
        _store.WriteConfig("good = 1\n");
        // Make the target read-only to force the atomic replace to fail, exercising rollback.
        File.SetAttributes(_paths.ConfigFile, FileAttributes.ReadOnly);
        try
        {
            var result = _store.WriteConfig("attempted = 2\n");
            Assert.False(result.Success);
            Assert.Equal(PlatformErrorKind.OperationFailed, result.Error);
        }
        finally
        {
            File.SetAttributes(_paths.ConfigFile, FileAttributes.Normal);
        }
        Assert.Equal("good = 1\n", File.ReadAllText(_paths.ConfigFile)); // unchanged
    }

    [Fact]
    public void RuleFilePath_hasMappingForEveryKind()
    {
        foreach (RuleFileKind kind in System.Enum.GetValues<RuleFileKind>())
        {
            var path = _paths.RuleFilePath(kind); // must not throw for any defined member
            Assert.False(string.IsNullOrWhiteSpace(path));
        }
    }

    // ---- B2: compare-and-swap write (BE-6 optimistic concurrency, IC-9/IC-10) ----

    /// <summary>Lowercase hex SHA-256 of a text's UTF-8 bytes (the IC-9 shape).</summary>
    private static string Sha256HexOf(string text) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();

    /// <summary>Lowercase hex SHA-256 of the exact current on-disk file BYTES (IC-9:
    /// the base sha is always over raw bytes, never a re-encoded string).</summary>
    private static string Sha256HexOfFile(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();

    [Fact]
    public void WriteConfigIfBaseMatches_whenShaMatches_writes_andBacksUpPrevious()
    {
        Assert.True(_store.WriteConfig("first = 1\n").Success);
        var baseSha = Sha256HexOfFile(_paths.ConfigFile);

        var result = _store.WriteConfigIfBaseMatches("second = 2\n", baseSha);

        Assert.True(result.Success);
        Assert.Equal("second = 2\n", File.ReadAllText(_paths.ConfigFile));
        Assert.Contains(Directory.GetFiles(_paths.BackupsDir), b => File.ReadAllText(b) == "first = 1\n");
    }

    [Fact]
    public void WriteConfigIfBaseMatches_whenShaMismatches_returnsConflict_andFileUntouched()
    {
        Assert.True(_store.WriteConfig("first = 1\n").Success);
        var staleSha = Sha256HexOf("some other bytes entirely\n");

        var result = _store.WriteConfigIfBaseMatches("second = 2\n", staleSha);

        Assert.False(result.Success);
        Assert.Equal(PlatformErrorKind.Conflict, result.Error);
        // IC-10: the UI shows this verbatim — pin the exact human-actionable message.
        Assert.Equal("config file changed on disk since it was loaded — reload before saving", result.Message);
        Assert.Equal("first = 1\n", File.ReadAllText(_paths.ConfigFile)); // untouched
        Assert.Empty(Directory.GetFiles(_paths.BackupsDir)); // reject path never reached the write machinery
    }

    [Fact]
    public void WriteConfigIfBaseMatches_whenFileAbsent_returnsConflict_namingTheMissingFile()
    {
        var result = _store.WriteConfigIfBaseMatches("a = 1\n", Sha256HexOf("anything\n"));

        Assert.False(result.Success);
        Assert.Equal(PlatformErrorKind.Conflict, result.Error);
        Assert.Contains("missing", result.Message, StringComparison.Ordinal);
        Assert.Contains("dnscrypt-proxy.toml", result.Message, StringComparison.Ordinal); // names the file
        Assert.False(File.Exists(_paths.ConfigFile)); // nothing was created
    }

    public static TheoryData<string> MalformedShas => new()
    {
        "",                        // empty
        "abc",                     // far too short
        new string('a', 63),       // one char short
        new string('a', 65),       // one char long
        new string('a', 63) + "g", // 64 chars but not hex
    };

    [Theory]
    [MemberData(nameof(MalformedShas))]
    public void WriteConfigIfBaseMatches_withMalformedSha_returnsInvalidArgument_andFileUntouched(string badSha)
    {
        Assert.True(_store.WriteConfig("first = 1\n").Success);

        var result = _store.WriteConfigIfBaseMatches("second = 2\n", badSha);

        Assert.False(result.Success);
        Assert.Equal(PlatformErrorKind.InvalidArgument, result.Error); // a caller bug, NOT a Conflict
        Assert.Equal("first = 1\n", File.ReadAllText(_paths.ConfigFile)); // untouched
        Assert.Empty(Directory.GetFiles(_paths.BackupsDir));
    }

    [Fact]
    public void WriteConfigIfBaseMatches_withUppercaseSha_stillMatches()
    {
        Assert.True(_store.WriteConfig("first = 1\n").Success);
        var upperSha = Sha256HexOfFile(_paths.ConfigFile).ToUpperInvariant();

        var result = _store.WriteConfigIfBaseMatches("second = 2\n", upperSha);

        Assert.True(result.Success); // caller hex casing is normalized, never a false Conflict
        Assert.Equal("second = 2\n", File.ReadAllText(_paths.ConfigFile));
    }
}
