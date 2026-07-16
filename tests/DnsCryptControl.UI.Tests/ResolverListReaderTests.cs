using System;
using System.IO;
using System.Linq;
using DnsCryptControl.Core.Sources;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// B1: <see cref="ResolverListReader"/> — discovers sources from the config, reads the proxy's
/// cache files with share-tolerant IO, and reports a typed state per source. Fail-closed.
/// </summary>
public sealed class ResolverListReaderTests : IDisposable
{
    private const string DohCloudflare = "sdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rlr-" + Path.GetRandomFileName());

    public ResolverListReaderTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private string WriteConfig(string body)
    {
        var path = Path.Combine(_dir, "dnscrypt-proxy.toml");
        File.WriteAllText(path, body);
        return path;
    }

    private void WriteCache(string fileName, string content) => File.WriteAllText(Path.Combine(_dir, fileName), content);

    private ResolverListReader Reader(string? bundledDir = null) =>
        new(Path.Combine(_dir, "dnscrypt-proxy.toml"), _dir, bundledDir);

    private static string OneEntryList() => "## cloudflare\n\nCloudflare DNS.\n" + DohCloudflare + "\n";

    [Fact]
    public void ReadAll_readsCacheFiles_appliesPrefix_andReportsFresh()
    {
        WriteConfig(
            "[sources]\n" +
            "[sources.'public-resolvers']\n" +
            "cache_file = 'public-resolvers.md'\n" +
            "[sources.relays]\n" +
            "cache_file = 'relays.md'\n" +
            "prefix = 'anon-'\n");
        WriteCache("public-resolvers.md", OneEntryList());
        WriteCache("relays.md", "## cs-de\n\nrelay\nsdns://gQ8xNDYuNzAuODIuMzo0NDM\n");

        var snapshots = Reader().ReadAll();

        Assert.Equal(2, snapshots.Count);
        var pub = snapshots.Single(s => s.SourceName == "public-resolvers");
        Assert.Equal(ResolverListState.Fresh, pub.State);
        Assert.NotNull(pub.LastCheckedUtc);
        Assert.Equal("cloudflare", pub.Entries.Single().Name);

        var relays = snapshots.Single(s => s.SourceName == "relays");
        Assert.Equal("anon-", relays.Prefix);
        Assert.Equal("anon-cs-de", relays.Entries.Single().Name); // prefix applied
    }

    [Fact]
    public void ReadAll_missingCacheFile_andNoBundledSnapshot_isMissing()
    {
        // Pin an explicitly EMPTY bundled dir: the app now SHIPS resolver-snapshot\ next to the exe
        // (the F21 fallback), so the defaulted dir in this test's bin would legitimately serve
        // Bundled - this case is specifically "no cache AND nothing bundled".
        WriteConfig("[sources]\n[sources.'public-resolvers']\ncache_file = 'public-resolvers.md'\n");
        var emptyBundled = Path.Combine(_dir, "no-bundled");
        Directory.CreateDirectory(emptyBundled);

        var snapshot = Assert.Single(Reader(emptyBundled).ReadAll());
        Assert.Equal(ResolverListState.Missing, snapshot.State);
        Assert.Empty(snapshot.Entries);
    }

    [Fact]
    public void ReadAll_missingCacheFile_isServedByTheShippedSnapshot_byDefault()
    {
        // The inverse of the case above: with the DEFAULT bundled dir (AppContext.BaseDirectory\
        // resolver-snapshot, which ships in the build output), a missing cache falls back to the
        // bundled list instead of an empty Resolvers tab - the fresh-install experience.
        WriteConfig("[sources]\n[sources.'public-resolvers']\ncache_file = 'public-resolvers.md'\n");

        var snapshot = Assert.Single(Reader().ReadAll());
        Assert.Equal(ResolverListState.Bundled, snapshot.State);
        Assert.NotEmpty(snapshot.Entries);
        Assert.Contains(snapshot.Entries, e => e.Name == "cloudflare"); // the shipped default server
    }

    [Fact]
    public void ReadAll_bundledSnapshotUsedWhenCacheMissing()
    {
        WriteConfig("[sources]\n[sources.'public-resolvers']\ncache_file = 'public-resolvers.md'\n");
        var bundledDir = Path.Combine(_dir, "bundled");
        Directory.CreateDirectory(bundledDir);
        File.WriteAllText(Path.Combine(bundledDir, "public-resolvers.md"), OneEntryList());

        var snapshot = Assert.Single(Reader(bundledDir).ReadAll());
        Assert.Equal(ResolverListState.Bundled, snapshot.State);
        Assert.Equal("cloudflare", snapshot.Entries.Single().Name);
    }

    [Fact]
    public void ReadAll_garbageCache_isParseFailed()
    {
        WriteConfig("[sources]\n[sources.'public-resolvers']\ncache_file = 'public-resolvers.md'\n");
        WriteCache("public-resolvers.md", "no delimiter anywhere in this file\n");

        var snapshot = Assert.Single(Reader().ReadAll());
        Assert.Equal(ResolverListState.ParseFailed, snapshot.State);
    }

    [Fact]
    public void ReadAll_readsWhileCacheIsOpenForWrite()
    {
        WriteConfig("[sources]\n[sources.'public-resolvers']\ncache_file = 'public-resolvers.md'\n");
        var cachePath = Path.Combine(_dir, "public-resolvers.md");
        File.WriteAllText(cachePath, OneEntryList());

        // Simulate the proxy holding the cache file open for a rewrite.
        using var writer = new FileStream(cachePath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);

        var snapshot = Assert.Single(Reader().ReadAll());
        Assert.Equal(ResolverListState.Fresh, snapshot.State);
        Assert.Equal("cloudflare", snapshot.Entries.Single().Name);
    }

    [Fact]
    public void ReadAll_pathTraversalCacheFile_isSkippedAsMissing()
    {
        WriteConfig("[sources]\n[sources.'evil']\ncache_file = '..\\\\..\\\\Windows\\\\hosts'\n");
        var snapshot = Assert.Single(Reader().ReadAll());
        Assert.Equal(ResolverListState.Missing, snapshot.State); // ComposeCachePath refused the path
    }

    [Fact]
    public void ReadAll_missingConfig_returnsEmpty()
    {
        Assert.Empty(Reader().ReadAll());
    }

    [Fact]
    public void ReadAll_configWithoutSources_returnsEmpty()
    {
        WriteConfig("server_names = ['cloudflare']\n");
        Assert.Empty(Reader().ReadAll());
    }

    [Fact]
    public void ReadAll_sourceWithoutCacheFile_isSkipped()
    {
        WriteConfig("[sources]\n[sources.'x']\nurls = ['https://example/x.md']\n"); // no cache_file
        Assert.Empty(Reader().ReadAll());
    }

    [Fact]
    public void ReadAll_malformedConfig_returnsEmpty()
    {
        WriteConfig("[[[not valid toml\n");
        Assert.Empty(Reader().ReadAll());
    }
}
