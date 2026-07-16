using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using DnsCryptControl.Core.Sources;
using DnsCryptControl.Service.Supplychain;
using DnsCryptControl.Service.Windows;
using Xunit;

namespace DnsCryptControl.Service.Tests;

/// <summary>
/// Drift locks between the SHIPPED packaging config (tools/packaging/assets/dnscrypt-proxy.toml)
/// and the constants the helper seeds/verifies with. The proxy verifies the seeded cache against
/// the toml's minisign_key at load — if a maintainer rotates the embedded assets + the pinned
/// constant but forgets the toml (or renames cache_file away from the seeded filenames), every
/// test stays green while a fresh install re-creates the exact FATAL-at-first-protect DNS brick
/// the seed exists to fix. These tests read the shipped toml from the repo and pin the couplings.
/// </summary>
public class ShippedConfigDriftLockTests
{
    [Fact]
    public void shipped_toml_minisign_key_equals_the_pinned_resolver_list_key()
    {
        var toml = ReadShippedToml();
        var m = Regex.Match(toml, @"minisign_key\s*=\s*'([^']+)'");
        Assert.True(m.Success, "shipped toml has no minisign_key");
        Assert.Equal(ResolverListSignature.PinnedResolverListKeyBase64, m.Groups[1].Value);
    }

    [Fact]
    public void shipped_toml_cache_file_matches_the_seeded_asset_name()
    {
        var toml = ReadShippedToml();
        Assert.Contains("[sources.'public-resolvers']", toml, StringComparison.Ordinal);
        var m = Regex.Match(toml, @"cache_file\s*=\s*'([^']+)'");
        Assert.True(m.Success, "shipped toml has no cache_file");
        // Must equal the filename EnsureDefaultSourceCaches places (and the embedded LogicalName).
        Assert.Equal("public-resolvers.md", m.Groups[1].Value);
    }

    [Fact]
    public void shipped_toml_seeds_the_dnscrypt_relays_source_with_the_pinned_key()
    {
        var toml = ReadShippedToml();
        // The DNSCrypt anonymization relays are a SEPARATE list from public-resolvers.md; without this
        // source the Anonymized DNS relay picker is empty and anonymized DNSCrypt cannot work. It must
        // cache to the seeded filename (or the proxy boot-downloads it — FATAL off-53) and pin the same
        // resolver-list key the embedded relays.md is signed with.
        Assert.Contains("[sources.'relays']", toml, StringComparison.Ordinal);
        Assert.Contains("cache_file = 'relays.md'", toml, StringComparison.Ordinal);
        // EVERY source's minisign_key must be the pinned key (public-resolvers AND relays).
        var keys = Regex.Matches(toml, @"minisign_key\s*=\s*'([^']+)'");
        Assert.True(keys.Count >= 2, "expected minisign_key on both the public-resolvers and relays sources");
        foreach (Match k in keys)
            Assert.Equal(ResolverListSignature.PinnedResolverListKeyBase64, k.Groups[1].Value);
    }

    [Fact]
    public void every_shipped_default_server_exists_in_the_seeded_list()
    {
        var toml = ReadShippedToml();
        var m = Regex.Match(toml, @"server_names\s*=\s*\[([^\]]*)\]");
        Assert.True(m.Success, "shipped toml has no server_names");
        var names = Regex.Matches(m.Groups[1].Value, @"'([^']+)'");
        Assert.True(names.Count > 0, "shipped server_names is empty");

        using var stream = typeof(FileSystemConfigStore).Assembly.GetManifestResourceStream("public-resolvers.md");
        Assert.NotNull(stream);
        using var reader = new StreamReader(stream!, Encoding.UTF8);
        var parsed = ResolverListParser.Parse(reader.ReadToEnd(), prefix: "");
        Assert.False(parsed.WholeFileInvalid);

        foreach (Match name in names)
        {
            Assert.Contains(parsed.Entries, e => e.Name == name.Groups[1].Value);
        }
    }

    /// <summary>Walks up from the test bin dir to the repo root (the directory holding the .sln)
    /// and reads the shipped packaging toml. Skips nothing: the repo layout is part of the CI
    /// checkout, so a missing file is a genuine failure, not an environment quirk.</summary>
    private static string ReadShippedToml()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "DnsCryptControl.sln")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        var path = Path.Combine(dir!.FullName, "tools", "packaging", "assets", "dnscrypt-proxy.toml");
        Assert.True(File.Exists(path), $"shipped toml not found at {path}");
        return File.ReadAllText(path);
    }
}
