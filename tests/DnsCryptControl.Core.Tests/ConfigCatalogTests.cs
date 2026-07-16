using DnsCryptControl.Core.Schema;
using Xunit;

namespace DnsCryptControl.Core.Tests;

public class ConfigCatalogTests
{
    [Fact]
    public void All_isComprehensive()
    {
        // The spec's Appendix A enumerates ~90 keys. Guard against accidental shrinkage.
        Assert.True(ConfigCatalog.All.Count >= 80, $"catalog too small: {ConfigCatalog.All.Count}");
    }

    [Theory]
    [InlineData("listen_addresses", SettingValueType.StringArray)]
    [InlineData("max_clients", SettingValueType.Long)]
    [InlineData("require_nolog", SettingValueType.Bool)]
    [InlineData("timeout_load_reduction", SettingValueType.Float)]
    [InlineData("query_log.format", SettingValueType.String)]
    [InlineData("anonymized_dns.skip_incompatible", SettingValueType.Bool)]
    public void Find_knownKey_hasExpectedType(string key, SettingValueType type)
    {
        var d = ConfigCatalog.Find(key);
        Assert.NotNull(d);
        Assert.Equal(type, d!.Type);
        Assert.False(string.IsNullOrWhiteSpace(d.Doc));
    }

    [Fact]
    public void Find_isCaseSensitiveAndExact()
    {
        Assert.Null(ConfigCatalog.Find("Max_Clients"));
        Assert.Null(ConfigCatalog.Find("nope"));
    }

    [Fact]
    public void DeprecatedKey_isFlaggedWithReplacement()
    {
        var d = ConfigCatalog.Find("fallback_resolvers");
        Assert.NotNull(d);
        Assert.True(d!.Deprecated);
        Assert.Equal("bootstrap_resolvers", d.ReplacedBy);
    }

    [Fact]
    public void Sections_includeAllMajorTables()
    {
        foreach (var s in new[] { "query_log", "sources", "anonymized_dns", "monitoring_ui", "blocked_names" })
            Assert.Contains(s, ConfigCatalog.Sections);
    }

    // ---- A4: curated display groups (the Configuration tab's section nav derives from these) ----

    private static readonly string[] _curatedGroups =
    {
        "General",
        "Server selection",
        "Connection",
        "Connectivity",
        "Logging",
        "Certificates & TLS",
        "Filters & rules",
        "Cache",
        "Local DoH",
        "Anonymized DNS",
        "Monitoring",
        "Sources",
        "Schedules",
        "Static servers",
    };

    [Fact]
    public void EveryDescriptor_hasNonEmptyGroup()
    {
        Assert.All(ConfigCatalog.All, d =>
            Assert.False(string.IsNullOrWhiteSpace(d.Group), $"{d.KeyPath} has no Group"));
    }

    [Fact]
    public void GroupSet_matchesTheCuratedNavList()
    {
        var actual = ConfigCatalog.All.Select(d => d.Group).Distinct(StringComparer.Ordinal).ToArray();
        Assert.Equal(
            _curatedGroups.OrderBy(g => g, StringComparer.Ordinal).ToArray(),
            actual.OrderBy(g => g, StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public void GroupCount_isMockupScaled_notACatchAllBucket()
    {
        var count = ConfigCatalog.All.Select(d => d.Group).Distinct(StringComparer.Ordinal).Count();
        Assert.InRange(count, 10, 14);
    }

    // ---- 5g-6: plain-language Friendly second line (WP3 seeds only local_doh.*) ----

    [Theory]
    [InlineData("local_doh.listen_addresses")]
    [InlineData("local_doh.path")]
    [InlineData("local_doh.cert_file")]
    [InlineData("local_doh.cert_key_file")]
    public void LocalDohDescriptor_hasNonEmptyFriendly(string key)
    {
        var d = ConfigCatalog.Find(key);
        Assert.NotNull(d);
        Assert.False(string.IsNullOrWhiteSpace(d!.Friendly), $"{key} has no Friendly text");
    }

    /// <summary>5g WP4: EVERY catalog entry carries a plain-language Friendly line.
    /// This hard-locks the rule — any future descriptor added without one fails here.</summary>
    [Fact]
    public void EveryDescriptor_hasNonEmptyFriendly()
    {
        Assert.All(ConfigCatalog.All, d =>
            Assert.False(string.IsNullOrWhiteSpace(d.Friendly), $"{d.KeyPath} has no Friendly text"));
    }

    [Fact]
    public void SettingDescriptor_friendlyIsOptional_andOldCallShapesAreUnaffected()
    {
        // The pre-5g positional-6 construction shape still works: Friendly defaults to
        // null and record equality between two such instances is unchanged.
        var a = new SettingDescriptor("k", string.Empty, SettingValueType.Bool, "false", "doc", "General");
        var b = new SettingDescriptor("k", string.Empty, SettingValueType.Bool, "false", "doc", "General");
        Assert.Null(a.Friendly);
        Assert.Equal(a, b);

        // Friendly round-trips and participates in record equality.
        var c = a with { Friendly = "plain words" };
        Assert.Equal("plain words", c.Friendly);
        Assert.NotEqual(a, c);
        Assert.Equal(c, c with { });
    }

    [Theory]
    [InlineData("listen_addresses", "General")]
    [InlineData("require_dnssec", "Server selection")]
    [InlineData("force_tcp", "Connection")]
    [InlineData("lb_strategy", "Connection")]
    [InlineData("netprobe_timeout", "Connectivity")]
    [InlineData("bootstrap_resolvers", "Connectivity")]
    [InlineData("log_level", "Logging")]
    [InlineData("query_log.format", "Logging")]
    [InlineData("tls_cipher_suite", "Certificates & TLS")]
    [InlineData("block_ipv6", "Filters & rules")]
    [InlineData("blocked_names.blocked_names_file", "Filters & rules")]
    [InlineData("cloaking_rules", "Filters & rules")]
    [InlineData("cache_size", "Cache")]
    [InlineData("local_doh.path", "Local DoH")]
    [InlineData("anonymized_dns.routes", "Anonymized DNS")]
    [InlineData("monitoring_ui.enabled", "Monitoring")]
    [InlineData("sources.urls", "Sources")]
    [InlineData("schedules", "Schedules")]
    [InlineData("static", "Static servers")]
    [InlineData("fallback_resolvers", "Connectivity")]
    [InlineData("cache_neg_ttl", "Cache")]
    public void KnownKey_mapsToItsCuratedGroup(string key, string group)
    {
        var d = ConfigCatalog.Find(key);
        Assert.NotNull(d);
        Assert.Equal(group, d!.Group);
    }
}
