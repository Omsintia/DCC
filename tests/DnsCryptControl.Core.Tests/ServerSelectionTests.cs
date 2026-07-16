using DnsCryptControl.Core.Sources;
using DnsCryptControl.Core.Stamps;
using DnsCryptControl.Core.Toml;
using Xunit;

namespace DnsCryptControl.Core.Tests;

/// <summary>
/// A5: <see cref="ServerSelection"/> — the proxy-faithful pool evaluator. Each test pins one
/// row of the verbatim 2.1.16 registration behaviour (family algorithm incl. both-off/DoH-dual/
/// empty-addr-IPv4, manual bypasses only require_*, disabled wins, relays exempt-but-family-filtered,
/// unsupported protocols, dedup, zero-pool).
/// </summary>
public class ServerSelectionTests
{
    // stamps chosen for their protocol + family + props
    private const string DohCloudflare = "sdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5";       // DoH, IPv4, props 7
    private const string DohGoogle = "sdns://AgUAAAAAAAAABzguOC44LjggsKKKE4EwvtIbNjGjagI2607EdKSVHowYZtyvD9iPrkkHOC44LjguOAovZG5zLXF1ZXJ5"; // DoH, IPv4, props 5 (no NoLog)
    private const string DohCloudflareV6 = "sdns://AgcAAAAAAAAAFlsyNjA2OjQ3MDA6NDcwMDo6MTExMV0AGlsyNjA2OjQ3MDA6NDcwMDo6MTExMV06NDQzCi9kbnMtcXVlcnk"; // DoH, IPv6 addr
    private const string DnsCryptQuad9 = "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0"; // DNSCrypt, IPv4
    private const string OdohTarget = "sdns://BQcAAAAAAAAAF29kb2guY2xvdWRmbGFyZS1kbnMuY29tCi9kbnMtcXVlcnk";            // ODoH target, no addr (classifies IPv4)
    private const string DotQuad9 = "sdns://AwcAAAAAAAAABzkuOS45LjkADWRucy5xdWFkOS5uZXQ";                              // DoT — unsupported upstream
    private const string RelayV4 = "sdns://gQ8xNDYuNzAuODIuMzo0NDM";                                                   // relay, IPv4
    private const string RelayV6 = "sdns://gR9bMjYwNDo5YTAwOjIwMTA6YTBiYjo2Ojo1M106NDQz";                             // relay, IPv6

    private static ResolverListEntry Entry(string name, params string[] stampStrings)
    {
        var stamps = new List<ServerStamp>();
        foreach (var s in stampStrings)
        {
            Assert.True(ServerStampParser.TryParse(s, out var stamp, out var err), err.ToString());
            stamps.Add(stamp!);
        }
        return new ResolverListEntry(name, name, "", stampStrings, stamps,
            Array.Empty<StampParseError>(), IsSelectable: true, Array.Empty<string>());
    }

    private static ServerSelectionConfig Config(
        string[]? serverNames = null, string[]? disabled = null,
        bool ipv4 = true, bool ipv6 = false, bool dnscrypt = true, bool doh = true, bool odoh = false,
        bool reqDnssec = false, bool reqNolog = false, bool reqNofilter = false)
        => new(serverNames ?? Array.Empty<string>(), disabled ?? Array.Empty<string>(),
            ipv4, ipv6, dnscrypt, doh, odoh, reqDnssec, reqNolog, reqNofilter);

    private static SelectionVerdict Verdict(ResolverListEntry entry, ServerSelectionConfig config)
        => ServerSelection.Evaluate(new[] { entry }, config).Evaluations[0].Verdict;

    [Fact]
    public void Automatic_defaults_includesDohAndDnsCrypt_excludesOdohByProtocol_dotUnsupported()
    {
        var config = Config();
        Assert.Equal(SelectionVerdict.Included, Verdict(Entry("cf", DohCloudflare), config));
        Assert.Equal(SelectionVerdict.Included, Verdict(Entry("q9", DnsCryptQuad9), config));
        Assert.Equal(SelectionVerdict.ExcludedByProtocolToggle, Verdict(Entry("odoh", OdohTarget), config)); // odoh off
        Assert.Equal(SelectionVerdict.UnsupportedProtocol, Verdict(Entry("dot", DotQuad9), config));
    }

    [Fact]
    public void Automatic_requireNolog_excludesServerWithoutTheProp()
    {
        var config = Config(reqNolog: true);
        Assert.Equal(SelectionVerdict.Included, Verdict(Entry("cf", DohCloudflare), config));        // props 7 has NoLog
        Assert.Equal(SelectionVerdict.ExcludedByRequiredProps, Verdict(Entry("g", DohGoogle), config)); // props 5 lacks NoLog
    }

    [Fact]
    public void Manual_bypassesRequireStar_butNotServerNames()
    {
        // require_nolog would exclude google in automatic; manual pinning it bypasses require_*.
        var config = Config(serverNames: new[] { "g" }, reqNolog: true);
        Assert.Equal(SelectionVerdict.Included, Verdict(Entry("g", DohGoogle), config));
        Assert.Equal(SelectionVerdict.ExcludedByServerNames, Verdict(Entry("cf", DohCloudflare), config));
    }

    [Fact]
    public void Disabled_winsOverManualPick()
    {
        var config = Config(serverNames: new[] { "cf" }, disabled: new[] { "cf" });
        Assert.Equal(SelectionVerdict.ExcludedByDisabled, Verdict(Entry("cf", DohCloudflare), config));
    }

    [Fact]
    public void FamilyFilter_bothTogglesFalse_isSkipped()
    {
        var config = Config(ipv4: false, ipv6: false);
        // an IPv6 DoH server is not family-excluded when both toggles are off
        Assert.Equal(SelectionVerdict.Included, Verdict(Entry("cf6", DohCloudflareV6), config));
    }

    [Fact]
    public void FamilyFilter_dohIsDualFamily_keptUnderIpv6Only()
    {
        // DoH with an IPv4 addr survives ipv4=false, ipv6=true (dual-family) — the non-obvious case.
        var config = Config(ipv4: false, ipv6: true);
        Assert.Equal(SelectionVerdict.Included, Verdict(Entry("cf", DohCloudflare), config));
    }

    [Fact]
    public void FamilyFilter_emptyAddrOdoh_classifiesIpv4_droppedUnderIpv6Only()
    {
        // ODoH target has no addr => classifies IPv4 => excluded when ipv4=false. odoh enabled so
        // the family reason (checked before the protocol toggle) is what surfaces.
        var config = Config(ipv4: false, ipv6: true, odoh: true);
        Assert.Equal(SelectionVerdict.ExcludedByFamilyToggle, Verdict(Entry("odoh", OdohTarget), config));
    }

    [Fact]
    public void Relay_isExemptFromProtocolAndServerNames_butFamilyFiltered()
    {
        // manual mode with an unrelated pin: the relay is still included (exempt from server_names).
        var manual = Config(serverNames: new[] { "cf" });
        var relay = ServerSelection.Evaluate(new[] { Entry("anon", RelayV4) }, manual).Evaluations[0];
        Assert.True(relay.IsRelay);
        Assert.Equal(SelectionVerdict.Included, relay.Verdict);

        // an IPv6 relay is dropped under ipv6=false.
        Assert.Equal(SelectionVerdict.ExcludedByFamilyToggle, Verdict(Entry("anon6", RelayV6), Config(ipv4: true, ipv6: false)));
    }

    [Fact]
    public void MixedProtocolEntry_isNondeterministic()
    {
        Assert.Equal(SelectionVerdict.Nondeterministic, Verdict(Entry("mixed", DohCloudflare, RelayV4), Config()));
    }

    [Fact]
    public void Pool_countsUniqueIncludedServers_notRelays()
    {
        var config = Config();
        var result = ServerSelection.Evaluate(new[]
        {
            Entry("cf", DohCloudflare),
            Entry("q9", DnsCryptQuad9),
            Entry("anon", RelayV4),   // relay — not counted
        }, config);
        Assert.Equal(2, result.Pool.EffectiveCount);
        Assert.False(result.Pool.IsZeroPool);
    }

    [Fact]
    public void Pool_dedupsByName()
    {
        var config = Config();
        var result = ServerSelection.Evaluate(new[]
        {
            Entry("cf", DohCloudflare),
            Entry("cf", DohGoogle),   // same name, later stamp — counts once
        }, config);
        Assert.Equal(1, result.Pool.EffectiveCount);
    }

    [Fact]
    public void Pool_dedupLastWins_falseSafeZeroPool_isCaught()
    {
        // Core review IMPORTANT: two entries named 'dup' — first v4 (Included), last v6 (family-excluded
        // under default ipv4-only). The proxy's LAST stamp wins, so the real pool is 0 (proxy won't
        // start). Counting any-included-with-that-name would falsely report a live pool of 1.
        var config = Config(); // ipv4 true, ipv6 false
        var result = ServerSelection.Evaluate(new[]
        {
            Entry("dup", DohCloudflare),    // v4 -> Included
            Entry("dup", DohCloudflareV6),  // v6 -> ExcludedByFamilyToggle (authoritative, last)
        }, config);
        Assert.Equal(0, result.Pool.EffectiveCount);
        Assert.True(result.Pool.IsZeroPool);
    }

    [Fact]
    public void SameProtocolMultiStamp_differingFamily_isNondeterministic()
    {
        // Core review IMPORTANT: same proto (DoH) but one v4 + one v6 stamp -> the proxy picks one at
        // random; under ipv4-only the verdict flips, so it must be Nondeterministic, not a stable Included.
        Assert.Equal(SelectionVerdict.Nondeterministic,
            Verdict(Entry("twin", DohCloudflare, DohCloudflareV6), Config(ipv4: true, ipv6: false)));
    }

    [Fact]
    public void Pool_allPinnedMissing_isZeroPool_andReportsMissing()
    {
        var config = Config(serverNames: new[] { "no-such-server" });
        var result = ServerSelection.Evaluate(new[] { Entry("cf", DohCloudflare) }, config);
        Assert.True(result.Pool.IsZeroPool);
        Assert.Contains("no-such-server", result.Pool.MissingPinnedNames);
    }

    [Fact]
    public void Pool_requireStarWipesAutomaticPool_isZeroPool()
    {
        // require_dnssec+nolog+nofilter against a server missing NoLog leaves nothing.
        var config = Config(reqNolog: true);
        var result = ServerSelection.Evaluate(new[] { Entry("g", DohGoogle) }, config);
        Assert.True(result.Pool.IsZeroPool);
    }

    [Fact]
    public void NoUsableStamp_isReported()
    {
        var entry = new ResolverListEntry("dead", "dead", "", new[] { "sdns://bad" },
            Array.Empty<ServerStamp>(), Array.Empty<StampParseError>(), false, Array.Empty<string>());
        Assert.Equal(SelectionVerdict.NoUsableStamp, Verdict(entry, Config()));
    }

    [Fact]
    public void FromDocument_appliesStockDefaults_forAllAbsentKeys()
    {
        // the VM's stock config sets none of the toggles.
        var doc = TomlConfigDocument.Parse("# empty config\n");
        var config = ServerSelectionConfig.FromDocument(doc);
        Assert.False(config.IsManual);
        Assert.True(config.Ipv4Servers);
        Assert.False(config.Ipv6Servers);
        Assert.True(config.DnsCryptServers);
        Assert.True(config.DohServers);
        Assert.False(config.ODoHServers);
        Assert.False(config.RequireDnssec);

        // DoH IPv4 server is included under stock defaults; ODoH excluded (odoh off).
        Assert.Equal(SelectionVerdict.Included, Verdict(Entry("cf", DohCloudflare), config));
    }
}
