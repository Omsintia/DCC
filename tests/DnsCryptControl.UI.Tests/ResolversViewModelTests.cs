using System.Collections.Concurrent;
using DnsCryptControl.Core.Sources;
using DnsCryptControl.Core.Stamps;
using DnsCryptControl.Core.Toml;
using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.UI.Models;
using DnsCryptControl.UI.Services;
using DnsCryptControl.UI.Tests.Fakes;
using DnsCryptControl.UI.ViewModels;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// C1–C3: <see cref="ResolversViewModel"/> — load/browse the cached lists + A5 verdicts
/// (C1), staged writes + IC-9 Save &amp; apply (C2), consented kill-switch-aware latency
/// probe (C3). Pure-POCO tests (IC-5): no WPF types, every post-await write through the
/// injected <see cref="IUiDispatcher"/>, zero wall-clock sleeps.
/// </summary>
public class ResolversViewModelTests
{
    private static readonly string Sha = new('a', 64);
    private static readonly string Sha2 = new('b', 64);

    // ------------------------------------------------------------------ fixtures

    private sealed class SynchronousDispatcher : IUiDispatcher
    {
        public void Post(Action action) => action();
    }

    /// <summary>Queues posted actions so a test can prove a mutation happens INSIDE the post.</summary>
    private sealed class QueueingDispatcher : IUiDispatcher, IDisposable
    {
        private readonly ConcurrentQueue<Action> _pending = new();
        private readonly SemaphoreSlim _arrived = new(0);

        public void Dispose() => _arrived.Dispose();

        public void Post(Action action)
        {
            _pending.Enqueue(action);
            _arrived.Release();
        }

        public async Task WaitForQueuedPostAsync()
        {
            Assert.True(await _arrived.WaitAsync(TimeSpan.FromSeconds(10)), "timed out waiting for a queued post");
        }

        public void RunNext()
        {
            Assert.True(_pending.TryDequeue(out var action), "no queued post to run");
            action!();
        }
    }

    private sealed class FakeConfigFileService : IConfigFileService
    {
        public ConfigLoadResult NextLoad { get; set; } = ConfigLoadResult.Fail("unscripted Load");
        public int LoadCalls { get; private set; }
        public List<(string Text, string BaseSha256)> SaveCalls { get; } = new();
        public Func<string, string, CancellationToken, Task<ConfigSaveOutcome>>? SaveHandler { get; set; }

        public ConfigLoadResult Load()
        {
            LoadCalls++;
            return NextLoad;
        }

        public Task<ConfigSaveOutcome> SaveAndApplyAsync(string candidateText, string baseSha256, CancellationToken ct)
        {
            SaveCalls.Add((candidateText, baseSha256));
            return SaveHandler?.Invoke(candidateText, baseSha256, ct)
                ?? throw new NotSupportedException("SaveAndApplyAsync was not scripted for this test.");
        }
    }

    private sealed class FakeListReader : IResolverListReader
    {
        public List<ResolverListSnapshot> Snapshots { get; } = new();
        public int ReadCalls { get; private set; }

        public IReadOnlyList<ResolverListSnapshot> ReadAll()
        {
            ReadCalls++;
            return Snapshots.ToArray();
        }
    }

    private sealed class FakeUiStateStore : IUiStateStore
    {
        public UiState State { get; set; } = new();
        public List<UiState> Saves { get; } = new();

        public UiState Load() => State;

        public void Save(UiState state) => Saves.Add(state);
    }

    private sealed class FakeProber : ILatencyProber
    {
        public List<IReadOnlyList<ProbeTarget>> Invocations { get; } = new();
        public Func<IReadOnlyList<ProbeTarget>, IProgress<ProbeResult>?, CancellationToken, Task<IReadOnlyList<ProbeResult>>>? Handler { get; set; }

        public Task<IReadOnlyList<ProbeResult>> ProbeAsync(
            IReadOnlyList<ProbeTarget> targets, IProgress<ProbeResult>? progress, CancellationToken ct)
        {
            Invocations.Add(targets);
            if (Handler is not null) return Handler(targets, progress, ct);
            var results = targets.Select(t => new ProbeResult(t.Name, true, 10, null)).ToArray();
            foreach (var r in results) progress?.Report(r);
            return Task.FromResult<IReadOnlyList<ProbeResult>>(results);
        }
    }

    private sealed class FakeProbeGate : IProbeGate
    {
        public bool IsProbingAllowed { get; set; } = true;
    }

    // ---- entry/stamp builders -------------------------------------------------

    private static ServerStamp DnsCryptStamp(string ip = "1.2.3.4", int port = 443, ulong props = 7) =>
        new(StampProtocol.DnsCrypt, props, ip, port, new byte[32], "2.dnscrypt-cert.x",
            Array.Empty<byte[]>(), null, null, Array.Empty<string>(), false);

    private static ServerStamp DohStamp(string? ip = "9.9.9.9", int port = 443, ulong props = 7) =>
        new(StampProtocol.DoH, props, ip, port, null, null,
            new[] { new byte[32] }, "dns.example", "/dns-query", Array.Empty<string>(), false);

    private static ServerStamp OdohTargetStamp() =>
        new(StampProtocol.ODoHTarget, 7, null, 443, null, null,
            Array.Empty<byte[]>(), "odoh.example", "/dns-query", Array.Empty<string>(), false);

    private static ServerStamp RelayStamp(string ip = "5.6.7.8", int port = 443) =>
        new(StampProtocol.DnsCryptRelay, 0, ip, port, null, null,
            Array.Empty<byte[]>(), null, null, Array.Empty<string>(), false);

    private static ServerStamp OdohRelayStamp(string ip = "7.7.7.7") =>
        new(StampProtocol.ODoHRelay, 0, ip, 443, null, null,
            new[] { new byte[32] }, "odoh-relay.example", null, Array.Empty<string>(), false);

    /// <summary>A relay stamp carrying NO address, hostname, or provider — the "(no address)" fallback.</summary>
    private static ServerStamp BareRelayStamp() =>
        new(StampProtocol.DnsCryptRelay, 0, null, 443, null, null,
            Array.Empty<byte[]>(), null, null, Array.Empty<string>(), false);

    private static ResolverListEntry ZeroStampEntry(string name) =>
        new(name, name, "", new[] { "sdns://x" }, Array.Empty<ServerStamp>(),
            Array.Empty<StampParseError>(), false, Array.Empty<string>());

    private static ResolverListEntry Entry(
        string name, ServerStamp stamp, string description = "", bool isSelectable = true) =>
        new(name, name, description, new[] { "sdns://x" }, new[] { stamp },
            Array.Empty<StampParseError>(), isSelectable, Array.Empty<string>());

    private static ResolverListEntry MultiStampEntry(string name, params ServerStamp[] stamps) =>
        new(name, name, "", new[] { "sdns://x" }, stamps,
            Array.Empty<StampParseError>(), true, Array.Empty<string>());

    private static ResolverListSnapshot Snapshot(
        string sourceName, string prefix, IEnumerable<ResolverListEntry> entries,
        ResolverListState state = ResolverListState.Fresh, DateTimeOffset? mtime = null)
    {
        var list = entries.ToList();
        var parsed = new ResolverListParseResult(list, Array.Empty<string>(), null, false, false);
        return new ResolverListSnapshot(sourceName, prefix, state, mtime ?? DateTimeOffset.UtcNow, parsed);
    }

    private sealed record Harness(
        ResolversViewModel Vm,
        FakeConfigFileService File,
        FakeListReader Lists,
        FakeHelperClient Helper,
        FakeUiStateStore Store,
        SynchronousDispatcher Dispatcher,
        FakeProber Prober,
        FakeProbeGate Gate);

    private static Harness Build(
        string configText,
        IEnumerable<ResolverListSnapshot>? snapshots = null,
        UiState? uiState = null,
        bool killSwitchEnabled = false,
        bool statusOk = true)
    {
        var file = new FakeConfigFileService { NextLoad = ConfigLoadResult.Ok(configText, Sha) };
        var lists = new FakeListReader();
        if (snapshots is not null) lists.Snapshots.AddRange(snapshots);
        var helper = new FakeHelperClient
        {
            GetStatusHandler = _ => Task.FromResult<Result<StatusResponse>?>(
                statusOk
                    ? Result<StatusResponse>.Ok(
                        new StatusResponse(true, "r", killSwitchEnabled, false, IpcProtocol.Version, "1.0"))
                    : null),
        };
        var store = new FakeUiStateStore { State = uiState ?? new UiState() };
        var dispatcher = new SynchronousDispatcher();
        var prober = new FakeProber();
        var gate = new FakeProbeGate();
        var vm = new ResolversViewModel(file, lists, helper, store, dispatcher, prober, gate);
        return new Harness(vm, file, lists, helper, store, dispatcher, prober, gate);
    }

    private static async Task<Harness> LoadedAsync(
        string configText,
        IEnumerable<ResolverListSnapshot>? snapshots = null,
        UiState? uiState = null,
        bool killSwitchEnabled = false,
        bool statusOk = true)
    {
        var h = Build(configText, snapshots, uiState, killSwitchEnabled, statusOk);
        await h.Vm.LoadAsync(CancellationToken.None);
        return h;
    }

    private static ResolverRowViewModel Row(ResolversViewModel vm, string name) =>
        vm.Rows.Single(r => r.Name == name);

    // ------------------------------------------------------------------ C1: load + browse

    [Fact]
    public async Task load_projects_one_row_per_entry_across_sources()
    {
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[]
            {
                Entry("cloudflare", DohStamp(), "United States anycast"),
                Entry("quad9", DohStamp()),
            }),
            Snapshot("relays", "", new[] { Entry("anon-relay", RelayStamp()) }),
        };
        var h = await LoadedAsync("", snaps);

        Assert.False(h.Vm.LoadFailed);
        Assert.Equal(3, h.Vm.Rows.Count);
        Assert.Contains(h.Vm.Rows, r => r.Name == "cloudflare");
        Assert.Contains(h.Vm.Rows, r => r.Name == "anon-relay" && r.IsRelay);
        Assert.Equal(Sha, h.Vm.BaseSha256);
    }

    [Fact]
    public async Task load_failure_is_a_distinct_state()
    {
        var h = Build("");
        h.File.NextLoad = ConfigLoadResult.Fail("config not found");
        await h.Vm.LoadAsync(CancellationToken.None);

        Assert.True(h.Vm.LoadFailed);
        Assert.Equal("config not found", h.Vm.LoadError);
        Assert.Empty(h.Vm.Rows);
        Assert.Null(h.Vm.BaseSha256);
    }

    [Fact]
    public async Task load_publishes_inside_the_dispatched_post()
    {
        var file = new FakeConfigFileService { NextLoad = ConfigLoadResult.Ok("", Sha) };
        var lists = new FakeListReader();
        lists.Snapshots.Add(Snapshot("public-resolvers", "", new[] { Entry("cloudflare", DohStamp()) }));
        using var dispatcher = new QueueingDispatcher();
        var vm = new ResolversViewModel(
            file, lists, new FakeHelperClient(), new FakeUiStateStore(), dispatcher, new FakeProber(), new FakeProbeGate());

        var load = vm.LoadAsync(CancellationToken.None);
        await dispatcher.WaitForQueuedPostAsync();

        // The post is queued but not run: rows are still empty.
        Assert.Empty(vm.Rows);
        dispatcher.RunNext();
        Assert.Single(vm.Rows);
        await load;
    }

    [Fact]
    public async Task included_row_is_enabled_excluded_row_is_greyed_with_a_reason()
    {
        // Manual mode pins only cloudflare; quad9 is excluded by server_names.
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[]
            {
                Entry("cloudflare", DnsCryptStamp()),
                Entry("quad9", DnsCryptStamp()),
            }),
        };
        var h = await LoadedAsync("server_names = ['cloudflare']\n", snaps);

        Assert.True(h.Vm.IsManualMode);
        var cf = Row(h.Vm, "cloudflare");
        Assert.True(cf.IsIncluded);
        Assert.Null(cf.ExclusionReason);

        var q9 = Row(h.Vm, "quad9");
        Assert.False(q9.IsIncluded);
        Assert.Equal(SelectionVerdict.ExcludedByServerNames, q9.Verdict);
        Assert.NotNull(q9.ExclusionReason);
    }

    [Fact]
    public async Task rows_carry_property_chips_from_stamps()
    {
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[] { Entry("cloudflare", DnsCryptStamp(props: 7)) }),
        };
        var h = await LoadedAsync("", snaps);
        var cf = Row(h.Vm, "cloudflare");

        Assert.Contains("DNSCrypt", cf.Chips);
        Assert.Contains("DNSSEC", cf.Chips);
        Assert.Contains("no-log", cf.Chips);
        Assert.Contains("no-filter", cf.Chips);
    }

    [Fact]
    public async Task favorites_come_from_the_ui_state_store()
    {
        var snaps = new[] { Snapshot("public-resolvers", "", new[] { Entry("cloudflare", DohStamp()) }) };
        var h = await LoadedAsync("", snaps, new UiState { Favorites = { "cloudflare" } });

        Assert.True(Row(h.Vm, "cloudflare").IsFavorite);
    }

    [Fact]
    public async Task location_is_best_effort_with_an_unknown_bucket()
    {
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[]
            {
                Entry("germany-server", DohStamp(), "Located in Germany, no logs"),
                Entry("mystery", DohStamp(), "a resolver"),
            }),
        };
        var h = await LoadedAsync("", snaps);

        Assert.Equal("Germany", Row(h.Vm, "germany-server").Location);
        Assert.Equal("Unknown", Row(h.Vm, "mystery").Location);
    }

    [Fact]
    public async Task automatic_mode_when_server_names_absent()
    {
        var snaps = new[] { Snapshot("public-resolvers", "", new[] { Entry("cloudflare", DohStamp()) }) };
        var h = await LoadedAsync("", snaps);

        Assert.False(h.Vm.IsManualMode);
        // 5g-1: the chips are view-side LIST FILTERS now, all default OFF (= facet inactive,
        // show everything) — they no longer mirror the config's selection flags.
        Assert.False(h.Vm.FilterDnsCrypt);
        Assert.False(h.Vm.FilterDoh);
        Assert.False(h.Vm.FilterOdoh);
        Assert.False(h.Vm.FilterDnssec);
        Assert.False(h.Vm.FilterNolog);
        Assert.False(h.Vm.FilterNofilter);
        Assert.False(h.Vm.FilterIpv4);
        Assert.False(h.Vm.FilterIpv6);
        Assert.Single(h.Vm.Rows); // no facet active → every loaded row is visible
    }

    [Fact]
    public async Task source_header_shows_state_mtime_and_clamped_refresh_delay()
    {
        var mtime = DateTimeOffset.UtcNow.AddHours(-3);
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[] { Entry("cloudflare", DohStamp()) }, ResolverListState.Fresh, mtime),
        };
        // refresh_delay = 5 is below the proxy's real floor of 25 — the header shows the CLAMPED value.
        var h = await LoadedAsync(
            "[sources]\n[sources.'public-resolvers']\nurls = ['https://x']\ncache_file = 'public-resolvers.md'\nrefresh_delay = 5\n",
            snaps);

        var header = h.Vm.Sources.Single(s => s.SourceName == "public-resolvers");
        Assert.Equal(ResolverListState.Fresh, header.State);
        Assert.Equal(mtime, header.LastCheckedUtc);
        Assert.Equal(25, header.RefreshDelayHours);
    }

    [Fact]
    public async Task missing_and_bundled_source_states_render_honest_text()
    {
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", Array.Empty<ResolverListEntry>(), ResolverListState.Missing),
            Snapshot("relays", "", new[] { Entry("r", RelayStamp()) }, ResolverListState.Bundled),
        };
        var h = await LoadedAsync("", snaps);

        var missing = h.Vm.Sources.Single(s => s.SourceName == "public-resolvers");
        Assert.Equal(ResolverListState.Missing, missing.State);
        Assert.Contains("not yet downloaded", missing.StatusText, StringComparison.OrdinalIgnoreCase);

        var bundled = h.Vm.Sources.Single(s => s.SourceName == "relays");
        Assert.Contains("bundled", bundled.StatusText, StringComparison.OrdinalIgnoreCase);
    }

    // ---- pristine guards (anti-false-badge) ----

    [Fact]
    public async Task pristine_load_pinning_a_nonexistent_server_shows_the_missing_pinned_warning()
    {
        var snaps = new[] { Snapshot("public-resolvers", "", new[] { Entry("cloudflare", DnsCryptStamp()) }) };
        var h = await LoadedAsync("server_names = ['cloudflare', 'no-such-server']\n", snaps);

        Assert.Contains("no-such-server", h.Vm.MissingPinnedNames);
        Assert.DoesNotContain("cloudflare", h.Vm.MissingPinnedNames);
        // cloudflare is still live, so this is a warning, not a zero-pool outage.
        Assert.Null(h.Vm.ZeroPoolWarning);
        Assert.Equal(1, h.Vm.EffectivePoolCount);
    }

    [Fact]
    public async Task pristine_load_with_all_pinned_names_missing_is_a_zero_pool_fatal_state()
    {
        var snaps = new[] { Snapshot("public-resolvers", "", new[] { Entry("cloudflare", DnsCryptStamp()) }) };
        var h = await LoadedAsync("server_names = ['no-such-server']\n", snaps);

        Assert.NotNull(h.Vm.ZeroPoolWarning);
        Assert.Equal(0, h.Vm.EffectivePoolCount);
    }

    // ---- search ----

    [Fact]
    public async Task search_filters_the_visible_rows()
    {
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[]
            {
                Entry("cloudflare", DohStamp(), "United States"),
                Entry("quad9", DohStamp(), "Switzerland"),
            }),
        };
        var h = await LoadedAsync("", snaps);
        Assert.Equal(2, h.Vm.Rows.Count);

        h.Vm.SearchText = "quad";
        Assert.Single(h.Vm.Rows);
        Assert.Equal("quad9", h.Vm.Rows[0].Name);

        h.Vm.SearchText = "switzerland"; // matches description
        Assert.Single(h.Vm.Rows);
        Assert.Equal("quad9", h.Vm.Rows[0].Name);

        h.Vm.SearchText = "";
        Assert.Equal(2, h.Vm.Rows.Count);
    }

    // ------------------------------------------------------------------ 5g-5: all-stamps projection

    [Fact]
    public async Task stamps_projection_lists_every_stamp_with_protocol_endpoint_and_provider()
    {
        var stamps = new[]
        {
            DohStamp(ip: "9.9.9.9", port: 443),           // IP endpoint + hostname provider
            DohStamp(ip: null),                            // hostname-only: endpoint falls back to Hostname
            DnsCryptStamp(ip: "1.2.3.4", port: 8443),     // provider = DNSCrypt provider name
            DnsCryptStamp(ip: "2620:fe::fe", port: 443),  // IPv6-literal endpoint
            DohStamp(ip: "9.9.9.10"),
            DnsCryptStamp(ip: "5.5.5.5"),
            DohStamp(ip: "9.9.9.11"),
            OdohTargetStamp(),                             // hostname-only ODoH target
        };
        var snaps = new[] { Snapshot("public-resolvers", "", new[] { MultiStampEntry("multi", stamps) }) };
        var h = await LoadedAsync("", snaps);

        var row = Row(h.Vm, "multi");
        Assert.Equal(8, row.Stamps.Count);
        Assert.Equal(new StampDisplay("DoH", "9.9.9.9:443", "dns.example"), row.Stamps[0]);
        // Hostname-only: the endpoint IS the hostname, so Provider must not duplicate it.
        Assert.Equal(new StampDisplay("DoH", "dns.example", null), row.Stamps[1]);
        Assert.Equal(new StampDisplay("DNSCrypt", "1.2.3.4:8443", "2.dnscrypt-cert.x"), row.Stamps[2]);
        // IPv6 literal re-bracketed for an unambiguous host:port display.
        Assert.Equal(new StampDisplay("DNSCrypt", "[2620:fe::fe]:443", "2.dnscrypt-cert.x"), row.Stamps[3]);
        Assert.Equal(new StampDisplay("ODoH", "odoh.example", null), row.Stamps[7]);
        // IC-16: SelectedStamp stays EXACTLY stamps[0] — probe targeting + kill-switch pin to it.
        Assert.Same(stamps[0], row.SelectedStamp);
    }

    [Fact]
    public async Task stamp_with_no_address_hostname_or_provider_shows_the_no_address_fallback()
    {
        var snaps = new[] { Snapshot("relays", "", new[] { Entry("bare", BareRelayStamp()) }) };
        var h = await LoadedAsync("", snaps);

        var stamp = Assert.Single(Row(h.Vm, "bare").Stamps);
        Assert.Equal("(no address)", stamp.Endpoint);
        Assert.Equal("DNSCrypt relay", stamp.Protocol);
        Assert.Null(stamp.Provider);
    }

    // ------------------------------------------------------------------ 5g-1: chip facet filters

    [Fact]
    public async Task protocol_facet_is_an_or_within_the_checked_set()
    {
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[]
            {
                Entry("dc", DnsCryptStamp()),
                Entry("doh", DohStamp()),
                Entry("odoh", OdohTargetStamp()),
            }),
        };
        var h = await LoadedAsync("", snaps);

        h.Vm.FilterDnsCrypt = true;
        Assert.Equal(new[] { "dc" }, h.Vm.Rows.Select(r => r.Name).ToArray());

        h.Vm.FilterDoh = true; // OR within the protocol facet
        Assert.Equal(new[] { "dc", "doh" }, h.Vm.Rows.Select(r => r.Name).ToArray());

        h.Vm.FilterOdoh = true;
        Assert.Equal(3, h.Vm.Rows.Count);

        h.Vm.FilterDnsCrypt = false;
        h.Vm.FilterDoh = false;
        h.Vm.FilterOdoh = false;
        Assert.Equal(3, h.Vm.Rows.Count); // all unchecked → facet inactive → everything shows
    }

    [Fact]
    public async Task relays_match_their_protocol_family_chip()
    {
        var snaps = new[]
        {
            Snapshot("relays", "", new[]
            {
                Entry("dc-relay", RelayStamp()),
                Entry("odoh-relay", OdohRelayStamp()),
            }),
        };
        var h = await LoadedAsync("", snaps);

        h.Vm.FilterDnsCrypt = true; // DNSCrypt chip ⇒ DnsCrypt | DnsCryptRelay
        Assert.Equal(new[] { "dc-relay" }, h.Vm.Rows.Select(r => r.Name).ToArray());

        h.Vm.FilterDnsCrypt = false;
        h.Vm.FilterOdoh = true; // ODoH chip ⇒ ODoHTarget | ODoHRelay
        Assert.Equal(new[] { "odoh-relay" }, h.Vm.Rows.Select(r => r.Name).ToArray());
    }

    [Fact]
    public async Task a_property_facet_requires_every_stamp_to_declare_it()
    {
        // Multi-stamp honesty: the proxy picks one stamp at random, so NoLog is only guaranteed
        // when EVERY stamp declares it. props bit 1 = NoLog.
        var mixed = MultiStampEntry("mixed",
            DnsCryptStamp(ip: "1.2.3.4", props: 2), DnsCryptStamp(ip: "4.4.4.4", props: 0));
        var honest = MultiStampEntry("honest",
            DnsCryptStamp(ip: "6.6.6.6", props: 2), DnsCryptStamp(ip: "7.7.7.7", props: 2));
        var h = await LoadedAsync("", new[] { Snapshot("public-resolvers", "", new[] { mixed, honest }) });

        h.Vm.FilterNolog = true;

        Assert.Equal(new[] { "honest" }, h.Vm.Rows.Select(r => r.Name).ToArray());
    }

    [Fact]
    public async Task family_facets_use_the_proxy_faithful_classification()
    {
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[]
            {
                Entry("doh-v4", DohStamp(ip: "9.9.9.9")),         // DoH ⇒ dual-family
                Entry("dc-v6", DnsCryptStamp(ip: "2620:fe::fe")), // ':' literal ⇒ IPv6-only
                Entry("odoh-host", OdohTargetStamp()),            // hostname-only ⇒ IPv4 default
            }),
        };
        var h = await LoadedAsync("", snaps);

        h.Vm.FilterIpv4 = true;
        Assert.Equal(new[] { "doh-v4", "odoh-host" }, h.Vm.Rows.Select(r => r.Name).ToArray());

        h.Vm.FilterIpv4 = false;
        h.Vm.FilterIpv6 = true;
        Assert.Equal(new[] { "doh-v4", "dc-v6" }, h.Vm.Rows.Select(r => r.Name).ToArray());

        h.Vm.FilterIpv4 = true; // both checked → OR: any family match qualifies
        Assert.Equal(3, h.Vm.Rows.Count);
    }

    [Fact]
    public async Task zero_stamp_rows_are_hidden_while_any_facet_is_active()
    {
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[] { ZeroStampEntry("broken"), Entry("doh", DohStamp()) }),
        };
        var h = await LoadedAsync("", snaps);
        Assert.Equal(2, h.Vm.Rows.Count); // visible while no facet is active

        h.Vm.FilterDoh = true; // protocol facet
        Assert.Equal(new[] { "doh" }, h.Vm.Rows.Select(r => r.Name).ToArray());

        h.Vm.FilterDoh = false;
        h.Vm.FilterDnssec = true; // property facet — zero stamps can guarantee nothing
        Assert.DoesNotContain(h.Vm.Rows, r => r.Name == "broken");

        h.Vm.FilterDnssec = false;
        h.Vm.FilterIpv4 = true; // family facet
        Assert.DoesNotContain(h.Vm.Rows, r => r.Name == "broken");
    }

    [Fact]
    public async Task facets_compose_with_the_text_search()
    {
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[]
            {
                Entry("cloudflare-doh", DohStamp()),
                Entry("cloudflare-dnscrypt", DnsCryptStamp()),
                Entry("quad9-doh", DohStamp(ip: "9.9.9.10")),
            }),
        };
        var h = await LoadedAsync("", snaps);

        h.Vm.FilterDoh = true;
        h.Vm.SearchText = "cloudflare";

        Assert.Equal(new[] { "cloudflare-doh" }, h.Vm.Rows.Select(r => r.Name).ToArray());
    }

    [Fact]
    public async Task facets_and_across_categories()
    {
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[]
            {
                Entry("doh-nolog", DohStamp(props: 2)),
                Entry("doh-logging", DohStamp(ip: "9.9.9.10", props: 0)),
                Entry("dc-nolog", DnsCryptStamp(props: 2)),
            }),
        };
        var h = await LoadedAsync("", snaps);

        h.Vm.FilterDoh = true;    // protocol facet
        h.Vm.FilterNolog = true;  // property facet — AND across categories

        Assert.Equal(new[] { "doh-nolog" }, h.Vm.Rows.Select(r => r.Name).ToArray());
    }

    // ---- per-row multi-protocol chips + the any/only protocol-match mode ----

    [Fact]
    public async Task a_multi_protocol_server_shows_a_chip_for_every_protocol()
    {
        // cloudflare-style: one DNSCrypt stamp + one DoH stamp. The row must show BOTH protocol chips,
        // not just stamps[0]'s — a "DNSCrypt"-only chip on a row that also matches the DoH filter reads
        // as the filter lying (the reported confusion).
        var cf = MultiStampEntry("cloudflare", DnsCryptStamp(), DohStamp());
        var h = await LoadedAsync("", new[] { Snapshot("public-resolvers", "", new[] { cf }) });
        var row = Row(h.Vm, "cloudflare");

        Assert.Contains("DNSCrypt", row.Chips);
        Assert.Contains("DoH", row.Chips);
    }

    [Fact]
    public async Task any_mode_doh_filter_includes_a_multi_protocol_server()
    {
        var cf = MultiStampEntry("cloudflare", DnsCryptStamp(), DohStamp()); // DNSCrypt + DoH
        var dohOnly = Entry("mullvad", DohStamp(ip: "9.9.9.10"));            // DoH only
        var h = await LoadedAsync("", new[] { Snapshot("public-resolvers", "", new[] { cf, dohOnly }) });

        Assert.False(h.Vm.ProtocolFilterExclusive); // "any" is the default
        h.Vm.FilterDoh = true;

        // Both match: cloudflare SUPPORTS DoH (any stamp), mullvad is DoH.
        Assert.Equal(new[] { "cloudflare", "mullvad" }, h.Vm.Rows.Select(r => r.Name).ToArray());
    }

    [Fact]
    public async Task only_mode_doh_filter_keeps_doh_only_servers_and_hides_multi_protocol()
    {
        var cf = MultiStampEntry("cloudflare", DnsCryptStamp(), DohStamp()); // DNSCrypt + DoH
        var dohOnly = Entry("mullvad", DohStamp(ip: "9.9.9.10"));            // DoH only
        var dcOnly = Entry("scaleway", DnsCryptStamp(ip: "5.5.5.5"));        // DNSCrypt only
        var h = await LoadedAsync("", new[] { Snapshot("public-resolvers", "", new[] { cf, dohOnly, dcOnly }) });

        h.Vm.FilterDoh = true;
        h.Vm.ProtocolFilterExclusive = true; // "only" mode = every stamp must be DoH

        // Only the exclusively-DoH server survives; the DNSCrypt+DoH cloudflare is hidden.
        Assert.Equal(new[] { "mullvad" }, h.Vm.Rows.Select(r => r.Name).ToArray());
    }

    [Fact]
    public async Task only_mode_dnscrypt_keeps_a_dnscrypt_only_multi_stamp_server()
    {
        // Two DNSCrypt stamps (same proto, different IP) = still DNSCrypt-only under "only" mode.
        var dcMulti = MultiStampEntry("scaleway", DnsCryptStamp(ip: "1.1.1.1"), DnsCryptStamp(ip: "2.2.2.2"));
        var cf = MultiStampEntry("cloudflare", DnsCryptStamp(), DohStamp());
        var h = await LoadedAsync("", new[] { Snapshot("public-resolvers", "", new[] { dcMulti, cf }) });

        h.Vm.FilterDnsCrypt = true;
        h.Vm.ProtocolFilterExclusive = true;

        Assert.Equal(new[] { "scaleway" }, h.Vm.Rows.Select(r => r.Name).ToArray());
    }

    [Fact]
    public async Task only_mode_doh_hides_a_mixed_doh_plus_dot_server()
    {
        // OnlyDoh is a strict per-stamp AND, so a DoH+DoT server is NOT DoH-only and must be hidden by
        // "only" DoH (a regression computing OnlyDoh from the loose "any" flags would wrongly show it).
        var mixed = MultiStampEntry("mixed",
            DohStamp(),
            new ServerStamp(StampProtocol.DoT, 0, "2.3.4.5", 853, null, null,
                new[] { new byte[32] }, "dot.example", null, Array.Empty<string>(), false));
        var dohOnly = Entry("mullvad", DohStamp(ip: "9.9.9.10"));
        var h = await LoadedAsync("", new[] { Snapshot("public-resolvers", "", new[] { mixed, dohOnly }) });

        h.Vm.FilterDoh = true; // "any": both support DoH
        Assert.Equal(new[] { "mixed", "mullvad" }, h.Vm.Rows.Select(r => r.Name).ToArray());

        h.Vm.ProtocolFilterExclusive = true; // "only": the mixed DoH+DoT server is not DoH-only → hidden
        Assert.Equal(new[] { "mullvad" }, h.Vm.Rows.Select(r => r.Name).ToArray());
    }

    [Fact]
    public async Task filter_summary_reports_visible_and_total_counts()
    {
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[]
            {
                Entry("a", DnsCryptStamp()),
                Entry("b", DohStamp()),
                Entry("c", DohStamp(ip: "9.9.9.10")),
            }),
        };
        var h = await LoadedAsync("", snaps);

        Assert.Equal("3 listed", h.Vm.FilterSummary); // nothing filtered

        h.Vm.FilterDnsCrypt = true;                   // only 'a' matches
        Assert.Equal("showing 1 of 3", h.Vm.FilterSummary);
    }

    // ---- kind facet: servers vs relays ----

    [Fact]
    public async Task kind_facet_filters_servers_versus_relays()
    {
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[] { Entry("dc-server", DnsCryptStamp()), Entry("doh-server", DohStamp()) }),
            Snapshot("relays", "", new[] { Entry("dc-relay", RelayStamp()), Entry("odoh-relay", OdohRelayStamp()) }),
        };
        var h = await LoadedAsync("", snaps);
        Assert.Equal(4, h.Vm.Rows.Count); // neither checked -> both servers and relays

        h.Vm.FilterRelays = true;
        Assert.Equal(new[] { "dc-relay", "odoh-relay" }, h.Vm.Rows.Select(r => r.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray());
        Assert.All(h.Vm.Rows, r => Assert.True(r.IsRelay));

        h.Vm.FilterRelays = false;
        h.Vm.FilterServers = true;
        Assert.Equal(new[] { "dc-server", "doh-server" }, h.Vm.Rows.Select(r => r.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray());
        Assert.All(h.Vm.Rows, r => Assert.False(r.IsRelay));

        h.Vm.FilterRelays = true; // both checked -> OR within the kind category -> everything
        Assert.Equal(4, h.Vm.Rows.Count);
    }

    [Fact]
    public async Task kind_facet_composes_with_protocol_dnscrypt_plus_relays_is_dnscrypt_relays()
    {
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[] { Entry("dc-server", DnsCryptStamp()) }),
            Snapshot("relays", "", new[] { Entry("dc-relay", RelayStamp()), Entry("odoh-relay", OdohRelayStamp()) }),
        };
        var h = await LoadedAsync("", snaps);

        h.Vm.FilterDnsCrypt = true; // DNSCrypt family = the DNSCrypt server + the DNSCrypt relay
        h.Vm.FilterRelays = true;   // AND relays only -> just the DNSCrypt relay
        Assert.Equal(new[] { "dc-relay" }, h.Vm.Rows.Select(r => r.Name).ToArray());
    }

    // ------------------------------------------------------------------ C2: staged writes

    private static ResolverListSnapshot[] TwoServerList() => new[]
    {
        Snapshot("public-resolvers", "", new[]
        {
            Entry("cloudflare", DnsCryptStamp()),
            Entry("quad9", DnsCryptStamp()),
        }),
    };

    private static void ScriptApplied(FakeConfigFileService file, string appliedText, string newSha)
    {
        file.SaveHandler = (_, _, _) =>
        {
            file.NextLoad = ConfigLoadResult.Ok(appliedText, newSha);
            return Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));
        };
    }

    [Fact]
    public async Task use_only_this_server_stages_server_names_and_warns_of_a_single_pool()
    {
        var h = await LoadedAsync("", TwoServerList());
        h.Vm.UseOnlyThisServer(Row(h.Vm, "cloudflare"));

        Assert.True(h.Vm.IsDirty);
        Assert.NotNull(h.Vm.SingleServerWarning);
        Assert.Contains("cloudflare", h.Vm.SingleServerWarning!, StringComparison.Ordinal);
        Assert.True(h.Vm.CanSave);
    }

    [Fact]
    public async Task add_to_pool_appends_and_remove_drops()
    {
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.Vm.AddToPool(Row(h.Vm, "quad9"));
        Assert.True(h.Vm.IsDirty);
        Assert.Null(h.Vm.SingleServerWarning);

        // Removing quad9 again returns to just cloudflare.
        h.Vm.RemoveFromPool(Row(h.Vm, "quad9"));
        Assert.True(h.Vm.IsDirty); // still diverges from the empty staged? no — server_names staged = [cloudflare]
    }

    [Fact]
    public async Task pick_of_an_unselectable_row_is_refused_with_a_reason()
    {
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[]
            {
                new ResolverListEntry("bad name!", "bad name!", "", new[] { "sdns://x" },
                    new[] { DnsCryptStamp() }, Array.Empty<StampParseError>(), false, Array.Empty<string>()),
            }),
        };
        var h = await LoadedAsync("", snaps);

        h.Vm.UseOnlyThisServer(Row(h.Vm, "bad name!"));

        Assert.False(h.Vm.IsDirty);
        Assert.NotNull(h.Vm.SaveBlockedReason);
        Assert.Contains("bad name!", h.Vm.SaveBlockedReason!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task switch_to_automatic_mode_stages_an_empty_server_names()
    {
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        Assert.True(h.Vm.IsManualMode);

        h.Vm.SwitchToAutomaticMode();
        Assert.True(h.Vm.IsDirty);
    }

    [Fact]
    public async Task staged_pool_of_zero_live_servers_blocks_save()
    {
        // Pin a name that exists but then disable the only protocol so the pool goes to zero.
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        Assert.Null(h.Vm.SaveBlockedReason);

        h.Vm.ToggleFilter("dnscrypt_servers", enabled: false); // both entries are DNSCrypt → zero pool

        Assert.NotNull(h.Vm.SaveBlockedReason);
        Assert.Contains("zero live resolvers", h.Vm.SaveBlockedReason!, StringComparison.OrdinalIgnoreCase);
        Assert.False(h.Vm.CanSave);
    }

    [Fact]
    public async Task zero_pool_block_degrades_to_a_warning_when_no_snapshot_is_fresh()
    {
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[] { Entry("cloudflare", DnsCryptStamp()) }, ResolverListState.Bundled),
        };
        var h = await LoadedAsync("server_names = ['cloudflare']\n", snaps);

        h.Vm.ToggleFilter("dnscrypt_servers", enabled: false);

        // Not a hard block — the list is not fresh, so it degrades to a dedicated non-blocking warning.
        Assert.Null(h.Vm.SaveBlockedReason);
        Assert.NotNull(h.Vm.ZeroPoolStagedWarning);
        Assert.Contains("not fresh", h.Vm.ZeroPoolStagedWarning!, StringComparison.OrdinalIgnoreCase);
        Assert.True(h.Vm.CanSave);
    }

    // ---- IC-9 abort paths ----

    [Fact]
    public async Task save_aborts_when_the_fresh_load_fails()
    {
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.Vm.AddToPool(Row(h.Vm, "quad9"));

        h.File.NextLoad = ConfigLoadResult.Fail("gone");
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.NotNull(h.Vm.ConflictMessage);
        Assert.True(h.Vm.IsDirty); // staged set preserved
        Assert.Empty(h.File.SaveCalls); // nothing dispatched
    }

    [Fact]
    public async Task save_aborts_when_the_fresh_doc_has_errors()
    {
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.Vm.AddToPool(Row(h.Vm, "quad9"));

        h.File.NextLoad = ConfigLoadResult.Ok("cache = [unclosed\n", Sha);
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.NotNull(h.Vm.ConflictMessage);
        Assert.True(h.Vm.IsDirty);
        Assert.Empty(h.File.SaveCalls);
    }

    [Fact]
    public async Task save_aborts_when_a_staged_key_diverged_on_disk()
    {
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.Vm.AddToPool(Row(h.Vm, "quad9")); // browse-time server_names = ['cloudflare']

        // The file changed under us: server_names is now something else.
        h.File.NextLoad = ConfigLoadResult.Ok("server_names = ['someone-else']\n", Sha2);
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.NotNull(h.Vm.ConflictMessage);
        Assert.Contains("server_names", h.Vm.ConflictMessage!, StringComparison.Ordinal);
        Assert.True(h.Vm.IsDirty);
        Assert.Empty(h.File.SaveCalls);
    }

    [Fact]
    public async Task divergence_free_save_dispatches_the_fresh_sha_and_the_mutated_candidate()
    {
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.Vm.AddToPool(Row(h.Vm, "quad9"));

        // Fresh load returns the SAME server_names (no divergence) but a fresh sha.
        h.File.NextLoad = ConfigLoadResult.Ok("server_names = ['cloudflare']\n", Sha2);
        ScriptApplied(h.File, "server_names = ['cloudflare', 'quad9']\n", new string('c', 64));

        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Single(h.File.SaveCalls);
        Assert.Equal(Sha2, h.File.SaveCalls[0].BaseSha256); // FRESH sha, not the load-time one
        Assert.Contains("quad9", h.File.SaveCalls[0].Text, StringComparison.Ordinal);
        Assert.False(h.Vm.IsDirty); // staged ops removed on Applied
        Assert.Equal("Configuration saved and applied.", h.Vm.SaveNotice);
    }

    [Fact]
    public async Task applied_reloads_and_clears_the_staged_set()
    {
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.Vm.AddToPool(Row(h.Vm, "quad9"));
        var loadsBefore = h.File.LoadCalls;

        h.File.NextLoad = ConfigLoadResult.Ok("server_names = ['cloudflare']\n", Sha2);
        ScriptApplied(h.File, "server_names = ['cloudflare', 'quad9']\n", new string('c', 64));

        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.False(h.Vm.IsDirty);
        Assert.True(h.File.LoadCalls > loadsBefore); // reload-first happened
    }

    [Fact]
    public async Task edited_mid_flight_removes_only_the_dispatched_ops_and_stays_dirty()
    {
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.Vm.AddToPool(Row(h.Vm, "quad9")); // this op will be dispatched

        h.File.NextLoad = ConfigLoadResult.Ok("server_names = ['cloudflare']\n", Sha2);
        h.File.SaveHandler = (_, _, _) =>
        {
            // Simulate an edit landing DURING the save: stage a filter toggle mid-flight.
            h.Vm.ToggleFilter("require_dnssec", enabled: true);
            return Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));
        };

        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        // The dispatched server_names op is gone, but the mid-flight require_dnssec op remains.
        Assert.True(h.Vm.IsDirty);
        Assert.Contains("still unsaved", h.Vm.SaveNotice!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task conflict_outcome_from_the_service_shows_the_banner()
    {
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.Vm.AddToPool(Row(h.Vm, "quad9"));

        h.File.NextLoad = ConfigLoadResult.Ok("server_names = ['cloudflare']\n", Sha2);
        h.File.SaveHandler = (_, _, _) =>
            Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Conflict, "CAS lost the race"));

        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Equal("CAS lost the race", h.Vm.ConflictMessage);
        Assert.True(h.Vm.IsDirty); // nothing landed — staged set stays
    }

    [Fact]
    public async Task rejected_outcome_shows_the_helper_message_verbatim()
    {
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.Vm.AddToPool(Row(h.Vm, "quad9"));

        h.File.NextLoad = ConfigLoadResult.Ok("server_names = ['cloudflare']\n", Sha2);
        h.File.SaveHandler = (_, _, _) =>
            Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Rejected, "OPSEC guard: nope"));

        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Equal("OPSEC guard: nope", h.Vm.SaveError);
    }

    // ------------------------------------------------------------------ 5j: Add ODoH source lists

    [Fact]
    public async Task add_odoh_sources_writes_both_lists_and_enables_odoh_via_the_cas_path()
    {
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        Assert.False(h.Vm.IsDirty);
        Assert.True(h.Vm.CanAddOdohSources);

        h.File.NextLoad = ConfigLoadResult.Ok("server_names = ['cloudflare']\n", Sha2);
        h.File.SaveHandler = (_, _, _) =>
            Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));

        await h.Vm.AddOdohSourcesCommand.ExecuteAsync(null);

        Assert.Single(h.File.SaveCalls);
        var written = h.File.SaveCalls[0].Text;
        Assert.Contains("[sources.'odoh-servers']", written, StringComparison.Ordinal);
        Assert.Contains("[sources.'odoh-relays']", written, StringComparison.Ordinal);
        Assert.Contains("odoh-servers.md", written, StringComparison.Ordinal);
        Assert.Matches(@"odoh_servers\s*=\s*true", written);           // ODoH actually enabled
        Assert.Equal(Sha2, h.File.SaveCalls[0].BaseSha256);            // FRESH CAS sha, not load-time
        Assert.Equal(1, h.Helper.PlaceOdohCacheCalls);                 // signed cache placed BEFORE the sources
        Assert.Contains("bootstrap through the proxy", h.Vm.SaveNotice!, StringComparison.Ordinal);
        Assert.Contains("127.0.0.1:53", written, StringComparison.Ordinal);   // loopback bootstrap written
        Assert.Null(h.Vm.BootstrapAnchorWarning);                             // cloudflare is a plain DNSCrypt anchor
    }

    [Fact]
    public async Task add_odoh_header_comment_is_ascii_only_no_em_dash()
    {
        // The generated comment must contain no non-ASCII byte. An em-dash there is the seed of an
        // encoding-amplification bug: any tool that round-trips the config through the wrong encoding
        // re-encodes it and grows it each pass (a single char once ballooned the file to 2.26 GB).
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.File.NextLoad = ConfigLoadResult.Ok("server_names = ['cloudflare']\n", Sha2);
        h.File.SaveHandler = (_, _, _) =>
            Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));

        await h.Vm.AddOdohSourcesCommand.ExecuteAsync(null);

        var written = h.File.SaveCalls[0].Text;
        Assert.Contains("source lists - added by DnsCrypt Control", written, StringComparison.Ordinal); // ASCII '-'
        Assert.False(written.Contains('—'), "generated config must contain no em-dash (U+2014)");
    }

    [Fact]
    public async Task add_odoh_does_not_duplicate_the_header_comment_when_re_adding_a_missing_table()
    {
        // Partial state: the header comment + odoh-servers are already present (from a prior add), but
        // odoh-relays is missing. Re-adding must append ONLY the relays table, never a second copy of
        // the comment block (repeated adds otherwise accreted duplicate comments).
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        var existing =
            "server_names = ['cloudflare']\nodoh_servers = true\nbootstrap_resolvers = ['127.0.0.1:53']\n" +
            "\n# ODoH (Oblivious DoH) source lists - added by DnsCrypt Control. The dnscrypt-proxy service\n" +
            "# downloads and minisign-verifies these on its schedule; an ODoH target is only usable via an\n" +
            "# ODoH relay, so add a route in the Anonymized DNS tab after these download.\n" +
            "\n[sources.'odoh-servers']\nurls = ['x']\ncache_file = 'odoh-servers.md'\n";
        h.File.NextLoad = ConfigLoadResult.Ok(existing, Sha2);
        h.File.SaveHandler = (_, _, _) =>
            Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));

        await h.Vm.AddOdohSourcesCommand.ExecuteAsync(null);

        var written = h.File.SaveCalls[0].Text;
        var headerCount = System.Text.RegularExpressions.Regex.Matches(
            written,
            System.Text.RegularExpressions.Regex.Escape("# ODoH (Oblivious DoH) source lists")).Count;
        Assert.Equal(1, headerCount);                                          // header NOT duplicated
        Assert.Contains("[sources.'odoh-relays']", written, StringComparison.Ordinal); // missing table added
    }

    [Fact]
    public async Task add_odoh_sources_is_idempotent_only_when_both_tables_present_and_enabled()
    {
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        // Truly already set up now ALSO requires the loopback bootstrap in place (else ODoH can't start
        // behind the kill switch): BOTH active odoh tables AND odoh_servers=true AND bootstrap_resolvers
        // = ['127.0.0.1:53'] → no write, "already" notice.
        h.File.NextLoad = ConfigLoadResult.Ok(
            "server_names = ['cloudflare']\nodoh_servers = true\nbootstrap_resolvers = ['127.0.0.1:53']\n\n[sources.'odoh-servers']\nurls = ['x']\ncache_file = 'odoh-servers.md'\n\n[sources.'odoh-relays']\nurls = ['y']\ncache_file = 'odoh-relays.md'\n", Sha2);

        await h.Vm.AddOdohSourcesCommand.ExecuteAsync(null);

        Assert.Empty(h.File.SaveCalls); // nothing written to the config
        Assert.Equal(1, h.Helper.PlaceOdohCacheCalls); // but the signed cache IS (re)placed — heals a no-cache brick
        Assert.Contains("in place", h.Vm.SaveNotice!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task add_odoh_places_the_signed_cache_before_it_ever_writes_the_sources()
    {
        // The safety invariant: the bundled signed ODoH caches must be on disk BEFORE the odoh-* sources
        // are referenced, so the proxy loads them from cache instead of the boot-time download it treats
        // as FATAL (which bricks all DNS). Both steps happen on the happy path.
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.File.NextLoad = ConfigLoadResult.Ok("server_names = ['cloudflare']\n", Sha2);
        h.File.SaveHandler = (_, _, _) => Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));

        await h.Vm.AddOdohSourcesCommand.ExecuteAsync(null);

        Assert.Equal(1, h.Helper.PlaceOdohCacheCalls); // cache placed
        Assert.Single(h.File.SaveCalls);               // sources written
    }

    [Fact]
    public async Task add_odoh_writes_no_sources_when_the_cache_cannot_be_placed()
    {
        // If the helper can't place the signed cache, adding the sources would brick the proxy — so the
        // command MUST abort before any config write. This is the core "never leave DNS bricked" guard.
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.File.NextLoad = ConfigLoadResult.Ok("server_names = ['cloudflare']\n", Sha2);
        h.Helper.PlaceOdohCacheHandler = _ =>
            Task.FromResult<Result?>(Result.Fail(IpcErrorCode.OperationFailed, "bundled asset missing"));

        await h.Vm.AddOdohSourcesCommand.ExecuteAsync(null);

        Assert.Equal(1, h.Helper.PlaceOdohCacheCalls);
        Assert.Empty(h.File.SaveCalls);        // NOTHING written to the config
        Assert.NotNull(h.Vm.SaveError);        // and the failure is surfaced
    }

    [Fact]
    public async Task add_odoh_writes_no_sources_when_the_cache_place_reply_is_lost()
    {
        // A null reply (helper down / broken pipe) is UNKNOWN, never success — treat it like a failed
        // placement and never proceed to write the sources.
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.File.NextLoad = ConfigLoadResult.Ok("server_names = ['cloudflare']\n", Sha2);
        h.Helper.PlaceOdohCacheHandler = _ => Task.FromResult<Result?>(null);

        await h.Vm.AddOdohSourcesCommand.ExecuteAsync(null);

        Assert.Empty(h.File.SaveCalls);
        Assert.NotNull(h.Vm.SaveError);
    }

    [Fact]
    public async Task add_odoh_sets_the_loopback_bootstrap_so_odoh_resolves_behind_the_kill_switch()
    {
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.File.NextLoad = ConfigLoadResult.Ok("server_names = ['cloudflare']\n", Sha2);
        h.File.SaveHandler = (_, _, _) =>
            Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));

        await h.Vm.AddOdohSourcesCommand.ExecuteAsync(null);

        var written = h.File.SaveCalls[0].Text;
        Assert.Matches(@"bootstrap_resolvers\s*=", written);
        Assert.Contains("127.0.0.1:53", written, StringComparison.Ordinal); // loopback bootstrap, kill-switch-safe
        Assert.Null(h.Vm.BootstrapAnchorWarning);                           // cloudflare (DNSCrypt, unrouted) IS the anchor
    }

    [Fact]
    public async Task add_odoh_normalizes_a_remote_port53_bootstrap_to_loopback()
    {
        // A remote :53 bootstrap would BOTH strand ODoH (kill switch blocks it) AND fail the OPSEC gate.
        // Adding ODoH replaces it EXACTLY with the loopback endpoint — this doubles as a repair path.
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.File.NextLoad = ConfigLoadResult.Ok(
            "server_names = ['cloudflare']\nbootstrap_resolvers = ['9.9.9.9:53']\n", Sha2);
        h.File.SaveHandler = (_, _, _) =>
            Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));

        await h.Vm.AddOdohSourcesCommand.ExecuteAsync(null);

        var written = h.File.SaveCalls[0].Text;
        Assert.Contains("127.0.0.1:53", written, StringComparison.Ordinal);
        Assert.DoesNotContain("9.9.9.9:53", written, StringComparison.Ordinal); // remote :53 removed
    }

    [Fact]
    public async Task add_odoh_heals_a_config_that_has_sources_but_no_loopback_bootstrap()
    {
        // sources + odoh_servers=true but NO loopback bootstrap is NOT "already configured": it needs the
        // bootstrap added so ODoH actually starts behind the kill switch. The button writes (repair path).
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.File.NextLoad = ConfigLoadResult.Ok(
            "server_names = ['cloudflare']\nodoh_servers = true\n\n[sources.'odoh-servers']\nurls = ['x']\ncache_file = 'odoh-servers.md'\n\n[sources.'odoh-relays']\nurls = ['y']\ncache_file = 'odoh-relays.md'\n", Sha2);
        h.File.SaveHandler = (_, _, _) =>
            Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));

        await h.Vm.AddOdohSourcesCommand.ExecuteAsync(null);

        Assert.Single(h.File.SaveCalls); // NOT a no-op — the loopback bootstrap was added
        Assert.Contains("127.0.0.1:53", h.File.SaveCalls[0].Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task add_odoh_warns_when_there_is_no_plain_dnscrypt_anchor()
    {
        // Manual mode pinned to a DoH-only server: no plain DNSCrypt server to bootstrap the ODoH hostnames
        // through. ODoH can't start until an unrouted DNSCrypt anchor is added — so a (non-blocking) guidance
        // warning is surfaced, and (brick guard) bootstrap_resolvers is left UNTOUCHED (no anchor ⇒ don't set
        // a loopback the proxy couldn't answer).
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[]
            {
                Entry("doh-only", DohStamp()),
                Entry("quad9", DnsCryptStamp()),   // in the list, but NOT pinned in manual mode → not the anchor
            }),
        };
        var h = await LoadedAsync("server_names = ['doh-only']\n", snaps);
        h.File.NextLoad = ConfigLoadResult.Ok("server_names = ['doh-only']\n", Sha2);
        h.File.SaveHandler = (_, _, _) =>
            Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));

        await h.Vm.AddOdohSourcesCommand.ExecuteAsync(null);

        Assert.NotNull(h.Vm.BootstrapAnchorWarning);
        Assert.Contains("plain DNSCrypt", h.Vm.BootstrapAnchorWarning!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("127.0.0.1:53", h.File.SaveCalls[0].Text, StringComparison.Ordinal); // NOT set (no anchor)
    }

    [Fact]
    public async Task add_odoh_preserves_an_existing_remote_bootstrap_when_there_is_no_anchor()
    {
        // BRICK GUARD (review finding): a hostname-only DoH/DoT server can rely on a REMOTE bootstrap to
        // resolve its OWN hostname. With no plain DNSCrypt anchor, replacing that bootstrap with loopback
        // would strand it (loopback can't resolve the hostname without an anchor). So when there's no anchor,
        // LEAVE an existing bootstrap untouched — only warn.
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[]
            {
                Entry("doh-host", DohStamp()),
                Entry("quad9", DnsCryptStamp()),   // in the list, NOT pinned → not the anchor
            }),
        };
        var h = await LoadedAsync("server_names = ['doh-host']\n", snaps);
        h.File.NextLoad = ConfigLoadResult.Ok(
            "server_names = ['doh-host']\nbootstrap_resolvers = ['9.9.9.9:53']\n", Sha2);
        h.File.SaveHandler = (_, _, _) =>
            Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));

        await h.Vm.AddOdohSourcesCommand.ExecuteAsync(null);

        var written = h.File.SaveCalls[0].Text;
        Assert.Contains("9.9.9.9:53", written, StringComparison.Ordinal);         // remote bootstrap PRESERVED (no strand)
        Assert.DoesNotContain("127.0.0.1:53", written, StringComparison.Ordinal); // loopback NOT forced in
        Assert.NotNull(h.Vm.BootstrapAnchorWarning);                             // but the user IS warned
    }

    [Fact]
    public async Task add_odoh_warns_when_the_only_dnscrypt_server_is_routed_via_a_malformed_route()
    {
        // A [[anonymized_dns.routes]] block with no `via` parses as valid TOML but TryRead REJECTS it. The
        // anchor check must fail toward WARNING (unreadable routes ⇒ can't confirm an unrouted anchor), not
        // silently treat the config as route-free and falsely report an anchor.
        var snaps = new[] { Snapshot("public-resolvers", "", new[] { Entry("cloudflare", DnsCryptStamp()) }) };
        var h = await LoadedAsync("server_names = ['cloudflare']\n", snaps);
        h.File.NextLoad = ConfigLoadResult.Ok(
            "server_names = ['cloudflare']\n\n[[anonymized_dns.routes]]\nserver_name = 'cloudflare'\n", Sha2);
        h.File.SaveHandler = (_, _, _) =>
            Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));

        await h.Vm.AddOdohSourcesCommand.ExecuteAsync(null);

        Assert.NotNull(h.Vm.BootstrapAnchorWarning); // fail-toward-warning on an unreadable route
    }

    [Fact]
    public async Task add_odoh_treats_an_empty_via_route_as_an_unrouted_anchor()
    {
        // A route with `via = []` assigns no relay (dnscrypt-proxy uses the server DIRECTLY), so the server
        // is still a plain anchor — it must NOT trigger the "no anchor" warning (false positive).
        var snaps = new[] { Snapshot("public-resolvers", "", new[] { Entry("cloudflare", DnsCryptStamp()) }) };
        var h = await LoadedAsync("server_names = ['cloudflare']\n", snaps);
        h.File.NextLoad = ConfigLoadResult.Ok(
            "server_names = ['cloudflare']\n\n[[anonymized_dns.routes]]\nserver_name = 'cloudflare'\nvia = []\n", Sha2);
        h.File.SaveHandler = (_, _, _) =>
            Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));

        await h.Vm.AddOdohSourcesCommand.ExecuteAsync(null);

        Assert.Null(h.Vm.BootstrapAnchorWarning); // empty-via cloudflare IS a plain anchor
    }

    [Fact]
    public async Task row_flags_distinguish_pool_servers_relays_and_anonymizable_servers()
    {
        // IsServer gates the pool actions (relays are excluded — they belong in Anonymized DNS);
        // IsAnonymizableServer gates the "Route through a relay" shortcut (DNSCrypt / ODoH target only —
        // DoH can't be relayed).
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[]
            {
                Entry("cloudflare", DnsCryptStamp()),
                Entry("doh-only", DohStamp()),
                Entry("odoh-target", OdohTargetStamp()),
            }),
            Snapshot("relays", "", new[] { Entry("a-relay", OdohRelayStamp()) }),
        };
        var h = await LoadedAsync("", snaps);
        var byName = h.Vm.Rows.ToDictionary(r => r.Name);

        // IsServer (poolable) = not a relay
        Assert.True(byName["cloudflare"].IsServer);
        Assert.True(byName["doh-only"].IsServer);
        Assert.True(byName["a-relay"].IsRelay);
        Assert.False(byName["a-relay"].IsServer);

        // IsAnonymizableServer = DNSCrypt or ODoH target (never DoH, never a relay)
        Assert.True(byName["cloudflare"].IsAnonymizableServer);
        Assert.True(byName["odoh-target"].IsAnonymizableServer);
        Assert.False(byName["doh-only"].IsAnonymizableServer);
        Assert.False(byName["a-relay"].IsAnonymizableServer);
    }

    [Fact]
    public async Task add_odoh_sources_writes_on_the_canonical_example_with_commented_blocks()
    {
        // Review finding #1: the seeded example config has COMMENTED-OUT odoh blocks + odoh_servers=false.
        // A raw substring scan false-positives "already configured" and silently no-ops. The parsed check
        // sees NO active table and DOES the write.
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.File.NextLoad = ConfigLoadResult.Ok(
            "server_names = ['cloudflare']\nodoh_servers = false\n\n# [sources.'odoh-servers']\n#   cache_file = 'odoh-servers.md'\n\n# [sources.'odoh-relays']\n#   cache_file = 'odoh-relays.md'\n", Sha2);
        h.File.SaveHandler = (_, _, _) =>
            Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));

        await h.Vm.AddOdohSourcesCommand.ExecuteAsync(null);

        Assert.Single(h.File.SaveCalls); // NOT a no-op — the write happened
        var written = h.File.SaveCalls[0].Text;
        Assert.Contains("[sources.'odoh-servers']", written, StringComparison.Ordinal);
        Assert.Contains("[sources.'odoh-relays']", written, StringComparison.Ordinal);
        Assert.Matches(@"odoh_servers\s*=\s*true", written);
    }

    [Fact]
    public async Task add_odoh_sources_appends_only_the_missing_table_never_a_duplicate()
    {
        // Review finding #2: config already has an ACTIVE odoh-relays table. Appending the full block would
        // duplicate it (invalid TOML). Only odoh-servers must be appended, and the candidate stays valid.
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.File.NextLoad = ConfigLoadResult.Ok(
            "server_names = ['cloudflare']\n\n[sources.'odoh-relays']\nurls = ['y']\ncache_file = 'odoh-relays.md'\nminisign_key = 'k'\n", Sha2);
        h.File.SaveHandler = (_, _, _) =>
            Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));

        await h.Vm.AddOdohSourcesCommand.ExecuteAsync(null);

        Assert.Single(h.File.SaveCalls);
        var written = h.File.SaveCalls[0].Text;
        Assert.Contains("[sources.'odoh-servers']", written, StringComparison.Ordinal);
        Assert.Equal(1, written.Split("[sources.'odoh-relays']").Length - 1); // exactly ONE relays table
        Assert.False(TomlConfigDocument.Parse(written).HasErrors);            // valid TOML (no duplicate-key)
    }

    [Fact]
    public async Task odoh_empty_hint_is_suppressed_when_another_facet_still_has_rows()
    {
        // Review finding #5: ODoH + DNSCrypt checked, no ODoH stamps but DNSCrypt rows match → the opaque
        // ODoH explainer must NOT overlay the populated list.
        var h = await LoadedAsync("", TwoServerList()); // DNSCrypt servers, zero ODoH
        h.Vm.FilterDnsCrypt = true;
        h.Vm.FilterOdoh = true;

        Assert.True(h.Vm.Rows.Count > 0);      // rows are showing
        Assert.False(h.Vm.ShowOdohEmptyHint);  // so the ODoH empty-state is hidden (gated on Rows.Count==0)
    }

    [Fact]
    public async Task add_odoh_sources_is_blocked_while_there_are_pending_edits()
    {
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.Vm.AddToPool(Row(h.Vm, "quad9")); // stage an edit → dirty
        Assert.True(h.Vm.IsDirty);
        // A reload after the write would discard staged edits, so the action is gated on a clean state.
        Assert.False(h.Vm.CanAddOdohSources);
    }

    [Fact]
    public async Task revert_discards_staged_edits_and_reloads()
    {
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.Vm.AddToPool(Row(h.Vm, "quad9"));
        Assert.True(h.Vm.IsDirty);

        h.File.NextLoad = ConfigLoadResult.Ok("server_names = ['cloudflare']\n", Sha2);
        await h.Vm.RevertCommand.ExecuteAsync(null);

        Assert.False(h.Vm.IsDirty);
        Assert.Equal(Sha2, h.Vm.BaseSha256);
    }

    [Fact]
    public async Task on_tab_activated_reloads_only_when_clean_and_idle()
    {
        var h = await LoadedAsync("", TwoServerList());
        var loadsBefore = h.File.LoadCalls;

        h.File.NextLoad = ConfigLoadResult.Ok("", Sha2);
        await h.Vm.OnTabActivatedAsync();
        Assert.True(h.File.LoadCalls > loadsBefore); // clean+idle → reloaded

        h.Vm.UseOnlyThisServer(Row(h.Vm, "cloudflare"));
        var loadsAfterDirty = h.File.LoadCalls;
        await h.Vm.OnTabActivatedAsync();
        Assert.Equal(loadsAfterDirty, h.File.LoadCalls); // dirty → no reload
    }

    // ------------------------------------------------------------------ C3: latency probe

    private static ResolverListSnapshot[] ProbeableList() => new[]
    {
        Snapshot("public-resolvers", "", new[]
        {
            Entry("cloudflare", DnsCryptStamp(ip: "1.1.1.1", port: 443)),
            Entry("quad9", DohStamp(ip: "9.9.9.9", port: 443)),
        }),
    };

    [Fact]
    public async Task test_all_arms_a_consent_request_and_probes_nothing_until_confirmed()
    {
        var h = await LoadedAsync("", ProbeableList());

        h.Vm.TestAllLatenciesCommand.Execute(null);

        Assert.NotNull(h.Vm.PendingConsentRequest);
        Assert.Equal(2, h.Vm.PendingConsentRequest!.TargetCount);
        Assert.Empty(h.Prober.Invocations); // nothing probed yet
    }

    [Fact]
    public async Task declining_the_consent_probes_nothing()
    {
        var h = await LoadedAsync("", ProbeableList());
        h.Vm.TestAllLatenciesCommand.Execute(null);

        h.Vm.CancelTestAll();

        Assert.Null(h.Vm.PendingConsentRequest);
        Assert.Empty(h.Prober.Invocations);
    }

    [Fact]
    public async Task confirming_the_consent_probes_the_probeable_rows()
    {
        var h = await LoadedAsync("", ProbeableList());
        h.Vm.TestAllLatenciesCommand.Execute(null);

        await h.Vm.ConfirmTestAllAsync();

        Assert.Single(h.Prober.Invocations);
        Assert.Equal(2, h.Prober.Invocations[0].Count);
        Assert.Null(h.Vm.PendingConsentRequest);
        Assert.False(h.Vm.IsProbing);
        Assert.Equal(10, Row(h.Vm, "cloudflare").LatencyMs);
    }

    [Fact]
    public async Task per_row_click_is_its_own_consent_no_dialog()
    {
        var h = await LoadedAsync("", ProbeableList());

        await h.Vm.ProbeRowAsync(Row(h.Vm, "quad9"));

        Assert.Null(h.Vm.PendingConsentRequest); // no dialog was armed
        Assert.Single(h.Prober.Invocations);
        Assert.Single(h.Prober.Invocations[0]);
        Assert.Equal("quad9", h.Prober.Invocations[0][0].Name);
    }

    [Fact]
    public async Task a_row_with_no_ip_in_its_stamp_is_never_a_target()
    {
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[]
            {
                Entry("cloudflare", DnsCryptStamp(ip: "1.1.1.1")),
                Entry("odoh", OdohTargetStamp()), // no IP → not probeable
            }),
        };
        var h = await LoadedAsync("", snaps);
        h.Vm.TestAllLatenciesCommand.Execute(null);
        Assert.Equal(1, h.Vm.PendingConsentRequest!.TargetCount); // only cloudflare is probeable

        await h.Vm.ConfirmTestAllAsync();

        Assert.Single(h.Prober.Invocations[0]);
        Assert.Equal("cloudflare", h.Prober.Invocations[0][0].Name);
    }

    [Fact]
    public async Task a_kill_switch_blocked_row_is_excluded_and_labeled()
    {
        // A DNSCrypt stamp on :53 while the kill switch is ON → blocked (UDP/TCP 53 firewalled).
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[]
            {
                Entry("dnscrypt-53", DnsCryptStamp(ip: "1.2.3.4", port: 53)),
                Entry("cloudflare", DnsCryptStamp(ip: "1.1.1.1", port: 443)),
            }),
        };
        var h = await LoadedAsync("", snaps, killSwitchEnabled: true);

        await h.Vm.ProbeRowAsync(Row(h.Vm, "dnscrypt-53"));
        Assert.Empty(h.Prober.Invocations.SelectMany(i => i)); // blocked row was never probed

        h.Vm.TestAllLatenciesCommand.Execute(null);
        await h.Vm.ConfirmTestAllAsync();

        Assert.DoesNotContain(h.Prober.Invocations.SelectMany(i => i), t => t.Name == "dnscrypt-53");
        Assert.Contains(h.Prober.Invocations.SelectMany(i => i), t => t.Name == "cloudflare");
        Assert.Equal("blocked by kill switch", Row(h.Vm, "dnscrypt-53").ProbeStatus);
    }

    [Fact]
    public async Task status_fetch_failure_fails_closed_and_probes_no_port_53_or_853_rows()
    {
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[]
            {
                Entry("dns-53", DnsCryptStamp(ip: "1.2.3.4", port: 53)),
                Entry("dot-853", new ServerStamp(StampProtocol.DoT, 0, "2.3.4.5", 853, null, null,
                    new[] { new byte[32] }, "dot.example", null, Array.Empty<string>(), false)),
                Entry("cloudflare", DnsCryptStamp(ip: "1.1.1.1", port: 443)),
            }),
        };
        // statusOk:false → GetStatusAsync returns null → fail-closed treats kill switch as ON.
        var h = await LoadedAsync("", snaps, statusOk: false);

        h.Vm.TestAllLatenciesCommand.Execute(null);
        await h.Vm.ConfirmTestAllAsync();

        var probed = h.Prober.Invocations.SelectMany(i => i).Select(t => t.Name).ToArray();
        Assert.DoesNotContain("dns-53", probed);
        Assert.DoesNotContain("dot-853", probed);
        Assert.Contains("cloudflare", probed); // :443 is unaffected by the kill switch
    }

    [Fact]
    public async Task test_all_is_a_no_op_while_a_pending_consent_is_active()
    {
        var h = await LoadedAsync("", ProbeableList());
        h.Vm.TestAllLatenciesCommand.Execute(null);
        var first = h.Vm.PendingConsentRequest;

        h.Vm.TestAllLatenciesCommand.Execute(null); // second arm is a no-op

        Assert.Same(first, h.Vm.PendingConsentRequest);
        Assert.False(h.Vm.TestAllLatenciesCommand.CanExecute(null));
    }

    [Fact]
    public async Task a_reload_mid_probe_cancels_the_session_and_publishes_nothing_after()
    {
        var release = new TaskCompletionSource();
        var started = new TaskCompletionSource();
        var h = await LoadedAsync("", ProbeableList());
        h.Prober.Handler = async (targets, progress, ct) =>
        {
            started.TrySetResult();
            await release.Task;
            // After release the reload has already cancelled this session — every post must drop.
            foreach (var t in targets) progress?.Report(new ProbeResult(t.Name, true, 42, null));
            return targets.Select(t => new ProbeResult(t.Name, true, 42, null)).ToArray();
        };

        h.Vm.TestAllLatenciesCommand.Execute(null);
        var probe = h.Vm.ConfirmTestAllAsync(); // enters ProbeAsync and awaits release
        Assert.True(await Task.WhenAny(started.Task, Task.Delay(5000)) == started.Task, "probe never started");

        // A reload lands while the probe is in flight: it must cancel the session first.
        h.File.NextLoad = ConfigLoadResult.Ok("", Sha2);
        await h.Vm.LoadAsync(CancellationToken.None);

        release.SetResult(); // the orphaned prober now reports — every post must be dropped
        await probe;

        // The fresh rows carry no latency (the cancelled session published nothing over them).
        Assert.Null(Row(h.Vm, "cloudflare").LatencyMs);
        Assert.False(h.Vm.IsProbing);
    }

    [Fact]
    public async Task offline_gate_disables_probing_with_a_reason()
    {
        var h = await LoadedAsync("", ProbeableList());
        h.Gate.IsProbingAllowed = false;

        h.Vm.TestAllLatenciesCommand.Execute(null);
        Assert.Null(h.Vm.PendingConsentRequest);
        Assert.False(h.Vm.TestAllLatenciesCommand.CanExecute(null));

        await h.Vm.ProbeRowAsync(Row(h.Vm, "quad9"));
        Assert.Empty(h.Prober.Invocations);
        Assert.NotNull(h.Vm.ProbingDisabledReason);
    }

    [Fact]
    public async Task reload_clears_latency_results()
    {
        var h = await LoadedAsync("", ProbeableList());
        h.Vm.TestAllLatenciesCommand.Execute(null);
        await h.Vm.ConfirmTestAllAsync();
        Assert.Equal(10, Row(h.Vm, "cloudflare").LatencyMs);

        h.File.NextLoad = ConfigLoadResult.Ok("", Sha2);
        await h.Vm.LoadAsync(CancellationToken.None);

        Assert.Null(Row(h.Vm, "cloudflare").LatencyMs); // latencies do not survive a reload
    }

    // ------------------------------------------------------------------ R1: stuck IsProbing

    [Fact]
    public async Task save_ending_in_conflict_mid_probe_does_not_leave_probing_stuck()
    {
        // R1: a Save fires while a per-row probe is in flight → SaveAndApplyAsync calls
        // CancelProbeSession(), orphaning the session. The save ends in Conflict (a NON-reloading
        // outcome), so nothing resets IsProbing. Before the fix it stays true forever → the probe
        // buttons are dead. After the fix CancelProbeSession clears IsProbing.
        var release = new TaskCompletionSource();
        var started = new TaskCompletionSource();
        var h = await LoadedAsync("server_names = ['cloudflare']\n", ProbeableList());
        h.Prober.Handler = async (targets, progress, ct) =>
        {
            started.TrySetResult();
            await release.Task;
            return targets.Select(t => new ProbeResult(t.Name, true, 42, null)).ToArray();
        };

        // Stage an edit so Save has something to dispatch, then start a per-row probe that blocks.
        h.Vm.AddToPool(Row(h.Vm, "quad9"));
        var probe = h.Vm.ProbeRowAsync(Row(h.Vm, "cloudflare"));
        Assert.True(await Task.WhenAny(started.Task, Task.Delay(5000)) == started.Task, "probe never started");
        Assert.True(h.Vm.IsProbing);

        // The fresh re-read diverges → the save aborts to Conflict (no reload, no staged clear).
        h.File.NextLoad = ConfigLoadResult.Ok("server_names = ['someone-else']\n", Sha2);
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        release.SetResult();
        await probe;

        Assert.NotNull(h.Vm.ConflictMessage);
        Assert.False(h.Vm.IsProbing); // the probe UI must not be stuck
        Assert.True(h.Vm.TestAllLatenciesCommand.CanExecute(null)); // "Test all" is alive again
    }

    // ------------------------------------------------------------------ R2: disabled_server_names conflict

    [Fact]
    public async Task add_to_pool_of_a_disabled_name_surfaces_a_post_save_warning_not_clean_success()
    {
        // R2: staging AddToPool(quad9) while the FRESH doc's disabled_server_names contains quad9.
        // The proxy excludes quad9 (disabled beats a manual pick) but server_names lands with it in.
        // A clean "saved and applied" would be dishonest — surface a post-save warning naming it.
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.Vm.AddToPool(Row(h.Vm, "quad9"));

        // Fresh doc: server_names unchanged (no divergence) but quad9 is in disabled_server_names.
        h.File.NextLoad = ConfigLoadResult.Ok(
            "server_names = ['cloudflare']\ndisabled_server_names = ['quad9']\n", Sha2);
        ScriptApplied(h.File, "server_names = ['cloudflare', 'quad9']\ndisabled_server_names = ['quad9']\n", new string('c', 64));

        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Single(h.File.SaveCalls); // the save still lands (not a hard block)
        Assert.NotNull(h.Vm.DisabledPickWarning);
        Assert.Contains("quad9", h.Vm.DisabledPickWarning!, StringComparison.Ordinal);
        Assert.Contains("disabled_server_names", h.Vm.DisabledPickWarning!, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ R3: zero-pool degrade must warn

    [Fact]
    public async Task zero_pool_degrade_on_non_fresh_lists_surfaces_a_dedicated_warning_naming_the_state()
    {
        // R3: a staged zero-pool over Bundled/Missing lists must set a VISIBLE non-blocking warning
        // naming the list state — on a dedicated surface (not the fragile SingleServerWarning, which
        // picks overwrite/clear). Mirrors the AnonDNS ZeroPoolWarning convention.
        var snaps = new[]
        {
            Snapshot("public-resolvers", "", new[] { Entry("cloudflare", DnsCryptStamp()) }, ResolverListState.Bundled),
        };
        var h = await LoadedAsync("server_names = ['cloudflare']\n", snaps);

        h.Vm.ToggleFilter("dnscrypt_servers", enabled: false); // cloudflare is DNSCrypt → staged zero pool

        Assert.Null(h.Vm.SaveBlockedReason); // not a hard block on non-fresh lists
        Assert.NotNull(h.Vm.ZeroPoolStagedWarning);
        Assert.Contains("Bundled", h.Vm.ZeroPoolStagedWarning!, StringComparison.OrdinalIgnoreCase);
        Assert.True(h.Vm.CanSave);
    }

    // ------------------------------------------------------------------ R4: RestartFailedMessage clears on clean reload

    [Fact]
    public async Task restart_failed_message_clears_on_a_clean_reload_but_proxy_rejected_survives()
    {
        // R4: mirror ConfigurationViewModel.LoadAsync — a successful refresh clears the stale
        // "restart failed — status unverified" banner (false-scary otherwise); ProxyRejected survives.
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.Vm.AddToPool(Row(h.Vm, "quad9"));

        h.File.NextLoad = ConfigLoadResult.Ok("server_names = ['cloudflare']\n", Sha2);
        h.File.SaveHandler = (_, _, _) =>
        {
            h.File.NextLoad = ConfigLoadResult.Ok("server_names = ['cloudflare', 'quad9']\n", new string('c', 64));
            return Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.RestartFailed, "restart failed — status unverified"));
        };
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);
        Assert.NotNull(h.Vm.RestartFailedMessage);

        // A clean reload (e.g. tab-away/tab-back) must clear the stale banner.
        h.File.SaveHandler = null;
        h.File.NextLoad = ConfigLoadResult.Ok("server_names = ['cloudflare', 'quad9']\n", new string('d', 64));
        await h.Vm.LoadAsync(CancellationToken.None);

        Assert.Null(h.Vm.RestartFailedMessage);
    }

    [Fact]
    public async Task proxy_rejected_message_survives_a_clean_reload()
    {
        // R4 corollary: ProxyRejectedMessage is a never-green state — it must NOT be cleared by a reload
        // (its only exits are Applied or Revert), matching the 5b contract.
        var h = await LoadedAsync("server_names = ['cloudflare']\n", TwoServerList());
        h.Vm.AddToPool(Row(h.Vm, "quad9"));

        h.File.NextLoad = ConfigLoadResult.Ok("server_names = ['cloudflare']\n", Sha2);
        h.File.SaveHandler = (_, _, _) =>
        {
            h.File.NextLoad = ConfigLoadResult.Ok("server_names = ['cloudflare', 'quad9']\n", new string('c', 64));
            return Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.ProxyRejected, "rejected by proxy"));
        };
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);
        Assert.NotNull(h.Vm.ProxyRejectedMessage);

        h.File.SaveHandler = null;
        h.File.NextLoad = ConfigLoadResult.Ok("server_names = ['cloudflare', 'quad9']\n", new string('d', 64));
        await h.Vm.LoadAsync(CancellationToken.None);

        Assert.NotNull(h.Vm.ProxyRejectedMessage); // survives
    }

    // ------------------------------------------------------------------ R5: consent count is an upper bound

    [Fact]
    public async Task consent_count_is_labeled_as_an_upper_bound_not_an_exact_count()
    {
        // R5: PendingConsentRequest.TargetCount counts IsProbeable rows, but the actual probe set
        // removes kill-switch-blocked rows (fetched fresh at confirm). The dialog must present it as
        // an upper bound ("up to N"), never an exact count the probe won't hit.
        var h = await LoadedAsync("", ProbeableList());
        h.Vm.TestAllLatenciesCommand.Execute(null);

        Assert.NotNull(h.Vm.PendingConsentRequest);
        Assert.Equal(2, h.Vm.PendingConsentRequest!.TargetCount);
        Assert.True(h.Vm.PendingConsentRequest.IsUpperBound); // honesty: may be fewer after the kill-switch filter
    }
}
