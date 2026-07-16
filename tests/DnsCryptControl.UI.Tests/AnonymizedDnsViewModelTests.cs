using System.Collections.Concurrent;
using DnsCryptControl.Core.AnonymizedDns;
using DnsCryptControl.Core.Sources;
using DnsCryptControl.Core.Stamps;
using DnsCryptControl.Ipc;
using DnsCryptControl.Platform.Diagnostics;
using DnsCryptControl.UI.Models;
using DnsCryptControl.UI.Services;
using DnsCryptControl.UI.Tests.Fakes;
using DnsCryptControl.UI.ViewModels;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// C4: <see cref="AnonymizedDnsViewModel"/> — the strict-by-default toggle, the proto-matched
/// route builder, and coverage honesty over <c>[anonymized_dns].routes</c>. Pure-POCO tests
/// (IC-5): no WPF types, every post-await observable write through the injected
/// <see cref="IUiDispatcher"/>, zero wall-clock sleeps. Save/Revert ride the IC-9 fresh
/// read-modify-write with divergence abort (four paths incl. CanWrite on the fresh doc).
/// </summary>
public class AnonymizedDnsViewModelTests
{
    private static readonly string Sha = new('a', 64);
    private static readonly string Sha2 = new('b', 64);

    // ------------------------------------------------------------------ fixtures

    private sealed class SynchronousDispatcher : IUiDispatcher
    {
        public void Post(Action action) => action();
    }

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

        public async Task WaitForQueuedPostAsync() =>
            Assert.True(await _arrived.WaitAsync(TimeSpan.FromSeconds(10)), "timed out waiting for a queued post");

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

        public IReadOnlyList<ResolverListSnapshot> ReadAll() => Snapshots.ToArray();
    }

    private sealed class FakeUiStateStore : IUiStateStore
    {
        public UiState State { get; set; } = new();
        public List<UiState> Saves { get; } = new();

        public UiState Load() => State;

        public void Save(UiState state) => Saves.Add(state);
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

    private static ServerStamp DnsCryptRelayStamp(string ip = "5.6.7.8", int port = 443) =>
        new(StampProtocol.DnsCryptRelay, 0, ip, port, null, null,
            Array.Empty<byte[]>(), null, null, Array.Empty<string>(), false);

    private static ServerStamp OdohRelayStamp(string ip = "7.8.9.10", int port = 443) =>
        new(StampProtocol.ODoHRelay, 0, ip, port, null, null,
            new[] { new byte[32] }, "relay.example", "/proxy", Array.Empty<string>(), false);

    private static ResolverListEntry Entry(string name, ServerStamp stamp, string description = "", bool isSelectable = true) =>
        new(name, name, description, new[] { "sdns://x" }, new[] { stamp },
            Array.Empty<StampParseError>(), isSelectable, Array.Empty<string>());

    private static ResolverListSnapshot Snapshot(
        string sourceName, IEnumerable<ResolverListEntry> entries,
        ResolverListState state = ResolverListState.Fresh) =>
        new(sourceName, "", state, DateTimeOffset.UtcNow,
            new ResolverListParseResult(entries.ToList(), Array.Empty<string>(), null, false, false));

    /// <summary>Two DNSCrypt servers + one DNSCrypt relay — the standard anonymizable list.</summary>
    private static ResolverListSnapshot[] StandardLists() => new[]
    {
        Snapshot("public-resolvers", new[]
        {
            Entry("cloudflare", DnsCryptStamp()),
            Entry("quad9", DnsCryptStamp()),
        }),
        Snapshot("relays", new[] { Entry("anon-relay", DnsCryptRelayStamp()) }),
    };

    private sealed record Harness(
        AnonymizedDnsViewModel Vm,
        FakeConfigFileService File,
        FakeListReader Lists,
        FakeUiStateStore Store,
        SynchronousDispatcher Dispatcher,
        FakeHelperClient Helper);

    private static Harness Build(string configText, IEnumerable<ResolverListSnapshot>? snapshots = null, UiState? uiState = null)
    {
        var file = new FakeConfigFileService { NextLoad = ConfigLoadResult.Ok(configText, Sha) };
        var lists = new FakeListReader();
        if (snapshots is not null) lists.Snapshots.AddRange(snapshots);
        var store = new FakeUiStateStore { State = uiState ?? new UiState() };
        var dispatcher = new SynchronousDispatcher();
        var helper = new FakeHelperClient(); // unscripted VerifyResolution default = resolved route (no warning)
        var vm = new AnonymizedDnsViewModel(file, lists, store, dispatcher, helper);
        return new Harness(vm, file, lists, store, dispatcher, helper);
    }

    private static async Task<Harness> LoadedAsync(
        string configText, IEnumerable<ResolverListSnapshot>? snapshots = null, UiState? uiState = null)
    {
        var h = Build(configText, snapshots ?? StandardLists(), uiState);
        await h.Vm.LoadAsync(CancellationToken.None);
        return h;
    }

    private static void ScriptApplied(FakeConfigFileService file, string newSha)
    {
        file.SaveHandler = (text, _, _) =>
        {
            file.NextLoad = ConfigLoadResult.Ok(text, newSha);
            return Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));
        };
    }

    // A stock config with routes present but the strict bundle NOT applied (pre-existing weak config).
    private const string WeakEnabledConfig =
        "[anonymized_dns]\nroutes = [ { server_name = 'cloudflare', via = ['anon-relay'] } ]\n";

    // A config with routes present AND the strict bundle applied.
    private const string StrictEnabledConfig =
        "[anonymized_dns]\n" +
        "skip_incompatible = true\n" +
        "direct_cert_fallback = false\n" +
        "routes = [ { server_name = 'cloudflare', via = ['anon-relay'] } ]\n";

    // ================================================================== load

    [Fact]
    public async Task load_of_a_config_with_no_routes_is_off_and_not_dirty()
    {
        var h = await LoadedAsync("");

        Assert.False(h.Vm.LoadFailed);
        Assert.False(h.Vm.IsEnabled);
        Assert.False(h.Vm.IsDirty);
        Assert.Empty(h.Vm.Routes);
        Assert.Null(h.Vm.CoverageSummary);
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
        Assert.Null(h.Vm.BaseSha256);
    }

    [Fact]
    public async Task load_publishes_inside_the_dispatched_post()
    {
        var file = new FakeConfigFileService { NextLoad = ConfigLoadResult.Ok(WeakEnabledConfig, Sha) };
        var lists = new FakeListReader();
        lists.Snapshots.AddRange(StandardLists());
        using var dispatcher = new QueueingDispatcher();
        var vm = new AnonymizedDnsViewModel(file, lists, new FakeUiStateStore(), dispatcher, new FakeHelperClient());

        var load = vm.LoadAsync(CancellationToken.None);
        await dispatcher.WaitForQueuedPostAsync();
        Assert.Empty(vm.Routes); // queued but not run
        dispatcher.RunNext();
        Assert.Single(vm.Routes);
        await load;
    }

    // ---- route-builder candidates (proto pairing filter) ----

    [Fact]
    public async Task server_candidates_are_dnscrypt_servers_and_relays_are_dnscrypt_relays()
    {
        var h = await LoadedAsync("");

        Assert.Contains(h.Vm.ServerCandidates, c => c.Name == "cloudflare" && c.Protocol == StampProtocol.DnsCrypt);
        Assert.Contains(h.Vm.ServerCandidates, c => c.Name == "quad9");
        // DoH / relays are never server candidates.
        Assert.DoesNotContain(h.Vm.ServerCandidates, c => c.Name == "anon-relay");
    }

    [Fact]
    public async Task doh_servers_are_not_anonymizable_candidates()
    {
        var snaps = new[]
        {
            Snapshot("public-resolvers", new[]
            {
                Entry("cloudflare", DnsCryptStamp()),
                Entry("doh-only", DohStamp()),
            }),
        };
        var h = await LoadedAsync("", snaps);

        Assert.Contains(h.Vm.ServerCandidates, c => c.Name == "cloudflare");
        Assert.DoesNotContain(h.Vm.ServerCandidates, c => c.Name == "doh-only");
    }

    [Fact]
    public async Task odoh_target_is_a_candidate_only_when_odoh_sources_are_enabled()
    {
        var snaps = new[]
        {
            Snapshot("public-resolvers", new[]
            {
                Entry("cloudflare", DnsCryptStamp()),
                Entry("odoh-target", OdohTargetStamp()),
            }),
            Snapshot("relays", new[]
            {
                Entry("dnscrypt-relay", DnsCryptRelayStamp()),
                Entry("odoh-relay", OdohRelayStamp()),
            }),
        };

        var off = await LoadedAsync("", snaps);
        Assert.DoesNotContain(off.Vm.ServerCandidates, c => c.Name == "odoh-target");

        var on = await LoadedAsync("odoh_servers = true\n", snaps);
        Assert.Contains(on.Vm.ServerCandidates, c => c.Name == "odoh-target" && c.Protocol == StampProtocol.ODoHTarget);
    }

    [Fact]
    public async Task via_candidates_for_a_dnscrypt_server_are_filtered_to_dnscrypt_relays()
    {
        var snaps = new[]
        {
            Snapshot("public-resolvers", new[]
            {
                Entry("cloudflare", DnsCryptStamp()),
                Entry("odoh-target", OdohTargetStamp()),
            }),
            Snapshot("relays", new[]
            {
                Entry("dnscrypt-relay", DnsCryptRelayStamp()),
                Entry("odoh-relay", OdohRelayStamp()),
            }),
        };
        var h = await LoadedAsync("odoh_servers = true\n", snaps);

        // Add a DNSCrypt-server route: its via candidates must exclude the ODoH relay (a mismatched
        // pair silently kills the server), but include the DNSCrypt relay and '*'.
        h.Vm.AddRoute("cloudflare", Array.Empty<string>());
        var dnscryptRow = h.Vm.Routes.Single(r => r.ServerName == "cloudflare");
        Assert.Contains("dnscrypt-relay", dnscryptRow.ViaCandidates);
        Assert.Contains("*", dnscryptRow.ViaCandidates);
        Assert.DoesNotContain("odoh-relay", dnscryptRow.ViaCandidates);

        // An ODoH-target route's via candidates are the ODoH relay, not the DNSCrypt relay.
        h.Vm.AddRoute("odoh-target", Array.Empty<string>());
        var odohRow = h.Vm.Routes.Single(r => r.ServerName == "odoh-target");
        Assert.Contains("odoh-relay", odohRow.ViaCandidates);
        Assert.DoesNotContain("dnscrypt-relay", odohRow.ViaCandidates);
    }

    // ---- add-route builder via combo (the relay picker was blank — no ItemsSource) ----

    [Fact]
    public async Task add_via_candidates_are_populated_at_load_with_every_relay_and_the_wildcard()
    {
        // The builder's via combo had NO ItemsSource, so the relay picker was ALWAYS blank (an ODoH server
        // could never be paired with its relay). At load, with no server picked yet, it offers '*' + every relay.
        var snaps = new[]
        {
            Snapshot("public-resolvers", new[] { Entry("cloudflare", DnsCryptStamp()), Entry("odoh-target", OdohTargetStamp()) }),
            Snapshot("relays", new[] { Entry("dnscrypt-relay", DnsCryptRelayStamp()) }),
            Snapshot("odoh-relays", new[] { Entry("odoh-relay", OdohRelayStamp()) }),
        };
        var h = await LoadedAsync("odoh_servers = true\n", snaps);

        Assert.Contains("*", h.Vm.AddViaCandidates);
        Assert.Contains("dnscrypt-relay", h.Vm.AddViaCandidates);
        Assert.Contains("odoh-relay", h.Vm.AddViaCandidates);
        Assert.Null(h.Vm.AddViaEmptyHint);
    }

    [Fact]
    public async Task set_builder_server_filters_the_via_candidates_to_the_servers_relay_proto()
    {
        // Picking a server in the builder repoints the via combo to that server's proto-matched relays (+ '*'):
        // an ODoH server offers the ODoH relay, a DNSCrypt server offers the DNSCrypt relay — never a mismatch.
        var snaps = new[]
        {
            Snapshot("public-resolvers", new[] { Entry("cloudflare", DnsCryptStamp()), Entry("odoh-target", OdohTargetStamp()) }),
            Snapshot("relays", new[] { Entry("dnscrypt-relay", DnsCryptRelayStamp()) }),
            Snapshot("odoh-relays", new[] { Entry("odoh-relay", OdohRelayStamp()) }),
        };
        var h = await LoadedAsync("odoh_servers = true\n", snaps);

        h.Vm.SetBuilderServer("odoh-target");
        Assert.Contains("*", h.Vm.AddViaCandidates);
        Assert.Contains("odoh-relay", h.Vm.AddViaCandidates);
        Assert.DoesNotContain("dnscrypt-relay", h.Vm.AddViaCandidates);
        Assert.Null(h.Vm.AddViaEmptyHint);

        h.Vm.SetBuilderServer("cloudflare");
        Assert.Contains("dnscrypt-relay", h.Vm.AddViaCandidates);
        Assert.DoesNotContain("odoh-relay", h.Vm.AddViaCandidates);
    }

    [Fact]
    public async Task set_builder_server_surfaces_an_empty_hint_when_no_matching_relay_is_loaded()
    {
        // An ODoH server picked before its ODoH relay list is cached: only '*' is offered (no odoh relay),
        // so the near-empty picker is EXPLAINED (add the ODoH lists / restart), not left silently blank.
        var snaps = new[]
        {
            Snapshot("public-resolvers", new[] { Entry("odoh-target", OdohTargetStamp()) }),
            Snapshot("relays", new[] { Entry("dnscrypt-relay", DnsCryptRelayStamp()) }),
            // No odoh-relays list is present.
        };
        var h = await LoadedAsync("odoh_servers = true\n", snaps);

        h.Vm.SetBuilderServer("odoh-target");

        Assert.Equal(new[] { "*" }, h.Vm.AddViaCandidates);   // only the wildcard
        Assert.NotNull(h.Vm.AddViaEmptyHint);
        Assert.Contains("ODoH relays", h.Vm.AddViaEmptyHint!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task set_builder_server_empty_hint_for_a_dnscrypt_server_names_dnscrypt_relays()
    {
        // Pins the DNSCrypt arm of BuildNoRelayHint (the ODoH test above covers the other arm): a DNSCrypt
        // server picked before the relays list is cached offers only '*' → a DNSCrypt-specific empty hint.
        var snaps = new[]
        {
            Snapshot("public-resolvers", new[] { Entry("cloudflare", DnsCryptStamp()) }),
            // No relays list is present.
        };
        var h = await LoadedAsync("", snaps);

        h.Vm.SetBuilderServer("cloudflare");

        Assert.Equal(new[] { "*" }, h.Vm.AddViaCandidates);
        Assert.NotNull(h.Vm.AddViaEmptyHint);
        Assert.Contains("DNSCrypt relays", h.Vm.AddViaEmptyHint!, StringComparison.OrdinalIgnoreCase);
    }

    // ---- Resolvers "Route through a relay" shortcut (PendingRouteServer) ----

    [Fact]
    public async Task pending_route_server_stages_a_route_via_auto_on_tab_activation()
    {
        // The Resolvers "Route through a relay" shortcut sets PendingRouteServer before switching tabs;
        // the activation lifecycle stages a route for it (via '*') once candidates are loaded, so the user
        // lands in the builder with the matching relays available.
        var snaps = new[]
        {
            Snapshot("odoh-servers", new[] { Entry("odoh-target", OdohTargetStamp()) }),
            Snapshot("odoh-relays", new[] { Entry("odoh-relay", OdohRelayStamp()) }),
        };
        var h = await LoadedAsync("odoh_servers = true\n", snaps);
        Assert.False(h.Vm.IsDirty);

        h.Vm.PendingRouteServer = "odoh-target";
        await h.Vm.OnTabActivatedAsync();

        Assert.True(h.Vm.IsDirty);
        var row = Assert.Single(h.Vm.Routes);
        Assert.Equal("odoh-target", row.ServerName);
        Assert.Equal(new[] { "*" }, row.Via);
        Assert.Contains("odoh-relay", row.ViaCandidates);   // the matching relay is offered for refinement
        Assert.Null(h.Vm.PendingRouteServer);               // consumed exactly once
    }

    [Fact]
    public async Task pending_route_server_is_a_noop_when_that_server_is_already_routed()
    {
        // The server already has a route → don't duplicate it; just consume the request.
        var snaps = new[]
        {
            Snapshot("odoh-servers", new[] { Entry("odoh-target", OdohTargetStamp()) }),
            Snapshot("odoh-relays", new[] { Entry("odoh-relay", OdohRelayStamp()) }),
        };
        var h = await LoadedAsync(
            "odoh_servers = true\n[anonymized_dns]\nroutes = [ { server_name = 'odoh-target', via = ['odoh-relay'] } ]\n", snaps);

        h.Vm.PendingRouteServer = "odoh-target";
        await h.Vm.OnTabActivatedAsync();

        var row = Assert.Single(h.Vm.Routes);        // still exactly one route (no duplicate)
        Assert.Equal(new[] { "odoh-relay" }, row.Via); // the ORIGINAL route, unchanged
        Assert.Null(h.Vm.PendingRouteServer);
    }

    // ================================================================== toggle: strict bundle

    [Fact]
    public async Task enable_stages_the_strict_bundle_writes()
    {
        var h = await LoadedAsync(""); // AnonDNS off

        h.Vm.SetEnabled(true);
        Assert.True(h.Vm.IsDirty);

        // The strict bundle rides the save: dispatch it and assert the written text.
        h.File.NextLoad = ConfigLoadResult.Ok("", Sha2);
        ScriptApplied(h.File, new string('c', 64));
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Single(h.File.SaveCalls);
        var text = h.File.SaveCalls[0].Text;
        Assert.Contains("skip_incompatible = true", text, StringComparison.Ordinal);
        Assert.Contains("direct_cert_fallback = false", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task enable_restores_stashed_routes_from_the_ui_state_store()
    {
        var stash = new UiState
        {
            StashedRoutes = { new UiStashedRoute { ServerName = "cloudflare", Via = { "anon-relay" } } },
        };
        var h = await LoadedAsync("", StandardLists(), stash);

        h.Vm.SetEnabled(true);

        Assert.Single(h.Vm.Routes);
        Assert.Equal("cloudflare", h.Vm.Routes[0].ServerName);
    }

    [Fact]
    public async Task enable_with_no_stash_starts_an_empty_builder()
    {
        var h = await LoadedAsync("");

        h.Vm.SetEnabled(true);

        Assert.Empty(h.Vm.Routes);
        Assert.True(h.Vm.IsEnabledButEmpty);
        Assert.Contains("nothing is anonymized yet", h.Vm.AnonymizationStateText, StringComparison.OrdinalIgnoreCase);
    }

    // ---- load-time strictness mirror ----

    [Fact]
    public async Task load_time_strict_mirror_fires_on_a_pre_existing_weak_config()
    {
        // Routes present but the strict bundle NOT applied — the banner catches this at LOAD,
        // not only on the enable transition.
        var h = await LoadedAsync(WeakEnabledConfig);

        Assert.NotNull(h.Vm.StrictBannerMessage);
        Assert.False(h.Vm.IsDirty); // pristine — no edits yet
    }

    [Fact]
    public async Task load_time_strict_mirror_is_silent_on_a_strict_config()
    {
        var h = await LoadedAsync(StrictEnabledConfig);

        Assert.Null(h.Vm.StrictBannerMessage);
    }

    [Fact]
    public async Task strict_one_click_fix_stages_the_strict_bundle_and_clears_the_banner()
    {
        var h = await LoadedAsync(WeakEnabledConfig);
        Assert.NotNull(h.Vm.StrictBannerMessage);

        h.Vm.ApplyStrictFix();

        Assert.True(h.Vm.IsDirty);
        Assert.Null(h.Vm.StrictBannerMessage); // the effective (staged) strict flags now satisfy it
    }

    // ================================================================== coverage honesty

    [Fact]
    public async Task coverage_summary_reports_uncovered_pool_servers()
    {
        // Pool = cloudflare + quad9 (both DNSCrypt, automatic mode). Only cloudflare has a route.
        var h = await LoadedAsync(WeakEnabledConfig);

        Assert.NotNull(h.Vm.CoverageSummary);
        Assert.True(h.Vm.HasUncoveredServers);
        Assert.Contains("1 of 2", h.Vm.CoverageSummary!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task a_wildcard_route_covers_every_pool_server()
    {
        var config = "[anonymized_dns]\nroutes = [ { server_name = '*', via = ['anon-relay'] } ]\n";
        var h = await LoadedAsync(config);

        Assert.False(h.Vm.HasUncoveredServers);
        Assert.Contains("covered by a wildcard", h.Vm.CoverageSummary!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task enabled_with_zero_routes_is_an_explicit_nothing_anonymized_state()
    {
        // Routes key present but empty array — enabled, 0 routes.
        var config = "[anonymized_dns]\nroutes = []\n";
        var h = await LoadedAsync(config);

        Assert.True(h.Vm.IsEnabled);
        Assert.True(h.Vm.IsEnabledButEmpty);
        Assert.Contains("nothing is anonymized yet", h.Vm.AnonymizationStateText, StringComparison.OrdinalIgnoreCase);
        Assert.Null(h.Vm.CoverageSummary); // no routes → no coverage claim
    }

    // ================================================================== DoH banner

    [Fact]
    public async Task doh_banner_is_shown_while_anon_on_and_doh_absent_treated_as_true()
    {
        // Stock config omits doh_servers → treat absent as true → banner shows while AnonDNS is on.
        var h = await LoadedAsync(WeakEnabledConfig);

        Assert.NotNull(h.Vm.DohBannerMessage);
    }

    [Fact]
    public async Task doh_banner_is_absent_when_doh_is_off()
    {
        var config = "doh_servers = false\n" + WeakEnabledConfig;
        var h = await LoadedAsync(config);

        Assert.Null(h.Vm.DohBannerMessage);
    }

    [Fact]
    public async Task doh_banner_is_absent_when_anon_is_off()
    {
        var h = await LoadedAsync(""); // routes absent → off

        Assert.Null(h.Vm.DohBannerMessage);
    }

    [Fact]
    public async Task doh_one_click_fix_stages_doh_servers_false_and_clears_the_banner()
    {
        var h = await LoadedAsync(WeakEnabledConfig);
        Assert.NotNull(h.Vm.DohBannerMessage);

        h.Vm.ApplyDohFix();

        Assert.True(h.Vm.IsDirty);
        Assert.Null(h.Vm.DohBannerMessage);
    }

    [Fact]
    public async Task doh_one_click_fix_on_an_all_doh_pool_blocks_save_on_zero_pool()
    {
        // The only live server is DoH; disabling doh_servers would leave zero live resolvers.
        var snaps = new[]
        {
            Snapshot("public-resolvers", new[] { Entry("doh-only", DohStamp()) }),
            Snapshot("relays", new[] { Entry("anon-relay", DnsCryptRelayStamp()) }),
        };
        var config = "[anonymized_dns]\nroutes = [ { server_name = 'doh-only', via = ['anon-relay'] } ]\n";
        var h = await LoadedAsync(config, snaps);

        h.Vm.ApplyDohFix();

        Assert.NotNull(h.Vm.SaveBlockedReason);
        Assert.Contains("zero live resolvers", h.Vm.SaveBlockedReason!, StringComparison.OrdinalIgnoreCase);
        Assert.False(h.Vm.CanSave);
    }

    // ================================================================== CanWrite=false read-only

    [Fact]
    public async Task routes_in_array_of_tables_form_are_read_only()
    {
        // [[anonymized_dns.routes]] form → CanWrite=false → read-only builder + raw-editor guidance.
        var config =
            "[[anonymized_dns.routes]]\n" +
            "server_name = 'cloudflare'\n" +
            "via = ['anon-relay']\n";
        var h = await LoadedAsync(config);

        Assert.NotNull(h.Vm.ReadOnlyReason);
        Assert.True(h.Vm.IsRoutesReadOnly);

        // Editing operations are inert while read-only.
        h.Vm.SetEnabled(false);
        h.Vm.AddRoute("quad9", new[] { "anon-relay" });
        Assert.False(h.Vm.IsDirty);
    }

    // ================================================================== stash round-trip

    [Fact]
    public async Task disable_then_save_stashes_the_fresh_docs_routes_after_a_write_landed()
    {
        // Enabled config with one route. Disable → save → the fresh doc's routes are stashed.
        var h = await LoadedAsync(StrictEnabledConfig);
        Assert.True(h.Vm.IsEnabled);

        h.Vm.SetEnabled(false); // stages empty routes
        Assert.True(h.Vm.IsDirty);
        Assert.Empty(h.Store.Saves); // NOT persisted at toggle time

        h.File.NextLoad = ConfigLoadResult.Ok(StrictEnabledConfig, Sha2);
        ScriptApplied(h.File, new string('c', 64));
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        // Persisted ONLY after the write landed: the on-disk route is stashed for re-enable.
        Assert.Single(h.Store.Saves);
        var stashed = h.Store.Saves[0].StashedRoutes;
        Assert.Single(stashed);
        Assert.Equal("cloudflare", stashed[0].ServerName);
    }

    [Fact]
    public async Task revert_after_a_disable_toggle_keeps_the_prior_stash()
    {
        var priorStash = new UiState
        {
            StashedRoutes = { new UiStashedRoute { ServerName = "prior", Via = { "anon-relay" } } },
        };
        var h = await LoadedAsync(StrictEnabledConfig, StandardLists(), priorStash);

        h.Vm.SetEnabled(false); // an abandoned toggle
        h.File.NextLoad = ConfigLoadResult.Ok(StrictEnabledConfig, Sha2);
        await h.Vm.RevertCommand.ExecuteAsync(null);

        // Revert never persists — the prior stash is untouched.
        Assert.Empty(h.Store.Saves);
        Assert.False(h.Vm.IsDirty);
    }

    // ================================================================== IC-9 abort paths

    [Fact]
    public async Task save_aborts_when_the_fresh_load_fails()
    {
        var h = await LoadedAsync(StrictEnabledConfig);
        h.Vm.AddRoute("quad9", new[] { "anon-relay" });

        h.File.NextLoad = ConfigLoadResult.Fail("gone");
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.NotNull(h.Vm.ConflictMessage);
        Assert.True(h.Vm.IsDirty);
        Assert.Empty(h.File.SaveCalls);
    }

    [Fact]
    public async Task save_aborts_when_the_fresh_doc_has_errors()
    {
        var h = await LoadedAsync(StrictEnabledConfig);
        h.Vm.AddRoute("quad9", new[] { "anon-relay" });

        h.File.NextLoad = ConfigLoadResult.Ok("cache = [unclosed\n", Sha2);
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.NotNull(h.Vm.ConflictMessage);
        Assert.True(h.Vm.IsDirty);
        Assert.Empty(h.File.SaveCalls);
    }

    [Fact]
    public async Task save_aborts_when_a_staged_bool_key_diverged_on_disk()
    {
        var h = await LoadedAsync(WeakEnabledConfig);
        h.Vm.ApplyDohFix(); // stages doh_servers=false; browse-time doh_servers absent (=true)

        // The file changed under us: doh_servers is now explicitly false already.
        h.File.NextLoad = ConfigLoadResult.Ok("doh_servers = false\n" + WeakEnabledConfig, Sha2);
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.NotNull(h.Vm.ConflictMessage);
        Assert.Contains("doh_servers", h.Vm.ConflictMessage!, StringComparison.Ordinal);
        Assert.True(h.Vm.IsDirty);
        Assert.Empty(h.File.SaveCalls);
    }

    [Fact]
    public async Task save_aborts_when_the_fresh_doc_routes_are_not_canwrite_array_of_tables()
    {
        // Stage a routes edit against a clean doc, but the fresh doc's routes are now [[...]] form.
        var h = await LoadedAsync(StrictEnabledConfig);
        h.Vm.AddRoute("quad9", new[] { "anon-relay" });

        var arrayOfTables =
            "[[anonymized_dns.routes]]\nserver_name = 'cloudflare'\nvia = ['anon-relay']\n";
        h.File.NextLoad = ConfigLoadResult.Ok(arrayOfTables, Sha2);
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.NotNull(h.Vm.ConflictMessage);
        Assert.True(h.Vm.IsDirty);
        Assert.Empty(h.File.SaveCalls); // CanWrite abort (d) — nothing dispatched
    }

    [Fact]
    public async Task divergence_free_save_dispatches_the_fresh_sha_and_the_route()
    {
        var h = await LoadedAsync(StrictEnabledConfig);
        h.Vm.AddRoute("quad9", new[] { "anon-relay" });

        h.File.NextLoad = ConfigLoadResult.Ok(StrictEnabledConfig, Sha2);
        ScriptApplied(h.File, new string('c', 64));
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Single(h.File.SaveCalls);
        Assert.Equal(Sha2, h.File.SaveCalls[0].BaseSha256); // FRESH sha
        Assert.Contains("quad9", h.File.SaveCalls[0].Text, StringComparison.Ordinal);
        Assert.False(h.Vm.IsDirty);
        Assert.Equal("Configuration saved and applied.", h.Vm.SaveNotice);
    }

    [Fact]
    public async Task conflict_outcome_from_the_service_shows_the_banner()
    {
        var h = await LoadedAsync(StrictEnabledConfig);
        h.Vm.AddRoute("quad9", new[] { "anon-relay" });

        h.File.NextLoad = ConfigLoadResult.Ok(StrictEnabledConfig, Sha2);
        h.File.SaveHandler = (_, _, _) =>
            Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Conflict, "CAS lost the race"));
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Equal("CAS lost the race", h.Vm.ConflictMessage);
        Assert.True(h.Vm.IsDirty);
    }

    // ================================================================== FIX #1: post-apply route verification
    //
    // "Applied" only proves the WRITE landed and the proxy restarted — the continuous self-check
    // cannot prove the applied route RESOLVES (its undelegated .test name is answered locally by
    // block_undelegated, so a structurally-valid but dead relay route false-greens and silently
    // bricks DNS behind a green "Saved"). These tests pin the honest post-apply verification.

    /// <summary>Stages a route and scripts a clean Applied save — the shared setup for the
    /// verification tests. The route verdict comes from h.Helper.VerifyResolutionHandler.</summary>
    private static async Task<Harness> StagedForAppliedSaveAsync()
    {
        var h = await LoadedAsync(StrictEnabledConfig);
        h.Vm.AddRoute("quad9", new[] { "anon-relay" });
        h.File.NextLoad = ConfigLoadResult.Ok(StrictEnabledConfig, Sha2);
        ScriptApplied(h.File, new string('c', 64));
        return h;
    }

    [Fact]
    public async Task applied_save_with_a_resolving_route_verifies_once_and_shows_no_warning()
    {
        var h = await StagedForAppliedSaveAsync();
        // Unscripted FakeHelperClient default = Resolved:true.

        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Equal(1, h.Helper.VerifyResolutionCalls);
        Assert.Null(h.Vm.PostApplyWarning);
        Assert.Equal("Configuration saved and applied.", h.Vm.SaveNotice);
    }

    [Fact]
    public async Task applied_save_with_a_dead_route_shows_the_dead_route_warning()
    {
        var h = await StagedForAppliedSaveAsync();
        h.Helper.VerifyResolutionHandler = _ => Task.FromResult<Result<ResolveVerification>?>(
            Result<ResolveVerification>.Ok(new ResolveVerification(false, 5000, "timeout")));

        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Equal(AnonymizedDnsViewModel.PostApplyDeadRouteWarning, h.Vm.PostApplyWarning);
        Assert.Contains("turn Anonymized DNS off", h.Vm.PostApplyWarning!, StringComparison.Ordinal);
        Assert.DoesNotContain("Revert", h.Vm.PostApplyWarning!, StringComparison.Ordinal); // Applied cleared the staged set — Revert wouldn't undo the route
        Assert.Equal("Configuration saved and applied.", h.Vm.SaveNotice); // both true: the write landed AND the route is dead
    }

    [Fact]
    public async Task applied_save_with_a_null_verify_reply_shows_the_softer_unknown_warning()
    {
        var h = await StagedForAppliedSaveAsync();
        h.Helper.VerifyResolutionHandler = _ => Task.FromResult<Result<ResolveVerification>?>(null);

        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Equal(AnonymizedDnsViewModel.PostApplyVerifyUnavailableWarning, h.Vm.PostApplyWarning);
        Assert.Contains("couldn't verify", h.Vm.PostApplyWarning!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task applied_save_with_a_failed_verify_result_shows_the_softer_unknown_warning()
    {
        var h = await StagedForAppliedSaveAsync();
        h.Helper.VerifyResolutionHandler = _ => Task.FromResult<Result<ResolveVerification>?>(
            Result<ResolveVerification>.Fail(IpcErrorCode.OperationFailed, "probe could not run"));

        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Equal(AnonymizedDnsViewModel.PostApplyVerifyUnavailableWarning, h.Vm.PostApplyWarning);
    }

    [Fact]
    public async Task rejected_save_never_calls_verify_and_shows_no_postapply_warning()
    {
        var h = await LoadedAsync(StrictEnabledConfig);
        h.Vm.AddRoute("quad9", new[] { "anon-relay" });
        h.File.NextLoad = ConfigLoadResult.Ok(StrictEnabledConfig, Sha2);
        h.File.SaveHandler = (_, _, _) =>
            Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Rejected, "invalid config"));

        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Equal(0, h.Helper.VerifyResolutionCalls); // nothing new is live — nothing to verify
        Assert.Null(h.Vm.PostApplyWarning);
        Assert.Equal("invalid config", h.Vm.SaveError);
    }

    [Fact]
    public async Task conflict_outcome_never_calls_verify()
    {
        var h = await LoadedAsync(StrictEnabledConfig);
        h.Vm.AddRoute("quad9", new[] { "anon-relay" });
        h.File.NextLoad = ConfigLoadResult.Ok(StrictEnabledConfig, Sha2);
        h.File.SaveHandler = (_, _, _) =>
            Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Conflict, "CAS lost the race"));

        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Equal(0, h.Helper.VerifyResolutionCalls);
        Assert.Null(h.Vm.PostApplyWarning);
    }

    [Fact]
    public async Task a_prior_dead_route_warning_clears_on_the_next_successful_save()
    {
        // Apply a dead route → warning. Then turn Anonymized DNS off (the warning's own advice)
        // and save again with a verdict of resolved → the stale warning must clear.
        var h = await StagedForAppliedSaveAsync();
        h.Helper.VerifyResolutionHandler = _ => Task.FromResult<Result<ResolveVerification>?>(
            Result<ResolveVerification>.Ok(new ResolveVerification(false, 5000, "timeout")));
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);
        Assert.Equal(AnonymizedDnsViewModel.PostApplyDeadRouteWarning, h.Vm.PostApplyWarning);

        h.Helper.VerifyResolutionHandler = _ => Task.FromResult<Result<ResolveVerification>?>(
            Result<ResolveVerification>.Ok(new ResolveVerification(true, 90, "RCODE=0")));
        h.Vm.SetEnabled(false); // stages empty routes (disable) — re-dirties the tab
        Assert.True(h.Vm.IsDirty);
        ScriptApplied(h.File, new string('d', 64));
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Equal(2, h.Helper.VerifyResolutionCalls);
        Assert.Null(h.Vm.PostApplyWarning);
    }

    [Fact]
    public async Task revert_discards_staged_edits_and_reloads()
    {
        var h = await LoadedAsync(StrictEnabledConfig);
        h.Vm.AddRoute("quad9", new[] { "anon-relay" });
        Assert.True(h.Vm.IsDirty);

        h.File.NextLoad = ConfigLoadResult.Ok(StrictEnabledConfig, Sha2);
        await h.Vm.RevertCommand.ExecuteAsync(null);

        Assert.False(h.Vm.IsDirty);
        Assert.Equal(Sha2, h.Vm.BaseSha256);
    }

    [Fact]
    public async Task on_tab_activated_reloads_only_when_clean_and_idle()
    {
        var h = await LoadedAsync(StrictEnabledConfig);
        var before = h.File.LoadCalls;

        h.File.NextLoad = ConfigLoadResult.Ok(StrictEnabledConfig, Sha2);
        await h.Vm.OnTabActivatedAsync();
        Assert.True(h.File.LoadCalls > before);

        h.Vm.AddRoute("quad9", new[] { "anon-relay" });
        var afterDirty = h.File.LoadCalls;
        await h.Vm.OnTabActivatedAsync();
        Assert.Equal(afterDirty, h.File.LoadCalls); // dirty → no reload
    }

    // ================================================================== A1 routes concurrent-clobber

    [Fact]
    public async Task save_aborts_when_routes_changed_on_disk_since_browse_time()
    {
        // Stage a route against the loaded doc; a CONCURRENT writer changes routes on disk to a
        // DIFFERENT route. Save must ABORT (no clobber = no silent de-anonymization), keep the staged
        // set, and the concurrent route survives on disk (never dispatched over).
        var h = await LoadedAsync(StrictEnabledConfig); // routes = [ cloudflare ]
        h.Vm.AddRoute("quad9", new[] { "anon-relay" });
        Assert.True(h.Vm.IsDirty);

        // Fresh doc has a route the user never saw (a concurrent writer added 'other').
        var concurrent =
            "[anonymized_dns]\n" +
            "skip_incompatible = true\n" +
            "direct_cert_fallback = false\n" +
            "routes = [ { server_name = 'other', via = ['anon-relay'] } ]\n";
        h.File.NextLoad = ConfigLoadResult.Ok(concurrent, Sha2);
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.NotNull(h.Vm.ConflictMessage);
        Assert.Empty(h.File.SaveCalls);       // ABORTED — nothing written
        Assert.True(h.Vm.IsDirty);            // staged set preserved
    }

    [Fact]
    public async Task save_does_not_abort_when_routes_unchanged_on_disk()
    {
        // Sanity: identical on-disk routes must NOT trip the new routes-divergence gate.
        var h = await LoadedAsync(StrictEnabledConfig);
        h.Vm.AddRoute("quad9", new[] { "anon-relay" });

        h.File.NextLoad = ConfigLoadResult.Ok(StrictEnabledConfig, Sha2); // routes identical
        ScriptApplied(h.File, new string('c', 64));
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Single(h.File.SaveCalls);
        Assert.Null(h.Vm.ConflictMessage);
    }

    // ================================================================== A2 zero-pool + wildcard

    [Fact]
    public async Task zero_pool_with_wildcard_route_shows_a_warning_not_all_covered()
    {
        // require_dnssec=true empties a props-0 (no-DNSSEC-bit) pool; a wildcard route is present.
        var snaps = new[]
        {
            Snapshot("public-resolvers", new[] { Entry("cloudflare", DnsCryptStamp(props: 0)) }),
            Snapshot("relays", new[] { Entry("anon-relay", DnsCryptRelayStamp()) }),
        };
        var config =
            "require_dnssec = true\n" +
            "[anonymized_dns]\nroutes = [ { server_name = '*', via = ['anon-relay'] } ]\n";
        var h = await LoadedAsync(config, snaps);

        Assert.True(h.Vm.HasUncoveredServers);
        Assert.DoesNotContain("all covered", h.Vm.CoverageSummary ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.Contains("applies to nothing", h.Vm.CoverageSummary!, StringComparison.OrdinalIgnoreCase);
        // Pristine zero-pool banner surfaced at load (before any edit).
        Assert.NotNull(h.Vm.ZeroPoolBannerMessage);
        Assert.False(h.Vm.IsDirty);
    }

    // ================================================================== A3 AddRoute strict bundle

    [Fact]
    public async Task add_route_on_a_disabled_config_stages_the_strict_bundle()
    {
        // AnonDNS off (no routes key). AddRoute transitions absent→present and must stage the strict
        // bundle so the config never lands weak (de-anonymizing) without SetEnabled(true).
        var h = await LoadedAsync(""); // AnonDNS off

        h.Vm.AddRoute("cloudflare", new[] { "anon-relay" });

        h.File.NextLoad = ConfigLoadResult.Ok("", Sha2);
        ScriptApplied(h.File, new string('c', 64));
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Single(h.File.SaveCalls);
        var text = h.File.SaveCalls[0].Text;
        Assert.Contains("skip_incompatible = true", text, StringComparison.Ordinal);
        Assert.Contains("direct_cert_fallback = false", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task add_route_for_an_already_routed_server_replaces_that_row_rather_than_duplicating_it()
    {
        // A server has exactly one route (its via IS the relay list), so re-adding the same server must
        // REPLACE its row (this is how Edit changes the relay): add cloudflare via '*', then via 'anon-relay'
        // => exactly ONE cloudflare row whose via is the second (edited) relay.
        var h = await LoadedAsync(""); // AnonDNS off

        h.Vm.AddRoute("cloudflare", new[] { "*" });
        h.Vm.AddRoute("cloudflare", new[] { "anon-relay" });

        var row = Assert.Single(h.Vm.Routes);
        Assert.Equal("cloudflare", row.ServerName);
        Assert.Equal(new[] { "anon-relay" }, row.Via);
    }

    // ================================================================== A4 DoH server not "covered"

    [Fact]
    public async Task coverage_does_not_count_a_routed_doh_server_as_covered()
    {
        // Pool = { doh-only (DoH, routed), cloudflare (DnsCrypt, unrouted) }. dnscrypt-proxy will not
        // relay DoH, so doh-only must NOT be reported "covered".
        var snaps = new[]
        {
            Snapshot("public-resolvers", new[]
            {
                Entry("doh-only", DohStamp()),
                Entry("cloudflare", DnsCryptStamp()),
            }),
            Snapshot("relays", new[] { Entry("anon-relay", DnsCryptRelayStamp()) }),
        };
        var config =
            "[anonymized_dns]\nroutes = [ { server_name = 'doh-only', via = ['anon-relay'] } ]\n";
        var h = await LoadedAsync(config, snaps);

        // doh-only is NOT among the covered/anonymizable set — the DoH server is flagged, cloudflare uncovered.
        Assert.True(h.Vm.HasUncoveredServers);
        Assert.Contains("DoH", h.Vm.CoverageSummary!, StringComparison.Ordinal);
        // Coverage must not claim doh-only as an anonymized/covered server.
        Assert.DoesNotContain("All 2 pool server", h.Vm.CoverageSummary!, StringComparison.Ordinal);
    }

    // ================================================================== A5 zero-pool degrade to warning

    [Fact]
    public async Task zero_pool_save_on_non_fresh_lists_surfaces_a_warning_not_silence()
    {
        // DoH-only pool, lists in Missing state, ApplyDohFix ⇒ staged pool is zero but no list is Fresh.
        // The block degrades to a NON-BLOCKING warning (not null/silence).
        var snaps = new[]
        {
            Snapshot("public-resolvers", new[] { Entry("doh-only", DohStamp()) }, ResolverListState.Missing),
            Snapshot("relays", new[] { Entry("anon-relay", DnsCryptRelayStamp()) }, ResolverListState.Missing),
        };
        var config = "[anonymized_dns]\nroutes = [ { server_name = 'doh-only', via = ['anon-relay'] } ]\n";
        var h = await LoadedAsync(config, snaps);

        h.Vm.ApplyDohFix();

        Assert.Null(h.Vm.SaveBlockedReason);          // not a hard block on non-fresh lists
        Assert.NotNull(h.Vm.ZeroPoolWarning);         // but NOT silent
        Assert.Contains("zero resolvers", h.Vm.ZeroPoolWarning!, StringComparison.OrdinalIgnoreCase);
    }

    // ================================================================== A6 SetEnabled while enabled

    [Fact]
    public async Task set_enabled_true_on_an_already_enabled_config_keeps_the_routes()
    {
        // Config with 1 route (already enabled). SetEnabled(true) must NOT restore the (empty) stash and
        // zero the live routes — a genuine off→on transition is the only restore trigger.
        var h = await LoadedAsync(StrictEnabledConfig);
        Assert.True(h.Vm.IsEnabled);
        Assert.Single(h.Vm.Routes);

        h.Vm.SetEnabled(true);

        Assert.Single(h.Vm.Routes);       // routes preserved, not dirty-zeroed
        Assert.False(h.Vm.IsEnabledButEmpty);
    }

    // ================================================================== A7 AddRoute IC-7 validation

    [Fact]
    public async Task add_route_with_a_hostile_via_is_not_staged_and_surfaces_an_inline_reason()
    {
        var h = await LoadedAsync("");

        h.Vm.AddRoute("cloudflare", new[] { "relay']\ninjected='x" });

        Assert.False(h.Vm.IsDirty);                   // not staged
        Assert.NotNull(h.Vm.AddRouteError);           // inline reason (IC-10)
        Assert.Contains("relay']", h.Vm.AddRouteError!, StringComparison.Ordinal); // names the offending value
        Assert.Empty(h.Vm.Routes);
    }

    [Fact]
    public async Task add_route_with_a_hostile_server_name_is_not_staged()
    {
        var h = await LoadedAsync("");

        h.Vm.AddRoute("evil name!; drop", new[] { "anon-relay" });

        Assert.False(h.Vm.IsDirty);
        Assert.NotNull(h.Vm.AddRouteError);
        Assert.Contains("evil name", h.Vm.AddRouteError!, StringComparison.Ordinal);
    }

    // ================================================================== A8 RestartFailedMessage cleared on reload

    [Fact]
    public async Task restart_failed_message_is_cleared_on_a_clean_reload()
    {
        var h = await LoadedAsync(StrictEnabledConfig);
        h.Vm.AddRoute("quad9", new[] { "anon-relay" });

        // Save ends in RestartFailed.
        h.File.NextLoad = ConfigLoadResult.Ok(StrictEnabledConfig, Sha2);
        h.File.SaveHandler = (text, _, _) =>
        {
            h.File.NextLoad = ConfigLoadResult.Ok(text, new string('c', 64));
            return Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.RestartFailed, "restart failed"));
        };
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);
        Assert.NotNull(h.Vm.RestartFailedMessage);

        // A clean reload (tab-away/back) clears the stale scary banner.
        h.File.NextLoad = ConfigLoadResult.Ok(StrictEnabledConfig, Sha2);
        await h.Vm.OnTabActivatedAsync();

        Assert.Null(h.Vm.RestartFailedMessage);
    }

    // ================================================================== A9 emptied-but-enabled preserves prior stash

    [Fact]
    public async Task removing_the_last_route_does_not_overwrite_the_prior_stash()
    {
        // Config with 1 route + a prior stash [PRIOR]. RemoveRoute(last) leaves enabled-but-empty (NOT a
        // disable). Save writes routes=[]; the prior stash must be intact (E10 "stash only on disable").
        var priorStash = new UiState
        {
            StashedRoutes = { new UiStashedRoute { ServerName = "prior", Via = { "anon-relay" } } },
        };
        var h = await LoadedAsync(StrictEnabledConfig, StandardLists(), priorStash);
        Assert.Single(h.Vm.Routes);

        h.Vm.RemoveRoute(0);
        Assert.True(h.Vm.IsEnabledButEmpty); // emptied but NOT disabled

        h.File.NextLoad = ConfigLoadResult.Ok(StrictEnabledConfig, Sha2);
        ScriptApplied(h.File, new string('c', 64));
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Single(h.File.SaveCalls);
        // The prior stash must NOT be clobbered by an emptied-but-enabled write.
        if (h.Store.Saves.Count > 0)
        {
            var lastStash = h.Store.Saves[^1].StashedRoutes;
            Assert.Single(lastStash);
            Assert.Equal("prior", lastStash[0].ServerName);
        }
    }

    [Fact]
    public async Task true_disable_still_stashes_the_fresh_docs_routes()
    {
        // Regression guard for A9: a TRUE disable (SetEnabled(false)) must still stash the on-disk routes.
        var h = await LoadedAsync(StrictEnabledConfig);

        h.Vm.SetEnabled(false); // true disable
        h.File.NextLoad = ConfigLoadResult.Ok(StrictEnabledConfig, Sha2);
        ScriptApplied(h.File, new string('c', 64));
        await h.Vm.SaveAndApplyCommand.ExecuteAsync(null);

        Assert.Single(h.Store.Saves);
        var stashed = h.Store.Saves[0].StashedRoutes;
        Assert.Single(stashed);
        Assert.Equal("cloudflare", stashed[0].ServerName);
    }
}
