using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DnsCryptControl.Core.AnonymizedDns;
using DnsCryptControl.Core.Sources;
using DnsCryptControl.Core.Stamps;
using DnsCryptControl.Core.Toml;
using DnsCryptControl.UI.Models;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.ViewModels;

/// <summary>
/// The Anonymized DNS tab (Phase 5c, C4): a strict-by-default toggle, a proto-matched route
/// builder, and coverage honesty over the <c>[anonymized_dns].routes</c> table. Pure POCO
/// <see cref="ObservableObject"/> (IC-5): zero WPF types; every post-await observable write
/// goes through <see cref="IUiDispatcher.Post"/>; injectable seams keep tests deterministic.
///
/// <para>All config mutation rides the 5b Save &amp; apply pipeline with a fresh
/// read-modify-write + explicit divergence detection (IC-9), including
/// <see cref="AnonymizedDnsRoutes.CanWrite"/> on the FRESH doc as abort-path (d). The
/// displayed anonymization state derives from the routes' CONTENT, never the toggle
/// (a "enabled, 0 routes" config anonymizes nothing).</para>
/// </summary>
public sealed partial class AnonymizedDnsViewModel : ObservableObject, IDisposable
{
    private readonly IConfigFileService _configFile;
    private readonly IResolverListReader _listReader;
    private readonly IUiStateStore _stateStore;
    private readonly IUiDispatcher _ui;
    private readonly IHelperClient _helper;

    /// <summary>The selection config read at load (browse-time baseline for IC-9 divergence + the DoH banner).</summary>
    private ServerSelectionConfig? _loadedSelection;

    /// <summary>The routes read from the loaded doc (the browse-time baseline the routes op diverges against).</summary>
    private IReadOnlyList<AnonRoute> _loadedRoutes = Array.Empty<AnonRoute>();

    /// <summary>The list snapshots read at load — re-evaluated against the staged config for the zero-pool block.</summary>
    private IReadOnlyList<ResolverListSnapshot> _loadedLists = Array.Empty<ResolverListSnapshot>();

    /// <summary>The UI state loaded at load time — its StashedRoutes feed the enable restore.</summary>
    private UiState _loadedUiState = new();

    /// <summary>True when the <c>anonymized_dns.routes</c> key is present on the loaded doc (enabled position).</summary>
    private bool _loadedRoutesKeyPresent;

    /// <summary>The loaded <c>anonymized_dns.skip_incompatible</c> value (absent ⇒ false).</summary>
    private bool _loadedSkipIncompatible;

    /// <summary>The loaded <c>anonymized_dns.direct_cert_fallback</c> value (absent ⇒ false).</summary>
    private bool _loadedDirectCertFallback;

    /// <summary>The staged edits awaiting Save &amp; apply (IC-9), keyed by config key path.</summary>
    private readonly Dictionary<string, StagedOp> _staged = new(StringComparer.Ordinal);

    // ---- route-builder projection ----

    [ObservableProperty]
    private IReadOnlyList<RouteRowViewModel> _routes = Array.Empty<RouteRowViewModel>();

    /// <summary>The candidate server names a route row may target (anonymizable servers + <c>*</c>).</summary>
    [ObservableProperty]
    private IReadOnlyList<RouteServerCandidate> _serverCandidates = Array.Empty<RouteServerCandidate>();

    /// <summary>All relay candidates (used to filter each row's via-list by the row's server proto).</summary>
    private IReadOnlyList<RouteRelayCandidate> _relayCandidates = Array.Empty<RouteRelayCandidate>();

    /// <summary>The relays offered in the ADD-ROUTE builder's "via" combo for the currently selected server
    /// (proto-matched + <c>*</c>). The combo previously had NO ItemsSource, so the relay picker was always
    /// blank — an ODoH server could never be paired with its relay. Refreshed by <see cref="SetBuilderServer"/>.</summary>
    [ObservableProperty]
    private IReadOnlyList<string> _addViaCandidates = Array.Empty<string>();

    /// <summary>Non-null when the builder's selected (named) server has no relay to route through — only
    /// <c>*</c> is offered, e.g. an ODoH server picked before its relay list is cached. Explains the near-empty
    /// picker instead of leaving it silently blank.</summary>
    [ObservableProperty]
    private string? _addViaEmptyHint;

    // ---- displayed anonymization state (derives from ROUTES CONTENT, not the toggle) ----

    /// <summary>True when AnonDNS is enabled (routes key present / stashed) — the raw toggle position.</summary>
    [ObservableProperty]
    private bool _isEnabled;

    /// <summary>Honest headline: what routes CONTENT actually achieves (not the toggle).</summary>
    [ObservableProperty]
    private string _anonymizationStateText = "Anonymized DNS is off — DNS goes directly to your resolvers.";

    /// <summary>Explicit "enabled, 0 routes — nothing is anonymized yet" state (routes present-but-empty).</summary>
    [ObservableProperty]
    private bool _isEnabledButEmpty;

    // ---- coverage honesty ----

    /// <summary>The coverage summary: "N of M pool servers have no route — they resolve directly" (wildcard ⇒ all covered).</summary>
    [ObservableProperty]
    private string? _coverageSummary;

    /// <summary>True when N&gt;0 uncovered pool servers exist — the summary is warning-styled.</summary>
    [ObservableProperty]
    private bool _hasUncoveredServers;

    // ---- banners ----

    /// <summary>Load-time strictness mirror: non-null while routes are non-empty AND the strict bundle is not set.</summary>
    [ObservableProperty]
    private string? _strictBannerMessage;

    /// <summary>The DoH warning banner: non-null while AnonDNS-on AND doh_servers is absent-or-true.</summary>
    [ObservableProperty]
    private string? _dohBannerMessage;

    /// <summary>Pristine zero-pool guard (A2): non-null while AnonDNS-on AND the effective pool is 0 live servers —
    /// surfaced at load, before any edit (mirrors the Resolvers C1 pristine guard). Anonymization applies to nothing.</summary>
    [ObservableProperty]
    private string? _zeroPoolBannerMessage;

    /// <summary>CanWrite=false (routes are [[...]] or malformed) ⇒ read-only routes + raw-editor guidance (IC-12).</summary>
    [ObservableProperty]
    private string? _readOnlyReason;

    /// <summary>Inline reason (IC-10) when the last <see cref="AddRoute"/> was refused by the IC-7 gate — names the offending value.</summary>
    [ObservableProperty]
    private string? _addRouteError;

    /// <summary>True when routes are read-only (raw-managed config) — the builder is disabled.</summary>
    public bool IsRoutesReadOnly => ReadOnlyReason is not null;

    /// <summary>Transient cross-tab request: the Resolvers "Route through a relay" shortcut sets this to a
    /// server name just before switching to this tab; the tab's activation lifecycle consumes it exactly
    /// once and stages a route for that server (see <see cref="ProcessPendingRoute"/>). Not observable —
    /// it never renders.</summary>
    public string? PendingRouteServer { get; set; }

    // ---- C2/IC-9 save surfaces ----

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanSave))]
    [NotifyPropertyChangedFor(nameof(CanRevert))]
    [NotifyCanExecuteChangedFor(nameof(SaveAndApplyCommand))]
    [NotifyCanExecuteChangedFor(nameof(RevertCommand))]
    private bool _isDirty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanSave))]
    [NotifyPropertyChangedFor(nameof(CanRevert))]
    [NotifyCanExecuteChangedFor(nameof(SaveAndApplyCommand))]
    [NotifyCanExecuteChangedFor(nameof(RevertCommand))]
    private bool _isBusy;

    /// <summary>UI-local save block (IC-14): non-null disables Save with the reason (zero-pool guard).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanSave))]
    [NotifyCanExecuteChangedFor(nameof(SaveAndApplyCommand))]
    private string? _saveBlockedReason;

    /// <summary>A5: non-blocking zero-pool warning surfaced when the staged pool is zero but no list is Fresh
    /// (a stale list can't authoritatively hard-block, but must not degrade to SILENCE — IC-14/sec-F8).</summary>
    [ObservableProperty]
    private string? _zeroPoolWarning;

    [ObservableProperty]
    private string? _saveNotice;

    /// <summary>FIX #1 (v1.2.0): the post-apply route-verification warning. Set ONLY after an
    /// Applied save, from the helper's VerifyResolution real-name resolve check — the continuous
    /// self-check false-greens on a structurally-valid but DEAD anonymized route, so this is the
    /// user's only honest signal that the route they just applied doesn't resolve. Cleared at the
    /// top of the next Save &amp; apply and by <see cref="ClearStagedInternal"/> (reload/revert).
    /// The copy never says "Revert": after Applied the staged set is cleared and the tab reloads,
    /// so Revert would NOT undo the route.</summary>
    [ObservableProperty]
    private string? _postApplyWarning;

    [ObservableProperty]
    private string? _saveError;

    [ObservableProperty]
    private string? _conflictMessage;

    [ObservableProperty]
    private string? _helperIncompatibleMessage;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanRevert))]
    [NotifyCanExecuteChangedFor(nameof(RevertCommand))]
    private string? _restartFailedMessage;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanRevert))]
    [NotifyCanExecuteChangedFor(nameof(RevertCommand))]
    private string? _proxyRejectedMessage;

    [ObservableProperty]
    private bool _loadFailed;

    [ObservableProperty]
    private string? _loadError;

    /// <summary>Lowercase-hex SHA-256 of the on-disk bytes as loaded — the CAS base (fresh sha wins at save).</summary>
    public string? BaseSha256 { get; private set; }

    public AnonymizedDnsViewModel(
        IConfigFileService configFile,
        IResolverListReader listReader,
        IUiStateStore stateStore,
        IUiDispatcher ui,
        IHelperClient helper)
    {
        ArgumentNullException.ThrowIfNull(configFile);
        ArgumentNullException.ThrowIfNull(listReader);
        ArgumentNullException.ThrowIfNull(stateStore);
        ArgumentNullException.ThrowIfNull(ui);
        ArgumentNullException.ThrowIfNull(helper);
        _configFile = configFile;
        _listReader = listReader;
        _stateStore = stateStore;
        _ui = ui;
        _helper = helper;
    }

    // --------------------------------------------------------------- load

    /// <summary>
    /// Loads the config + cached lists off the UI thread, reads the routes, derives the
    /// route-builder candidates, and publishes the whole projection in ONE dispatcher post.
    /// Fail-closed: never throws. Discards staged edits (Revert / Conflict-Reload route here).
    /// </summary>
    public async Task LoadAsync(CancellationToken ct)
    {
        var snapshot = await Task.Run(() => LoadSnapshot(), ct).ConfigureAwait(false);

        _ui.Post(() =>
        {
            if (!snapshot.Success)
            {
                _loadedSelection = null;
                _loadedRoutes = Array.Empty<AnonRoute>();
                _loadedLists = Array.Empty<ResolverListSnapshot>();
                _loadedUiState = new UiState();
                _loadedRoutesKeyPresent = false;
                _loadedSkipIncompatible = false;
                _loadedDirectCertFallback = false;
                BaseSha256 = null;
                Routes = Array.Empty<RouteRowViewModel>();
                ServerCandidates = Array.Empty<RouteServerCandidate>();
                _relayCandidates = Array.Empty<RouteRelayCandidate>();
                AddViaCandidates = Array.Empty<string>();
                AddViaEmptyHint = null;
                ReadOnlyReason = null;
                StrictBannerMessage = null;
                DohBannerMessage = null;
                ZeroPoolBannerMessage = null;
                AddRouteError = null;
                RestartFailedMessage = null;
                CoverageSummary = null;
                HasUncoveredServers = false;
                IsEnabled = false;
                IsEnabledButEmpty = false;
                AnonymizationStateText = "The configuration could not be read.";
                ClearStagedInternal();
                LoadError = snapshot.Error;
                LoadFailed = true;
                return;
            }

            _loadedSelection = snapshot.Selection;
            _loadedRoutes = snapshot.Routes;
            _loadedLists = snapshot.Lists;
            _loadedUiState = snapshot.UiState;
            _loadedRoutesKeyPresent = snapshot.RoutesKeyPresent;
            _loadedSkipIncompatible = snapshot.SkipIncompatible;
            _loadedDirectCertFallback = snapshot.DirectCertFallback;
            BaseSha256 = snapshot.Sha256;
            _relayCandidates = snapshot.RelayCandidates;
            ServerCandidates = snapshot.ServerCandidates;
            ReadOnlyReason = snapshot.ReadOnlyReason;

            Routes = BuildRouteRows(snapshot.Routes);
            // Wire the add-route builder's via combo (was blank — no ItemsSource). null ⇒ every relay + '*'.
            SetBuilderServer(null);

            ClearStagedInternal();
            LoadError = null;
            LoadFailed = false;
            AddRouteError = null;
            // A8: a clean reload clears the "restart failed — status unverified" banner (mirrors 5b
            // ConfigurationViewModel.LoadAsync — a successful refresh is a documented RestartFailed exit).
            // ProxyRejectedMessage deliberately SURVIVES a reload (its only exits are Applied or Revert).
            RestartFailedMessage = null;
            RefreshDerivedState();
            // Consume a cross-tab "route this server" request now that the candidates are loaded (so the
            // staged route offers the matching relays). Runs inside this post body = the UI thread, right order.
            ProcessPendingRoute();
        });
    }

    /// <summary>Off-thread: read config + lists + routes + candidates. Never throws.</summary>
    private LoadSnapshotResult LoadSnapshot()
    {
        ConfigLoadResult load;
        try
        {
            load = _configFile.Load();
        }
        catch (Exception ex)
        {
            // Fail-closed: any fault becomes a load-failed state (CA1031 suppressed for this file).
            return LoadSnapshotResult.Fail(ex.Message);
        }

        if (!load.Success)
            return LoadSnapshotResult.Fail(load.Error ?? "the config could not be read");

        try
        {
            var doc = TomlConfigDocument.Parse(load.Text!);
            var selection = ServerSelectionConfig.FromDocument(doc);
            var lists = _listReader.ReadAll();
            var uiState = _stateStore.Load();

            var canWrite = AnonymizedDnsRoutes.CanWrite(doc, out var reason);
            AnonymizedDnsRoutes.TryRead(doc, out var routes, out _);

            // AnonDNS is "enabled" when the routes key is present on disk (even if empty). The
            // DISPLAYED anonymization state derives from routes CONTENT below, never this bit.
            var routesKeyPresent = doc.GetRaw(AnonymizedDnsRoutes.KeyPath) is not null;
            var skip = doc.TryGetBool(AnonSkipIncompatibleKey, out var s) && s;
            var fallback = doc.TryGetBool(AnonDirectCertFallbackKey, out var f) && f;

            var (serverCandidates, relayCandidates) = BuildCandidates(lists, selection);

            return LoadSnapshotResult.Ok(
                load.Sha256!, selection, routes, lists, uiState,
                canWrite ? null : reason, routesKeyPresent, skip, fallback, serverCandidates, relayCandidates);
        }
        catch (Exception ex)
        {
            return LoadSnapshotResult.Fail(ex.Message);
        }
    }

    /// <summary>
    /// Builds the route-builder candidate sets from the loaded lists: anonymizable servers
    /// (DNSCrypt 0x01, ODoH-target 0x05 when odoh sources are present) and relays. Each relay
    /// carries its proto so a route row can filter its via-list to the proto that MATCHES the
    /// row's server (relayProtoForServerProto: DNSCrypt↔0x81, ODoHTarget↔0x85). A mismatched
    /// pair silently kills the server, so the builder never offers one.
    /// </summary>
    private static (IReadOnlyList<RouteServerCandidate> Servers, IReadOnlyList<RouteRelayCandidate> Relays) BuildCandidates(
        IReadOnlyList<ResolverListSnapshot> lists, ServerSelectionConfig selection)
    {
        var servers = new List<RouteServerCandidate>();
        var relays = new List<RouteRelayCandidate>();
        var seenServers = new HashSet<string>(StringComparer.Ordinal);
        var seenRelays = new HashSet<string>(StringComparer.Ordinal);
        // ODoH-target candidates are only real when the config actually has odoh sources enabled.
        var odohActive = selection.ODoHServers;

        foreach (var entry in lists.SelectMany(s => s.Entries))
        {
            if (!entry.IsSelectable || entry.Stamps.Count == 0) continue;
            var proto = entry.Stamps[0].Protocol;

            if (entry.IsRelay)
            {
                if (proto is StampProtocol.DnsCryptRelay or StampProtocol.ODoHRelay && seenRelays.Add(entry.Name))
                    relays.Add(new RouteRelayCandidate(entry.Name, proto));
                continue;
            }

            // Anonymizable servers: DNSCrypt always; ODoH-target only when odoh sources are on.
            if (proto == StampProtocol.DnsCrypt && seenServers.Add(entry.Name))
                servers.Add(new RouteServerCandidate(entry.Name, proto));
            else if (proto == StampProtocol.ODoHTarget && odohActive && seenServers.Add(entry.Name))
                servers.Add(new RouteServerCandidate(entry.Name, proto));
        }

        return (servers, relays);
    }

    /// <summary>The relay proto that anonymizes a given server proto (0x01↔0x81, 0x05↔0x85).</summary>
    internal static StampProtocol? RelayProtoForServerProto(StampProtocol serverProto) => serverProto switch
    {
        StampProtocol.DnsCrypt => StampProtocol.DnsCryptRelay,
        StampProtocol.ODoHTarget => StampProtocol.ODoHRelay,
        _ => null,
    };

    /// <summary>Projects the loaded routes into editable rows, each carrying its proto-matched via candidates.</summary>
    private List<RouteRowViewModel> BuildRouteRows(IReadOnlyList<AnonRoute> routes)
    {
        var rows = new List<RouteRowViewModel>(routes.Count);
        foreach (var route in routes)
            rows.Add(new RouteRowViewModel(route.ServerName, route.Via.ToList(), ViaCandidatesFor(route.ServerName)));
        return rows;
    }

    /// <summary>The relay names offered for a route row targeting <paramref name="serverName"/> — filtered to the
    /// proto that matches the server's proto (plus <c>*</c> auto). A <c>*</c> server offers every relay.</summary>
    private List<string> ViaCandidatesFor(string serverName)
    {
        // The wildcard server '*' can be anonymized by any relay proto; a named server filters by its proto.
        var serverProto = serverName == "*"
            ? (StampProtocol?)null
            : ServerCandidates.FirstOrDefault(c => c.Name == serverName)?.Protocol;
        var wanted = serverProto is { } p ? RelayProtoForServerProto(p) : null;

        var names = new List<string> { "*" };
        foreach (var relay in _relayCandidates)
        {
            if (wanted is null || relay.Protocol == wanted) names.Add(relay.Name);
        }
        return names;
    }

    /// <summary>Repoints the ADD-ROUTE builder's "via" combo to the relays that can anonymize
    /// <paramref name="serverName"/> (proto-matched + <c>*</c>). Called by the view when the server combo
    /// selection changes (and once at load, with <c>null</c> ⇒ every relay). Fixes the blank relay picker:
    /// the combo had no ItemsSource, so no relay could ever be attached to a server. A NAMED server with no
    /// matching relay (only <c>*</c> offered) surfaces <see cref="AddViaEmptyHint"/> so the near-empty picker
    /// is explained (e.g. an ODoH server picked before its relay list is cached), not silently blank.</summary>
    public void SetBuilderServer(string? serverName)
    {
        var name = string.IsNullOrWhiteSpace(serverName) ? "*" : serverName!;
        var candidates = ViaCandidatesFor(name);
        AddViaCandidates = candidates;

        // Only '*' offered for a NAMED server = no relay of the matching proto is loaded. '*' alone cannot
        // route when the proxy has no compatible relay, so guide the user rather than leave a blank picker.
        AddViaEmptyHint = candidates.Count <= 1 && name != "*"
            ? BuildNoRelayHint(name)
            : null;
    }

    /// <summary>The empty-state guidance for a named server that has no relay of its matching proto.</summary>
    private string? BuildNoRelayHint(string serverName) =>
        ServerCandidates.FirstOrDefault(c => c.Name == serverName)?.Protocol switch
        {
            StampProtocol.ODoHTarget =>
                "No ODoH relays are available yet — an ODoH server can only work through an ODoH relay. Add the ODoH lists on the Resolvers tab, then restart the proxy (or type a relay's sdns:// stamp).",
            StampProtocol.DnsCrypt =>
                "No DNSCrypt relays are available. Restart the proxy so the relays list is cached, or type a relay's sdns:// stamp.",
            _ => null,
        };

    // --------------------------------------------------------------- derived state

    /// <summary>Recomputes the honest headline, coverage summary, and banners from the EFFECTIVE
    /// (staged-if-present, else loaded) routes + selection. Called after load and every staged edit.</summary>
    private void RefreshDerivedState()
    {
        var routes = EffectiveRoutes();
        var enabled = EffectiveEnabled();
        var selection = EffectiveStagedSelection();

        IsEnabled = enabled;
        IsEnabledButEmpty = enabled && routes.Count == 0;

        if (!enabled)
        {
            AnonymizationStateText = "Anonymized DNS is off — DNS goes directly to your resolvers. Each resolver can see your address alongside what you look up.";
        }
        else if (routes.Count == 0)
        {
            AnonymizationStateText = "Enabled, 0 routes — nothing is anonymized yet. Add a route below.";
        }
        else
        {
            AnonymizationStateText = $"Anonymizing {routes.Count} route(s) — DNS to those servers is relayed. The relay carries your questions, so the answering server can't see who asked.";
        }

        RefreshCoverage(routes, selection);
        RefreshStrictBanner(routes);
        RefreshDohBanner(enabled, selection);
        RefreshZeroPoolBanner(enabled, selection);
    }

    /// <summary>Coverage honesty: of the effective (included) pool servers, how many have no route and
    /// resolve directly. A wildcard (<c>*</c>) route server covers everything.</summary>
    private void RefreshCoverage(IReadOnlyList<AnonRoute> routes, ServerSelectionConfig selection)
    {
        if (!EffectiveEnabled() || routes.Count == 0)
        {
            CoverageSummary = null;
            HasUncoveredServers = false;
            return;
        }

        var entries = _loadedLists.SelectMany(s => s.Entries).ToArray();
        var evaluation = ServerSelection.Evaluate(entries, selection);
        var included = evaluation.Evaluations
            .Where(e => e.IsIncludedServer)
            .ToArray();

        // A4: a route to a DoH pool server is NOT real coverage — dnscrypt-proxy will not relay DoH, so it
        // resolves direct despite the route. Only anonymizable-proto servers (DNSCrypt/ODoH-target) count.
        var anonymizableNames = included
            .Where(e => IsAnonymizableProto(e.Entry.PrimaryProtocol))
            .Select(e => e.Entry.Name)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var dohNames = included
            .Where(e => e.Entry.PrimaryProtocol == StampProtocol.DoH)
            .Select(e => e.Entry.Name)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        var poolCount = anonymizableNames.Length + dohNames.Length;

        // A2: a zero-pool config (no live resolvers at all) can never be "all covered" — that is a false-safe
        // green while the proxy has nothing to resolve with. Warn, never print the wildcard "all covered".
        if (poolCount == 0)
        {
            CoverageSummary = "0 live pool servers — anonymization applies to nothing (this config has no usable resolvers).";
            HasUncoveredServers = true;
            return;
        }

        var hasWildcardRoute = routes.Any(r => r.ServerName == "*");
        // DoH servers can never be covered by a wildcard either — the wildcard only anonymizes routable protos.
        var dohNote = dohNames.Length > 0
            ? $" {dohNames.Length} DoH server(s) cannot be anonymized (routed but resolve directly)."
            : string.Empty;

        if (hasWildcardRoute)
        {
            HasUncoveredServers = dohNames.Length > 0;
            CoverageSummary =
                $"All {anonymizableNames.Length} anonymizable pool server(s) are covered by a wildcard route.{dohNote}";
            return;
        }

        var routed = new HashSet<string>(routes.Select(r => r.ServerName), StringComparer.Ordinal);
        var uncovered = anonymizableNames.Count(n => !routed.Contains(n));
        HasUncoveredServers = uncovered > 0 || dohNames.Length > 0;
        CoverageSummary = uncovered > 0
            ? $"{uncovered} of {anonymizableNames.Length} anonymizable pool server(s) have no route — they resolve directly. Those servers still see your address.{dohNote}"
            : $"All {anonymizableNames.Length} anonymizable pool server(s) have a route.{dohNote}";
    }

    /// <summary>Anonymizable protos (a relay can carry them): DNSCrypt (0x01) and ODoH-target (0x05). DoH cannot.</summary>
    private static bool IsAnonymizableProto(StampProtocol? proto) =>
        proto is StampProtocol.DnsCrypt or StampProtocol.ODoHTarget;

    /// <summary>A2 pristine zero-pool guard: surfaced whenever AnonDNS is on AND the effective pool is 0 live servers.</summary>
    private void RefreshZeroPoolBanner(bool enabled, ServerSelectionConfig selection)
    {
        if (!enabled)
        {
            ZeroPoolBannerMessage = null;
            return;
        }

        var entries = _loadedLists.SelectMany(s => s.Entries).ToArray();
        var evaluation = ServerSelection.Evaluate(entries, selection);
        var poolCount = evaluation.Evaluations.Count(e => e.IsIncludedServer);
        ZeroPoolBannerMessage = poolCount == 0
            ? "0 live pool servers — anonymization applies to nothing (this config has no usable resolvers)."
            : null;
    }

    /// <summary>Load-time strictness mirror: while routes are non-empty AND (skip_incompatible≠true OR
    /// direct_cert_fallback≠false), show a persistent "apply strict settings" banner (catches pre-existing
    /// weak configs, not only the enable transition). Uses the EFFECTIVE (staged) strict values.</summary>
    private void RefreshStrictBanner(IReadOnlyList<AnonRoute> routes)
    {
        if (routes.Count == 0)
        {
            StrictBannerMessage = null;
            return;
        }

        var skip = EffectiveFlag(AnonSkipIncompatibleKey, LoadedSkipIncompatible());
        var fallback = EffectiveFlag(AnonDirectCertFallbackKey, LoadedDirectCertFallback());
        StrictBannerMessage = (!skip || fallback)
            ? "Anonymized DNS is not using the strict bundle — a resolver that can't be relayed could silently fall back to a direct, de-anonymizing connection. Apply strict settings."
            : null;
    }

    /// <summary>DoH warning banner: persistent while AnonDNS-on AND doh_servers is absent-or-true
    /// (stock config omits the key — treat absent as true). A DoH resolver can't be anonymized by a relay.</summary>
    private void RefreshDohBanner(bool enabled, ServerSelectionConfig selection)
    {
        DohBannerMessage = enabled && selection.DohServers
            ? "DoH resolvers are enabled — their traffic is NOT anonymized by these relays (only DNSCrypt/ODoH is). Disable DoH so anonymization is not silently bypassed."
            : null;
    }

    // --------------------------------------------------------------- toggle

    /// <summary>
    /// Turns the AnonDNS master toggle on/off (staged). Enable ⇒ restore stashed routes (or an empty
    /// builder) + the STRICT BUNDLE. Disable ⇒ stage empty routes (the fresh doc's routes are stashed
    /// at save time during the IC-9 re-apply — never here). No-op while routes are read-only.
    /// </summary>
    public void SetEnabled(bool enabled)
    {
        if (IsRoutesReadOnly) return;
        if (enabled)
        {
            // A6: only a GENUINE off→on transition restores the stash. On an already-enabled config the
            // stash is empty (nothing was disabled), so restoring would silently zero the live routes.
            if (EffectiveEnabled())
            {
                // Already enabled — preserve current routes; just (re)assert the strict bundle (U3).
                StageStrictBundle();
                RefreshStagedState();
                return;
            }

            var restore = StashedRoutesFromUiState();
            StageRoutes(restore);
            // Strict bundle on enable (U3): skip_incompatible=true, direct_cert_fallback=false.
            StageStrictBundle();
            Routes = BuildRouteRows(restore);
        }
        else
        {
            StageRoutes(Array.Empty<AnonRoute>(), isDisable: true);
            Routes = Array.Empty<RouteRowViewModel>();
        }

        RefreshStagedState();
    }

    /// <summary>Stages the strict bundle (U3): <c>skip_incompatible=true</c>, <c>direct_cert_fallback=false</c>.</summary>
    private void StageStrictBundle()
    {
        StageBool(AnonSkipIncompatibleKey, LoadedSkipIncompatible(), true);
        StageBool(AnonDirectCertFallbackKey, LoadedDirectCertFallback(), false);
    }

    /// <summary>One-click DoH fix: stage <c>doh_servers=false</c> (blocks on zero-pool via RecomputeSaveBlock).</summary>
    public void ApplyDohFix()
    {
        if (IsRoutesReadOnly) return;
        StageBool("doh_servers", _loadedSelection?.DohServers ?? true, false);
        RefreshStagedState();
    }

    /// <summary>One-click strict fix: stage the strict bundle (skip_incompatible=true, direct_cert_fallback=false).</summary>
    public void ApplyStrictFix()
    {
        if (IsRoutesReadOnly) return;
        StageStrictBundle();
        RefreshStagedState();
    }

    // --------------------------------------------------------------- route builder

    /// <summary>Adds a route row for <paramref name="serverName"/> (a candidate name or <c>*</c>) with
    /// the given via list (proto-matched relay names, <c>*</c>, or a validated relay sdns:// stamp — IC-7).</summary>
    public void AddRoute(string serverName, IReadOnlyList<string> via)
    {
        ArgumentException.ThrowIfNullOrEmpty(serverName);
        ArgumentNullException.ThrowIfNull(via);
        if (IsRoutesReadOnly) return;

        // A7/IC-7: validate BEFORE staging so a hostile server_name/via never reaches the save path
        // (where Write would throw and mislabel it a Conflict). Surface an inline reason (IC-10) naming
        // the offending value; do not stage.
        if (!IsValidRouteServerName(serverName))
        {
            AddRouteError = $"'{serverName}' is not a valid server name — use letters, digits, '.', '_', '-' (max 64) or '*'.";
            return;
        }
        foreach (var relay in via)
        {
            if (!IsValidVia(relay))
            {
                AddRouteError = $"'{relay}' is not a valid relay — use a relay name, '*', or a relay sdns:// stamp.";
                return;
            }
        }
        AddRouteError = null;

        // A3: adding the FIRST route to a disabled config (routes absent/empty) transitions it to enabled;
        // stage the strict bundle so the config never lands weak (de-anonymizing) without SetEnabled(true).
        var wasEnabled = EffectiveEnabled() && EffectiveRoutes().Count > 0;

        // Replace-by-server: a DNSCrypt/ODoH server has exactly one route (its via IS the relay list), so
        // two rows for the same server is wrong. Dropping any existing row for this server before adding
        // both fixes that latent duplicate AND makes Edit work by re-adding (Edit loads the row back into
        // the builder, the user changes the relay, and this add replaces the old row).
        var next = EffectiveRoutes().Where(r => !string.Equals(r.ServerName, serverName, StringComparison.Ordinal)).ToList();
        next.Add(new AnonRoute(serverName, via.ToArray()));
        StageRoutes(next);
        if (!wasEnabled) StageStrictBundle();
        Routes = BuildRouteRows(next);
        RefreshStagedState();
    }

    /// <summary>Removes the route row at <paramref name="index"/>.</summary>
    public void RemoveRoute(int index)
    {
        if (IsRoutesReadOnly) return;
        var next = EffectiveRoutes().ToList();
        if (index < 0 || index >= next.Count) return;
        next.RemoveAt(index);
        StageRoutes(next);
        Routes = BuildRouteRows(next);
        RefreshStagedState();
    }

    /// <summary>The auto-relay via for a shortcut-staged route ('*'): the builder lets the user pick a
    /// specific relay before Save. Shared to satisfy CA1861 (no per-call array literal).</summary>
    private static readonly string[] AutoViaRelay = { "*" };

    /// <summary>
    /// Consumes a <see cref="PendingRouteServer"/> request (the Resolvers "Route through a relay"
    /// shortcut): stages a route for that server via the auto (<c>*</c>) relay, so the user lands in the
    /// builder with the pair ready to refine + save (the first route also stages the strict bundle, via
    /// <see cref="AddRoute"/>). No-op when there's no request, the routes are read-only, or the server is
    /// already routed. Consumes the request exactly once. Runs on the UI thread — its only callers are the
    /// LoadAsync post body and <see cref="OnTabActivatedAsync"/>.
    /// </summary>
    private void ProcessPendingRoute()
    {
        if (PendingRouteServer is not { Length: > 0 } server)
        {
            PendingRouteServer = null;
            return;
        }

        PendingRouteServer = null;

        if (IsRoutesReadOnly)
        {
            AddRouteError = "These routes are managed directly in the config file — add this route there.";
            return;
        }

        if (EffectiveRoutes().Any(r => string.Equals(r.ServerName, server, StringComparison.Ordinal)))
        {
            return; // already routed — the existing row is shown
        }

        AddRoute(server, AutoViaRelay);
    }

    // IC-7 route gate (mirrors AnonymizedDnsRoutes' write-time validation so a bad name never stages).
    private static bool IsValidRouteServerName(string s) => s == "*" || IsBareRouteName(s);

    private static bool IsValidVia(string s)
    {
        if (s == "*" || IsBareRouteName(s)) return true;
        if (s.StartsWith("sdns:", StringComparison.Ordinal))
            return ServerStampParser.TryParse(s, out var stamp, out _) && stamp is { IsRelay: true };
        return false;
    }

    private static bool IsBareRouteName(string s) => ServerNamePolicy.IsAllowedName(s);

    /// <summary>The upstream caveat for the wildcard "auto" route (offered in the builder).</summary>
    public const string WildcardRouteCaveat =
        "A wildcard 'auto' route is likely suboptimal — prefer manual pairs run by different entities for the strongest anonymization.";

    // --------------------------------------------------------------- staging support

    private const string AnonSkipIncompatibleKey = "anonymized_dns.skip_incompatible";
    private const string AnonDirectCertFallbackKey = "anonymized_dns.direct_cert_fallback";
    private const string RoutesKey = "__routes__"; // internal staged-op key (not a config key path)

    private AnonRoute[] StashedRoutesFromUiState() =>
        _loadedUiState.StashedRoutes
            .Select(r => new AnonRoute(r.ServerName, r.Via.ToArray()))
            .ToArray();

    /// <summary>Stages a routes edit. <paramref name="isDisable"/> distinguishes a TRUE disable (master
    /// toggle off) from an emptied-but-enabled builder — both serialize to <c>routes = []</c> but only a
    /// true disable stashes the on-disk routes for a later re-enable (A9). The browse-time baseline is the
    /// on-disk routes read at load (<c>_loadedRoutes</c>): the routes op diverges against it at save (A1).</summary>
    private void StageRoutes(IReadOnlyList<AnonRoute> finalRoutes, bool isDisable = false)
    {
        _staged[RoutesKey] = new StagedOp(
            RoutesKey, StagedKind.Routes, null, null, finalRoutes, _loadedRoutes, isDisable);
    }

    private void StageBool(string keyPath, bool loadedValue, bool finalValue)
    {
        _staged[keyPath] = new StagedOp(keyPath, StagedKind.Bool, loadedValue, finalValue, null);
    }

    /// <summary>The effective (staged if present, else loaded) routes.</summary>
    private IReadOnlyList<AnonRoute> EffectiveRoutes() =>
        _staged.TryGetValue(RoutesKey, out var op) && op.FinalRoutes is { } r ? r : _loadedRoutes;

    /// <summary>Effective "enabled" = a routes op is staged (any content, incl. empty). When no routes op is
    /// staged the loaded position governs: the routes key was present on disk (even if empty).</summary>
    private bool EffectiveEnabled() =>
        _staged.ContainsKey(RoutesKey) || _loadedRoutesKeyPresent;

    private bool LoadedSkipIncompatible() => _loadedSkipIncompatible;

    private bool LoadedDirectCertFallback() => _loadedDirectCertFallback;

    private bool EffectiveFlag(string key, bool loaded) =>
        _staged.TryGetValue(key, out var op) && op.FinalBool is { } v ? v : loaded;

    /// <summary>The selection config with every staged bool op applied over the loaded baseline.</summary>
    private ServerSelectionConfig EffectiveStagedSelection()
    {
        var b = _loadedSelection ?? ServerSelectionConfig.FromDocument(TomlConfigDocument.Parse(""));
        bool Flag(string key, bool loaded) =>
            _staged.TryGetValue(key, out var op) && op.FinalBool is { } v ? v : loaded;
        return new ServerSelectionConfig(
            b.ServerNames, b.DisabledServerNames,
            Ipv4Servers: Flag("ipv4_servers", b.Ipv4Servers),
            Ipv6Servers: Flag("ipv6_servers", b.Ipv6Servers),
            DnsCryptServers: Flag("dnscrypt_servers", b.DnsCryptServers),
            DohServers: Flag("doh_servers", b.DohServers),
            ODoHServers: Flag("odoh_servers", b.ODoHServers),
            RequireDnssec: Flag("require_dnssec", b.RequireDnssec),
            RequireNolog: Flag("require_nolog", b.RequireNolog),
            RequireNofilter: Flag("require_nofilter", b.RequireNofilter));
    }

    private void RefreshStagedState()
    {
        IsDirty = _staged.Count > 0;
        SaveNotice = null;
        RecomputeSaveBlock();
        RefreshDerivedState();
    }

    /// <summary>
    /// UI-local zero-pool block (IC-14): EVERY staged save runs A5 PoolSummary on the staged config;
    /// a staged pool of zero live servers blocks Save (the DoH one-click fix on an all-DoH pool would
    /// otherwise brick DNS). Degrades to a warning when no snapshot is Fresh (a stale list is not
    /// authoritative enough to hard-block).
    /// </summary>
    private void RecomputeSaveBlock()
    {
        SaveBlockedReason = null;
        ZeroPoolWarning = null;
        if (_staged.Count == 0) return;

        var entries = _loadedLists.SelectMany(s => s.Entries).ToArray();
        var result = ServerSelection.Evaluate(entries, EffectiveStagedSelection());
        if (!result.Pool.IsZeroPool) return;

        var anyFresh = _loadedLists.Any(s => s.State == ResolverListState.Fresh);
        if (anyFresh)
        {
            SaveBlockedReason =
                "These changes would leave zero live resolvers — the proxy would refuse to start (total DNS outage). Adjust your filters before saving.";
        }
        else
        {
            // A5/sec-F8: a non-Fresh list is not authoritative enough to hard-block, but degrading to
            // SILENCE lets the user save a DNS-bricking config with zero feedback. Surface a non-blocking
            // warning naming the list state instead of null.
            var state = _loadedLists.Count > 0
                ? string.Join("/", _loadedLists.Select(s => s.State).Distinct())
                : "unavailable";
            ZeroPoolWarning =
                $"Could not confirm live resolvers — lists are {state}; these changes may leave zero resolvers (proxy would refuse to start).";
        }
    }

    // --------------------------------------------------------------- Save & apply (IC-9)

    public bool CanSave => IsDirty && SaveBlockedReason is null && !IsBusy;

    public bool CanRevert =>
        !IsBusy && (IsDirty || RestartFailedMessage is not null || ProxyRejectedMessage is not null);

    public const string RevertLabel = "Revert to on-disk config";

    /// <summary>FIX #1: the verification RAN and the route is provably dead (queries do not come
    /// back). Deliberately actionable — pick another pair or turn the feature off; never "Revert"
    /// (after Applied there is nothing staged to revert).</summary>
    public const string PostApplyDeadRouteWarning =
        "Applied, but DNS isn't resolving through this route — the relay/server pair may be unreachable. " +
        "Pick a different relay or server; if your network blocks UDP (some VMs and NATs do), turn on " +
        "'Always use TCP' (force_tcp) in Configuration → Connection; or turn Anonymized DNS off.";

    /// <summary>FIX #1: the verification could NOT run (helper unreachable / probe failure) — the
    /// route state is UNKNOWN, so the copy is softer but never silent.</summary>
    public const string PostApplyVerifyUnavailableWarning =
        "Applied, but we couldn't verify DNS resolution just now. Check the Dashboard status; " +
        "if browsing fails, pick a different relay or server, or turn Anonymized DNS off.";

    /// <summary>
    /// Save &amp; apply (IC-9): fresh Load → build fresh doc → ABORT with a preserved staged set + a
    /// Conflict banner when ANY of: (a) fresh load fails; (b) fresh doc HasErrors; (c) any staged op's
    /// key now reads ≠ its browse-time value; (d) the routes op fails
    /// <see cref="AnonymizedDnsRoutes.CanWrite"/> on the fresh doc. Only a divergence-free fresh doc is
    /// mutated and dispatched with the FRESH sha. Non-cancellable.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanSave))]
    private async Task SaveAndApplyAsync()
    {
        if (IsBusy || !IsDirty || SaveBlockedReason is not null) return;

        var dispatched = _staged.Values.ToArray();

        IsBusy = true;
        SaveNotice = null;
        PostApplyWarning = null;
        SaveError = null;
        ConflictMessage = null;
        HelperIncompatibleMessage = null;
        try
        {
            var prepared = await Task.Run(() => PrepareSave(dispatched), CancellationToken.None).ConfigureAwait(false);
            if (!prepared.Success)
            {
                _ui.Post(() => ConflictMessage = prepared.ConflictReason);
                return;
            }

            var outcome = await _configFile
                .SaveAndApplyAsync(prepared.CandidateText!, prepared.FreshSha!, CancellationToken.None)
                .ConfigureAwait(false);
            await ApplySaveOutcomeAsync(outcome, dispatched, prepared.StashedFreshRoutes).ConfigureAwait(false);
        }
        finally
        {
            _ui.Post(() => IsBusy = false);
        }
    }

    /// <summary>IC-9 fresh read + divergence check (incl. CanWrite path (d)) + candidate build. Off-thread; never throws.
    /// Also captures the FRESH doc's routes (E10: what a disable would stash — read during THIS re-apply).</summary>
    private PrepareResult PrepareSave(IReadOnlyList<StagedOp> ops)
    {
        ConfigLoadResult fresh;
        try
        {
            fresh = _configFile.Load();
        }
        catch (Exception ex)
        {
            return PrepareResult.Conflict(
                "config could not be re-read before saving (" + ex.Message + ") — your staged changes stay; Reload to review.");
        }

        // (a) fresh load fails.
        if (!fresh.Success)
            return PrepareResult.Conflict(
                "config changed underneath your staged changes — Reload to review; your staged changes stay until you Reload/Revert.");

        TomlConfigDocument doc;
        try
        {
            doc = TomlConfigDocument.Parse(fresh.Text!);
        }
        catch (Exception ex)
        {
            return PrepareResult.Conflict("the on-disk config could not be parsed (" + ex.Message + ") — Reload to review.");
        }

        // (b) fresh doc HasErrors.
        if (doc.HasErrors)
            return PrepareResult.Conflict(
                "the on-disk config now has TOML errors — Reload to review; your staged changes stay until you Reload/Revert.");

        var hasRoutesOp = ops.Any(o => o.Kind == StagedKind.Routes);

        // (d) any staged routes op fails CanWrite on the FRESH doc (routes are [[...]] or malformed).
        if (hasRoutesOp && !AnonymizedDnsRoutes.CanWrite(doc, out var canWriteReason))
            return PrepareResult.Conflict(
                (canWriteReason ?? "the routes cannot be written structurally") + " Reload to review; your staged changes stay until you Reload/Revert.");

        // The fresh doc's routes — read during THIS re-apply — are what a disable stashes (E10/mvvm-F6)
        // AND the value the routes-divergence gate (A1) compares against the browse-time baseline.
        IReadOnlyList<AnonRoute> freshRoutes = Array.Empty<AnonRoute>();
        if (hasRoutesOp)
            AnonymizedDnsRoutes.TryRead(doc, out freshRoutes, out _);

        // (c) any staged op's key now reads != its browse-time value.
        foreach (var op in ops)
        {
            if (op.Kind == StagedKind.Bool && DivergedBool(doc, op))
                return PrepareResult.Conflict(
                    $"'{op.KeyPath}' changed on disk since you staged your edit — Reload to review; your staged changes stay until you Reload/Revert.");

            // A1 (IC-9(d) gap): a routes op has NO keypath compare, so a concurrent on-disk routes write
            // would be silently clobbered = silent de-anonymization. Compare the fresh doc's routes against
            // the browse-time baseline (order-sensitive structural {ServerName, Via[]} equality) and abort.
            if (op.Kind == StagedKind.Routes && RoutesDiverged(op.BrowseTimeRoutes ?? Array.Empty<AnonRoute>(), freshRoutes))
                return PrepareResult.Conflict(
                    "the anonymized-DNS routes changed on disk since you staged your edit — Reload to review; your staged changes stay until you Reload/Revert.");
        }

        try
        {
            foreach (var op in ops)
            {
                if (op.Kind == StagedKind.Bool && op.FinalBool is { } b) doc.SetBool(op.KeyPath, b);
                else if (op.Kind == StagedKind.Routes && op.FinalRoutes is { } r) AnonymizedDnsRoutes.Write(doc, r);
            }
        }
        catch (Exception ex)
        {
            return PrepareResult.Conflict("the staged changes could not be applied (" + ex.Message + ") — Reload to review.");
        }

        return PrepareResult.Ok(doc.ToText(), fresh.Sha256!, freshRoutes);
    }

    /// <summary>A1: order-sensitive structural equality of two route lists ({ServerName, Via[]}). True when they differ.</summary>
    private static bool RoutesDiverged(IReadOnlyList<AnonRoute> browse, IReadOnlyList<AnonRoute> fresh)
    {
        if (browse.Count != fresh.Count) return true;
        for (var i = 0; i < browse.Count; i++)
        {
            if (!string.Equals(browse[i].ServerName, fresh[i].ServerName, StringComparison.Ordinal)) return true;
            var bVia = browse[i].Via;
            var fVia = fresh[i].Via;
            if (bVia.Count != fVia.Count) return true;
            for (var j = 0; j < bVia.Count; j++)
                if (!string.Equals(bVia[j], fVia[j], StringComparison.Ordinal)) return true;
        }
        return false;
    }

    private static bool DivergedBool(TomlConfigDocument doc, StagedOp op)
    {
        var browse = op.BrowseTimeBool ?? false;
        var present = doc.TryGetBool(op.KeyPath, out var now);
        return present ? now != browse : browse != DefaultFlag(op.KeyPath);
    }

    private static bool DefaultFlag(string keyPath) => keyPath switch
    {
        "dnscrypt_servers" or "doh_servers" or "ipv4_servers" => true,
        // anonymized_dns.skip_incompatible / direct_cert_fallback default false (absent = off).
        _ => false,
    };

    /// <summary>Maps a save outcome onto the state surfaces (reload-first ordering, mirror ResolversViewModel).
    /// On a write-LANDED outcome (Applied/RestartFailed/ProxyRejected) the stash is persisted (never at toggle
    /// time / never on Revert): the fresh doc's routes are stashed IFF the routes op wrote empty routes (disable).</summary>
    private async Task ApplySaveOutcomeAsync(
        ConfigSaveOutcome outcome, IReadOnlyList<StagedOp> dispatched, IReadOnlyList<AnonRoute> freshRoutesBeforeWrite)
    {
        switch (outcome.Kind)
        {
            case ConfigSaveOutcomeKind.Applied:
                PersistStashIfDisable(dispatched, freshRoutesBeforeWrite);
                RemoveDispatchedOps(dispatched);
                if (_staged.Count == 0)
                {
                    await LoadAsync(CancellationToken.None).ConfigureAwait(false);
                    _ui.Post(() =>
                    {
                        ProxyRejectedMessage = null;
                        SaveNotice = "Configuration saved and applied.";
                    });
                }
                else
                {
                    _ui.Post(() =>
                    {
                        ProxyRejectedMessage = null;
                        SaveNotice = "Configuration saved and applied — an edit made during the save is still unsaved.";
                    });
                }
                // FIX #1: Applied means the write landed AND the proxy is running — now prove the
                // route it runs actually RESOLVES (the local self-check cannot; block_undelegated
                // answers its .test name locally, false-greening a dead anonymized route). Runs
                // AFTER the reload so LoadAsync's ClearStagedInternal can't wipe the verdict.
                // Applied only — every other outcome means nothing new is live to verify.
                await VerifyAppliedResolutionAsync().ConfigureAwait(false);
                break;

            case ConfigSaveOutcomeKind.RestartFailed:
                PersistStashIfDisable(dispatched, freshRoutesBeforeWrite);
                RemoveDispatchedOps(dispatched);
                if (_staged.Count == 0)
                    await LoadAsync(CancellationToken.None).ConfigureAwait(false);
                _ui.Post(() => RestartFailedMessage = outcome.Message
                    ?? "config saved, but the proxy restart failed — status unverified");
                break;

            case ConfigSaveOutcomeKind.ProxyRejected:
                PersistStashIfDisable(dispatched, freshRoutesBeforeWrite);
                RemoveDispatchedOps(dispatched);
                if (_staged.Count == 0)
                    await LoadAsync(CancellationToken.None).ConfigureAwait(false);
                _ui.Post(() => ProxyRejectedMessage = outcome.Message
                    ?? "new config rejected by proxy — Revert or re-edit");
                break;

            case ConfigSaveOutcomeKind.Conflict:
                _ui.Post(() => ConflictMessage = outcome.Message
                    ?? "config changed on disk — Reload to review; your staged changes stay until you Reload/Revert.");
                break;

            case ConfigSaveOutcomeKind.HelperIncompatible:
                _ui.Post(() => HelperIncompatibleMessage = outcome.Message
                    ?? "helper protocol version does not match this app — update the helper and app together, then retry");
                break;

            case ConfigSaveOutcomeKind.Rejected:
            case ConfigSaveOutcomeKind.HelperUnavailable:
            case ConfigSaveOutcomeKind.TooLarge:
            default:
                _ui.Post(() => SaveError = outcome.Message ?? "the save failed");
                break;
        }
    }

    /// <summary>FIX #1: one bounded real-name resolve through the helper after an Applied save.
    /// Three verdicts, mapped fail-closed-to-honesty: Resolved=true ⇒ no warning; Resolved=false ⇒
    /// the dead-route warning; failed/<c>null</c> result ⇒ the softer "couldn't verify" warning
    /// (UNKNOWN is surfaced, never silenced). Posted via the dispatcher like every post-await write.</summary>
    private async Task VerifyAppliedResolutionAsync()
    {
        var verification = await _helper.VerifyResolutionAsync(CancellationToken.None).ConfigureAwait(false);
        _ui.Post(() => PostApplyWarning = verification switch
        {
            { Success: true, Value.Resolved: true } => null,
            { Success: true, Value.Resolved: false } => PostApplyDeadRouteWarning,
            _ => PostApplyVerifyUnavailableWarning,
        });
    }

    /// <summary>Persist the stash ONLY after a write landed (never at toggle time / on Revert): a routes op
    /// that wrote EMPTY routes is a disable — stash the FRESH doc's routes read during the re-apply so a later
    /// re-enable restores exactly what was there. A non-empty routes write clears the stash.</summary>
    private void PersistStashIfDisable(IReadOnlyList<StagedOp> dispatched, IReadOnlyList<AnonRoute> freshRoutesBeforeWrite)
    {
        var routesOp = dispatched.FirstOrDefault(o => o.Kind == StagedKind.Routes);
        if (routesOp?.FinalRoutes is not { } written) return;

        var state = _stateStore.Load();
        // A9: "emptied-but-enabled" (last route removed via the builder) and a TRUE disable (master toggle
        // off) both serialize to routes=[]. Only a TRUE disable stashes the on-disk routes — an emptied
        // builder must NOT clobber the prior stash (E10 "stash only on disable"). Distinguish via IsDisable.
        if (written.Count == 0 && routesOp.IsDisable)
        {
            // True disable: stash the routes that were on disk before this write (from the fresh re-apply).
            state.StashedRoutes = freshRoutesBeforeWrite
                .Select(r => new UiStashedRoute { ServerName = r.ServerName, Via = r.Via.ToList() })
                .ToList();
        }
        else if (written.Count > 0)
        {
            // A non-empty write (enable/route edit) — the prior stash is consumed; clear it.
            state.StashedRoutes = new List<UiStashedRoute>();
        }
        else
        {
            // Emptied-but-enabled (written empty, not a disable): leave the prior stash untouched.
            return;
        }
        _stateStore.Save(state);
    }

    private void RemoveDispatchedOps(IReadOnlyList<StagedOp> dispatched)
    {
        _ui.Post(() =>
        {
            foreach (var op in dispatched)
            {
                if (_staged.TryGetValue(op.KeyPath, out var current) && ReferenceEquals(current, op))
                    _staged.Remove(op.KeyPath);
            }
            IsDirty = _staged.Count > 0;
            RecomputeSaveBlock();
            RefreshDerivedState();
        });
    }

    [RelayCommand(CanExecute = nameof(CanRevert))]
    private async Task RevertAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        RestartFailedMessage = null;
        ProxyRejectedMessage = null;
        try
        {
            await LoadAsync(CancellationToken.None).ConfigureAwait(false);
        }
        finally
        {
            _ui.Post(() => IsBusy = false);
        }
    }

    public Task OnTabActivatedAsync()
    {
        if (IsDirty || IsBusy)
        {
            // A reload would discard unsaved edits, so don't — but still honour a pending "route this
            // server" request by adding it on top of the current staged state.
            ProcessPendingRoute();
            return Task.CompletedTask;
        }

        return LoadAsync(CancellationToken.None);
    }

    private void ClearStagedInternal()
    {
        _staged.Clear();
        IsDirty = false;
        SaveBlockedReason = null;
        ZeroPoolWarning = null;
        SaveNotice = null;
        PostApplyWarning = null;
        SaveError = null;
        ConflictMessage = null;
        HelperIncompatibleMessage = null;
    }

    public void Dispose() => GC.SuppressFinalize(this);

    // --------------------------------------------------------------- projection DTOs

    private sealed record LoadSnapshotResult(
        bool Success,
        string? Error,
        string? Sha256,
        ServerSelectionConfig? SelectionRaw,
        IReadOnlyList<AnonRoute> Routes,
        IReadOnlyList<ResolverListSnapshot> Lists,
        UiState UiState,
        string? ReadOnlyReason,
        bool RoutesKeyPresent,
        bool SkipIncompatible,
        bool DirectCertFallback,
        IReadOnlyList<RouteServerCandidate> ServerCandidates,
        IReadOnlyList<RouteRelayCandidate> RelayCandidates)
    {
        public ServerSelectionConfig Selection => SelectionRaw!;

        public static LoadSnapshotResult Fail(string error) => new(
            false, error, null, null, Array.Empty<AnonRoute>(), Array.Empty<ResolverListSnapshot>(),
            new UiState(), null, false, false, false, Array.Empty<RouteServerCandidate>(), Array.Empty<RouteRelayCandidate>());

        public static LoadSnapshotResult Ok(
            string sha, ServerSelectionConfig selection, IReadOnlyList<AnonRoute> routes,
            IReadOnlyList<ResolverListSnapshot> lists, UiState uiState, string? readOnlyReason,
            bool routesKeyPresent, bool skipIncompatible, bool directCertFallback,
            IReadOnlyList<RouteServerCandidate> serverCandidates, IReadOnlyList<RouteRelayCandidate> relayCandidates) => new(
            true, null, sha, selection, routes, lists, uiState, readOnlyReason,
            routesKeyPresent, skipIncompatible, directCertFallback, serverCandidates, relayCandidates);
    }

    private enum StagedKind
    {
        Bool,
        Routes,
    }

    private sealed record StagedOp(
        string KeyPath,
        StagedKind Kind,
        bool? BrowseTimeBool,
        bool? FinalBool,
        IReadOnlyList<AnonRoute>? FinalRoutes,
        IReadOnlyList<AnonRoute>? BrowseTimeRoutes = null,
        bool IsDisable = false);

    private sealed record PrepareResult(
        bool Success, string? CandidateText, string? FreshSha, IReadOnlyList<AnonRoute> StashedFreshRoutes, string? ConflictReason)
    {
        public static PrepareResult Ok(string candidate, string sha, IReadOnlyList<AnonRoute> freshRoutes) =>
            new(true, candidate, sha, freshRoutes, null);

        public static PrepareResult Conflict(string reason) =>
            new(false, null, null, Array.Empty<AnonRoute>(), reason);
    }
}

/// <summary>A candidate server for a route row's <c>server_name</c> (anonymizable proto + name).</summary>
public sealed record RouteServerCandidate(string Name, StampProtocol Protocol);

/// <summary>A candidate relay for a route row's <c>via</c> list, carrying its proto for the pairing filter.</summary>
public sealed record RouteRelayCandidate(string Name, StampProtocol Protocol);

/// <summary>One editable route row: a server (or <c>*</c>) and its via relays, plus the proto-matched
/// relay candidates the builder offers for THIS row (IC-7 pairing filter — a mismatch silently kills the server).</summary>
public sealed partial class RouteRowViewModel : ObservableObject
{
    public string ServerName { get; }

    /// <summary>The relays this route is via (relay names, <c>*</c>, or validated relay sdns:// stamps).</summary>
    public IReadOnlyList<string> Via { get; }

    /// <summary>The via relay names offered for this row — filtered to the server's matching relay proto.</summary>
    public IReadOnlyList<string> ViaCandidates { get; }

    public RouteRowViewModel(string serverName, IReadOnlyList<string> via, IReadOnlyList<string> viaCandidates)
    {
        ServerName = serverName;
        Via = via;
        ViaCandidates = viaCandidates;
    }
}
