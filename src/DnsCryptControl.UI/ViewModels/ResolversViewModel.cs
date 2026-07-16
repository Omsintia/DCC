using System;
using System.Collections.Generic;
using System.Globalization;
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
/// The Resolvers tab (Phase 5c, C1–C3): browses the proxy's cached resolver/relay lists,
/// projects the A5 honesty engine's verdicts into enabled/greyed rows, and (C3) runs a
/// consented, kill-switch-aware latency probe. Pure POCO <see cref="ObservableObject"/>
/// (IC-5): zero WPF types; every post-await observable write goes through
/// <see cref="IUiDispatcher.Post"/>; injectable seams keep tests deterministic.
///
/// <para>Config mutation (C2) rides the 5b Save &amp; apply pipeline with a fresh
/// read-modify-write + explicit divergence detection (IC-9) — the VM stages edits as
/// <see cref="StagedOp"/> records and never trusts a load-time doc snapshot at save time.</para>
/// </summary>
public sealed partial class ResolversViewModel : ObservableObject, IDisposable
{
    // dnscrypt-proxy clamps refresh_delay to [25,169] hours (ConfigCatalog note; the doc-string
    // "24..168" is wrong). The header shows the EFFECTIVE clamped value the proxy would use.
    private const int RefreshDelayMinHours = 25;
    private const int RefreshDelayMaxHours = 169;

    private readonly IConfigFileService _configFile;
    private readonly IResolverListReader _listReader;
    private readonly IHelperClient _helper;
    private readonly IUiStateStore _stateStore;
    private readonly IUiDispatcher _ui;
    private readonly ILatencyProber _prober;
    private readonly IProbeGate _probeGate;

    /// <summary>The selection config read at load time — the browse-time baseline picks/toggles diverge against (IC-9).</summary>
    private ServerSelectionConfig? _loadedSelection;

    /// <summary>The list snapshots read at load time — re-evaluated against the staged config for the zero-pool block.</summary>
    private IReadOnlyList<ResolverListSnapshot> _loadedLists = Array.Empty<ResolverListSnapshot>();

    /// <summary>All rows before the search filter (the filter is applied over this).</summary>
    private IReadOnlyList<ResolverRowViewModel> _allRows = Array.Empty<ResolverRowViewModel>();

    /// <summary>5j: true iff the loaded lists contain ANY ODoH stamp. ODoH targets/relays live in
    /// separate source lists (odoh-servers/odoh-relays) that aren't in dnscrypt-proxy's default
    /// sources, and this offline-by-design app never downloads them — so this is normally false,
    /// which is why checking the ODoH facet empties the list. Drives <see cref="ShowOdohEmptyHint"/>.</summary>
    private bool _anyOdohStampsLoaded;

    /// <summary>The set of favorite names loaded from the UI state store.</summary>
    private HashSet<string> _favorites = new(StringComparer.Ordinal);

    /// <summary>The staged edits awaiting Save &amp; apply (C2, IC-9). Keyed by config key path.</summary>
    private readonly Dictionary<string, StagedOp> _staged = new(StringComparer.Ordinal);

    /// <summary>The current latency-probe session (C3): CTS + token, mirroring the ConfigurationViewModel busy discipline.</summary>
    private ProbeSession? _probeSession;

    [ObservableProperty]
    private IReadOnlyList<ResolverRowViewModel> _rows = Array.Empty<ResolverRowViewModel>();

    [ObservableProperty]
    private IReadOnlyList<ResolverSourceHeader> _sources = Array.Empty<ResolverSourceHeader>();

    /// <summary>Search box: case-insensitive contains over name/description/source.</summary>
    [ObservableProperty]
    private string _searchText = string.Empty;

    /// <summary>Automatic (server_names empty) vs Manual (server_names present &amp; non-empty).</summary>
    [ObservableProperty]
    private bool _isManualMode;

    // 5g-1 view-side facet filters: the 8 chips narrow the VISIBLE list only and never write
    // config (Configuration → Server selection owns the proxy's own rules). All default FALSE
    // (= facet inactive = show everything); checking narrows. OR within a facet category,
    // AND across categories; a property chip requires EVERY stamp (multi-stamp honesty).
    [ObservableProperty]
    private bool _filterDnsCrypt;

    [ObservableProperty]
    private bool _filterDoh;

    [ObservableProperty]
    private bool _filterOdoh;

    [ObservableProperty]
    private bool _filterDnssec;

    [ObservableProperty]
    private bool _filterNolog;

    [ObservableProperty]
    private bool _filterNofilter;

    [ObservableProperty]
    private bool _filterIpv4;

    [ObservableProperty]
    private bool _filterIpv6;

    /// <summary>Protocol-filter mode for the DNSCrypt/DoH/ODoH chips: false = "any" (a server matches
    /// if ANY of its stamps is the checked protocol — the honest capability filter, the default), true =
    /// "only" (a server matches only if EVERY stamp is the checked protocol, e.g. DoH-only servers).
    /// Most public resolvers carry both a DNSCrypt AND a DoH stamp, so "any" DoH barely shrinks the list
    /// while "only" DoH isolates the exclusively-DoH servers. A view filter — never written to config.</summary>
    [ObservableProperty]
    private bool _protocolFilterExclusive;

    // Kind facet: the list mixes queryable SERVERS with routing RELAYS (a DNSCrypt/ODoH relay is
    // infrastructure, not something you pool). Neither checked = show both (default). "Servers" = only
    // servers; "Relays" = only relays; OR within this category, AND across categories (e.g. DNSCrypt +
    // Relays = DNSCrypt relays). A view filter — never written to config.
    [ObservableProperty]
    private bool _filterServers;

    [ObservableProperty]
    private bool _filterRelays;

    /// <summary>Pristine zero-pool fatal state (anti-false-badge, mirror ConfigurationViewModel):
    /// non-null when the LOADED config yields no live server — a total DNS outage the proxy
    /// refuses to start on.</summary>
    [ObservableProperty]
    private string? _zeroPoolWarning;

    /// <summary>Pristine missing-pinned warning: names in <c>server_names</c> not present in any list.</summary>
    [ObservableProperty]
    private IReadOnlyList<string> _missingPinnedNames = Array.Empty<string>();

    /// <summary>The effective pool count from the LOADED config (drives the header honesty).</summary>
    [ObservableProperty]
    private int _effectivePoolCount;

    [ObservableProperty]
    private bool _loadFailed;

    [ObservableProperty]
    private string? _loadError;

    // ---- C2 staged-write + save surfaces ----

    /// <summary>True when there are staged edits awaiting Save &amp; apply.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanSave))]
    [NotifyPropertyChangedFor(nameof(CanRevert))]
    [NotifyCanExecuteChangedFor(nameof(SaveAndApplyCommand))]
    [NotifyCanExecuteChangedFor(nameof(RevertCommand))]
    [NotifyPropertyChangedFor(nameof(CanAddOdohSources))]
    [NotifyCanExecuteChangedFor(nameof(AddOdohSourcesCommand))]
    private bool _isDirty;

    /// <summary>Single busy owner: true while a Save &amp; apply is in flight (mirrors ConfigurationViewModel).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanSave))]
    [NotifyPropertyChangedFor(nameof(CanRevert))]
    [NotifyCanExecuteChangedFor(nameof(SaveAndApplyCommand))]
    [NotifyCanExecuteChangedFor(nameof(RevertCommand))]
    [NotifyPropertyChangedFor(nameof(CanAddOdohSources))]
    [NotifyCanExecuteChangedFor(nameof(AddOdohSourcesCommand))]
    private bool _isBusy;

    /// <summary>UI-local save block (IC-14, SaveBlockedReason-style): non-null disables Save with the reason.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanSave))]
    [NotifyCanExecuteChangedFor(nameof(SaveAndApplyCommand))]
    private string? _saveBlockedReason;

    /// <summary>The single-server warning (U2): non-null after "Use only this server" pins one name.</summary>
    [ObservableProperty]
    private string? _singleServerWarning;

    /// <summary>R3 non-blocking staged zero-pool degrade warning: set when the staged pool would be zero
    /// but no source snapshot is Fresh (a stale list can't authoritatively hard-block, but must not
    /// degrade to SILENCE — sec-F8). Dedicated surface (not the fragile SingleServerWarning, which picks
    /// overwrite/clear); mirrors the AnonymizedDnsViewModel ZeroPoolWarning convention.</summary>
    [ObservableProperty]
    private string? _zeroPoolStagedWarning;

    /// <summary>R2 non-blocking post-save honesty warning: set after a landed save when a staged pinned
    /// server_name is in the FRESH doc's disabled_server_names — the proxy excludes it (disabled beats a
    /// manual pick), so a clean "saved and applied" would be dishonest. Names the offending value (IC-10).</summary>
    [ObservableProperty]
    private string? _disabledPickWarning;

    /// <summary>Transient "saved" notice, cleared by the next edit/save.</summary>
    [ObservableProperty]
    private string? _saveNotice;

    /// <summary>The helper's refusal message shown verbatim (IC-10), or the orchestration error.</summary>
    [ObservableProperty]
    private string? _saveError;

    /// <summary>IC-9 divergence banner (non-null = shown): the config changed under the staged edits.</summary>
    [ObservableProperty]
    private string? _conflictMessage;

    /// <summary>Version-skew banner (HelperIncompatible).</summary>
    [ObservableProperty]
    private string? _helperIncompatibleMessage;

    /// <summary>Persistent non-green state: written but the restart failed / reply lost.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanRevert))]
    [NotifyCanExecuteChangedFor(nameof(RevertCommand))]
    private string? _restartFailedMessage;

    /// <summary>Persistent error state (never green): written + restarted but the proxy never reported running.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanRevert))]
    [NotifyCanExecuteChangedFor(nameof(RevertCommand))]
    private string? _proxyRejectedMessage;

    // ---- C3 latency-probe surfaces ----

    /// <summary>The pending "Test all" consent (P5c-U1): non-null while a batch consent is
    /// awaiting confirm/cancel; carries the exact target count the dialog states. The view's
    /// code-behind only shows/routes it — it is VM state, testable without WPF.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(TestAllLatenciesCommand))]
    private PendingConsentRequest? _pendingConsentRequest;

    /// <summary>True while a probe session is running (the batch button + per-row clicks are no-ops).</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(TestAllLatenciesCommand))]
    private bool _isProbing;

    /// <summary>Set when probing is disabled by the offline gate (with a reason the view shows).</summary>
    [ObservableProperty]
    private string? _probingDisabledReason;

    /// <summary>Lowercase-hex SHA-256 of the on-disk bytes as loaded — the C2 save CAS base.</summary>
    public string? BaseSha256 { get; private set; }

    public ResolversViewModel(
        IConfigFileService configFile,
        IResolverListReader listReader,
        IHelperClient helper,
        IUiStateStore stateStore,
        IUiDispatcher ui,
        ILatencyProber prober,
        IProbeGate probeGate)
    {
        ArgumentNullException.ThrowIfNull(configFile);
        ArgumentNullException.ThrowIfNull(listReader);
        ArgumentNullException.ThrowIfNull(helper);
        ArgumentNullException.ThrowIfNull(stateStore);
        ArgumentNullException.ThrowIfNull(ui);
        ArgumentNullException.ThrowIfNull(prober);
        ArgumentNullException.ThrowIfNull(probeGate);
        _configFile = configFile;
        _listReader = listReader;
        _helper = helper;
        _stateStore = stateStore;
        _ui = ui;
        _prober = prober;
        _probeGate = probeGate;
    }

    // --------------------------------------------------------------- C1: load + browse

    /// <summary>
    /// Loads the config + cached lists off the UI thread, runs the A5 evaluation, and
    /// publishes the whole projected object graph in ONE dispatcher post (5b LoadAsync
    /// shape). Fail-closed: never throws. The pristine guards (zero-pool + missing-pinned)
    /// run over the LOADED on-disk doc so a false green never paints on first load.
    /// </summary>
    public async Task LoadAsync(CancellationToken ct)
    {
        // Any in-flight probe session dies with the reload (C3): its results describe the
        // pre-reload rows, so it must never publish over the fresh baseline.
        CancelProbeSession();

        var snapshot = await Task.Run(() => LoadSnapshot(), ct).ConfigureAwait(false);

        _ui.Post(() =>
        {
            // A reload cancels any probe session and clears its transient UI state (a probe
            // describes an event; its results never survive a reload — C3).
            CancelProbeSession();
            IsProbing = false;
            PendingConsentRequest = null;
            ProbingDisabledReason = null;
            if (!snapshot.Success)
            {
                _loadedSelection = null;
                _loadedLists = Array.Empty<ResolverListSnapshot>();
                BaseSha256 = null;
                _allRows = Array.Empty<ResolverRowViewModel>();
                _anyOdohStampsLoaded = false;
                Rows = Array.Empty<ResolverRowViewModel>();
                Sources = Array.Empty<ResolverSourceHeader>();
                ZeroPoolWarning = null;
                MissingPinnedNames = Array.Empty<string>();
                EffectivePoolCount = 0;
                ClearStagedInternal();
                LoadError = snapshot.Error;
                LoadFailed = true;
                return;
            }

            _loadedSelection = snapshot.Selection;
            _loadedLists = snapshot.Lists;
            BaseSha256 = snapshot.Sha256;
            _favorites = snapshot.Favorites;
            _allRows = snapshot.Rows;
            _anyOdohStampsLoaded = snapshot.Rows.Any(r => r.Facets.HasOdohFamily);
            Sources = snapshot.Headers;

            IsManualMode = snapshot.Selection.IsManual;

            // Pristine guards (anti-false-badge): surface the on-disk pool truth on first paint.
            EffectivePoolCount = snapshot.Pool.EffectiveCount;
            MissingPinnedNames = snapshot.Pool.MissingPinnedNames;
            ZeroPoolWarning = snapshot.Pool.IsZeroPool
                ? "No resolver would be live with this configuration — the proxy will not start (total DNS outage). Fix the filters or picks below."
                : null;

            ClearStagedInternal();
            // R4: a clean reload clears the stale "restart failed — status unverified" banner (mirrors
            // ConfigurationViewModel.LoadAsync + the AnonymizedDnsViewModel precedent — a successful refresh
            // is a documented RestartFailed exit). ProxyRejectedMessage deliberately SURVIVES a reload (its
            // only exits are Applied or Revert), so it is NOT cleared here.
            RestartFailedMessage = null;
            LoadError = null;
            LoadFailed = false;
            ApplySearch();
        });
    }

    /// <summary>Off-thread: read config + lists, evaluate, project rows. Never throws.</summary>
    private LoadSnapshotResult LoadSnapshot()
    {
        ConfigLoadResult load;
        try
        {
            load = _configFile.Load();
        }
        catch (Exception ex)
        {
            // Fail-closed: any fault becomes a load-failed state, never a throw. CA1031 is
            // suppressed for this file in .editorconfig (safety concern for this OPSEC tool).
            return LoadSnapshotResult.Fail(ex.Message);
        }

        if (!load.Success)
            return LoadSnapshotResult.Fail(load.Error ?? "the config could not be read");

        TomlConfigDocument doc;
        ServerSelectionConfig selectionConfig;
        IReadOnlyList<ResolverListSnapshot> lists;
        UiState uiState;
        try
        {
            doc = TomlConfigDocument.Parse(load.Text!);
            selectionConfig = ServerSelectionConfig.FromDocument(doc);
            lists = _listReader.ReadAll();
            uiState = _stateStore.Load();
        }
        catch (Exception ex)
        {
            // Fail-closed: a hostile config/list must degrade to a load-failed state, not crash.
            return LoadSnapshotResult.Fail(ex.Message);
        }

        var favorites = new HashSet<string>(uiState.Favorites, StringComparer.Ordinal);

        // Evaluate the whole pool ACROSS all sources (the proxy dedups by prefixed name).
        var allEntries = lists.SelectMany(s => s.Entries).ToArray();
        var result = ServerSelection.Evaluate(allEntries, selectionConfig);
        var verdictByEntry = new Dictionary<ResolverListEntry, ServerEvaluation>(ReferenceEqualityComparer.Instance);
        foreach (var eval in result.Evaluations)
            verdictByEntry[eval.Entry] = eval;

        var rows = new List<ResolverRowViewModel>(allEntries.Length);
        var headers = new List<ResolverSourceHeader>(lists.Count);
        foreach (var list in lists)
        {
            headers.Add(BuildHeader(list, doc));
            foreach (var entry in list.Entries)
            {
                var eval = verdictByEntry[entry];
                rows.Add(BuildRow(entry, list.SourceName, eval, favorites));
            }
        }

        return LoadSnapshotResult.Ok(
            load.Sha256!, selectionConfig, result.Pool, favorites, rows, headers, lists);
    }

    private static ResolverSourceHeader BuildHeader(ResolverListSnapshot list, TomlConfigDocument doc)
    {
        int? refreshHours = null;
        if (doc.TryGetSubTables("sources", out var subTables))
        {
            var sub = subTables.FirstOrDefault(t => string.Equals(t.Name, list.SourceName, StringComparison.Ordinal));
            if (sub is not null && sub.TryGetLong("refresh_delay", out var raw))
                refreshHours = Math.Clamp((int)Math.Clamp(raw, int.MinValue, int.MaxValue), RefreshDelayMinHours, RefreshDelayMaxHours);
        }

        var text = list.State switch
        {
            ResolverListState.Fresh => "list loaded from the proxy's cache",
            ResolverListState.Bundled => "bundled snapshot — may be outdated",
            ResolverListState.Missing => "lists not yet downloaded — start the proxy to fetch them",
            ResolverListState.Unreadable => "cache file present but could not be read",
            ResolverListState.ParseFailed => "cache file present but is not a valid list",
            _ => "unknown list state",
        };
        return new ResolverSourceHeader(list.SourceName, list.State, list.LastCheckedUtc, refreshHours, text);
    }

    private static ResolverRowViewModel BuildRow(
        ResolverListEntry entry, string sourceName, ServerEvaluation eval, HashSet<string> favorites)
    {
        var stamp = entry.Stamps.Count > 0 ? entry.Stamps[0] : null;
        var chips = BuildChips(entry, stamp);
        var reason = eval.Verdict == SelectionVerdict.Included ? null : DescribeVerdict(eval.Verdict);
        var location = ResolverDisplay.GuessLocation(entry.Description);
        return new ResolverRowViewModel(
            entry.Name,
            sourceName,
            Truncate(entry.Description, 4096),
            location,
            chips,
            eval.IsRelay,
            eval.Verdict,
            eval.Verdict == SelectionVerdict.Included,
            reason,
            entry.IsSelectable,
            stamp,
            BuildStampDisplays(entry.Stamps),
            BuildFacets(entry.Stamps),
            favorites.Contains(entry.Name));
    }

    /// <summary>5g-5: projects EVERY parsed stamp for the detail pane (SelectedStamp stays stamps[0] — IC-16).</summary>
    private static StampDisplay[] BuildStampDisplays(IReadOnlyList<ServerStamp> stamps)
    {
        if (stamps.Count == 0) return Array.Empty<StampDisplay>();
        var result = new StampDisplay[stamps.Count];
        for (var i = 0; i < stamps.Count; i++)
        {
            var s = stamps[i];
            var endpoint = ResolverDisplay.Endpoint(s); // shared with the Dashboard panel (5h)
            var provider = s.Protocol is StampProtocol.DnsCrypt or StampProtocol.DnsCryptRelay
                ? s.ProviderName
                : s.Hostname;
            // Don't repeat the endpoint as the provider (hostname-only stamps fall back to it).
            if (string.Equals(provider, endpoint, StringComparison.Ordinal)) provider = null;
            result[i] = new StampDisplay(ResolverDisplay.ProtocolChip(s.Protocol), endpoint, provider);
        }
        return result;
    }

    /// <summary>5g-1: precomputes the per-row facet facts. Protocol/family = ANY stamp; the
    /// properties = ALL stamps (multi-stamp honesty). Zero stamps match no facet at all.</summary>
    private static ResolverFilterFacets BuildFacets(IReadOnlyList<ServerStamp> stamps)
    {
        if (stamps.Count == 0) return ResolverFilterFacets.None;
        bool dnscrypt = false, doh = false, odoh = false, anyIpv4 = false, anyIpv6 = false;
        bool allDnssec = true, allNoLog = true, allNoFilter = true;
        // "only"-mode facets: true iff EVERY stamp is that protocol family (a DoH-only server has no
        // DNSCrypt/ODoH stamp). Start true, AND per stamp; stamps.Count>0 here, so a surviving true
        // means all stamps matched. Powers the "only" protocol filter (isolate exclusively-DoH servers).
        bool onlyDnsCrypt = true, onlyDoh = true, onlyOdoh = true;
        foreach (var s in stamps)
        {
            var isDnsCrypt = s.Protocol is StampProtocol.DnsCrypt or StampProtocol.DnsCryptRelay;
            var isDoh = s.Protocol == StampProtocol.DoH;
            var isOdoh = s.Protocol is StampProtocol.ODoHTarget or StampProtocol.ODoHRelay;
            if (isDnsCrypt) dnscrypt = true;
            else if (isDoh) doh = true;
            else if (isOdoh) odoh = true;
            onlyDnsCrypt &= isDnsCrypt;
            onlyDoh &= isDoh;
            onlyOdoh &= isOdoh;

            allDnssec &= s.Dnssec;
            allNoLog &= s.NoLog;
            allNoFilter &= s.NoFilter;

            // Family classification mirrored from ServerSelection.FamilyExcludes
            // (src/DnsCryptControl.Core/Sources/ServerSelection.cs:198-209) — proxy-faithful:
            // default IPv4-only; DoH ⇒ dual-family; an AddressIp containing ':' ⇒ IPv6-only.
            var isIpv4 = true;
            var isIpv6 = false;
            if (s.Protocol == StampProtocol.DoH) { isIpv4 = true; isIpv6 = true; }
            if (s.AddressIp is { } ip && ip.Contains(':')) { isIpv4 = false; isIpv6 = true; }
            anyIpv4 |= isIpv4;
            anyIpv6 |= isIpv6;
        }
        return new ResolverFilterFacets(
            dnscrypt, doh, odoh, allDnssec, allNoLog, allNoFilter, anyIpv4, anyIpv6,
            onlyDnsCrypt, onlyDoh, onlyOdoh);
    }

    private static List<string> BuildChips(ResolverListEntry entry, ServerStamp? stamp)
    {
        var chips = new List<string>();
        if (stamp is null)
        {
            chips.Add("no usable stamp");
            return chips;
        }

        // A server can carry stamps of DIFFERENT protocols (e.g. cloudflare = DNSCrypt + DoH). Show a chip
        // for EVERY distinct protocol so the list is honest about multi-protocol servers — the protocol
        // filter matches on ANY stamp, so a lone stamps[0] chip made the filter look like it was lying
        // (a "DNSCrypt"-chipped row still matched the DoH filter). Order-preserving, deduped.
        var seenProtocols = new HashSet<StampProtocol>();
        foreach (var s in entry.Stamps)
        {
            if (seenProtocols.Add(s.Protocol))
                chips.Add(ResolverDisplay.ProtocolChip(s.Protocol));
        }
        if (stamp.Dnssec) chips.Add("DNSSEC");
        if (stamp.NoLog) chips.Add("no-log");
        if (stamp.NoFilter) chips.Add("no-filter");
        if (stamp.Port is 53 or 853) chips.Add(":" + stamp.Port.ToString(CultureInfo.InvariantCulture));
        if (entry.Stamps.Count > 1) chips.Add(entry.Stamps.Count.ToString(CultureInfo.InvariantCulture) + " stamps");
        return chips;
    }

    private static string DescribeVerdict(SelectionVerdict verdict) => verdict switch
    {
        SelectionVerdict.ExcludedByServerNames => "not in server_names (Manual mode)",
        SelectionVerdict.ExcludedByRequiredProps => "does not satisfy the require_* filters",
        SelectionVerdict.ExcludedByProtocolToggle => "excluded by a protocol toggle",
        SelectionVerdict.ExcludedByFamilyToggle => "excluded by an IP-family toggle",
        SelectionVerdict.ExcludedByDisabled => "in disabled_server_names",
        SelectionVerdict.UnsupportedProtocol => "protocol not usable as an upstream",
        SelectionVerdict.Nondeterministic => "mixed stamps — the proxy picks one of N at random",
        SelectionVerdict.NoUsableStamp => "no usable stamp parsed",
        _ => "excluded",
    };

    private static string Truncate(string s, int max) => s.Length <= max ? s : s.Substring(0, max);

    // --------------------------------------------------------------- C1: search + facet filter

    partial void OnSearchTextChanged(string value) => ApplySearch();

    partial void OnFilterDnsCryptChanged(bool value) => ApplySearch();

    partial void OnFilterDohChanged(bool value) => ApplySearch();

    partial void OnFilterOdohChanged(bool value) => ApplySearch();

    partial void OnFilterDnssecChanged(bool value) => ApplySearch();

    partial void OnFilterNologChanged(bool value) => ApplySearch();

    partial void OnFilterNofilterChanged(bool value) => ApplySearch();

    partial void OnFilterIpv4Changed(bool value) => ApplySearch();

    partial void OnFilterIpv6Changed(bool value) => ApplySearch();

    partial void OnProtocolFilterExclusiveChanged(bool value) => ApplySearch();

    partial void OnFilterServersChanged(bool value) => ApplySearch();

    partial void OnFilterRelaysChanged(bool value) => ApplySearch();

    /// <summary>5j: the ODoH facet is checked but no ODoH stamps are loaded — the reported
    /// "check ODoH → blank list" case. This is CORRECT behavior (not a filter bug): ODoH targets
    /// come from a separate source list not enabled by default, and this offline app can't fetch it.
    /// The explainer keeps the app honest instead of leaving an unexplained empty list.</summary>
    public bool ShowOdohEmptyHint => !LoadFailed && Rows.Count == 0 && FilterOdoh && !_anyOdohStampsLoaded;

    /// <summary>A visible count so a near-no-op protocol filter reads as truth rather than a broken filter
    /// (checking "DoH" barely shrinks a DoH-heavy list). Empty until the first load; "N listed" when nothing
    /// is filtered, "showing N of M" when a search/facet narrows the list. Recomputed on every ApplySearch.</summary>
    public string FilterSummary =>
        _allRows.Count == 0
            ? string.Empty
            : Rows.Count == _allRows.Count
                ? $"{_allRows.Count} listed"
                : $"showing {Rows.Count} of {_allRows.Count}";

    /// <summary>5j: generic empty-state — a search/facet is active and matched nothing (and it is
    /// NOT the special ODoH-source case, which shows its own actionable explainer above).</summary>
    public bool ShowNoMatchHint =>
        !LoadFailed
        && Rows.Count == 0
        && (SearchText.Trim().Length > 0
            || FilterDnsCrypt || FilterDoh || FilterOdoh
            || FilterDnssec || FilterNolog || FilterNofilter || FilterIpv4 || FilterIpv6
            || FilterServers || FilterRelays)
        && !ShowOdohEmptyHint;

    /// <summary>5j: the two empty-state hints gate on LoadFailed, but the load-FAILURE path returns
    /// before ApplySearch (their only other raise point), so a flip to failed would otherwise leave a
    /// stale explainer showing over the failed-load view. Re-raise both on every LoadFailed change.</summary>
    partial void OnLoadFailedChanged(bool value)
    {
        OnPropertyChanged(nameof(ShowOdohEmptyHint));
        OnPropertyChanged(nameof(ShowNoMatchHint));
    }

    /// <summary>The single _allRows → Rows choke point: text match AND the 5g-1 facet predicate.
    /// Also refreshes the 5j empty-state hints (single exit so both filter paths raise them).</summary>
    private void ApplySearch()
    {
        var filter = SearchText.Trim();
        var protocolFacetActive = FilterDnsCrypt || FilterDoh || FilterOdoh;
        var familyFacetActive = FilterIpv4 || FilterIpv6;
        var kindFacetActive = FilterServers || FilterRelays;
        var anyFacetActive = protocolFacetActive || familyFacetActive || kindFacetActive
            || FilterDnssec || FilterNolog || FilterNofilter;

        Rows = (filter.Length == 0 && !anyFacetActive)
            ? _allRows
            : _allRows
                .Where(r => MatchesText(r, filter) && MatchesFacets(r, protocolFacetActive, familyFacetActive, kindFacetActive))
                .ToArray();

        OnPropertyChanged(nameof(ShowOdohEmptyHint));
        OnPropertyChanged(nameof(ShowNoMatchHint));
        OnPropertyChanged(nameof(FilterSummary));
    }

    private static bool MatchesText(ResolverRowViewModel r, string filter) =>
        filter.Length == 0
        || r.Name.Contains(filter, StringComparison.OrdinalIgnoreCase)
        || r.Description.Contains(filter, StringComparison.OrdinalIgnoreCase)
        || r.SourceName.Contains(filter, StringComparison.OrdinalIgnoreCase);

    /// <summary>OR within a facet category, AND across categories. A zero-stamp row's facets are
    /// all-false (ResolverFilterFacets.None), so it is hidden whenever any facet is active.</summary>
    private bool MatchesFacets(ResolverRowViewModel r, bool protocolFacetActive, bool familyFacetActive, bool kindFacetActive)
    {
        var f = r.Facets;
        // Kind (server vs relay): OR within the category. A relay is r.IsRelay; a server is !IsRelay.
        if (kindFacetActive && !((FilterServers && !r.IsRelay) || (FilterRelays && r.IsRelay))) return false;

        if (protocolFacetActive)
        {
            // "only" mode requires EVERY stamp to be the checked protocol (exclusive); "any" mode (default)
            // matches a server that supports the protocol on at least one stamp (capability). OR within the
            // protocol category either way.
            var protocolMatch = ProtocolFilterExclusive
                ? (FilterDnsCrypt && f.OnlyDnsCrypt) || (FilterDoh && f.OnlyDoh) || (FilterOdoh && f.OnlyOdoh)
                : (FilterDnsCrypt && f.HasDnsCryptFamily) || (FilterDoh && f.HasDohFamily) || (FilterOdoh && f.HasOdohFamily);
            if (!protocolMatch) return false;
        }

        if (FilterDnssec && !f.AllDnssec) return false;
        if (FilterNolog && !f.AllNoLog) return false;
        if (FilterNofilter && !f.AllNoFilter) return false;
        if (familyFacetActive && !((FilterIpv4 && f.AnyIpv4) || (FilterIpv6 && f.AnyIpv6))) return false;
        return true;
    }

    // --------------------------------------------------------------- C2: staged writes

    /// <summary>The IC-7 injection allowlist: only these characters may become a config name
    /// (delegates to the shared <see cref="ServerNamePolicy"/>).</summary>
    private static bool IsAllowlistedName(string name) => ServerNamePolicy.IsAllowedName(name);

    /// <summary>The effective (staged if present, else loaded) <c>server_names</c> value.</summary>
    private IReadOnlyList<string> EffectiveServerNames()
    {
        if (_staged.TryGetValue("server_names", out var op) && op.FinalArray is { } staged) return staged;
        return _loadedSelection?.ServerNames ?? Array.Empty<string>();
    }

    /// <summary>Stages a <c>server_names</c> array write, recording the browse-time baseline for IC-9 divergence.</summary>
    private void StageServerNames(IReadOnlyList<string> finalNames)
    {
        var browseTime = _loadedSelection?.ServerNames ?? Array.Empty<string>();
        _staged["server_names"] = new StagedOp(
            "server_names", StagedKind.StringArray, null, browseTime, null, finalNames);
        RefreshStagedState();
    }

    private void StageBool(string keyPath, bool loadedValue, bool finalValue)
    {
        _staged[keyPath] = new StagedOp(keyPath, StagedKind.Bool, loadedValue, null, finalValue, null);
        RefreshStagedState();
    }

    /// <summary>Pins EXACTLY this server (U2 "Use only this server"): <c>server_names=[name]</c> + a single-pool warning.</summary>
    public void UseOnlyThisServer(ResolverRowViewModel row)
    {
        ArgumentNullException.ThrowIfNull(row);
        if (!GuardPickable(row)) return;
        StageServerNames(new[] { row.Name });
        SingleServerWarning =
            $"'{row.Name}' is now your only resolver — if it goes down, DNS stops until you add another. Consider 'Add to pool' for redundancy.";
    }

    /// <summary>Appends this server to the pool (U2 "Add to pool"): <c>server_names += name</c> (idempotent).</summary>
    public void AddToPool(ResolverRowViewModel row)
    {
        ArgumentNullException.ThrowIfNull(row);
        if (!GuardPickable(row)) return;
        var current = EffectiveServerNames();
        if (current.Contains(row.Name, StringComparer.Ordinal)) return; // already pinned — no-op
        StageServerNames(current.Append(row.Name).ToArray());
        SingleServerWarning = null;
    }

    /// <summary>Removes this server from the pool (U2 "Remove"): drops it from <c>server_names</c>.</summary>
    public void RemoveFromPool(ResolverRowViewModel row)
    {
        ArgumentNullException.ThrowIfNull(row);
        var current = EffectiveServerNames();
        if (!current.Contains(row.Name, StringComparer.Ordinal)) return; // not pinned — no-op
        StageServerNames(current.Where(n => !string.Equals(n, row.Name, StringComparison.Ordinal)).ToArray());
        SingleServerWarning = null;
    }

    /// <summary>Switches to Automatic mode: stage an empty <c>server_names</c> (the proxy uses require_* filtering).</summary>
    public void SwitchToAutomaticMode()
    {
        StageServerNames(Array.Empty<string>());
        SingleServerWarning = null;
    }

    /// <summary>Stages a protocol/family chip toggle (dnscrypt_servers / doh_servers / … / require_*).</summary>
    public void ToggleFilter(string keyPath, bool enabled)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyPath);
        var loaded = LoadedFlag(keyPath);
        StageBool(keyPath, loaded, enabled);
    }

    private bool LoadedFlag(string keyPath)
    {
        var s = _loadedSelection;
        if (s is null) return false;
        return keyPath switch
        {
            "dnscrypt_servers" => s.DnsCryptServers,
            "doh_servers" => s.DohServers,
            "odoh_servers" => s.ODoHServers,
            "ipv4_servers" => s.Ipv4Servers,
            "ipv6_servers" => s.Ipv6Servers,
            "require_dnssec" => s.RequireDnssec,
            "require_nolog" => s.RequireNolog,
            "require_nofilter" => s.RequireNofilter,
            _ => false,
        };
    }

    /// <summary>IC-7 pick gate: only an IsSelectable (allowlisted name + usable stamp) entry may be written.</summary>
    private bool GuardPickable(ResolverRowViewModel row)
    {
        if (row.IsSelectable && IsAllowlistedName(row.Name)) return true;
        SaveBlockedReason =
            $"'{row.Name}' cannot be selected — its name or stamp is malformed (it would be refused by the config allowlist).";
        return false;
    }

    /// <summary>Recomputes dirty + the zero-pool save block after a staging change.</summary>
    private void RefreshStagedState()
    {
        IsDirty = _staged.Count > 0;
        SaveNotice = null;
        RecomputeSaveBlock();
    }

    /// <summary>The selection config with every staged op applied over the loaded baseline.</summary>
    private ServerSelectionConfig EffectiveStagedSelection()
    {
        var b = _loadedSelection ?? ServerSelectionConfig.FromDocument(TomlConfigDocument.Parse(""));
        bool Flag(string key, bool loaded) =>
            _staged.TryGetValue(key, out var op) && op.FinalBool is { } v ? v : loaded;
        var names = _staged.TryGetValue("server_names", out var so) && so.FinalArray is { } n ? n : b.ServerNames;
        return new ServerSelectionConfig(
            names, b.DisabledServerNames,
            Ipv4Servers: Flag("ipv4_servers", b.Ipv4Servers),
            Ipv6Servers: Flag("ipv6_servers", b.Ipv6Servers),
            DnsCryptServers: Flag("dnscrypt_servers", b.DnsCryptServers),
            DohServers: Flag("doh_servers", b.DohServers),
            ODoHServers: Flag("odoh_servers", b.ODoHServers),
            RequireDnssec: Flag("require_dnssec", b.RequireDnssec),
            RequireNolog: Flag("require_nolog", b.RequireNolog),
            RequireNofilter: Flag("require_nofilter", b.RequireNofilter));
    }

    /// <summary>
    /// UI-local zero-pool block (IC-14, E6): re-evaluate A5 over the loaded snapshots with the
    /// STAGED config; a staged pool of zero live servers blocks Save. If NO source snapshot is
    /// Fresh (the lists are stale/missing/bundled), the block degrades to a warning naming the
    /// list state — a stale list is not authoritative enough to hard-block a save (sec-F8).
    /// </summary>
    private void RecomputeSaveBlock()
    {
        SaveBlockedReason = null;
        ZeroPoolStagedWarning = null;
        if (_staged.Count == 0) return;

        var entries = _loadedLists.SelectMany(s => s.Entries).ToArray();
        var result = ServerSelection.Evaluate(entries, EffectiveStagedSelection());
        if (!result.Pool.IsZeroPool) return;

        var anyFresh = _loadedLists.Any(s => s.State == ResolverListState.Fresh);
        if (anyFresh)
        {
            SaveBlockedReason =
                "These changes would leave zero live resolvers — the proxy would refuse to start (total DNS outage). Adjust your picks or filters before saving.";
        }
        else
        {
            // R3/sec-F8: a non-Fresh list can't authoritatively hard-block, but degrading to SILENCE lets
            // the user save a DNS-bricking config with no feedback. Surface a dedicated non-blocking warning
            // naming the list state (not SingleServerWarning, which picks overwrite/clear).
            var states = _loadedLists.Count > 0
                ? string.Join(", ", _loadedLists.Select(s => s.State).Distinct())
                : "unavailable";
            ZeroPoolStagedWarning =
                $"These changes may leave zero live resolvers, but the resolver lists are not fresh ({states}) — start the proxy to refresh them, then re-check.";
        }
    }

    // --------------------------------------------------------------- C2: Save & apply

    /// <summary>Save enable gate: dirty, not blocked, and idle.</summary>
    public bool CanSave => IsDirty && SaveBlockedReason is null && !IsBusy;

    /// <summary>Revert enable gate: dirty or in a persistent post-save failure state, and idle.</summary>
    public bool CanRevert =>
        !IsBusy && (IsDirty || RestartFailedMessage is not null || ProxyRejectedMessage is not null);

    /// <summary>The Revert button label (mirrors ConfigurationViewModel).</summary>
    public const string RevertLabel = "Revert to on-disk config";

    /// <summary>
    /// Save &amp; apply (IC-9): fresh <see cref="IConfigFileService.Load"/> → build a fresh doc →
    /// ABORT with a preserved staged set + a Conflict banner when ANY of: (a) fresh load fails,
    /// (b) fresh doc HasErrors, (c) any staged op's key now reads ≠ its browse-time value. Only a
    /// divergence-free fresh doc is mutated (each StagedFinalValue via the mutators) and dispatched
    /// to <see cref="IConfigFileService.SaveAndApplyAsync"/> with the FRESH sha. Non-cancellable.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanSave))]
    private async Task SaveAndApplyAsync()
    {
        if (IsBusy || !IsDirty || SaveBlockedReason is not null) return;

        // A reload cancels any probe session first (its results describe the pre-save rows).
        CancelProbeSession();

        // Snapshot the ops this save will dispatch (editedMidFlight: the outcome handler removes
        // EXACTLY these, leaving ops staged during the save intact — mvvm-F4).
        var dispatched = _staged.Values.ToArray();

        IsBusy = true;
        SaveNotice = null;
        SaveError = null;
        ConflictMessage = null;
        HelperIncompatibleMessage = null;
        try
        {
            // Fresh read-modify-write off the UI thread.
            var prepared = await Task.Run(() => PrepareSave(dispatched), CancellationToken.None).ConfigureAwait(false);
            if (!prepared.Success)
            {
                _ui.Post(() => ConflictMessage = prepared.ConflictReason);
                return;
            }

            var outcome = await _configFile
                .SaveAndApplyAsync(prepared.CandidateText!, prepared.FreshSha!, CancellationToken.None)
                .ConfigureAwait(false);
            await ApplySaveOutcomeAsync(outcome, dispatched, prepared.DisabledPins).ConfigureAwait(false);
        }
        finally
        {
            _ui.Post(() => IsBusy = false);
        }
    }

    /// <summary>IC-9 fresh read + divergence check + candidate build. Off-thread; never throws.</summary>
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

        // (c) any staged op's key now reads != its browse-time value.
        foreach (var op in ops)
        {
            if (Diverged(doc, op))
                return PrepareResult.Conflict(
                    $"'{op.KeyPath}' changed on disk since you staged your edit — Reload to review; your staged changes stay until you Reload/Revert.");
        }

        // R2: a staged server_names pick that is ALSO in the fresh doc's disabled_server_names lands
        // dishonestly — the proxy excludes it (disabled beats a manual pick), so a clean "saved and
        // applied" would claim a pick that never goes live. Surface these names as a post-save warning
        // (non-blocking: cloudflare still resolves; only the disabled pick is inert). disabled_server_names
        // is never staged here, so this is read from the FRESH doc.
        var disabledPins = Array.Empty<string>();
        var serverNamesOp = ops.FirstOrDefault(o => o.KeyPath == "server_names");
        if (serverNamesOp?.FinalArray is { } stagedNames && stagedNames.Count > 0)
        {
            var freshDisabled = doc.TryGetStringArray("disabled_server_names", out var d) ? d : Array.Empty<string>();
            if (freshDisabled.Count > 0)
            {
                var disabledSet = new HashSet<string>(freshDisabled, StringComparer.Ordinal);
                disabledPins = stagedNames.Where(disabledSet.Contains).Distinct(StringComparer.Ordinal).ToArray();
            }
        }

        // Apply each staged final value onto the divergence-free fresh doc.
        try
        {
            foreach (var op in ops)
            {
                if (op.Kind == StagedKind.Bool && op.FinalBool is { } b) doc.SetBool(op.KeyPath, b);
                else if (op.Kind == StagedKind.StringArray && op.FinalArray is { } a) doc.SetStringArray(op.KeyPath, a);
            }
        }
        catch (Exception ex)
        {
            return PrepareResult.Conflict("the staged changes could not be applied (" + ex.Message + ") — Reload to review.");
        }

        return PrepareResult.Ok(doc.ToText(), fresh.Sha256!, disabledPins);
    }

    /// <summary>True when the fresh doc's value for this op's key differs from its browse-time baseline (IC-9c).</summary>
    private static bool Diverged(TomlConfigDocument doc, StagedOp op)
    {
        if (op.Kind == StagedKind.Bool)
        {
            var browse = op.BrowseTimeBool ?? false;
            var present = doc.TryGetBool(op.KeyPath, out var now);
            // Absent reads as the loaded default the browse-time value already reflects; compare presence-aware.
            return present ? now != browse : browse != DefaultFlag(op.KeyPath);
        }

        var browseArr = op.BrowseTimeArray ?? Array.Empty<string>();
        var freshArr = doc.TryGetStringArray(op.KeyPath, out var v) ? v : Array.Empty<string>();
        return !freshArr.SequenceEqual(browseArr, StringComparer.Ordinal);
    }

    private static bool DefaultFlag(string keyPath) => keyPath switch
    {
        "dnscrypt_servers" or "doh_servers" or "ipv4_servers" => true,
        _ => false,
    };

    /// <summary>Maps a save outcome onto the state surfaces (reload-first ordering, mirror ConfigurationViewModel).
    /// <paramref name="dispatched"/> is the exact op snapshot the save sent: on a write-landed
    /// outcome exactly those ops are removed, leaving ops staged mid-flight intact (mvvm-F4).</summary>
    private async Task ApplySaveOutcomeAsync(
        ConfigSaveOutcome outcome, IReadOnlyList<StagedOp> dispatched, IReadOnlyList<string> disabledPins)
    {
        switch (outcome.Kind)
        {
            case ConfigSaveOutcomeKind.Applied:
                RemoveDispatchedOps(dispatched);
                if (_staged.Count == 0)
                {
                    await LoadAsync(CancellationToken.None).ConfigureAwait(false);
                    _ui.Post(() =>
                    {
                        ProxyRejectedMessage = null;
                        SaveNotice = "Configuration saved and applied.";
                        SetDisabledPickWarning(disabledPins);
                    });
                }
                else
                {
                    _ui.Post(() =>
                    {
                        ProxyRejectedMessage = null;
                        SaveNotice = "Configuration saved and applied — an edit made during the save is still unsaved.";
                        SetDisabledPickWarning(disabledPins);
                    });
                }
                break;

            case ConfigSaveOutcomeKind.RestartFailed:
                RemoveDispatchedOps(dispatched);
                if (_staged.Count == 0)
                    await LoadAsync(CancellationToken.None).ConfigureAwait(false);
                _ui.Post(() =>
                {
                    RestartFailedMessage = outcome.Message
                        ?? "config saved, but the proxy restart failed — status unverified";
                    SetDisabledPickWarning(disabledPins);
                });
                break;

            case ConfigSaveOutcomeKind.ProxyRejected:
                RemoveDispatchedOps(dispatched);
                if (_staged.Count == 0)
                    await LoadAsync(CancellationToken.None).ConfigureAwait(false);
                _ui.Post(() =>
                {
                    ProxyRejectedMessage = outcome.Message
                        ?? "new config rejected by proxy — Revert or re-edit";
                    SetDisabledPickWarning(disabledPins);
                });
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

    // ------------------------------------------------------- ODoH behind the kill switch: bootstrap + anchor

    /// <summary>The loopback bootstrap endpoint the ODoH-behind-kill-switch flow writes. The proxy resolves
    /// hostname-based ODoH targets by querying its OWN listener (re-encrypted upstream on :443), so no
    /// plaintext :53 ever leaves the machine and loopback is firewall-exempt — it works with the kill switch
    /// ARMED (proven M102/N41). Written EXACTLY (a remote :53 left here would strand ODoH AND trip the OPSEC gate).</summary>
    private const string LoopbackBootstrapEndpoint = "127.0.0.1:53";

    /// <summary>Non-null after Add-ODoH when the config has NO plain (unrouted) DNSCrypt server for the
    /// loopback bootstrap to resolve ODoH hostnames through — ODoH cannot start behind the kill switch
    /// without one. Guidance, never a block (the DNSCrypt servers still resolve).</summary>
    [ObservableProperty]
    private string? _bootstrapAnchorWarning;

    // ------------------------------------------------------- 5j: Add ODoH source lists

    /// <summary>The canonical v3 ODoH source URLs the PROXY (not this app) downloads from — shown to the
    /// user in the confirmation dialog. Same signing key as the shipped public-resolvers source.</summary>
    public const string OdohServersUrl =
        "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-servers.md";

    public const string OdohRelaysUrl =
        "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/odoh-relays.md";

    private const string OdohMinisignKey = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";

    /// <summary>Header comment prepended once when any ODoH source table is appended. Deliberately
    /// ASCII-only (a plain '-' not an em-dash): a non-ASCII byte in a generated config comment is
    /// fragile — any downstream tool that round-trips the file through the wrong encoding (e.g. a
    /// PowerShell 5.1 Get-Content/Set-Content ANSI mismatch) re-encodes it and grows it each pass.</summary>
    private const string OdohSourcesHeader =
        "\n# ODoH (Oblivious DoH) source lists - added by DnsCrypt Control. The dnscrypt-proxy service\n" +
        "# downloads and minisign-verifies these on its schedule; an ODoH target is only usable via an\n" +
        "# ODoH relay, so add a route in the Anonymized DNS tab after these download.\n";

    /// <summary>Signature line used to detect whether <see cref="OdohSourcesHeader"/> is already present,
    /// so re-adding after a partial state (only one source table missing) never appends a duplicate
    /// comment block. Matches the header regardless of the dash char (old em-dash configs included).</summary>
    private const string OdohSourcesHeaderSignature = "# ODoH (Oblivious DoH) source lists";

    /// <summary>The odoh-servers (ODoH targets) source table. Mirrors the shipped public-resolvers
    /// source shape (single-quoted name, urls/cache_file/minisign_key). Appended ONLY when absent, so a
    /// partial config (only odoh-relays present) never gets a duplicate table.</summary>
    private const string OdohServersBlock =
        "\n[sources.'odoh-servers']\n" +
        "urls = ['" + OdohServersUrl + "']\n" +
        "cache_file = 'odoh-servers.md'\n" +
        "minisign_key = '" + OdohMinisignKey + "'\n";

    /// <summary>The odoh-relays source table. Appended ONLY when absent.</summary>
    private const string OdohRelaysBlock =
        "\n[sources.'odoh-relays']\n" +
        "urls = ['" + OdohRelaysUrl + "']\n" +
        "cache_file = 'odoh-relays.md'\n" +
        "minisign_key = '" + OdohMinisignKey + "'\n";

    /// <summary>Add-ODoH-sources gate: idle and no pending staged edits (a reload after the write would
    /// discard staged edits, so we require a clean state first).</summary>
    public bool CanAddOdohSources => !IsBusy && !IsDirty;

    /// <summary>
    /// 5j: writes the odoh-servers + odoh-relays SOURCES into the config and sets <c>odoh_servers=true</c>,
    /// then applies via the SAME CAS Save &amp; apply path (no new wire — IC-2 preserved). The app itself
    /// never downloads: the proxy fetches + minisign-verifies the lists on its schedule (offline-by-design
    /// preserved). Idempotent: a no-op notice if an odoh source is already present. Confirmation (the URLs
    /// the proxy will contact) is shown by the view's dialog before this runs.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanAddOdohSources))]
    private async Task AddOdohSourcesAsync()
    {
        if (IsBusy || IsDirty) return;

        CancelProbeSession();
        IsBusy = true;
        SaveNotice = null;
        SaveError = null;
        ConflictMessage = null;
        RestartFailedMessage = null;
        ProxyRejectedMessage = null;
        HelperIncompatibleMessage = null;
        BootstrapAnchorWarning = null;
        try
        {
            // STEP 1 — place the bundled, signed ODoH source caches BEFORE the config ever references
            // them. dnscrypt-proxy treats an un-downloadable source as FATAL, so adding the odoh-* sources
            // without a valid cache present bricks the WHOLE proxy the next time it starts (its boot-time
            // download can't resolve the list URL yet — the bootstrap chicken-and-egg). With the signed
            // cache already on disk the proxy loads ODoH from cache and never attempts that fatal download.
            // A null/failed reply means the cache is NOT in place, so we must NOT go on to add the sources.
            var place = await _helper.PlaceOdohCacheAsync(CancellationToken.None).ConfigureAwait(false);
            if (place is null)
            {
                _ui.Post(() => SaveError =
                    "Couldn't reach the helper to prepare the ODoH server lists — nothing was changed. Try again.");
                return;
            }

            if (!place.Success)
            {
                _ui.Post(() => SaveError =
                    place.Message ?? "Couldn't place the ODoH server lists — nothing was changed.");
                return;
            }

            // STEP 2 — the cache is safely in place; add the sources (idempotently).
            var prepared = await Task.Run(PrepareAddOdohSources, CancellationToken.None).ConfigureAwait(false);
            if (prepared.AlreadyConfigured)
            {
                // Sources already present — placing the signed cache above also HEALS the "sources present
                // but no cache" shape (exactly what bricks the proxy), so this doubles as a repair path.
                _ui.Post(() =>
                {
                    SaveNotice =
                        "ODoH is configured and the signed server lists are now in place. If no ODoH servers appear yet, click Restart service. Then open Anonymized DNS to add a route pairing an ODoH server with an ODoH relay.";
                    BootstrapAnchorWarning = prepared.AnchorWarning; // still surface the no-anchor warning
                });
                return;
            }

            if (!prepared.Success)
            {
                _ui.Post(() => ConflictMessage = prepared.Error);
                return;
            }

            var outcome = await _configFile
                .SaveAndApplyAsync(prepared.CandidateText!, prepared.FreshSha!, CancellationToken.None)
                .ConfigureAwait(false);

            // Reload on a landed write so the ODoH source rows (now loadable from the placed cache) appear.
            if (outcome.Kind is ConfigSaveOutcomeKind.Applied or ConfigSaveOutcomeKind.RestartFailed)
                await LoadAsync(CancellationToken.None).ConfigureAwait(false);

            _ui.Post(() =>
            {
                switch (outcome.Kind)
                {
                    case ConfigSaveOutcomeKind.Applied:
                        SaveNotice =
                            "ODoH added and set to bootstrap through the proxy (kill-switch-safe) — the proxy loaded the signed lists and refreshes them automatically. Open Anonymized DNS to pair an ODoH server with an ODoH relay.";
                        BootstrapAnchorWarning = prepared.AnchorWarning;
                        break;
                    case ConfigSaveOutcomeKind.RestartFailed:
                        RestartFailedMessage = outcome.Message
                            ?? "ODoH sources saved and the signed lists are in place, but the proxy restart did not confirm — try Restart service.";
                        BootstrapAnchorWarning = prepared.AnchorWarning;
                        break;
                    case ConfigSaveOutcomeKind.Conflict:
                        ConflictMessage = outcome.Message
                            ?? "The config changed on disk — nothing was written. Reload and try again.";
                        break;
                    case ConfigSaveOutcomeKind.ProxyRejected:
                        ProxyRejectedMessage = outcome.Message
                            ?? "The proxy rejected the new config — Revert or re-edit.";
                        break;
                    case ConfigSaveOutcomeKind.HelperIncompatible:
                        HelperIncompatibleMessage = outcome.Message
                            ?? "Helper version mismatch — update the helper and app together, then retry.";
                        break;
                    default:
                        SaveError = outcome.Message ?? "Couldn't add the ODoH source lists.";
                        break;
                }
            });
        }
        finally
        {
            _ui.Post(() => IsBusy = false);
        }
    }

    /// <summary>Off-thread: fresh read → idempotency check → build the candidate (odoh_servers=true +
    /// the two appended source tables). Never throws; any fault becomes a Fail result.</summary>
    private OdohPrepareResult PrepareAddOdohSources()
    {
        ConfigLoadResult fresh;
        try
        {
            fresh = _configFile.Load();
        }
        catch (Exception ex)
        {
            return OdohPrepareResult.Fail("config could not be re-read (" + ex.Message + ") — try again.");
        }

        if (!fresh.Success || fresh.Text is null)
            return OdohPrepareResult.Fail("config could not be read — try again.");

        TomlConfigDocument doc;
        try
        {
            doc = TomlConfigDocument.Parse(fresh.Text);
        }
        catch (Exception ex)
        {
            return OdohPrepareResult.Fail("the on-disk config could not be parsed (" + ex.Message + ") — fix it first.");
        }

        if (doc.HasErrors)
            return OdohPrepareResult.Fail("the on-disk config has TOML errors — fix them before adding sources.");

        // Idempotency on the PARSED doc (comments excluded): only ACTIVE [sources.'odoh-*'] tables count.
        // A raw substring scan false-positives on the commented example blocks the app seeds on install,
        // and appending a table that already exists would produce a duplicate-key (invalid) document.
        bool hasServers = false, hasRelays = false;
        if (doc.TryGetSubTables("sources", out var sources))
        {
            foreach (var t in sources)
            {
                if (string.Equals(t.Name, "odoh-servers", StringComparison.OrdinalIgnoreCase)) hasServers = true;
                else if (string.Equals(t.Name, "odoh-relays", StringComparison.OrdinalIgnoreCase)) hasRelays = true;
            }
        }
        var odohEnabled = doc.TryGetBool("odoh_servers", out var oe) && oe;
        // ODoH targets are HOSTNAME-based, so behind the kill switch they need the LOOPBACK bootstrap
        // (resolve their hostnames through the proxy's own :53). Already set up ONLY when bootstrap_resolvers
        // is EXACTLY the loopback endpoint — a remote :53 left here would both strand ODoH and trip the
        // kill-switch OPSEC gate (KillSwitchCritical), so we normalize it below.
        var bootstrapLoopbackOnly = doc.TryGetStringArray("bootstrap_resolvers", out var bs)
            && bs.Count == 1 && string.Equals(bs[0], LoopbackBootstrapEndpoint, StringComparison.Ordinal);

        // The loopback bootstrap only works if a PLAIN (unrouted, IP-stamped) DNSCrypt anchor comes up first
        // to answer the proxy's self-query. Warn (never block — the existing servers still resolve) when
        // there is none: ODoH won't start until the user adds an unrouted DNSCrypt server.
        var hasAnchor = HasPlainDnsCryptAnchor(doc);
        var anchorWarning = hasAnchor
            ? null
            : "ODoH is configured, but there's no plain DNSCrypt server for it to look up ODoH server names through. Add a DNSCrypt server (e.g. Quad9) on this tab and keep it UNROUTED (no Anonymized DNS route) — otherwise ODoH won't start while the kill switch is on.";

        // Set the loopback bootstrap ONLY when a plain DNSCrypt anchor exists to answer it. When there is no
        // anchor, NEVER touch bootstrap_resolvers: a hostname-only DoH/DoT server may rely on the current
        // bootstrap (a remote entry, or the proxy's default/system resolver when the key is absent) to resolve
        // its OWN name, and pointing bootstrap at a loopback the proxy can't yet answer would strand it. Leave
        // it alone and just warn — the user adds an unrouted DNSCrypt anchor, then re-adds ODoH.
        var needBootstrap = hasAnchor && !bootstrapLoopbackOnly;
        var needSources = !hasServers || !hasRelays;
        var needOdoh = !odohEnabled;

        // Nothing to change (sources + odoh_servers present, and the bootstrap is already right or must be
        // left alone) — but still surface the anchor warning so the user isn't left thinking ODoH will start.
        if (!needSources && !needOdoh && !needBootstrap)
            return OdohPrepareResult.Already(anchorWarning);

        try
        {
            if (needOdoh) doc.SetBool("odoh_servers", true);  // required for the proxy to use ODoH targets
            if (needBootstrap) doc.SetStringArray("bootstrap_resolvers", new[] { LoopbackBootstrapEndpoint });
        }
        catch (Exception ex)
        {
            return OdohPrepareResult.Fail("could not enable odoh_servers (" + ex.Message + ").");
        }

        string candidate;
        if (!needSources)
        {
            // Both sources already present — we only needed to enable odoh_servers; append nothing.
            candidate = doc.ToText();
        }
        else
        {
            // Append ONLY the table(s) actually missing → always valid TOML (never a duplicate table).
            // And prepend the header comment ONLY when it isn't already present: re-adding after a
            // partial state (e.g. odoh-relays missing but odoh-servers + header already there) must add
            // just the missing table, never a second copy of the comment block.
            var block = fresh.Text.Contains(OdohSourcesHeaderSignature, StringComparison.Ordinal)
                ? string.Empty
                : OdohSourcesHeader;
            if (!hasServers) block += OdohServersBlock;
            if (!hasRelays) block += OdohRelaysBlock;
            candidate = doc.ToText().TrimEnd('\r', '\n') + "\n" + block;
        }

        return OdohPrepareResult.Ok(candidate, fresh.Sha256!, anchorWarning);
    }

    /// <summary>True when the config has at least one PLAIN (included, IP-stamped DNSCrypt, and NOT routed
    /// through an Anonymized DNS relay) server — the anchor the loopback ODoH bootstrap resolves hostnames
    /// through. A wildcard ('*') route anonymizes EVERY server, so it leaves no plain anchor. Reads the cached
    /// lists; if none are cached (or none are included DNSCrypt) it returns false — warn rather than falsely
    /// reassure. Off-thread safe (pure reads; called from <see cref="PrepareAddOdohSources"/>).</summary>
    private bool HasPlainDnsCryptAnchor(TomlConfigDocument doc)
    {
        var entries = _listReader.ReadAll().SelectMany(s => s.Entries).ToArray();
        if (entries.Length == 0) return false;

        var selection = ServerSelectionConfig.FromDocument(doc);
        var includedDnsCrypt = ServerSelection.Evaluate(entries, selection).Evaluations
            .Where(e => e.IsIncludedServer && e.Entry.PrimaryProtocol == StampProtocol.DnsCrypt)
            .Select(e => e.Entry.Name)
            .ToArray();
        if (includedDnsCrypt.Length == 0) return false;

        // Unreadable routes ⇒ we cannot confirm any server is UNrouted ⇒ fail toward WARNING (mirrors the
        // other unknowns above). A semantically-malformed route parses as valid TOML, so the doc.HasErrors
        // gate in PrepareAddOdohSources never caught it.
        if (!AnonymizedDnsRoutes.TryRead(doc, out var routes, out _))
            return false;

        // A route only anonymizes a server when it has at least one via relay. An EMPTY via[] assigns no
        // relay (dnscrypt-proxy uses the server DIRECTLY), so such a "route" leaves the server a plain anchor
        // — it must not count as routed (nor should an empty-via '*' short-circuit us to "no anchor").
        if (routes.Any(r => string.Equals(r.ServerName, "*", StringComparison.Ordinal) && r.Via.Count > 0))
            return false; // a real wildcard route anonymizes everything → no plain anchor left

        var routed = new HashSet<string>(
            routes.Where(r => r.Via.Count > 0).Select(r => r.ServerName), StringComparer.Ordinal);
        return includedDnsCrypt.Any(n => !routed.Contains(n));
    }

    private readonly record struct OdohPrepareResult(
        bool Success, bool AlreadyConfigured, string? CandidateText, string? FreshSha, string? Error, string? AnchorWarning)
    {
        public static OdohPrepareResult Ok(string text, string sha, string? anchorWarning) =>
            new(true, false, text, sha, null, anchorWarning);
        public static OdohPrepareResult Already(string? anchorWarning) =>
            new(false, true, null, null, null, anchorWarning);
        public static OdohPrepareResult Fail(string error) => new(false, false, null, null, error, null);
    }

    /// <summary>R2: after a landed save, name any pinned server_name the fresh doc's disabled_server_names
    /// silently overrides (disabled beats a manual pick) so the success is not falsely clean. Cleared when none.</summary>
    private void SetDisabledPickWarning(IReadOnlyList<string> disabledPins)
    {
        if (disabledPins.Count == 0)
        {
            DisabledPickWarning = null;
            return;
        }

        var names = string.Join(", ", disabledPins.Select(n => "'" + n + "'"));
        var verb = disabledPins.Count == 1 ? "is" : "are";
        DisabledPickWarning =
            $"{names} {verb} in disabled_server_names and won't be used — remove {(disabledPins.Count == 1 ? "it" : "them")} from the disabled list to activate this pick.";
    }

    /// <summary>Removes exactly the dispatched ops (write-landed) and re-derives dirty/block.</summary>
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
        });
    }

    /// <summary>Revert: discard staged edits + fresh reload. Non-cancellable.</summary>
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

    /// <summary>Tab-activation freshness reload — only when clean and idle (never discards staged edits).</summary>
    public Task OnTabActivatedAsync()
    {
        if (IsDirty || IsBusy || _probeSession is not null) return Task.CompletedTask;
        return LoadAsync(CancellationToken.None);
    }

    // --------------------------------------------------------------- C3: latency probe

    /// <summary>True when a batch probe can be armed: not already probing, no pending consent, and online.</summary>
    private bool CanTestAll => !IsProbing && PendingConsentRequest is null && _probeGate.IsProbingAllowed;

    /// <summary>
    /// "Test all latencies" (P5c-U1): arms a <see cref="PendingConsentRequest"/> stating an UPPER-BOUND
    /// target count ("up to N"). It does NOT probe — the user must Confirm (which fetches status fresh and
    /// probes) or Cancel. No-op while a session or a pending consent is active, or offline.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanTestAll))]
    private void TestAllLatencies()
    {
        if (!CanTestAll) return;
        if (!_probeGate.IsProbingAllowed)
        {
            ProbingDisabledReason = "Latency testing is disabled while offline.";
            return;
        }

        // R5: this count is an UPPER BOUND, not an exact count. The kill-switch filter runs FRESH at
        // CONFIRM and can only reduce the set (:53/:853 rows blocked), so fewer may be probed. It counts
        // the rows that CARRY a probeable IP; PendingConsentRequest.IsUpperBound pins the "up to N" wording.
        var probeableCount = Rows.Count(r => r.IsProbeable);
        PendingConsentRequest = new PendingConsentRequest(probeableCount);
    }

    /// <summary>Confirms the batch consent (P5c-U1): fetch status fresh, compute kill-switch-safe
    /// targets, and probe. No dialog is shown again — this IS the consented act.</summary>
    public Task ConfirmTestAllAsync()
    {
        if (PendingConsentRequest is null) return Task.CompletedTask;
        PendingConsentRequest = null;
        return StartProbeAsync(Rows.Where(r => r.IsProbeable).ToArray());
    }

    /// <summary>Cancels the pending batch consent — nothing is probed.</summary>
    public void CancelTestAll() => PendingConsentRequest = null;

    /// <summary>A per-row probe click IS its own consent (P5c-U1 — no dialog). No-op while a
    /// session or a pending batch consent is active, or offline.</summary>
    public Task ProbeRowAsync(ResolverRowViewModel row)
    {
        ArgumentNullException.ThrowIfNull(row);
        if (IsProbing || PendingConsentRequest is not null) return Task.CompletedTask;
        if (!_probeGate.IsProbingAllowed)
        {
            ProbingDisabledReason = "Latency testing is disabled while offline.";
            return Task.CompletedTask;
        }
        if (!row.IsProbeable) return Task.CompletedTask;
        return StartProbeAsync(new[] { row });
    }

    /// <summary>Runs one probe session over the candidate rows: status-gated target derivation
    /// (IC-15/IC-16 + kill-switch), IProgress marshaled through the dispatcher with a session-token
    /// re-check inside every post (5b stale-drop), sort-by-latency. Results in-memory only.</summary>
    private async Task StartProbeAsync(IReadOnlyList<ResolverRowViewModel> candidates)
    {
        if (IsProbing || PendingConsentRequest is not null) return;

        CancelProbeSession();
        var session = new ProbeSession();
        _probeSession = session;
        IsProbing = true;
        ProbingDisabledReason = null;
        try
        {
            // Fetch the kill-switch state FRESH at confirm (fail-closed: a null/failed status
            // treats every kill-switch-eligible endpoint as blocked — IC-15).
            var killSwitchEnabled = await ReadKillSwitchFailClosedAsync(session.Token).ConfigureAwait(false);

            var rowByName = candidates.ToDictionary(r => r.Name, StringComparer.Ordinal);
            var targets = new List<ProbeTarget>();
            foreach (var row in candidates)
            {
                var stamp = row.SelectedStamp;
                if (stamp?.AddressIp is null) continue; // no IP → never a target (IC-15)
                if (KillSwitchClassification.IsBlockedByKillSwitch(stamp.Protocol, stamp.Port, killSwitchEnabled))
                {
                    // Blocked rows are pre-classified, never probed.
                    _ui.Post(() =>
                    {
                        if (session.Cancelled) return;
                        row.ProbeStatus = "blocked by kill switch";
                        row.LatencyMs = null;
                    });
                    continue;
                }

                if (!System.Net.IPAddress.TryParse(stamp.AddressIp, out var ip)) continue; // never resolve a hostname
                if (!ProbeTargetPolicy.IsProbableResolverEndpoint(ip, stamp.Port))
                {
                    // A resolver stamp has no legitimate reason to aim a latency probe at loopback / private /
                    // link-local space; refusing here stops a hostile stamp turning the probe into an internal
                    // port-scan or beacon (finding 2026-07-08). The stamp still parses and displays; it's just
                    // never dialed.
                    _ui.Post(() =>
                    {
                        if (session.Cancelled) return;
                        row.ProbeStatus = "not a public resolver endpoint";
                        row.LatencyMs = null;
                    });
                    continue;
                }

                targets.Add(new ProbeTarget(row.Name, ip, stamp.Port));
                _ui.Post(() =>
                {
                    if (session.Cancelled) return;
                    row.ProbeStatus = "testing…";
                });
            }

            if (session.Cancelled) return;

            // A custom IProgress marshals through the dispatcher and re-checks the session flag
            // inside every post (never the disposed CTS token) — the 5b stale-drop discipline.
            var progress = new ProbeProgress(this, session, rowByName);
            await _prober.ProbeAsync(targets, progress, session.Token).ConfigureAwait(false);

            _ui.Post(() =>
            {
                if (session.Cancelled) return;
                SortRowsByLatency();
            });
        }
        catch (OperationCanceledException)
        {
            // Expected: a reload/new session cancelled this one — publish nothing.
        }
        catch (Exception)
        {
            // Fail-closed: a probe fault must not crash the tab. CA1031 suppressed for this file.
        }
        finally
        {
            _ui.Post(() =>
            {
                if (ReferenceEquals(_probeSession, session))
                {
                    _probeSession = null;
                    IsProbing = false;
                }
            });
        }
    }

    /// <summary>Reads the live kill-switch state; ANY failure (null result, failed Result, throw)
    /// is treated as ENABLED so eligible endpoints are blocked, never mislabeled reachable (IC-15).</summary>
    private async Task<bool> ReadKillSwitchFailClosedAsync(CancellationToken ct)
    {
        try
        {
            var status = await _helper.GetStatusAsync(ct).ConfigureAwait(false);
            if (status is null || !status.Success || status.Value is null) return true; // fail-closed
            return status.Value.KillSwitchEnabled;
        }
        catch (Exception)
        {
            // Fail-closed: a status-fetch fault blocks the kill-switch-eligible rows.
            return true;
        }
    }

    /// <summary>Stable sort placing probed rows by ascending latency, unreached/unprobed last,
    /// preserving load order within a tier. Results describe an event — they do NOT survive a reload.</summary>
    private void SortRowsByLatency()
    {
        var order = _allRows
            .Select((row, index) => (row, index))
            .OrderBy(t => t.row.LatencyMs.HasValue ? 0 : 1)
            .ThenBy(t => t.row.LatencyMs ?? int.MaxValue)
            .ThenBy(t => t.index)
            .Select(t => t.row)
            .ToArray();
        _allRows = order;
        ApplySearch();
    }

    /// <summary>Discards all staged edits (C2) and resets the per-attempt save surfaces.
    /// Called on load, Revert, and after a landed save. The persistent
    /// RestartFailed/ProxyRejected states are NOT cleared here — only their defined exits clear them.</summary>
    private void ClearStagedInternal()
    {
        _staged.Clear();
        IsDirty = false;
        SaveBlockedReason = null;
        SingleServerWarning = null;
        ZeroPoolStagedWarning = null;
        DisabledPickWarning = null;
        SaveNotice = null;
        SaveError = null;
        ConflictMessage = null;
        HelperIncompatibleMessage = null;
    }

    /// <summary>Cancels any in-flight probe session (C3) so its results never publish over a reload.
    /// Marks the session cancelled BEFORE disposing its CTS so a late progress post reads the flag
    /// (not the disposed token) and drops cleanly. Also resets <see cref="IsProbing"/> here (R1): the
    /// orphaned <see cref="StartProbeAsync"/>'s finally is guarded by ReferenceEquals(_probeSession,
    /// session) — false after a cancel — so it never resets IsProbing. A save (or any session-cancelling
    /// path) that ends in a NON-reloading outcome (Conflict/HelperIncompatible/Rejected/TooLarge/
    /// HelperUnavailable) would otherwise leave IsProbing stuck true forever = dead probe buttons.</summary>
    private void CancelProbeSession()
    {
        var session = _probeSession;
        _probeSession = null;
        if (session is null)
        {
            // No live session, but a prior cancel may have left IsProbing set (e.g. the finally's
            // ReferenceEquals guard skipped the reset). Clear it so the buttons never stick.
            if (IsProbing) _ui.Post(() => IsProbing = false);
            return;
        }
        session.MarkCancelled();
        try
        {
            session.Cts.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Already disposed by a concurrent cancel — the flag is set, which is all posts read.
        }
        session.Cts.Dispose();
        // Reset the probe UI state here (marshaled — Save calls this off the pristine path) instead of
        // relying on StartProbeAsync's reference-guarded finally, which won't fire for a superseded session.
        _ui.Post(() => IsProbing = false);
    }

    public void Dispose()
    {
        CancelProbeSession();
        GC.SuppressFinalize(this);
    }

    // ---------------------------------------------------------------- load projection DTO

    private sealed record LoadSnapshotResult(
        bool Success,
        string? Error,
        string? Sha256,
        ServerSelectionConfig? SelectionConfig,
        PoolSummary? PoolRaw,
        HashSet<string> Favorites,
        IReadOnlyList<ResolverRowViewModel> Rows,
        IReadOnlyList<ResolverSourceHeader> Headers,
        IReadOnlyList<ResolverListSnapshot> Lists)
    {
        public PoolSummary Pool => PoolRaw!;

        public ServerSelectionConfig Selection => SelectionConfig!;

        public static LoadSnapshotResult Fail(string error) => new(
            false, error, null, null, null,
            new HashSet<string>(StringComparer.Ordinal),
            Array.Empty<ResolverRowViewModel>(), Array.Empty<ResolverSourceHeader>(),
            Array.Empty<ResolverListSnapshot>());

        public static LoadSnapshotResult Ok(
            string sha, ServerSelectionConfig selectionConfig,
            PoolSummary pool, HashSet<string> favorites,
            IReadOnlyList<ResolverRowViewModel> rows, IReadOnlyList<ResolverSourceHeader> headers,
            IReadOnlyList<ResolverListSnapshot> lists) => new(
            true, null, sha, selectionConfig, pool, favorites, rows, headers, lists);
    }

    // ---------------------------------------------------------------- C2/C3 support types

    /// <summary>The value kind a staged op writes (drives which mutator + divergence read is used).</summary>
    private enum StagedKind
    {
        Bool,
        StringArray,
    }

    /// <summary>
    /// One staged edit (IC-9): the config <see cref="KeyPath"/>, the value that key read AT
    /// BROWSE TIME (<see cref="BrowseTimeValue"/> — the divergence baseline), and the value to
    /// write on save (<see cref="StagedFinalValue"/>). Never a load-time doc snapshot.
    /// </summary>
    private sealed record StagedOp(
        string KeyPath,
        StagedKind Kind,
        bool? BrowseTimeBool,
        IReadOnlyList<string>? BrowseTimeArray,
        bool? FinalBool,
        IReadOnlyList<string>? FinalArray);

    /// <summary>The result of the IC-9 fresh read-modify-write preparation. <see cref="DisabledPins"/>
    /// carries any staged pinned server_name found in the fresh doc's disabled_server_names (R2 warning).</summary>
    private sealed record PrepareResult(
        bool Success, string? CandidateText, string? FreshSha, IReadOnlyList<string> DisabledPins, string? ConflictReason)
    {
        public static PrepareResult Ok(string candidate, string sha, IReadOnlyList<string> disabledPins) =>
            new(true, candidate, sha, disabledPins, null);

        public static PrepareResult Conflict(string reason) =>
            new(false, null, null, Array.Empty<string>(), reason);
    }

    /// <summary>A latency-probe session (C3): a CTS for cancelling the prober, plus a
    /// <see cref="Cancelled"/> flag every marshaled progress post re-checks (5b stale-drop).
    /// The flag — not the disposed CTS token — is what posts read, so a post that lands after
    /// the session was cancelled+disposed drops cleanly instead of throwing ObjectDisposedException.</summary>
    private sealed class ProbeSession
    {
        private volatile bool _cancelled;

        public CancellationTokenSource Cts { get; } = new();

        public CancellationToken Token => Cts.Token;

        /// <summary>True once this session has been superseded/cancelled — checked inside every post.</summary>
        public bool Cancelled => _cancelled;

        public void MarkCancelled() => _cancelled = true;
    }

    /// <summary>An <see cref="IProgress{T}"/> that marshals each report straight through the
    /// dispatcher (no <see cref="SynchronizationContext"/> capture, unlike <see cref="Progress{T}"/>)
    /// and drops it if the session was cancelled — the deterministic 5b stale-drop the tests pin.</summary>
    private sealed class ProbeProgress : IProgress<ProbeResult>
    {
        private readonly ResolversViewModel _vm;
        private readonly ProbeSession _session;
        private readonly IReadOnlyDictionary<string, ResolverRowViewModel> _rowByName;

        public ProbeProgress(ResolversViewModel vm, ProbeSession session, IReadOnlyDictionary<string, ResolverRowViewModel> rowByName)
        {
            _vm = vm;
            _session = session;
            _rowByName = rowByName;
        }

        public void Report(ProbeResult result) => _vm._ui.Post(() =>
        {
            if (_session.Cancelled) return;
            if (!_rowByName.TryGetValue(result.Name, out var row)) return;
            row.LatencyMs = result.Reachable ? result.LatencyMs : null;
            row.ProbeStatus = result.Reachable ? null : result.Error ?? "unreachable";
        });
    }
}
