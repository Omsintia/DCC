using System;
using System.Collections.Generic;
using CommunityToolkit.Mvvm.ComponentModel;
using DnsCryptControl.Core.Sources;
using DnsCryptControl.Core.Stamps;

namespace DnsCryptControl.UI.ViewModels;

/// <summary>
/// One row in the Resolvers list: a resolver/relay entry projected for display. Pure POCO
/// (IC-5) — no WPF types. The structured facts (chips, relay-ness, selection verdict,
/// probeability) come from the A5 evaluation and the parsed stamps (IC-13); the description
/// is advisory display text only. Latency (C3) is transient and NEVER persisted (IC-11).
/// </summary>
public sealed partial class ResolverRowViewModel : ObservableObject
{
    /// <summary>The prefixed name — the config identity used for picks and favorites.</summary>
    public string Name { get; }

    /// <summary>The source this entry came from (e.g. <c>public-resolvers</c>).</summary>
    public string SourceName { get; }

    /// <summary>Advisory display description (sanitized in Core), capped for display.</summary>
    public string Description { get; }

    /// <summary>Best-effort location bucket from a description keyword heuristic (E8) — "Unknown" when no hint.</summary>
    public string Location { get; }

    /// <summary>The per-stamp property/protocol chips (IC-13 — from stamp props/proto/port).</summary>
    public IReadOnlyList<string> Chips { get; }

    /// <summary>True when this entry is a relay (routing infrastructure, not a pool server).</summary>
    public bool IsRelay { get; }

    /// <summary>The A5 selection verdict for this entry.</summary>
    public SelectionVerdict Verdict { get; }

    /// <summary>True when the proxy would register + use this entry (row shown enabled).</summary>
    public bool IsIncluded { get; }

    /// <summary>Human-readable reason the row is greyed out (null when included).</summary>
    public string? ExclusionReason { get; }

    /// <summary>True when the name passes the IC-7 allowlist and has a usable stamp — only then may it be picked.</summary>
    public bool IsSelectable { get; }

    /// <summary>The selected stamp used for kill-switch classification + probe targeting (IC-16 — first stamp).</summary>
    public ServerStamp? SelectedStamp { get; }

    /// <summary>Every parsed stamp projected for the detail pane (5g-5). <see cref="SelectedStamp"/>
    /// stays stamps[0] (IC-16) — this list is display-only and never drives probing.</summary>
    public IReadOnlyList<StampDisplay> Stamps { get; }

    /// <summary>Precomputed facet-match facts for the 5g-1 chip filters (keeps ApplySearch allocation-light).</summary>
    public ResolverFilterFacets Facets { get; }

    /// <summary>True when the selected stamp carries an IP literal a probe may target (IC-15).</summary>
    public bool IsProbeable => SelectedStamp?.IsProbeable ?? false;

    /// <summary>True when this row is a queryable server (not a relay) — gates the pool actions
    /// ("Use only this server" / "Add to pool"), which write <c>server_names</c>. A relay is routing
    /// infrastructure and never belongs in the pool, so those actions are hidden for it (it gets the
    /// Anonymized-DNS guidance instead).</summary>
    public bool IsServer => !IsRelay;

    /// <summary>True when this is a server that can be ANONYMIZED through a relay — DNSCrypt or an ODoH
    /// target (DoH cannot be relayed). Drives the Resolvers "Route through a relay" shortcut into the
    /// Anonymized-DNS route builder.</summary>
    public bool IsAnonymizableServer =>
        !IsRelay && SelectedStamp is { Protocol: StampProtocol.DnsCrypt or StampProtocol.ODoHTarget };

    /// <summary>The favorite star (B2) — user preference, mutable.</summary>
    [ObservableProperty]
    private bool _isFavorite;

    /// <summary>Transient latency result (C3): null until probed, cleared on reload. In-memory only.</summary>
    [ObservableProperty]
    private int? _latencyMs;

    /// <summary>Transient probe state text (C3): "blocked", "no IP", "testing…", an error — never persisted.</summary>
    [ObservableProperty]
    private string? _probeStatus;

    public ResolverRowViewModel(
        string name,
        string sourceName,
        string description,
        string location,
        IReadOnlyList<string> chips,
        bool isRelay,
        SelectionVerdict verdict,
        bool isIncluded,
        string? exclusionReason,
        bool isSelectable,
        ServerStamp? selectedStamp,
        IReadOnlyList<StampDisplay> stamps,
        ResolverFilterFacets facets,
        bool isFavorite)
    {
        Name = name;
        SourceName = sourceName;
        Description = description;
        Location = location;
        Chips = chips;
        IsRelay = isRelay;
        Verdict = verdict;
        IsIncluded = isIncluded;
        ExclusionReason = exclusionReason;
        IsSelectable = isSelectable;
        SelectedStamp = selectedStamp;
        Stamps = stamps;
        Facets = facets;
        _isFavorite = isFavorite;
    }
}

/// <summary>One stamp projected for the detail pane (5g-5). Pure display data — WPF-free (IC-5).</summary>
/// <param name="Protocol">The human protocol label (the ProtocolChip mapping, e.g. "DoH", "DNSCrypt relay").</param>
/// <param name="Endpoint">"ip:port" when the stamp carries an IP literal, else the hostname, else the
/// provider name, else "(no address)".</param>
/// <param name="Provider">The DNSCrypt provider name / DoH-family hostname — null when it would just
/// repeat <paramref name="Endpoint"/>.</param>
public sealed record StampDisplay(string Protocol, string Endpoint, string? Provider);

/// <summary>
/// Per-row facts for the 5g-1 chip facet filters, precomputed at projection time (BuildRow).
/// Protocol/family flags are ANY-stamp matches; the property flags are ALL-stamp matches
/// (multi-stamp honesty: the proxy picks one stamp at random, so a property is only guaranteed
/// when every stamp declares it). A zero-stamp row is <see cref="None"/> — it matches NO facet.
/// </summary>
/// <param name="HasDnsCryptFamily">Any stamp is DnsCrypt or DnsCryptRelay.</param>
/// <param name="HasDohFamily">Any stamp is DoH.</param>
/// <param name="HasOdohFamily">Any stamp is ODoHTarget or ODoHRelay.</param>
/// <param name="AllDnssec">Every stamp declares DNSSEC (false when there are no stamps).</param>
/// <param name="AllNoLog">Every stamp declares no-log (false when there are no stamps).</param>
/// <param name="AllNoFilter">Every stamp declares no-filter (false when there are no stamps).</param>
/// <param name="AnyIpv4">Any stamp classifies IPv4 under the proxy's family rules.</param>
/// <param name="AnyIpv6">Any stamp classifies IPv6 under the proxy's family rules.</param>
/// <param name="OnlyDnsCrypt">EVERY stamp is DnsCrypt/DnsCryptRelay (an exclusively-DNSCrypt server).</param>
/// <param name="OnlyDoh">EVERY stamp is DoH (an exclusively-DoH server) — powers the "only DoH" filter.</param>
/// <param name="OnlyOdoh">EVERY stamp is ODoHTarget/ODoHRelay (an exclusively-ODoH server).</param>
public sealed record ResolverFilterFacets(
    bool HasDnsCryptFamily,
    bool HasDohFamily,
    bool HasOdohFamily,
    bool AllDnssec,
    bool AllNoLog,
    bool AllNoFilter,
    bool AnyIpv4,
    bool AnyIpv6,
    bool OnlyDnsCrypt = false,
    bool OnlyDoh = false,
    bool OnlyOdoh = false)
{
    /// <summary>The zero-stamp facts: matches no protocol/property/family facet (and no "only" facet).</summary>
    public static ResolverFilterFacets None { get; } =
        new(false, false, false, false, false, false, false, false);
}

/// <summary>One source's list-state header (State + last-checked + clamped refresh delay + honest text).</summary>
/// <param name="SourceName">The <c>[sources.&lt;name&gt;]</c> name.</param>
/// <param name="State">Fresh / Missing / Unreadable / ParseFailed / Bundled.</param>
/// <param name="LastCheckedUtc">The cache file's last-write time, or null.</param>
/// <param name="RefreshDelayHours">The refresh delay CLAMPED to the proxy's real [25,169]h range, or null when unset.</param>
/// <param name="StatusText">Honest human text describing the source's state.</param>
public sealed record ResolverSourceHeader(
    string SourceName,
    Services.ResolverListState State,
    DateTimeOffset? LastCheckedUtc,
    int? RefreshDelayHours,
    string StatusText);

/// <summary>
/// A pending "Test all latencies" consent (P5c-U1): the batch probe waits behind a user
/// confirmation. <see cref="TargetCount"/> is an UPPER BOUND, not an exact count: it counts the
/// probeable (IP-carrying) visible rows at arm time, but the actual probe set — computed at confirm
/// after a fresh kill-switch status fetch — removes kill-switch-blocked (:53/:853) rows, so fewer may
/// be probed. <see cref="IsUpperBound"/> is always true; the dialog must word it "up to N" and never
/// claim an exact count the probe won't hit. Pure VM state — the view maps it to a <c>ContentDialog</c>;
/// the VM never references WPF.
/// </summary>
/// <param name="TargetCount">The upper-bound number of rows that may be probed.</param>
/// <param name="IsUpperBound">True (the only value produced): the kill-switch filter runs fresh at
/// confirm and can only reduce the set, so the dialog wording must be "up to N".</param>
public sealed record PendingConsentRequest(int TargetCount, bool IsUpperBound = true);
