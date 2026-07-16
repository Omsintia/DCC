using DnsCryptControl.Core.Stamps;
using DnsCryptControl.Core.Toml;

namespace DnsCryptControl.Core.Sources;

/// <summary>Why an entry is or is not in the effective server pool (mirrors dnscrypt-proxy 2.1.16 registration).</summary>
public enum SelectionVerdict
{
    /// <summary>The proxy would register and use this server.</summary>
    Included,

    /// <summary>Manual mode: the name is not in <c>server_names</c>.</summary>
    ExcludedByServerNames,

    /// <summary>Automatic mode: the stamp props don't satisfy the <c>require_*</c> filters.</summary>
    ExcludedByRequiredProps,

    /// <summary>The protocol toggle (<c>dnscrypt_servers</c>/<c>doh_servers</c>/<c>odoh_servers</c>) excludes it.</summary>
    ExcludedByProtocolToggle,

    /// <summary>The IP-family toggle (<c>ipv4_servers</c>/<c>ipv6_servers</c>) excludes it.</summary>
    ExcludedByFamilyToggle,

    /// <summary>The name is in <c>disabled_server_names</c> (wins over a manual pick).</summary>
    ExcludedByDisabled,

    /// <summary>Plain DNS / DoT / DoQ — never usable as an upstream, no toggle can include it.</summary>
    UnsupportedProtocol,

    /// <summary>The entry carries stamps of differing protocols; the proxy picks one at random (never a stable verdict).</summary>
    Nondeterministic,

    /// <summary>No stamp parsed — the proxy cannot use this entry.</summary>
    NoUsableStamp,
}

/// <summary>The verdict for one list entry, plus whether it is a relay (routing infrastructure, not a pool server).</summary>
public sealed record ServerEvaluation(ResolverListEntry Entry, SelectionVerdict Verdict, bool IsRelay)
{
    /// <summary>True when the entry is an included, non-relay pool server.</summary>
    public bool IsIncludedServer => !IsRelay && Verdict == SelectionVerdict.Included;
}

/// <summary>The effective-pool rollup (drives the zero-pool save block and the missing-pinned warnings).</summary>
/// <param name="EffectiveCount">Distinct names of included non-relay servers.</param>
/// <param name="IsZeroPool">True when no server would be live — a config the proxy refuses to start on (total DNS outage).</param>
/// <param name="MissingPinnedNames">Names in <c>server_names</c> not present in any list entry.</param>
/// <param name="IsManual">True when <c>server_names</c> is set.</param>
public sealed record PoolSummary(
    int EffectiveCount,
    bool IsZeroPool,
    IReadOnlyList<string> MissingPinnedNames,
    bool IsManual);

/// <summary>The full evaluation of a list against a config.</summary>
public sealed record ServerSelectionResult(IReadOnlyList<ServerEvaluation> Evaluations, PoolSummary Pool);

/// <summary>The config values the selection depends on. Absent keys resolve to the 2.1.16 defaults.</summary>
public sealed record ServerSelectionConfig(
    IReadOnlyList<string> ServerNames,
    IReadOnlyList<string> DisabledServerNames,
    bool Ipv4Servers,
    bool Ipv6Servers,
    bool DnsCryptServers,
    bool DohServers,
    bool ODoHServers,
    bool RequireDnssec,
    bool RequireNolog,
    bool RequireNofilter)
{
    /// <summary>Automatic mode when <c>server_names</c> is empty; manual otherwise.</summary>
    public bool IsManual => ServerNames.Count > 0;

    /// <summary>Reads the selection config from a document, applying the dnscrypt-proxy 2.1.16 defaults for absent keys.</summary>
    public static ServerSelectionConfig FromDocument(TomlConfigDocument doc)
    {
        ArgumentNullException.ThrowIfNull(doc);
        IReadOnlyList<string> Arr(string key) => doc.TryGetStringArray(key, out var v) ? v : Array.Empty<string>();
        bool Flag(string key, bool fallback) => doc.TryGetBool(key, out var v) ? v : fallback;

        return new ServerSelectionConfig(
            Arr("server_names"),
            Arr("disabled_server_names"),
            Ipv4Servers: Flag("ipv4_servers", true),
            Ipv6Servers: Flag("ipv6_servers", false),
            DnsCryptServers: Flag("dnscrypt_servers", true),
            DohServers: Flag("doh_servers", true),
            ODoHServers: Flag("odoh_servers", false),
            RequireDnssec: Flag("require_dnssec", false),
            RequireNolog: Flag("require_nolog", false),
            RequireNofilter: Flag("require_nofilter", false));
    }
}

/// <summary>
/// Proxy-faithful evaluation of which list entries would be live, and why the rest are excluded.
/// The verdict logic is transcribed verbatim from dnscrypt-proxy 2.1.16 <c>updateRegisteredServers</c>
/// (branch order: server_names/require_* → disabled → family → protocol; relays exempt from
/// server_names/require_*/protocol but family-filtered). This is the honesty engine behind the
/// Resolvers grey-outs, the effective-pool count, and the zero-pool save block.
/// </summary>
public static class ServerSelection
{
    /// <summary>Evaluates every entry against <paramref name="config"/> and rolls up the effective pool.</summary>
    public static ServerSelectionResult Evaluate(IReadOnlyList<ResolverListEntry> entries, ServerSelectionConfig config)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(config);

        var evaluations = new List<ServerEvaluation>(entries.Count);
        foreach (var entry in entries)
            evaluations.Add(new ServerEvaluation(entry, Classify(entry, config), entry.IsRelay));

        // Pool count dedups by prefixed name the way the proxy does — a later same-name entry
        // OVERRIDES the earlier one's stamp ("Updating stamp for [x]"). So the AUTHORITATIVE entry
        // for a name is the LAST one; counting any-included-with-that-name would falsely report a
        // live pool when the final stamp is actually excluded (Core review 2026-07-02, a false-safe
        // on the exact zero-pool guard this engine exists for).
        var lastEvalByName = new Dictionary<string, ServerEvaluation>(StringComparer.Ordinal);
        foreach (var evaluation in evaluations)
            lastEvalByName[evaluation.Entry.Name] = evaluation; // last write wins

        var includedNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (name, evaluation) in lastEvalByName)
            if (evaluation.IsIncludedServer) includedNames.Add(name);

        var missingPinned = config.ServerNames.Where(n => !lastEvalByName.ContainsKey(n)).ToArray();

        var pool = new PoolSummary(includedNames.Count, includedNames.Count == 0, missingPinned, config.IsManual);
        return new ServerSelectionResult(evaluations, pool);
    }

    private static SelectionVerdict Classify(ResolverListEntry entry, ServerSelectionConfig config)
    {
        if (!entry.HasUsableStamp) return SelectionVerdict.NoUsableStamp;

        // Mixed protocols (incl. relay vs non-relay) have no stable ROLE — the proxy shuffles the
        // stamps and uses one at random per load.
        if (entry.Stamps.Select(s => s.Protocol).Distinct().Count() > 1)
            return SelectionVerdict.Nondeterministic;

        // Same protocol but the stamps could still differ in family or props (e.g. a v4 + a
        // bracketed-v6 twin), yielding different verdicts — also nondeterministic (Core review).
        SelectionVerdict? agreed = null;
        foreach (var stamp in entry.Stamps)
        {
            var verdict = ClassifyStamp(stamp, entry.Name, config);
            if (agreed is null) agreed = verdict;
            else if (agreed != verdict) return SelectionVerdict.Nondeterministic;
        }
        return agreed!.Value;
    }

    /// <summary>Classifies ONE stamp (relay or server) under the config — the per-stamp verdict.</summary>
    private static SelectionVerdict ClassifyStamp(ServerStamp stamp, string name, ServerSelectionConfig config)
    {
        // Relays: exempt from server_names / require_* / protocol toggle (branch order), but
        // disabled_server_names applies and the family filter applies.
        if (stamp.IsRelay)
        {
            if (Contains(config.DisabledServerNames, name)) return SelectionVerdict.ExcludedByDisabled;
            if (FamilyExcludes(stamp, config)) return SelectionVerdict.ExcludedByFamilyToggle;
            return SelectionVerdict.Included;
        }

        // Plain / DoT / DoQ are never registered as upstreams — no toggle can include them.
        if (stamp.Protocol is not (StampProtocol.DnsCrypt or StampProtocol.DoH or StampProtocol.ODoHTarget))
            return SelectionVerdict.UnsupportedProtocol;

        // server_names (manual) OR require_* props (automatic).
        if (config.IsManual)
        {
            if (!Contains(config.ServerNames, name)) return SelectionVerdict.ExcludedByServerNames;
        }
        else
        {
            var required = (config.RequireDnssec ? 1UL : 0) | (config.RequireNolog ? 2UL : 0) | (config.RequireNofilter ? 4UL : 0);
            if ((stamp.Props & required) != required) return SelectionVerdict.ExcludedByRequiredProps;
        }

        // disabled_server_names wins over a manual pick.
        if (Contains(config.DisabledServerNames, name)) return SelectionVerdict.ExcludedByDisabled;

        // IP-family toggle.
        if (FamilyExcludes(stamp, config)) return SelectionVerdict.ExcludedByFamilyToggle;

        // Protocol toggle.
        if (!ProtocolAllowed(stamp.Protocol, config)) return SelectionVerdict.ExcludedByProtocolToggle;

        return SelectionVerdict.Included;
    }

    // Verbatim 2.1.16 family classification + filter:
    //   isIPv4, isIPv6 := true, false
    //   if proto == DoH { isIPv4, isIPv6 = true, true }        // DoH is dual-family
    //   if addr starts with '[' { isIPv4, isIPv6 = false, true } // bracketed IPv6
    //   if (SourceIPv4 || SourceIPv6) && !(SourceIPv4==isIPv4 || SourceIPv6==isIPv6) => excluded
    // AddressIp is stored unbracketed, so the bracket test becomes a ':'-in-literal test (only
    // IPv6 literals contain a colon).
    private static bool FamilyExcludes(ServerStamp stamp, ServerSelectionConfig config)
    {
        if (!config.Ipv4Servers && !config.Ipv6Servers) return false; // both off => filter skipped entirely

        var isIPv4 = true;
        var isIPv6 = false;
        if (stamp.Protocol == StampProtocol.DoH) { isIPv4 = true; isIPv6 = true; }
        if (stamp.AddressIp is { } ip && ip.Contains(':')) { isIPv4 = false; isIPv6 = true; }

        var kept = config.Ipv4Servers == isIPv4 || config.Ipv6Servers == isIPv6;
        return !kept;
    }

    private static bool ProtocolAllowed(StampProtocol protocol, ServerSelectionConfig config) => protocol switch
    {
        StampProtocol.DnsCrypt => config.DnsCryptServers,
        StampProtocol.DoH => config.DohServers,
        StampProtocol.ODoHTarget => config.ODoHServers,
        _ => false,
    };

    private static bool Contains(IReadOnlyList<string> names, string name)
    {
        foreach (var n in names)
            if (string.Equals(n, name, StringComparison.Ordinal)) return true;
        return false;
    }
}
