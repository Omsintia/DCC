using DnsCryptControl.Core.Stamps;

namespace DnsCryptControl.UI.Models;

/// <summary>
/// 5h: shared display facts for resolver entries — extracted from ResolversViewModel so the
/// Dashboard's Active-Resolver panel and the Resolvers tab derive protocol labels, endpoints
/// and location guesses from ONE place (the whole-branch 5g review showed that same-fact
/// strings authored twice inevitably drift).
/// </summary>
internal static class ResolverDisplay
{
    /// <summary>The protocol chip label — must match the Resolvers tab's badges exactly.</summary>
    internal static string ProtocolChip(StampProtocol protocol) => protocol switch
    {
        StampProtocol.PlainDns => "plain DNS",
        StampProtocol.DnsCrypt => "DNSCrypt",
        StampProtocol.DoH => "DoH",
        StampProtocol.DoT => "DoT",
        StampProtocol.DoQ => "DoQ",
        StampProtocol.ODoHTarget => "ODoH",
        StampProtocol.DnsCryptRelay => "DNSCrypt relay",
        StampProtocol.ODoHRelay => "ODoH relay",
        _ => "unknown",
    };

    /// <summary>
    /// One stamp's endpoint for display. IPv6 literals are stored unbracketed (the parser strips
    /// them) — re-bracket for an unambiguous host:port; hostname-only stamps fall back to
    /// Hostname, then ProviderName.
    /// </summary>
    internal static string Endpoint(ServerStamp stamp)
    {
        var host = stamp.AddressIp is not null && stamp.AddressIp.Contains(':')
            ? "[" + stamp.AddressIp + "]"
            : stamp.AddressIp;
        return host is not null
            ? host + ":" + stamp.Port.ToString(System.Globalization.CultureInfo.InvariantCulture)
            : stamp.Hostname ?? stamp.ProviderName ?? "(no address)";
    }

    private static readonly (string Keyword, string Bucket)[] LocationHints =
    {
        ("united states", "United States"), ("usa", "United States"), (" us ", "United States"),
        ("germany", "Germany"), ("deutschland", "Germany"),
        ("france", "France"), ("netherlands", "Netherlands"), ("switzerland", "Switzerland"),
        ("united kingdom", "United Kingdom"), (" uk ", "United Kingdom"), ("england", "United Kingdom"),
        ("canada", "Canada"), ("australia", "Australia"), ("japan", "Japan"), ("singapore", "Singapore"),
        ("sweden", "Sweden"), ("finland", "Finland"), ("norway", "Norway"), ("poland", "Poland"),
        ("spain", "Spain"), ("italy", "Italy"), ("austria", "Austria"), ("belgium", "Belgium"),
        ("russia", "Russia"), ("china", "China"), ("india", "India"), ("brazil", "Brazil"),
        ("anycast", "Anycast"), ("global", "Global"),
    };

    /// <summary>Best-effort location bucket from the entry's free-text description.</summary>
    internal static string GuessLocation(string description)
    {
        if (string.IsNullOrEmpty(description)) return "Unknown";
        var haystack = " " + description.ToLowerInvariant() + " ";
        foreach (var (keyword, bucket) in LocationHints)
            if (haystack.Contains(keyword, StringComparison.Ordinal)) return bucket;
        return "Unknown";
    }
}
