using DnsCryptControl.Core.Stamps;

namespace DnsCryptControl.Core.Sources;

/// <summary>
/// One entry parsed from a resolver/relay list (a <c>## name</c> block). An entry carries
/// 1..N stamps; dnscrypt-proxy uses ONE at random per load, so all are retained and a
/// mixed-protocol entry is flagged. Fail-closed: a malformed name is rendered but not
/// <see cref="IsSelectable"/>; unparseable stamps are retained as errors, never silently dropped.
/// </summary>
/// <param name="Name">The prefixed name (source prefix + raw name) — the config identity.</param>
/// <param name="RawName">The name exactly as it appeared in the list.</param>
/// <param name="Description">Sanitized description text (control chars stripped; see <paramref name="Anomalies"/>).</param>
/// <param name="StampStrings">The raw <c>sdns://</c> candidate strings from the entry.</param>
/// <param name="Stamps">Successfully parsed stamps (may be empty when all candidates were invalid).</param>
/// <param name="StampErrors">Per-candidate parse errors (aligned with the failed subset of <paramref name="StampStrings"/>).</param>
/// <param name="IsSelectable">True when the name passes the IC-7 allowlist AND at least one stamp parsed — only then may it be written into config.</param>
/// <param name="Anomalies">Human-readable notes (mixed protocol, duplicate name, bidi/zero-width text stripped, …).</param>
public sealed record ResolverListEntry(
    string Name,
    string RawName,
    string Description,
    IReadOnlyList<string> StampStrings,
    IReadOnlyList<ServerStamp> Stamps,
    IReadOnlyList<StampParseError> StampErrors,
    bool IsSelectable,
    IReadOnlyList<string> Anomalies)
{
    /// <summary>True when at least one stamp parsed (the entry is usable by the proxy).</summary>
    public bool HasUsableStamp => Stamps.Count > 0;

    /// <summary>True when every parsed stamp is a relay protocol (0x81/0x85) — classified by stamp proto (IC-13).</summary>
    public bool IsRelay => Stamps.Count > 0 && Stamps.All(s => s.IsRelay);

    /// <summary>The protocol of the first parsed stamp, or null when none parsed.</summary>
    public StampProtocol? PrimaryProtocol => Stamps.Count > 0 ? Stamps[0].Protocol : null;
}
