namespace DnsCryptControl.Core.Sources;

/// <summary>
/// The result of parsing one resolver/relay list. Models dnscrypt-proxy's outcome as well as
/// exposing every entry for display: the parser CONTINUES past a hard-abort (so the UI can show
/// the whole file) but records <see cref="ProxyWouldStopAtEntryIndex"/> so entries the proxy
/// would never load can be surfaced honestly.
/// </summary>
/// <param name="Entries">Every parsed entry, in file order (includes entries with 0 usable stamps).</param>
/// <param name="Warnings">Non-fatal notes (missing stamps, duplicate names, …).</param>
/// <param name="ProxyWouldStopAtEntryIndex">
/// Index into <see cref="Entries"/> at/after which dnscrypt-proxy would abort the whole file (an
/// empty-name or single-line block); null when the file has no such hard-abort. The proxy keeps
/// entries before this point and drops the rest.
/// </param>
/// <param name="WholeFileInvalid">True when the file contains no <c>## </c> delimiter at all (proxy hard-errors).</param>
/// <param name="Truncated">True when the input exceeded the parser's size cap and was cut short.</param>
public sealed record ResolverListParseResult(
    IReadOnlyList<ResolverListEntry> Entries,
    IReadOnlyList<string> Warnings,
    int? ProxyWouldStopAtEntryIndex,
    bool WholeFileInvalid,
    bool Truncated)
{
    /// <summary>An empty result for a whole-file-invalid input.</summary>
    public static ResolverListParseResult Invalid(bool truncated = false) =>
        new(Array.Empty<ResolverListEntry>(), Array.Empty<string>(), null, WholeFileInvalid: true, truncated);

    /// <summary>True when the entry at <paramref name="index"/> would never be loaded by the proxy (it is at/after the abort point).</summary>
    public bool IsBeyondProxyStop(int index) =>
        ProxyWouldStopAtEntryIndex is { } stop && index >= stop;
}
