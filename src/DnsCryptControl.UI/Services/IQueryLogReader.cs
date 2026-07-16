using System.Collections.Generic;
using DnsCryptControl.Core.QueryLog;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// The Query Monitor's read-and-shred query-log reader (Phase 5e, IC-QM4). Unlike the other UI
/// readers it does NOT just read: each <see cref="Drain"/> reads all current bytes, parses the
/// complete-line prefix through <see cref="QueryLogParser.ParseLines"/>, and then TRUNCATES the
/// on-disk file to zero — so browsing history at rest is bounded to a single poll interval. The proxy
/// (LocalSystem) holds a concurrent write handle, so reads open with
/// <c>FileShare.ReadWrite | FileShare.Delete</c> (the default <c>FileShare.Read</c> hits a sharing
/// violation — proven on the VM). Fail-closed: a missing file drains empty; a transient
/// <see cref="System.IO.IOException"/> is retried once then drains empty for this tick; no method
/// ever throws.
/// </summary>
public interface IQueryLogReader
{
    /// <summary>
    /// Reads all current bytes of the query log, parses the complete-line prefix (everything up to and
    /// including the last newline), then truncates the file to zero (read-and-shred). A partial trailing
    /// line with no newline — a rare proxy write split across the read/truncate boundary — is DROPPED
    /// this tick and discarded by the truncate (bounded fuzz: at most one straddling line lost, ≤1 poll
    /// interval; see the implementation's remarks). A missing file, or a sharing conflict that survives
    /// one retry, yields <see cref="DrainedQueries.Empty"/> for this tick — never a throw. An oversized
    /// file past the internal cap is truncated and reported with <see cref="DrainedQueries.HadReadError"/>
    /// set (a dropped burst, not a silent gap).
    /// </summary>
    /// <returns>The lines parsed from the bytes read this tick (empty when there was nothing to read).</returns>
    DrainedQueries Drain();

    /// <summary>
    /// Deletes the on-disk query log entirely (IC-QM5, the disable/stop path): after the proxy stops
    /// writing to it, this removes the last ≤1-interval residue so nothing is left at rest. Idempotent
    /// and fail-closed — a missing file or a sharing conflict is a no-op, never a throw.
    /// </summary>
    void Purge();
}

/// <summary>
/// The typed result of one <see cref="IQueryLogReader.Drain"/>: the parsed lines read this tick plus
/// whether the drain hit an I/O conflict it could not resolve (so the caller can distinguish "nothing
/// new" from "we could not read this tick" without either surfacing as a throw). Empty is the
/// fail-closed value.
/// </summary>
/// <param name="Lines">The lines parsed from the bytes read this tick (in file order; empty when none).</param>
/// <param name="HadReadError">
/// True when the drain could not report the file's content cleanly this tick: either a transient
/// sharing conflict that survived the single retry (the file was NOT truncated, so its content is
/// retried next tick), or an oversized file past the internal cap that was truncated to self-heal (a
/// dropped burst — the bytes are gone, but the caller is told so it can flag the gap rather than show a
/// silent hole). False for a clean read (including a missing file, which is an ordinary empty drain).
/// </param>
public readonly record struct DrainedQueries(IReadOnlyList<QueryLogLine> Lines, bool HadReadError)
{
    /// <summary>The fail-closed empty drain: no lines, no read error.</summary>
    public static DrainedQueries Empty { get; } =
        new(System.Array.Empty<QueryLogLine>(), HadReadError: false);
}
