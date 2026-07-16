using System;
using System.Collections.Generic;

namespace DnsCryptControl.UI.ViewModels;

/// <summary>
/// The per-session query-log source shared by the Query Monitor tab (which OWNS it — see
/// <see cref="QueryMonitorViewModel"/>) and the Dashboard (Phase 5i), which reads live counts + recent
/// queries from it. It exists because there can be exactly ONE read-and-shred reader (a second would
/// race the truncate and corrupt the log), and because the Dashboard needs data even when the Query
/// Monitor tab is not the active one. The single bounded in-memory buffer therefore accumulates on every
/// tick regardless of the active tab, and both surfaces read the same aggregates.
///
/// <para>All the per-session, read-and-shred OPSEC invariants (IC-QM1..6: off by default, consent-gated
/// enable, read-and-shred, purge + clear on disable, hard-reset at launch, no exfil) live on the
/// implementer; consumers of this interface only READ. When logging is turned off the buffer is cleared,
/// so every reader (Dashboard included) reverts to its off-state — browsing data is shown ONLY while
/// logging is explicitly on, and never survives a stop or the app closing.</para>
/// </summary>
public interface IQueryLogSession
{
    /// <summary>True while query logging is on (<c>query_log.file</c> is set and the shredder is running).
    /// When false, consumers show their off-state and ignore <see cref="Stats"/> / <see cref="RecentRows"/>.</summary>
    bool LoggingActive { get; }

    /// <summary>Content-only aggregates over the current session buffer (never fabricated). All zero when
    /// logging is off or the buffer is empty.</summary>
    QueryLogStats Stats { get; }

    /// <summary>The most recent <paramref name="max"/> buffered rows, NEWEST FIRST (empty when off/empty).
    /// A snapshot copy — safe to enumerate on the UI thread without racing the poller.</summary>
    IReadOnlyList<QueryRowViewModel> RecentRows(int max);

    /// <summary>Raised (on the UI dispatcher, so handlers are UI-affine) whenever the buffer changes or
    /// <see cref="LoggingActive"/> flips — a consumer re-reads <see cref="LoggingActive"/> /
    /// <see cref="Stats"/> / <see cref="RecentRows"/> in response.</summary>
    event EventHandler? Changed;
}

/// <summary>
/// Content-only per-session query aggregates (Phase 5i). Every value is a direct count/derivation over
/// the buffered rows — never estimated. <see cref="AnsweredLocally"/> is the log's literal
/// "<c>server = "-"</c>" marker: answered without contacting an upstream — blocks + cloaks + synth +
/// cache hits. (The proxy's TSV has no dedicated cache field, so a "cache hit rate" cannot be shown
/// honestly; "answered locally" is exactly what the data supports.)
/// </summary>
/// <param name="Queries">Total buffered queries this session.</param>
/// <param name="Blocked">REJECT + SYNTH (matches the Query Monitor's blocked taxonomy).</param>
/// <param name="Cloaked">CLOAK.</param>
/// <param name="AnsweredLocally">Rows whose <c>server</c> is "-" (never left this machine).</param>
/// <param name="UpstreamCount">Rows that went to an upstream server (server != "-").</param>
/// <param name="AvgUpstreamLatencyMs">Mean duration over upstream rows (0 when there are none).</param>
public readonly record struct QueryLogStats(
    int Queries,
    int Blocked,
    int Cloaked,
    int AnsweredLocally,
    int UpstreamCount,
    int AvgUpstreamLatencyMs)
{
    /// <summary>The empty session — every count zero.</summary>
    public static QueryLogStats Empty { get; } = new(0, 0, 0, 0, 0, 0);

    /// <summary>Percent of queries answered locally (server = "-"), 0 when there are no queries yet.
    /// Rounded to the nearest whole percent.</summary>
    public int AnsweredLocallyPercent =>
        Queries == 0 ? 0 : (int)Math.Round(100.0 * AnsweredLocally / Queries, MidpointRounding.AwayFromZero);
}
