using System.Globalization;

namespace DnsCryptControl.Core.QueryLog;

/// <summary>
/// The ground-truth parser for the dnscrypt-proxy 2.1.16 TSV query log (VM spikes 501/502). Pure,
/// total, and lenient in the same spirit as the Phase 5d rule parsers: a malformed or short line is
/// SKIPPED (returns <see langword="null"/>), never fatal, and no method throws. The proxy writes one
/// tab-separated line per query:
/// <code>
/// [YYYY-MM-DD HH:MM:SS]\tclient_ip\tqname\tqtype\tACTION\tNNNms\tserver\trelay
/// </code>
/// Locally-answered actions (REJECT/CLOAK/SYNTH) carry <c>-</c> for <c>server</c>/<c>relay</c>; the
/// timestamp is LOCAL and bracketed (NOT ISO-Z), so it is preserved as raw text rather than parsed
/// into a <see cref="DateTime"/>.
/// </summary>
public static class QueryLogParser
{
    /// <summary>The number of tab-separated columns a well-formed query-log line carries.</summary>
    private const int ColumnCount = 8;

    /// <summary>
    /// Leniently parses a single TSV query-log <paramref name="line"/>. Returns <see langword="null"/>
    /// when the line is <see langword="null"/> or has fewer than <see cref="ColumnCount"/> tab-separated
    /// columns (a live tail can read a half-written line); NEVER throws. The <c>ACTION</c> token is
    /// mapped case-sensitively (the proxy always upper-cases it) via <see cref="MapAction"/> — any
    /// unrecognised token becomes <see cref="QueryAction.Other"/>. The duration token (e.g. <c>183ms</c>)
    /// is parsed to an <see cref="int"/> millisecond count via <see cref="ParseDurationMs"/>; a
    /// malformed token yields <c>0</c>. Every string column is preserved verbatim (the timestamp keeps
    /// its brackets). A line with MORE than <see cref="ColumnCount"/> columns keeps the first seven
    /// fields and treats everything from the eighth column onward as the relay (defensive — the shipped
    /// format has exactly eight, and none of the earlier fields can contain a tab).
    /// </summary>
    /// <param name="line">One raw log line (without its trailing newline).</param>
    /// <returns>The parsed <see cref="QueryLogLine"/>, or <see langword="null"/> for a malformed/short line.</returns>
    public static QueryLogLine? ParseLine(string? line)
    {
        if (line is null)
        {
            return null;
        }

        // Split into at most ColumnCount fields: the shipped format has exactly eight columns and no
        // earlier field can contain a tab, so capping the split keeps a stray tail (if any) attached to
        // the last column rather than dropping the line.
        var columns = line.Split('\t', ColumnCount);
        if (columns.Length < ColumnCount)
        {
            return null;
        }

        return new QueryLogLine(
            Time: columns[0],
            Client: columns[1],
            Name: columns[2],
            Type: columns[3],
            Action: MapAction(columns[4]),
            DurationMs: ParseDurationMs(columns[5]),
            Server: columns[6],
            Relay: columns[7]);
    }

    /// <summary>
    /// Leniently parses a whole log <paramref name="text"/> into the successfully-parsed lines, in file
    /// order. Splits on <c>'\n'</c> (a trailing <c>'\r'</c> from a CRLF write is tolerated by
    /// <see cref="ParseLine"/> keeping the relay field verbatim; the shipped proxy writes LF). A live
    /// tail can read a half-written final line, so a trailing partial line (one NOT terminated by a
    /// newline) is DROPPED; a complete final line (terminated by a newline, which yields a trailing
    /// empty split element) is kept as far as it parses. Any line that <see cref="ParseLine"/> rejects
    /// is skipped-and-continued. Pure and total: never throws. A <see langword="null"/> or empty input
    /// yields an empty list.
    /// </summary>
    /// <param name="text">The full (possibly partial-tailed) log text.</param>
    /// <returns>The parsed lines in order (empty when nothing parses).</returns>
    public static IReadOnlyList<QueryLogLine> ParseLines(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return Array.Empty<QueryLogLine>();
        }

        var rawLines = text.Split('\n');

        // Drop a trailing PARTIAL line — one with no newline terminator. Splitting on '\n' means a
        // newline-terminated final line produces a trailing empty element, so when the last element is
        // non-empty the file did NOT end in a newline and that last element is a half-written tail.
        var count = rawLines.Length;
        if (rawLines[count - 1].Length != 0)
        {
            count--;
        }

        var result = new List<QueryLogLine>(count);
        for (var i = 0; i < count; i++)
        {
            var parsed = ParseLine(rawLines[i]);
            if (parsed is not null)
            {
                result.Add(parsed);
            }
        }

        return result;
    }

    /// <summary>
    /// Returns <paramref name="time"/> with a single leading <c>'['</c> and trailing <c>']'</c> removed
    /// (for display), when both are present; otherwise the input verbatim. Never throws.
    /// </summary>
    /// <param name="time">The bracketed timestamp field (e.g. <c>[2026-07-03 10:24:59]</c>).</param>
    /// <returns>The timestamp without its surrounding brackets, or the input unchanged.</returns>
    public static string StripTimeBrackets(string time)
    {
        ArgumentNullException.ThrowIfNull(time);

        if (time.Length >= 2 && time[0] == '[' && time[^1] == ']')
        {
            return time[1..^1];
        }

        return time;
    }

    /// <summary>
    /// Maps a raw <c>ACTION</c> token to the closed <see cref="QueryAction"/> taxonomy. The proxy always
    /// upper-cases the action, so the match is case-sensitive; any unrecognised token (including a future
    /// action) maps to <see cref="QueryAction.Other"/>.
    /// </summary>
    private static QueryAction MapAction(string action) => action switch
    {
        "PASS" => QueryAction.Pass,
        "REJECT" => QueryAction.Reject,
        "CLOAK" => QueryAction.Cloak,
        "SYNTH" => QueryAction.Synth,
        "NXDOMAIN" => QueryAction.NxDomain,
        "FORWARD" => QueryAction.Forward,
        _ => QueryAction.Other,
    };

    /// <summary>
    /// Parses a duration token like <c>183ms</c> / <c>0ms</c> into a millisecond <see cref="int"/>. A
    /// bare number (no <c>ms</c> suffix) is also accepted; anything that does not parse to a
    /// non-negative integer yields <c>0</c> (lenient — a bad duration never drops the line). Never throws.
    /// </summary>
    private static int ParseDurationMs(string duration)
    {
        var digits = duration;
        if (digits.EndsWith("ms", StringComparison.Ordinal))
        {
            digits = digits[..^2];
        }

        return int.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out var ms)
            ? ms
            : 0;
    }
}
