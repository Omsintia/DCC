using DnsCryptControl.Core.QueryLog;

namespace DnsCryptControl.UI.ViewModels;

/// <summary>
/// The display severity of a query row's action — a colour/emphasis hint the view maps to the
/// WPF-UI palette (design 2.6). Derived purely from the <see cref="QueryAction"/> taxonomy, so the
/// view never re-classifies actions itself and the two can never drift.
/// </summary>
public enum QuerySeverity
{
    /// <summary>PASS / FORWARD / NXDOMAIN / anything answered upstream — neutral.</summary>
    Neutral,

    /// <summary>REJECT / SYNTH — the query was blocked/synthesized locally (red-ish emphasis).</summary>
    Blocked,

    /// <summary>CLOAK — the name was cloaked to a local/override IP (blue emphasis).</summary>
    Cloaked,
}

/// <summary>
/// One row in the Query Monitor's live view: a single parsed <see cref="QueryLogLine"/> projected for
/// display (Phase 5e, design 2.5). Pure POCO (IC-5) — no WPF types. Immutable: each row describes one
/// past query and is never mutated after construction (the ring buffer replaces rows, it never edits
/// them). The bracketed timestamp is stripped for display; the raw action is mapped to a
/// <see cref="QuerySeverity"/> colour hint the view binds without re-classifying.
/// </summary>
public sealed class QueryRowViewModel
{
    /// <summary>The query timestamp with its surrounding brackets stripped for display (e.g.
    /// <c>2026-07-03 10:24:59</c>).</summary>
    public string Time { get; }

    /// <summary>The queried name / qname (verbatim from the log).</summary>
    public string Name { get; }

    /// <summary>The DNS query type (e.g. <c>A</c>, <c>AAAA</c>, <c>PTR</c>).</summary>
    public string Type { get; }

    /// <summary>The mapped query action (PASS/REJECT/CLOAK/SYNTH/NXDOMAIN/FORWARD/other).</summary>
    public QueryAction Action { get; }

    /// <summary>A short, uppercase display label for the action (e.g. <c>REJECT</c>), stable across cultures.</summary>
    public string ActionLabel { get; }

    /// <summary>The display severity/colour hint derived from <see cref="Action"/>.</summary>
    public QuerySeverity Severity { get; }

    /// <summary>The resolution duration in milliseconds (0 for a locally-answered action or a bad token).</summary>
    public int DurationMs { get; }

    /// <summary>The upstream server, or <c>-</c> for a locally-answered action (verbatim).</summary>
    public string Server { get; }

    public QueryRowViewModel(QueryLogLine line)
    {
        ArgumentNullException.ThrowIfNull(line);
        Time = QueryLogParser.StripTimeBrackets(line.Time);
        Name = line.Name;
        Type = line.Type;
        Action = line.Action;
        ActionLabel = LabelFor(line.Action);
        Severity = SeverityFor(line.Action);
        DurationMs = line.DurationMs;
        Server = line.Server;
    }

    /// <summary>The action's stable uppercase display label (matches the proxy's own token where one
    /// exists; <see cref="QueryAction.Other"/> renders as <c>OTHER</c>).</summary>
    private static string LabelFor(QueryAction action) => action switch
    {
        QueryAction.Pass => "PASS",
        QueryAction.Reject => "REJECT",
        QueryAction.Cloak => "CLOAK",
        QueryAction.Synth => "SYNTH",
        QueryAction.NxDomain => "NXDOMAIN",
        QueryAction.Forward => "FORWARD",
        _ => "OTHER",
    };

    /// <summary>Maps the action taxonomy to the display severity: REJECT/SYNTH are "blocked" (the query
    /// was refused/synthesized locally), CLOAK is its own bucket, everything else is neutral.</summary>
    private static QuerySeverity SeverityFor(QueryAction action) => action switch
    {
        QueryAction.Reject or QueryAction.Synth => QuerySeverity.Blocked,
        QueryAction.Cloak => QuerySeverity.Cloaked,
        _ => QuerySeverity.Neutral,
    };
}
