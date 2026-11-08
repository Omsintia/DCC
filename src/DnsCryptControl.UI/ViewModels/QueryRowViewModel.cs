using CommunityToolkit.Mvvm.ComponentModel;
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
/// display (Phase 5e, design 2.5). Pure POCO <see cref="ObservableObject"/> (IC-5) — no WPF types.
/// Each row describes one past query, and every cell is fixed at construction EXCEPT
/// <see cref="App"/>: the owning <see cref="QueryMonitorViewModel"/> may late-bind it ONCE, from the
/// honest unknown to a correlation decision, when the row's attribution arrives a tick or two after
/// the row did (v1.3.0 — see <see cref="TryBindApp"/>). That one change raises
/// <c>PropertyChanged</c>, so every surface holding this same instance (the Query Monitor's rows, the
/// Dashboard's recent list) updates in place. The ring buffer still evicts whole rows and never edits
/// any other cell. The bracketed timestamp is stripped for display; the raw action is mapped to a
/// <see cref="QuerySeverity"/> colour hint the view binds without re-classifying.
/// </summary>
public sealed class QueryRowViewModel : ObservableObject
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

    /// <summary>The originating app (v1.3.0 per-app attribution): the ETW-correlated process name,
    /// a bare <c>PID 1234</c> when the process had already exited, <c>multiple</c> when more than
    /// one process looked the name up inside the correlation window, and <c>—</c> when nothing
    /// matched (yet). BEST-EFFORT display data correlated by the VM (IC-16: the honest unknown is
    /// shown rather than a guess). Observable: a row appended as <c>—</c> is late-bound in place
    /// via <see cref="TryBindApp"/> if its attribution lands while the row is still pending (the
    /// VM's bounded pending lifetime), and once decided it never changes again. Hand-written over
    /// <c>SetProperty</c> rather than <c>[ObservableProperty]</c> because the field-based generator
    /// this repo uses always emits a PUBLIC setter — the private one keeps the guarded one-way
    /// transition the only way in.</summary>
    public string App
    {
        get => _app;
        private set => SetProperty(ref _app, value);
    }

    private string _app;

    /// <param name="app">The correlated originating-app label; defaults to the honest unknown
    /// (<c>—</c>) so attribution-less construction sites stay truthful by default.</param>
    public QueryRowViewModel(QueryLogLine line, string app = QueryMonitorViewModel.UnknownAppLabel)
    {
        ArgumentNullException.ThrowIfNull(line);
        ArgumentNullException.ThrowIfNull(app);
        Time = QueryLogParser.StripTimeBrackets(line.Time);
        Name = line.Name;
        Type = line.Type;
        Action = line.Action;
        ActionLabel = LabelFor(line.Action);
        Severity = SeverityFor(line.Action);
        DurationMs = line.DurationMs;
        Server = line.Server;
        _app = app;
    }

    /// <summary>Late-binds <see cref="App"/> (v1.3.0): applies <paramref name="app"/> only while the
    /// row still shows the honest unknown, and only when <paramref name="app"/> is a real decision
    /// (a process name, <c>PID n</c>, or <c>multiple</c>) — so a decided row is never changed or
    /// downgraded, by construction. Called by the owning VM from its UI-thread tick (IC-5), so the
    /// <c>PropertyChanged</c> it raises is binding-safe.</summary>
    /// <returns>True when the label changed; false when the row was already decided or
    /// <paramref name="app"/> is itself the unknown.</returns>
    internal bool TryBindApp(string app)
    {
        ArgumentNullException.ThrowIfNull(app);
        if (_app != QueryMonitorViewModel.UnknownAppLabel || app == QueryMonitorViewModel.UnknownAppLabel)
        {
            return false;
        }

        App = app;
        return true;
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
