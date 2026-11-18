using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using DnsCryptControl.Core.QueryLog;
using DnsCryptControl.Core.Security;
using DnsCryptControl.Core.Toml;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.UI.Models;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.ViewModels;

/// <summary>
/// The Query Monitor tab (Phase 5e, design 2.5). Streams the proxy's TSV query log into a bounded
/// in-memory ring buffer via the read-and-shred <see cref="IQueryLogReader"/>, so browsing history at
/// rest is bounded to one poll interval (IC-QM4). Enabling logging is CONSENT-GATED (IC-QM2): the
/// command only ARMS a <see cref="PendingLoggingConsent"/>; nothing is written to config until the
/// view routes the user's confirmation to <see cref="ConfirmEnableAsync"/>. Disabling unsets
/// <c>query_log.file</c>, stops the poller, and purges the on-disk file (IC-QM5).
///
/// <para>Config edits ride the SAME fresh read-modify-write + <see cref="IConfigFileService"/> Save
/// path the Filtering tab uses — no new IPC verb (IC-2). Pure POCO <see cref="ObservableObject"/>
/// (IC-5): zero WPF types; every post-await observable write goes through the injected
/// <see cref="IUiDispatcher"/>. The poller + reader are injected seams so tests pump ticks with zero
/// wall-clock sleeps. Fail-closed: a reader error never crashes the VM, and a lost/rejected config
/// write leaves the VM in a coherent state.</para>
///
/// <para>Per-app attribution (v1.3.0): each tick FIRST awaits an <see cref="IDnsAttributionReader"/>
/// fetch (the helper's ETW-observed lookups with their originating process), merges it into a
/// bounded by-name lookup, and correlates rows by normalized name inside an ASYMMETRIC window around
/// each row's APPEND time — from 5 s before it to 0.5 s after (jitter slack only: the lookup that
/// produced a row was raised before the row existed, so a candidate stamped later can only be a
/// different, later lookup). Best-effort and honest (IC-16): exactly one distinct in-window process
/// names the row; more than one shows <c>multiple</c>; none shows <c>—</c>, never a guess. Because
/// ETW delivers its events in ~1 s flush batches, a row is often drained BEFORE its lookup's event
/// has been fetched, so attribution is LATE-BOUND: a row appended as <c>—</c> waits on a bounded
/// pending list (at most 256 rows, each at most 8 s) and is re-correlated — still around its append
/// time — on every later tick, right after that tick's merge. The first decision is written into the
/// row's observable <see cref="QueryRowViewModel.App"/> (one-way: a decided row is never changed or
/// downgraded), and a row that ages out keeps <c>—</c>; a fetch failure is simply "no data" for that
/// tick, and a batch fetched before a clear is dropped whole, never merged. The polls themselves are
/// the demand signal the helper's capture lives by, so they run only while logging is enabled (the
/// same consent gate as everything here).</para>
/// </summary>
public sealed partial class QueryMonitorViewModel : ObservableObject, IDisposable, IQueryLogSession
{
    /// <summary>The read-and-shred window / poll cadence (design 2.4 default ~750 ms). Injected so tests
    /// pass a value they never actually wait on (they pump the fake poller's ticks directly).</summary>
    private static readonly TimeSpan DefaultPollInterval = TimeSpan.FromMilliseconds(750);

    /// <summary>The in-memory ring-buffer cap (design 2.5 ~500): the oldest row is evicted past this so
    /// memory stays bounded regardless of query volume.</summary>
    private const int MaxRows = 500;

    /// <summary>The app's own leak self-check qname (matches WindowsDiagnosticsProbe.SelfCheckName). The
    /// Dashboard's diagnostics poll sends this to the proxy every ~1.5s to attest proxy liveness; when
    /// logging is on it gets logged like any query and — being the most frequent — would dominate the
    /// Dashboard summary. So the SESSION aggregates (<see cref="Stats"/> / <see cref="RecentRows"/>, read
    /// only by the Dashboard) EXCLUDE it, showing the user's own traffic rather than the app's probe. The
    /// raw Query Monitor (its own <see cref="Rows"/> over the full buffer) still shows it — Dashboard-only
    /// filter (Phase 5i).</summary>
    internal const string DiagnosticsSelfCheckName = "dnscrypt-resolver-selfcheck.test";

    private readonly IConfigFileService _configFile;
    private readonly IQueryLogReader _reader;
    private readonly IQueryPoller _poller;
    private readonly IUiDispatcher _ui;
    private readonly IUiStateStore _uiState;
    private readonly IDnsAttributionReader _attribution;
    private readonly TimeSpan _pollInterval;
    private readonly Func<DateTimeOffset> _clock;

    /// <summary>Every row ever appended this session (bounded to <see cref="MaxRows"/>), before the
    /// search/action filter. <see cref="Rows"/> is the filtered projection of this.</summary>
    private readonly List<QueryRowViewModel> _allRows = new();

    private bool _disposed;

    /// <summary>The live, filtered rows the view binds (newest last). Rebuilt from <see cref="_allRows"/>
    /// whenever the buffer or a filter changes.</summary>
    public ObservableCollection<QueryRowViewModel> Rows { get; } = new();

    /// <summary>True when the loaded config has <c>query_log.file</c> set — logging is ON and the proxy
    /// is writing the browsing-history log. Derived from config CONTENT at load, and updated by the
    /// enable/disable commands.</summary>
    [ObservableProperty]
    private bool _loggingEnabled;

    /// <summary>True while the tab is the active/selected one. Does NOT gate the poller: the read-and-shred
    /// loop runs whenever <see cref="LoggingEnabled"/> (FIX 1) so at-rest history stays bounded even when
    /// the tab is left. This only gates whether a drained tick is APPENDED to the visible
    /// <see cref="Rows"/> — an inactive tab still shreds the file, it just discards the rows.</summary>
    [ObservableProperty]
    private bool _isActive;

    /// <summary>True while the live view is frozen (Pause). The DISPLAY stops accumulating, but logging
    /// stays ON (config untouched) AND the poller keeps draining+shredding the on-disk file (FIX 1) —
    /// this is a display freeze, not a disable and not a shred pause. Drained ticks are discarded while
    /// paused rather than shown.</summary>
    [ObservableProperty]
    private bool _isPaused;

    /// <summary>The pending "enable query logging" consent (IC-QM2): non-null while the confirm dialog is
    /// awaiting the user. Arming it writes NOTHING — only <see cref="ConfirmEnableAsync"/> commits config.
    /// The view's code-behind watches this and shows/routes a <c>ContentDialog</c>, mirroring the
    /// Resolvers consent pattern; the VM never references WPF.</summary>
    [ObservableProperty]
    private LoggingConsentRequest? _pendingLoggingConsent;

    /// <summary>Single busy owner: true while an enable/disable config write is in flight.</summary>
    [ObservableProperty]
    private bool _isBusy;

    /// <summary>The search box: a case-insensitive qname substring filter over the buffered rows.</summary>
    [ObservableProperty]
    private string _searchText = string.Empty;

    /// <summary>The action filter (All / Blocked / Cloaked / Passed). Content-derived; never fabricates.</summary>
    [ObservableProperty]
    private QueryActionFilter _actionFilter = QueryActionFilter.All;

    /// <summary>The action-filter choices the view's combo binds to (FIX view MED-1). Exposed as a plain
    /// VM property so the XAML avoids the precedent-less <c>ObjectDataProvider</c>/<c>sys:Enum</c> pattern
    /// and binds <c>ItemsSource</c> directly. The order mirrors the enum declaration (All first).</summary>
    public static IReadOnlyList<QueryActionFilter> ActionFilters { get; } = Enum.GetValues<QueryActionFilter>();

    /// <summary>Content-derived headline (IC-16 style): "N shown · M blocked · K cloaked". Counts are over
    /// the FILTERED rows (what the user is actually looking at), never a claim the content can't back.</summary>
    [ObservableProperty]
    private string _countsHeadline = "0 shown · 0 blocked · 0 cloaked.";

    /// <summary>The honesty banner shown while logging is ON (design 2.5): states plainly that every domain
    /// is recorded and that entries are shredded from disk after display. Null when logging is off.</summary>
    [ObservableProperty]
    private string? _loggingOnBanner;

    /// <summary>Transient "couldn't read this tick" state (IC-QM4): true when the last drain hit a sharing
    /// conflict it could not resolve. Purely informational — the bytes are retried next tick.</summary>
    [ObservableProperty]
    private bool _hadReadError;

    /// <summary>The verbatim reason the last enable/disable config write failed, or null on success.</summary>
    [ObservableProperty]
    private string? _configError;

    /// <param name="uiState">The per-user preference store; seeds (and persists) the column widths.</param>
    /// <param name="attributionReader">The per-app attribution seam (v1.3.0); polled each tick while
    /// logging is on so appended rows can be correlated to their originating process.</param>
    /// <param name="pollInterval">The read-and-shred poll cadence; defaults to ~750 ms. Tests pass any
    /// value — they never wait on it, they pump the fake poller's ticks directly.</param>
    /// <param name="clock">Injectable UTC clock — the attribution correlation's time base (each
    /// tick's candidate prune, the pending age-out, and the append stamp every row's window is
    /// anchored to); defaults to <see cref="DateTimeOffset.UtcNow"/>. Exposed only so tests can age
    /// pending rows deterministically (mirrors <see cref="DashboardViewModel"/>'s clock seam).</param>
    public QueryMonitorViewModel(
        IConfigFileService configFile,
        IQueryLogReader reader,
        IQueryPoller poller,
        IUiDispatcher ui,
        IUiStateStore uiState,
        IDnsAttributionReader attributionReader,
        TimeSpan? pollInterval = null,
        Func<DateTimeOffset>? clock = null)
    {
        ArgumentNullException.ThrowIfNull(configFile);
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(poller);
        ArgumentNullException.ThrowIfNull(ui);
        ArgumentNullException.ThrowIfNull(uiState);
        ArgumentNullException.ThrowIfNull(attributionReader);
        _configFile = configFile;
        _reader = reader;
        _poller = poller;
        _ui = ui;
        _uiState = uiState;
        _attribution = attributionReader;
        _pollInterval = pollInterval ?? DefaultPollInterval;
        _clock = clock ?? (static () => DateTimeOffset.UtcNow);

        // Seed the column layout from the persisted per-user state, clamped so a hand-edited
        // ui-state.json can never produce an ungrabbable (0-width) or off-screen column.
        var cols = uiState.Load().QueryMonitorColumns ?? new UiQueryMonitorColumns();
        _timeColumnWidth = ClampWidth(cols.Time);
        _typeColumnWidth = ClampWidth(cols.Type);
        _actionColumnWidth = ClampWidth(cols.Action);
        _latencyColumnWidth = ClampWidth(cols.Latency);
        _serverColumnWidth = ClampWidth(cols.Server);
        _appColumnWidth = ClampWidth(cols.App);

        _poller.Tick += OnPollerTick;
    }

    // --------------------------------------------------------------- column layout (view geometry)

    /// <summary>Clamp bounds for the user-resizable column widths (px). The floor keeps every column
    /// grabbable (a 0-width column could never be re-widened by dragging); the ceiling keeps a column
    /// from pushing the star-sized Name column entirely off-screen.</summary>
    internal const double MinColumnWidth = 36;

    /// <inheritdoc cref="MinColumnWidth"/>
    internal const double MaxColumnWidth = 800;

    /// <summary>Width (px) of the Time column. The six width properties are pure view geometry —
    /// bound by both the header and every row so the two stay aligned; persisted only on
    /// <see cref="CommitColumnWidths"/> (drag end), never per drag tick.</summary>
    [ObservableProperty]
    private double _timeColumnWidth;

    /// <inheritdoc cref="TimeColumnWidth"/>
    [ObservableProperty]
    private double _typeColumnWidth;

    /// <inheritdoc cref="TimeColumnWidth"/>
    [ObservableProperty]
    private double _actionColumnWidth;

    /// <inheritdoc cref="TimeColumnWidth"/>
    [ObservableProperty]
    private double _latencyColumnWidth;

    /// <inheritdoc cref="TimeColumnWidth"/>
    [ObservableProperty]
    private double _serverColumnWidth;

    /// <inheritdoc cref="TimeColumnWidth"/>
    [ObservableProperty]
    private double _appColumnWidth;

    /// <summary>Applies one live drag delta from a header divider to its column — clamped, no
    /// persistence (that happens once, on <see cref="CommitColumnWidths"/> at drag end).</summary>
    public void ResizeColumn(QueryMonitorColumn column, double delta)
    {
        switch (column)
        {
            case QueryMonitorColumn.Time: TimeColumnWidth = ClampWidth(TimeColumnWidth + delta); break;
            case QueryMonitorColumn.Type: TypeColumnWidth = ClampWidth(TypeColumnWidth + delta); break;
            case QueryMonitorColumn.Action: ActionColumnWidth = ClampWidth(ActionColumnWidth + delta); break;
            case QueryMonitorColumn.Latency: LatencyColumnWidth = ClampWidth(LatencyColumnWidth + delta); break;
            case QueryMonitorColumn.Server: ServerColumnWidth = ClampWidth(ServerColumnWidth + delta); break;
            case QueryMonitorColumn.App: AppColumnWidth = ClampWidth(AppColumnWidth + delta); break;
            default: break; // unknown column — geometry only, never throw at a drag.
        }
    }

    /// <summary>Persists the current column widths. Loads FRESH state and replaces only the column
    /// block, so preferences other tabs' view-models persist (favorites, theme, the kill-switch
    /// opt-in) are never clobbered by a stale copy held here.</summary>
    public void CommitColumnWidths()
    {
        var state = _uiState.Load();
        state.QueryMonitorColumns = new UiQueryMonitorColumns
        {
            Time = TimeColumnWidth,
            Type = TypeColumnWidth,
            Action = ActionColumnWidth,
            Latency = LatencyColumnWidth,
            Server = ServerColumnWidth,
            App = AppColumnWidth,
        };
        _uiState.Save(state);
    }

    /// <summary>Clamps a width to the grabbable range; non-finite input (a hand-edited file) falls
    /// to the floor rather than poisoning layout with NaN/Infinity.</summary>
    private static double ClampWidth(double value) =>
        double.IsFinite(value) ? Math.Clamp(value, MinColumnWidth, MaxColumnWidth) : MinColumnWidth;

    // --------------------------------------------------------------- launch (per-session hard-reset)

    /// <summary>
    /// The ONCE-per-launch initializer that makes query logging a PER-SESSION capability (FIX HIGH-1, the
    /// OPSEC-critical one). Query logging must NEVER outlive the session that turned it on: the read-and-
    /// shred loop only runs in THIS UI process, so if <c>query_log.file</c> is left set in the persistent
    /// config (a prior session that did not clean up, or a crash), the LocalSystem proxy keeps appending
    /// the user's full browsing history to the on-disk log — UNSHREDDED — the entire time the app is closed.
    ///
    /// <para>So at every launch this reads the config and, if <c>query_log.file</c> is currently SET, treats
    /// it as an anomaly and HARD-RESETS logging to OFF: it reflects the on-disk truth (logging on) then runs
    /// the guard-free disable body (<see cref="PerformDisableAsync"/>), which unsets <c>query_log.file</c>
    /// (stopping the proxy from writing), stops the poller, PURGES any accumulated on-disk history, and
    /// clears the view. If the key is not set, logging is simply OFF and the poller stays stopped. Net:
    /// logging is ALWAYS off at launch and any at-rest history is purged. Fail-closed — never throws.</para>
    /// </summary>
    public async Task InitializeAtLaunchAsync(CancellationToken ct)
    {
        try
        {
            var leftoverEnabled = await Task.Run(LoadLoggingEnabled, ct).ConfigureAwait(false);

            if (!leftoverEnabled)
            {
                // Stock/off config — nothing to reset. Publish the coherent OFF state and leave the poller
                // stopped (it is already idle at construction, but reconcile to be explicit).
                _ui.Post(() =>
                {
                    LoggingEnabled = false;
                    LoggingOnBanner = null;
                    ConfigError = null;
                    ReconcilePoller();
                });
                return;
            }

            // A leftover-enabled config: the proxy has been appending browsing history while the app was
            // closed. Reflect the on-disk truth (logging IS on in the config) so that if the reset write
            // fails to land, the VM honestly shows "on" with the shredder stopped + a surfaced error —
            // fail-closed. Then run the GUARD-FREE disable body directly: unset the key, stop the poller,
            // purge the file, clear the view. We call PerformDisableAsync rather than DisableAsync so we do
            // NOT depend on a racily-queued LoggingEnabled=true reaching the guard first (the production
            // dispatcher posts are async/BeginInvoke — the guard could read the stale false and no-op).
            _ui.Post(() =>
            {
                LoggingEnabled = true;
                LoggingOnBanner = LoggingOnBannerText;
            });
            await PerformDisableAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Fail-closed: a canceled token must not escape (contract: never throws). Leave logging shown
            // OFF — the safe display for a browsing-history recorder.
            _ui.Post(() => LoggingEnabled = false);
        }
    }

    // --------------------------------------------------------------- load

    /// <summary>
    /// Loads the config off the UI thread and derives <see cref="LoggingEnabled"/> from whether
    /// <c>query_log.file</c> is present. Fail-closed: any fault leaves logging shown as OFF (the safe
    /// display for a browsing-history recorder) and never throws. Reconciles the poller to the freshly
    /// derived state so a relaunch while logging is already on resumes the live view.
    ///
    /// <para>This is the TAB-ACTIVATE read (called on selecting the tab): it only READS the config and
    /// RECONCILES the poller to what it finds. It must NOT fight <see cref="InitializeAtLaunchAsync"/> —
    /// after the launch reset has run, <c>query_log.file</c> is unset, so this reads OFF and is a no-op.
    /// And because it derives state purely from the on-disk config, an IN-SESSION enable (which HAS written
    /// <c>query_log.file</c>) reads back as ON here — so re-activating the tab never re-disables a live
    /// in-session enable; it just re-derives the same ON state and re-reconciles the (already running)
    /// poller.</para>
    /// </summary>
    public async Task LoadAsync(CancellationToken ct)
    {
        var enabled = await Task.Run(LoadLoggingEnabled, ct).ConfigureAwait(false);

        _ui.Post(() =>
        {
            LoggingEnabled = enabled;
            LoggingOnBanner = enabled ? LoggingOnBannerText : null;
            ConfigError = null;
            ReconcilePoller();
        });
    }

    /// <summary>Off-thread: read the config and report whether <c>query_log.file</c> is set to a
    /// non-empty value. Never throws — any fault reads as "off".</summary>
    private bool LoadLoggingEnabled()
    {
        ConfigLoadResult load;
        try
        {
            load = _configFile.Load();
        }
        catch (Exception)
        {
            // Fail-closed: an unreadable config shows logging OFF (never a false "on"). CA1031 is
            // suppressed for this file in .editorconfig (safety concern for this OPSEC tool).
            return false;
        }

        if (!load.Success || load.Text is null)
        {
            return false;
        }

        TomlConfigDocument doc;
        try
        {
            doc = TomlConfigDocument.Parse(load.Text);
        }
        catch (Exception)
        {
            return false;
        }

        if (doc.HasErrors)
        {
            return false;
        }

        return doc.TryGetString("query_log.file", out var value) && !string.IsNullOrEmpty(value);
    }

    // --------------------------------------------------------------- enable (consent-gated, IC-QM2)

    /// <summary>
    /// Arms the enable-logging consent (IC-QM2): sets <see cref="PendingLoggingConsent"/> and writes
    /// NOTHING. The view shows a plain-language dialog and routes the user's choice to
    /// <see cref="ConfirmEnableAsync"/> (confirm) or <see cref="CancelEnable"/> (cancel). No-op while
    /// busy, already enabled, or a consent is already pending.
    /// </summary>
    public void RequestEnable()
    {
        if (IsBusy || LoggingEnabled || PendingLoggingConsent is not null)
        {
            return;
        }

        PendingLoggingConsent = new LoggingConsentRequest(UiPaths.QueryLogFile);
    }

    /// <summary>Cancels the pending enable consent — clears the request and writes nothing (IC-QM2).</summary>
    public void CancelEnable() => PendingLoggingConsent = null;

    /// <summary>
    /// Confirms the enable consent (IC-QM2 — this IS the consented act): writes
    /// <c>query_log.file = <see cref="UiPaths.QueryLogFile"/></c> + <c>query_log.format = 'tsv'</c> via
    /// the fresh read-modify-write + <see cref="IConfigFileService.SaveAndApplyAsync"/> path, then — only
    /// on a landed write — flips <see cref="LoggingEnabled"/> on and starts the poller. No-op when no
    /// consent is pending. Never throws.
    /// </summary>
    public async Task ConfirmEnableAsync(CancellationToken ct)
    {
        if (PendingLoggingConsent is null || IsBusy)
        {
            return;
        }

        PendingLoggingConsent = null;
        IsBusy = true;
        ConfigError = null;
        try
        {
            var outcome = await Task.Run(
                () => WriteConfig(edit: doc =>
                {
                    // FIX MED-1: create the per-user log directory BEFORE pointing the proxy at the path.
                    // On a fresh profile %LOCALAPPDATA%\DnsCryptControl may not exist yet; without it the
                    // LocalSystem proxy is aimed at a file whose directory is missing and logging silently
                    // produces nothing. A create failure surfaces as a typed ConfigError (never throws).
                    Directory.CreateDirectory(Path.GetDirectoryName(UiPaths.QueryLogFile)!);
                    doc.SetString("query_log.file", UiPaths.QueryLogFile);
                    doc.SetString("query_log.format", "tsv");
                }),
                ct).ConfigureAwait(false);

            var landing = await ApplyConfigWriteAsync(outcome, ct).ConfigureAwait(false);
            if (landing != ConfigWriteLanding.NotWritten)
            {
                _ui.Post(() =>
                {
                    LoggingEnabled = true;
                    LoggingOnBanner = LoggingOnBannerText;
                    IsPaused = false;
                    ReconcilePoller();
                });
            }
        }
        catch (OperationCanceledException)
        {
            // A canceled token (e.g. Task.Run on an already-canceled ct) must NOT escape — the contract
            // is "never throws". Nothing was flipped on, so logging stays off and the poller stays as it
            // was (off); surface a benign note rather than crashing the tab. Mirrors the sibling VMs.
            _ui.Post(() => ConfigError = "enabling logging was canceled.");
        }
        finally
        {
            _ui.Post(() => IsBusy = false);
        }
    }

    // --------------------------------------------------------------- disable (IC-QM5)

    /// <summary>
    /// Disables logging (IC-QM5, "Stop &amp; clear"): unsets <c>query_log.file</c> via the same Save path
    /// (so the proxy stops writing), stops the poller, PURGES the on-disk file, and CLEARS the in-memory
    /// buffer so the displayed history disappears (FIX 2). Disable ALWAYS intends to stop: the poller
    /// stays STOPPED and the file is purged even if the config write did not land (fail-closed) — we do
    /// NOT resurrect the poller on a failed disable (FIX 4). Flips <see cref="LoggingEnabled"/> off only
    /// on a landed write; a failed write leaves logging shown as on but with the shredder stopped and a
    /// surfaced <see cref="ConfigError"/>. No-op while busy or already disabled. Never throws.
    /// </summary>
    public Task DisableAsync(CancellationToken ct)
    {
        if (IsBusy || !LoggingEnabled)
        {
            return Task.CompletedTask;
        }

        return PerformDisableAsync(ct);
    }

    /// <summary>
    /// The GUARD-FREE disable body shared by <see cref="DisableAsync"/> (after its
    /// <see cref="LoggingEnabled"/>/<see cref="IsBusy"/> guard) and <see cref="InitializeAtLaunchAsync"/>
    /// (the per-session launch reset). Kept separate from the guard so the launch reset can force the
    /// teardown WITHOUT the fragile dance of transiently flipping <see cref="LoggingEnabled"/> on through
    /// the (async, BeginInvoke-queued) dispatcher just to satisfy a guard it would then read back. Unsets
    /// <c>query_log.file</c>, stops the poller, purges the on-disk file, and clears the view. Fail-closed.
    /// </summary>
    private async Task PerformDisableAsync(CancellationToken ct)
    {
        IsBusy = true;
        ConfigError = null;
        // Stop the live tail immediately — the file must stop being read/shredded before we purge it. On
        // the disable path the poller stays stopped regardless of the write outcome (FIX 4): there is no
        // ReconcilePoller in the finally that could resurrect it while LoggingEnabled is still true.
        _poller.StopPolling();
        try
        {
            var outcome = await Task.Run(
                () => WriteConfig(edit: doc => doc.RemoveKey("query_log.file")),
                ct).ConfigureAwait(false);

            var landing = await ApplyConfigWriteAsync(outcome, ct).ConfigureAwait(false);
            if (landing != ConfigWriteLanding.NotWritten)
            {
                // The bytes are on disk, so logging is off IN THE CONFIG regardless of whether the proxy
                // confirmed the restart. Flip the flag off either way (FIX MED-2) — but when the restart
                // was NOT confirmed (RestartFailed / ProxyRejected), do NOT claim a clean stop: the proxy
                // may keep logging until it next restarts, so replace the generic caveat with an honest
                // disable-specific one. The launch-reset (InitializeAtLaunchAsync) is the backstop.
                var unconfirmed = landing == ConfigWriteLanding.LandedUnconfirmed;
                _ui.Post(() =>
                {
                    LoggingEnabled = false;
                    LoggingOnBanner = null;
                    HadReadError = false;
                    if (unconfirmed)
                    {
                        ConfigError =
                            "logging was turned off in the config, but the proxy restart couldn't be " +
                            "confirmed — it may keep logging until it next restarts.";
                    }
                });
            }

            // Purge the on-disk residue regardless of the config outcome: even if the write was lost, the
            // last ≤1-interval of bytes should not be left at rest. Idempotent + fail-closed (IC-QM5).
            _reader.Purge();

            // "Stop & clear" (FIX 2): also drop the in-memory buffer so the displayed browsing history
            // disappears when the user stops. Runs regardless of the write outcome — the user asked to
            // clear, and the buffered rows are the on-screen residue. ClearView also drops the
            // domain→process attribution lookup (the same residue, one join away from the rows) and
            // the late-binding pending list (no tick will ever age it out once the poller stops), and
            // the poll cursor rewinds to 0 so a FRESH consent starts a fresh cursor — the helper's
            // ring is likewise cleared when its capture session stops, so nothing replays. ClearView
            // also moves the attribution epoch on, so a fetch still in flight right now is dropped
            // when it lands — it can neither refill the lookup nor un-rewind this cursor.
            _ui.Post(() =>
            {
                _attributionAfterSeq = 0;
                ClearView();
            });
        }
        catch (OperationCanceledException)
        {
            // A canceled token (e.g. Task.Run on an already-canceled ct) must NOT escape — the contract
            // is "never throws". The poller is already stopped above and we do NOT resurrect it (disable
            // always intends to stop); surface a benign note and fail closed with the shredder off (FIX 4).
            _ui.Post(() => ConfigError = "stopping logging was canceled — logging left unchanged.");
        }
        finally
        {
            // NB: no ReconcilePoller here (FIX 4) — the poller must stay STOPPED on the disable path even
            // when the config write did not land (LoggingEnabled still true), so the shredder does not
            // restart itself against a file we are trying to stop and purge.
            _ui.Post(() => IsBusy = false);
        }
    }

    // --------------------------------------------------------------- config write plumbing

    /// <summary>
    /// The fresh read-modify-write shared by enable/disable: load the config, parse, apply
    /// <paramref name="edit"/>, and Save &amp; apply with the FRESH sha (IC-9). Off-thread; never throws —
    /// any fault becomes a typed failure the caller surfaces. Mirrors the Filtering tab's PrepareSave +
    /// SaveAndApplyAsync split, minus the divergence check (a single logging key has no browse-time
    /// baseline to diverge against — this is an unconditional set/unset of one key).
    /// </summary>
    private ConfigWriteResult WriteConfig(Action<TomlConfigDocument> edit)
    {
        ConfigLoadResult load;
        try
        {
            load = _configFile.Load();
        }
        catch (Exception ex)
        {
            return ConfigWriteResult.Failed("the config could not be read (" + MessageScrub.Redact(ex.Message) + ").");
        }

        if (!load.Success || load.Text is null || load.Sha256 is null)
        {
            return ConfigWriteResult.Failed(MessageScrub.Redact(load.Error) ?? "the config could not be read.");
        }

        TomlConfigDocument doc;
        try
        {
            doc = TomlConfigDocument.Parse(load.Text);
        }
        catch (Exception ex)
        {
            return ConfigWriteResult.Failed("the on-disk config could not be parsed (" + MessageScrub.Redact(ex.Message) + ").");
        }

        if (doc.HasErrors)
        {
            return ConfigWriteResult.Failed(
                "the on-disk config has TOML errors — fix it in the Configuration tab first.");
        }

        try
        {
            edit(doc);
        }
        catch (Exception ex)
        {
            return ConfigWriteResult.Failed("the change could not be applied (" + MessageScrub.Redact(ex.Message) + ").");
        }

        return ConfigWriteResult.Ready(doc.ToText(), load.Sha256);
    }

    /// <summary>Dispatches a prepared candidate through <see cref="IConfigFileService.SaveAndApplyAsync"/>
    /// and maps the outcome onto <see cref="ConfigError"/>. Returns a <see cref="ConfigWriteLanding"/>
    /// describing whether the bytes LANDED (Applied / RestartFailed / ProxyRejected — the config is on
    /// disk) and, when landed, whether the proxy CONFIRMED the change (Applied) or the restart was
    /// unverified (RestartFailed / ProxyRejected). Never throws. On the confirmed path it clears
    /// <see cref="ConfigError"/>; on the unconfirmed path it posts the generic caveat, which the caller
    /// may overwrite with a path-specific one (e.g. disable, FIX MED-2).</summary>
    private async Task<ConfigWriteLanding> ApplyConfigWriteAsync(ConfigWriteResult prepared, CancellationToken ct)
    {
        if (!prepared.Success)
        {
            _ui.Post(() => ConfigError = prepared.Error);
            return ConfigWriteLanding.NotWritten;
        }

        ConfigSaveOutcome outcome;
        try
        {
            outcome = await _configFile
                .SaveAndApplyAsync(prepared.CandidateText!, prepared.BaseSha256!, ct)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _ui.Post(() => ConfigError = "the save could not be sent to the helper (" + MessageScrub.Redact(ex.Message) + ").");
            return ConfigWriteLanding.NotWritten;
        }

        switch (outcome.Kind)
        {
            case ConfigSaveOutcomeKind.Applied:
                _ui.Post(() => ConfigError = null);
                return ConfigWriteLanding.Applied;

            case ConfigSaveOutcomeKind.RestartFailed:
            case ConfigSaveOutcomeKind.ProxyRejected:
                // The config bytes landed even though application is unverified — treat as written so the
                // enable/disable state reflects the on-disk truth, but surface the caveat.
                _ui.Post(() => ConfigError = outcome.Message
                    ?? "config saved, but the proxy did not confirm the change — status unverified.");
                return ConfigWriteLanding.LandedUnconfirmed;

            case ConfigSaveOutcomeKind.Conflict:
            case ConfigSaveOutcomeKind.HelperIncompatible:
            case ConfigSaveOutcomeKind.Rejected:
            case ConfigSaveOutcomeKind.HelperUnavailable:
            case ConfigSaveOutcomeKind.TooLarge:
            default:
                _ui.Post(() => ConfigError = outcome.Message ?? "the change could not be saved.");
                return ConfigWriteLanding.NotWritten;
        }
    }

    // --------------------------------------------------------------- poller lifecycle

    /// <summary>
    /// Starts the poller iff <see cref="LoggingEnabled"/>; stops it otherwise. The poller is gated ONLY
    /// on logging being on — NOT on the tab being active or paused (FIX 1, the OPSEC-critical one): while
    /// the proxy is writing browsing history to the on-disk log, the read-and-shred loop MUST keep
    /// draining+truncating it even when the user has left the tab, otherwise unbounded at-rest history
    /// accumulates. The tab-active/paused state only gates whether a drained tick is APPENDED to the
    /// visible <see cref="Rows"/> (see <see cref="OnPollerTick"/>) — every tick still shreds the file.
    /// Idempotent-safe: <see cref="IQueryPoller.StartPolling"/> restarts cleanly and
    /// <see cref="IQueryPoller.StopPolling"/> is a no-op when idle.
    /// </summary>
    private void ReconcilePoller()
    {
        if (_disposed)
        {
            return;
        }

        if (LoggingEnabled)
        {
            if (!_poller.IsRunning)
            {
                _poller.StartPolling(_pollInterval);
            }
        }
        else
        {
            _poller.StopPolling();
        }
    }

    // The tab-active state does NOT touch the poller (FIX 1): the shredder keeps running while logging
    // is on. It only changes whether ticks refresh the display. Phase 5i: because the buffer now
    // accumulates while inactive, re-entering the tab refreshes the display to show what arrived while
    // it was away (previously those rows were dropped).
    partial void OnIsActiveChanged(bool value)
    {
        if (value && !IsPaused)
        {
            RefreshView();
        }
    }

    // Phase 5i: when logging flips on/off, notify session consumers (the Dashboard) so they show the
    // on-state (live counts) or revert to the off-state. Fires from a UI-affine context (enable/disable/
    // load post through _ui), so the Dashboard's Changed handler is UI-safe.
    partial void OnLoggingEnabledChanged(bool value) => RaiseChanged();

    /// <summary>Freezes the live view (Pause) WITHOUT disabling logging AND WITHOUT stopping the poller:
    /// the read-and-shred loop keeps draining+truncating the on-disk log (so at-rest history stays
    /// bounded), but drained ticks are discarded instead of appended to the display while paused (FIX 1).</summary>
    public void Pause()
    {
        if (IsPaused)
        {
            return;
        }

        IsPaused = true;
    }

    /// <summary>Resumes the live view (undo Pause): drained ticks are appended to the display again. The
    /// poller was never stopped by Pause, so there is nothing to restart here.</summary>
    public void Resume()
    {
        if (!IsPaused)
        {
            return;
        }

        IsPaused = false;
    }

    /// <summary>Empties the in-memory ring buffer (design 2.5 "Clear view"), the domain→process
    /// attribution lookup, AND the late-binding pending list — the buffered rows are the on-screen
    /// residue, the lookup is the same browsing-history residue one join away (domain→app pairs), and
    /// each pending entry pins a row + its name, so "clear" must drop all three rather than leave them
    /// in memory until the next poller tick prunes them (after "Stop &amp; clear" no tick ever comes).
    /// A row cleared while pending is let go: a batch landing later has nothing to bind. It also
    /// moves the attribution epoch on, so a fetch still in flight is dropped when it lands rather
    /// than merged back in (see <see cref="OnPollerTick"/>). A display/memory reset only; does not
    /// touch config, the poller, or the on-disk file.</summary>
    public void ClearView()
    {
        _allRows.Clear();
        Rows.Clear();
        _attributionsByName.Clear();
        _pendingAttributions.Clear();
        _attributionEpoch++; // a fetch still in flight now belongs to the cleared session: drop it.
        RefreshCounts();
        RaiseChanged();   // Phase 5i: reset the session aggregates + notify consumers (the Dashboard clears too).
    }

    // --------------------------------------------------------------- IQueryLogSession (Phase 5i)

    /// <inheritdoc/>
    public event EventHandler? Changed;

    /// <inheritdoc/>
    public bool LoggingActive => LoggingEnabled;

    /// <inheritdoc/>
    public QueryLogStats Stats { get; private set; } = QueryLogStats.Empty;

    /// <inheritdoc/>
    public IReadOnlyList<QueryRowViewModel> RecentRows(int max)
    {
        if (max <= 0 || _allRows.Count == 0)
        {
            return Array.Empty<QueryRowViewModel>();
        }

        // Newest first, EXCLUDING the app's own diagnostics self-check (Dashboard-only filter — the raw
        // Query Monitor still shows it). Walk from the tail collecting up to `max` real rows.
        var result = new List<QueryRowViewModel>(Math.Min(max, _allRows.Count));
        for (var i = _allRows.Count - 1; i >= 0 && result.Count < max; i--)
        {
            if (_allRows[i].Name == DiagnosticsSelfCheckName)
            {
                continue;
            }

            result.Add(_allRows[i]);
        }

        return result;
    }

    /// <summary>Recomputes the content-only session <see cref="Stats"/> over the full buffer, then raises
    /// <see cref="Changed"/>. Called on every accumulating tick, on ClearView, and when
    /// <see cref="LoggingEnabled"/> flips — always from a UI-affine context (the poller marshals its
    /// ticks; enable/disable/load post through <see cref="_ui"/>), so consumers' handlers are UI-safe.</summary>
    private void RaiseChanged()
    {
        RecomputeStats();
        Changed?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Derives the per-session aggregates from the buffer: total, blocked (REJECT+SYNTH), cloaked
    /// (CLOAK), answered-locally (server == "-": blocks + cloaks + synth + cache), and the mean latency
    /// over UPSTREAM rows only (locally-answered rows are 0 ms and would drag the average to nothing).</summary>
    private void RecomputeStats()
    {
        var queries = 0;
        var blocked = 0;
        var cloaked = 0;
        var answeredLocally = 0;
        var upstreamCount = 0;
        long upstreamLatencySum = 0;

        foreach (var row in _allRows)
        {
            // Dashboard-only filter: exclude the app's own leak self-check probe from the summary counts.
            if (row.Name == DiagnosticsSelfCheckName)
            {
                continue;
            }

            queries++;
            switch (row.Severity)
            {
                case QuerySeverity.Blocked:
                    blocked++;
                    break;
                case QuerySeverity.Cloaked:
                    cloaked++;
                    break;
                default:
                    break;
            }

            if (row.Server == "-")
            {
                answeredLocally++;
            }
            else
            {
                upstreamCount++;
                upstreamLatencySum += row.DurationMs;
            }
        }

        var avgUpstream = upstreamCount == 0 ? 0 : (int)(upstreamLatencySum / upstreamCount);
        Stats = new QueryLogStats(queries, blocked, cloaked, answeredLocally, upstreamCount, avgUpstream);
    }

    // --------------------------------------------------------------- poller tick → drain → buffer

    /// <summary>
    /// One poll tick. FIRST awaits an attribution fetch (v1.3.0 — awaited, never fire-and-forget,
    /// so the batch is merged BEFORE <see cref="DrainTick"/> runs: the pending rows it re-correlates
    /// and the rows it appends both see data at least as fresh as this tick; the merge and
    /// everything after the await run through <see cref="_ui"/>.Post, keeping all state
    /// UI-thread-confined per IC-5), then drains and appends via <see cref="DrainTick"/>. The
    /// fetch is SKIPPED — not queued — while a previous one is still in flight: the drain is the
    /// OPSEC shredder and must never stack up behind a slow pipe; correlation is best-effort and
    /// simply uses the last merged lookup for that tick (a row that misses out waits on the
    /// pending list and is re-checked when the slow batch lands, within its pending lifetime).
    /// Because a fetch can still be in flight when "Stop &amp; clear" (or any clear) runs, the
    /// batch is merged only after re-checking ON the UI thread that logging is still on AND the
    /// attribution epoch it was fetched under is still current; otherwise it is dropped whole (no
    /// merge, no cursor move) — while the drain below runs either way. <c>async void</c> is the
    /// event-handler idiom (mirrors the view's Click handlers) and nothing can escape it: the fetch
    /// contract is null-on-failure, and the defensive catch degrades a faulted seam to "no data".
    /// </summary>
    private async void OnPollerTick(object? sender, EventArgs e)
    {
        if (_disposed)
        {
            return;
        }

        DnsAttributionBatch? batch = null;
        var fetched = false;
        var epoch = _attributionEpoch; // which attribution session this fetch belongs to
        if (LoggingEnabled && !_attributionFetchInFlight)
        {
            _attributionFetchInFlight = true;
            fetched = true;
            try
            {
                batch = await _attribution.FetchAsync(_attributionAfterSeq, CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (Exception)
            {
                batch = null; // best-effort (IC-16): a faulted fetch is just "no data" this tick
                              // (pending rows wait for the next one) — an exception must never
                              // escape this async void handler.
            }
        }

        _ui.Post(() =>
        {
            if (fetched)
            {
                _attributionFetchInFlight = false;

                // Re-checked HERE — on the UI thread, AFTER the await — because a Stop & clear (or any
                // clear) may have run while the fetch was in flight: such a batch belongs to the
                // cleared session, and merging it would refill the lookup the clear just emptied and
                // un-reset the rewound cursor. It is dropped whole: no merge, no cursor move. Logging
                // being on again (a quick re-enable) is not enough — the epoch must match too.
                if (batch is not null && LoggingEnabled && epoch == _attributionEpoch)
                {
                    _attributionAfterSeq = batch.LastSeq;
                    MergeAttributions(batch.Entries);
                }
            }

            // The shredder is never gated or delayed by any of the above.
            DrainTick();
        });
    }

    /// <summary>
    /// The drain/append tick body. ALWAYS drains the reader (read-and-shred) while running — this is the
    /// load-bearing OPSEC behaviour (FIX 1): the on-disk log is truncated every tick for as long as
    /// logging is on, even when the tab is inactive or paused, so browsing history at rest never
    /// accumulates past ~1 interval. The DISPLAY is what's gated: the drained rows are only appended to
    /// the visible <see cref="Rows"/> when <see cref="IsActive"/> AND not <see cref="IsPaused"/>;
    /// otherwise they are DISCARDED (still shredded, just not shown). Fail-closed by contract — the
    /// reader never throws; a read error only surfaces as <see cref="HadReadError"/>. Runs UI-affine
    /// (posted through <see cref="_ui"/> by <see cref="OnPollerTick"/>), so it touches
    /// <see cref="Rows"/> directly.
    ///
    /// <para>Attribution (v1.3.0): ONE clock read per tick is the time base for everything below —
    /// the candidate prune, the pending age-out, and the APPEND stamp each new row's correlation
    /// window is anchored to. The pending (late-binding) rows are re-correlated FIRST, against the
    /// lookup <see cref="OnPollerTick"/> has just merged this tick's batch into, and BEFORE the
    /// nothing-drained early return — the batch that completes a row usually lands on a tick that
    /// drains nothing new. Each new row is then correlated at append exactly as before; one left at
    /// <see cref="UnknownAppLabel"/> joins the pending list. A tick that lands while logging is OFF
    /// (one already in flight when "Stop &amp; clear" ran) still drains, but appends nothing — the
    /// buffer, and with it the pending list, only ever accumulates while logging is on.</para>
    /// </summary>
    private void DrainTick()
    {
        if (_disposed)
        {
            return;
        }

        // ALWAYS drain (shred the file), regardless of tab-active/paused — this is the shredder.
        var drained = _reader.Drain();
        HadReadError = drained.HadReadError;

        // One clock read is this tick's time base: the prune, the pending age-out, and the append
        // stamp (correlation anchor) of every row appended below. Age out stale attribution
        // candidates every tick so the lookup stays bounded and a long-gone process can never claim
        // a fresh query.
        var nowMs = _clock().ToUnixTimeMilliseconds();
        PruneAttributions(nowMs);

        // Late binding (v1.3.0): rows still showing "—" get another look now that this tick's batch
        // is merged — before the early return, since that batch usually lands on a tick that drains
        // nothing new.
        RebindPendingAttributions(nowMs);

        if (drained.Lines.Count == 0)
        {
            return;
        }

        // A tick that lands after logging went off (one already in flight when "Stop & clear" ran)
        // has still shredded above — the drain is never gated — but must not refill a buffer that
        // exists only while logging is on: rows appended now would outlive the clear, and sit on the
        // pending list with no tick left to age them out.
        if (!LoggingEnabled)
        {
            return;
        }

        // Phase 5i: ALWAYS accumulate into the session buffer, regardless of tab-active/paused — the
        // Dashboard reads live stats + recent queries from this buffer while the Query Monitor tab is
        // inactive. Same OPSEC posture as before: bounded (ring buffer), in-memory, per-session, purged
        // on disable. Only the VISIBLE list is gated on active/not-paused (below).
        foreach (var line in drained.Lines)
        {
            // Correlated at append around nowMs — this row's anchor for good — exactly as before; a
            // row that comes up unknown waits on the pending list for its attribution to land.
            var key = NormalizeQueryName(line.Name);
            var row = new QueryRowViewModel(line, ResolveAppFor(key, nowMs));
            AppendRow(row);
            if (row.App == UnknownAppLabel && key.Length > 0)
            {
                TrackPendingAttribution(row, key, nowMs); // an empty key can never match: no slot.
            }
        }

        // The DISPLAY (visible Rows) still only refreshes while the tab is active AND not paused, so
        // glancing away never churns the list; the accumulated buffer is shown when the tab is
        // re-entered (OnIsActiveChanged) or resumed.
        if (IsActive && !IsPaused)
        {
            RefreshView();
        }

        // Notify session consumers (the Dashboard) with fresh aggregates (also recomputes Stats).
        RaiseChanged();
    }

    // --------------------------------------------------------------- per-app attribution (v1.3.0)

    /// <summary>The honest unknown (IC-16): shown when no attribution matched a row — including
    /// every degraded case (fetch failed, helper old, ETW unavailable). Never a guess.</summary>
    internal const string UnknownAppLabel = "—";

    /// <summary>Shown when MORE THAN ONE distinct process looked the row's name up inside the
    /// correlation window — naming any one of them would be a guess (IC-16).</summary>
    internal const string MultipleAppsLabel = "multiple";

    // The correlation window is ASYMMETRIC around a row's anchor — its APPEND time, the clock read of
    // the tick that drained it: [anchor − AttributionLookback, anchor + AttributionForwardSlack]. A
    // query-log row exists only AFTER its lookup was answered, and it is anchored later still (when a
    // tick drains it), so the lookup that produced the row was raised BEFORE the anchor; late binding
    // only ever needs late-ARRIVING events from the past. A candidate stamped seconds AFTER the anchor
    // can only be a DIFFERENT, later lookup of the same name (nslookup at t=0 raises no DNS-client
    // event of its own; chrome resolving the same name at t=+3 s would otherwise claim the nslookup
    // row) — a guess IC-16 forbids. At append time the forward edge changes nothing (no candidate
    // stamped after the anchor exists yet); it only matters to the late-binding re-checks.

    /// <summary>How far BEFORE a row's anchor a candidate may be stamped. Rows are at most one poll
    /// (~750 ms) old when appended and an event reaches the helper within ETW's ~1 s flush, so 5 s
    /// comfortably absorbs the capture→proxy-log→drain pipeline plus skew between the helper's
    /// stamps and this process — while staying narrow enough that an old lookup of the same name
    /// cannot claim a fresh query. The first check (at append) and every late-binding re-check judge
    /// the SAME window around the SAME anchor, never around "now".</summary>
    private static readonly TimeSpan AttributionLookback = TimeSpan.FromSeconds(5);

    /// <summary>How far AFTER a row's anchor a candidate may be stamped: timestamp-jitter slack only
    /// (helper and UI read the same machine clock), never room for a later lookup. Sound because the
    /// helper stamps each candidate with WHEN THE LOOKUP HAPPENED — the ETW event's own timestamp
    /// (<c>DnsAttributionWatcher.HandleQueryEvent</c>), not the moment its ~1 s flush batch was
    /// delivered — so a row's own lookup is always stamped before the row's anchor.</summary>
    private static readonly TimeSpan AttributionForwardSlack = TimeSpan.FromMilliseconds(500);

    /// <summary>How long merged candidates are retained before pruning — comfortably past the
    /// correlation window (nothing older can ever match) and past the late-binding horizon (a
    /// pending row is re-checked at most <see cref="PendingAttributionLifetime"/> after its append,
    /// against candidates stamped at most <see cref="AttributionLookback"/> before that append, so
    /// none it could still match is ever older than 13 s), while keeping the lookup small.</summary>
    private static readonly TimeSpan AttributionRetention = TimeSpan.FromSeconds(30);

    /// <summary>Per-name candidate cap: only the most recent few can fall inside the 5 s look-back,
    /// so keeping more would only serve stale data.</summary>
    private const int MaxAttributionCandidatesPerName = 4;

    /// <summary>Hard cap on distinct names in the lookup (matches the helper ring's bound): the
    /// 30 s prune keeps it far smaller in practice; past the cap new names are dropped (attribution
    /// is best-effort — bounded memory wins over completeness).</summary>
    private const int MaxAttributionNames = 2048;

    /// <summary>How long a row appended as <see cref="UnknownAppLabel"/> waits on the late-binding
    /// pending list. A candidate that can still match is stamped no later than
    /// <see cref="AttributionForwardSlack"/> after the anchor, but it still has to reach the UI — ETW
    /// hands the helper its events in ~1 s flush batches, the next poll fetches them, and a fetch is
    /// skipped while a slow one is still in flight — so 8 s leaves a wide margin for a slow pipe.
    /// Past it the row gives up and keeps the honest unknown for good.</summary>
    internal static readonly TimeSpan PendingAttributionLifetime = TimeSpan.FromSeconds(8);

    /// <summary>Hard cap on pending rows — bounded memory regardless of query volume (a heavy
    /// 12.5 q/s of all-unknown rows keeps ~100 pending over the 8 s lifetime). Past it the OLDEST
    /// pending row gives up first: it has had the longest to bind, while the newest is the one
    /// whose attribution is likeliest still in flight.</summary>
    internal const int MaxPendingAttributions = 256;

    /// <summary>The by-name attribution lookup (keys normalized: lowercase, trailing dot
    /// stripped). UI-thread-confined like every other piece of VM state. Pruned to ~30 s by the
    /// poller ticks AND dropped outright by <see cref="ClearView"/> (so "Stop &amp; clear" leaves
    /// no domain→process residue behind once the ticks stop).</summary>
    private readonly Dictionary<string, List<AttributionCandidate>> _attributionsByName = new(StringComparer.Ordinal);

    /// <summary>Test seam: the number of distinct names the attribution lookup currently holds —
    /// lets the OPSEC tests prove disable/ClearView actually dropped the domain→process residue
    /// (mirroring the other internal observability seams here).</summary>
    internal int AttributionLookupCount => _attributionsByName.Count;

    /// <summary>The late-binding pending list (v1.3.0): rows appended as <see cref="UnknownAppLabel"/>
    /// whose attribution may still be in flight, oldest first — each with its normalized key and its
    /// append stamp (the anchor its window is judged around). Bounded by
    /// <see cref="MaxPendingAttributions"/> and <see cref="PendingAttributionLifetime"/>, always an
    /// in-order subsequence of <see cref="_allRows"/> (a row the ring evicts leaves with it — see
    /// <see cref="AppendRow"/>), UI-thread-confined, and dropped by <see cref="ClearView"/> with the
    /// rest of the attribution residue.</summary>
    private readonly List<PendingAttribution> _pendingAttributions = new();

    /// <summary>Test seam: the number of rows currently awaiting a late binding — lets the tests
    /// prove the pending list stays bounded and that disable/ClearView drop it (mirroring
    /// <see cref="AttributionLookupCount"/>).</summary>
    internal int PendingAttributionCount => _pendingAttributions.Count;

    /// <summary>The poll cursor: the last batch's <c>LastSeq</c>, sent back so each attribution
    /// entry crosses the pipe exactly once.</summary>
    private long _attributionAfterSeq;

    /// <summary>True while a fetch is awaiting the pipe — the next tick skips its fetch (never
    /// queues) so the shredder drain is never delayed by a slow helper.</summary>
    private bool _attributionFetchInFlight;

    /// <summary>The attribution session epoch: bumped by every <see cref="ClearView"/> — and so by
    /// "Stop &amp; clear" and the launch reset. A fetch captures it before awaiting the pipe, and its
    /// batch is merged only if the epoch is unchanged AND logging is still on: a batch fetched before
    /// a clear belongs to the session that was cleared, so it is dropped whole — never merged into the
    /// emptied lookup, never moving the (possibly rewound) cursor. After a plain "Clear view" (logging
    /// still on, cursor untouched) the next fetch simply re-requests those entries.
    /// UI-thread-confined like the rest of the attribution state.</summary>
    private long _attributionEpoch;

    /// <summary>Folds one fetched batch into the by-name lookup, newest-last (batches arrive
    /// oldest → newest), enforcing both bounds. Names are normalized so the ETW spelling (often
    /// with a trailing dot / mixed case) meets the proxy log's spelling on equal terms.</summary>
    private void MergeAttributions(IReadOnlyList<DnsAttributionEntry> entries)
    {
        foreach (var entry in entries)
        {
            var key = NormalizeQueryName(entry.QueryName);
            if (key.Length == 0)
            {
                continue;
            }

            if (!_attributionsByName.TryGetValue(key, out var candidates))
            {
                if (_attributionsByName.Count >= MaxAttributionNames)
                {
                    continue; // bounded: drop new names rather than grow without limit.
                }

                candidates = new List<AttributionCandidate>(MaxAttributionCandidatesPerName);
                _attributionsByName[key] = candidates;
            }

            candidates.Add(new AttributionCandidate(entry.ProcessId, entry.ProcessName, entry.UnixTimeMs));
            if (candidates.Count > MaxAttributionCandidatesPerName)
            {
                candidates.RemoveAt(0); // oldest first — entries arrive in capture order.
            }
        }
    }

    /// <summary>Drops candidates older than <see cref="AttributionRetention"/> (and then-empty
    /// names) so the lookup can never accumulate a session's worth of history — while ticks run it
    /// only ever holds the last ~30 s needed for correlation, and when they STOP the final window
    /// is dropped too (<see cref="ClearView"/>, run by "Stop &amp; clear"), never left behind.</summary>
    private void PruneAttributions(long nowMs)
    {
        List<string>? empty = null;
        foreach (var (name, candidates) in _attributionsByName)
        {
            candidates.RemoveAll(c => nowMs - c.UnixTimeMs > (long)AttributionRetention.TotalMilliseconds);
            if (candidates.Count == 0)
            {
                (empty ??= new List<string>()).Add(name);
            }
        }

        if (empty is not null)
        {
            foreach (var name in empty)
            {
                _attributionsByName.Remove(name);
            }
        }
    }

    /// <summary>Puts a row that came up <see cref="UnknownAppLabel"/> at append on the pending list,
    /// stamped with its append time. At the cap the OLDEST pending row gives up first and keeps the
    /// honest unknown (see <see cref="MaxPendingAttributions"/>).</summary>
    private void TrackPendingAttribution(QueryRowViewModel row, string key, long appendedAtMs)
    {
        if (_pendingAttributions.Count >= MaxPendingAttributions)
        {
            _pendingAttributions.RemoveAt(0);
        }

        _pendingAttributions.Add(new PendingAttribution(row, key, appendedAtMs));
    }

    /// <summary>
    /// Late binding (v1.3.0) — runs every tick, right after that tick's batch is merged. ETW
    /// delivers a lookup's event in ~1 s flush batches, so the tick that drains its log line often
    /// runs BEFORE the tick that fetches the event; deciding only at append would leave such rows
    /// <see cref="UnknownAppLabel"/> forever even though the matching attribution lands a tick
    /// later. So each pending row is re-correlated by <see cref="ResolveAppFor"/> around its APPEND
    /// stamp (never "now" — the same window its first check used): a decision (one process → its
    /// name or <c>PID n</c>; more than one → <see cref="MultipleAppsLabel"/>) is written into the
    /// row via <see cref="QueryRowViewModel.TryBindApp"/> and the row leaves pending for good; no
    /// match yet keeps it waiting; a row older than <see cref="PendingAttributionLifetime"/> —
    /// measured in either direction, so a wall-clock step cannot pin it — gives up and keeps the
    /// honest unknown. Never guesses, never revisits a decided row.
    /// </summary>
    private void RebindPendingAttributions(long nowMs)
    {
        if (_pendingAttributions.Count == 0)
        {
            return;
        }

        var lifetimeMs = (long)PendingAttributionLifetime.TotalMilliseconds;
        List<(QueryRowViewModel Row, string App)>? decided = null;
        _pendingAttributions.RemoveAll(pending =>
        {
            if (Math.Abs(nowMs - pending.AppendedAtMs) > lifetimeMs)
            {
                return true; // aged out: nothing that could still match is in flight any more.
            }

            var app = ResolveAppFor(pending.Key, pending.AppendedAtMs);
            if (app == UnknownAppLabel)
            {
                return false; // nothing inside its window yet — keep waiting.
            }

            (decided ??= new()).Add((pending.Row, app));
            return true; // decided — it leaves pending for good.
        });

        // Bind only once the list is compacted: each bind raises PropertyChanged (the cell updates in
        // place), and no handler should ever observe a half-compacted pending list.
        if (decided is not null)
        {
            foreach (var (row, app) in decided)
            {
                row.TryBindApp(app);
            }
        }
    }

    /// <summary>Correlates one row against the lookup: candidates for its normalized
    /// <paramref name="key"/> stamped inside [<paramref name="anchorMs"/> − <see cref="AttributionLookback"/>,
    /// <paramref name="anchorMs"/> + <see cref="AttributionForwardSlack"/>] — the anchor being the
    /// row's APPEND stamp, both at append (where it is that tick's now and no later-stamped candidate
    /// exists yet, so the result is exactly the append-time behaviour this always had) and on every
    /// late-binding re-check. Only in-window candidates count: exactly ONE distinct process → its
    /// name (or a bare <c>PID n</c> when the name was unresolvable — the process had exited at
    /// capture); more than one distinct process → <see cref="MultipleAppsLabel"/>; none →
    /// <see cref="UnknownAppLabel"/>. Never guesses (IC-16).</summary>
    private string ResolveAppFor(string key, long anchorMs)
    {
        if (key.Length == 0 || !_attributionsByName.TryGetValue(key, out var candidates))
        {
            return UnknownAppLabel;
        }

        var earliestMs = anchorMs - (long)AttributionLookback.TotalMilliseconds;
        var latestMs = anchorMs + (long)AttributionForwardSlack.TotalMilliseconds;
        var any = false;
        var matchedPid = 0;
        string? matchedName = null;
        foreach (var candidate in candidates)
        {
            if (candidate.UnixTimeMs < earliestMs || candidate.UnixTimeMs > latestMs)
            {
                continue; // outside the window — not a candidate, not even a rival one.
            }

            if (!any)
            {
                any = true;
                matchedPid = candidate.ProcessId;
                matchedName = candidate.ProcessName;
            }
            else if (candidate.ProcessId != matchedPid)
            {
                return MultipleAppsLabel; // two distinct processes — naming either is a guess.
            }
            else
            {
                matchedName ??= candidate.ProcessName; // same pid — take any capture that got a name.
            }
        }

        if (!any)
        {
            return UnknownAppLabel;
        }

        return matchedName ?? string.Create(CultureInfo.InvariantCulture, $"PID {matchedPid}");
    }

    /// <summary>Correlation key normalization: the ETW payload name is often FQDN-dotted and/or
    /// differently cased from the proxy log's qname — lowercase + strip ONE trailing dot so the
    /// two spellings of the same lookup meet on one key.</summary>
    private static string NormalizeQueryName(string name)
    {
        var trimmed = name.Length > 0 && name[^1] == '.' ? name[..^1] : name;
        return trimmed.ToLowerInvariant();
    }

    /// <summary>One merged attribution candidate: who (pid + name resolved at capture) looked the
    /// key name up, and when — the when drives both the correlation-window match and the 30 s
    /// prune.</summary>
    private readonly record struct AttributionCandidate(int ProcessId, string? ProcessName, long UnixTimeMs);

    /// <summary>One late-binding pending row: the row itself (the SAME instance every surface holds,
    /// so binding it updates them all in place), its normalized correlation key, and its append
    /// stamp — the anchor of its correlation window and the start of its pending lifetime.</summary>
    private readonly record struct PendingAttribution(QueryRowViewModel Row, string Key, long AppendedAtMs);

    /// <summary>Appends one row to the buffer, evicting the oldest past the <see cref="MaxRows"/> cap so
    /// memory stays bounded (ring buffer). An evicted row also leaves the late-binding pending list, so
    /// the ring cap stays THE bound on rows held in memory (a frozen paused display may still show such
    /// a row; it simply keeps the honest unknown). Does NOT rebuild the view — the caller batches that
    /// per tick.</summary>
    private void AppendRow(QueryRowViewModel row)
    {
        _allRows.Add(row);
        var overflow = _allRows.Count - MaxRows;
        if (overflow <= 0)
        {
            return;
        }

        // Both lists are in append order and pending is a subsequence of the buffer, so a pending row
        // being evicted is always at the pending head: one merge-walk over the evicted prefix.
        for (var i = 0; i < overflow && _pendingAttributions.Count > 0; i++)
        {
            if (ReferenceEquals(_pendingAttributions[0].Row, _allRows[i]))
            {
                _pendingAttributions.RemoveAt(0);
            }
        }

        _allRows.RemoveRange(0, overflow);
    }

    partial void OnSearchTextChanged(string value) => RefreshView();

    partial void OnActionFilterChanged(QueryActionFilter value) => RefreshView();

    /// <summary>Rebuilds <see cref="Rows"/> from the buffer under the current search + action filter, then
    /// refreshes the counts headline. Replaces the collection contents wholesale (the buffer is small and
    /// bounded, so a clear+re-add is simpler and correct than an incremental diff).</summary>
    private void RefreshView()
    {
        var search = SearchText.Trim();
        Rows.Clear();
        foreach (var row in _allRows)
        {
            if (!MatchesActionFilter(row))
            {
                continue;
            }

            if (search.Length > 0 && !row.Name.Contains(search, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            Rows.Add(row);
        }

        RefreshCounts();
    }

    /// <summary>Content-derived counts over the CURRENTLY-SHOWN rows (IC-16): shown = the filtered count,
    /// blocked = REJECT+SYNTH, cloaked = CLOAK. Never claims more than the visible content backs.</summary>
    private void RefreshCounts()
    {
        var shown = Rows.Count;
        var blocked = 0;
        var cloaked = 0;
        foreach (var row in Rows)
        {
            switch (row.Severity)
            {
                case QuerySeverity.Blocked:
                    blocked++;
                    break;
                case QuerySeverity.Cloaked:
                    cloaked++;
                    break;
                default:
                    break;
            }
        }

        CountsHeadline = $"{shown} shown · {blocked} blocked · {cloaked} cloaked.";
    }

    /// <summary>True when a row passes the current <see cref="ActionFilter"/> (All matches everything;
    /// Blocked = REJECT+SYNTH; Cloaked = CLOAK; Passed = PASS).</summary>
    private bool MatchesActionFilter(QueryRowViewModel row) => ActionFilter switch
    {
        QueryActionFilter.All => true,
        QueryActionFilter.Blocked => row.Severity == QuerySeverity.Blocked,
        QueryActionFilter.Cloaked => row.Severity == QuerySeverity.Cloaked,
        QueryActionFilter.Passed => row.Action == QueryAction.Pass,
        _ => true,
    };

    public void Dispose()
    {
        _disposed = true;
        _poller.Tick -= OnPollerTick;
        _poller.StopPolling();
        if (_poller is IDisposable disposablePoller)
        {
            disposablePoller.Dispose();
        }

        GC.SuppressFinalize(this);
    }

    // --------------------------------------------------------------- static text + support types

    /// <summary>The honesty banner text shown while logging is ON (design 2.5). States plainly that the
    /// on-disk log is continuously shredded while logging is on — NOT only when you are viewing the tab
    /// (FIX 1) — that entries are kept only in memory, and that logging is PER-SESSION (FIX HIGH-1): it
    /// turns off when you stop it OR close the app, and is off again next launch.</summary>
    public const string LoggingOnBannerText =
        "Query logging is ON — this records every domain you look up. While logging is on, the on-disk " +
        "log is continuously shredded (even when you leave this tab) and entries are kept only in memory. " +
        "Logging is per-session: it turns off when you stop it or close the app, and starts off again next launch.";

    /// <summary>The result of the fresh read-modify-write preparation (analogous to Filtering's
    /// PrepareResult): a ready candidate + fresh sha, or a typed failure reason.</summary>
    private sealed record ConfigWriteResult(bool Success, string? CandidateText, string? BaseSha256, string? Error)
    {
        public static ConfigWriteResult Ready(string candidate, string sha) => new(true, candidate, sha, null);

        public static ConfigWriteResult Failed(string error) => new(false, null, null, error);
    }

    /// <summary>How a config write LANDED (FIX MED-2). <see cref="NotWritten"/> = nothing on disk;
    /// <see cref="Applied"/> = on disk AND the proxy confirmed the restart; <see cref="LandedUnconfirmed"/>
    /// = on disk but the proxy restart was not confirmed (RestartFailed / ProxyRejected). Callers that
    /// must reflect the on-disk truth (enable/disable) treat both landed cases as "written", but a disable
    /// uses the unconfirmed distinction to avoid claiming a clean stop it cannot verify.</summary>
    private enum ConfigWriteLanding
    {
        NotWritten,
        Applied,
        LandedUnconfirmed,
    }
}

/// <summary>The Query Monitor's live action filter (design 2.5): All / Blocked (REJECT+SYNTH) /
/// Cloaked (CLOAK) / Passed (PASS).</summary>
public enum QueryActionFilter
{
    /// <summary>Show every buffered query.</summary>
    All,

    /// <summary>Show only locally-blocked queries (REJECT + SYNTH).</summary>
    Blocked,

    /// <summary>Show only cloaked queries (CLOAK).</summary>
    Cloaked,

    /// <summary>Show only upstream-resolved queries (PASS).</summary>
    Passed,
}

/// <summary>
/// A pending "enable query logging" consent (IC-QM2): the enable command arms this and writes nothing;
/// the view shows a plain-language <c>ContentDialog</c> and routes the user's choice to the VM's
/// <see cref="QueryMonitorViewModel.ConfirmEnableAsync"/> / <see cref="QueryMonitorViewModel.CancelEnable"/>.
/// Pure VM state — the VM never references WPF. <see cref="LogPath"/> is the absolute per-user path the
/// dialog names so the user sees exactly where their browsing history will be written.
/// </summary>
/// <param name="LogPath">The absolute <c>%LOCALAPPDATA%</c> query-log path logging would write to.</param>
public sealed record LoggingConsentRequest(string LogPath);
