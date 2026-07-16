using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using DnsCryptControl.Core.QueryLog;
using DnsCryptControl.Core.Security;
using DnsCryptControl.Core.Toml;
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
    private readonly TimeSpan _pollInterval;

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

    /// <param name="pollInterval">The read-and-shred poll cadence; defaults to ~750 ms. Tests pass any
    /// value — they never wait on it, they pump the fake poller's ticks directly.</param>
    public QueryMonitorViewModel(
        IConfigFileService configFile,
        IQueryLogReader reader,
        IQueryPoller poller,
        IUiDispatcher ui,
        TimeSpan? pollInterval = null)
    {
        ArgumentNullException.ThrowIfNull(configFile);
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(poller);
        ArgumentNullException.ThrowIfNull(ui);
        _configFile = configFile;
        _reader = reader;
        _poller = poller;
        _ui = ui;
        _pollInterval = pollInterval ?? DefaultPollInterval;
        _poller.Tick += OnPollerTick;
    }

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
            // clear, and the buffered rows are the on-screen residue.
            _ui.Post(ClearView);
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

    /// <summary>Empties the in-memory ring buffer (design 2.5 "Clear view") — a display reset only; does
    /// not touch config, the poller, or the on-disk file.</summary>
    public void ClearView()
    {
        _allRows.Clear();
        Rows.Clear();
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
    /// One poll tick. ALWAYS drains the reader (read-and-shred) while running — this is the load-bearing
    /// OPSEC behaviour (FIX 1): the on-disk log is truncated every tick for as long as logging is on,
    /// even when the tab is inactive or paused, so browsing history at rest never accumulates past ~1
    /// interval. The DISPLAY is what's gated: the drained rows are only appended to the visible
    /// <see cref="Rows"/> when <see cref="IsActive"/> AND not <see cref="IsPaused"/>; otherwise they are
    /// DISCARDED (still shredded, just not shown). Fail-closed by contract — the reader never throws; a
    /// read error only surfaces as <see cref="HadReadError"/>. Runs UI-affine (the poller marshals its
    /// ticks through the dispatcher), so it touches <see cref="Rows"/> directly.
    /// </summary>
    private void OnPollerTick(object? sender, EventArgs e)
    {
        if (_disposed)
        {
            return;
        }

        // ALWAYS drain (shred the file), regardless of tab-active/paused — this is the shredder.
        var drained = _reader.Drain();
        HadReadError = drained.HadReadError;

        if (drained.Lines.Count == 0)
        {
            return;
        }

        // Phase 5i: ALWAYS accumulate into the session buffer, regardless of tab-active/paused — the
        // Dashboard reads live stats + recent queries from this buffer while the Query Monitor tab is
        // inactive. Same OPSEC posture as before: bounded (ring buffer), in-memory, per-session, purged
        // on disable. Only the VISIBLE list is gated on active/not-paused (below).
        foreach (var line in drained.Lines)
        {
            AppendRow(new QueryRowViewModel(line));
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

    /// <summary>Appends one row to the buffer, evicting the oldest past the <see cref="MaxRows"/> cap so
    /// memory stays bounded (ring buffer). Does NOT rebuild the view — the caller batches that per tick.</summary>
    private void AppendRow(QueryRowViewModel row)
    {
        _allRows.Add(row);
        if (_allRows.Count > MaxRows)
        {
            _allRows.RemoveRange(0, _allRows.Count - MaxRows);
        }
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
