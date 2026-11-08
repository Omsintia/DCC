using System.ComponentModel;
using DnsCryptControl.Core.QueryLog;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.UI.Models;
using DnsCryptControl.UI.Services;
using DnsCryptControl.UI.ViewModels;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// Phase 5e Group C: <see cref="QueryMonitorViewModel"/> — the consent-gated, read-and-shred Query
/// Monitor. Proves the OPSEC-load-bearing behaviours the design flags (§2.5, IC-QM1..6):
/// <list type="bullet">
///   <item><b>Off by default + consent gate (IC-QM1/2):</b> a fresh config yields logging OFF; the
///     enable command only ARMS a consent request and writes NOTHING; Cancel writes nothing; Confirm
///     writes <c>query_log.file</c> and starts the poller.</item>
///   <item><b>Disable clears (IC-QM5):</b> Disable unsets the config key, stops the poller, and purges
///     the on-disk file.</item>
///   <item><b>Read-and-shred plumbing:</b> a poller tick drains the reader, appends parsed rows to the
///     bounded ring buffer (cap + eviction), and derives content counts; a reader error never crashes.</item>
///   <item><b>Poller lifecycle:</b> the poller runs ONLY while logging is enabled AND the tab is active
///     AND not paused.</item>
/// </list>
///
/// <para>Pure-POCO/IC-5: no WPF types, every post-await observable write through the injected
/// <see cref="IUiDispatcher"/>, and a FAKE poller pumped synchronously (zero wall-clock sleeps),
/// mirroring the <c>SynchronousDispatcher</c>/injected-seam style of the other VM tests.</para>
/// </summary>
public class QueryMonitorViewModelTests
{
    private static readonly string Sha = new('a', 64);

    // ------------------------------------------------------------------ fixtures

    private sealed class SynchronousDispatcher : IUiDispatcher
    {
        public void Post(Action action) => action();
    }

    private sealed class FakeConfigFileService : IConfigFileService
    {
        public Queue<ConfigLoadResult> LoadQueue { get; } = new();
        public ConfigLoadResult NextLoad { get; set; } = ConfigLoadResult.Ok(string.Empty, Sha);
        public List<(string Text, string BaseSha256)> SaveCalls { get; } = new();
        public Func<string, string, CancellationToken, Task<ConfigSaveOutcome>>? SaveHandler { get; set; }

        public ConfigLoadResult Load() => LoadQueue.Count > 0 ? LoadQueue.Dequeue() : NextLoad;

        public Task<ConfigSaveOutcome> SaveAndApplyAsync(string candidateText, string baseSha256, CancellationToken ct)
        {
            SaveCalls.Add((candidateText, baseSha256));
            return SaveHandler?.Invoke(candidateText, baseSha256, ct)
                ?? Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Applied, null));
        }
    }

    private sealed class FakeQueryLogReader : IQueryLogReader
    {
        public Queue<DrainedQueries> DrainQueue { get; } = new();
        public int DrainCalls { get; private set; }
        public int PurgeCalls { get; private set; }

        public DrainedQueries Drain()
        {
            DrainCalls++;
            return DrainQueue.Count > 0 ? DrainQueue.Dequeue() : DrainedQueries.Empty;
        }

        public void Purge() => PurgeCalls++;

        public void Enqueue(params QueryLogLine[] lines) =>
            DrainQueue.Enqueue(new DrainedQueries(lines, HadReadError: false));

        public void EnqueueReadError() =>
            DrainQueue.Enqueue(new DrainedQueries(Array.Empty<QueryLogLine>(), HadReadError: true));
    }

    /// <summary>A hand-pumped poller: no timer, no sleeps. <see cref="Fire"/> raises one tick so tests
    /// drive the drain synchronously; <see cref="IsRunning"/> tracks StartPolling/StopPolling.</summary>
    private sealed class FakeQueryPoller : IQueryPoller
    {
        public event EventHandler? Tick;
        public bool IsRunning { get; private set; }
        public int StartCalls { get; private set; }
        public int StopCalls { get; private set; }
        public TimeSpan? LastInterval { get; private set; }

        public void StartPolling(TimeSpan interval)
        {
            StartCalls++;
            LastInterval = interval;
            IsRunning = true;
        }

        public void StopPolling()
        {
            if (IsRunning)
            {
                StopCalls++;
            }

            IsRunning = false;
        }

        /// <summary>Raise one tick (only meaningful while running — the production poller only ticks then).</summary>
        public void Fire() => Tick?.Invoke(this, EventArgs.Empty);
    }

    private sealed class FakeUiStateStore : IUiStateStore
    {
        public UiState ToLoad { get; set; } = new();
        public UiState Saved { get; private set; } = new();
        public int SaveCount { get; private set; }

        public UiState Load() => ToLoad;

        public void Save(UiState state)
        {
            Saved = state;
            SaveCount++;
        }
    }

    /// <summary>Scriptable per-tick attribution seam (v1.3.0): each fetch dequeues one scripted
    /// batch (falling back to <see cref="NextBatch"/> — default null, i.e. the degraded/no-data
    /// case, so pre-existing tests exercise the honest "—" path) and records the afterSeq cursor.
    /// Always a completed Task, so ticks stay synchronous end-to-end (zero wall-clock waits).</summary>
    private sealed class FakeAttributionReader : IDnsAttributionReader
    {
        public Queue<DnsAttributionBatch?> BatchQueue { get; } = new();
        public DnsAttributionBatch? NextBatch { get; set; }
        public List<long> FetchCalls { get; } = new();

        /// <summary>One-shot: when set, the NEXT fetch returns this gate's task instead of a completed
        /// one, so a test can hold a fetch in flight across a Stop &amp; clear and complete it after.
        /// A plain TaskCompletionSource runs the VM's ConfigureAwait(false) continuation inline on
        /// SetResult, so the late continuation has run by the time SetResult returns — zero sleeps.</summary>
        public TaskCompletionSource<DnsAttributionBatch?>? Gate { get; set; }

        public Task<DnsAttributionBatch?> FetchAsync(long afterSeq, CancellationToken ct)
        {
            FetchCalls.Add(afterSeq);
            if (Gate is { } gate)
            {
                Gate = null;
                return gate.Task;
            }

            var batch = BatchQueue.Count > 0 ? BatchQueue.Dequeue() : NextBatch;
            return Task.FromResult(batch);
        }

        public void Enqueue(long lastSeq, params DnsAttributionEntry[] entries) =>
            BatchQueue.Enqueue(new DnsAttributionBatch(lastSeq, entries));
    }

    /// <summary>A hand-advanced UTC clock for the late-binding tests: the VM's clock seam reads
    /// <see cref="Now"/>, so the pending-lifetime and window-anchor tests move time by exactly what
    /// they name — zero wall-clock sleeps. Starts at a fixed instant so every stamp is deterministic.</summary>
    private sealed class ManualClock
    {
        private DateTimeOffset _now = new(2026, 7, 3, 10, 24, 59, TimeSpan.Zero);

        public DateTimeOffset Now() => _now;

        public long NowMs => _now.ToUnixTimeMilliseconds();

        public void Advance(TimeSpan by) => _now += by;
    }

    private sealed class Harness : IDisposable
    {
        public FakeConfigFileService Config { get; } = new();
        public FakeQueryLogReader Reader { get; } = new();
        public FakeQueryPoller Poller { get; } = new();
        public FakeUiStateStore UiState { get; } = new();
        public FakeAttributionReader Attribution { get; } = new();
        public QueryMonitorViewModel Vm { get; }

        /// <param name="clock">The VM's clock seam; null = the real clock (every pre-late-binding test
        /// runs exactly as before, stamping entries with the real now).</param>
        public Harness(UiState? initialUiState = null, Func<DateTimeOffset>? clock = null)
        {
            if (initialUiState is not null)
            {
                UiState.ToLoad = initialUiState;
            }

            Vm = new QueryMonitorViewModel(
                Config, Reader, Poller, new SynchronousDispatcher(), UiState, Attribution, clock: clock);
        }

        public void Dispose() => Vm.Dispose();
    }

    private static QueryLogLine Line(
        string name, QueryAction action = QueryAction.Pass, string type = "A", string time = "[2026-07-03 10:24:59]") =>
        new(time, "127.0.0.1", name, type, action, 12, action is QueryAction.Pass ? "cloudflare" : "-", "-");

    // ------------------------------------------------------------------ column layout (resizable headers)

    [Fact]
    public void ctor_seeds_column_widths_from_persisted_state()
    {
        using var h = new Harness(new UiState
        {
            QueryMonitorColumns = new UiQueryMonitorColumns { Time = 100, Type = 40, Action = 90, Latency = 70, Server = 300, App = 130 },
        });

        Assert.Equal(100, h.Vm.TimeColumnWidth);
        Assert.Equal(40, h.Vm.TypeColumnWidth);
        Assert.Equal(90, h.Vm.ActionColumnWidth);
        Assert.Equal(70, h.Vm.LatencyColumnWidth);
        Assert.Equal(300, h.Vm.ServerColumnWidth);
        Assert.Equal(130, h.Vm.AppColumnWidth);
    }

    [Fact]
    public void ctor_clamps_hand_edited_widths_to_the_grabbable_range()
    {
        // A hand-edited ui-state.json must never produce an ungrabbable (0-width) or runaway column.
        using var h = new Harness(new UiState
        {
            QueryMonitorColumns = new UiQueryMonitorColumns { Time = 0, Type = -50, Action = 5000, Latency = double.NaN, Server = double.PositiveInfinity, App = -1 },
        });

        Assert.Equal(QueryMonitorViewModel.MinColumnWidth, h.Vm.TimeColumnWidth);
        Assert.Equal(QueryMonitorViewModel.MinColumnWidth, h.Vm.TypeColumnWidth);
        Assert.Equal(QueryMonitorViewModel.MaxColumnWidth, h.Vm.ActionColumnWidth);
        Assert.Equal(QueryMonitorViewModel.MinColumnWidth, h.Vm.LatencyColumnWidth);
        Assert.Equal(QueryMonitorViewModel.MinColumnWidth, h.Vm.ServerColumnWidth);
        Assert.Equal(QueryMonitorViewModel.MinColumnWidth, h.Vm.AppColumnWidth);
    }

    [Fact]
    public void app_column_resizes_clamps_and_persists_like_the_others()
    {
        // v1.3.0: the App column is a full member of the resizable-column set — same clamp arms,
        // same commit path.
        using var h = new Harness();
        var start = h.Vm.AppColumnWidth;

        h.Vm.ResizeColumn(QueryMonitorColumn.App, 30);
        Assert.Equal(start + 30, h.Vm.AppColumnWidth);

        h.Vm.ResizeColumn(QueryMonitorColumn.App, -10_000);
        Assert.Equal(QueryMonitorViewModel.MinColumnWidth, h.Vm.AppColumnWidth);

        h.Vm.CommitColumnWidths();
        Assert.Equal(1, h.UiState.SaveCount);
        Assert.Equal(h.Vm.AppColumnWidth, h.UiState.Saved.QueryMonitorColumns.App);
    }

    [Fact]
    public void resize_column_applies_the_delta_and_clamps_at_both_ends()
    {
        using var h = new Harness();
        var start = h.Vm.ServerColumnWidth;

        h.Vm.ResizeColumn(QueryMonitorColumn.Server, 40);
        Assert.Equal(start + 40, h.Vm.ServerColumnWidth);

        h.Vm.ResizeColumn(QueryMonitorColumn.Server, -10_000);
        Assert.Equal(QueryMonitorViewModel.MinColumnWidth, h.Vm.ServerColumnWidth);

        h.Vm.ResizeColumn(QueryMonitorColumn.Server, 10_000);
        Assert.Equal(QueryMonitorViewModel.MaxColumnWidth, h.Vm.ServerColumnWidth);

        // No persistence during the drag — only CommitColumnWidths (drag end) saves.
        Assert.Equal(0, h.UiState.SaveCount);
    }

    [Fact]
    public void commit_column_widths_persists_the_current_widths_once()
    {
        using var h = new Harness();
        h.Vm.ResizeColumn(QueryMonitorColumn.Server, 60);
        h.Vm.ResizeColumn(QueryMonitorColumn.Time, -20);

        h.Vm.CommitColumnWidths();

        Assert.Equal(1, h.UiState.SaveCount);
        Assert.Equal(h.Vm.ServerColumnWidth, h.UiState.Saved.QueryMonitorColumns.Server);
        Assert.Equal(h.Vm.TimeColumnWidth, h.UiState.Saved.QueryMonitorColumns.Time);
    }

    [Fact]
    public void commit_column_widths_does_not_clobber_other_persisted_preferences()
    {
        // Commit loads FRESH state and replaces only the column block — the favorites, theme, and the
        // kill-switch opt-in another VM persisted must survive a width save from this one.
        using var h = new Harness(new UiState
        {
            Favorites = { "quad9-dnscrypt-ip4-filter-pri" },
            Theme = "Dark",
            KillSwitchOptIn = true,
        });

        h.Vm.CommitColumnWidths();

        Assert.Equal(new[] { "quad9-dnscrypt-ip4-filter-pri" }, h.UiState.Saved.Favorites);
        Assert.Equal("Dark", h.UiState.Saved.Theme);
        Assert.True(h.UiState.Saved.KillSwitchOptIn);
    }

    // ------------------------------------------------------------------ off by default (IC-QM1)

    [Fact]
    public async Task logging_is_off_by_default_when_query_log_file_absent()
    {
        using var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Ok("listen_addresses = ['127.0.0.1:53']\n", Sha);

        await h.Vm.LoadAsync(CancellationToken.None);

        Assert.False(h.Vm.LoggingEnabled);
        Assert.Null(h.Vm.LoggingOnBanner);
        Assert.False(h.Poller.IsRunning);
    }

    [Fact]
    public async Task logging_reads_as_on_when_query_log_file_present()
    {
        using var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Ok("[query_log]\nfile = 'C:\\\\x\\\\query.log'\n", Sha);
        h.Vm.IsActive = true;

        await h.Vm.LoadAsync(CancellationToken.None);

        Assert.True(h.Vm.LoggingEnabled);
        Assert.NotNull(h.Vm.LoggingOnBanner);
        // Active + enabled → the poller is reconciled ON at load (resumes the live view after a relaunch).
        Assert.True(h.Poller.IsRunning);
    }

    [Fact]
    public async Task load_failure_shows_logging_off_and_never_throws()
    {
        using var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Fail("config unreadable");

        await h.Vm.LoadAsync(CancellationToken.None);

        Assert.False(h.Vm.LoggingEnabled);
        Assert.False(h.Poller.IsRunning);
    }

    // ------------------------------------------------------------------ per-session launch reset (FIX HIGH-1)

    [Fact]
    public async Task initialize_at_launch_hard_resets_a_leftover_enabled_config_to_off_and_purges()
    {
        // FIX HIGH-1: a config left with query_log.file SET (a prior session that did not clean up, or a
        // crash) means the LocalSystem proxy has been appending browsing history UNSHREDDED while the app
        // was closed. Launch MUST hard-reset: unset the key, stop the poller, purge the file, logging OFF.
        using var h = new Harness();
        h.Vm.IsActive = true;
        // Both the launch read AND the DisableAsync RMW re-read see the leftover-enabled config.
        h.Config.NextLoad = ConfigLoadResult.Ok("[query_log]\nfile = 'C:\\\\x\\\\query.log'\n", Sha);

        await h.Vm.InitializeAtLaunchAsync(CancellationToken.None);

        Assert.False(h.Vm.LoggingEnabled);                    // hard-reset to OFF
        Assert.Null(h.Vm.LoggingOnBanner);
        var saved = Assert.Single(h.Config.SaveCalls);        // the unset was written (proxy stops writing)
        Assert.DoesNotContain("query.log", saved.Text);
        Assert.Equal(1, h.Reader.PurgeCalls);                 // accumulated on-disk history purged
        Assert.False(h.Poller.IsRunning);                     // poller left stopped
        Assert.Empty(h.Vm.Rows);                              // view cleared
    }

    [Fact]
    public async Task initialize_at_launch_is_a_noop_off_for_a_stock_config()
    {
        // FIX HIGH-1: a stock/off config (no query_log.file) is the common case — launch is a pure no-op:
        // logging stays OFF, nothing is written, the poller stays stopped, nothing is purged.
        using var h = new Harness();
        h.Config.NextLoad = ConfigLoadResult.Ok("listen_addresses = ['127.0.0.1:53']\n", Sha);

        await h.Vm.InitializeAtLaunchAsync(CancellationToken.None);

        Assert.False(h.Vm.LoggingEnabled);
        Assert.Null(h.Vm.LoggingOnBanner);
        Assert.Empty(h.Config.SaveCalls); // nothing written for a stock config
        Assert.Equal(0, h.Reader.PurgeCalls);
        Assert.False(h.Poller.IsRunning);
    }

    [Fact]
    public async Task load_after_an_in_session_enable_does_not_disable_it()
    {
        // FIX HIGH-1 (non-conflict): the tab-activate LoadAsync only READS + RECONCILES — it must NOT
        // re-disable an in-session enable. After enabling in-session (which wrote query_log.file), a
        // subsequent LoadAsync that re-reads that same config MUST leave logging ON and the poller running.
        using var h = new Harness();
        await EnableAndActivateAsync(h);
        Assert.True(h.Vm.LoggingEnabled);
        Assert.True(h.Poller.IsRunning);
        h.Config.SaveCalls.Clear();

        // The on-disk config now HAS query_log.file (the in-session enable wrote it) — LoadAsync re-reads it.
        h.Config.NextLoad = ConfigLoadResult.Ok("[query_log]\nfile = 'C:\\\\x\\\\query.log'\n", Sha);
        await h.Vm.LoadAsync(CancellationToken.None);

        Assert.True(h.Vm.LoggingEnabled); // still ON — LoadAsync did not re-disable the in-session enable
        Assert.True(h.Poller.IsRunning);  // poller still running (reconciled to the same ON state)
        Assert.Empty(h.Config.SaveCalls); // LoadAsync writes NOTHING — it only reads/reconciles
    }

    // ------------------------------------------------------------------ action-filter choices (FIX view MED-1)

    [Fact]
    public void action_filters_exposes_the_four_query_action_filter_values()
    {
        // FIX view MED-1: the combo binds ActionFilters instead of an ObjectDataProvider/sys:Enum.
        Assert.Equal(4, QueryMonitorViewModel.ActionFilters.Count);
        Assert.Equal(
            new[]
            {
                QueryActionFilter.All,
                QueryActionFilter.Blocked,
                QueryActionFilter.Cloaked,
                QueryActionFilter.Passed,
            },
            QueryMonitorViewModel.ActionFilters);
    }

    // ------------------------------------------------------------------ consent gate (IC-QM2)

    [Fact]
    public void request_enable_only_arms_consent_and_writes_nothing()
    {
        using var h = new Harness();

        h.Vm.RequestEnable();

        Assert.NotNull(h.Vm.PendingLoggingConsent);
        Assert.Contains("query.log", h.Vm.PendingLoggingConsent!.LogPath);
        Assert.Empty(h.Config.SaveCalls); // NOTHING written on arm
        Assert.False(h.Vm.LoggingEnabled);
        Assert.False(h.Poller.IsRunning);
    }

    [Fact]
    public async Task cancel_enable_writes_no_config_and_leaves_logging_off()
    {
        using var h = new Harness();
        h.Vm.RequestEnable();

        h.Vm.CancelEnable();
        // A confirm after cancel must be a no-op (the request is gone).
        await h.Vm.ConfirmEnableAsync(CancellationToken.None);

        Assert.Null(h.Vm.PendingLoggingConsent);
        Assert.Empty(h.Config.SaveCalls); // the load-bearing assertion: zero config writes on cancel
        Assert.False(h.Vm.LoggingEnabled);
        Assert.False(h.Poller.IsRunning);
    }

    [Fact]
    public async Task confirm_enable_writes_query_log_file_and_starts_poller()
    {
        using var h = new Harness();
        h.Vm.IsActive = true;
        // Load the fresh config the read-modify-write re-reads.
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok(string.Empty, Sha));

        h.Vm.RequestEnable();
        await h.Vm.ConfirmEnableAsync(CancellationToken.None);

        Assert.True(h.Vm.LoggingEnabled);
        Assert.Null(h.Vm.PendingLoggingConsent);
        var saved = Assert.Single(h.Config.SaveCalls);
        Assert.Contains("query_log", saved.Text);
        Assert.Contains("tsv", saved.Text);
        Assert.Equal(Sha, saved.BaseSha256); // saved with the FRESH re-read sha
        Assert.True(h.Poller.IsRunning);
        Assert.Equal(1, h.Poller.StartCalls);
    }

    [Fact]
    public async Task confirm_enable_that_the_helper_rejects_does_not_flip_logging_on()
    {
        using var h = new Harness();
        h.Vm.IsActive = true;
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok(string.Empty, Sha));
        h.Config.SaveHandler = (_, _, _) =>
            Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.Rejected, "helper refused: OPSEC guard"));

        h.Vm.RequestEnable();
        await h.Vm.ConfirmEnableAsync(CancellationToken.None);

        Assert.False(h.Vm.LoggingEnabled); // nothing landed → stays off
        Assert.False(h.Poller.IsRunning);
        Assert.Contains("helper refused", h.Vm.ConfigError);
    }

    // ------------------------------------------------------------------ disable (IC-QM5)

    [Fact]
    public async Task disable_unsets_config_stops_poller_and_purges_file()
    {
        using var h = new Harness();
        h.Vm.IsActive = true;
        // Enable first so we have a live state to disable.
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok("[query_log]\nfile = 'C:\\\\x\\\\query.log'\n", Sha));
        h.Vm.RequestEnable();
        await h.Vm.ConfirmEnableAsync(CancellationToken.None);
        Assert.True(h.Vm.LoggingEnabled);
        h.Config.SaveCalls.Clear();

        // Now disable: the RMW re-reads a config that HAS the key so RemoveKey has something to remove.
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok("[query_log]\nfile = 'C:\\\\x\\\\query.log'\n", Sha));
        await h.Vm.DisableAsync(CancellationToken.None);

        Assert.False(h.Vm.LoggingEnabled);
        var saved = Assert.Single(h.Config.SaveCalls);
        Assert.DoesNotContain("query.log", saved.Text); // the key was unset
        Assert.False(h.Poller.IsRunning);
        Assert.Equal(1, h.Reader.PurgeCalls); // the on-disk residue is purged (IC-QM5)
    }

    [Fact]
    public async Task disable_clears_the_in_memory_buffer_so_history_disappears()
    {
        // FIX 2: "Stop & clear" must also drop the displayed browsing history, not just stop logging.
        using var h = new Harness();
        await EnableAndActivateAsync(h);
        h.Reader.Enqueue(Line("secret.example"), Line("private.example"));
        h.Poller.Fire();
        Assert.Equal(2, h.Vm.Rows.Count); // history is showing before disable

        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok("[query_log]\nfile = 'C:\\\\x\\\\query.log'\n", Sha));
        await h.Vm.DisableAsync(CancellationToken.None);

        Assert.False(h.Vm.LoggingEnabled);
        Assert.Empty(h.Vm.Rows); // the in-memory history is cleared on Stop & clear
        Assert.Equal("0 shown · 0 blocked · 0 cloaked.", h.Vm.CountsHeadline);
    }

    [Fact]
    public async Task disable_on_an_unconfirmed_restart_flips_off_but_surfaces_a_caveat()
    {
        // FIX MED-2: when the disable write LANDS on disk but the proxy restart is NOT confirmed
        // (RestartFailed / ProxyRejected), logging IS off in the config so we flip the flag off — but we
        // must NOT claim a clean stop we can't verify: surface an honest caveat.
        using var h = new Harness();
        await EnableAndActivateAsync(h);
        Assert.True(h.Vm.LoggingEnabled);
        h.Config.SaveCalls.Clear();

        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok("[query_log]\nfile = 'C:\\\\x\\\\query.log'\n", Sha));
        h.Config.SaveHandler = (_, _, _) =>
            Task.FromResult(new ConfigSaveOutcome(ConfigSaveOutcomeKind.RestartFailed, "restart not confirmed"));

        await h.Vm.DisableAsync(CancellationToken.None);

        Assert.False(h.Vm.LoggingEnabled);                 // bytes landed → logging off in the config
        Assert.False(h.Poller.IsRunning);                  // shredder stopped
        Assert.Equal(1, h.Reader.PurgeCalls);              // file still purged
        Assert.NotNull(h.Vm.ConfigError);                  // but a caveat is surfaced (no false clean stop)
        Assert.Contains("couldn't be confirmed", h.Vm.ConfigError);
    }

    [Fact]
    public async Task disable_with_an_already_canceled_token_does_not_throw_or_restart_the_poller()
    {
        // FIX 4: an already-canceled token makes Task.Run throw OperationCanceledException. DisableAsync
        // must swallow it (contract: never throws) AND must NOT resurrect the poller while LoggingEnabled
        // is still true — disable always intends to stop, so the shredder stays stopped (fail-closed).
        using var h = new Harness();
        await EnableAndActivateAsync(h);
        Assert.True(h.Poller.IsRunning);

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await h.Vm.DisableAsync(cts.Token); // must not throw

        Assert.False(h.Poller.IsRunning);   // stopped and NOT resurrected despite the canceled write
        Assert.False(h.Vm.IsBusy);          // busy released in the finally
    }

    // ------------------------------------------------------------------ read-and-shred → ring buffer

    [Fact]
    public async Task tick_drains_reader_and_appends_parsed_rows()
    {
        using var h = new Harness();
        await EnableAndActivateAsync(h);

        h.Reader.Enqueue(Line("ads.example.com", QueryAction.Reject), Line("cloudflare.com"));
        h.Poller.Fire();

        Assert.Equal(2, h.Vm.Rows.Count);
        Assert.Equal("ads.example.com", h.Vm.Rows[0].Name);
        Assert.Equal(QuerySeverity.Blocked, h.Vm.Rows[0].Severity);
        Assert.Equal("2026-07-03 10:24:59", h.Vm.Rows[0].Time); // brackets stripped for display
    }

    [Fact]
    public async Task ring_buffer_caps_at_500_and_evicts_oldest()
    {
        using var h = new Harness();
        await EnableAndActivateAsync(h);

        // 600 lines across two ticks → only the newest 500 survive; oldest evicted.
        var first = new QueryLogLine[300];
        for (var i = 0; i < 300; i++)
        {
            first[i] = Line("old-" + i);
        }

        var second = new QueryLogLine[300];
        for (var i = 0; i < 300; i++)
        {
            second[i] = Line("new-" + i);
        }

        h.Reader.Enqueue(first);
        h.Poller.Fire();
        h.Reader.Enqueue(second);
        h.Poller.Fire();

        Assert.Equal(500, h.Vm.Rows.Count);
        // The very first 100 "old-*" rows were evicted; the last visible row is the newest.
        Assert.Equal("new-299", h.Vm.Rows[^1].Name);
        Assert.DoesNotContain(h.Vm.Rows, r => r.Name == "old-0");
        Assert.Contains(h.Vm.Rows, r => r.Name == "new-0");
    }

    [Fact]
    public async Task reader_error_sets_flag_and_never_crashes()
    {
        using var h = new Harness();
        await EnableAndActivateAsync(h);

        h.Reader.EnqueueReadError();
        h.Poller.Fire(); // must not throw

        Assert.True(h.Vm.HadReadError);
        Assert.Empty(h.Vm.Rows);
    }

    [Fact]
    public async Task tick_while_inactive_shreds_and_accumulates_but_display_refreshes_on_reactivation()
    {
        // FIX 1 (the OPSEC-critical one): while logging is on, the read-and-shred loop MUST keep draining
        // (truncating the on-disk log) even when the tab is NOT active. Phase 5i: the buffer now
        // ACCUMULATES while inactive too (so the Dashboard has data), but the VISIBLE list stays frozen
        // while inactive — it refreshes to show the accumulated buffer when the tab is re-entered.
        using var h = new Harness();
        await EnableAndActivateAsync(h);

        // Leave the tab: the poller must stay RUNNING (it is gated on LoggingEnabled, not IsActive).
        h.Vm.IsActive = false;
        Assert.True(h.Vm.LoggingEnabled);
        Assert.True(h.Poller.IsRunning); // the shredder keeps running with the tab left

        var drainsBefore = h.Reader.DrainCalls;
        h.Reader.Enqueue(Line("background.example"));
        h.Poller.Fire();

        Assert.Equal(drainsBefore + 1, h.Reader.DrainCalls); // STILL drained/shredded while inactive
        Assert.Empty(h.Vm.Rows);                             // display frozen while inactive
        Assert.Equal(1, h.Vm.Stats.Queries);                 // but the buffer accumulated (Phase 5i)

        // Re-enter the tab → the display refreshes to show what arrived while away.
        h.Vm.IsActive = true;
        Assert.Single(h.Vm.Rows);
        Assert.Equal("background.example", h.Vm.Rows[0].Name);
    }

    // ------------------------------------------------------------------ filters + counts

    [Fact]
    public async Task action_filter_and_search_narrow_rows_and_counts()
    {
        using var h = new Harness();
        await EnableAndActivateAsync(h);

        h.Reader.Enqueue(
            Line("ads.tracker.com", QueryAction.Reject),
            Line("cdn.tracker.com", QueryAction.Pass),
            Line("printer.local", QueryAction.Cloak),
            Line("evil.tracker.com", QueryAction.Synth));
        h.Poller.Fire();

        // Counts over ALL rows: 4 shown, 2 blocked (REJECT+SYNTH), 1 cloaked.
        Assert.Equal("4 shown · 2 blocked · 1 cloaked.", h.Vm.CountsHeadline);

        // Action filter = Blocked → only REJECT+SYNTH rows.
        h.Vm.ActionFilter = QueryActionFilter.Blocked;
        Assert.Equal(2, h.Vm.Rows.Count);
        Assert.All(h.Vm.Rows, r => Assert.Equal(QuerySeverity.Blocked, r.Severity));

        // Add a qname substring filter → intersect with the action filter.
        h.Vm.SearchText = "ads";
        Assert.Single(h.Vm.Rows);
        Assert.Equal("ads.tracker.com", h.Vm.Rows[0].Name);
    }

    [Fact]
    public async Task clear_view_empties_the_buffer_without_touching_config_or_poller()
    {
        using var h = new Harness();
        await EnableAndActivateAsync(h);
        h.Reader.Enqueue(Line("a.example"), Line("b.example"));
        h.Poller.Fire();
        Assert.Equal(2, h.Vm.Rows.Count);

        h.Vm.ClearView();

        Assert.Empty(h.Vm.Rows);
        Assert.Equal("0 shown · 0 blocked · 0 cloaked.", h.Vm.CountsHeadline);
        Assert.True(h.Vm.LoggingEnabled); // logging untouched
        Assert.True(h.Poller.IsRunning);
    }

    // ------------------------------------------------------------------ poller lifecycle (gated ONLY on LoggingEnabled — FIX 1)

    [Fact]
    public async Task poller_runs_whenever_logging_is_enabled_regardless_of_active()
    {
        // FIX 1: the shredder is gated ONLY on logging being on — NOT on the tab being active. Enabling
        // while INACTIVE still starts the poller so the on-disk log is drained/shredded in the background.
        using var h = new Harness();
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok(string.Empty, Sha));
        h.Vm.RequestEnable();
        await h.Vm.ConfirmEnableAsync(CancellationToken.None);
        Assert.True(h.Vm.LoggingEnabled);
        Assert.True(h.Poller.IsRunning); // enabled → running even though the tab is not active

        // Toggling the tab active/inactive does NOT start/stop the shredder — it keeps running.
        h.Vm.IsActive = true;
        Assert.True(h.Poller.IsRunning);
        h.Vm.IsActive = false;
        Assert.True(h.Poller.IsRunning);
    }

    [Fact]
    public async Task pause_does_not_stop_the_shredder_it_only_freezes_the_display()
    {
        // FIX 1: Pause is a DISPLAY freeze, not a shred pause. The poller must keep running (and shredding)
        // while paused; only the append to Rows is suppressed.
        using var h = new Harness();
        await EnableAndActivateAsync(h);
        Assert.True(h.Poller.IsRunning);

        h.Vm.Pause();
        Assert.True(h.Vm.IsPaused);
        Assert.True(h.Poller.IsRunning); // the shredder keeps running while the display is frozen
        Assert.True(h.Vm.LoggingEnabled);

        h.Vm.Resume();
        Assert.False(h.Vm.IsPaused);
        Assert.True(h.Poller.IsRunning);
    }

    [Fact]
    public async Task a_tick_that_lands_while_paused_shreds_and_accumulates_but_the_display_stays_frozen()
    {
        // FIX 1: a paused tick must NOT refresh the display, but it MUST still Drain() (shred the file).
        // Phase 5i: the buffer still accumulates while paused (the Dashboard counts every query); only the
        // visible list is frozen.
        using var h = new Harness();
        await EnableAndActivateAsync(h);
        h.Vm.Pause();

        var drainsBefore = h.Reader.DrainCalls;
        h.Reader.Enqueue(Line("late.example"));
        h.Poller.Fire();

        Assert.Equal(drainsBefore + 1, h.Reader.DrainCalls); // still shredded while paused
        Assert.Empty(h.Vm.Rows);                             // display frozen while paused
        Assert.Equal(1, h.Vm.Stats.Queries);                 // but accumulated for the session (Phase 5i)
    }

    // ------------------------------------------------------------------ IQueryLogSession (Phase 5i)

    [Fact]
    public async Task session_stats_derive_blocked_cloaked_answered_locally_and_avg_latency()
    {
        using var h = new Harness();
        await EnableAndActivateAsync(h);

        // 3 upstream PASS (server="cloudflare", 12 ms each) + 2 locally-answered (REJECT/CLOAK, server="-").
        h.Reader.Enqueue(
            Line("a.example", QueryAction.Pass),
            Line("b.example", QueryAction.Pass),
            Line("c.example", QueryAction.Pass),
            Line("ads.example", QueryAction.Reject),
            Line("printer.local", QueryAction.Cloak));
        h.Poller.Fire();

        var s = ((IQueryLogSession)h.Vm).Stats;
        Assert.Equal(5, s.Queries);
        Assert.Equal(1, s.Blocked);           // REJECT
        Assert.Equal(1, s.Cloaked);           // CLOAK
        Assert.Equal(2, s.AnsweredLocally);   // REJECT + CLOAK (server == "-")
        Assert.Equal(3, s.UpstreamCount);     // the 3 PASS rows
        Assert.Equal(12, s.AvgUpstreamLatencyMs);
        Assert.Equal(40, s.AnsweredLocallyPercent); // 2 / 5
    }

    [Fact]
    public async Task session_recentRows_are_newest_first_and_capped()
    {
        using var h = new Harness();
        await EnableAndActivateAsync(h);
        h.Reader.Enqueue(Line("first.example"), Line("second.example"), Line("third.example"));
        h.Poller.Fire();

        var recent = ((IQueryLogSession)h.Vm).RecentRows(2);
        Assert.Equal(2, recent.Count);
        Assert.Equal("third.example", recent[0].Name);   // newest first
        Assert.Equal("second.example", recent[1].Name);
    }

    [Fact]
    public async Task dashboard_session_excludes_the_diagnostics_selfcheck_but_query_monitor_shows_it()
    {
        // Dashboard-only filter (Phase 5i): the app's own leak self-check probe (fired every ~1.5s by the
        // Dashboard diagnostics poll) must NOT appear in the Dashboard's summary counts / recent list, but
        // the raw Query Monitor still shows it.
        using var h = new Harness();
        await EnableAndActivateAsync(h);
        h.Reader.Enqueue(
            Line("google.com", QueryAction.Pass),
            Line("dnscrypt-resolver-selfcheck.test", QueryAction.NxDomain),
            Line("dnscrypt-resolver-selfcheck.test", QueryAction.NxDomain),
            Line("wikipedia.org", QueryAction.Pass));
        h.Poller.Fire();

        var session = h.Vm; // QueryMonitorViewModel implements IQueryLogSession; use the concrete type (CA1859)
        // The Dashboard's view (session aggregates) EXCLUDES the self-check: 2 real queries.
        Assert.Equal(2, session.Stats.Queries);
        var recent = session.RecentRows(5);
        Assert.Equal(2, recent.Count);
        Assert.DoesNotContain(recent, r => r.Name == "dnscrypt-resolver-selfcheck.test");
        Assert.Equal("wikipedia.org", recent[0].Name); // newest REAL query first

        // The raw Query Monitor (its own Rows over the full buffer) STILL shows all four, incl. the self-check.
        Assert.Equal(4, h.Vm.Rows.Count);
        Assert.Contains(h.Vm.Rows, r => r.Name == "dnscrypt-resolver-selfcheck.test");
    }

    [Fact]
    public async Task session_Changed_fires_on_tick_and_stats_clear_on_disable()
    {
        using var h = new Harness();
        await EnableAndActivateAsync(h);
        var session = (IQueryLogSession)h.Vm;
        var changes = 0;
        session.Changed += (_, _) => changes++;

        h.Reader.Enqueue(Line("x.example"));
        h.Poller.Fire();
        Assert.True(changes > 0);
        Assert.True(session.LoggingActive);
        Assert.Equal(1, session.Stats.Queries);

        // Disable → the buffer clears + logging goes off, so consumers (the Dashboard) revert to off-state.
        await h.Vm.DisableAsync(CancellationToken.None);
        Assert.False(session.LoggingActive);
        Assert.Equal(0, session.Stats.Queries);
    }

    // ------------------------------------------------------------------ per-app attribution (v1.3.0)

    [Fact]
    public async Task row_with_a_matching_attribution_gets_the_process_name_normalized()
    {
        using var h = new Harness();
        await EnableAndActivateAsync(h);

        // The ETW spelling is FQDN-dotted + differently cased — normalization must still match.
        h.Attribution.Enqueue(1, Entry(1, "ADS.Example.COM.", pid: 100, processName: "chrome"));
        h.Reader.Enqueue(Line("ads.example.com"));
        h.Poller.Fire();

        Assert.Equal("chrome", Assert.Single(h.Vm.Rows).App);
    }

    [Fact]
    public async Task row_with_no_matching_attribution_shows_the_honest_unknown()
    {
        using var h = new Harness();
        await EnableAndActivateAsync(h);

        h.Attribution.Enqueue(1, Entry(1, "other.example", pid: 100, processName: "chrome"));
        h.Reader.Enqueue(Line("unrelated.example"));
        h.Poller.Fire();

        Assert.Equal(QueryMonitorViewModel.UnknownAppLabel, Assert.Single(h.Vm.Rows).App);
    }

    [Fact]
    public async Task two_distinct_processes_in_the_window_show_multiple_never_a_guess()
    {
        using var h = new Harness();
        await EnableAndActivateAsync(h);

        // Two PIDs — even with the SAME image name — make the row ambiguous (IC-16: never guess).
        h.Attribution.Enqueue(2,
            Entry(1, "shared.example", pid: 100, processName: "chrome"),
            Entry(2, "shared.example", pid: 200, processName: "chrome"));
        h.Reader.Enqueue(Line("shared.example"));
        h.Poller.Fire();

        Assert.Equal(QueryMonitorViewModel.MultipleAppsLabel, Assert.Single(h.Vm.Rows).App);
    }

    [Fact]
    public async Task attribution_fetch_failure_degrades_to_unknown_and_never_throws()
    {
        using var h = new Harness();
        await EnableAndActivateAsync(h);

        // The reader's default (NextBatch = null) IS the degraded transport: the tick must still
        // drain, append, and label honestly.
        h.Reader.Enqueue(Line("a.example"));
        h.Poller.Fire(); // must not throw

        Assert.Equal(QueryMonitorViewModel.UnknownAppLabel, Assert.Single(h.Vm.Rows).App);
        Assert.Single(h.Attribution.FetchCalls); // the fetch DID run — its failure just degraded
    }

    [Fact]
    public async Task exited_process_with_no_name_falls_back_to_the_bare_pid()
    {
        using var h = new Harness();
        await EnableAndActivateAsync(h);

        h.Attribution.Enqueue(1, Entry(1, "gone.example", pid: 1234, processName: null));
        h.Reader.Enqueue(Line("gone.example"));
        h.Poller.Fire();

        Assert.Equal("PID 1234", Assert.Single(h.Vm.Rows).App);
    }

    [Fact]
    public async Task stale_attribution_outside_the_window_does_not_claim_a_fresh_query()
    {
        using var h = new Harness();
        await EnableAndActivateAsync(h);

        // Same name, but captured 10 s ago — retained (< 30 s) yet past the 5 s look-back, so a
        // long-gone lookup can never label a fresh query.
        h.Attribution.Enqueue(1, Entry(1, "old.example", pid: 100, processName: "chrome", unixMs: NowMs() - 10_000));
        h.Reader.Enqueue(Line("old.example"));
        h.Poller.Fire();

        Assert.Equal(QueryMonitorViewModel.UnknownAppLabel, Assert.Single(h.Vm.Rows).App);
    }

    [Fact]
    public async Task attribution_cursor_advances_by_the_batch_LastSeq_each_tick()
    {
        using var h = new Harness();
        await EnableAndActivateAsync(h);

        h.Attribution.Enqueue(7, Entry(7, "a.example", pid: 100, processName: "chrome"));
        h.Reader.Enqueue(Line("a.example"));
        h.Poller.Fire();

        h.Reader.Enqueue(Line("b.example"));
        h.Poller.Fire(); // second fetch (unscripted default: empty batch is fine)

        Assert.Equal(2, h.Attribution.FetchCalls.Count);
        Assert.Equal(0, h.Attribution.FetchCalls[0]);  // first poll starts from the beginning
        Assert.Equal(7, h.Attribution.FetchCalls[1]);  // then resumes after the last seen seq
    }

    [Fact]
    public async Task attribution_merged_on_an_earlier_tick_still_correlates_a_row_arriving_the_next_tick()
    {
        // The ETW event fires when the app CALLS the resolver; the proxy log line lands up to a
        // poll later. A candidate merged on tick N must still match a row appended on tick N+1
        // (stamped before that row's anchor, inside its 5 s look-back).
        using var h = new Harness();
        await EnableAndActivateAsync(h);

        h.Attribution.Enqueue(1, Entry(1, "lag.example", pid: 100, processName: "firefox"));
        h.Poller.Fire(); // merge only — nothing drained this tick

        h.Reader.Enqueue(Line("lag.example"));
        h.Poller.Fire(); // the row arrives one tick later

        Assert.Equal("firefox", Assert.Single(h.Vm.Rows).App);
    }

    [Fact]
    public async Task disable_clears_the_attribution_lookup_and_rewinds_the_cursor()
    {
        // OPSEC residue (FIX D): the domain→process lookup is pruned only on poller ticks, so
        // "Stop & clear" must drop it explicitly — otherwise the final ~30 s of pairs sit in
        // memory for the rest of the app session after the ticks stop. A fresh consent also
        // starts a fresh cursor (the helper's ring is cleared when its capture session stops).
        using var h = new Harness();
        await EnableAndActivateAsync(h);

        h.Attribution.Enqueue(3, Entry(3, "residue.example", pid: 100, processName: "chrome"));
        h.Reader.Enqueue(Line("residue.example"));
        h.Poller.Fire();
        Assert.Equal(1, h.Vm.AttributionLookupCount);

        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok("[query_log]\nfile = 'x'\n", Sha));
        await h.Vm.DisableAsync(CancellationToken.None);

        Assert.Equal(0, h.Vm.AttributionLookupCount); // no domain→process residue survives the stop

        // The rewound cursor: a re-enabled session's first fetch starts from 0, not the old seq.
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok(string.Empty, Sha));
        h.Vm.RequestEnable();
        await h.Vm.ConfirmEnableAsync(CancellationToken.None);
        h.Poller.Fire();

        Assert.Equal(0, h.Attribution.FetchCalls[^1]);
    }

    [Fact]
    public async Task clear_view_drops_the_attribution_lookup_with_the_rows()
    {
        using var h = new Harness();
        await EnableAndActivateAsync(h);

        h.Attribution.Enqueue(1, Entry(1, "residue.example", pid: 100, processName: "chrome"));
        h.Reader.Enqueue(Line("residue.example"));
        h.Poller.Fire();
        Assert.Equal(1, h.Vm.AttributionLookupCount);

        h.Vm.ClearView();

        Assert.Empty(h.Vm.Rows);
        Assert.Equal(0, h.Vm.AttributionLookupCount); // the lookup is the same residue, one join away
    }

    [Fact]
    public void no_attribution_fetch_while_logging_is_off()
    {
        // The polls are the helper's demand signal for machine-wide ETW capture — a tick that
        // somehow fires while logging is off must NOT poll (no unconsented demand).
        using var h = new Harness();

        h.Poller.Fire();

        Assert.Empty(h.Attribution.FetchCalls);
    }

    // ------------------------------------------------------------------ late binding (v1.3.0)

    [Fact]
    public async Task a_row_drained_before_its_attribution_is_late_bound_when_the_batch_lands_next_tick()
    {
        // The flaw this pins: ETW hands the helper its events in ~1 s flush batches, so the tick that
        // drains a lookup's log line usually runs BEFORE the tick that fetches that lookup's event.
        // Deciding App once at append time left such rows "—" forever.
        var clock = new ManualClock();
        using var h = new Harness(clock: clock.Now);
        await EnableAndActivateAsync(h);
        var anchorMs = clock.NowMs;

        h.Reader.Enqueue(Line("late.example"));
        h.Poller.Fire(); // tick N: the row is drained; its attribution has not been fetched yet
        var row = Assert.Single(h.Vm.Rows);
        Assert.Equal(QueryMonitorViewModel.UnknownAppLabel, row.App);

        clock.Advance(TimeSpan.FromMilliseconds(750));
        h.Attribution.Enqueue(1, Entry(1, "late.example", pid: 100, processName: "chrome", unixMs: anchorMs - 200));
        h.Poller.Fire(); // tick N+1: the batch lands; nothing new is drained

        Assert.Equal("chrome", row.App);
    }

    [Fact]
    public async Task a_late_bound_row_notifies_App_so_every_surface_bound_to_it_updates_in_place()
    {
        // The Query Monitor cell binds {Binding App} on the row instance the Dashboard's recent list
        // also holds: without a change notification the cell keeps painting "—" after the VM has the
        // answer. Exactly one notification, for App alone (no other cell ever changes).
        var clock = new ManualClock();
        using var h = new Harness(clock: clock.Now);
        await EnableAndActivateAsync(h);
        var anchorMs = clock.NowMs;
        h.Reader.Enqueue(Line("late.example"));
        h.Poller.Fire();
        var row = Assert.Single(h.Vm.Rows);
        var notifier = Assert.IsAssignableFrom<INotifyPropertyChanged>(row);
        var changed = new List<string?>();
        notifier.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        clock.Advance(TimeSpan.FromMilliseconds(750));
        h.Attribution.Enqueue(1, Entry(1, "late.example", pid: 100, processName: "chrome", unixMs: anchorMs - 200));
        h.Poller.Fire();

        Assert.Equal(new[] { "App" }, changed);
        Assert.Equal("chrome", Assert.Single(h.Vm.RecentRows(5)).App); // the Dashboard's view agrees
    }

    [Fact]
    public async Task late_binding_keeps_completing_rows_while_the_tab_is_inactive_or_paused()
    {
        // The buffer keeps accumulating while the tab is away or paused (Phase 5i), so its rows must
        // keep completing too — re-entering the tab must not show "—" for attributions that landed
        // while the display was away.
        var clock = new ManualClock();
        using var h = new Harness(clock: clock.Now);
        await EnableAndActivateAsync(h);
        h.Vm.IsActive = false;
        var awayAnchorMs = clock.NowMs;
        h.Reader.Enqueue(Line("away.example"));
        h.Poller.Fire();
        clock.Advance(TimeSpan.FromMilliseconds(750));
        h.Attribution.Enqueue(1, Entry(1, "away.example", pid: 100, processName: "chrome", unixMs: awayAnchorMs - 200));
        h.Poller.Fire();

        h.Vm.IsActive = true; // re-entering refreshes the display from the buffer
        Assert.Equal("chrome", Assert.Single(h.Vm.Rows).App);

        h.Vm.Pause();
        var pausedAnchorMs = clock.NowMs;
        h.Reader.Enqueue(Line("paused.example"));
        h.Poller.Fire();
        clock.Advance(TimeSpan.FromMilliseconds(750));
        h.Attribution.Enqueue(2, Entry(2, "paused.example", pid: 200, processName: "msedge", unixMs: pausedAnchorMs - 200));
        h.Poller.Fire();
        Assert.Equal("msedge", h.Vm.RecentRows(1)[0].App); // the buffered row completed while frozen out
    }

    [Fact]
    public void a_rows_App_binds_one_way_from_the_unknown_and_never_again()
    {
        // The row's own contract — "never downgrade, never re-decide" holds by construction, not
        // only by the VM's pending-list bookkeeping: only a row still showing the honest unknown can
        // bind, the unknown itself is no decision, and a decided row refuses every later one.
        var row = new QueryRowViewModel(Line("x.example"));

        Assert.False(row.TryBindApp(QueryMonitorViewModel.UnknownAppLabel));
        Assert.True(row.TryBindApp("chrome"));
        Assert.False(row.TryBindApp(QueryMonitorViewModel.MultipleAppsLabel));
        Assert.False(row.TryBindApp("edge"));
        Assert.Equal("chrome", row.App);

        var decidedAtAppend = new QueryRowViewModel(Line("y.example"), "firefox");
        Assert.False(decidedAtAppend.TryBindApp("chrome"));
        Assert.Equal("firefox", decidedAtAppend.App);
    }

    [Fact]
    public async Task late_binding_judges_the_window_around_the_rows_append_time_not_now()
    {
        // A pending row re-checked 7 s after it was appended must still be judged around WHEN it was
        // appended: an attribution stamped 0.5 s BEFORE the append binds (though it is 7.5 s before
        // "now"), while one stamped 6.5 s AFTER the append does not (though it is just 0.5 s before
        // "now"). A window that drifted with the clock would get both backwards.
        var clock = new ManualClock();
        using var h = new Harness(clock: clock.Now);
        await EnableAndActivateAsync(h);
        var appendedAtMs = clock.NowMs;
        h.Reader.Enqueue(Line("anchored.example"), Line("drifted.example"));
        h.Poller.Fire();
        var anchored = h.Vm.Rows.Single(r => r.Name == "anchored.example");
        var drifted = h.Vm.Rows.Single(r => r.Name == "drifted.example");

        var recheckAfter = TimeSpan.FromSeconds(7);
        Assert.True(recheckAfter < QueryMonitorViewModel.PendingAttributionLifetime); // both still pending
        clock.Advance(recheckAfter);
        h.Attribution.Enqueue(2,
            Entry(1, "anchored.example", pid: 100, processName: "chrome", unixMs: appendedAtMs - 500),
            Entry(2, "drifted.example", pid: 200, processName: "edge", unixMs: appendedAtMs + 6_500));
        h.Poller.Fire();

        Assert.Equal("chrome", anchored.App);
        Assert.Equal(QueryMonitorViewModel.UnknownAppLabel, drifted.App);
    }

    [Fact]
    public async Task an_attribution_stamped_after_the_rows_anchor_never_late_binds_it()
    {
        // A query-log row exists only after its lookup was answered, so the lookup that produced it
        // was raised BEFORE the row's anchor; a candidate stamped seconds AFTER the anchor can only be
        // a DIFFERENT, later lookup of the same name. E.g. nslookup (no DNS-client event of its own)
        // queries at t=0 and chrome resolves the same name at t=+3 s: binding the nslookup row to
        // chrome would be a guess (IC-16).
        var clock = new ManualClock();
        using var h = new Harness(clock: clock.Now);
        await EnableAndActivateAsync(h);
        var anchorMs = clock.NowMs;
        h.Reader.Enqueue(Line("shared.example"));
        h.Poller.Fire(); // the nslookup row: appended, nothing to bind it to
        var row = Assert.Single(h.Vm.Rows);

        clock.Advance(TimeSpan.FromSeconds(3.75)); // chrome's +3 s lookup is fetched a tick later
        h.Attribution.Enqueue(1, Entry(1, "shared.example", pid: 100, processName: "chrome", unixMs: anchorMs + 3_000));
        h.Poller.Fire();

        Assert.Equal(QueryMonitorViewModel.UnknownAppLabel, row.App);
    }

    [Fact]
    public async Task an_attribution_stamped_just_after_the_anchor_binds_within_the_jitter_slack()
    {
        // The forward edge is not zero: a few hundred ms of helper/UI timestamp jitter must not cost a
        // row its own lookup.
        var clock = new ManualClock();
        using var h = new Harness(clock: clock.Now);
        await EnableAndActivateAsync(h);
        var anchorMs = clock.NowMs;
        h.Reader.Enqueue(Line("jitter.example"));
        h.Poller.Fire();
        var row = Assert.Single(h.Vm.Rows);

        clock.Advance(TimeSpan.FromMilliseconds(750));
        h.Attribution.Enqueue(1, Entry(1, "jitter.example", pid: 100, processName: "chrome", unixMs: anchorMs + 300));
        h.Poller.Fire();

        Assert.Equal("chrome", row.App);
    }

    [Fact]
    public async Task a_lookup_stamped_well_before_the_anchor_still_binds_when_it_arrives_ticks_later()
    {
        // The case late binding exists for: an event stamped BEFORE the row's anchor that only reaches
        // the UI ticks after the row. Anywhere inside the 5 s look-back it still binds — here 4.5 s
        // back, fetched three ticks late.
        var clock = new ManualClock();
        using var h = new Harness(clock: clock.Now);
        await EnableAndActivateAsync(h);
        var anchorMs = clock.NowMs;
        h.Reader.Enqueue(Line("backward.example"));
        h.Poller.Fire();
        var row = Assert.Single(h.Vm.Rows);

        clock.Advance(TimeSpan.FromMilliseconds(750));
        h.Poller.Fire();
        clock.Advance(TimeSpan.FromMilliseconds(750));
        h.Poller.Fire();
        Assert.Equal(QueryMonitorViewModel.UnknownAppLabel, row.App); // still waiting

        clock.Advance(TimeSpan.FromMilliseconds(750));
        h.Attribution.Enqueue(1, Entry(1, "backward.example", pid: 100, processName: "chrome", unixMs: anchorMs - 4_500));
        h.Poller.Fire();

        Assert.Equal("chrome", row.App);
    }

    [Fact]
    public async Task multiple_counts_only_candidates_inside_the_window()
    {
        // Ambiguity is judged over the window alone: another process's lookup stamped 3 s AFTER the
        // anchor (a later lookup), or 6 s before it (past the look-back), is no rival candidate — the
        // one in-window process names the row rather than "multiple".
        var clock = new ManualClock();
        using var h = new Harness(clock: clock.Now);
        await EnableAndActivateAsync(h);
        var anchorMs = clock.NowMs;
        h.Reader.Enqueue(Line("crowded.example"));
        h.Poller.Fire();
        var row = Assert.Single(h.Vm.Rows);

        clock.Advance(TimeSpan.FromSeconds(3.75));
        h.Attribution.Enqueue(3,
            Entry(1, "crowded.example", pid: 300, processName: "firefox", unixMs: anchorMs - 6_000),
            Entry(2, "crowded.example", pid: 100, processName: "chrome", unixMs: anchorMs - 1_000),
            Entry(3, "crowded.example", pid: 200, processName: "msedge", unixMs: anchorMs + 3_000));
        h.Poller.Fire();

        Assert.Equal("chrome", row.App);
    }

    [Fact]
    public async Task two_processes_landing_late_in_the_window_late_bind_multiple_never_a_guess()
    {
        // Late binding runs the same ambiguity rule as append time: two distinct PIDs inside the
        // row's window make it "multiple" — never whichever of them happened to be merged first.
        var clock = new ManualClock();
        using var h = new Harness(clock: clock.Now);
        await EnableAndActivateAsync(h);
        var anchorMs = clock.NowMs;
        h.Reader.Enqueue(Line("shared.example"));
        h.Poller.Fire();
        var row = Assert.Single(h.Vm.Rows);

        clock.Advance(TimeSpan.FromMilliseconds(750));
        h.Attribution.Enqueue(2,
            Entry(1, "shared.example", pid: 100, processName: "chrome", unixMs: anchorMs - 300),
            Entry(2, "shared.example", pid: 200, processName: "msedge", unixMs: anchorMs - 100));
        h.Poller.Fire();

        Assert.Equal(QueryMonitorViewModel.MultipleAppsLabel, row.App);
        Assert.Equal(0, h.Vm.PendingAttributionCount); // "multiple" is a decision — it leaves pending
    }

    [Fact]
    public async Task a_decided_row_is_never_changed_by_later_batches()
    {
        // Never downgrade, never re-decide: a row named at append time AND a row late-bound on the
        // next tick both keep their first decision when a different process's lookup of the same
        // name lands later (still inside their windows) — neither so much as raises a notification.
        var clock = new ManualClock();
        using var h = new Harness(clock: clock.Now);
        await EnableAndActivateAsync(h);
        var anchorMs = clock.NowMs; // both rows are appended by the first tick below
        h.Attribution.Enqueue(1, Entry(1, "early.example", pid: 100, processName: "chrome", unixMs: anchorMs - 400));
        h.Reader.Enqueue(Line("early.example"), Line("late.example"));
        h.Poller.Fire();
        var early = h.Vm.Rows.Single(r => r.Name == "early.example");
        var late = h.Vm.Rows.Single(r => r.Name == "late.example");
        Assert.Equal("chrome", early.App);             // decided at append, exactly as before
        Assert.Equal(1, h.Vm.PendingAttributionCount); // so only the unknown row waits

        clock.Advance(TimeSpan.FromMilliseconds(750));
        h.Attribution.Enqueue(2, Entry(2, "late.example", pid: 300, processName: "firefox", unixMs: anchorMs - 200));
        h.Poller.Fire();
        Assert.Equal("firefox", late.App);

        var notifications = 0;
        early.PropertyChanged += (_, _) => notifications++;
        late.PropertyChanged += (_, _) => notifications++;
        clock.Advance(TimeSpan.FromMilliseconds(750));
        h.Attribution.Enqueue(4,
            Entry(3, "early.example", pid: 200, processName: "msedge", unixMs: anchorMs - 100),
            Entry(4, "late.example", pid: 400, processName: "msedge", unixMs: anchorMs - 100));
        h.Poller.Fire();

        Assert.Equal("chrome", early.App);
        Assert.Equal("firefox", late.App);
        Assert.Equal(0, notifications);
    }

    [Fact]
    public async Task a_row_whose_name_can_never_match_takes_no_pending_slot()
    {
        // A root query "." normalizes to an empty key, which the merge never stores — it can never be
        // attributed, so it must not occupy one of the capped pending slots for its whole lifetime.
        using var h = new Harness();
        await EnableAndActivateAsync(h);
        h.Reader.Enqueue(Line(".", type: "NS"));
        h.Poller.Fire();

        Assert.Equal(QueryMonitorViewModel.UnknownAppLabel, Assert.Single(h.Vm.Rows).App);
        Assert.Equal(0, h.Vm.PendingAttributionCount);
    }

    [Fact]
    public async Task an_attribution_landing_after_the_pending_lifetime_leaves_the_row_unknown()
    {
        // Pending is bounded in time: once the lifetime has passed the row gives up for good and
        // keeps the honest unknown — even though the attribution that finally lands is stamped 0.5 s
        // before the append, well inside the row's 5 s look-back. The lifetime, not the window,
        // refuses it (inside the lifetime the very same stamp binds — see the anchor test above).
        var clock = new ManualClock();
        using var h = new Harness(clock: clock.Now);
        await EnableAndActivateAsync(h);
        var appendedAtMs = clock.NowMs;
        h.Reader.Enqueue(Line("slow.example"));
        h.Poller.Fire();
        var row = Assert.Single(h.Vm.Rows);

        clock.Advance(QueryMonitorViewModel.PendingAttributionLifetime + TimeSpan.FromMilliseconds(1));
        h.Attribution.Enqueue(1, Entry(1, "slow.example", pid: 100, processName: "chrome", unixMs: appendedAtMs - 500));
        h.Poller.Fire();

        Assert.Equal(QueryMonitorViewModel.UnknownAppLabel, row.App);
    }

    [Fact]
    public async Task a_wall_clock_step_back_past_the_lifetime_does_not_pin_pending_rows()
    {
        // The lifetime is judged in both directions: once the clock steps BACK by more than the
        // lifetime, the row's anchor sits in the "future" and no fresh stamp can meet it — the row
        // must give up now rather than linger until the clock catches up again.
        var clock = new ManualClock();
        using var h = new Harness(clock: clock.Now);
        await EnableAndActivateAsync(h);
        h.Reader.Enqueue(Line("stepped.example"));
        h.Poller.Fire();
        Assert.Equal(1, h.Vm.PendingAttributionCount);

        clock.Advance(-TimeSpan.FromHours(1));
        h.Poller.Fire();

        Assert.Equal(0, h.Vm.PendingAttributionCount);
    }

    [Fact]
    public async Task the_pending_list_is_capped_and_the_oldest_unknown_rows_give_up_first()
    {
        // Bounded memory regardless of volume: a burst of unknown rows past the cap keeps only the
        // NEWEST pending (theirs is the attribution likeliest still in flight); the oldest overflow
        // gives up and keeps "—" even when its attribution does land.
        var clock = new ManualClock();
        using var h = new Harness(clock: clock.Now);
        await EnableAndActivateAsync(h);
        var anchorMs = clock.NowMs;
        const int overflow = 44;
        var burst = new QueryLogLine[QueryMonitorViewModel.MaxPendingAttributions + overflow];
        for (var i = 0; i < burst.Length; i++)
        {
            burst[i] = Line("n-" + i);
        }

        h.Reader.Enqueue(burst);
        h.Poller.Fire();
        Assert.Equal(QueryMonitorViewModel.MaxPendingAttributions, h.Vm.PendingAttributionCount);

        // n-0..n-43 overflowed (n-43 the newest of them); n-44 is the oldest row that kept its place.
        clock.Advance(TimeSpan.FromMilliseconds(750));
        h.Attribution.Enqueue(4,
            Entry(1, "n-0", pid: 100, processName: "chrome", unixMs: anchorMs - 100),
            Entry(2, "n-43", pid: 100, processName: "chrome", unixMs: anchorMs - 100),
            Entry(3, "n-44", pid: 200, processName: "edge", unixMs: anchorMs - 100),
            Entry(4, "n-" + (burst.Length - 1), pid: 300, processName: "firefox", unixMs: anchorMs - 100));
        h.Poller.Fire();

        Assert.Equal(QueryMonitorViewModel.UnknownAppLabel, h.Vm.Rows.Single(r => r.Name == "n-0").App);
        Assert.Equal(QueryMonitorViewModel.UnknownAppLabel, h.Vm.Rows.Single(r => r.Name == "n-43").App);
        Assert.Equal("edge", h.Vm.Rows.Single(r => r.Name == "n-44").App);
        Assert.Equal("firefox", h.Vm.Rows[^1].App);
        Assert.Equal(QueryMonitorViewModel.MaxPendingAttributions - 2, h.Vm.PendingAttributionCount);
    }

    [Fact]
    public async Task clear_view_drops_the_pending_list_so_a_later_batch_binds_nothing()
    {
        // OPSEC residue: each pending entry pins a row + its name (browsing history), so "Clear view"
        // must drop them with the buffer and the lookup — and a batch landing afterwards must find
        // nothing left to bind.
        using var h = new Harness();
        await EnableAndActivateAsync(h);
        h.Reader.Enqueue(Line("cleared.example"));
        h.Poller.Fire();
        var row = Assert.Single(h.Vm.Rows);
        Assert.Equal(1, h.Vm.PendingAttributionCount);

        h.Vm.ClearView();
        Assert.Equal(0, h.Vm.PendingAttributionCount);

        h.Attribution.Enqueue(1, Entry(1, "cleared.example", pid: 100, processName: "chrome"));
        h.Poller.Fire();
        Assert.Equal(QueryMonitorViewModel.UnknownAppLabel, row.App); // the cleared row was let go
    }

    [Fact]
    public async Task stop_and_clear_drops_the_pending_list()
    {
        // "Stop & clear" ends the ticks, so nothing would ever age the pending entries out — the
        // disable path must drop them explicitly, exactly like the domain→process lookup.
        using var h = new Harness();
        await EnableAndActivateAsync(h);
        h.Reader.Enqueue(Line("stopped.example"));
        h.Poller.Fire();
        Assert.Equal(1, h.Vm.PendingAttributionCount);

        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok("[query_log]\nfile = 'x'\n", Sha));
        await h.Vm.DisableAsync(CancellationToken.None);

        Assert.Equal(0, h.Vm.PendingAttributionCount);
    }

    [Fact]
    public async Task a_row_evicted_from_the_ring_leaves_the_pending_list_with_it()
    {
        // The 500-row ring stays THE bound on rows held in memory: a pending row the buffer evicts
        // must not be pinned by the pending list, nor late-bound behind the ring's back.
        using var h = new Harness();
        await EnableAndActivateAsync(h);
        h.Reader.Enqueue(Line("lonely.example"));
        h.Poller.Fire();
        var lonely = Assert.Single(h.Vm.Rows);

        // A full ring of rows that resolve AT APPEND (their attribution is merged first), so none of
        // them is pending — they only push "lonely" out of the buffer.
        var flood = new QueryLogLine[500];
        for (var i = 0; i < flood.Length; i++)
        {
            flood[i] = Line("busy.example");
        }

        h.Attribution.Enqueue(1, Entry(1, "busy.example", pid: 100, processName: "chrome"));
        h.Reader.Enqueue(flood);
        h.Poller.Fire();
        Assert.DoesNotContain(lonely, h.Vm.Rows);
        Assert.Equal(0, h.Vm.PendingAttributionCount);

        h.Attribution.Enqueue(2, Entry(2, "lonely.example", pid: 200, processName: "edge"));
        h.Poller.Fire();
        Assert.Equal(QueryMonitorViewModel.UnknownAppLabel, lonely.App);
    }

    // ------------------------------------------------------------------ in-flight fetch vs Stop & clear

    [Fact]
    public async Task an_attribution_fetch_completing_after_stop_and_clear_is_dropped_not_merged()
    {
        // OPSEC: a fetch issued before "Stop & clear" can complete after it. Its batch belongs to the
        // session that was cleared, so it is dropped whole — merging it would refill the
        // domain→process lookup the clear just emptied and un-reset the rewound cursor.
        using var h = new Harness();
        await EnableAndActivateAsync(h);
        h.Attribution.Enqueue(3, Entry(3, "before.example", pid: 100, processName: "chrome"));
        h.Poller.Fire(); // an ordinary fetch: the cursor moves to 3
        var gate = new TaskCompletionSource<DnsAttributionBatch?>();
        h.Attribution.Gate = gate;
        h.Poller.Fire(); // this fetch is still awaiting the pipe...

        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok("[query_log]\nfile = 'x'\n", Sha));
        await h.Vm.DisableAsync(CancellationToken.None); // ...when the user stops & clears
        Assert.Equal(0, h.Vm.AttributionLookupCount);

        gate.SetResult(new DnsAttributionBatch(9, new[] { Entry(9, "stale.example", pid: 200, processName: "msedge") }));

        Assert.Equal(0, h.Vm.AttributionLookupCount); // dropped, not merged
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok(string.Empty, Sha));
        h.Vm.RequestEnable();
        await h.Vm.ConfirmEnableAsync(CancellationToken.None);
        h.Poller.Fire();
        Assert.Equal(0, h.Attribution.FetchCalls[^1]); // the rewound cursor stayed rewound (not 9, not 3)
    }

    [Fact]
    public async Task a_pre_clear_fetch_landing_after_a_quick_re_enable_is_still_dropped()
    {
        // Logging being back ON is not enough to trust a late batch: when the user re-enables before
        // the pre-clear fetch completes, that batch still belongs to the cleared session — it must not
        // seed the new session's lookup or drag its fresh cursor forward.
        using var h = new Harness();
        await EnableAndActivateAsync(h);
        var gate = new TaskCompletionSource<DnsAttributionBatch?>();
        h.Attribution.Gate = gate;
        h.Poller.Fire(); // in flight across the whole stop → re-enable below

        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok("[query_log]\nfile = 'x'\n", Sha));
        await h.Vm.DisableAsync(CancellationToken.None);
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok(string.Empty, Sha));
        h.Vm.RequestEnable();
        await h.Vm.ConfirmEnableAsync(CancellationToken.None);
        Assert.True(h.Vm.LoggingEnabled);

        gate.SetResult(new DnsAttributionBatch(9, new[] { Entry(9, "stale.example", pid: 200, processName: "msedge") }));

        Assert.Equal(0, h.Vm.AttributionLookupCount);
        h.Poller.Fire();
        Assert.Equal(0, h.Attribution.FetchCalls[^1]);
    }

    [Fact]
    public async Task a_fetch_landing_after_logging_was_found_off_is_never_merged()
    {
        // The other half of the re-check: logging can also go off WITHOUT a clear (the tab re-reads a
        // config whose query_log.file is gone, so the epoch never moves). A batch landing then is not
        // merged either — attribution data is only ever kept while logging is on.
        using var h = new Harness();
        await EnableAndActivateAsync(h);
        var gate = new TaskCompletionSource<DnsAttributionBatch?>();
        h.Attribution.Gate = gate;
        h.Poller.Fire();

        h.Config.NextLoad = ConfigLoadResult.Ok("listen_addresses = ['127.0.0.1:53']\n", Sha);
        await h.Vm.LoadAsync(CancellationToken.None);
        Assert.False(h.Vm.LoggingEnabled);

        gate.SetResult(new DnsAttributionBatch(9, new[] { Entry(9, "late.example", pid: 200, processName: "msedge") }));

        Assert.Equal(0, h.Vm.AttributionLookupCount);
    }

    [Fact]
    public async Task a_tick_landing_after_stop_and_clear_still_shreds_but_leaves_no_rows_behind()
    {
        // The shredder is never gated — the late tick still drains (truncates) the on-disk log — but a
        // buffer that only exists while logging is on must not be refilled by it: rows appended after
        // "Stop & clear" would sit in memory, and on the pending list with no tick left to age them
        // out, until some later clear.
        using var h = new Harness();
        await EnableAndActivateAsync(h);
        var gate = new TaskCompletionSource<DnsAttributionBatch?>();
        h.Attribution.Gate = gate;
        h.Poller.Fire();

        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok("[query_log]\nfile = 'x'\n", Sha));
        await h.Vm.DisableAsync(CancellationToken.None);
        var drainsBefore = h.Reader.DrainCalls;
        h.Reader.Enqueue(Line("after-stop.example"));

        gate.SetResult(null);

        Assert.Equal(drainsBefore + 1, h.Reader.DrainCalls); // still shredded
        Assert.Equal(0, h.Vm.Stats.Queries);
        Assert.Empty(h.Vm.RecentRows(5));
        Assert.Equal(0, h.Vm.PendingAttributionCount);
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>Enables logging (consent + confirm) and activates the tab, leaving the poller running.</summary>
    private static async Task EnableAndActivateAsync(Harness h)
    {
        h.Vm.IsActive = true;
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok(string.Empty, Sha));
        h.Vm.RequestEnable();
        await h.Vm.ConfirmEnableAsync(CancellationToken.None);
    }

    private static long NowMs() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    /// <summary>A wire attribution entry stamped NOW unless a test needs it stale.</summary>
    private static DnsAttributionEntry Entry(
        long seq, string name, int pid, string? processName, long? unixMs = null) =>
        new(seq, unixMs ?? NowMs(), pid, name, processName);
}
