using DnsCryptControl.Core.QueryLog;
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

    private sealed class Harness : IDisposable
    {
        public FakeConfigFileService Config { get; } = new();
        public FakeQueryLogReader Reader { get; } = new();
        public FakeQueryPoller Poller { get; } = new();
        public QueryMonitorViewModel Vm { get; }

        public Harness()
        {
            Vm = new QueryMonitorViewModel(Config, Reader, Poller, new SynchronousDispatcher());
        }

        public void Dispose() => Vm.Dispose();
    }

    private static QueryLogLine Line(
        string name, QueryAction action = QueryAction.Pass, string type = "A", string time = "[2026-07-03 10:24:59]") =>
        new(time, "127.0.0.1", name, type, action, 12, action is QueryAction.Pass ? "cloudflare" : "-", "-");

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

    // ------------------------------------------------------------------ helpers

    /// <summary>Enables logging (consent + confirm) and activates the tab, leaving the poller running.</summary>
    private static async Task EnableAndActivateAsync(Harness h)
    {
        h.Vm.IsActive = true;
        h.Config.LoadQueue.Enqueue(ConfigLoadResult.Ok(string.Empty, Sha));
        h.Vm.RequestEnable();
        await h.Vm.ConfirmEnableAsync(CancellationToken.None);
    }
}
