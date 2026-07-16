using DnsCryptControl.Core.QueryLog;
using DnsCryptControl.Core.Sources;
using DnsCryptControl.Core.Stamps;
using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Platform.Diagnostics;
using DnsCryptControl.UI.Models;
using DnsCryptControl.UI.Services;
using DnsCryptControl.UI.Tests.Fakes;
using DnsCryptControl.UI.ViewModels;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// C1: the heart of Phase 5a. Covers the master protection toggle, the truthful
/// (diagnostics-verified) status, the in-flight lock, and the converge-on-lost-reply
/// behavior — all against fakes so the tests run headlessly and deterministically.
/// A false green "Protected" badge is the worst possible failure for this OPSEC tool,
/// so <c>green_requires_diagnostics_not_just_flags</c> is the load-bearing test here.
/// </summary>
public class DashboardViewModelTests
{
    private sealed class SynchronousDispatcher : IUiDispatcher
    {
        public int PostCount { get; private set; }

        public void Post(Action action)
        {
            PostCount++;
            action();
        }
    }

    private sealed class FakeStateReader : IProtectionStateReader
    {
        public ProtectionIntent Intent { get; set; } = new(false, false, false);

        public ProtectionIntent Read() => Intent;
    }

    private sealed class FakeResolverReader : IActiveResolverReader
    {
        public string? Name { get; set; }

        public string? ReadPrimaryName() => Name;
    }

    /// <summary>5h: cached-list fake for the Active-Resolver panel lookup. Empty by default.</summary>
    private sealed class FakeListReader : IResolverListReader
    {
        public IReadOnlyList<ResolverListSnapshot> Snapshots { get; set; } = Array.Empty<ResolverListSnapshot>();

        public int ReadAllCalls { get; private set; }

        public IReadOnlyList<ResolverListSnapshot> ReadAll()
        {
            ReadAllCalls++;
            return Snapshots;
        }
    }

    /// <summary>Phase 5i: fake shared query-log session driving the Dashboard KPIs + Live Activity.</summary>
    private sealed class FakeQueryLogSession : IQueryLogSession
    {
        public bool LoggingActive { get; set; }

        public QueryLogStats Stats { get; set; } = QueryLogStats.Empty;

        private IReadOnlyList<QueryRowViewModel> _recent = Array.Empty<QueryRowViewModel>();

        public void SetRecent(params QueryRowViewModel[] rows) => _recent = rows;

        public IReadOnlyList<QueryRowViewModel> RecentRows(int max) =>
            _recent.Count <= max ? _recent : _recent.Take(max).ToList();

        public event EventHandler? Changed;

        public void RaiseChanged() => Changed?.Invoke(this, EventArgs.Empty);
    }

    private static QueryRowViewModel Row(string name, QueryAction action = QueryAction.Pass) =>
        new(new QueryLogLine("[2026-07-05 10:00:00]", "127.0.0.1", name, "A", action, 12,
            action is QueryAction.Pass ? "cloudflare" : "-", "-"));

    /// <summary>In-memory UiState store for the kill-switch opt-in preference. Load returns the live
    /// State instance (tests can pre-set State.KillSwitchOptIn); Save records the write.</summary>
    private sealed class FakeUiStateStore : IUiStateStore
    {
        public UiState State { get; set; } = new();

        public int SaveCount { get; private set; }

        public UiState Load() => State;

        public void Save(UiState state) { State = state; SaveCount++; }
    }

    private static DashboardViewModel MakeSut(
        FakeHelperClient helper, FakeStateReader stateReader, FakeResolverReader resolverReader, SynchronousDispatcher dispatcher,
        FakeListReader? listReader = null, FakeQueryLogSession? querySession = null, Func<DateTimeOffset>? clock = null,
        IUiStateStore? uiStateStore = null) =>
        new(helper, stateReader, resolverReader, listReader ?? new FakeListReader(), dispatcher, querySession ?? new FakeQueryLogSession(),
            uiStateStore ?? new FakeUiStateStore(), pollInterval: null, clock: clock);

    // ---- Phase 5i: Dashboard live query KPIs + Live Activity (read from the shared per-session session) ----

    [Fact]
    public void query_kpis_off_by_default_show_the_prompt_and_no_recent_queries()
    {
        var vm = MakeSut(new FakeHelperClient(), new FakeStateReader(), new FakeResolverReader(),
            new SynchronousDispatcher(), querySession: new FakeQueryLogSession());

        Assert.False(vm.LoggingActive);
        Assert.Contains("query logging", vm.QueriesValue, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("query logging", vm.AnsweredLocallyValue, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(vm.RecentQueries);
    }

    [Fact]
    public void query_kpis_populate_from_session_when_logging_on()
    {
        var session = new FakeQueryLogSession
        {
            LoggingActive = true,
            Stats = new QueryLogStats(Queries: 10, Blocked: 3, Cloaked: 1, AnsweredLocally: 5, UpstreamCount: 5, AvgUpstreamLatencyMs: 42),
        };
        session.SetRecent(Row("github.com"), Row("ads.example", QueryAction.Reject));
        var vm = MakeSut(new FakeHelperClient(), new FakeStateReader(), new FakeResolverReader(),
            new SynchronousDispatcher(), querySession: session);

        session.RaiseChanged();

        Assert.True(vm.LoggingActive);
        Assert.Equal("10", vm.QueriesValue);
        Assert.Equal("3", vm.BlockedValue);
        Assert.Equal("42 ms", vm.AvgLatencyValue);
        Assert.Equal("50%", vm.AnsweredLocallyValue);      // 5 / 10
        Assert.Equal(2, vm.RecentQueries.Count);
        Assert.Equal("github.com", vm.RecentQueries[0].Name); // newest-first order preserved
    }

    [Fact]
    public void query_kpis_clear_completely_when_logging_turned_off()
    {
        var session = new FakeQueryLogSession
        {
            LoggingActive = true,
            Stats = new QueryLogStats(5, 1, 0, 2, 3, 20),
        };
        session.SetRecent(Row("a.example"));
        var vm = MakeSut(new FakeHelperClient(), new FakeStateReader(), new FakeResolverReader(),
            new SynchronousDispatcher(), querySession: session);
        session.RaiseChanged();
        Assert.True(vm.LoggingActive);
        Assert.NotEmpty(vm.RecentQueries);

        // Turn logging off → the Dashboard reverts to the off-prompt and drops all query-derived data.
        session.LoggingActive = false;
        session.RaiseChanged();

        Assert.False(vm.LoggingActive);
        Assert.Empty(vm.RecentQueries);
        Assert.Contains("query logging", vm.QueriesValue, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void avg_latency_shows_dash_when_no_upstream_queries_yet()
    {
        var session = new FakeQueryLogSession
        {
            LoggingActive = true,
            Stats = new QueryLogStats(4, 4, 0, 4, UpstreamCount: 0, AvgUpstreamLatencyMs: 0),
        };
        var vm = MakeSut(new FakeHelperClient(), new FakeStateReader(), new FakeResolverReader(),
            new SynchronousDispatcher(), querySession: session);

        session.RaiseChanged();

        Assert.Equal("—", vm.AvgLatencyValue);
        Assert.Equal("100%", vm.AnsweredLocallyValue); // all 4 answered locally
    }

    // ---- Phase 5f: Dashboard browser-DoH toggle (single-source from the diagnostics snapshot) ----

    [Fact]
    public async Task browserDoh_checked_derives_from_diagnostics_snapshot()
    {
        var helper = new FakeHelperClient
        {
            RunDiagnosticsHandler = _ => Task.FromResult<Result<DiagnosticsSnapshot>?>(
                Result<DiagnosticsSnapshot>.Ok(FakeHelperClient.MakeSnapshot(browserDoh: true))),
        };
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(true, false, false) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher());

        await vm.RefreshAsync(CancellationToken.None);

        Assert.True(vm.BrowserDohEnabled);
        Assert.True(vm.BrowserDohStateKnown);
    }

    [Fact]
    public async Task browserDoh_reflects_disabled_policy_and_is_unknown_when_unprotected()
    {
        var helper = new FakeHelperClient
        {
            RunDiagnosticsHandler = _ => Task.FromResult<Result<DiagnosticsSnapshot>?>(
                Result<DiagnosticsSnapshot>.Ok(FakeHelperClient.MakeSnapshot(browserDoh: false))),
        };
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(true, false, false) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher());

        await vm.RefreshAsync(CancellationToken.None);
        Assert.False(vm.BrowserDohEnabled);
        Assert.True(vm.BrowserDohStateKnown);

        // Unprotected: diagnostics does not run → the state is honestly UNKNOWN, never a stale assert.
        stateReader.Intent = new ProtectionIntent(false, false, false);
        await vm.RefreshAsync(CancellationToken.None);
        Assert.False(vm.BrowserDohStateKnown);
    }

    [Fact]
    public async Task browserDoh_toggle_calls_SetBrowserDohPolicy_with_intended_value()
    {
        var helper = new FakeHelperClient();
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(true, false, false) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher());
        // BrowserDohEnabled starts false → toggling intends to enable (block browser DoH).

        await vm.ToggleBrowserDohCommand.ExecuteAsync(null);

        Assert.Single(helper.SetBrowserDohCalls);
        Assert.True(helper.SetBrowserDohCalls[0]);
    }

    [Fact]
    public async Task browserDoh_toggle_nullReply_reconciles_from_diagnostics_no_false_flip()
    {
        var helper = new FakeHelperClient
        {
            SetBrowserDohHandler = (_, _) => Task.FromResult<Result?>(null), // lost reply == UNKNOWN
            RunDiagnosticsHandler = _ => Task.FromResult<Result<DiagnosticsSnapshot>?>(
                Result<DiagnosticsSnapshot>.Ok(FakeHelperClient.MakeSnapshot(browserDoh: false))),
        };
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(true, false, false) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher());

        await vm.ToggleBrowserDohCommand.ExecuteAsync(null);

        // The caller intended to enable, but the null reply must NOT optimistically flip the shown
        // state — it reflects the reconciled diagnostics reading (false).
        Assert.False(vm.BrowserDohEnabled);
        Assert.Single(helper.SetBrowserDohCalls);
    }

    [Fact]
    public async Task toggle_on_sends_EnableProtection_with_killswitch_flag()
    {
        var helper = new FakeHelperClient();
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(false, false, false) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher());
        vm.KillSwitchOptIn = true;

        await vm.ToggleProtectionCommand.ExecuteAsync(null);

        Assert.Single(helper.EnableCalls);
        Assert.True(helper.EnableCalls[0]);
        Assert.Equal(0, helper.DisableCalls);
    }

    [Fact]
    public async Task toggle_off_sends_DisableProtection()
    {
        var helper = new FakeHelperClient();
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(true, false, false) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher());
        // IsProtected reflects the off-disk intent (set here directly to simulate an
        // already-refreshed VM without depending on RefreshAsync's own timing).
        vm.IsProtected = true;

        await vm.ToggleProtectionCommand.ExecuteAsync(null);

        Assert.Equal(1, helper.DisableCalls);
        Assert.Empty(helper.EnableCalls);
    }

    [Fact]
    public async Task in_flight_lock_ignores_second_click_until_resolved()
    {
        var helper = new FakeHelperClient();
        var gate = new TaskCompletionSource<Result<ProtectionResponse>?>();
        helper.EnableHandler = (_, _) => gate.Task;
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(false, false, false) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher());

        var firstToggle = vm.ToggleProtectionCommand.ExecuteAsync(null);

        Assert.Equal(ProtectionStatusView.Applying, vm.Status);

        // Second click while the first is still in flight must be ignored.
        await vm.ToggleProtectionCommand.ExecuteAsync(null);

        Assert.Single(helper.EnableCalls); // only the first click's call went through

        gate.SetResult(Result<ProtectionResponse>.Ok(new ProtectionResponse(true, false, true, false, null)));
        await firstToggle;
    }

    [Fact]
    public async Task null_response_reconciles_and_reissues_when_state_differs_not_blind_rollback()
    {
        var helper = new FakeHelperClient();
        helper.EnableHandler = (_, _) => Task.FromResult<Result<ProtectionResponse>?>(null);
        // Observed reality disagrees with the target ("on"): intent still reads off, and
        // diagnostics show a leak (adapter not on loopback) — i.e. protection never took.
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(false, false, false) };
        helper.RunDiagnosticsHandler = (_) => Task.FromResult<Result<DiagnosticsSnapshot>?>(
            Result<DiagnosticsSnapshot>.Ok(FakeHelperClient.MakeSnapshot(allLoopback: false)));
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher());
        vm.KillSwitchOptIn = false; // pin the opt-in off so both Enable calls carry a deterministic kill-switch flag

        await vm.ToggleProtectionCommand.ExecuteAsync(null);

        // The lost reply must never provoke a Disable (no blind rollback) — only the
        // SAME verb (Enable), re-issued because the observed state != target.
        Assert.Equal(0, helper.DisableCalls);
        Assert.Equal(2, helper.EnableCalls.Count); // original attempt + one reconciling re-issue
        Assert.All(helper.EnableCalls, ks => Assert.False(ks));
    }

    [Fact]
    public async Task null_response_does_not_reissue_when_observed_state_already_matches_target()
    {
        var helper = new FakeHelperClient();
        helper.EnableHandler = (_, _) => Task.FromResult<Result<ProtectionResponse>?>(null);
        // Observed reality already matches the target ("on"): intent reads on and
        // diagnostics show no leak — the enable silently succeeded despite the lost reply.
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(true, false, false) };
        helper.RunDiagnosticsHandler = (_) => Task.FromResult<Result<DiagnosticsSnapshot>?>(
            Result<DiagnosticsSnapshot>.Ok(FakeHelperClient.MakeSnapshot(allLoopback: true, proxyAnswered: true)));
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher());

        await vm.ToggleProtectionCommand.ExecuteAsync(null);

        Assert.Equal(0, helper.DisableCalls);
        Assert.Single(helper.EnableCalls); // no reconciling re-issue needed
    }

    [Fact]
    public async Task killswitch_advisory_surfaced_without_dropping_protection()
    {
        var helper = new FakeHelperClient();
        helper.EnableHandler = (withKs, _) => Task.FromResult<Result<ProtectionResponse>?>(
            Result<ProtectionResponse>.Ok(new ProtectionResponse(true, false, true, false, "kill-switch could not bind port 53")));
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(true, false, true) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher());
        vm.KillSwitchOptIn = true;

        await vm.ToggleProtectionCommand.ExecuteAsync(null);

        Assert.Equal("kill-switch could not bind port 53", vm.Advisory);
        Assert.Equal(0, helper.DisableCalls);
        Assert.True(vm.IsProtected);
    }

    [Fact]
    public async Task green_requires_diagnostics_not_just_flags()
    {
        var helper = new FakeHelperClient();
        helper.GetStatusHandler = (_) => Task.FromResult<Result<StatusResponse>?>(
            Result<StatusResponse>.Ok(new StatusResponse(true, "resolver", true, true, IpcProtocol.Version, "1.0.0")));
        helper.RunDiagnosticsHandler = (_) => Task.FromResult<Result<DiagnosticsSnapshot>?>(
            Result<DiagnosticsSnapshot>.Ok(FakeHelperClient.MakeSnapshot(allLoopback: false, proxyAnswered: true)));
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(true, true, true) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher());

        await vm.RefreshAsync(CancellationToken.None);

        Assert.Equal(ProtectionStatusView.PartiallyProtected, vm.Status);
        Assert.NotEqual(ProtectionStatusView.ProtectedVerified, vm.Status);
    }

    // ---- deadlock fix: a failed DNS self-check (RunDiagnostics null/!Success) must NOT read as
    // "Helper unavailable" when GetStatus already proved the helper reachable + the proxy running.
    // Otherwise a broken route (which makes the self-check fail) raises the blocking banner and locks
    // the user out of the very controls needed to fix it. ----

    [Fact]
    public async Task diagnostics_null_with_proxy_running_is_diagnosticsUnavailable_not_helperUnavailable()
    {
        var helper = new FakeHelperClient();
        helper.GetStatusHandler = (_) => Task.FromResult<Result<StatusResponse>?>(
            Result<StatusResponse>.Ok(new StatusResponse(true, "resolver", true, true, IpcProtocol.Version, "1.0.0")));
        helper.RunDiagnosticsHandler = (_) => Task.FromResult<Result<DiagnosticsSnapshot>?>(null);
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(true, true, true) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher());

        await vm.RefreshAsync(CancellationToken.None);

        Assert.Equal(ProtectionStatusView.DiagnosticsUnavailable, vm.Status);
        Assert.NotEqual(ProtectionStatusView.HelperUnavailable, vm.Status);
    }

    [Fact]
    public async Task diagnostics_fail_with_proxy_running_is_diagnosticsUnavailable_not_helperUnavailable()
    {
        var helper = new FakeHelperClient();
        helper.GetStatusHandler = (_) => Task.FromResult<Result<StatusResponse>?>(
            Result<StatusResponse>.Ok(new StatusResponse(true, "resolver", true, true, IpcProtocol.Version, "1.0.0")));
        helper.RunDiagnosticsHandler = (_) => Task.FromResult<Result<DiagnosticsSnapshot>?>(
            Result<DiagnosticsSnapshot>.Fail(IpcErrorCode.OperationFailed, "probe threw"));
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(true, true, true) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher());

        await vm.RefreshAsync(CancellationToken.None);

        Assert.Equal(ProtectionStatusView.DiagnosticsUnavailable, vm.Status);
        Assert.False(vm.BrowserDohStateKnown); // browser-DoH state is only observable via diagnostics
    }

    [Fact]
    public async Task getStatus_null_still_shows_helperUnavailable_regression_guard()
    {
        // The genuine transport-failure signal must be preserved: GetStatus itself returning null is a
        // real "helper unreachable" and MUST still raise HelperUnavailable (only the diagnostics-fail
        // path was reclassified). Mirrors helper_unavailable_when_calls_return_null; kept adjacent to the
        // deadlock-fix tests so the two paths can't be conflated in a future refactor.
        var helper = new FakeHelperClient();
        helper.GetStatusHandler = (_) => Task.FromResult<Result<StatusResponse>?>(null);
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(true, false, false) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher());

        await vm.RefreshAsync(CancellationToken.None);

        Assert.Equal(ProtectionStatusView.HelperUnavailable, vm.Status);
    }

    // ---- 5j: cold-start "Verifying…" warm-up window (adapters pinned but the proxy hasn't answered yet) ----

    [Fact]
    public async Task cold_start_shows_verifying_not_leak_while_the_proxy_warms_up()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var helper = new FakeHelperClient();
        helper.EnableHandler = (_, _) => Task.FromResult<Result<ProtectionResponse>?>(
            Result<ProtectionResponse>.Ok(new ProtectionResponse(true, false, false, false, null)));
        helper.GetStatusHandler = (_) => Task.FromResult<Result<StatusResponse>?>(
            Result<StatusResponse>.Ok(new StatusResponse(true, "resolver", false, false, IpcProtocol.Version, "1.0.0")));
        // Adapters ARE pinned to loopback; the proxy just hasn't answered its first self-check yet.
        helper.RunDiagnosticsHandler = (_) => Task.FromResult<Result<DiagnosticsSnapshot>?>(
            Result<DiagnosticsSnapshot>.Ok(FakeHelperClient.MakeSnapshot(allLoopback: true, proxyAnswered: false)));
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(true, false, false) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher(), clock: () => now);

        await vm.ToggleProtectionCommand.ExecuteAsync(null); // stamps 'now'; verdict runs in-window

        Assert.Equal(ProtectionStatusView.Verifying, vm.Status);          // amber, not "leak detected"
        Assert.Equal("Verifying protection…", vm.HeroHeadline);
        Assert.NotEqual(ProtectionStatusView.ProtectedVerified, vm.Status); // NEVER green while unverified
    }

    [Fact]
    public async Task verifying_falls_through_to_partially_protected_after_the_window()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var helper = new FakeHelperClient();
        helper.EnableHandler = (_, _) => Task.FromResult<Result<ProtectionResponse>?>(
            Result<ProtectionResponse>.Ok(new ProtectionResponse(true, false, false, false, null)));
        helper.GetStatusHandler = (_) => Task.FromResult<Result<StatusResponse>?>(
            Result<StatusResponse>.Ok(new StatusResponse(true, "resolver", false, false, IpcProtocol.Version, "1.0.0")));
        helper.RunDiagnosticsHandler = (_) => Task.FromResult<Result<DiagnosticsSnapshot>?>(
            Result<DiagnosticsSnapshot>.Ok(FakeHelperClient.MakeSnapshot(allLoopback: true, proxyAnswered: false)));
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(true, false, false) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher(), clock: () => now);

        await vm.ToggleProtectionCommand.ExecuteAsync(null);
        Assert.Equal(ProtectionStatusView.Verifying, vm.Status);         // in-window

        now = now.AddSeconds(30);                                        // past the warm-up window
        await vm.RefreshAsync(CancellationToken.None);                   // a later poll tick

        // The transient state is time-boxed: a still-failing self-check is now the REAL warning.
        Assert.Equal(ProtectionStatusView.PartiallyProtected, vm.Status);
    }

    [Fact]
    public async Task protected_but_proxy_service_stopped_shows_proxy_stopped_not_leak_detected()
    {
        // The proxy service is DOWN while protection is on by intent. Honest "the DNS proxy isn't
        // running" (fail-closed) — NOT PartiallyProtected's "leak detected" (which implies the proxy
        // is up and being bypassed). Short-circuits BEFORE diagnostics.
        var helper = new FakeHelperClient();
        helper.GetStatusHandler = (_) => Task.FromResult<Result<StatusResponse>?>(
            Result<StatusResponse>.Ok(new StatusResponse(false, "resolver", false, false, IpcProtocol.Version, "1.0.0")));
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(true, false, false) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher());

        await vm.RefreshAsync(CancellationToken.None);

        Assert.Equal(ProtectionStatusView.ProxyStopped, vm.Status);
        Assert.Equal("Protection incomplete — the DNS proxy isn't running", vm.HeroHeadline);
        Assert.Equal(0, helper.RunDiagnosticsCalls); // never runs diagnostics for a stopped proxy
    }

    [Fact]
    public async Task after_a_verified_pass_a_later_failure_is_partially_protected_not_verifying()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var proxyAnswered = true;
        var helper = new FakeHelperClient();
        helper.EnableHandler = (_, _) => Task.FromResult<Result<ProtectionResponse>?>(
            Result<ProtectionResponse>.Ok(new ProtectionResponse(true, false, false, false, null)));
        helper.GetStatusHandler = (_) => Task.FromResult<Result<StatusResponse>?>(
            Result<StatusResponse>.Ok(new StatusResponse(true, "resolver", false, false, IpcProtocol.Version, "1.0.0")));
        helper.RunDiagnosticsHandler = (_) => Task.FromResult<Result<DiagnosticsSnapshot>?>(
            Result<DiagnosticsSnapshot>.Ok(FakeHelperClient.MakeSnapshot(allLoopback: true, proxyAnswered: proxyAnswered)));
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(true, false, false) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher(), clock: () => now);

        await vm.ToggleProtectionCommand.ExecuteAsync(null);            // first pass verifies → green
        Assert.Equal(ProtectionStatusView.ProtectedVerified, vm.Status);

        proxyAnswered = false;                                         // the proxy later stops answering — REAL
        await vm.RefreshAsync(CancellationToken.None);

        // Once verified this session, a failure is never re-softened to "Verifying…".
        Assert.Equal(ProtectionStatusView.PartiallyProtected, vm.Status);
    }

    [Fact]
    public async Task verifying_applies_on_the_reboot_path_via_refresh_alone_no_toggle()
    {
        // Review finding #3: the app is opened while protection is ALREADY on (reboot / enabled out-of-band).
        // No ToggleProtection call happens, yet the poll must still stamp the window and show Verifying —
        // not the alarming "leak detected" — while the proxy warms up.
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var helper = new FakeHelperClient();
        helper.GetStatusHandler = (_) => Task.FromResult<Result<StatusResponse>?>(
            Result<StatusResponse>.Ok(new StatusResponse(true, "resolver", false, false, IpcProtocol.Version, "1.0.0")));
        helper.RunDiagnosticsHandler = (_) => Task.FromResult<Result<DiagnosticsSnapshot>?>(
            Result<DiagnosticsSnapshot>.Ok(FakeHelperClient.MakeSnapshot(allLoopback: true, proxyAnswered: false)));
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(true, false, false) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher(), clock: () => now);

        await vm.RefreshAsync(CancellationToken.None); // poll observes protected — no toggle ever flipped

        Assert.Equal(ProtectionStatusView.Verifying, vm.Status);
    }

    [Fact]
    public async Task restart_service_rearms_the_warmup_and_shows_verifying_not_leak_after_a_verified_pass()
    {
        // Live-reported gap: after the session verified green, pressing "Restart service" cold-starts the
        // proxy; the transient self-check failure must show Verifying, not "Partially protected — leak
        // detected". A manual Restart re-arms the warm-up window.
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var proxyAnswered = true;
        var helper = new FakeHelperClient();
        helper.GetStatusHandler = (_) => Task.FromResult<Result<StatusResponse>?>(
            Result<StatusResponse>.Ok(new StatusResponse(true, "resolver", false, false, IpcProtocol.Version, "1.0.0")));
        helper.RunDiagnosticsHandler = (_) => Task.FromResult<Result<DiagnosticsSnapshot>?>(
            Result<DiagnosticsSnapshot>.Ok(FakeHelperClient.MakeSnapshot(allLoopback: true, proxyAnswered: proxyAnswered)));
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(true, false, false) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher(), clock: () => now);

        await vm.RefreshAsync(CancellationToken.None);            // first pass verifies -> green (session verified)
        Assert.Equal(ProtectionStatusView.ProtectedVerified, vm.Status);

        proxyAnswered = false;                                    // the proxy is restarting -> self-check fails
        await vm.RestartCommand.ExecuteAsync(null);               // re-arms the warm-up + refreshes

        Assert.Equal(ProtectionStatusView.Verifying, vm.Status);  // NOT PartiallyProtected
    }

    [Fact]
    public async Task reboot_recommended_is_surfaced()
    {
        var helper = new FakeHelperClient();
        helper.EnableHandler = (_, _) => Task.FromResult<Result<ProtectionResponse>?>(
            Result<ProtectionResponse>.Ok(new ProtectionResponse(true, false, true, true, null)));
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(true, false, true) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher());

        await vm.ToggleProtectionCommand.ExecuteAsync(null);

        Assert.True(vm.RebootRecommended);
    }

    [Fact]
    public async Task helper_unavailable_when_calls_return_null()
    {
        var helper = new FakeHelperClient();
        helper.GetStatusHandler = (_) => Task.FromResult<Result<StatusResponse>?>(null);
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(true, false, false) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher());

        await vm.RefreshAsync(CancellationToken.None);

        Assert.Equal(ProtectionStatusView.HelperUnavailable, vm.Status);
        Assert.True(vm.IsProtected); // toggle position still reflects off-disk intent
    }

    /// <summary>
    /// F20: a helper reporting a different <c>ProtocolVersion</c> than
    /// <see cref="IpcProtocol.Version"/> must be treated as a hard stop — the UI cannot
    /// trust any OTHER field in that response either, so it must never fall through to
    /// diagnostics and must never reach <see cref="ProtectionStatusView.ProtectedVerified"/>,
    /// even though intent is on and diagnostics (if consulted) would report all-loopback /
    /// no leak. <c>RunDiagnosticsCalls</c> staying at 0 is the proof that diagnostics were
    /// never consulted after the version mismatch was detected.
    /// </summary>
    [Fact]
    public async Task version_mismatch_is_helper_incompatible_and_never_reaches_protected_verified()
    {
        var helper = new FakeHelperClient();
        helper.GetStatusHandler = (_) => Task.FromResult<Result<StatusResponse>?>(
            Result<StatusResponse>.Ok(new StatusResponse(true, "resolver", true, true, IpcProtocol.Version + 1, "1.0.0")));
        helper.RunDiagnosticsHandler = (_) => Task.FromResult<Result<DiagnosticsSnapshot>?>(
            Result<DiagnosticsSnapshot>.Ok(FakeHelperClient.MakeSnapshot(allLoopback: true, proxyAnswered: true)));
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(true, true, true) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher());

        await vm.RefreshAsync(CancellationToken.None);

        Assert.Equal(ProtectionStatusView.HelperIncompatible, vm.Status);
        Assert.NotEqual(ProtectionStatusView.ProtectedVerified, vm.Status);
        Assert.Equal(0, helper.RunDiagnosticsCalls); // diagnostics must never be consulted after a version mismatch
    }

    [Fact]
    public async Task poll_skips_when_a_command_is_in_flight()
    {
        var helper = new FakeHelperClient();
        var gate = new TaskCompletionSource<Result<ProtectionResponse>?>();
        helper.EnableHandler = (_, _) => gate.Task;
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(false, false, false) };
        // A very short poll interval (injected via the ctor seam) keeps the wall-clock window
        // small: the zero-GetStatusCalls absence proof below is taken over a bounded Task.Delay
        // of ~10 tick intervals, and the follow-up StartPolling/WaitUntilAsync phase proves the
        // loop does tick (guarding against a false pass from a never-ticking loop).
        var tickInterval = TimeSpan.FromMilliseconds(10);
        var vm = new DashboardViewModel(helper, stateReader, new FakeResolverReader(), new FakeListReader(), new SynchronousDispatcher(), new FakeQueryLogSession(), new FakeUiStateStore(), tickInterval);

        var toggleTask = vm.ToggleProtectionCommand.ExecuteAsync(null);

        // Hold the toggle command in flight (via the unresolved `gate`), then let the poll
        // loop run for several tick intervals. Because _inFlight is set for the whole window,
        // every tick must hit the `if (_inFlight) continue;` skip branch — GetStatus (called
        // only from RefreshAsync) must never be invoked while the toggle is still pending.
        vm.StartPolling();
        await Task.Delay(tickInterval * 10);
        vm.StopPolling();

        Assert.Equal(0, helper.GetStatusCalls);

        gate.SetResult(Result<ProtectionResponse>.Ok(new ProtectionResponse(true, false, true, false, null)));
        await toggleTask;

        // Now that the in-flight command has resolved, a fresh poll must go through and
        // actually call GetStatus — proving the earlier zero count was the skip branch at
        // work, not simply the poll loop never having ticked at all.
        vm.StartPolling();
        await WaitUntilAsync(() => helper.GetStatusCalls > 0);
        vm.StopPolling();

        Assert.True(helper.GetStatusCalls > 0);
    }

    /// <summary>
    /// Polls a condition on a short, bounded interval instead of a single fixed
    /// <c>Task.Delay</c>, so the wait resolves as soon as the condition is true rather than
    /// depending on picking a "long enough" sleep.
    /// </summary>
    private static async Task WaitUntilAsync(Func<bool> condition, int timeoutMs = 2000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                Assert.Fail("Condition was not met within the timeout.");
            }

            await Task.Delay(5);
        }
    }

    [Fact]
    public async Task property_writes_go_through_the_injected_dispatcher()
    {
        var helper = new FakeHelperClient();
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(true, false, false) };
        var dispatcher = new SynchronousDispatcher();
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), dispatcher);

        await vm.RefreshAsync(CancellationToken.None);

        Assert.True(dispatcher.PostCount > 0);
    }

    /// <summary>
    /// The opt-in defaults to the persisted preference (recommended = on); the FIRST successful refresh
    /// only ever STRENGTHENS it to ON when the kill switch is actually armed (<c>StatusResponse.
    /// KillSwitchEnabled</c>), so a relaunch while the kill switch is active shows the toggle ON. A
    /// second refresh must NOT re-seed over a user's own subsequent change (proven here by flipping it
    /// back to false between the two GetStatus-armed refreshes and asserting the user's false sticks).
    /// </summary>
    [Fact]
    public async Task kill_switch_opt_in_is_seeded_once_from_ground_truth_and_not_reseeded()
    {
        var helper = new FakeHelperClient();
        helper.GetStatusHandler = (_) => Task.FromResult<Result<StatusResponse>?>(
            Result<StatusResponse>.Ok(new StatusResponse(true, "resolver", true, true, IpcProtocol.Version, "1.0.0")));
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(false, false, false) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher());

        await vm.RefreshAsync(CancellationToken.None);

        Assert.True(vm.KillSwitchOptIn); // seeded from the live KillSwitchEnabled == true

        // Simulate the user manually turning it back off after the seed.
        vm.KillSwitchOptIn = false;

        await vm.RefreshAsync(CancellationToken.None);

        Assert.False(vm.KillSwitchOptIn); // the second refresh must not re-seed over the user's change
    }

    [Fact]
    public void kill_switch_opt_in_defaults_on_for_a_fresh_install()
    {
        // Fresh install: no saved preference -> the recommended default (on) applies from construction,
        // so the very first Protect is fail-closed without the user having to find the toggle first.
        var store = new FakeUiStateStore(); // State.KillSwitchOptIn defaults to true
        var vm = MakeSut(new FakeHelperClient(), new FakeStateReader(), new FakeResolverReader(),
            new SynchronousDispatcher(), uiStateStore: store);

        Assert.True(vm.KillSwitchOptIn);
    }

    [Fact]
    public async Task kill_switch_opt_in_default_survives_an_unprotected_refresh()
    {
        // The seed only ever STRENGTHENS to on (when actually armed); an unprotected refresh
        // (KillSwitchEnabled == false) must never weaken the recommended default back to off.
        var helper = new FakeHelperClient();
        helper.GetStatusHandler = (_) => Task.FromResult<Result<StatusResponse>?>(
            Result<StatusResponse>.Ok(new StatusResponse(false, "resolver", false, false, IpcProtocol.Version, "1.0.0")));
        var vm = MakeSut(helper, new FakeStateReader { Intent = new ProtectionIntent(false, false, false) },
            new FakeResolverReader(), new SynchronousDispatcher(), uiStateStore: new FakeUiStateStore());

        await vm.RefreshAsync(CancellationToken.None);

        Assert.True(vm.KillSwitchOptIn);
    }

    [Fact]
    public void kill_switch_opt_in_reads_a_persisted_off_preference()
    {
        var store = new FakeUiStateStore();
        store.State.KillSwitchOptIn = false; // the user turned it off in a prior session
        var vm = MakeSut(new FakeHelperClient(), new FakeStateReader(), new FakeResolverReader(),
            new SynchronousDispatcher(), uiStateStore: store);

        Assert.False(vm.KillSwitchOptIn);
    }

    [Fact]
    public void toggling_kill_switch_opt_in_persists_the_preference()
    {
        var store = new FakeUiStateStore();
        var vm = MakeSut(new FakeHelperClient(), new FakeStateReader(), new FakeResolverReader(),
            new SynchronousDispatcher(), uiStateStore: store);

        vm.KillSwitchOptIn = false;
        Assert.False(store.State.KillSwitchOptIn);
        Assert.True(store.SaveCount >= 1);

        vm.KillSwitchOptIn = true;
        Assert.True(store.State.KillSwitchOptIn);
    }

    /// <summary>
    /// D1: after the user installs/starts the SYSTEM helper out-of-band (the unprivileged
    /// UI can never do this itself), the "helper unavailable" banner's "Re-check" button
    /// must simply re-run the same status refresh the poll uses — proven here by asserting
    /// <c>GetStatus</c> was actually called after invoking <see cref="DashboardViewModel.RepairCommand"/>.
    /// </summary>
    [Fact]
    public async Task repair_command_triggers_a_status_refresh()
    {
        var helper = new FakeHelperClient();
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(false, false, false) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher());

        await vm.RepairCommand.ExecuteAsync(null);

        Assert.True(helper.GetStatusCalls > 0);
    }

    [Fact]
    public async Task repair_command_is_ignored_while_a_command_is_in_flight()
    {
        var helper = new FakeHelperClient();
        var gate = new TaskCompletionSource<Result<ProtectionResponse>?>();
        helper.EnableHandler = (_, _) => gate.Task;
        var stateReader = new FakeStateReader { Intent = new ProtectionIntent(false, false, false) };
        var vm = MakeSut(helper, stateReader, new FakeResolverReader(), new SynchronousDispatcher());

        var toggleTask = vm.ToggleProtectionCommand.ExecuteAsync(null);

        await vm.RepairCommand.ExecuteAsync(null);

        Assert.Equal(0, helper.GetStatusCalls); // ignored: the toggle still owns _inFlight

        gate.SetResult(Result<ProtectionResponse>.Ok(new ProtectionResponse(true, false, true, false, null)));
        await toggleTask;
    }
    // ---- 5h: Active-Resolver panel detail lookup (cached lists, name-change driven) ----

    private static ServerStamp Stamp(StampProtocol protocol, ulong props, string? ip, int port, string? hostname) =>
        new(protocol, props, ip, port, null, protocol == StampProtocol.DnsCrypt ? "2.dnscrypt-cert.test" : null,
            Array.Empty<byte[]>(), hostname, hostname is null ? null : "/dns-query", Array.Empty<string>(), false);

    private static ResolverListSnapshot ListSnapshot(params ResolverListEntry[] entries) =>
        new("public-resolvers", "", ResolverListState.Fresh, null,
            new ResolverListParseResult(entries, Array.Empty<string>(), null, false, false));

    private static ResolverListEntry ListEntry(string name, string description, params ServerStamp[] stamps) =>
        new(name, name, description, Array.Empty<string>(), stamps,
            Array.Empty<StampParseError>(), true, Array.Empty<string>());

    [Fact]
    public void active_resolver_details_populate_from_the_cached_list_on_name_change()
    {
        var listReader = new FakeListReader
        {
            Snapshots = new[]
            {
                ListSnapshot(ListEntry("a-and-a", "Cloudflare DNS (anycast)",
                    Stamp(StampProtocol.DoH, 0b111, "1.1.1.1", 443, "cloudflare-dns.com"))),
            },
        };
        var vm = MakeSut(new FakeHelperClient(), new FakeStateReader(), new FakeResolverReader(),
            new SynchronousDispatcher(), listReader);

        vm.ActiveResolverName = "a-and-a";

        Assert.Equal("DoH", vm.ActiveResolverProtocol);
        Assert.Equal("1.1.1.1:443", vm.ActiveResolverAddress);
        Assert.Equal("Anycast", vm.ActiveResolverLocation);
        Assert.Equal(new[] { "DNSSEC", "No log", "No filter" }, vm.ActiveResolverProperties);
    }

    [Fact]
    public void active_resolver_details_clear_for_unknown_and_null_names()
    {
        var listReader = new FakeListReader
        {
            Snapshots = new[]
            {
                ListSnapshot(ListEntry("known", "Germany",
                    Stamp(StampProtocol.DnsCrypt, 0b010, "9.9.9.9", 8443, null))),
            },
        };
        var vm = MakeSut(new FakeHelperClient(), new FakeStateReader(), new FakeResolverReader(),
            new SynchronousDispatcher(), listReader);

        vm.ActiveResolverName = "known";
        Assert.Equal("DNSCrypt", vm.ActiveResolverProtocol);
        Assert.Equal(new[] { "No log" }, vm.ActiveResolverProperties);

        vm.ActiveResolverName = "missing-from-lists";
        Assert.Null(vm.ActiveResolverProtocol);
        Assert.Null(vm.ActiveResolverAddress);
        Assert.Null(vm.ActiveResolverLocation);
        Assert.Empty(vm.ActiveResolverProperties);

        vm.ActiveResolverName = null;
        Assert.Null(vm.ActiveResolverProtocol);
        Assert.Empty(vm.ActiveResolverProperties);
    }

    [Fact]
    public void active_resolver_lookup_skips_relays_and_runs_only_on_a_name_CHANGE()
    {
        var listReader = new FakeListReader
        {
            Snapshots = new[]
            {
                // A relay entry with the SAME name must never satisfy the lookup.
                ListSnapshot(
                    ListEntry("anon-x", "a relay", Stamp(StampProtocol.DnsCryptRelay, 0, "5.5.5.5", 443, null)),
                    ListEntry("resolver-x", "United States", Stamp(StampProtocol.DoH, 0b001, "2620:fe::fe", 443, "dns.test"))),
            },
        };
        var vm = MakeSut(new FakeHelperClient(), new FakeStateReader(), new FakeResolverReader(),
            new SynchronousDispatcher(), listReader);

        vm.ActiveResolverName = "anon-x";
        Assert.Null(vm.ActiveResolverProtocol); // relay skipped -> honestly unknown

        vm.ActiveResolverName = "resolver-x";
        Assert.Equal("DoH", vm.ActiveResolverProtocol);
        Assert.Equal("[2620:fe::fe]:443", vm.ActiveResolverAddress); // IPv6 re-bracketed
        Assert.Equal("United States", vm.ActiveResolverLocation);

        var callsAfterTwoChanges = listReader.ReadAllCalls;
        vm.ActiveResolverName = "resolver-x"; // SAME value: generated setter skips -> no disk read
        Assert.Equal(callsAfterTwoChanges, listReader.ReadAllCalls);
    }

    // ---- 5h hero copy (headline/subtitle honesty) ----

    [Fact]
    public void hero_headline_and_subtitle_follow_status_and_resolver()
    {
        var vm = MakeSut(new FakeHelperClient(), new FakeStateReader(), new FakeResolverReader(),
            new SynchronousDispatcher());

        Assert.Equal("Not protected", vm.HeroHeadline);
        Assert.Contains("normal Windows DNS", vm.HeroSubtitle, StringComparison.Ordinal);

        vm.Status = ProtectionStatusView.ProtectedVerified;
        vm.ActiveResolverName = "a-and-a";
        Assert.Equal("You're protected", vm.HeroHeadline);
        Assert.Contains("via a-and-a", vm.HeroSubtitle, StringComparison.Ordinal);

        vm.Status = ProtectionStatusView.HelperUnavailable;
        Assert.Equal("Helper unavailable", vm.HeroHeadline);
    }

}
