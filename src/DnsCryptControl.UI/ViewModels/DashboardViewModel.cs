using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Platform.Diagnostics;
using DnsCryptControl.UI.Models;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.ViewModels;

/// <summary>
/// The Dashboard's view-model — the master protection toggle, the truthful
/// (diagnostics-verified) status, and marshalled polling (§7.1/§7.4). This is the heart
/// of Phase 5a: a false green "Protected" badge is the worst possible failure for this
/// OPSEC tool, so <see cref="ProtectionStatusView.ProtectedVerified"/> is only ever set
/// after a <c>RunDiagnostics</c> pass proves no leak.
///
/// <para>PURE POCO <see cref="ObservableObject"/> — zero WPF type references. Every
/// observable-property write that happens after an awaited helper/disk call (i.e. on a
/// continuation that may resume off the UI thread) goes through the injected
/// <see cref="IUiDispatcher"/>, never directly.</para>
///
/// <para><b>One "busy" owner:</b> the VM-owned <c>_inFlight</c> flag is the sole gate for
/// both the toggle/restart/flush commands and the poll loop (a tick is skipped while
/// <c>_inFlight</c> is set). <see cref="IHelperClient"/>'s internal semaphore is purely
/// frame-integrity for concurrent pipe callers — this VM never inspects it.</para>
///
/// <para><b>Converge-on-lost-reply:</b> a <c>null</c> result from a mutating helper call
/// (broken pipe / timeout / untrusted owner) is NEVER treated as failure-therefore-roll-
/// back and NEVER answered with the opposite verb. Instead the VM reconciles: it re-reads
/// disk intent + runs diagnostics to observe the REAL state, and only if the observed
/// state disagrees with the target does it re-issue the SAME idempotent verb once.</para>
/// </summary>
public partial class DashboardViewModel : ObservableObject, IDisposable
{
    private static readonly TimeSpan DefaultPollInterval = TimeSpan.FromSeconds(1.5);

    private readonly IHelperClient _helper;
    private readonly IProtectionStateReader _stateReader;
    private readonly IActiveResolverReader _resolverReader;
    private readonly IResolverListReader _listReader;
    private readonly IUiDispatcher _ui;
    private readonly IQueryLogSession _querySession;
    private readonly IUiStateStore _uiStateStore;
    private readonly TimeSpan _pollInterval;

    private bool _inFlight;
    private bool _killSwitchSeeded;
    private PeriodicTimer? _pollTimer;
    private Task? _pollLoop;
    private CancellationTokenSource? _pollCts;
    private readonly SemaphoreSlim _refreshGate = new(1, 1);

    /// <summary>5j warm-up: when protection was FIRST OBSERVED on this session (VM clock), null when off.
    /// Stamped once in RefreshAsync's verdict (covers the toggle, reboot/relaunch, and enabled-out-of-band
    /// paths alike), cleared when protection is observed off. Drives the bounded "Verifying…" cold-start
    /// window so the transient first-self-check failure (proxy still bootstrapping) isn't shown as a leak.</summary>
    private DateTimeOffset? _protectionEnabledAt;

    /// <summary>5j warm-up: set the first time diagnostics verify no-leak this session. Once true, a
    /// later failure is a REAL fault and is never re-softened to "Verifying…". Reset when off.</summary>
    private bool _verifiedThisSession;

    /// <summary>Injectable clock so the warm-up window is deterministically testable (mirrors the
    /// pollInterval seam). Defaults to <see cref="DateTimeOffset.UtcNow"/>.</summary>
    private readonly Func<DateTimeOffset> _clock;

    /// <summary>The cold-start window — longer than the proxy bootstrap, shorter than a "something is
    /// actually wrong" threshold. Past this, the real verdict (green or PartiallyProtected) is shown.</summary>
    private const double WarmUpSeconds = 12;

    [ObservableProperty]
    private ProtectionStatusView _status;

    [ObservableProperty]
    private bool _isProtected;

    [ObservableProperty]
    private bool _killSwitchOptIn;

    [ObservableProperty]
    private bool _rebootRecommended;

    [ObservableProperty]
    private string? _activeResolverName;

    /// <summary>5h Active-Resolver panel details, looked up from the proxy's CACHED resolver
    /// lists (read off disk — the same split-privilege read path as the Resolvers tab) whenever
    /// the active resolver NAME changes. Null/empty when the name is unknown or not in any list;
    /// the panel collapses those rows rather than guessing. First-stamp facts, matching the
    /// Resolvers tab's own badges.</summary>
    [ObservableProperty]
    private string? _activeResolverProtocol;

    [ObservableProperty]
    private string? _activeResolverAddress;

    [ObservableProperty]
    private string? _activeResolverLocation;

    [ObservableProperty]
    private IReadOnlyList<string> _activeResolverProperties = Array.Empty<string>();

    [ObservableProperty]
    private string? _advisory;

    [ObservableProperty]
    private bool _proxyRunning;

    [ObservableProperty]
    private bool _killSwitchEnabled;

    [ObservableProperty]
    private bool _leakMitigationsEnabled;

    /// <summary>Whether browsers' built-in DoH is currently disabled by policy (Phase 5f). Derived from
    /// the SAME diagnostics snapshot the badge uses — never a second source (5e-VM-1 discipline).</summary>
    [ObservableProperty]
    private bool _browserDohEnabled;

    /// <summary>True only when <see cref="BrowserDohEnabled"/> reflects a LIVE diagnostics reading
    /// (protection on + diagnostics succeeded). Browser-DoH state is observable ONLY via diagnostics,
    /// which run only while protected — so when this is false the toggle is honestly "unknown" (shown
    /// disabled) rather than asserting a stale value.</summary>
    [ObservableProperty]
    private bool _browserDohStateKnown;

    // --- Phase 5i: live query KPIs + recent activity, read from the shared per-session query-log session.
    //     Populated while logging is on; revert to the off-prompt (and RecentQueries clears) the instant
    //     logging is turned off — query-derived data is shown ONLY while logging is explicitly on.
    private const string QueryOffPrompt = "Shown once query logging is on — turn it on in the Query Monitor tab.";
    private const int MaxRecentQueries = 5;

    /// <summary>True while query logging is on — gates whether the KPI cards + Live Activity show live
    /// values or the off-prompt.</summary>
    [ObservableProperty]
    private bool _loggingActive;

    [ObservableProperty]
    private string _queriesValue = QueryOffPrompt;

    [ObservableProperty]
    private string _blockedValue = QueryOffPrompt;

    [ObservableProperty]
    private string _avgLatencyValue = QueryOffPrompt;

    [ObservableProperty]
    private string _answeredLocallyValue = QueryOffPrompt;

    /// <summary>The most recent queries (newest first) shown in the Live Activity card while logging is
    /// on. Cleared on off — never persisted, never shown when logging is off.</summary>
    public ObservableCollection<QueryRowViewModel> RecentQueries { get; } = new();

    /// <param name="pollInterval">
    /// The poll-loop tick interval; defaults to ~1.5s. Exposed only so tests can inject a
    /// short, deterministic interval instead of depending on wall-clock timing.
    /// </param>
    /// <param name="clock">
    /// Injectable UTC clock for the warm-up window; defaults to <see cref="DateTimeOffset.UtcNow"/>.
    /// Exposed only so tests can control the cold-start "Verifying…" boundary deterministically.
    /// </param>
    public DashboardViewModel(
        IHelperClient helper,
        IProtectionStateReader stateReader,
        IActiveResolverReader resolverReader,
        IResolverListReader listReader,
        IUiDispatcher ui,
        IQueryLogSession querySession,
        IUiStateStore uiStateStore,
        TimeSpan? pollInterval = null,
        Func<DateTimeOffset>? clock = null)
    {
        ArgumentNullException.ThrowIfNull(helper);
        ArgumentNullException.ThrowIfNull(stateReader);
        ArgumentNullException.ThrowIfNull(resolverReader);
        ArgumentNullException.ThrowIfNull(listReader);
        ArgumentNullException.ThrowIfNull(ui);
        ArgumentNullException.ThrowIfNull(querySession);
        ArgumentNullException.ThrowIfNull(uiStateStore);
        _helper = helper;
        _stateReader = stateReader;
        _resolverReader = resolverReader;
        _listReader = listReader;
        _ui = ui;
        _querySession = querySession;
        _uiStateStore = uiStateStore;
        // Seed the kill-switch opt-in from the persisted preference (recommended default = on) so a fresh
        // install is fail-closed on the first Protect. Set the backing field directly: no change
        // notification, no write — OnKillSwitchOptInChanged persistence is for the user's own edits.
        _killSwitchOptIn = _uiStateStore.Load().KillSwitchOptIn;
        _pollInterval = pollInterval ?? DefaultPollInterval;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);

        // Phase 5i: reflect the shared per-session query log on the Dashboard. Subscribe first, then
        // publish the current (off) state so the KPI cards + Live Activity start in the off-prompt.
        _querySession.Changed += OnQuerySessionChanged;
        UpdateQueryKpis();
    }

    [RelayCommand]
    private async Task ToggleProtectionAsync(CancellationToken ct)
    {
        if (_inFlight)
        {
            return; // ignore re-entry / a mid-flight opposite click
        }

        _inFlight = true;
        _ui.Post(() => Status = ProtectionStatusView.Applying);
        try
        {
            var turningOn = !IsProtected;
            var killSwitchOptIn = KillSwitchOptIn;

            var result = turningOn
                ? await _helper.EnableProtectionAsync(killSwitchOptIn, ct).ConfigureAwait(false)
                : await _helper.DisableProtectionAsync(ct).ConfigureAwait(false);

            if (result is null)
            {
                await ReconcileAfterLostReplyAsync(turningOn, killSwitchOptIn, ct).ConfigureAwait(false);
                return;
            }

            if (result.Success)
            {
                _ui.Post(() =>
                {
                    Advisory = result.Value!.KillSwitchAdvisory;
                    RebootRecommended = result.Value!.RebootRecommended;
                });
            }
            // Whether success or failure, RefreshAsync recomputes the truthful status —
            // never assume green here; a failure must never be shown as protected.
            await RefreshAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _inFlight = false;
        }
    }

    /// <summary>
    /// A lost reply to a mutating call is NOT failure — it is UNKNOWN. Re-read the
    /// on-disk intent and run diagnostics to observe the real state; only re-issue the
    /// SAME verb (idempotent) if the observed state still disagrees with the target.
    /// Never calls the opposite verb (no blind rollback).
    /// </summary>
    private async Task ReconcileAfterLostReplyAsync(bool targetOn, bool killSwitchOptIn, CancellationToken ct)
    {
        var intent = _stateReader.Read();
        var diagnostics = await _helper.RunDiagnosticsAsync(ct).ConfigureAwait(false);

        var observedOn = intent.ProtectionEnabled && IsNoLeakVerified(diagnostics);

        if (observedOn != targetOn)
        {
            _ = targetOn
                ? await _helper.EnableProtectionAsync(killSwitchOptIn, ct).ConfigureAwait(false)
                : await _helper.DisableProtectionAsync(ct).ConfigureAwait(false);
        }

        await RefreshAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Phase 5f: disable or restore browsers' built-in DoH. Mirrors the master toggle's discipline —
    /// guarded by the same <c>_inFlight</c> lock, fires the intent then RECONCILES the shown state from
    /// diagnostics (never an optimistic flip), and treats a null reply as UNKNOWN (RefreshAsync re-reads
    /// the real state from the same single source the badge uses).
    /// </summary>
    [RelayCommand]
    private async Task ToggleBrowserDohAsync(CancellationToken ct)
    {
        if (_inFlight)
        {
            return; // ignore re-entry while another command / the poll owns the in-flight lock
        }

        _inFlight = true;
        try
        {
            var enable = !BrowserDohEnabled;
            await _helper.SetBrowserDohPolicyAsync(enable, ct).ConfigureAwait(false);
            // Reconcile the shown state from diagnostics regardless of the reply (null == UNKNOWN,
            // never an assumed flip). RefreshAsync updates BrowserDohEnabled only from a live reading.
            await RefreshAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _inFlight = false;
        }
    }

    [RelayCommand]
    private async Task RestartAsync(CancellationToken ct)
    {
        if (_inFlight)
        {
            return;
        }

        _inFlight = true;
        // 5j: a manual proxy Restart is a KNOWN cold-start — re-arm the warm-up window (on the UI thread,
        // with the poll gated off via _inFlight) so the transient loopback-self-check failure while the
        // proxy comes back shows "Verifying…" rather than the alarming "Partially protected — leak
        // detected". Clearing to null lets RefreshAsync's single stamp re-arm it fresh (same channel).
        _protectionEnabledAt = null;
        _verifiedThisSession = false;
        try
        {
            await _helper.RestartProxyAsync(ct).ConfigureAwait(false);
            await RefreshAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _inFlight = false;
        }
    }

    [RelayCommand]
    private async Task FlushAsync(CancellationToken ct)
    {
        if (_inFlight)
        {
            return;
        }

        _inFlight = true;
        try
        {
            await _helper.FlushDnsCacheAsync(ct).ConfigureAwait(false);
            await RefreshAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _inFlight = false;
        }
    }

    /// <summary>
    /// D1: the "helper unavailable" banner's "Re-check" action. The unprivileged UI can
    /// never install/start the SYSTEM helper itself (that requires an elevated, out-of-band
    /// step — the dev-install script in <c>tools/dev-install/Install-Helper.ps1</c> for a
    /// throwaway VM, or the Phase-6 installer in production). So "Repair" here means
    /// re-check, not self-install: after the user has installed/started the helper
    /// out-of-band, this simply re-runs the same status refresh the poll uses so the
    /// banner clears as soon as the helper responds. Guarded by the same <c>_inFlight</c>
    /// lock as every other command so it never races the poll loop or another command.
    /// </summary>
    [RelayCommand]
    private async Task RepairAsync(CancellationToken ct)
    {
        if (_inFlight)
        {
            return;
        }

        _inFlight = true;
        try
        {
            await RefreshAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _inFlight = false;
        }
    }

    /// <summary>
    /// Recomputes every observable from the ground truth: (a) toggle position off disk
    /// (authoritative even when the helper is down), (b) <c>GetStatus</c> sub-indicators,
    /// (c) the active-resolver display name, and (d) — only when protection is
    /// on-by-intent — a <c>RunDiagnostics</c> pass that is the ONLY path to the green
    /// <see cref="ProtectionStatusView.ProtectedVerified"/> badge.
    ///
    /// <para>Wrapped in <see cref="_refreshGate"/> so a poll-tick refresh and a
    /// command-triggered refresh (toggle/restart/flush/repair) can never run concurrently —
    /// <c>_inFlight</c> alone is only a point-in-time skip check on the poll loop and cannot
    /// prevent an in-progress poll from interleaving with a just-started command. The gate
    /// wait itself intentionally uses <see cref="CancellationToken.None"/>, not
    /// <paramref name="ct"/>: <paramref name="ct"/> is the per-command-invocation token that
    /// <c>[RelayCommand]</c>'s generated <c>AsyncRelayCommand</c> cancels whenever the SAME
    /// command is invoked again (even though <c>_inFlight</c> already makes that second
    /// invocation's body a no-op) — the gate's only job is mutual exclusion between
    /// refreshes, so it must not abort mid-wait just because an unrelated re-invocation of
    /// the calling command cancelled its own token. <paramref name="ct"/> is still honored
    /// for the actual awaited helper/IO calls below.</para>
    /// </summary>
    public async Task RefreshAsync(CancellationToken ct)
    {
        await _refreshGate.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        try
        {
            var intent = _stateReader.Read();
            var isProtected = intent.ProtectionEnabled;
            _ui.Post(() => IsProtected = isProtected);

            var status = await _helper.GetStatusAsync(ct).ConfigureAwait(false);
            if (status is null || !status.Success)
            {
                _ui.Post(() =>
                {
                    Status = ProtectionStatusView.HelperUnavailable;
                    BrowserDohStateKnown = false; // helper down → browser-DoH state unknown
                });
                return;
            }

            var statusValue = status.Value!;

            // F20 version handshake: a helper on a different protocol version cannot be
            // trusted for ANY other field in this response, so this is a hard stop —
            // never fall through to diagnostics, never reach ProtectedVerified.
            if (statusValue.ProtocolVersion != IpcProtocol.Version)
            {
                _ui.Post(() =>
                {
                    Status = ProtectionStatusView.HelperIncompatible;
                    BrowserDohStateKnown = false; // can't trust any field from an incompatible helper
                });
                return;
            }

            _ui.Post(() =>
            {
                ProxyRunning = statusValue.ProxyRunning;
                KillSwitchEnabled = statusValue.KillSwitchEnabled;
                LeakMitigationsEnabled = statusValue.LeakMitigationsEnabled;
            });

            if (!_killSwitchSeeded)
            {
                // The opt-in was already seeded from the persisted preference in the ctor (recommended
                // default = on). Run once, on the first successful refresh: if the kill switch is
                // ACTUALLY armed right now (e.g. a relaunch while protected) but the toggle reads off,
                // force it ON so we never silently drop an active kill switch on the next off->on toggle.
                // Only ever strengthens to ON here — the stored pref already carries any explicit OFF.
                _killSwitchSeeded = true;
                if (statusValue.KillSwitchEnabled && !KillSwitchOptIn)
                    _ui.Post(() => KillSwitchOptIn = true);
            }

            var resolverName = _resolverReader.ReadPrimaryName();
            _ui.Post(() => ActiveResolverName = resolverName);

            if (!isProtected)
            {
                _ui.Post(() =>
                {
                    _protectionEnabledAt = null;   // 5j: clear the warm-up window when protection is off
                    _verifiedThisSession = false;
                    Status = ProtectionStatusView.Unprotected;
                    BrowserDohStateKnown = false; // diagnostics only run when protected → state unknown
                });
                return;
            }

            // Protected by intent, but the proxy SERVICE is down (this same trusted status frame says so).
            // Show the honest "the DNS proxy isn't running" state instead of running diagnostics that would
            // report PartiallyProtected ("leak detected") — which is misleading, since a stopped proxy is
            // fail-closed (DNS points at a dead loopback listener; nothing leaks out). Clear the warm-up
            // fields so a later recovery re-arms the cold-start window rather than snapping to a verdict.
            if (!statusValue.ProxyRunning)
            {
                _ui.Post(() =>
                {
                    _protectionEnabledAt = null;
                    _verifiedThisSession = false;
                    Status = ProtectionStatusView.ProxyStopped;
                    BrowserDohStateKnown = false; // diagnostics not run → browser-DoH state unknown
                });
                return;
            }

            var diagnostics = await _helper.RunDiagnosticsAsync(ct).ConfigureAwait(false);
            if (diagnostics is null || !diagnostics.Success)
            {
                // The GetStatus frame above already proved the helper REACHABLE and the proxy RUNNING. A
                // null/!Success RunDiagnostics means "couldn't complete the DNS self-check this cycle" (probe
                // threw, or the call was starved) — NOT "the helper is gone". Show an honest amber
                // DiagnosticsUnavailable (retried by the ~1.5s poll) instead of HelperUnavailable, which would
                // raise the blocking banner and disable the controls — the exact deadlock where a broken route
                // (which makes the self-check fail) would lock the user out of fixing it. The genuine
                // "helper unreachable" signal still fires ONLY from the GetStatusAsync failure branch above.
                _ui.Post(() =>
                {
                    if (_protectionEnabledAt is null && !_verifiedThisSession)
                        _protectionEnabledAt = _clock();
                    Status = IsWarmingUp(diagnostics)   // false when the snapshot is null (this branch) — no NRE
                        ? ProtectionStatusView.Verifying
                        : ProtectionStatusView.DiagnosticsUnavailable;
                    BrowserDohStateKnown = false;       // browser-DoH state is only observable via diagnostics
                });
                return;
            }

            var verified = IsNoLeakVerified(diagnostics);
            var browserDoh = diagnostics.Value!.Hardening.BrowserDohPoliciesPresent;
            _ui.Post(() =>
            {
                // 5j: stamp the warm-up window on the FIRST observed protected state — covers the reboot /
                // relaunch / enabled-out-of-band paths too, not just the in-session toggle. Guarded so it
                // never re-arms mid-window or re-softens after a verified pass. This and the off-branch
                // reset are the ONLY writers, both on the UI thread via _ui.Post (RefreshAsync bodies are
                // serialized by _refreshGate), so no cross-thread reordering with the toggle is possible.
                if (_protectionEnabledAt is null && !_verifiedThisSession)
                    _protectionEnabledAt = _clock();

                // Three-way verdict:
                //   verified            → green (unchanged gate — no false-green possible)
                //   cold-start warm-up  → amber "Verifying…" (bounded, never green)
                //   otherwise           → the real "Partially protected — leak detected"
                ProtectionStatusView next;
                if (verified)
                {
                    next = ProtectionStatusView.ProtectedVerified;
                    _verifiedThisSession = true; // once verified, a later failure is a REAL fault
                }
                else if (IsWarmingUp(diagnostics))
                {
                    next = ProtectionStatusView.Verifying;
                }
                else
                {
                    next = ProtectionStatusView.PartiallyProtected;
                }

                Status = next;
                BrowserDohEnabled = browserDoh; // single source: the same snapshot the badge uses
                BrowserDohStateKnown = true;
            });
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    /// <summary>
    /// The exact no-leak signal for the green badge (§7.1): every up, non-loopback
    /// adapter's DNS points at loopback (<see cref="AdapterDnsCheck.AllLoopback"/>) AND
    /// the proxy actually answered a hand-built query sent straight to 127.0.0.1:53
    /// (<see cref="ActiveResolveCheck.ProxyAnswered"/> on <see cref="DiagnosticsSnapshot.ActiveResolve"/>).
    /// The IPv6 active-resolve probe is intentionally NOT required here — per its own
    /// doc comment it is policy-aware (Warn, not Fail, when IPv6 loopback is absent by
    /// design), so gating green on it would produce false negatives on IPv6-disabled
    /// machines. <see cref="DiagnosticsSnapshot.Overall"/> is not used directly because
    /// it also folds in <c>Hardening</c>/<c>Listeners</c> advisories that are not,
    /// themselves, DNS-leak signals.
    /// </summary>
    private static bool IsNoLeakVerified(Result<DiagnosticsSnapshot>? diagnostics)
    {
        if (diagnostics is null || !diagnostics.Success || diagnostics.Value is null)
        {
            return false;
        }

        var snapshot = diagnostics.Value;
        return snapshot.AdapterDns.AllLoopback && snapshot.ActiveResolve.ProxyAnswered;
    }

    /// <summary>
    /// 5j cold-start gate: true only when protection was JUST enabled (within <see cref="WarmUpSeconds"/>),
    /// has NOT yet verified this session, adapters ARE already pinned to loopback, but the proxy hasn't
    /// answered its first self-check yet — i.e. "warming up", not leaking. Three independent fall-throughs
    /// guarantee this is strictly transient and can NEVER mask a real leak: already-verified, window
    /// elapsed, or adapters-not-all-loopback each return false (→ the real PartiallyProtected verdict).
    /// Green is unaffected — it still requires the full <see cref="IsNoLeakVerified"/> pass — so a genuine
    /// leak is never softened and protected is never falsely claimed. Called only on the UI thread.
    /// </summary>
    private bool IsWarmingUp(Result<DiagnosticsSnapshot>? diagnostics)
    {
        if (_verifiedThisSession) return false;                                  // once green, a later fail is REAL
        if (_protectionEnabledAt is not { } enabledAt) return false;             // no fresh enable → not warm-up
        if ((_clock() - enabledAt).TotalSeconds > WarmUpSeconds) return false;   // window elapsed → real verdict
        if (diagnostics?.Value is not { } snapshot) return false;
        return snapshot.AdapterDns.AllLoopback && !snapshot.ActiveResolve.ProxyAnswered; // pinned, not answering yet
    }

    /// <summary>
    /// Starts a self-pacing ~1.5s poll loop calling <see cref="RefreshAsync"/>, skipping
    /// any tick that lands while a command is in flight (the toggle/restart/flush
    /// commands own <c>_inFlight</c>). Idempotent — a second call while already polling
    /// is a no-op.
    /// </summary>
    public void StartPolling()
    {
        if (_pollCts is not null)
        {
            return; // already polling — guard on _pollCts (not _pollLoop) so a fast
                    // tab-switch StopPolling/StartPolling pair can never leave two loops
                    // running: StopPolling nulls _pollCts synchronously without awaiting
                    // the loop task, so _pollCts is the only reliable "am I polling" guard.
        }

        _pollCts = new CancellationTokenSource();
        _pollTimer = new PeriodicTimer(_pollInterval);
        _pollLoop = RunPollLoopAsync(_pollTimer, _pollCts.Token);
    }

    private async Task RunPollLoopAsync(PeriodicTimer timer, CancellationToken ct)
    {
        try
        {
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
            {
                if (_inFlight)
                {
                    continue; // skip this tick; a command owns the in-flight lock
                }

                try
                {
                    await RefreshAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw; // cancellation must still break the loop; rethrow to the outer catch
                }
                catch (Exception)
                {
                    // A stale status surface is a safety concern for this OPSEC tool, so one
                    // bad tick (e.g. a transient pipe fault) must never permanently kill the
                    // fire-and-forget poll loop — swallow and let the next tick try again.
                    // CA1031 is suppressed for this file only; see .editorconfig.
                }
            }
        }
        catch (OperationCanceledException)
        {
            // expected on StopPolling
        }
    }

    /// <summary>5h hero headline — the big status line on the Dashboard banner. Same honesty
    /// discipline as the badge words: "You're protected" is reserved for the diagnostics-verified
    /// state; every other state says exactly what is (not) known.</summary>
    public string HeroHeadline => Status switch
    {
        ProtectionStatusView.ProtectedVerified => "You're protected",
        ProtectionStatusView.Applying => "Applying…",
        ProtectionStatusView.Verifying => "Verifying protection…",
        ProtectionStatusView.PartiallyProtected => "Partially protected — leak detected",
        ProtectionStatusView.ProxyStopped => "Protection incomplete — the DNS proxy isn't running",
        ProtectionStatusView.DiagnosticsUnavailable => "Protected — verifying DNS…",
        ProtectionStatusView.HelperUnavailable => "Helper unavailable",
        ProtectionStatusView.HelperIncompatible => "Helper version incompatible",
        ProtectionStatusView.Unprotected => "Not protected",
        _ => "Status unknown",
    };

    /// <summary>5h hero subtitle — one plain-language sentence under the headline.</summary>
    public string HeroSubtitle => Status switch
    {
        ProtectionStatusView.ProtectedVerified when ActiveResolverName is { Length: > 0 } name =>
            "Service running — encrypted DNS via " + name + ", verified by live diagnostics.",
        ProtectionStatusView.ProtectedVerified =>
            "Service running — encrypted DNS, verified by live diagnostics.",
        ProtectionStatusView.Applying =>
            "Hold on — protection is being applied.",
        ProtectionStatusView.Verifying =>
            "Protection is on — running a quick leak check to confirm your DNS is fully covered.",
        ProtectionStatusView.PartiallyProtected =>
            "The proxy is running, but a leak check failed — some DNS may be bypassing it.",
        ProtectionStatusView.ProxyStopped =>
            "Your DNS is pointed at the local proxy, but the proxy service is stopped — click Restart service to bring it back.",
        ProtectionStatusView.DiagnosticsUnavailable =>
            "Protection is on and the proxy is running, but the DNS self-check didn't complete this cycle — retrying automatically. If it persists, your resolver/relay may not be answering; check Logs & Diagnostics.",
        ProtectionStatusView.HelperUnavailable =>
            "The background helper service isn't reachable, so nothing can be changed from here.",
        ProtectionStatusView.HelperIncompatible =>
            "The app and its helper service are different versions — reinstall so they match.",
        ProtectionStatusView.Unprotected =>
            "This device is using normal Windows DNS. Turn the main switch on to protect it.",
        _ => "The protection state could not be determined.",
    };

    partial void OnStatusChanged(ProtectionStatusView value)
    {
        OnPropertyChanged(nameof(HeroHeadline));
        OnPropertyChanged(nameof(HeroSubtitle));
    }

    partial void OnActiveResolverNameChanged(string? value)
    {
        OnPropertyChanged(nameof(HeroSubtitle));
        RefreshActiveResolverDetails(value);
    }

    /// <summary>Persist the kill-switch opt-in as a per-user preference (default on) so the choice
    /// survives relaunch. Load-modify-Save so a concurrent write from another view-model's UiState copy
    /// isn't clobbered; the store swallows write failures (non-critical prefs).</summary>
    partial void OnKillSwitchOptInChanged(bool value)
    {
        var state = _uiStateStore.Load();
        if (state.KillSwitchOptIn == value)
        {
            return;
        }

        state.KillSwitchOptIn = value;
        _uiStateStore.Save(state);
    }

    /// <summary>Disk lookup runs ONLY on a name CHANGE (the generated setter skips equal
    /// values), never on every poll tick.</summary>
    private void RefreshActiveResolverDetails(string? name)
    {
        string? protocol = null, address = null, location = null;
        IReadOnlyList<string> properties = Array.Empty<string>();
        if (!string.IsNullOrEmpty(name))
        {
            try
            {
                foreach (var snapshot in _listReader.ReadAll())
                {
                    foreach (var entry in snapshot.Entries)
                    {
                        if (entry.IsRelay || entry.Stamps.Count == 0) continue;
                        if (!string.Equals(entry.Name, name, StringComparison.Ordinal)) continue;
                        var stamp = entry.Stamps[0];
                        protocol = ResolverDisplay.ProtocolChip(stamp.Protocol);
                        address = ResolverDisplay.Endpoint(stamp);
                        location = ResolverDisplay.GuessLocation(entry.Description);
                        var props = new List<string>(3);
                        if (stamp.Dnssec) props.Add("DNSSEC");
                        if (stamp.NoLog) props.Add("No log");
                        if (stamp.NoFilter) props.Add("No filter");
                        properties = props;
                        break;
                    }
                    if (protocol is not null) break;
                }
            }
            catch (Exception)
            {
                // Fail closed to "unknown" — the reader is documented never to throw, but a
                // display lookup must never take the Dashboard down.
                protocol = null; address = null; location = null;
                properties = Array.Empty<string>();
            }
        }

        ActiveResolverProtocol = protocol;
        ActiveResolverAddress = address;
        ActiveResolverLocation = location;
        ActiveResolverProperties = properties;
    }

    // --- Phase 5i: Dashboard reflects the shared per-session query-log session ---

    private void OnQuerySessionChanged(object? sender, EventArgs e) => _ui.Post(UpdateQueryKpis);

    /// <summary>Re-reads the shared session and publishes the KPI card values + recent queries. When
    /// logging is off, every card shows the off-prompt and the recent list is cleared — the Dashboard
    /// never shows query-derived data while logging is off. Always runs on the UI thread (ctor call +
    /// <see cref="OnQuerySessionChanged"/> posts through <see cref="_ui"/>).</summary>
    private void UpdateQueryKpis()
    {
        var active = _querySession.LoggingActive;
        LoggingActive = active;

        if (!active)
        {
            QueriesValue = QueryOffPrompt;
            BlockedValue = QueryOffPrompt;
            AvgLatencyValue = QueryOffPrompt;
            AnsweredLocallyValue = QueryOffPrompt;
            RecentQueries.Clear();
            return;
        }

        var s = _querySession.Stats;
        QueriesValue = s.Queries.ToString(CultureInfo.CurrentCulture);
        BlockedValue = s.Blocked.ToString(CultureInfo.CurrentCulture);
        AvgLatencyValue = s.UpstreamCount == 0
            ? "—"
            : string.Format(CultureInfo.CurrentCulture, "{0} ms", s.AvgUpstreamLatencyMs);
        AnsweredLocallyValue = string.Format(CultureInfo.CurrentCulture, "{0}%", s.AnsweredLocallyPercent);

        RecentQueries.Clear();
        foreach (var row in _querySession.RecentRows(MaxRecentQueries))
        {
            RecentQueries.Add(row);
        }
    }

    /// <summary>Cancels the poll loop and disposes the timer. Idempotent.</summary>
    public void StopPolling()
    {
        _pollCts?.Cancel();
        _pollTimer?.Dispose();
        _pollTimer = null;
        _pollLoop = null;
        _pollCts?.Dispose();
        _pollCts = null;
    }

    public void Dispose()
    {
        _querySession.Changed -= OnQuerySessionChanged;
        StopPolling();
        _refreshGate.Dispose();
        GC.SuppressFinalize(this);
    }
}
