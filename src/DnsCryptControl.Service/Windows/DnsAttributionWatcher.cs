using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using DnsCryptControl.Platform;

namespace DnsCryptControl.Service.Windows;

/// <summary>
/// Per-app DNS attribution capture (v1.3.0): a DEMAND-GATED real-time ETW subscription to
/// Microsoft-Windows-DNS-Client whose event 3006 ("query called") fires IN THE CALLING PROCESS's
/// context — so the event header's ProcessID is the real originating app, the datum the proxy's
/// query log structurally lacks (every query reaches it via the Windows DNS Client service as
/// 127.0.0.1). Runs in the LocalSystem helper because SYSTEM has ETW real-time consume rights.
///
/// PRIVACY INVARIANTS (the reason this class is shaped the way it is):
///  - The captured stream IS browsing history. It lives ONLY in the bounded in-memory
///    <see cref="DnsAttributionRing"/> — never on disk, never in a log — and capture AND
///    retention end with the session: every teardown (idle stop, host shutdown, dispose)
///    <see cref="DnsAttributionRing.Clear"/>s the ring, so nothing captured for one consented
///    polling window can be replayed to the NEXT session's <c>GetSince(0)</c> (which may be a
///    different user's).
///  - The subscription must NOT run when nobody is reading: <see cref="GetSince"/> doubles as the
///    demand signal (Touch), starting the session on first poll, and an idle timer STOPS it after
///    <see cref="IdleStopAfter"/> without polls. The UI only polls while the user has consented to
///    query logging, so machine-wide DNS observation runs exactly for the consented window.
///  - Process names are resolved AT CAPTURE (PIDs are reused — a later lookup could name the
///    wrong process), memoized per-PID in a small bounded cache that is cleared with the session
///    and whose entries are re-resolved past <see cref="NameCacheMaxAge"/>, so a recycled PID can
///    inherit a dead process's name for at most that long.
///
/// LIFECYCLE DISCIPLINE (mirrors <see cref="NetworkChangeWatcher"/>, the in-repo template for a
/// long-lived native watcher): <c>Source.Process()</c> BLOCKS, so it runs on a dedicated
/// background thread; teardown stops+disposes the session UNDER the lock (see
/// <see cref="StopSession"/> — the session name is machine-global, so an out-of-lock stop races a
/// concurrent restart) and joins the thread OUTSIDE it; the ETW callback
/// never lets an exception escape (a throw across the ETW dispatch would take down the SYSTEM
/// helper) — faults are swallowed and counted. <see cref="IHostedService.StartAsync"/> is
/// deliberately a no-op: registration is for DETERMINISTIC SHUTDOWN ordering only, the session
/// itself starts on demand. Test seam: the <c>startEtw: false</c> ctor (like NetworkChangeWatcher's
/// <c>registerNativeWatches</c>) exercises the gating + ring logic headlessly; the ETW arm itself
/// is not unit-tested.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class DnsAttributionWatcher : IHostedService, IDisposable, IDnsAttributionSource
{
    /// <summary>How often the idle timer re-checks the last-poll age (coarse on purpose — the
    /// stop deadline only needs ~5 s resolution, not precision).</summary>
    private static readonly TimeSpan IdleCheckPeriod = TimeSpan.FromSeconds(5);

    /// <summary>Stop the ETW session after this long without a <see cref="GetSince"/> poll. The
    /// UI polls every ~750 ms while query logging is on, so 15 s of silence means the consumer is
    /// gone (logging stopped, tab torn down, or the UI exited) — capture must not outlive it.</summary>
    internal static readonly TimeSpan IdleStopAfter = TimeSpan.FromSeconds(15);

    // A FIXED session name so a crashed helper's orphaned session is taken over (TraceEventSession
    // stops a same-named existing session on create) instead of leaking a second collector.
    private const string SessionName = "DnsCryptControl-DnsAttribution";
    private const string DnsClientProviderName = "Microsoft-Windows-DNS-Client";

    // Event 3006 = "query called", raised in the calling process's context (header PID = the app).
    private const int QueryCalledEventId = 3006;

    // Ring cap (bounded memory regardless of query volume; ~2.7 min of history at 12.5 q/s) and
    // the per-PID name-memo cap (cleared wholesale when full — crude, but bounded and short-lived).
    private const int RingCapacity = 2048;
    private const int NameCacheCapacity = 256;

    /// <summary>How long a memoized PID→name entry is trusted before a hit re-resolves it. Windows
    /// recycles PIDs, so a memo with no age would let a recycled PID wear the DEAD process's name
    /// for the rest of the session — 30 s bounds that mislabeling window while still amortizing the
    /// per-event OS lookup (matches the UI correlator's 30 s attribution retention).</summary>
    internal static readonly TimeSpan NameCacheMaxAge = TimeSpan.FromSeconds(30);

    private readonly DnsAttributionRing _ring = new(RingCapacity);
    private readonly ILogger<DnsAttributionWatcher> _logger;
    private readonly bool _startEtw;
    private readonly Func<DateTimeOffset> _clock;
    private readonly object _gate = new();
    private readonly object _nameCacheGate = new();
    private readonly Dictionary<int, CachedName> _nameCache = new();

    private DateTimeOffset _lastPoll;
    private bool _sessionRequested;
    private TraceEventSession? _session;
    private Thread? _processThread;
    private Timer? _idleTimer;
    private bool _disposed;
    private long _callbackFaults;

    /// <summary>Production ctor: real clock + the ETW arm enabled.</summary>
    public DnsAttributionWatcher(ILogger<DnsAttributionWatcher> logger)
        : this(logger, startEtw: true, clock: null)
    {
    }

    /// <summary>Test ctor: disable the ETW arm and (optionally) inject a controllable clock so the
    /// demand-gating state machine (poll → started, idle → stopped) is testable headlessly with
    /// zero wall-clock sleeps — the same seam shape as NetworkChangeWatcher's
    /// <c>registerNativeWatches</c>/timer-factory ctor. With <paramref name="startEtw"/> false,
    /// neither the ETW session nor the idle Timer is created; tests drive <see cref="CheckIdle"/>
    /// directly.</summary>
    internal DnsAttributionWatcher(
        ILogger<DnsAttributionWatcher> logger, bool startEtw, Func<DateTimeOffset>? clock = null)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
        _startEtw = startEtw;
        _clock = clock ?? (static () => DateTimeOffset.UtcNow);
    }

    /// <summary>True while the demand gate considers the capture "on" (a poll arrived and the idle
    /// stop has not fired). With the real ETW arm this tracks the session's intended state; in the
    /// <c>startEtw: false</c> test configuration it is the observable gating state itself.</summary>
    internal bool IsSessionRequested
    {
        get
        {
            lock (_gate)
            {
                return _sessionRequested;
            }
        }
    }

    /// <summary>Count of swallowed ETW-callback faults (the callback must never throw across the
    /// ETW dispatch, so faults are counted instead — a nonzero value is a diagnostics breadcrumb,
    /// never an error surface).</summary>
    internal long CallbackFaults => Interlocked.Read(ref _callbackFaults);

    /// <inheritdoc/>
    public DnsAttributionSnapshot GetSince(long afterSeq)
    {
        Touch();
        return _ring.GetSince(afterSeq);
    }

    /// <summary>Deliberately a no-op: the ETW session is DEMAND-gated (first <see cref="GetSince"/>
    /// poll starts it), never boot-started — a helper that captured every process's DNS lookups
    /// from boot would violate the consent posture. Hosted-service registration exists so
    /// <see cref="StopAsync"/> participates in the host's deterministic shutdown ordering.</summary>
    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>Host shutdown: unconditionally stop the session, join the processing thread
    /// briefly, and drop the captured ring + name memo (capture AND retention end with the
    /// session) — see <see cref="StopSession"/> for the teardown discipline.</summary>
    public Task StopAsync(CancellationToken cancellationToken)
    {
        StopSession(onlyIfIdle: false);
        return Task.CompletedTask;
    }

    /// <summary>The demand signal: records the poll time and starts the ETW session if it is not
    /// running. Called from the pipe-dispatch thread on every GetDnsAttributions request.</summary>
    private void Touch()
    {
        var needStart = false;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _lastPoll = _clock();
            if (!_sessionRequested)
            {
                _sessionRequested = true;
                needStart = true;
            }
        }

        if (needStart)
        {
            StartEtwSession();
        }
    }

    /// <summary>Idle-timer body (also the test seam — tests advance the injected clock and call
    /// this directly): stops the session once <see cref="IdleStopAfter"/> has passed without a
    /// poll. Runs on a pool thread; must never throw (an uncaught timer-callback exception
    /// crashes the process).</summary>
    internal void CheckIdle()
    {
        try
        {
            StopSession(onlyIfIdle: true);
        }
        catch (Exception ex)
        {
            Log.IdleCheckFailed(_logger, ex);
        }
    }

    /// <summary>Builds and publishes the ETW session + processing thread + idle timer. Everything
    /// is constructed OUTSIDE the lock, then published under it only if the watcher still wants a
    /// session (a shutdown may have raced the first poll) — otherwise the freshly built resources
    /// are disposed unpublished. On failure (ETW unavailable, access denied outside LocalSystem)
    /// the demand flag is reset so the next poll simply retries: attribution silently degrades to
    /// "unknown" in the UI rather than faulting the helper.</summary>
    private void StartEtwSession()
    {
        if (!_startEtw)
        {
            return; // test configuration: the gating flag is the whole observable behaviour.
        }

        TraceEventSession? session = null;
        Timer? timer = null;
        try
        {
            // Creating with a fixed name takes over (stops) any orphaned same-named session left
            // by a crashed helper, so at most one collector ever exists.
            session = new TraceEventSession(SessionName);
            session.EnableProvider(DnsClientProviderName, TraceEventLevel.Informational);
            session.Source.Dynamic.All += OnDnsEvent;

            // Source.Process() BLOCKS until the session stops — dedicated background thread.
            var localSession = session;
            var thread = new Thread(() => RunEtwProcessing(localSession))
            {
                IsBackground = true,
                Name = "DnsAttributionEtw",
            };
            timer = new Timer(_ => CheckIdle(), null, IdleCheckPeriod, IdleCheckPeriod);

            lock (_gate)
            {
                if (_sessionRequested && !_disposed && _session is null)
                {
                    _session = session;
                    _processThread = thread;
                    _idleTimer = timer;
                    thread.Start();
                    return;
                }

                // Lost the race with a shutdown/stop — dispose the unpublished resources WHILE
                // STILL HOLDING the gate (same stop-by-name hazard as StopSession: Dispose stops
                // the machine-global session NAME, so doing it after releasing the lock could kill
                // a same-named session a re-raced Touch had just published; in-lock, any such Touch
                // can only create its session after this dispose completes).
                timer.Dispose();
                session.Dispose();
            }
        }
        catch (Exception ex)
        {
            Log.SessionStartFailed(_logger, ex);
            timer?.Dispose();
            lock (_gate)
            {
                if (session is not null)
                {
                    // The half-built session's NAME may already have been taken over by a newer
                    // session (a stop+re-touch raced our failing start): if one is published,
                    // a stop-by-name Dispose here would kill IT, so only stop when no newer
                    // session exists — otherwise just release the managed handles.
                    session.StopOnDispose = _session is null;
                    session.Dispose();
                }

                if (_session is null)
                {
                    _sessionRequested = false; // let the next poll retry instead of wedging "on".
                }
            }
        }
    }

    /// <summary>Stops the session: the idle deadline is checked atomically with the teardown (when
    /// <paramref name="onlyIfIdle"/>, so a concurrent poll that just re-touched can never have its
    /// fresh session torn down), and the session Stop()+Dispose runs WHILE STILL HOLDING
    /// <c>_gate</c>. That is deliberate: <see cref="TraceEventSession"/> stops BY NAME
    /// (machine-global), so stopping outside the lock races a concurrent <see cref="Touch"/> —
    /// the Touch could publish a NEW same-named session in the window before our late Stop(),
    /// which would then kill it, wedging attribution (<c>_sessionRequested</c> true with a dead
    /// session). Under the lock the Touch instead blocks until teardown finishes and then starts
    /// a fresh session. Holding <c>_gate</c> across the stop is safe: Stop() is a fast ETW
    /// control op, and the pump/callback threads never take <c>_gate</c> (verified:
    /// <see cref="RunEtwProcessing"/> → <see cref="OnDnsEvent"/> → <see cref="HandleQueryEvent"/>
    /// touch only the ring's own lock and <c>_nameCacheGate</c>) — no deadlock. Only the thread
    /// JOIN (a real blocking wait) stays outside the lock.</summary>
    private void StopSession(bool onlyIfIdle)
    {
        Thread? thread;
        lock (_gate)
        {
            if (!_sessionRequested)
            {
                return;
            }

            if (onlyIfIdle && _clock() - _lastPoll < IdleStopAfter)
            {
                return;
            }

            _sessionRequested = false;
            var session = _session;
            _session = null;
            thread = _processThread;
            _processThread = null;
            _idleTimer?.Dispose();
            _idleTimer = null;

            if (session is not null)
            {
                try
                {
                    session.Stop(); // makes Source.Process() return, ending the processing thread.
                }
                catch (Exception ex)
                {
                    Log.SessionStopFailed(_logger, ex);
                }

                session.Dispose();
            }
        }

        // Brief join for deterministic teardown (mirrors NetworkChangeWatcher's shutdown ordering);
        // IsBackground means a wedged ETW thread still cannot block process exit.
        thread?.Join(TimeSpan.FromSeconds(2));

        // Retention ends with the session (the privacy contract): drop the captured browsing
        // history so it can never be replayed to the NEXT session's GetSince(0) — possibly another
        // user's. Cleared AFTER the join so a late pump callback cannot repopulate it; the seq
        // counter is preserved so an in-flight poller's cursor stays valid. A Touch that raced in
        // after the lock released may already be capturing for a fresh session — this wipe can then
        // drop a few of ITS first records, which errs in the safe (over-clearing) direction.
        _ring.Clear();

        // PID-name memos die with the session too: after a gap, the same PID may be a different process.
        lock (_nameCacheGate)
        {
            _nameCache.Clear();
        }
    }

    /// <summary>The blocking ETW pump. Any fault here (session torn down mid-dispatch, provider
    /// hiccup) is logged and ends the pump — it must never propagate off this thread (an unhandled
    /// exception on any thread terminates the SYSTEM helper).</summary>
    private void RunEtwProcessing(TraceEventSession session)
    {
        try
        {
            session.Source.Process();
        }
        catch (Exception ex)
        {
            Log.ProcessingEnded(_logger, ex);
        }
    }

    /// <summary>ETW callback (the collector's thread). Filters to event 3006, extracts the header
    /// PID + payload QueryName, and pushes into the ring. MUST NEVER THROW across the ETW
    /// dispatch — fully wrapped; faults are swallowed and counted.</summary>
    private void OnDnsEvent(TraceEvent data)
    {
        try
        {
            if ((int)data.ID != QueryCalledEventId)
            {
                return;
            }

            // Defensive: the payload schema is OS-owned; a missing/non-string QueryName is skipped.
            if (data.PayloadByName("QueryName") is not string queryName || queryName.Length == 0)
            {
                return;
            }

            // The event's OWN time (3006 is raised when the calling process STARTS the lookup), not
            // the moment this callback received it: real-time ETW delivers in ~1 s flush batches, so
            // receipt time can trail the lookup by a second or more. The UI's correlation relies on
            // "a row's own lookup is stamped before the row appeared" (it only looks a few hundred ms
            // forward of a row); a receipt-time stamp would break that and leave genuine matches
            // honest-but-wrongly "unknown".
            HandleQueryEvent(data.ProcessID, queryName, new DateTimeOffset(data.TimeStamp.ToUniversalTime(), TimeSpan.Zero));
        }
        catch (Exception)
        {
            Interlocked.Increment(ref _callbackFaults);
        }
    }

    /// <summary>The largest plausible lag between a lookup and this callback receiving its event (the
    /// flush batching plus slack). An event time outside [receipt − this, receipt + 2 s] means the
    /// timestamp conversion is untrustworthy (clock change mid-session, a malformed header), so the
    /// receipt time is used instead — it stays a sane, monotone-ish stamp either way.</summary>
    private static readonly TimeSpan MaxPlausibleEventLag = TimeSpan.FromSeconds(60);

    /// <summary>The ETW-free capture path (also the test seam): stamps the entry with the lookup's own
    /// time when it is plausible (else receipt time — see <see cref="MaxPlausibleEventLag"/>), resolves
    /// the process name NOW (PID reuse makes a deferred lookup wrong) and appends to the ring.</summary>
    /// <param name="eventTimeUtc">When the lookup happened (the ETW event's timestamp, UTC); null =
    /// unknown, stamp with receipt time.</param>
    internal void HandleQueryEvent(int processId, string queryName, DateTimeOffset? eventTimeUtc = null)
    {
        var receipt = _clock();
        var stamp = eventTimeUtc is { } evt && evt >= receipt - MaxPlausibleEventLag && evt <= receipt + TimeSpan.FromSeconds(2)
            ? evt
            : receipt;
        _ring.Add(stamp.ToUnixTimeMilliseconds(), processId, queryName, ResolveProcessName(processId));
    }

    /// <summary>Per-PID name memo: resolving via <see cref="Process.GetProcessById"/> on every
    /// event would be an OS round-trip per DNS query, so hits are cached. A process that already
    /// exited resolves to null (shown honestly as a bare PID downstream). Each entry carries its
    /// resolved-at stamp (the injected clock) and a hit older than <see cref="NameCacheMaxAge"/>
    /// is RE-resolved — Windows recycles PIDs, so an ageless memo would let a recycled PID wear
    /// the dead process's name for the rest of the session; the age bound (not the 256-entry cap,
    /// which only bounds memory) is what caps that mislabeling window. The cache is cleared
    /// wholesale at capacity and whenever the session stops.</summary>
    private string? ResolveProcessName(int processId)
    {
        var now = _clock();
        lock (_nameCacheGate)
        {
            if (_nameCache.TryGetValue(processId, out var cached)
                && now - cached.ResolvedAt <= NameCacheMaxAge)
            {
                return cached.Name;
            }
        }

        string? name;
        try
        {
            using var process = Process.GetProcessById(processId);
            name = process.ProcessName;
        }
        catch (ArgumentException)
        {
            name = null; // the process already exited — attribution stays honest with a bare PID.
        }
        catch (InvalidOperationException)
        {
            name = null; // exited between the lookup and the name read.
        }

        lock (_nameCacheGate)
        {
            if (_nameCache.Count >= NameCacheCapacity)
            {
                _nameCache.Clear();
            }

            _nameCache[processId] = new CachedName(name, now);
        }

        return name;
    }

    /// <summary>One PID→name memo entry: the name resolved at capture (null = already exited) and
    /// WHEN it was resolved — the age that drives the <see cref="NameCacheMaxAge"/> re-resolve.</summary>
    private readonly record struct CachedName(string? Name, DateTimeOffset ResolvedAt);

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        // Best-effort cleanup if StopAsync was never called (failed-start paths). Idempotent.
        StopSession(onlyIfIdle: false);
    }

    // High-performance log delegates (CA1848 — avoid string interpolation at call sites).
    private static class Log
    {
        private static readonly Action<ILogger, Exception?> _sessionStartFailed =
            LoggerMessage.Define(LogLevel.Warning, new EventId(20, "AttributionSessionStartFailed"),
                "Per-app attribution ETW session could not start; the App column degrades to unknown.");

        private static readonly Action<ILogger, Exception?> _sessionStopFailed =
            LoggerMessage.Define(LogLevel.Warning, new EventId(21, "AttributionSessionStopFailed"),
                "Per-app attribution ETW session stop reported an error during teardown.");

        private static readonly Action<ILogger, Exception?> _processingEnded =
            LoggerMessage.Define(LogLevel.Warning, new EventId(22, "AttributionProcessingEnded"),
                "Per-app attribution ETW processing ended with an error.");

        private static readonly Action<ILogger, Exception?> _idleCheckFailed =
            LoggerMessage.Define(LogLevel.Error, new EventId(23, "AttributionIdleCheckFailed"),
                "Per-app attribution idle check threw unexpectedly.");

        public static void SessionStartFailed(ILogger l, Exception ex) => _sessionStartFailed(l, ex);
        public static void SessionStopFailed(ILogger l, Exception ex) => _sessionStopFailed(l, ex);
        public static void ProcessingEnded(ILogger l, Exception ex) => _processingEnded(l, ex);
        public static void IdleCheckFailed(ILogger l, Exception ex) => _idleCheckFailed(l, ex);
    }
}
