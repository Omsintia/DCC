using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.State;

namespace DnsCryptControl.Service.Windows;

/// <summary>
/// Sticky-DNS watcher: re-asserts loopback (127.0.0.1 / ::1) DNS on every eligible adapter
/// whenever the system tries to change DNS, but ONLY while the user has protection enabled.
///
/// IC-9 — sticky-DNS triggers are NotifyIpInterfaceChange + RegNotifyChangeKeyValue + 20s poll.
/// NotifyAddrChange is intentionally NOT used. Rationale:
///   - Address add/remove already surfaces via NotifyIpInterfaceChange (a strict superset of what
///     NotifyAddrChange delivers) — so NotifyAddrChange adds nothing on the interface-level front.
///   - RegNotifyChangeKeyValue additionally catches the user-mode DNS-server-PUSH case that NO
///     IP-interface notification can see: a value write to NameServer/DhcpNameServer under
///     HKLM\...\Tcpip{,6}\Parameters\Interfaces\{GUID}. Per MS Q&amp;A 1692011, name-server
///     settings are "a purely user-mode concern" that interface notifications never fire on.
///     This is the path that catches a hostile re-push of real DNS from a VPN client, DHCP
///     policy, or management tool — without which the watcher is blind to the most common attack.
///   - The 20s safety poll guarantees eventual convergence: event mechanisms can drop
///     notifications (OS resource pressure); the poll is the last line of defence for leak
///     prevention and ensures drift is corrected within one poll cycle even if both event
///     mechanisms fail temporarily.
///   The trio (NotifyIpInterfaceChange + RegNotifyChangeKeyValue + poll) strictly dominates
///   NotifyAddrChange for the sticky-DNS purpose and has no redundancy with it.
///
/// NATIVE INTEROP INVARIANTS (verified research, must not be violated):
///
///  GC ROOTING: the OS holds no managed reference to our callback. We pass a STATIC
///  [UnmanagedCallersOnly] method via a delegate* unmanaged function pointer; a static method
///  has a stable native-callable address, so NO GCHandle pinning is needed. (The live instance is
///  carried via the static field _current — see SINGLE-INSTANCE ASSUMPTION below.)
///
///  NO THROW ACROSS NATIVE: the [UnmanagedCallersOnly] callback must never throw across the
///  native boundary — a managed exception escaping a native→managed callback causes the process
///  to terminate. The callback body is fully wrapped in try/catch so nothing escapes.
///
///  MINIMAL WORK IN CALLBACK: the callback must NOT call back into iphlpapi and must NOT call
///  CancelMibChangeNotify2 (deadlock risk). It only signals the debouncer and returns; all real
///  work happens on a thread-pool thread after the debounce window.
///
///  CancelMibChangeNotify2 DEADLOCK RULE: per MSDN, CancelMibChangeNotify2 must NOT be called
///  from the notification callback for the same handle (deadlock). We call it from StopAsync,
///  which runs on the host-shutdown thread — never the OS callback thread.
///
///  Row pointer is OS-owned and valid ONLY during the callback invocation — we ignore it
///  entirely and treat every non-initial notification as "something changed, re-assert".
///
///  InitialNotification ACK (MibInitialNotification, Row==NULL): this is a registration ACK,
///  NOT a real change. We skip it in the callback. The startup re-assert is performed
///  unconditionally in StartAsync, NOT by depending on this ACK.
///
///  BOOLEAN vs BOOL: NotifyIpInterfaceChange's InitialNotification parameter is a BOOLEAN
///  (1-byte Windows type) → [MarshalAs(UnmanagedType.U1)]. Do NOT use UnmanagedType.Bool
///  (4-byte Win32 BOOL) here — it would corrupt the following nint handle parameter.
///  RegNotifyChangeKeyValue's bWatchSubtree and fAsynchronous are BOOL (4-byte) → Bool.
///
///  SINGLE-INSTANCE ASSUMPTION: the static [UnmanagedCallersOnly] callback marshals work to
///  the instance via the static field <see cref="_current"/>, set in StartAsync and cleared
///  in StopAsync. Exactly one NetworkChangeWatcher is registered as a hosted service
///  (composition root registers one). Registering two concurrently is unsupported.
///
///  RegNotifyChangeKeyValue is ONE-SHOT per call: it fires once per registration and then must
///  be re-armed. We re-arm after every signal. This catches value writes under the per-interface
///  {GUID} subkeys (NameServer, DhcpNameServer) that carry DNS server lists.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class NetworkChangeWatcher : IHostedService, IDisposable
{
    // Quiet window for the debouncer (brief spec: 500ms-1s). Safety poll period (brief spec: 15-30s).
    private static readonly TimeSpan QuietWindow = TimeSpan.FromMilliseconds(750);
    private static readonly TimeSpan SafetyPollPeriod = TimeSpan.FromSeconds(20);

    // AF_UNSPEC (0): watch ALL address families (both IPv4 and IPv6 interface changes).
    private const ushort AF_UNSPEC = 0;

    // MibInitialNotification == 3: the registration ACK sent synchronously by NotifyIpInterfaceChange.
    // Row is NULL for this notification type — it is NOT a real change, skip it.
    private const int MibInitialNotification = 3;

    // Registry subtrees whose {GUID} subkeys carry NameServer / DhcpNameServer per interface.
    private const string Tcpip4InterfacesSubKey =
        @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
    private const string Tcpip6InterfacesSubKey =
        @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";

    private readonly IDnsAdapterConfigurator _configurator;
    private readonly ProtectionStateStore _protectionState;
    private readonly ILogger<NetworkChangeWatcher> _logger;
    private readonly DebounceTimerFactory _timerFactory;
    private readonly bool _registerNativeWatches;
    private readonly object _gate = new();

    private ReassertDebouncer? _debouncer;
    private nint _notifyHandle;          // NotifyIpInterfaceChange registration handle (0 = none).
    private RegKeyWatch? _regWatch4;
    private RegKeyWatch? _regWatch6;
    private Timer? _safetyPoll;
    private bool _disposed;

    // SINGLE-INSTANCE ASSUMPTION: static field so the [UnmanagedCallersOnly] callback can reach
    // the instance without a GCHandle (a static method has a stable native-callable address).
    // Set in StartAsync, cleared in StopAsync after CancelMibChangeNotify2 returns (OS guarantees
    // no further callbacks at that point, so clearing is safe).
    private static NetworkChangeWatcher? _current;

    /// <summary>Production ctor: real SystemDebounceTimer factory + native registration enabled.</summary>
    public NetworkChangeWatcher(
        IDnsAdapterConfigurator configurator,
        ProtectionStateStore protectionState,
        ILogger<NetworkChangeWatcher> logger)
        : this(configurator, protectionState, logger, SystemDebounceTimer.Create, registerNativeWatches: true)
    {
    }

    /// <summary>Test ctor: inject a controllable timer factory and disable native registration so
    /// the gating + debounce wiring can be exercised without touching the OS.</summary>
    internal NetworkChangeWatcher(
        IDnsAdapterConfigurator configurator,
        ProtectionStateStore protectionState,
        ILogger<NetworkChangeWatcher> logger,
        DebounceTimerFactory timerFactory,
        bool registerNativeWatches)
    {
        ArgumentNullException.ThrowIfNull(configurator);
        ArgumentNullException.ThrowIfNull(protectionState);
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(timerFactory);

        _configurator = configurator;
        _protectionState = protectionState;
        _logger = logger;
        _timerFactory = timerFactory;
        _registerNativeWatches = registerNativeWatches;

        // Create the debouncer eagerly so the test-seam methods (HandleChangeSignal /
        // PerformReassert) and the fake timer factory capture work without requiring
        // a StartAsync call. The debouncer is harmless when armed but never fired.
        _debouncer = new ReassertDebouncer(QuietWindow, PerformReassert, _timerFactory);
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return Task.CompletedTask;
            }

            if (_registerNativeWatches)
            {
                // SINGLE-INSTANCE ASSUMPTION: set the static slot before registering so the
                // callback can find the instance on the very first notification.
                _current = this;
                RegisterInterfaceChange();
                _regWatch4 = RegKeyWatch.TryArm(Tcpip4InterfacesSubKey, HandleChangeSignal, _logger);
                _regWatch6 = RegKeyWatch.TryArm(Tcpip6InterfacesSubKey, HandleChangeSignal, _logger);
                _safetyPoll = new Timer(_ => HandleChangeSignal(), null,
                    SafetyPollPeriod, SafetyPollPeriod);
            }
        }

        // Unconditional startup re-assert — do NOT depend on the InitialNotification ACK (Row==NULL)
        // for this; that ACK is not guaranteed to arrive and is not a meaningful "change" signal.
        PerformReassert();
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        // Shutdown ordering is critical for correctness (native-safety invariants):
        //  1. Grab and zero out all resources under the lock so concurrent callbacks see null.
        //  2. Call CancelMibChangeNotify2 from THIS thread (NOT the callback thread → no deadlock).
        //     After it returns, the OS guarantees no further callbacks.
        //  3. Dispose registry watches, safety poll, and debouncer.
        //  4. Only AFTER CancelMibChangeNotify2 returns, clear the static _current slot (safe:
        //     OS guarantees the callback will never fire again for this handle).
        nint handleToCancel;
        RegKeyWatch? w4;
        RegKeyWatch? w6;
        Timer? poll;
        ReassertDebouncer? debouncer;

        lock (_gate)
        {
            handleToCancel = _notifyHandle;
            _notifyHandle = 0;
            w4 = _regWatch4;
            _regWatch4 = null;
            w6 = _regWatch6;
            _regWatch6 = null;
            poll = _safetyPoll;
            _safetyPoll = null;
            debouncer = _debouncer;
            _debouncer = null;
        }

        if (handleToCancel != 0)
        {
            // CancelMibChangeNotify2 called here on the host-shutdown thread — never on the OS
            // callback thread for the same handle → no deadlock. After this call returns the OS
            // guarantees no further callbacks will be invoked for this handle.
            var err = IpInterfaceChangeNative.CancelMibChangeNotify2(handleToCancel);
            if (err != 0)
            {
                Log.CancelFailed(_logger, err, null);
            }
        }

        w4?.Dispose();
        w6?.Dispose();
        poll?.Dispose();
        debouncer?.Dispose();

        // Safe to drop the static slot: CancelMibChangeNotify2 has returned (no further callbacks).
        if (ReferenceEquals(_current, this))
        {
            _current = null;
        }

        return Task.CompletedTask;
    }

    /// <summary>Single funnel for ALL three triggers (native interface change, registry DNS-push,
    /// safety poll). Feeds the debouncer. Never throws — the static callback path depends on this.
    /// </summary>
    internal void HandleChangeSignal()
    {
        try
        {
            ReassertDebouncer? debouncer;
            lock (_gate)
            {
                debouncer = _debouncer;
            }

            debouncer?.Signal();
        }
        catch (Exception ex)
        {
            // Must not propagate: this method is called from the [UnmanagedCallersOnly] callback
            // path (via HandleChangeSignal) and from pool threads (safety poll, reg watch). In all
            // cases an escaping exception would either crash the native caller or the pool thread.
            Log.SignalFailed(_logger, ex);
        }
    }

    /// <summary>Debouncer callback: re-assert loopback DNS ONLY when protection is enabled. Runs on
    /// a thread-pool thread; must NOT throw (an uncaught exception from a pool thread callback
    /// crashes the process in .NET). Fail-closed: if protection is disabled we do nothing.</summary>
    internal void PerformReassert()
    {
        try
        {
            if (!_protectionState.Load().ProtectionEnabled)
            {
                return;
            }

            var result = _configurator.ReassertLoopback();
            if (!result.Success)
            {
                Log.ReassertFailed(_logger, result.Message ?? "(no detail)", null);
            }
        }
        catch (Exception ex)
        {
            Log.ReassertThrew(_logger, ex);
        }
    }

    // Register NotifyIpInterfaceChange with the static [UnmanagedCallersOnly] callback.
    // No GCHandle needed: a static [UnmanagedCallersOnly] method has a stable native-callable address.
    private unsafe void RegisterInterfaceChange()
    {
        nint handle = 0;
        var err = IpInterfaceChangeNative.NotifyIpInterfaceChange(
            AF_UNSPEC,
            &OnInterfaceChange,
            nint.Zero,
            initialNotification: true,
            ref handle);

        if (err != 0)
        {
            Log.RegisterFailed(_logger, err, null);
            return;
        }

        _notifyHandle = handle;
    }

    // STATIC callback invoked by the OS on a worker thread.
    // MUST NOT THROW — a managed exception escaping a native→managed callback terminates the process.
    // Ignores the OS-owned Row pointer (valid only during this call; we do not use it).
    // Treats every non-initial notification as a change signal.
    [UnmanagedCallersOnly]
    private static unsafe void OnInterfaceChange(nint callerContext, nint row, int notificationType)
    {
        // MibInitialNotification (3) is the registration ACK (Row==NULL), not a real change → skip.
        // The startup re-assert is done explicitly in StartAsync; we do not depend on this ACK.
        if (notificationType == MibInitialNotification)
        {
            return;
        }

        var instance = _current;
        if (instance is null)
        {
            return;
        }

        // HandleChangeSignal is itself fully try/catch-guarded, so nothing escapes to the native caller.
        instance.HandleChangeSignal();
    }

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

        // Best-effort cleanup if StopAsync was never called (e.g. failed Start path). Idempotent.
        StopAsync(CancellationToken.None).GetAwaiter().GetResult();
    }

    // High-performance log delegates (CA1848 — avoid string interpolation at call sites).
    private static class Log
    {
        private static readonly Action<ILogger, uint, Exception?> _registerFailed =
            LoggerMessage.Define<uint>(LogLevel.Warning, new EventId(10, "WatcherRegisterFailed"),
                "NotifyIpInterfaceChange registration failed (Win32 error {Error}); relying on registry watch + safety poll.");

        private static readonly Action<ILogger, uint, Exception?> _cancelFailed =
            LoggerMessage.Define<uint>(LogLevel.Warning, new EventId(11, "WatcherCancelFailed"),
                "CancelMibChangeNotify2 returned Win32 error {Error} during shutdown.");

        private static readonly Action<ILogger, string, Exception?> _reassertFailed =
            LoggerMessage.Define<string>(LogLevel.Warning, new EventId(12, "WatcherReassertFailed"),
                "Sticky-DNS re-assert failed: {Detail}");

        private static readonly Action<ILogger, Exception?> _reassertThrew =
            LoggerMessage.Define(LogLevel.Error, new EventId(13, "WatcherReassertThrew"),
                "Sticky-DNS re-assert threw unexpectedly.");

        private static readonly Action<ILogger, Exception?> _signalFailed =
            LoggerMessage.Define(LogLevel.Error, new EventId(14, "WatcherSignalFailed"),
                "Sticky-DNS change-signal handling threw unexpectedly.");

        public static void RegisterFailed(ILogger l, uint err, Exception? ex) => _registerFailed(l, err, ex);
        public static void CancelFailed(ILogger l, uint err, Exception? ex) => _cancelFailed(l, err, ex);
        public static void ReassertFailed(ILogger l, string detail, Exception? ex) => _reassertFailed(l, detail, ex);
        public static void ReassertThrew(ILogger l, Exception ex) => _reassertThrew(l, ex);
        public static void SignalFailed(ILogger l, Exception ex) => _signalFailed(l, ex);
    }
}

/// <summary>
/// The native P/Invoke surface for IP-interface-change registration (netioapi / iphlpapi.dll).
/// Function-pointer form: the callback is a delegate* unmanaged&lt;&gt; — LibraryImport source-gen
/// handles this without any delegate marshalling overhead.
///
/// APIs are Vista+ (NOT gated on 19041); they return the Win32 error code directly
/// (NO_ERROR == 0) and do NOT use SetLastError → SetLastError = false.
///
/// BOOLEAN vs BOOL: InitialNotification is BOOLEAN (1-byte Windows type) → U1.
/// Using UnmanagedType.Bool (4-byte Win32 BOOL) here would corrupt the nint ref handle argument
/// that immediately follows it in the native ABI.
/// </summary>
[SupportedOSPlatform("windows")]
internal static partial class IpInterfaceChangeNative
{
    [LibraryImport("iphlpapi.dll", SetLastError = false)]
    internal static unsafe partial uint NotifyIpInterfaceChange(
        ushort family,
        delegate* unmanaged<nint, nint, int, void> callback,
        nint callerContext,
        [MarshalAs(UnmanagedType.U1)] bool initialNotification,
        ref nint notificationHandle);

    [LibraryImport("iphlpapi.dll", SetLastError = false)]
    internal static partial uint CancelMibChangeNotify2(nint notificationHandle);
}

/// <summary>
/// A re-arming async RegNotifyChangeKeyValue watch over a HKLM subtree.
/// Catches the user-mode DNS-server-PUSH case: when a VPN client, DHCP responder, or management
/// tool writes NameServer/DhcpNameServer under ...\Interfaces\{GUID}, no IP-interface notification
/// fires — only the registry watch sees it (MS Q&amp;A 1692011).
///
/// RegNotifyChangeKeyValue is ONE-SHOT per registration call → must be re-armed after every signal.
/// Watch flags: REG_NOTIFY_CHANGE_LAST_SET (value writes) | REG_NOTIFY_CHANGE_NAME (subkey add/del),
/// watch-subtree enabled so per-interface {GUID} subkeys are covered by a single registration.
///
/// Best-effort: if the key cannot be opened (e.g. running without SYSTEM privileges in a test
/// environment) returns null and the watcher degrades to interface-change + safety-poll.
///
/// BOOL vs BOOLEAN: both bWatchSubtree and fAsynchronous in RegNotifyChangeKeyValue are Win32 BOOL
/// (4-byte) → [MarshalAs(UnmanagedType.Bool)].
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class RegKeyWatch : IDisposable
{
    private const int REG_NOTIFY_CHANGE_NAME = 0x00000001;
    private const int REG_NOTIFY_CHANGE_LAST_SET = 0x00000004;
    private const int FilterFlags = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET;

    private readonly RegistryKey _key;
    private readonly Action _onChange;
    private readonly ManualResetEvent _changeEvent;
    private readonly ManualResetEvent _stopEvent;
    private RegisteredWaitHandle? _registration;
    private bool _disposed;

    private RegKeyWatch(RegistryKey key, Action onChange)
    {
        _key = key;
        _onChange = onChange;
        _changeEvent = new ManualResetEvent(false);
        _stopEvent = new ManualResetEvent(false);
    }

    public static RegKeyWatch? TryArm(string subKey, Action onChange, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(onChange);
        ArgumentNullException.ThrowIfNull(logger);
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            var key = hklm.OpenSubKey(subKey, writable: false);
            if (key is null)
            {
                return null;
            }

            var watch = new RegKeyWatch(key, onChange);
            watch.Arm();
            return watch;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or System.IO.IOException)
        {
            RegLog.ArmFailed(logger, subKey, ex);
            return null;
        }
    }

    private void Arm()
    {
        _changeEvent.Reset();
        // Asynchronous + watch-subtree: per-interface NameServer/DhcpNameServer live under {GUID}
        // subkeys; a single subtree watch covers all of them.
        var err = RegNotifyNative.RegNotifyChangeKeyValue(
            _key.Handle, watchSubtree: true, FilterFlags, _changeEvent.SafeWaitHandle, asynchronous: true);
        if (err != 0)
        {
            // Could not arm; leave unregistered. Other triggers (interface change + poll) still run.
            return;
        }

        _registration = ThreadPool.RegisterWaitForSingleObject(
            _changeEvent, OnSignalled, state: null, millisecondsTimeOutInterval: Timeout.Infinite, executeOnlyOnce: true);
    }

    private void OnSignalled(object? state, bool timedOut)
    {
        if (_disposed || _stopEvent.WaitOne(0))
        {
            return;
        }

        // Signal the change funnel first, THEN re-arm (re-arm must happen after the callback to
        // avoid a gap where a write arrives between the signal and the new registration).
        _onChange();

        if (!_disposed)
        {
            // RE-ARM: RegNotifyChangeKeyValue is one-shot. Without re-arm we would miss all
            // subsequent DNS-push events after the first.
            Arm();
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _stopEvent.Set();
        _changeEvent.Set();             // Unblock any pending pool-thread wait so Unregister can drain.
        _registration?.Unregister(null);
        _key.Dispose();
        _changeEvent.Dispose();
        _stopEvent.Dispose();
    }

    private static class RegLog
    {
        private static readonly Action<ILogger, string, Exception?> _armFailed =
            LoggerMessage.Define<string>(LogLevel.Warning, new EventId(15, "RegWatchArmFailed"),
                "Could not open registry key {SubKey} for DNS-change watch; degrading to interface-change + poll.");

        public static void ArmFailed(ILogger l, string subKey, Exception ex) => _armFailed(l, subKey, ex);
    }
}

/// <summary>
/// advapi32 RegNotifyChangeKeyValue P/Invoke declaration.
/// Returns LSTATUS (Win32 error code directly, ERROR_SUCCESS == 0) → SetLastError = false.
/// bWatchSubtree and fAsynchronous are Win32 BOOL (4-byte) → [MarshalAs(UnmanagedType.Bool)].
/// Vista+ (no 19041 guard needed).
/// </summary>
[SupportedOSPlatform("windows")]
internal static partial class RegNotifyNative
{
    [LibraryImport("advapi32.dll", SetLastError = false)]
    internal static partial int RegNotifyChangeKeyValue(
        SafeRegistryHandle key,
        [MarshalAs(UnmanagedType.Bool)] bool watchSubtree,
        int notifyFilter,
        SafeWaitHandle eventHandle,
        [MarshalAs(UnmanagedType.Bool)] bool asynchronous);
}
