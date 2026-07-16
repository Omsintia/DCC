using System;
using System.Threading;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// Per-user (per-session) single-instance guard (B4/F22). Uses <c>Local\</c>-scoped
/// named kernel objects — a second logged-in user gets their own session namespace and
/// is therefore never blocked by this user's instance.
///
/// Names are injectable so tests can use unique per-test names and never collide with
/// each other or with a real running app sharing this session.
///
/// Ownership model: the constructor takes the named mutex with <c>WaitOne(0)</c> (never
/// blocks). If the previous owner terminated while holding it, <see cref="Mutex.WaitOne(int)"/>
/// throws <see cref="AbandonedMutexException"/> — this is still a successful acquisition
/// (the OS transfers ownership to us), so it is treated as "first instance", never as
/// "another instance is running".
/// </summary>
public sealed class SingleInstanceGuard : IDisposable
{
    private const string DefaultMutexName = "Local\\DnsCryptControl.UI.SingleInstance";
    private const string DefaultEventName = "Local\\DnsCryptControl.UI.Activate";

    private readonly string _eventName;
    private readonly Mutex _mutex;
    private readonly bool _isFirstInstance;

    private EventWaitHandle? _activationEvent;
    private RegisteredWaitHandle? _activationRegistration;
    private bool _disposed;

    public SingleInstanceGuard(string? mutexName = null, string? eventName = null)
    {
        _eventName = eventName ?? DefaultEventName;
        _mutex = new Mutex(initiallyOwned: false, mutexName ?? DefaultMutexName);

        try
        {
            _isFirstInstance = _mutex.WaitOne(0);
        }
        catch (AbandonedMutexException)
        {
            // A prior owner died while holding the mutex. The OS still grants us
            // ownership — this IS acquisition, not "another instance is running".
            _isFirstInstance = true;
        }
    }

    /// <summary>True if this instance acquired the mutex (i.e. is the first/only instance).</summary>
    public bool IsFirstInstance => _isFirstInstance;

    /// <summary>
    /// Called by a SECOND instance to ask the already-running first instance to
    /// foreground itself. Safe to call even if no first instance is currently waiting
    /// (the event simply has no listener; nothing throws).
    /// </summary>
    public void SignalExistingInstance()
    {
        using var activationEvent = new EventWaitHandle(initialState: false, EventResetMode.AutoReset, _eventName);
        activationEvent.Set();
    }

    /// <summary>
    /// Called by the FIRST instance to register a background wait on the activation
    /// event. When a second instance calls <see cref="SignalExistingInstance"/>,
    /// <paramref name="bringToFront"/> is invoked off the UI thread — the caller is
    /// responsible for marshalling it (e.g. via <c>Dispatcher.Invoke</c>).
    /// </summary>
    public void WaitForActivation(Action bringToFront)
    {
        ArgumentNullException.ThrowIfNull(bringToFront);

        _activationEvent = new EventWaitHandle(initialState: false, EventResetMode.AutoReset, _eventName);

        _activationRegistration = ThreadPool.RegisterWaitForSingleObject(
            _activationEvent,
            (state, timedOut) =>
            {
                if (!timedOut)
                {
                    bringToFront();
                }
            },
            state: null,
            millisecondsTimeOutInterval: Timeout.Infinite,
            executeOnlyOnce: false);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        _activationRegistration?.Unregister(null);
        _activationRegistration = null;

        _activationEvent?.Dispose();
        _activationEvent = null;

        if (_isFirstInstance)
        {
            try
            {
                _mutex.ReleaseMutex();
            }
            catch (ApplicationException)
            {
                // Not held (e.g. released elsewhere) — nothing to do.
            }
        }

        _mutex.Dispose();
    }
}
