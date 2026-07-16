using System;

namespace DnsCryptControl.Service.Windows;

/// <summary>Abstraction over a one-shot re-armable timer so the debounce logic can be unit-tested
/// deterministically (a fake fires elapse on command; production uses System.Threading.Timer).</summary>
internal interface IDebounceTimer : IDisposable
{
    /// <summary>(Re)arm the timer to elapse once after <paramref name="delay"/>. Any previously
    /// armed-but-not-yet-elapsed callback is superseded by this new delay.</summary>
    void Reset(TimeSpan delay);
}

/// <summary>Factory the <see cref="ReassertDebouncer"/> uses to obtain its timer. The supplied
/// <paramref name="onElapsed"/> is the callback the timer must invoke when the delay expires.</summary>
internal delegate IDebounceTimer DebounceTimerFactory(Action onElapsed);

/// <summary>Production <see cref="IDebounceTimer"/> backed by <see cref="System.Threading.Timer"/>.</summary>
internal static class SystemDebounceTimer
{
    public static IDebounceTimer Create(Action onElapsed)
    {
        ArgumentNullException.ThrowIfNull(onElapsed);
        return new TimerImpl(onElapsed);
    }

    private sealed class TimerImpl : IDebounceTimer
    {
        private readonly System.Threading.Timer _timer;

        public TimerImpl(Action onElapsed) =>
            // Created disarmed (Timeout.Infinite). Reset() arms it; it auto-disarms after one shot
            // because the period is also Infinite.
            _timer = new System.Threading.Timer(_ => onElapsed(), null,
                System.Threading.Timeout.Infinite, System.Threading.Timeout.Infinite);

        public void Reset(TimeSpan delay) =>
            _timer.Change(delay, System.Threading.Timeout.InfiniteTimeSpan);

        public void Dispose() => _timer.Dispose();
    }
}

/// <summary>Collapses a storm of change signals into a single re-assert after a quiet window.
/// Each <see cref="Signal"/> re-arms the timer; only when no signal arrives for the whole quiet
/// window does <c>onReassert</c> run — exactly once per settled storm. A later signal starts a new
/// cycle and yields another re-assert. Thread-safe: <see cref="Signal"/> may be called from the OS
/// notification thread while the timer callback runs on a thread-pool thread.</summary>
internal sealed class ReassertDebouncer : IDisposable
{
    private readonly TimeSpan _quietWindow;
    private readonly Action _onReassert;
    private readonly IDebounceTimer _timer;
    private readonly object _gate = new();
    private bool _disposed;

    public ReassertDebouncer(TimeSpan quietWindow, Action onReassert, DebounceTimerFactory timerFactory)
    {
        if (quietWindow <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(quietWindow), "Quiet window must be positive.");
        }

        ArgumentNullException.ThrowIfNull(onReassert);
        ArgumentNullException.ThrowIfNull(timerFactory);

        _quietWindow = quietWindow;
        _onReassert = onReassert;
        _timer = timerFactory(OnTimerElapsed);
    }

    /// <summary>Record a change signal. Safe to call from the native OS callback thread (it does no
    /// blocking work — just re-arms the timer and returns immediately).</summary>
    public void Signal()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _timer.Reset(_quietWindow);
        }
    }

    private void OnTimerElapsed()
    {
        // Snapshot disposal state under the lock, but invoke the callback OUTSIDE the lock so a
        // re-assert (which may take real work / native calls) never holds _gate while a concurrent
        // Signal() from the OS callback thread is waiting on it.
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }
        }

        _onReassert();
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

        _timer.Dispose();
    }
}
