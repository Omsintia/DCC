using System;
using System.Threading;
using System.Threading.Tasks;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// The production <see cref="IQueryPoller"/>: a <see cref="PeriodicTimer"/>-backed loop that raises
/// <see cref="Tick"/> on the UI thread (via the injected <see cref="IUiDispatcher"/>) every interval
/// while running, so the ViewModel's drain and its <c>ObservableCollection</c> writes stay UI-affine —
/// exactly the marshalling discipline <c>RuleFamilyEditorViewModel</c> uses for its debounced re-parse.
/// The poller owns cadence only; it never touches files. Off by default; the ViewModel drives
/// <see cref="StartPolling"/>/<see cref="StopPolling"/> from "logging enabled AND tab active".
///
/// <para>Tests do NOT use this type — they inject a fake <see cref="IQueryPoller"/> whose ticks they
/// pump synchronously with zero sleeps. This class exists to run the real cadence in the app.</para>
/// </summary>
public sealed class PeriodicTimerQueryPoller : IQueryPoller, IDisposable
{
    private readonly IUiDispatcher _ui;
    private readonly object _sync = new();

    private PeriodicTimer? _timer;
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private bool _disposed;

    /// <param name="ui">The UI-thread marshaller each tick is posted through, so handlers touch
    /// observable state on the UI thread (IC-5), matching the rest of the UI layer.</param>
    public PeriodicTimerQueryPoller(IUiDispatcher ui)
    {
        ArgumentNullException.ThrowIfNull(ui);
        _ui = ui;
    }

    public event EventHandler? Tick;

    public bool IsRunning
    {
        get { lock (_sync) { return _timer is not null; } }
    }

    public void StartPolling(TimeSpan interval)
    {
        if (interval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(interval), interval, "The poll interval must be positive.");
        }

        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            // Restart cleanly: stop any current loop, then arm a fresh timer at the new interval.
            StopLocked();

            var timer = new PeriodicTimer(interval);
            var cts = new CancellationTokenSource();
            _timer = timer;
            _cts = cts;
            _loop = RunAsync(timer, cts.Token);
        }
    }

    public void StopPolling()
    {
        lock (_sync)
        {
            StopLocked();
        }
    }

    private void StopLocked()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;

        _timer?.Dispose(); // makes the pending WaitForNextTickAsync return false → the loop exits
        _timer = null;

        _loop = null; // the loop task drains itself on cancellation; we don't block on it
    }

    private async Task RunAsync(PeriodicTimer timer, CancellationToken ct)
    {
        try
        {
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
            {
                // Marshal the tick to the UI thread so the ViewModel's drain + ObservableCollection
                // writes happen UI-affine. The handler is expected not to throw (the drain is
                // fail-closed); we don't catch here so a genuine bug is not swallowed.
                _ui.Post(() => Tick?.Invoke(this, EventArgs.Empty));
            }
        }
        catch (OperationCanceledException)
        {
            // Expected on Stop/Dispose — the loop simply ends.
        }
        catch (ObjectDisposedException)
        {
            // The timer was disposed out from under a pending wait during Stop/Dispose — end the loop.
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            StopLocked();
        }
    }
}
