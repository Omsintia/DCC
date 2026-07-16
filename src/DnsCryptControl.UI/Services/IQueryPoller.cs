using System;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// The Query Monitor's poll loop (Phase 5e, design 2.4). It owns ONLY the cadence — a repeating tick
/// while running — and raises <see cref="Tick"/> each interval; it does NOT read files. The
/// ViewModel wires each tick to <see cref="IQueryLogReader.Drain"/>, so the poller stays a thin,
/// deterministically-testable seam (production uses a <see cref="System.Threading.PeriodicTimer"/>;
/// tests pump ticks directly with zero wall-clock sleeps, mirroring how
/// <c>RuleFamilyEditorViewModel</c>'s injected debounce is driven).
/// </summary>
public interface IQueryPoller
{
    /// <summary>Raised on each poll tick while the poller is running. The handler runs the drain; it
    /// must not throw (the poller does not guard handler exceptions in production).</summary>
    event EventHandler? Tick;

    /// <summary>True between a <see cref="StartPolling"/> and the next <see cref="StopPolling"/>.</summary>
    bool IsRunning { get; }

    /// <summary>
    /// Starts (or restarts) the tick loop at <paramref name="interval"/>. Idempotent-ish: calling it
    /// while already running stops the current loop first and starts a fresh one at the new interval.
    /// The loop is off by default — the ViewModel starts it only while logging is enabled AND the tab
    /// is active, and stops it otherwise. (Named <c>StartPolling</c>/<c>StopPolling</c> to match
    /// <c>DashboardViewModel</c> and to avoid the reserved-keyword <c>Start</c>/<c>Stop</c>, CA1716.)
    /// </summary>
    /// <param name="interval">The poll cadence (production default ~750 ms — the read-and-shred window).</param>
    void StartPolling(TimeSpan interval);

    /// <summary>Stops the tick loop. Idempotent — a no-op when not running. Safe to call from disable,
    /// tab-deactivate, and dispose.</summary>
    void StopPolling();
}
