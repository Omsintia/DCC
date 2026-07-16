using System;
using System.Collections.Generic;
using DnsCryptControl.Service.Windows;
using Xunit;

namespace DnsCryptControl.Service.Tests;

public class ReassertDebouncerTests
{
    // A controllable fake timer: records each Reset delay, exposes Fire() to simulate elapse,
    // and tracks disposal. One instance is handed to the debouncer via the factory below.
    private sealed class FakeDebounceTimer : IDebounceTimer
    {
        private readonly Action _onElapsed;
        public int ResetCount { get; private set; }
        public TimeSpan LastDelay { get; private set; }
        public bool Disposed { get; private set; }

        public FakeDebounceTimer(Action onElapsed) => _onElapsed = onElapsed;

        public void Reset(TimeSpan delay)
        {
            ResetCount++;
            LastDelay = delay;
        }

        // Simulate the quiet window elapsing (the production timer would invoke onElapsed here).
        public void Fire() => _onElapsed();

        public void Dispose() => Disposed = true;
    }

    private static (ReassertDebouncer debouncer, FakeDebounceTimer timer, List<int> calls) Build(TimeSpan window)
    {
        var calls = new List<int>();
        FakeDebounceTimer? captured = null;
        var debouncer = new ReassertDebouncer(
            window,
            onReassert: () => calls.Add(1),
            timerFactory: onElapsed =>
            {
                captured = new FakeDebounceTimer(onElapsed);
                return captured;
            });
        return (debouncer, captured!, calls);
    }

    [Fact]
    public void Signal_armsTimerWithQuietWindow()
    {
        var (debouncer, timer, _) = Build(TimeSpan.FromMilliseconds(750));
        using (debouncer)
        {
            debouncer.Signal();
            Assert.Equal(1, timer.ResetCount);
            Assert.Equal(TimeSpan.FromMilliseconds(750), timer.LastDelay);
        }
    }

    [Fact]
    public void ThreeRapidSignals_collapseToOneReassert_afterWindow()
    {
        var (debouncer, timer, calls) = Build(TimeSpan.FromMilliseconds(750));
        using (debouncer)
        {
            debouncer.Signal();
            debouncer.Signal();
            debouncer.Signal();

            // Three signals each re-armed the same timer; nothing has fired yet.
            Assert.Equal(3, timer.ResetCount);
            Assert.Empty(calls);

            // The storm settles: the single armed timer elapses once.
            timer.Fire();
            Assert.Single(calls);
        }
    }

    [Fact]
    public void SignalAfterAnEarlierReassert_producesASecondReassert()
    {
        var (debouncer, timer, calls) = Build(TimeSpan.FromMilliseconds(750));
        using (debouncer)
        {
            debouncer.Signal();
            timer.Fire();
            Assert.Single(calls);

            // A later, separate storm produces another independent re-assert.
            debouncer.Signal();
            timer.Fire();
            Assert.Equal(2, calls.Count);
        }
    }

    [Fact]
    public void Fire_afterDispose_doesNotInvokeReassert()
    {
        var (debouncer, timer, calls) = Build(TimeSpan.FromMilliseconds(750));
        debouncer.Signal();
        debouncer.Dispose();

        // A late elapse that races past disposal must be swallowed (no re-assert).
        timer.Fire();
        Assert.Empty(calls);
        Assert.True(timer.Disposed);
    }

    [Fact]
    public void Signal_afterDispose_isNoOp()
    {
        var (debouncer, timer, calls) = Build(TimeSpan.FromMilliseconds(750));
        debouncer.Dispose();
        debouncer.Signal();
        timer.Fire();
        Assert.Empty(calls);
    }

    [Fact]
    public void Ctor_rejectsNonPositiveWindow()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new ReassertDebouncer(TimeSpan.Zero, () => { }, _ => throw new InvalidOperationException()));
    }
}
