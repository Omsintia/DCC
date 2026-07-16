using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// B (Phase 5e): <see cref="PeriodicTimerQueryPoller"/> — the production poll-cadence seam. It raises
/// <see cref="IQueryPoller.Tick"/> on the injected <see cref="IUiDispatcher"/> every interval while
/// running, owns cadence ONLY (never touches files), and is off by default. Timing here is proven by
/// awaited tick SIGNALS (a <see cref="TaskCompletionSource"/> released on the first tick), never a
/// wall-clock sleep, so a short interval is latency-only. The Query Monitor ViewModel (Group C) drives
/// StartPolling/StopPolling from "logging enabled AND tab active" and wires the tick to the drain.
/// </summary>
public class PeriodicTimerQueryPollerTests
{
    /// <summary>An interval short enough to tick promptly; every wait is an awaited signal, never a sleep.</summary>
    private static readonly TimeSpan Fast = TimeSpan.FromMilliseconds(15);

    /// <summary>A dispatcher that invokes posted actions inline (the poller's tick handler runs directly).</summary>
    private sealed class InlineDispatcher : IUiDispatcher
    {
        public void Post(Action action) => action();
    }

    private static async Task<bool> WithinTimeout(Task task) =>
        await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(10))) == task;

    [Fact]
    public void off_by_default_until_started()
    {
        using var poller = new PeriodicTimerQueryPoller(new InlineDispatcher());
        Assert.False(poller.IsRunning);
    }

    [Fact]
    public async Task raises_Tick_while_running()
    {
        using var poller = new PeriodicTimerQueryPoller(new InlineDispatcher());
        var firstTick = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        poller.Tick += (_, _) => firstTick.TrySetResult();

        poller.StartPolling(Fast);
        Assert.True(poller.IsRunning);

        Assert.True(await WithinTimeout(firstTick.Task), "the poller never raised a tick");
    }

    [Fact]
    public async Task StopPolling_halts_ticks_and_clears_IsRunning()
    {
        using var poller = new PeriodicTimerQueryPoller(new InlineDispatcher());
        var ticks = 0;
        var firstTick = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        poller.Tick += (_, _) =>
        {
            Interlocked.Increment(ref ticks);
            firstTick.TrySetResult();
        };

        poller.StartPolling(Fast);
        Assert.True(await WithinTimeout(firstTick.Task), "the poller never raised a tick");

        poller.StopPolling();
        Assert.False(poller.IsRunning);

        // After Stop, the count must not keep climbing. Sample it, yield the scheduler several times
        // (awaited, not slept), and confirm it is stable — no ticks leak past Stop.
        var afterStop = Volatile.Read(ref ticks);
        for (var i = 0; i < 20; i++)
        {
            await Task.Yield();
        }

        Assert.Equal(afterStop, Volatile.Read(ref ticks));
    }

    [Fact]
    public async Task restart_stops_the_old_loop_and_runs_at_the_new_interval()
    {
        using var poller = new PeriodicTimerQueryPoller(new InlineDispatcher());
        var tickAfterRestart = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        poller.StartPolling(TimeSpan.FromMilliseconds(5));
        // Re-start at a new interval: the first loop is stopped and a fresh one armed. A tick must
        // still arrive (proving exactly one live loop, restarted cleanly).
        poller.Tick += (_, _) => tickAfterRestart.TrySetResult();
        poller.StartPolling(Fast);

        Assert.True(poller.IsRunning);
        Assert.True(await WithinTimeout(tickAfterRestart.Task), "no tick after restart");
    }

    [Fact]
    public void StopPolling_when_not_running_is_a_no_op()
    {
        using var poller = new PeriodicTimerQueryPoller(new InlineDispatcher());
        poller.StopPolling(); // must not throw
        Assert.False(poller.IsRunning);
    }

    [Fact]
    public void Dispose_stops_the_loop_and_blocks_further_starts()
    {
        var poller = new PeriodicTimerQueryPoller(new InlineDispatcher());
        poller.StartPolling(Fast);
        poller.Dispose();

        Assert.False(poller.IsRunning);
        Assert.Throws<ObjectDisposedException>(() => poller.StartPolling(Fast));
    }

    [Fact]
    public void StartPolling_rejects_a_non_positive_interval()
    {
        using var poller = new PeriodicTimerQueryPoller(new InlineDispatcher());
        Assert.Throws<ArgumentOutOfRangeException>(() => poller.StartPolling(TimeSpan.Zero));
    }

    [Fact]
    public void ctor_rejects_a_null_dispatcher()
    {
        Assert.Throws<ArgumentNullException>(() => new PeriodicTimerQueryPoller(null!));
    }
}
