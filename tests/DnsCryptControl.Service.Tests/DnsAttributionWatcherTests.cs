using System;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DnsCryptControl.Service.Windows;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace DnsCryptControl.Service.Tests;

/// <summary>The demand-gated attribution watcher (v1.3.0), exercised through the
/// <c>startEtw: false</c> seam (like <see cref="NetworkChangeWatcherTests"/> uses
/// <c>registerNativeWatches: false</c>): a GetSince poll TOUCHES the gate on, the injected-clock
/// idle check turns it off after 15 s without polls, and the capture path resolves process names
/// at capture time. The ETW arm itself is deliberately not unit-tested.</summary>
public class DnsAttributionWatcherTests
{
    /// <summary>Builds a headless watcher whose clock the test advances via the returned box.</summary>
    private static (DnsAttributionWatcher Watcher, ClockBox Clock) Build()
    {
        var clock = new ClockBox { Now = DateTimeOffset.UnixEpoch.AddDays(20_000) };
        var watcher = new DnsAttributionWatcher(
            NullLogger<DnsAttributionWatcher>.Instance, startEtw: false, clock: () => clock.Now);
        return (watcher, clock);
    }

    private sealed class ClockBox
    {
        public DateTimeOffset Now { get; set; }
    }

    [Fact]
    public void SessionIsNotRequested_untilTheFirstPoll()
    {
        var (watcher, _) = Build();
        using (watcher)
        {
            // The privacy invariant's front half: constructing (and hosting) the watcher must not
            // start machine-wide DNS observation — only a consumer's poll may.
            Assert.False(watcher.IsSessionRequested);
        }
    }

    [Fact]
    public void GetSince_touchesTheGateOn()
    {
        var (watcher, _) = Build();
        using (watcher)
        {
            watcher.GetSince(0);
            Assert.True(watcher.IsSessionRequested);
        }
    }

    [Fact]
    public void IdleCheck_withinTheThreshold_keepsTheSessionRequested()
    {
        var (watcher, clock) = Build();
        using (watcher)
        {
            watcher.GetSince(0);
            clock.Now += DnsAttributionWatcher.IdleStopAfter - TimeSpan.FromSeconds(1);
            watcher.CheckIdle();
            Assert.True(watcher.IsSessionRequested);
        }
    }

    [Fact]
    public void IdleCheck_pastTheThreshold_stopsTheSession()
    {
        var (watcher, clock) = Build();
        using (watcher)
        {
            watcher.GetSince(0);
            clock.Now += DnsAttributionWatcher.IdleStopAfter + TimeSpan.FromSeconds(1);
            watcher.CheckIdle();
            // The privacy invariant's back half: once polls stop, capture stops.
            Assert.False(watcher.IsSessionRequested);
        }
    }

    [Fact]
    public void PollingAgain_afterAnIdleStop_restartsTheGate()
    {
        var (watcher, clock) = Build();
        using (watcher)
        {
            watcher.GetSince(0);
            clock.Now += DnsAttributionWatcher.IdleStopAfter + TimeSpan.FromSeconds(1);
            watcher.CheckIdle();
            Assert.False(watcher.IsSessionRequested);

            watcher.GetSince(0);
            Assert.True(watcher.IsSessionRequested);
        }
    }

    [Fact]
    public void FreshPolls_keepResettingTheIdleDeadline()
    {
        var (watcher, clock) = Build();
        using (watcher)
        {
            watcher.GetSince(0);
            // Three windows of "almost idle", each broken by a poll — the gate must stay on.
            for (var i = 0; i < 3; i++)
            {
                clock.Now += DnsAttributionWatcher.IdleStopAfter - TimeSpan.FromSeconds(1);
                watcher.CheckIdle();
                Assert.True(watcher.IsSessionRequested);
                watcher.GetSince(0);
            }
        }
    }

    [Fact]
    public void CapturedEvents_flowIntoTheRing_andOutThroughGetSince()
    {
        var (watcher, clock) = Build();
        using (watcher)
        {
            watcher.HandleQueryEvent(4242, "a.example.com");
            watcher.HandleQueryEvent(4242, "b.example.com");

            var snapshot = watcher.GetSince(0);
            Assert.Equal(2, snapshot.LastSeq);
            Assert.Equal(
                new[] { "a.example.com", "b.example.com" },
                snapshot.Records.Select(r => r.QueryName).ToArray());
            Assert.All(snapshot.Records, r => Assert.Equal(4242, r.ProcessId));
            Assert.All(
                snapshot.Records,
                r => Assert.Equal(clock.Now.ToUnixTimeMilliseconds(), r.UnixTimeMs));

            // The cursor round-trip the UI performs each tick.
            Assert.Empty(watcher.GetSince(snapshot.LastSeq).Records);
        }
    }

    [Fact]
    public void A_plausible_event_time_is_the_stamp_not_the_receipt_time()
    {
        // ETW delivers in ~1 s flush batches, so the callback receives a lookup's event up to a
        // second or more AFTER the lookup. The ring must carry WHEN THE LOOKUP HAPPENED: the UI only
        // looks a few hundred ms forward of a query-log row, which is sound only if a row's own lookup
        // is stamped before the row appeared — a receipt-time stamp can land after it.
        var (watcher, clock) = Build();
        using (watcher)
        {
            var lookupAt = clock.Now - TimeSpan.FromMilliseconds(1200); // flushed 1.2 s later

            watcher.HandleQueryEvent(4242, "late.example", lookupAt);

            var rec = Assert.Single(watcher.GetSince(0).Records);
            Assert.Equal(lookupAt.ToUnixTimeMilliseconds(), rec.UnixTimeMs);
        }
    }

    [Theory]
    [InlineData(-61_000)] // older than any plausible flush lag (a clock change / bad header)
    [InlineData(2_500)]   // in the future beyond jitter
    public void An_implausible_event_time_falls_back_to_the_receipt_time(int offsetMs)
    {
        var (watcher, clock) = Build();
        using (watcher)
        {
            watcher.HandleQueryEvent(4242, "odd.example", clock.Now + TimeSpan.FromMilliseconds(offsetMs));

            var rec = Assert.Single(watcher.GetSince(0).Records);
            Assert.Equal(clock.Now.ToUnixTimeMilliseconds(), rec.UnixTimeMs);
        }
    }

    [Fact]
    public void ProcessName_isResolvedAtCapture_forALiveProcess()
    {
        var (watcher, _) = Build();
        using (watcher)
        {
            watcher.HandleQueryEvent(Environment.ProcessId, "self.example");

            var record = Assert.Single(watcher.GetSince(0).Records);
            using var self = Process.GetCurrentProcess();
            Assert.Equal(self.ProcessName, record.ProcessName);
        }
    }

    [Fact]
    public void ProcessName_isNullForAnExitedProcess_neverAThrow()
    {
        var (watcher, _) = Build();
        using (watcher)
        {
            // PIDs are multiples of 4 on Windows; an odd PID can never name a real process, which
            // models the exited-at-capture case deterministically.
            watcher.HandleQueryEvent(1_000_001, "gone.example");

            var record = Assert.Single(watcher.GetSince(0).Records);
            Assert.Null(record.ProcessName);
        }
    }

    [Fact]
    public void IdleStop_dropsCapturedRecords_soTheNextSessionsFirstPollSeesNothing()
    {
        // The retention half of the privacy contract: capture AND retention end with the session.
        // Without the teardown Clear, everything captured for one consented window sat in the
        // SYSTEM helper indefinitely and replayed to the NEXT logging session's GetSince(0) —
        // possibly another user's.
        var (watcher, clock) = Build();
        using (watcher)
        {
            watcher.GetSince(0); // gate on — the consented window
            watcher.HandleQueryEvent(4242, "secret.example");
            Assert.Single(watcher.GetSince(0).Records);

            clock.Now += DnsAttributionWatcher.IdleStopAfter + TimeSpan.FromSeconds(1);
            watcher.CheckIdle(); // idle stop — the session teardown
            Assert.False(watcher.IsSessionRequested);

            // A later session's opening GetSince(0) replays nothing…
            var snapshot = watcher.GetSince(0);
            Assert.Empty(snapshot.Records);
            // …and the seq counter is preserved, so an in-flight cursor stays valid.
            Assert.Equal(1, snapshot.LastSeq);
        }
    }

    [Fact]
    public void TouchDuringAnIdleStop_blocksUntilTeardownFinishes_thenRearmsAStartableGate()
    {
        // FIX B pin: StopSession used to tear the session down OUTSIDE _gate; a TraceEventSession
        // stops BY NAME (machine-global), so a Touch landing between lock-release and Stop() could
        // start a new same-named session the late Stop() then killed — attribution wedged with
        // _sessionRequested true and a dead session. The teardown now runs UNDER _gate, so a poll
        // arriving DURING the stop must block until teardown finishes and then re-arm a fresh,
        // startable gate. The interleaving is driven through the injected clock: StopSession reads
        // the idle deadline inside the locked region, so firing the concurrent poll from that
        // clock callback places it exactly in the teardown window.
        var baseTime = DateTimeOffset.UnixEpoch.AddDays(20_000);
        Thread? concurrentTouch = null;
        var stopping = false;
        DnsAttributionWatcher watcher = null!;

        DateTimeOffset Clock()
        {
            if (stopping && concurrentTouch is null)
            {
                // We are inside StopSession's locked region (its idle-deadline read): launch the
                // concurrent poll now and give it a beat to reach the gate, so it contends with
                // the in-progress teardown rather than running after it.
                concurrentTouch = new Thread(() => watcher.GetSince(0));
                concurrentTouch.Start();
                Thread.Sleep(100);
                return baseTime + DnsAttributionWatcher.IdleStopAfter + TimeSpan.FromSeconds(1);
            }

            return baseTime;
        }

        watcher = new DnsAttributionWatcher(
            NullLogger<DnsAttributionWatcher>.Instance, startEtw: false, clock: Clock);
        using (watcher)
        {
            watcher.GetSince(0); // gate on
            stopping = true;
            watcher.CheckIdle(); // the idle stop; the clock hook fires the mid-stop poll

            Assert.True(
                concurrentTouch!.Join(TimeSpan.FromSeconds(10)),
                "the touch-during-stop never completed — the teardown wedged it");
            // The mid-stop poll re-armed the gate AFTER the teardown: startable, not wedged.
            Assert.True(watcher.IsSessionRequested);

            // And the fresh session captures normally.
            watcher.HandleQueryEvent(4242, "fresh.example");
            Assert.Single(watcher.GetSince(0).Records);
        }
    }

    [Fact]
    public void MemoizedName_expiresAfterTheMaxAge_andReResolves()
    {
        // FIX C pin: Windows recycles PIDs, so an ageless PID→name memo would let a recycled PID
        // wear the DEAD process's name for the rest of the session. Entries carry a resolved-at
        // stamp; a hit older than NameCacheMaxAge re-resolves. Modelled with a real child process:
        // alive at first capture (memoized), killed, then captured again inside and past the age.
        var (watcher, clock) = Build();
        using (watcher)
        {
            var psi = new ProcessStartInfo("cmd.exe")
            {
                RedirectStandardInput = true, // keeps cmd waiting on stdin until we kill it
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var child = Process.Start(psi)!;
            try
            {
                watcher.HandleQueryEvent(child.Id, "first.example");
                child.Kill();
                child.WaitForExit();

                // Within the age bound the memo answers — the dead process's name persists (the
                // accepted, BOUNDED staleness window)…
                clock.Now += DnsAttributionWatcher.NameCacheMaxAge - TimeSpan.FromSeconds(1);
                watcher.HandleQueryEvent(child.Id, "second.example");

                // …but past it the hit re-resolves: the PID no longer names a process, so the
                // record honestly degrades to null instead of wearing the dead name forever.
                clock.Now += TimeSpan.FromSeconds(2);
                watcher.HandleQueryEvent(child.Id, "third.example");

                var records = watcher.GetSince(0).Records;
                Assert.Equal("cmd", records[0].ProcessName);
                Assert.Equal("cmd", records[1].ProcessName); // memo hit — within the age
                Assert.Null(records[2].ProcessName);         // re-resolved — the process is gone
            }
            finally
            {
                if (!child.HasExited)
                {
                    child.Kill();
                }
            }
        }
    }

    [Fact]
    public async Task StartStop_withoutEtw_isClean()
    {
        var (watcher, _) = Build();
        using (watcher)
        {
            await watcher.StartAsync(CancellationToken.None);
            watcher.GetSince(0); // gate on
            watcher.HandleQueryEvent(4242, "captured.example");
            await watcher.StopAsync(CancellationToken.None);
            Assert.False(watcher.IsSessionRequested); // shutdown stops unconditionally
            Assert.Empty(watcher.GetSince(0).Records); // …and drops retention with the session
        }
    }

    [Fact]
    public void PollAfterDispose_isANoOpRead_neverARestart()
    {
        var (watcher, _) = Build();
        watcher.HandleQueryEvent(4242, "a.example.com");
        watcher.Dispose();

        // A racing pipe request after shutdown must neither throw nor re-arm the gate.
        var snapshot = watcher.GetSince(0);
        Assert.Equal(1, snapshot.LastSeq);
        Assert.False(watcher.IsSessionRequested);
    }

    [Trait("Category", "ManualIntegration")]
    [Fact]
    public async Task LiveEtw_capturesRealDnsClientEvents()
    {
        if (!OperatingSystem.IsWindows()) return;
        // Requires: elevated (LocalSystem/admin — ETW real-time consume rights). Manual procedure:
        // construct with startEtw:true, call GetSince(0) to arm, resolve a name (nslookup/browser),
        // poll GetSince again and observe records whose ProcessID names the resolving app; then
        // stop polling for >15 s and verify the session disappears from `logman query -ets`.
        // Validated by hand, not asserted in CI.
        await Task.CompletedTask;
    }
}
