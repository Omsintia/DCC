using System;
using System.Threading;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// B4: the per-user single-instance guard. Each test uses a UNIQUE mutex/event name
/// (derived from the test name + a GUID) so tests never collide with each other or
/// with a real running app instance sharing this session.
/// </summary>
public class SingleInstanceGuardTests
{
    private static (string mutexName, string eventName) UniqueNames(string suffix)
    {
        var id = Guid.NewGuid().ToString("N");
        return ($"Local\\DnsCryptControl.UI.Tests.{suffix}.{id}.Mutex",
                $"Local\\DnsCryptControl.UI.Tests.{suffix}.{id}.Event");
    }

    [Fact]
    public void First_instance_acquires()
    {
        var (mutexName, eventName) = UniqueNames(nameof(First_instance_acquires));

        using var guard = new SingleInstanceGuard(mutexName, eventName);

        Assert.True(guard.IsFirstInstance);
    }

    [Fact]
    public void Second_instance_detects_existing()
    {
        var (mutexName, eventName) = UniqueNames(nameof(Second_instance_detects_existing));

        var guard1 = new SingleInstanceGuard(mutexName, eventName);
        try
        {
            Assert.True(guard1.IsFirstInstance);

            // Named-mutex ownership is per-THREAD (recursive acquisition on the same
            // thread trivially succeeds), so guard2 must be constructed on a distinct
            // thread to faithfully simulate a second OS process.
            SingleInstanceGuard? guard2 = null;
            var thread = new Thread(() => guard2 = new SingleInstanceGuard(mutexName, eventName));
            thread.Start();
            thread.Join();

            try
            {
                Assert.NotNull(guard2);
                Assert.False(guard2!.IsFirstInstance);
            }
            finally
            {
                guard2?.Dispose();
            }
        }
        finally
        {
            guard1.Dispose();
        }
    }

    [Fact]
    public void Abandoned_mutex_is_treated_as_acquired()
    {
        var (mutexName, eventName) = UniqueNames(nameof(Abandoned_mutex_is_treated_as_acquired));

        var thread = new Thread(() =>
        {
            using var mutex = new Mutex(initiallyOwned: true, mutexName, out _);
            // Deliberately let the thread exit WITHOUT releasing — abandons the mutex.
        });
        thread.Start();
        thread.Join();

        using var guard = new SingleInstanceGuard(mutexName, eventName);

        Assert.True(guard.IsFirstInstance);
    }

    [Fact]
    public void SignalExistingInstance_sets_the_activation_event()
    {
        var (mutexName, eventName) = UniqueNames(nameof(SignalExistingInstance_sets_the_activation_event));

        using var guard1 = new SingleInstanceGuard(mutexName, eventName);
        Assert.True(guard1.IsFirstInstance);

        using var callbackInvoked = new ManualResetEventSlim(false);
        guard1.WaitForActivation(() => callbackInvoked.Set());

        // Named-mutex ownership is per-THREAD, so guard2 must be constructed on a
        // distinct thread to faithfully simulate a second OS process detecting guard1.
        SingleInstanceGuard? guard2 = null;
        var thread = new Thread(() => guard2 = new SingleInstanceGuard(mutexName, eventName));
        thread.Start();
        thread.Join();

        try
        {
            Assert.NotNull(guard2);
            Assert.False(guard2!.IsFirstInstance);
            guard2.SignalExistingInstance();

            var signalled = callbackInvoked.Wait(TimeSpan.FromSeconds(5));

            Assert.True(signalled);
        }
        finally
        {
            guard2?.Dispose();
        }
    }
}
