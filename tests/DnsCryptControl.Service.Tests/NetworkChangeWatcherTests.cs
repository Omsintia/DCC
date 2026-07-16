using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.State;
using DnsCryptControl.Service.Windows;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace DnsCryptControl.Service.Tests;

public class NetworkChangeWatcherTests
{
    // Fake configurator: counts ReassertLoopback() calls and returns a configurable result.
    private sealed class FakeConfigurator : IDnsAdapterConfigurator
    {
        public int ReassertCount { get; private set; }
        public PlatformResult NextResult { get; set; } = PlatformResult.Ok();

        public PlatformResult ApplyLoopbackToAllAdapters() => PlatformResult.Ok();
        public PlatformResult ReassertLoopback()
        {
            ReassertCount++;
            return NextResult;
        }

        public PlatformResult RestoreDns() => PlatformResult.Ok();
        public bool IsLoopbackApplied() => false;
    }

    // Controllable timer (same shape as Task H1's fake) so debounced re-asserts fire on command.
    private sealed class FakeDebounceTimer : IDebounceTimer
    {
        private readonly Action _onElapsed;
        public bool Disposed { get; private set; }
        public FakeDebounceTimer(Action onElapsed) => _onElapsed = onElapsed;
        public void Reset(TimeSpan delay) { }
        public void Fire() => _onElapsed();
        public void Dispose() => Disposed = true;
    }

    // A ProtectionStateStore backed by a temp file so we can flip ProtectionEnabled.
    private static (ProtectionStateStore store, string path) NewProtectionStore(bool enabled)
    {
        var path = Path.Combine(Path.GetTempPath(), "dcc-prot-" + Guid.NewGuid().ToString("N") + ".json");
        var store = new ProtectionStateStore(path);
        store.Save(new ProtectionState(ProtectionEnabled: enabled, KillSwitchEnabled: false, LeakMitigationsEnabled: false));
        return (store, path);
    }

    private static NetworkChangeWatcher Build(
        FakeConfigurator configurator, ProtectionStateStore protectionStore, out FakeDebounceTimer timer)
    {
        FakeDebounceTimer? captured = null;
        var watcher = new NetworkChangeWatcher(
            configurator,
            protectionStore,
            NullLogger<NetworkChangeWatcher>.Instance,
            timerFactory: onElapsed =>
            {
                captured = new FakeDebounceTimer(onElapsed);
                return captured;
            },
            registerNativeWatches: false);
        timer = captured!;
        return watcher;
    }

    [Fact]
    public void PerformReassert_whenProtectionEnabled_callsReassertLoopback()
    {
        var (store, path) = NewProtectionStore(enabled: true);
        try
        {
            var cfg = new FakeConfigurator();
            using var watcher = Build(cfg, store, out _);
            watcher.PerformReassert();
            Assert.Equal(1, cfg.ReassertCount);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void PerformReassert_whenProtectionDisabled_doesNotReassert()
    {
        var (store, path) = NewProtectionStore(enabled: false);
        try
        {
            var cfg = new FakeConfigurator();
            using var watcher = Build(cfg, store, out _);
            watcher.PerformReassert();
            Assert.Equal(0, cfg.ReassertCount);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void HandleChangeSignal_debouncesThroughTimer_thenReassertsWhenEnabled()
    {
        var (store, path) = NewProtectionStore(enabled: true);
        try
        {
            var cfg = new FakeConfigurator();
            using var watcher = Build(cfg, store, out var timer);

            // A storm of signals routes through the debouncer; nothing fires until the timer elapses.
            watcher.HandleChangeSignal();
            watcher.HandleChangeSignal();
            watcher.HandleChangeSignal();
            Assert.Equal(0, cfg.ReassertCount);

            timer.Fire();
            Assert.Equal(1, cfg.ReassertCount);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void HandleChangeSignal_whenDisabled_debouncedReassertIsGatedOut()
    {
        var (store, path) = NewProtectionStore(enabled: false);
        try
        {
            var cfg = new FakeConfigurator();
            using var watcher = Build(cfg, store, out var timer);

            watcher.HandleChangeSignal();
            timer.Fire();
            Assert.Equal(0, cfg.ReassertCount);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void PerformReassert_swallowsConfiguratorFailure_doesNotThrow()
    {
        var (store, path) = NewProtectionStore(enabled: true);
        try
        {
            var cfg = new FakeConfigurator
            {
                NextResult = PlatformResult.Fail(PlatformErrorKind.OperationFailed, "boom"),
            };
            using var watcher = Build(cfg, store, out _);

            // A failed re-assert must never escape the debounce callback (it runs on a pool thread).
            var ex = Record.Exception(() => watcher.PerformReassert());
            Assert.Null(ex);
            Assert.Equal(1, cfg.ReassertCount);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task StartStop_withoutNativeRegistration_isClean()
    {
        var (store, path) = NewProtectionStore(enabled: true);
        try
        {
            var cfg = new FakeConfigurator();
            using var watcher = Build(cfg, store, out _);

            await watcher.StartAsync(CancellationToken.None);
            await watcher.StopAsync(CancellationToken.None);
            // No native handle was acquired (registerNativeWatches:false), so Stop must be a clean no-op.
        }
        finally { File.Delete(path); }
    }

    [Trait("Category", "ManualIntegration")]
    [Fact]
    public async Task LiveRegistration_reassertsOnRealAdapterChange()
    {
        if (!OperatingSystem.IsWindows()) return;
        // Requires: elevated (LocalSystem), real adapters, protection ENABLED in the state store.
        // Manual procedure: start the watcher with registerNativeWatches:true, then toggle an adapter
        // (disable/enable a NIC or run `ipconfig /renew`) or edit a per-interface NameServer; observe
        // a single debounced ReassertLoopback() within ~1s. Validated by hand, not asserted in CI.
        await Task.CompletedTask;
    }
}
