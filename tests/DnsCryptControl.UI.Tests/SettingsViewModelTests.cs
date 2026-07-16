using System;
using System.Collections.Generic;
using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.UI.Models;
using DnsCryptControl.UI.Services;
using DnsCryptControl.UI.Tests.Fakes;
using DnsCryptControl.UI.ViewModels;

namespace DnsCryptControl.UI.Tests;

/// <summary>G: SettingsViewModel — appearance/startup/tray prefs (single-source persist) + the offline
/// integrity verdict (verified only when the proxy is running; no UI-side pin).</summary>
public sealed class SettingsViewModelTests
{
    private sealed class SyncDispatcher : IUiDispatcher
    {
        public void Post(Action action) => action();
    }

    private sealed class FakeUiStateStore : IUiStateStore
    {
        public UiState Saved { get; private set; } = new();
        public UiState ToLoad { get; set; } = new();
        public int SaveCount { get; private set; }

        public UiState Load() => ToLoad;

        public void Save(UiState state)
        {
            Saved = state;
            SaveCount++;
        }
    }

    private sealed class FakeStartup : IStartupRegistration
    {
        public bool Registered { get; set; }
        public int UnregisterCount { get; private set; }

        /// <summary>When false, Register() reports a rejected (locked/denied) write.</summary>
        public bool RegisterResult { get; set; } = true;

        public bool IsRegistered() => Registered;

        public bool Register()
        {
            if (!RegisterResult) return false;
            Registered = true;
            return true;
        }

        public bool Unregister()
        {
            Registered = false;
            UnregisterCount++;
            return true;
        }
    }

    private sealed class FakeThemeApplier : IThemeApplier
    {
        public List<string?> Applied { get; } = new();
        public void Apply(string? theme) => Applied.Add(theme);
        public void AttachWindow(object window) { }
        public void Prime() { }
    }

    private sealed class FakeIntegrityReader : IExeIntegrityReader
    {
        public ExeIntegrityInfo Info { get; set; } = new(@"C:\x\dnscrypt-proxy.exe", "2.1.16", "abc123", true);
        public int ReadCount { get; private set; }

        public ExeIntegrityInfo Read(string exePath)
        {
            ReadCount++;
            return Info;
        }
    }

    private static SettingsViewModel MakeSut(
        FakeUiStateStore? store = null, FakeStartup? startup = null, FakeThemeApplier? theme = null,
        FakeIntegrityReader? integrity = null, FakeHelperClient? helper = null) =>
        new(store ?? new FakeUiStateStore(), startup ?? new FakeStartup(), theme ?? new FakeThemeApplier(),
            integrity ?? new FakeIntegrityReader(), helper ?? new FakeHelperClient(), new SyncDispatcher());

    [Fact]
    public void Theme_setPersistsAndApplies()
    {
        var store = new FakeUiStateStore();
        var theme = new FakeThemeApplier();
        var vm = MakeSut(store: store, theme: theme);

        vm.SelectedTheme = "Dark";

        Assert.Equal("Dark", store.Saved.Theme);
        Assert.Contains("Dark", theme.Applied);
    }

    [Fact]
    public void StartWithWindows_setWritesRegistrationAndPersists()
    {
        var store = new FakeUiStateStore();
        var startup = new FakeStartup();
        var vm = MakeSut(store: store, startup: startup);

        vm.StartWithWindows = true;
        Assert.True(startup.Registered);
        Assert.True(store.Saved.StartWithWindows);

        vm.StartWithWindows = false;
        Assert.False(startup.Registered);
        Assert.Equal(1, startup.UnregisterCount);
    }

    [Fact]
    public void TrayPrefs_persist()
    {
        var store = new FakeUiStateStore();
        var vm = MakeSut(store: store);

        vm.StartMinimized = true;
        Assert.True(store.Saved.StartMinimized);

        vm.MinimizeToTrayOnClose = true;
        Assert.True(store.Saved.MinimizeToTrayOnClose);
    }

    [Fact]
    public void Load_seedsFromPersistedState_withoutReSaving()
    {
        var store = new FakeUiStateStore { ToLoad = new UiState { Theme = "Light", StartWithWindows = true } };

        var vm = MakeSut(store: store);

        Assert.Equal("Light", vm.SelectedTheme);
        Assert.True(vm.StartWithWindows);
        Assert.Equal(0, store.SaveCount); // seeding must not persist (no re-save loop)
    }

    [Fact]
    public async Task Integrity_verifiedOnlyWhenProxyRunning()
    {
        var helper = new FakeHelperClient
        {
            GetStatusHandler = _ => Task.FromResult<Result<StatusResponse>?>(
                Result<StatusResponse>.Ok(new StatusResponse(true, "r", false, false, IpcProtocol.Version, "1.0.0"))),
        };
        var vm = MakeSut(helper: helper);

        await vm.RefreshIntegrityCommand.ExecuteAsync(null);
        Assert.True(vm.IntegrityVerified);

        // Proxy NOT running → cannot attest, never verified (no false green).
        helper.GetStatusHandler = _ => Task.FromResult<Result<StatusResponse>?>(
            Result<StatusResponse>.Ok(new StatusResponse(false, "r", false, false, IpcProtocol.Version, "1.0.0")));
        await vm.RefreshIntegrityCommand.ExecuteAsync(null);
        Assert.False(vm.IntegrityVerified);
    }

    [Fact]
    public async Task Integrity_incompatibleProtocol_isNotVerified()
    {
        // A helper on a different protocol version cannot be trusted for ANY field (the F20 handshake), so
        // its ProxyRunning must NOT drive a green integrity verdict — never a false green from an untrusted helper.
        var helper = new FakeHelperClient
        {
            GetStatusHandler = _ => Task.FromResult<Result<StatusResponse>?>(
                Result<StatusResponse>.Ok(new StatusResponse(true, "r", false, false, IpcProtocol.Version + 1, "9.9.9"))),
        };
        var vm = MakeSut(helper: helper);

        await vm.RefreshIntegrityCommand.ExecuteAsync(null);

        Assert.False(vm.IntegrityVerified);
    }

    [Fact]
    public void StartWithWindows_registrationFails_revertsToggle_andDoesNotPersist()
    {
        var store = new FakeUiStateStore();
        var startup = new FakeStartup { RegisterResult = false }; // the Run-key write is rejected
        var vm = MakeSut(store: store, startup: startup);

        vm.StartWithWindows = true;

        Assert.False(vm.StartWithWindows);           // reverted to reality — no silent drift
        Assert.False(store.Saved.StartWithWindows);  // an intent the registry refused is never persisted
    }

    [Fact]
    public void Ctor_reconcilesRunKeyToPersistedIntent()
    {
        // Persisted intent = ON but the Run key was cleared out-of-band (Task Manager / regedit / AV) →
        // self-heal on load via the read-back seam, so a checked box truly means "launches at logon".
        var store = new FakeUiStateStore { ToLoad = new UiState { StartWithWindows = true } };
        var startup = new FakeStartup { Registered = false };

        _ = MakeSut(store: store, startup: startup);

        Assert.True(startup.Registered);
    }

    [Fact]
    public async Task Integrity_pathVersionSha_fromReader_andRehashReinvokes()
    {
        var integrity = new FakeIntegrityReader
        {
            Info = new ExeIntegrityInfo(@"C:\p\dnscrypt-proxy.exe", "2.1.16", "deadbeef", true),
        };
        var vm = MakeSut(integrity: integrity);

        await vm.RefreshIntegrityCommand.ExecuteAsync(null);
        Assert.Equal("deadbeef", vm.ProxySha256);
        Assert.Equal(@"C:\p\dnscrypt-proxy.exe", vm.ProxyExeDisplayPath);
        Assert.Equal("2.1.16", vm.ProxyVersion);

        await vm.RefreshIntegrityCommand.ExecuteAsync(null); // "Re-hash now" re-invokes the reader
        Assert.Equal(2, integrity.ReadCount);
    }
}
