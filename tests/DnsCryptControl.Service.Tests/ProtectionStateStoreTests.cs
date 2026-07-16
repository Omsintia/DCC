using System;
using System.IO;
using DnsCryptControl.Service.State;
using Xunit;

namespace DnsCryptControl.Service.Tests;

public class ProtectionStateStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "DnsCryptProtTest_" + Guid.NewGuid().ToString("N"));
    private readonly string _file;
    private readonly ProtectionStateStore _store;

    public ProtectionStateStoreTests()
    {
        _file = Path.Combine(_dir, "state", "protection.json");
        _store = new ProtectionStateStore(_file);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true); } catch (IOException) { }
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void Load_whenAbsent_returnsAllFalse()
    {
        var state = _store.Load();
        Assert.False(state.ProtectionEnabled);
        Assert.False(state.KillSwitchEnabled);
        Assert.False(state.LeakMitigationsEnabled);
    }

    [Fact]
    public void Save_thenLoad_roundTrips()
    {
        _store.Save(new ProtectionState(ProtectionEnabled: true, KillSwitchEnabled: false, LeakMitigationsEnabled: true));

        var state = _store.Load();
        Assert.True(state.ProtectionEnabled);
        Assert.False(state.KillSwitchEnabled);
        Assert.True(state.LeakMitigationsEnabled);
    }

    [Fact]
    public void Save_isAtomic_leavesNoTempFile()
    {
        _store.Save(new ProtectionState(true, true, true));
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(_file)!, "*.tmp"));
    }

    [Fact]
    public void Load_whenFileCorrupt_returnsAllFalse()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_file)!);
        File.WriteAllText(_file, "{ not valid json");
        var state = _store.Load();
        Assert.False(state.ProtectionEnabled);
        Assert.False(state.KillSwitchEnabled);
        Assert.False(state.LeakMitigationsEnabled);
    }

    // ---- B3: failure-VISIBLE read (TryLoad). Load() keeps its never-throws default-on-failure
    // contract untouched (BootReconciler/NetworkChangeWatcher/handlers depend on it); TryLoad
    // exists so ENFORCEMENT callers (the config write policy) can distinguish "fresh install,
    // legitimately unprotected" (absent → true + default) from "state file present but
    // unreadable/corrupt — protection status UNKNOWN" (→ false, caller fails closed). ----

    [Fact]
    public void TryLoad_whenAbsent_returnsTrue_withAllFalseDefault()
    {
        var ok = _store.TryLoad(out var state);

        Assert.True(ok);
        Assert.False(state.ProtectionEnabled);
        Assert.False(state.KillSwitchEnabled);
        Assert.False(state.LeakMitigationsEnabled);
    }

    [Fact]
    public void TryLoad_whenFileValid_returnsTrue_withPersistedValues()
    {
        _store.Save(new ProtectionState(ProtectionEnabled: true, KillSwitchEnabled: false, LeakMitigationsEnabled: true));

        var ok = _store.TryLoad(out var state);

        Assert.True(ok);
        Assert.True(state.ProtectionEnabled);
        Assert.False(state.KillSwitchEnabled);
        Assert.True(state.LeakMitigationsEnabled);
    }

    [Fact]
    public void TryLoad_whenFileCorrupt_returnsFalse_withAllFalseOut()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_file)!);
        File.WriteAllText(_file, "{ not valid json");

        var ok = _store.TryLoad(out var state);

        Assert.False(ok);
        Assert.False(state.ProtectionEnabled); // out value is the safe default, never null
    }

    [Fact]
    public void TryLoad_whenFileIsJsonNull_returnsFalse()
    {
        // A literal "null" deserializes cleanly but carries NO protection state — for a
        // failure-visible read that is indistinguishable from corrupt: report it.
        Directory.CreateDirectory(Path.GetDirectoryName(_file)!);
        File.WriteAllText(_file, "null");

        var ok = _store.TryLoad(out var state);

        Assert.False(ok);
        Assert.False(state.ProtectionEnabled);
    }
}
