using System;
using System.IO;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.State;
using Xunit;

namespace DnsCryptControl.Service.Tests;

/// <summary>Unit tests for <see cref="ProtectionStateWriter"/> (the Service-side
/// <see cref="IProtectionStateWriter"/> implementation) and the new
/// <see cref="ProtectionStateStore.Update"/> atomic read-modify-write helper.</summary>
public class ProtectionStateWriterTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "DnsCryptWriterTest_" + Guid.NewGuid().ToString("N"));
    private readonly string _file;
    private readonly ProtectionStateStore _store;
    private readonly ProtectionStateWriter _writer;

    public ProtectionStateWriterTests()
    {
        _file = Path.Combine(_dir, "state", "protection.json");
        _store = new ProtectionStateStore(_file);
        _writer = new ProtectionStateWriter(_store);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true); } catch (IOException) { }
        GC.SuppressFinalize(this);
    }

    // ── ProtectionStateStore.Update tests ─────────────────────────────────────

    [Fact]
    public void Update_transforms_and_persists_atomically()
    {
        _store.Save(new ProtectionState(ProtectionEnabled: true, KillSwitchEnabled: false, LeakMitigationsEnabled: false));
        var returned = _store.Update(s => s with { KillSwitchEnabled = true });
        var loaded = _store.Load();

        Assert.True(returned.KillSwitchEnabled);
        Assert.True(loaded.KillSwitchEnabled);
        Assert.True(loaded.ProtectionEnabled); // untouched
        Assert.False(loaded.LeakMitigationsEnabled); // untouched
    }

    [Fact]
    public void Update_on_absent_file_starts_from_allFalse_default()
    {
        var returned = _store.Update(s => s with { ProtectionEnabled = true });
        var loaded = _store.Load();

        Assert.True(returned.ProtectionEnabled);
        Assert.True(loaded.ProtectionEnabled);
        Assert.False(loaded.KillSwitchEnabled);
        Assert.False(loaded.LeakMitigationsEnabled);
    }

    [Fact]
    public void Update_returns_new_state()
    {
        var returned = _store.Update(s => new ProtectionState(true, true, true));
        Assert.True(returned.ProtectionEnabled);
        Assert.True(returned.KillSwitchEnabled);
        Assert.True(returned.LeakMitigationsEnabled);
    }

    [Fact]
    public void Update_rejects_null_transform()
    {
        Assert.Throws<ArgumentNullException>(() => _store.Update(null!));
    }

    [Fact]
    public void Update_rejects_transform_returning_null()
    {
        Assert.Throws<ArgumentNullException>(() => _store.Update(_ => null!));
    }

    // ── ProtectionStateWriter ctor ─────────────────────────────────────────────

    [Fact]
    public void Ctor_rejects_null_store()
    {
        Assert.Throws<ArgumentNullException>(() => new ProtectionStateWriter(null!));
    }

    // ── EnableProtection ──────────────────────────────────────────────────────

    [Fact]
    public void EnableProtection_on_fresh_store_sets_ProtectionEnabled_true_and_others_false()
    {
        var result = _writer.EnableProtection();
        var state = _store.Load();

        Assert.True(result.Success);
        Assert.True(state.ProtectionEnabled);
        Assert.False(state.KillSwitchEnabled);
        Assert.False(state.LeakMitigationsEnabled);
    }

    [Fact]
    public void EnableProtection_preserves_other_fields()
    {
        _store.Save(new ProtectionState(false, KillSwitchEnabled: true, LeakMitigationsEnabled: true));

        var result = _writer.EnableProtection();
        var state = _store.Load();

        Assert.True(result.Success);
        Assert.True(state.ProtectionEnabled);
        Assert.True(state.KillSwitchEnabled);
        Assert.True(state.LeakMitigationsEnabled);
    }

    // ── DisableProtection ─────────────────────────────────────────────────────

    [Fact]
    public void DisableProtection_clears_ProtectionEnabled_and_preserves_others()
    {
        _store.Save(new ProtectionState(true, KillSwitchEnabled: true, LeakMitigationsEnabled: true));

        var result = _writer.DisableProtection();
        var state = _store.Load();

        Assert.True(result.Success);
        Assert.False(state.ProtectionEnabled);
        Assert.True(state.KillSwitchEnabled);
        Assert.True(state.LeakMitigationsEnabled);
    }

    // ── SetKillSwitchEnabled ──────────────────────────────────────────────────

    [Fact]
    public void SetKillSwitchEnabled_true_flips_only_KillSwitchEnabled()
    {
        _store.Save(new ProtectionState(true, false, true));

        var result = _writer.SetKillSwitchEnabled(true);
        var state = _store.Load();

        Assert.True(result.Success);
        Assert.True(state.KillSwitchEnabled);
        Assert.True(state.ProtectionEnabled);
        Assert.True(state.LeakMitigationsEnabled);
    }

    [Fact]
    public void SetKillSwitchEnabled_false_clears_only_KillSwitchEnabled()
    {
        _store.Save(new ProtectionState(true, true, true));

        var result = _writer.SetKillSwitchEnabled(false);
        var state = _store.Load();

        Assert.True(result.Success);
        Assert.False(state.KillSwitchEnabled);
        Assert.True(state.ProtectionEnabled);
        Assert.True(state.LeakMitigationsEnabled);
    }

    // ── SetLeakMitigationsEnabled ─────────────────────────────────────────────

    [Fact]
    public void SetLeakMitigationsEnabled_true_flips_only_LeakMitigationsEnabled()
    {
        _store.Save(new ProtectionState(true, true, false));

        var result = _writer.SetLeakMitigationsEnabled(true);
        var state = _store.Load();

        Assert.True(result.Success);
        Assert.True(state.LeakMitigationsEnabled);
        Assert.True(state.ProtectionEnabled);
        Assert.True(state.KillSwitchEnabled);
    }

    [Fact]
    public void SetLeakMitigationsEnabled_false_clears_only_LeakMitigationsEnabled()
    {
        _store.Save(new ProtectionState(true, true, true));

        var result = _writer.SetLeakMitigationsEnabled(false);
        var state = _store.Load();

        Assert.True(result.Success);
        Assert.False(state.LeakMitigationsEnabled);
        Assert.True(state.ProtectionEnabled);
        Assert.True(state.KillSwitchEnabled);
    }

    // ── Persist-failure path ──────────────────────────────────────────────────

    [Fact]
    public void EnableProtection_fails_gracefully_when_path_is_an_existing_directory()
    {
        // Point the store at a path that IS a directory; the atomic write fails closed.
        var dirAsFile = Path.Combine(_dir, "is-a-directory");
        Directory.CreateDirectory(dirAsFile);
        // The temp write succeeds, but the final File.Move/Replace ONTO the directory path throws
        // (UnauthorizedAccessException or IOException) — ProtectionStateWriter.Persist catches both
        // and maps to OperationFailed.
        var badStore = new ProtectionStateStore(dirAsFile);
        var writer = new ProtectionStateWriter(badStore);

        var result = writer.EnableProtection();

        Assert.False(result.Success);
        Assert.Equal(PlatformErrorKind.OperationFailed, result.Error);
    }
}
