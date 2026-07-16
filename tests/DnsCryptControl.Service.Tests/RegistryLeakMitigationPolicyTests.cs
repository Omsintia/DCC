using System;
using System.IO;
using System.Linq;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.State;
using DnsCryptControl.Service.Windows;
using DnsCryptControl.Service.Windows.Registry;
using DnsCryptControl.Service.Tests.Fakes;
using Microsoft.Win32;
using Xunit;

namespace DnsCryptControl.Service.Tests;

public class RegistryLeakMitigationPolicyTests : IDisposable
{
    private readonly string _temp = Path.Combine(
        Path.GetTempPath(), "DnsCryptLeakTest_" + Guid.NewGuid().ToString("N"));
    private readonly DnsBackupStore _backup;

    public RegistryLeakMitigationPolicyTests()
    {
        Directory.CreateDirectory(_temp);
        _backup = new DnsBackupStore(Path.Combine(_temp, "backup.json"));
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_temp)) Directory.Delete(_temp, recursive: true); } catch (IOException) { }
        GC.SuppressFinalize(this);
    }

    private static RegistryLeakMitigationPolicy Policy(
        InMemoryRegistryRoot reg,
        DnsBackupStore backup,
        RebootAdvisory restartResult = RebootAdvisory.None)
        => new(reg, backup, () => restartResult);

    // ---- Cycle 1: seam shape ----

    [Fact]
    public void Seam_isImplementable_andReadsValue()
    {
        var reg = new InMemoryRegistryRoot()
            .WithValue(
                @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
                "X", 7, RegistryValueKind.DWord);

        using var sub = reg.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters", writable: false);

        Assert.NotNull(sub);
        Assert.Equal(7, sub!.GetValue("X"));
        Assert.Equal(RegistryValueKind.DWord, sub.GetValueKind("X"));
    }

    [Fact]
    public void Seam_openSubKey_returnsNull_whenAbsent()
    {
        var reg = new InMemoryRegistryRoot();
        Assert.Null(reg.OpenSubKey(@"SOFTWARE\DoesNotExist", writable: false));
    }

    [Fact]
    public void Seam_createSubKey_isIdempotent_andWriteable()
    {
        var reg = new InMemoryRegistryRoot();
        using var sub1 = reg.CreateSubKey(@"SOFTWARE\Test");
        sub1.SetValue("V", 42, RegistryValueKind.DWord);

        using var sub2 = reg.OpenSubKey(@"SOFTWARE\Test", writable: false);
        Assert.NotNull(sub2);
        Assert.Equal(42, sub2!.GetValue("V"));
    }

    [Fact]
    public void Seam_deleteValue_whenAbsent_withThrowFalse_isNoop()
    {
        var reg = new InMemoryRegistryRoot().WithSubKey(@"SOFTWARE\Test");
        using var sub = reg.OpenSubKey(@"SOFTWARE\Test", writable: true)!;
        // Must not throw.
        sub.DeleteValue("NoSuchValue", throwIfMissing: false);
    }

    [Fact]
    public void Seam_getValueNames_andSubKeyNames()
    {
        var reg = new InMemoryRegistryRoot()
            .WithValue(@"SOFTWARE\Parent", "ValA", "x", RegistryValueKind.String)
            .WithValue(@"SOFTWARE\Parent", "ValB", "y", RegistryValueKind.String)
            .WithSubKey(@"SOFTWARE\Parent\Child");

        using var sub = reg.OpenSubKey(@"SOFTWARE\Parent", writable: false)!;
        Assert.Contains("ValA", sub.GetValueNames());
        Assert.Contains("ValB", sub.GetValueNames());
        Assert.Contains("Child", sub.GetSubKeyNames());
    }

    // ---- Cycle 2: AreLeakMitigationsEnabled + Enable ----

    [Fact]
    public void AreLeakMitigationsEnabled_trueOnlyWhenBothValuesAreOne()
    {
        var both = new InMemoryRegistryRoot()
            .WithValue(RegistryLeakMitigationPolicy.DnsClientSubKey,
                RegistryLeakMitigationPolicy.SmhnrValueName, 1, RegistryValueKind.DWord)
            .WithValue(RegistryLeakMitigationPolicy.DnscacheParametersSubKey,
                RegistryLeakMitigationPolicy.ParallelValueName, 1, RegistryValueKind.DWord);
        Assert.True(Policy(both, _backup).AreLeakMitigationsEnabled());

        var onlyOne = new InMemoryRegistryRoot()
            .WithValue(RegistryLeakMitigationPolicy.DnsClientSubKey,
                RegistryLeakMitigationPolicy.SmhnrValueName, 1, RegistryValueKind.DWord);
        Assert.False(Policy(onlyOne, _backup).AreLeakMitigationsEnabled());

        var none = new InMemoryRegistryRoot();
        Assert.False(Policy(none, _backup).AreLeakMitigationsEnabled());

        var zero = new InMemoryRegistryRoot()
            .WithValue(RegistryLeakMitigationPolicy.DnsClientSubKey,
                RegistryLeakMitigationPolicy.SmhnrValueName, 0, RegistryValueKind.DWord)
            .WithValue(RegistryLeakMitigationPolicy.DnscacheParametersSubKey,
                RegistryLeakMitigationPolicy.ParallelValueName, 0, RegistryValueKind.DWord);
        Assert.False(Policy(zero, _backup).AreLeakMitigationsEnabled());
    }

    [Fact]
    public void Enable_writesBothDwordsToOne()
    {
        var reg = new InMemoryRegistryRoot();

        var result = Policy(reg, _backup).SetLeakMitigations(true);

        Assert.True(result.Success);
        using var smhnrSub = reg.OpenSubKey(RegistryLeakMitigationPolicy.DnsClientSubKey, writable: false);
        Assert.NotNull(smhnrSub);
        Assert.Equal(1, smhnrSub!.GetValue(RegistryLeakMitigationPolicy.SmhnrValueName));
        Assert.Equal(RegistryValueKind.DWord,
            smhnrSub.GetValueKind(RegistryLeakMitigationPolicy.SmhnrValueName));

        using var parSub = reg.OpenSubKey(RegistryLeakMitigationPolicy.DnscacheParametersSubKey, writable: false);
        Assert.NotNull(parSub);
        Assert.Equal(1, parSub!.GetValue(RegistryLeakMitigationPolicy.ParallelValueName));
        Assert.Equal(RegistryValueKind.DWord,
            parSub.GetValueKind(RegistryLeakMitigationPolicy.ParallelValueName));
    }

    [Fact]
    public void Enable_capturesPriorAbsentValues_intoBackup_asExistedFalse()
    {
        var reg = new InMemoryRegistryRoot(); // neither value present

        Policy(reg, _backup).SetLeakMitigations(true);

        var state = _backup.Load();
        Assert.NotNull(state);
        var smhnr = state!.RegistryValues.Single(r =>
            r.ValueName == RegistryLeakMitigationPolicy.SmhnrValueName);
        Assert.Equal("HKLM", smhnr.Hive);
        Assert.Equal(RegistryLeakMitigationPolicy.DnsClientSubKey, smhnr.SubKey);
        Assert.False(smhnr.Existed);
        Assert.Null(smhnr.Data);

        var par = state.RegistryValues.Single(r =>
            r.ValueName == RegistryLeakMitigationPolicy.ParallelValueName);
        Assert.False(par.Existed);
        Assert.Null(par.Data);
    }

    [Fact]
    public void Enable_capturesPriorExistingValue_withExactKindAndData()
    {
        var reg = new InMemoryRegistryRoot()
            .WithValue(RegistryLeakMitigationPolicy.DnscacheParametersSubKey,
                RegistryLeakMitigationPolicy.ParallelValueName, 0, RegistryValueKind.DWord);

        Policy(reg, _backup).SetLeakMitigations(true);

        var par = _backup.Load()!.RegistryValues.Single(r =>
            r.ValueName == RegistryLeakMitigationPolicy.ParallelValueName);
        Assert.True(par.Existed);
        Assert.Equal(RegistryValueKind.DWord, par.Kind);
        Assert.Equal("0", par.Data);
    }

    [Fact]
    public void Enable_doesNotOverwriteExistingUnrevertedBackupSlice()
    {
        // First capture: both values were absent.
        var reg1 = new InMemoryRegistryRoot();
        Policy(reg1, _backup).SetLeakMitigations(true);

        // Second enable, now the values are present (=1); must NOT replace the pristine capture.
        var reg2 = new InMemoryRegistryRoot()
            .WithValue(RegistryLeakMitigationPolicy.DnsClientSubKey,
                RegistryLeakMitigationPolicy.SmhnrValueName, 1, RegistryValueKind.DWord)
            .WithValue(RegistryLeakMitigationPolicy.DnscacheParametersSubKey,
                RegistryLeakMitigationPolicy.ParallelValueName, 1, RegistryValueKind.DWord);
        Policy(reg2, _backup).SetLeakMitigations(true);

        var par = _backup.Load()!.RegistryValues.Single(r =>
            r.ValueName == RegistryLeakMitigationPolicy.ParallelValueName);
        Assert.False(par.Existed); // still the original pristine "was absent" capture
    }

    [Fact]
    public void Enable_whenDnscacheRestartFails_returnsRebootRecommended()
    {
        var reg = new InMemoryRegistryRoot();
        var result = Policy(reg, _backup, RebootAdvisory.Recommended).SetLeakMitigations(true);
        Assert.True(result.Success);
        Assert.Equal(RebootAdvisory.Recommended, result.Value);
    }

    // ---- Cycle 3: Disable / revert ----

    [Fact]
    public void Disable_whenPriorWasAbsent_deletesBothValues()
    {
        var reg = new InMemoryRegistryRoot(); // both absent before enable
        var policy = Policy(reg, _backup);
        policy.SetLeakMitigations(true); // captures Existed=false for both, writes =1

        var result = policy.SetLeakMitigations(false);

        Assert.True(result.Success);
        using var smhnrSub = reg.OpenSubKey(RegistryLeakMitigationPolicy.DnsClientSubKey, writable: false);
        Assert.True(smhnrSub is null || smhnrSub.GetValue(RegistryLeakMitigationPolicy.SmhnrValueName) is null);

        using var parSub = reg.OpenSubKey(RegistryLeakMitigationPolicy.DnscacheParametersSubKey, writable: false);
        Assert.True(parSub is null || parSub.GetValue(RegistryLeakMitigationPolicy.ParallelValueName) is null);
    }

    [Fact]
    public void Disable_whenPriorExisted_restoresExactKindAndData()
    {
        // Parallel value existed with data=0 before enable.
        var reg = new InMemoryRegistryRoot()
            .WithValue(RegistryLeakMitigationPolicy.DnscacheParametersSubKey,
                RegistryLeakMitigationPolicy.ParallelValueName, 0, RegistryValueKind.DWord);
        var policy = Policy(reg, _backup);
        policy.SetLeakMitigations(true); // captures parallel Existed=true,kind=DWord,data="0"; smhnr absent

        var result = policy.SetLeakMitigations(false);

        Assert.True(result.Success);
        // parallel restored to its prior 0/DWord:
        using var parSub = reg.OpenSubKey(RegistryLeakMitigationPolicy.DnscacheParametersSubKey, writable: false);
        Assert.NotNull(parSub);
        Assert.Equal(0, parSub!.GetValue(RegistryLeakMitigationPolicy.ParallelValueName));
        Assert.Equal(RegistryValueKind.DWord,
            parSub.GetValueKind(RegistryLeakMitigationPolicy.ParallelValueName));
        // smhnr was absent prior -> deleted:
        using var smhnrSub = reg.OpenSubKey(RegistryLeakMitigationPolicy.DnsClientSubKey, writable: false);
        Assert.True(smhnrSub is null || smhnrSub.GetValue(RegistryLeakMitigationPolicy.SmhnrValueName) is null);
    }

    [Fact]
    public void Disable_clearsTheRegistrySliceFromBackup()
    {
        var reg = new InMemoryRegistryRoot();
        var policy = Policy(reg, _backup);
        policy.SetLeakMitigations(true);

        policy.SetLeakMitigations(false);

        var state = _backup.Load();
        // After revert the registry slice is emptied (file may persist for other slices).
        Assert.True(state is null || state.RegistryValues.Count == 0);
    }

    [Fact]
    public void Disable_whenNoBackupSlice_isIdempotentNoop()
    {
        var reg = new InMemoryRegistryRoot(); // nothing captured, nothing written
        var result = Policy(reg, _backup).SetLeakMitigations(false);

        Assert.True(result.Success);
        // No values were written (reg has no values at all).
        Assert.Null(reg.OpenSubKey(RegistryLeakMitigationPolicy.DnsClientSubKey, writable: false));
        Assert.Null(reg.OpenSubKey(RegistryLeakMitigationPolicy.DnscacheParametersSubKey, writable: false));
    }
}
