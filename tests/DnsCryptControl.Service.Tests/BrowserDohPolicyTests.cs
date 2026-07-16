using System;
using System.IO;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.State;
using DnsCryptControl.Service.Tests.Fakes;
using DnsCryptControl.Service.Windows;
using Microsoft.Win32;
using Xunit;

namespace DnsCryptControl.Service.Tests;

public class BrowserDohPolicyTests : IDisposable
{
    private readonly string _temp =
        Path.Combine(Path.GetTempPath(), "DnsCryptCtlDoh_" + Guid.NewGuid().ToString("N"));
    private readonly DnsBackupStore _backup;

    public BrowserDohPolicyTests()
    {
        Directory.CreateDirectory(_temp);
        _backup = new DnsBackupStore(Path.Combine(_temp, "backup.json"));
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_temp)) Directory.Delete(_temp, recursive: true); } catch (IOException) { }
        GC.SuppressFinalize(this);
    }

    private const string ChromeKey = @"SOFTWARE\Policies\Google\Chrome";
    private const string EdgeKey = @"SOFTWARE\Policies\Microsoft\Edge";
    private const string FirefoxDohKey = @"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS";

    private static object? Read(InMemoryRegistryRoot r, string key, string name) =>
        r.OpenSubKey(key, false)?.GetValue(name);

    // ---- Cycle 1: capture + write ----

    [Fact]
    public void Enable_onCleanMachine_writesChromeEdgeOff_andFirefoxDisabledLocked()
    {
        var reg = new InMemoryRegistryRoot();
        var policy = new BrowserDohPolicy(reg, _backup);

        var result = policy.SetBrowserDohPolicy(true);

        Assert.True(result.Success);
        Assert.Equal("off", Read(reg, ChromeKey, "DnsOverHttpsMode"));
        Assert.Equal("off", Read(reg, EdgeKey, "DnsOverHttpsMode"));
        Assert.Equal(0, Read(reg, FirefoxDohKey, "Enabled"));
        Assert.Equal(1, Read(reg, FirefoxDohKey, "Locked"));
    }

    [Fact]
    public void Enable_capturesPriorAbsence_intoBackupBrowserSlice()
    {
        var reg = new InMemoryRegistryRoot();
        var policy = new BrowserDohPolicy(reg, _backup);

        policy.SetBrowserDohPolicy(true);

        var state = _backup.Load();
        Assert.NotNull(state);
        // 2 string values + 2 DWORD values + 1 subkey marker = 5 captured entries; all absent before.
        Assert.Equal(5, state!.BrowserPolicyValues.Count);
        Assert.Contains(state.BrowserPolicyValues, b =>
            b.ValueName == "DnsOverHttpsMode" &&
            b.SubKey == BrowserDohPolicy.ChromeKey && !b.Existed && b.Data is null);
        Assert.Contains(state.BrowserPolicyValues, b =>
            b.ValueName == "DnsOverHttpsMode" &&
            b.SubKey == BrowserDohPolicy.EdgeKey && !b.Existed && b.Data is null);
        Assert.Contains(state.BrowserPolicyValues, b =>
            b.ValueName == "Enabled" && b.SubKey == BrowserDohPolicy.FirefoxDohKey && !b.Existed);
        Assert.Contains(state.BrowserPolicyValues, b =>
            b.ValueName == "Locked" && b.SubKey == BrowserDohPolicy.FirefoxDohKey && !b.Existed);
        Assert.Contains(state.BrowserPolicyValues, b =>
            b.ValueName == "" && b.SubKey == BrowserDohPolicy.FirefoxDohKey && !b.Existed); // subkey marker
    }

    // ---- Cycle 2: applied-predicate + revert ----

    [Fact]
    public void IsApplied_isTrue_onlyWhenBothChromeAndEdgeAreOff()
    {
        var reg = new InMemoryRegistryRoot();
        var policy = new BrowserDohPolicy(reg, _backup);

        Assert.False(policy.IsBrowserDohPolicyApplied()); // nothing written

        using (var k = reg.CreateSubKey(BrowserDohPolicy.ChromeKey))
            k.SetValue("DnsOverHttpsMode", "off", RegistryValueKind.String);
        Assert.False(policy.IsBrowserDohPolicyApplied()); // Chrome off, Edge absent

        using (var k = reg.CreateSubKey(BrowserDohPolicy.EdgeKey))
            k.SetValue("DnsOverHttpsMode", "off", RegistryValueKind.String);
        Assert.True(policy.IsBrowserDohPolicyApplied()); // both off

        using (var k = reg.CreateSubKey(BrowserDohPolicy.EdgeKey))
            k.SetValue("DnsOverHttpsMode", "automatic", RegistryValueKind.String);
        Assert.False(policy.IsBrowserDohPolicyApplied()); // Edge no longer off
    }

    [Fact]
    public void Revert_onCleanMachineCapture_deletesOnlyValuesWeCreated_andRemovesFirefoxLeaf()
    {
        var reg = new InMemoryRegistryRoot();
        var policy = new BrowserDohPolicy(reg, _backup);

        policy.SetBrowserDohPolicy(true);
        Assert.True(policy.IsBrowserDohPolicyApplied());

        var revert = policy.SetBrowserDohPolicy(false);

        Assert.True(revert.Success);
        Assert.Null(Read(reg, ChromeKey, "DnsOverHttpsMode")); // value we created -> deleted
        Assert.Null(Read(reg, EdgeKey, "DnsOverHttpsMode"));
        // Parent policy keys are NEVER deleted, only the values.
        Assert.NotNull(reg.OpenSubKey(ChromeKey, false));
        Assert.NotNull(reg.OpenSubKey(EdgeKey, false));
        // Firefox \DNSOverHTTPS leaf we created (and is now empty) -> removed.
        Assert.Null(reg.OpenSubKey(FirefoxDohKey, false));
        // Browser slice cleared after revert. It was the only captured slice, so clearing it routes
        // through SaveOrDeleteIfEmpty and removes the backup file (zero residue).
        var afterRevert = _backup.Load();
        Assert.True(afterRevert is null || afterRevert.BrowserPolicyValues.Count == 0);
        Assert.False(_backup.Exists);
    }

    [Fact]
    public void Revert_restoresExactPriorValueAndKind_whenValueExistedBefore()
    {
        var reg = new InMemoryRegistryRoot();
        // Pre-existing admin Chrome policy: mode "secure".
        using (var k = reg.CreateSubKey(ChromeKey))
            k.SetValue("DnsOverHttpsMode", "secure", RegistryValueKind.String);
        // Pre-existing Firefox leaf with an admin Enabled=1.
        using (var k = reg.CreateSubKey(FirefoxDohKey))
            k.SetValue("Enabled", 1, RegistryValueKind.DWord);

        var policy = new BrowserDohPolicy(reg, _backup);
        policy.SetBrowserDohPolicy(true);
        Assert.Equal("off", Read(reg, ChromeKey, "DnsOverHttpsMode"));
        Assert.Equal(0, Read(reg, FirefoxDohKey, "Enabled"));

        policy.SetBrowserDohPolicy(false);

        Assert.Equal("secure", Read(reg, ChromeKey, "DnsOverHttpsMode")); // exact prior restored
        Assert.Equal(1, Read(reg, FirefoxDohKey, "Enabled"));             // exact prior restored
        Assert.Null(Read(reg, FirefoxDohKey, "Locked"));                  // Locked we created -> deleted
        Assert.NotNull(reg.OpenSubKey(FirefoxDohKey, false));             // leaf pre-existed -> kept
    }

    [Fact]
    public void Revert_isIdempotent_whenNothingWasApplied()
    {
        var reg = new InMemoryRegistryRoot();
        var policy = new BrowserDohPolicy(reg, _backup);

        var revert = policy.SetBrowserDohPolicy(false);

        Assert.True(revert.Success); // no backup slice -> treated as already reverted
    }
}
