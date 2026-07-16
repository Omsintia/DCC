using System;
using System.Collections.Generic;
using System.IO;
using DnsCryptControl.Service.State;
using Microsoft.Win32;
using Xunit;

namespace DnsCryptControl.Service.Tests;

public class DnsBackupStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "DnsCryptBackupTest_" + Guid.NewGuid().ToString("N"));
    private readonly string _file;
    private readonly DnsBackupStore _store;

    public DnsBackupStoreTests()
    {
        _file = Path.Combine(_dir, "state", "backup.json");
        _store = new DnsBackupStore(_file);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true); } catch (IOException) { }
        GC.SuppressFinalize(this);
    }

    private static DnsBackupState Empty() => new()
    {
        SchemaVersion = DnsBackupState.CurrentSchemaVersion,
        CreatedUtc = DateTimeOffset.UtcNow.ToString("O"),
        Interfaces = Array.Empty<InterfaceDnsBackup>(),
        RegistryValues = Array.Empty<RegistryValueBackup>(),
        AddedFirewallRuleNames = Array.Empty<string>(),
        BrowserPolicyValues = Array.Empty<RegistryValueBackup>(),
    };

    [Fact]
    public void CurrentSchemaVersion_isOne()
    {
        Assert.Equal(1, DnsBackupState.CurrentSchemaVersion);
    }

    [Fact]
    public void Load_whenAbsent_returnsNull_andExistsFalse()
    {
        Assert.False(_store.Exists);
        Assert.Null(_store.Load());
    }

    [Fact]
    public void Save_thenLoad_roundTripsAllSlices()
    {
        var state = Empty() with
        {
            Interfaces = new[]
            {
                new InterfaceDnsBackup
                {
                    InterfaceGuid = "{29FB4A98-6063-4242-A6B6-245A63630B12}",
                    WasIpv4Static = true,
                    Ipv4Servers = new[] { "1.1.1.1", "8.8.8.8" },
                    WasIpv6Static = false,
                    Ipv6Servers = null,
                },
            },
            RegistryValues = new[]
            {
                new RegistryValueBackup
                {
                    Hive = "HKLM",
                    SubKey = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
                    ValueName = "DisableSmartNameResolution",
                    Existed = false,
                    Kind = RegistryValueKind.DWord,
                    Data = null,
                },
            },
            AddedFirewallRuleNames = new[] { "DnsCryptControl Block UDP 53" },
        };

        _store.Save(state);
        Assert.True(_store.Exists);

        var loaded = _store.Load();
        Assert.NotNull(loaded);
        Assert.Equal(1, loaded!.SchemaVersion);
        Assert.Single(loaded.Interfaces);
        Assert.Equal("{29FB4A98-6063-4242-A6B6-245A63630B12}", loaded.Interfaces[0].InterfaceGuid);
        Assert.True(loaded.Interfaces[0].WasIpv4Static);
        Assert.Equal(new[] { "1.1.1.1", "8.8.8.8" }, loaded.Interfaces[0].Ipv4Servers);
        Assert.False(loaded.Interfaces[0].WasIpv6Static);
        Assert.Null(loaded.Interfaces[0].Ipv6Servers);
        Assert.Single(loaded.RegistryValues);
        Assert.False(loaded.RegistryValues[0].Existed);
        Assert.Equal(RegistryValueKind.DWord, loaded.RegistryValues[0].Kind);
        Assert.Equal(new[] { "DnsCryptControl Block UDP 53" }, loaded.AddedFirewallRuleNames);
    }

    [Fact]
    public void Save_isAtomic_leavesNoTempFile()
    {
        _store.Save(Empty());
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(_file)!, "*.tmp"));
    }

    [Fact]
    public void Delete_removesFile_andExistsBecomesFalse()
    {
        _store.Save(Empty());
        Assert.True(_store.Exists);
        _store.Delete();
        Assert.False(_store.Exists);
        Assert.Null(_store.Load());
    }

    [Fact]
    public void CaptureInterfacesIfAbsent_writesOnce_thenDoesNotOverwrite()
    {
        var first = new[]
        {
            new InterfaceDnsBackup { InterfaceGuid = "{A}", WasIpv4Static = true,
                Ipv4Servers = new[] { "1.1.1.1" }, WasIpv6Static = false, Ipv6Servers = null },
        };
        _store.CaptureInterfacesIfAbsent(() => first);

        // Second capture supplies DIFFERENT data; the un-restored pristine slice must NOT be overwritten.
        _store.CaptureInterfacesIfAbsent(() => new[]
        {
            new InterfaceDnsBackup { InterfaceGuid = "{B}", WasIpv4Static = false,
                Ipv4Servers = null, WasIpv6Static = false, Ipv6Servers = null },
        });

        var loaded = _store.Load();
        Assert.NotNull(loaded);
        Assert.Single(loaded!.Interfaces);
        Assert.Equal("{A}", loaded.Interfaces[0].InterfaceGuid);
    }

    [Fact]
    public void CaptureRegistryValuesIfAbsent_isIndependentOfInterfaceSlice()
    {
        _store.CaptureInterfacesIfAbsent(() => new[]
        {
            new InterfaceDnsBackup { InterfaceGuid = "{A}", WasIpv4Static = false,
                Ipv4Servers = null, WasIpv6Static = false, Ipv6Servers = null },
        });
        _store.CaptureRegistryValuesIfAbsent(() => new[]
        {
            new RegistryValueBackup { Hive = "HKLM", SubKey = @"SYSTEM\X", ValueName = "V",
                Existed = false, Kind = RegistryValueKind.DWord, Data = null },
        });

        var loaded = _store.Load();
        Assert.NotNull(loaded);
        Assert.Single(loaded!.Interfaces);
        Assert.Single(loaded.RegistryValues);
    }

    [Fact]
    public void Load_whenFileCorrupt_returnsNull()
    {
        // Arrange: create the directory and write garbage JSON so the file exists but is unreadable.
        Directory.CreateDirectory(Path.GetDirectoryName(_file)!);
        File.WriteAllText(_file, "{ not valid json");

        // Act + Assert: Load must return null (corrupt backup reads as "no backup") — must not throw.
        Assert.Null(_store.Load());
    }

    [Fact]
    public void CaptureFirewallRulesIfAbsent_secondCall_doesNotOverwrite()
    {
        var first = new[] { "DnsCryptControl Block UDP 53" };
        _store.CaptureFirewallRulesIfAbsent(() => first);

        // Second call supplies DIFFERENT data; the pristine first capture must NOT be overwritten.
        _store.CaptureFirewallRulesIfAbsent(() => new[] { "SomeOtherRule" });

        var loaded = _store.Load();
        Assert.NotNull(loaded);
        Assert.Single(loaded!.AddedFirewallRuleNames);
        Assert.Equal("DnsCryptControl Block UDP 53", loaded.AddedFirewallRuleNames[0]);
    }

    [Fact]
    public void SaveOrDeleteIfEmpty_whenAllSlicesEmpty_deletesFile()
    {
        // Pre-existing backup with one slice, then "clear the last remaining slice" -> file must vanish.
        _store.Save(Empty() with { AddedFirewallRuleNames = new[] { "DnsCryptControl KillSwitch UDP53" } });
        Assert.True(_store.Exists);

        _store.SaveOrDeleteIfEmpty(Empty()); // all four slices empty
        Assert.False(_store.Exists);         // zero residue
        Assert.Null(_store.Load());
    }

    [Fact]
    public void SaveOrDeleteIfEmpty_whenAnySliceNonEmpty_keepsFile()
    {
        // Clearing a non-last slice (interfaces) while another slice (firewall) remains must KEEP the file.
        var state = Empty() with
        {
            AddedFirewallRuleNames = new[] { "DnsCryptControl KillSwitch UDP53" },
        };

        _store.SaveOrDeleteIfEmpty(state);
        Assert.True(_store.Exists);

        var loaded = _store.Load();
        Assert.NotNull(loaded);
        Assert.Single(loaded!.AddedFirewallRuleNames);
        Assert.Empty(loaded.Interfaces);
    }

    [Fact]
    public void SaveOrDeleteIfEmpty_whenNoFileAndEmptyState_isNoOp()
    {
        // No backup file present + empty state => delete-path no-ops (no throw, still absent).
        Assert.False(_store.Exists);
        _store.SaveOrDeleteIfEmpty(Empty());
        Assert.False(_store.Exists);
    }

    [Fact]
    public void CaptureBrowserPolicyIfAbsent_secondCall_doesNotOverwrite()
    {
        var first = new[]
        {
            new RegistryValueBackup { Hive = "HKLM", SubKey = @"SOFTWARE\Policies\Chrome",
                ValueName = "DnsOverHttpsMode", Existed = false, Kind = RegistryValueKind.String, Data = null },
        };
        _store.CaptureBrowserPolicyIfAbsent(() => first);

        // Second call supplies DIFFERENT data; the pristine first capture must NOT be overwritten.
        _store.CaptureBrowserPolicyIfAbsent(() => new[]
        {
            new RegistryValueBackup { Hive = "HKLM", SubKey = @"SOFTWARE\Policies\Firefox",
                ValueName = "DNSOverHTTPS", Existed = false, Kind = RegistryValueKind.String, Data = null },
        });

        var loaded = _store.Load();
        Assert.NotNull(loaded);
        Assert.Single(loaded!.BrowserPolicyValues);
        Assert.Equal(@"SOFTWARE\Policies\Chrome", loaded.BrowserPolicyValues[0].SubKey);
    }
}
