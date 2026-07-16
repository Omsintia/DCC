using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Versioning;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.State;
using DnsCryptControl.Service.Windows;
using Xunit;

namespace DnsCryptControl.Service.Tests;

[SupportedOSPlatform("windows10.0.19041")]
public class WindowsDnsAdapterConfiguratorTests
{
    // ---- fakes for the two OS seams ----

    private sealed class FakeQuery : INetworkInterfaceQuery
    {
        public List<AdapterInfo> Adapters { get; } = new();
        public IReadOnlyList<AdapterInfo> GetAdapters() => Adapters;
    }

    private sealed record SetCall(Guid Guid, string? Server, bool Ipv6, bool Cleared);

    private sealed class FakeSetter : IInterfaceDnsSetter
    {
        public List<SetCall> Calls { get; } = new();
        public uint FailWith { get; set; }

        public uint SetNameServer(Guid interfaceGuid, string serverList, bool ipv6)
        {
            Calls.Add(new SetCall(interfaceGuid, serverList, ipv6, Cleared: false));
            return FailWith;
        }

        public uint ClearToDhcp(Guid interfaceGuid, bool ipv6)
        {
            Calls.Add(new SetCall(interfaceGuid, null, ipv6, Cleared: true));
            return FailWith;
        }
    }

    [Fact]
    public void Seams_areImplementable_andExposeExpectedShapes()
    {
        var guid = Guid.NewGuid();
        var query = new FakeQuery();
        query.Adapters.Add(new AdapterInfo(
            guid,
            "Ethernet0",
            System.Net.NetworkInformation.NetworkInterfaceType.Ethernet,
            new[] { "1.1.1.1" }));

        INetworkInterfaceQuery q = query;
        Assert.Single(q.GetAdapters());

        IInterfaceDnsSetter s = new FakeSetter();
        Assert.Equal(0u, s.SetNameServer(guid, "127.0.0.1", ipv6: false));
        Assert.Equal(0u, s.ClearToDhcp(guid, ipv6: true));
    }

    // ---- Cycle 2: Apply helpers ----

    private static DnsBackupStore TempStore(out string path)
    {
        path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "dcc-b2-" + Guid.NewGuid().ToString("N") + ".json");
        return new DnsBackupStore(path);
    }

    private static AdapterInfo Eth(Guid g, params string[] dns) =>
        new(g, "Ethernet0", System.Net.NetworkInformation.NetworkInterfaceType.Ethernet, dns);

    [Fact]
    public void Apply_setsLoopbackV4andV6_onEachEligibleAdapter_andSkipsLoopback()
    {
        var eth = Guid.NewGuid();
        var loop = Guid.NewGuid();
        var query = new FakeQuery();
        query.Adapters.Add(Eth(eth, "8.8.8.8"));
        query.Adapters.Add(new AdapterInfo(loop, "Loopback Pseudo-Interface 1",
            System.Net.NetworkInformation.NetworkInterfaceType.Loopback, new[] { "127.0.0.1" }));
        var setter = new FakeSetter();
        var store = TempStore(out var path);
        try
        {
            var cfg = new WindowsDnsAdapterConfigurator(query, setter, store);

            var result = cfg.ApplyLoopbackToAllAdapters();

            Assert.True(result.Success);
            // Loopback adapter must NOT be touched.
            Assert.DoesNotContain(setter.Calls, c => c.Guid == loop);
            // Eth gets v4 127.0.0.1 and v6 ::1.
            Assert.Contains(setter.Calls, c => c.Guid == eth && !c.Ipv6 && c.Server == "127.0.0.1");
            Assert.Contains(setter.Calls, c => c.Guid == eth && c.Ipv6 && c.Server == "::1");
        }
        finally { System.IO.File.Delete(path); }
    }

    [Fact]
    public void Apply_capturesPriorDns_intoBackup_andMarksLoopbackApplied()
    {
        var eth = Guid.NewGuid();
        var query = new FakeQuery();
        query.Adapters.Add(Eth(eth, "8.8.8.8", "8.8.4.4"));
        var store = TempStore(out var path);
        try
        {
            var cfg = new WindowsDnsAdapterConfigurator(query, new FakeSetter(), store);

            cfg.ApplyLoopbackToAllAdapters();

            var state = store.Load();
            Assert.NotNull(state);
            var slice = Assert.Single(state!.Interfaces);
            Assert.Equal("{" + eth.ToString().ToUpperInvariant() + "}", slice.InterfaceGuid.ToUpperInvariant());
            Assert.True(slice.WasIpv4Static);                 // had explicit servers
            Assert.Equal(new[] { "8.8.8.8", "8.8.4.4" }, slice.Ipv4Servers);
            Assert.False(slice.WasIpv6Static);                // no IPv6 servers on this adapter
            Assert.Null(slice.Ipv6Servers);
            Assert.True(cfg.IsLoopbackApplied());
        }
        finally { System.IO.File.Delete(path); }
    }

    [Fact]
    public void Apply_isIdempotent_doesNotOverwriteAnUnrestoredBackup()
    {
        var eth = Guid.NewGuid();
        var query = new FakeQuery();
        query.Adapters.Add(Eth(eth, "8.8.8.8"));         // first apply records 8.8.8.8
        var store = TempStore(out var path);
        try
        {
            var cfg = new WindowsDnsAdapterConfigurator(query, new FakeSetter(), store);
            cfg.ApplyLoopbackToAllAdapters();

            // Simulate the world AFTER lockdown: live DNS now reads loopback. A second Apply must
            // NOT overwrite the pristine 8.8.8.8 capture with 127.0.0.1.
            query.Adapters.Clear();
            query.Adapters.Add(Eth(eth, "127.0.0.1"));
            cfg.ApplyLoopbackToAllAdapters();

            var slice = Assert.Single(store.Load()!.Interfaces);
            Assert.Equal(new[] { "8.8.8.8" }, slice.Ipv4Servers);   // original preserved
        }
        finally { System.IO.File.Delete(path); }
    }

    [Fact]
    public void Apply_recordsDhcp_whenAdapterHadNoStaticServers()
    {
        var eth = Guid.NewGuid();
        var query = new FakeQuery();
        query.Adapters.Add(Eth(eth));     // no DNS servers => was DHCP/automatic
        var store = TempStore(out var path);
        try
        {
            var cfg = new WindowsDnsAdapterConfigurator(query, new FakeSetter(), store);
            cfg.ApplyLoopbackToAllAdapters();

            var slice = Assert.Single(store.Load()!.Interfaces);
            Assert.False(slice.WasIpv4Static);
            Assert.Null(slice.Ipv4Servers);
        }
        finally { System.IO.File.Delete(path); }
    }

    // IC-5 dual-stack test: mixed IPv4+IPv6 DnsAddresses must be split by address family.
    [Fact]
    public void Apply_splitsDnsAddressesByFamily_dualStackAdapter()
    {
        var eth = Guid.NewGuid();
        var query = new FakeQuery();
        // DnsAddresses returns IPv4 and IPv6 intermixed — must be partitioned by family.
        query.Adapters.Add(Eth(eth, "8.8.8.8", "2001:4860:4860::8888"));
        var store = TempStore(out var path);
        try
        {
            var cfg = new WindowsDnsAdapterConfigurator(query, new FakeSetter(), store);
            cfg.ApplyLoopbackToAllAdapters();

            var state = store.Load();
            Assert.NotNull(state);
            var slice = Assert.Single(state!.Interfaces);

            // IPv4 family only.
            Assert.True(slice.WasIpv4Static);
            Assert.Equal(new[] { "8.8.8.8" }, slice.Ipv4Servers);

            // IPv6 family only.
            Assert.True(slice.WasIpv6Static);
            Assert.Equal(new[] { "2001:4860:4860::8888" }, slice.Ipv6Servers);
        }
        finally { System.IO.File.Delete(path); }
    }

    // ---- Cycle 3: Restore + Reassert + error mapping ----

    [Fact]
    public void Restore_replaysStaticServers_thenClearsTheInterfaceSlice()
    {
        var eth = Guid.NewGuid();
        var query = new FakeQuery();
        query.Adapters.Add(Eth(eth, "8.8.8.8", "8.8.4.4"));
        var setter = new FakeSetter();
        var store = TempStore(out var path);
        try
        {
            var cfg = new WindowsDnsAdapterConfigurator(query, setter, store);
            cfg.ApplyLoopbackToAllAdapters();
            setter.Calls.Clear();

            var restore = cfg.RestoreDns();

            Assert.True(restore.Success);
            // v4 re-applied as the captured static list.
            Assert.Contains(setter.Calls, c => c.Guid == eth && !c.Ipv6 && !c.Cleared && c.Server == "8.8.8.8,8.8.4.4");
            // v6 had no separate static capture in this fake => reverted to DHCP.
            Assert.Contains(setter.Calls, c => c.Guid == eth && c.Ipv6 && c.Cleared);
            // Slice cleared after a successful restore. Interfaces was the only captured slice, so
            // clearing it routes through SaveOrDeleteIfEmpty and removes the backup file (zero residue).
            Assert.False(cfg.IsLoopbackApplied());
            Assert.False(store.Exists);
            Assert.Null(store.Load());
        }
        finally { System.IO.File.Delete(path); }
    }

    [Fact]
    public void Restore_revertsToDhcp_whenAdapterWasNotStatic()
    {
        var eth = Guid.NewGuid();
        var query = new FakeQuery();
        query.Adapters.Add(Eth(eth));     // was DHCP
        var setter = new FakeSetter();
        var store = TempStore(out var path);
        try
        {
            var cfg = new WindowsDnsAdapterConfigurator(query, setter, store);
            cfg.ApplyLoopbackToAllAdapters();
            setter.Calls.Clear();

            cfg.RestoreDns();

            Assert.Contains(setter.Calls, c => c.Guid == eth && !c.Ipv6 && c.Cleared);
            Assert.Contains(setter.Calls, c => c.Guid == eth && c.Ipv6 && c.Cleared);
        }
        finally { System.IO.File.Delete(path); }
    }

    [Fact]
    public void Restore_onEmptyBackup_isNoOpSuccess()
    {
        var store = TempStore(out var path);
        try
        {
            var cfg = new WindowsDnsAdapterConfigurator(new FakeQuery(), new FakeSetter(), store);
            Assert.True(cfg.RestoreDns().Success);   // nothing recorded
        }
        finally { System.IO.File.Delete(path); }
    }

    [Fact]
    public void Apply_mapsSetterFailure_toOperationFailed()
    {
        var eth = Guid.NewGuid();
        var query = new FakeQuery();
        query.Adapters.Add(Eth(eth, "8.8.8.8"));
        var setter = new FakeSetter { FailWith = 5 };   // ERROR_ACCESS_DENIED
        var store = TempStore(out var path);
        try
        {
            var cfg = new WindowsDnsAdapterConfigurator(query, setter, store);
            var result = cfg.ApplyLoopbackToAllAdapters();
            Assert.False(result.Success);
            Assert.Equal(PlatformErrorKind.OperationFailed, result.Error);
            Assert.Contains("Win32 error 5", result.Message);
        }
        finally { System.IO.File.Delete(path); }
    }

    // IC-7: Loopback addresses must be stripped from the backup capture so RestoreDns
    // never re-pins loopback instead of real DNS or DHCP.
    [Fact]
    public void Apply_excludesLoopbackFromCapturedBackup()
    {
        var eth1 = Guid.NewGuid();
        var eth2 = Guid.NewGuid();
        var query = new FakeQuery();
        // Adapter with loopback-only DNS: must be treated as DHCP (WasIpv4Static=false, Ipv4Servers=null).
        query.Adapters.Add(Eth(eth1, "127.0.0.1"));
        // Adapter with a mix of loopback + real DNS: loopback stripped, real server kept.
        query.Adapters.Add(Eth(eth2, "127.0.0.1", "8.8.8.8"));
        var setter = new FakeSetter();
        var store = TempStore(out var path);
        try
        {
            var cfg = new WindowsDnsAdapterConfigurator(query, setter, store);
            cfg.ApplyLoopbackToAllAdapters();

            var state = store.Load();
            Assert.NotNull(state);
            Assert.Equal(2, state!.Interfaces.Count);

            var slice1 = state.Interfaces.Single(s => s.InterfaceGuid.Contains(eth1.ToString(), StringComparison.OrdinalIgnoreCase));
            // Loopback-only: must look like DHCP to RestoreDns.
            Assert.False(slice1.WasIpv4Static);
            Assert.Null(slice1.Ipv4Servers);

            var slice2 = state.Interfaces.Single(s => s.InterfaceGuid.Contains(eth2.ToString(), StringComparison.OrdinalIgnoreCase));
            // Mixed: loopback dropped, real server retained.
            Assert.True(slice2.WasIpv4Static);
            Assert.Equal(new[] { "8.8.8.8" }, slice2.Ipv4Servers);
        }
        finally { System.IO.File.Delete(path); }
    }

    [Fact]
    public void Restore_onLoopbackOnlyCapturedAdapter_callsClearToDhcp()
    {
        // Simulate a backup that was written when the adapter already had loopback DNS
        // (i.e. loopback was excluded → WasIpv4Static=false). RestoreDns must call ClearToDhcp,
        // not SetNameServer, for that family.
        var eth = Guid.NewGuid();
        var query = new FakeQuery();
        query.Adapters.Add(Eth(eth, "127.0.0.1"));
        var setter = new FakeSetter();
        var store = TempStore(out var path);
        try
        {
            var cfg = new WindowsDnsAdapterConfigurator(query, setter, store);
            cfg.ApplyLoopbackToAllAdapters();
            setter.Calls.Clear();

            var restore = cfg.RestoreDns();

            Assert.True(restore.Success);
            // v4: loopback-only capture → must clear to DHCP, never re-set loopback.
            Assert.Contains(setter.Calls, c => c.Guid == eth && !c.Ipv6 && c.Cleared);
            Assert.DoesNotContain(setter.Calls, c => c.Guid == eth && !c.Ipv6 && !c.Cleared && c.Server == "127.0.0.1");
        }
        finally { System.IO.File.Delete(path); }
    }

    [Fact]
    public void Restore_mapsSetterFailure_toOperationFailed()
    {
        var eth = Guid.NewGuid();
        var query = new FakeQuery();
        query.Adapters.Add(Eth(eth, "8.8.8.8"));
        var setter = new FakeSetter();
        var store = TempStore(out var path);
        try
        {
            var cfg = new WindowsDnsAdapterConfigurator(query, setter, store);
            cfg.ApplyLoopbackToAllAdapters();
            // Now make the setter fail so RestoreDns hits an error.
            setter.FailWith = 5;   // ERROR_ACCESS_DENIED
            setter.Calls.Clear();

            var result = cfg.RestoreDns();

            Assert.False(result.Success);
            Assert.Equal(PlatformErrorKind.OperationFailed, result.Error);
            Assert.Contains("Win32 error 5", result.Message);
        }
        finally { System.IO.File.Delete(path); }
    }

    [Fact]
    public void Reassert_mapsSetterFailure_toOperationFailed()
    {
        var eth = Guid.NewGuid();
        var query = new FakeQuery();
        query.Adapters.Add(Eth(eth, "8.8.8.8"));
        var setter = new FakeSetter { FailWith = 5 };   // ERROR_ACCESS_DENIED
        var store = TempStore(out var path);
        try
        {
            var cfg = new WindowsDnsAdapterConfigurator(query, setter, store);
            var result = cfg.ReassertLoopback();

            Assert.False(result.Success);
            Assert.Equal(PlatformErrorKind.OperationFailed, result.Error);
            Assert.Contains("Win32 error 5", result.Message);
        }
        finally { System.IO.File.Delete(path); }
    }

    [Fact]
    public void Reassert_pinsLoopback_withoutChangingTheBackup()
    {
        var eth = Guid.NewGuid();
        var query = new FakeQuery();
        query.Adapters.Add(Eth(eth, "8.8.8.8"));
        var setter = new FakeSetter();
        var store = TempStore(out var path);
        try
        {
            var cfg = new WindowsDnsAdapterConfigurator(query, setter, store);
            cfg.ApplyLoopbackToAllAdapters();
            var before = store.Load();
            setter.Calls.Clear();

            var result = cfg.ReassertLoopback();

            Assert.True(result.Success);
            Assert.Contains(setter.Calls, c => c.Guid == eth && !c.Ipv6 && c.Server == "127.0.0.1");
            Assert.Contains(setter.Calls, c => c.Guid == eth && c.Ipv6 && c.Server == "::1");
            // Backup unchanged by a reassert.
            var after = store.Load();
            Assert.Equal(before!.Interfaces.Single().Ipv4Servers, after!.Interfaces.Single().Ipv4Servers);
        }
        finally { System.IO.File.Delete(path); }
    }

    [Fact]
    public void Skip_predicate_excludesTheProxyOwnAdapter()
    {
        var eth = Guid.NewGuid();
        var proxyAdapter = Guid.NewGuid();
        var query = new FakeQuery();
        query.Adapters.Add(Eth(eth, "8.8.8.8"));
        query.Adapters.Add(Eth(proxyAdapter, "8.8.8.8"));
        var setter = new FakeSetter();
        var store = TempStore(out var path);
        try
        {
            // Skip Loopback OR the proxy's own adapter GUID.
            var cfg = new WindowsDnsAdapterConfigurator(query, setter, store,
                a => a.Type == System.Net.NetworkInformation.NetworkInterfaceType.Loopback || a.Guid == proxyAdapter);

            cfg.ApplyLoopbackToAllAdapters();

            Assert.DoesNotContain(setter.Calls, c => c.Guid == proxyAdapter);
            Assert.Contains(setter.Calls, c => c.Guid == eth);
            Assert.Single(store.Load()!.Interfaces);   // only eth captured
        }
        finally { System.IO.File.Delete(path); }
    }

    [Trait("Category", "ManualIntegration")]
    [Fact]
    public void Apply_then_Restore_onRealAdapters_roundTrips()
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 0, 19041)) return;
        // Requires: elevated/LocalSystem on a real 19041+ box. Exercises the REAL seams end-to-end:
        // SystemNetworkInterfaceQuery + IpHlpInterfaceDnsSetter. Captures prior DNS, pins loopback on
        // every eligible adapter, then restores. Run manually; verify with `ipconfig /all` between steps.
        var path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "dcc-b2-manual-" + Guid.NewGuid().ToString("N") + ".json");
        var store = new DnsBackupStore(path);
        try
        {
            var cfg = new WindowsDnsAdapterConfigurator(store);
            var apply = cfg.ApplyLoopbackToAllAdapters();
            Assert.True(apply.Success, apply.Message);
            Assert.True(cfg.IsLoopbackApplied());

            var restore = cfg.RestoreDns();
            Assert.True(restore.Success, restore.Message);
            Assert.False(cfg.IsLoopbackApplied());
        }
        finally { try { System.IO.File.Delete(path); } catch (System.IO.IOException) { } }
    }
}
