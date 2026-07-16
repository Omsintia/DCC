using System;
using System.Collections.Generic;
using DnsCryptControl.Platform.Diagnostics;
using Xunit;

namespace DnsCryptControl.Platform.Tests;

public class DiagnosticsSnapshotTests
{
    private static DiagnosticsSnapshot BuildSample() => new(
        TakenUtc: new DateTimeOffset(2026, 6, 29, 12, 0, 0, TimeSpan.Zero),
        Overall: HealthState.Pass,
        Listeners: new ListenerCheck(
            State: HealthState.Pass,
            Udp_127_0_0_1_53: true,
            Udp_IPv6Loopback_53: true,
            Tcp_127_0_0_1_53: false,
            Tcp_IPv6Loopback_53: false,
            ObservedPort53Listeners: new[] { "127.0.0.1:53", "[::1]:53" }),
        ActiveResolve: new ActiveResolveCheck(
            State: HealthState.Pass,
            QueriedName: "dnscrypt-resolver-selfcheck.test",
            ProxyAnswered: true,
            ElapsedMs: 12,
            Detail: "RCODE=0, ancount=1"),
        ActiveResolveV6: new ActiveResolveCheck(
            State: HealthState.Pass,
            QueriedName: "dnscrypt-resolver-selfcheck.test",
            ProxyAnswered: true,
            ElapsedMs: 14,
            Detail: "RCODE=0, ancount=1"),
        AdapterDns: new AdapterDnsCheck(
            State: HealthState.Pass,
            AllLoopback: true,
            Adapters: new[]
            {
                new AdapterDnsEntry(
                    Name: "Ethernet",
                    Description: "Intel NIC",
                    OperationalStatus: "Up",
                    DnsServers: new[] { "127.0.0.1", "::1" },
                    DnsAllLoopback: true),
            }),
        Hardening: new HardeningCheck(
            State: HealthState.Pass,
            SmhnrDisabled: true,
            ParallelAAaaaDisabled: true,
            KillSwitchRulesPresent: true,
            BrowserDohPoliciesPresent: true,
            Notes: new[] { "all clear" }));

    [Fact]
    public void Snapshot_constructs_andExposesEveryProbe()
    {
        var s = BuildSample();

        Assert.Equal(HealthState.Pass, s.Overall);
        Assert.Equal(new DateTimeOffset(2026, 6, 29, 12, 0, 0, TimeSpan.Zero), s.TakenUtc);
        Assert.True(s.Listeners.Udp_127_0_0_1_53);
        Assert.True(s.Listeners.Udp_IPv6Loopback_53);
        Assert.Equal(new[] { "127.0.0.1:53", "[::1]:53" }, s.Listeners.ObservedPort53Listeners);
        Assert.True(s.ActiveResolve.ProxyAnswered);
        Assert.Equal("dnscrypt-resolver-selfcheck.test", s.ActiveResolve.QueriedName);
        Assert.True(s.ActiveResolveV6.ProxyAnswered);
        Assert.Equal(HealthState.Pass, s.ActiveResolveV6.State);
        Assert.True(s.AdapterDns.AllLoopback);
        Assert.Single(s.AdapterDns.Adapters);
        Assert.True(s.Hardening.SmhnrDisabled);
        Assert.True(s.Hardening.ParallelAAaaaDisabled);
    }

    [Fact]
    public void ActiveResolveCheck_allowsNullDetail()
    {
        var c = new ActiveResolveCheck(HealthState.Fail, "name.test", ProxyAnswered: false, ElapsedMs: 1500, Detail: null);
        Assert.False(c.ProxyAnswered);
        Assert.Null(c.Detail);
        Assert.Equal(HealthState.Fail, c.State);
    }

    [Fact]
    public void HealthState_hasTheFourMembers()
    {
        foreach (var v in new[] { HealthState.Pass, HealthState.Warn, HealthState.Fail, HealthState.Unknown })
            Assert.True(Enum.IsDefined(v));
    }
}
