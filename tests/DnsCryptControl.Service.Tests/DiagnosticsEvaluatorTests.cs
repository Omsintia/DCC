using System;
using System.Collections.Generic;
using DnsCryptControl.Platform.Diagnostics;
using DnsCryptControl.Service.Windows;
using Xunit;

namespace DnsCryptControl.Service.Tests;

public class DiagnosticsEvaluatorTests
{
    private static readonly DateTimeOffset T = new(2026, 6, 29, 0, 0, 0, TimeSpan.Zero);

    private static ListenerObservation Listeners(bool udp4, bool udp6) =>
        new(udp4, udp6, Tcp_127_0_0_1_53: false, Tcp_IPv6Loopback_53: false,
            ObservedPort53Listeners: new[] { "127.0.0.1:53" });

    private static ActiveResolveObservation Resolve(bool answered) =>
        new("selfcheck.test", answered, ElapsedMs: 10, Detail: answered ? "RCODE=0" : "timeout");

    private static ActiveResolveObservation ResolveV6(bool answered) =>
        new("selfcheck.test", answered, ElapsedMs: 10, Detail: answered ? "RCODE=0" : "timeout");

    private static AdapterObservation Adapter(string name, string status, string[] dns, bool allLoopback) =>
        new(name, name + " desc", status, dns, allLoopback);

    private static HardeningObservation Harden(bool smhnr, bool parallel, bool ks, bool doh) =>
        new(smhnr, parallel, ks, doh, new[] { "note" });

    [Fact]
    public void AllGood_rollsUpToPass()
    {
        var s = DiagnosticsEvaluator.Evaluate(
            T,
            Listeners(udp4: true, udp6: true),
            Resolve(answered: true),
            ResolveV6(answered: true),
            new[] { Adapter("Ethernet", "Up", new[] { "127.0.0.1", "::1" }, allLoopback: true) },
            Harden(smhnr: true, parallel: true, ks: true, doh: true));

        Assert.Equal(HealthState.Pass, s.Listeners.State);
        Assert.Equal(HealthState.Pass, s.ActiveResolveV6.State);
        Assert.Equal(HealthState.Pass, s.ActiveResolve.State);
        Assert.Equal(HealthState.Pass, s.AdapterDns.State);
        Assert.True(s.AdapterDns.AllLoopback);
        Assert.Equal(HealthState.Pass, s.Hardening.State);
        Assert.Equal(HealthState.Pass, s.Overall);
        Assert.Equal(T, s.TakenUtc);
    }

    [Fact]
    public void AdapterNotLoopback_failsAdapterCheck_andDragsOverallToFail()
    {
        var s = DiagnosticsEvaluator.Evaluate(
            T,
            Listeners(udp4: true, udp6: true),
            Resolve(answered: true),
            ResolveV6(answered: true),
            new[] { Adapter("Wi-Fi", "Up", new[] { "8.8.8.8" }, allLoopback: false) },
            Harden(smhnr: true, parallel: true, ks: true, doh: true));

        Assert.Equal(HealthState.Fail, s.AdapterDns.State);
        Assert.False(s.AdapterDns.AllLoopback);
        Assert.Equal(HealthState.Fail, s.Overall); // worst-of
    }

    [Fact]
    public void MissingUdp4Listener_failsListenerCheck()
    {
        var s = DiagnosticsEvaluator.Evaluate(
            T,
            Listeners(udp4: false, udp6: true),
            Resolve(answered: true),
            ResolveV6(answered: true),
            new[] { Adapter("Ethernet", "Up", new[] { "127.0.0.1" }, allLoopback: true) },
            Harden(smhnr: true, parallel: true, ks: true, doh: true));

        Assert.Equal(HealthState.Fail, s.Listeners.State); // UDP/53 IPv4 is authoritative
        Assert.Equal(HealthState.Fail, s.Overall);
    }

    [Fact]
    public void MissingOnlyUdp6Listener_isWarn_notFail()
    {
        var s = DiagnosticsEvaluator.Evaluate(
            T,
            Listeners(udp4: true, udp6: false),
            Resolve(answered: true),
            ResolveV6(answered: false),  // no v6 listener => v6 active-resolve is Warn (not Fail)
            new[] { Adapter("Ethernet", "Up", new[] { "127.0.0.1" }, allLoopback: true) },
            Harden(smhnr: true, parallel: true, ks: true, doh: true));

        Assert.Equal(HealthState.Warn, s.Listeners.State); // IPv6 loopback missing is advisory
        Assert.Equal(HealthState.Warn, s.ActiveResolveV6.State); // listener absent => advisory, not Fail
        Assert.Equal(HealthState.Warn, s.Overall);          // worst-of is Warn (nothing Fails)
    }

    [Fact]
    public void ProxyDidNotAnswer_failsActiveResolve()
    {
        var s = DiagnosticsEvaluator.Evaluate(
            T,
            Listeners(udp4: true, udp6: true),
            Resolve(answered: false),
            ResolveV6(answered: true),
            new[] { Adapter("Ethernet", "Up", new[] { "127.0.0.1" }, allLoopback: true) },
            Harden(smhnr: true, parallel: true, ks: true, doh: true));

        Assert.Equal(HealthState.Fail, s.ActiveResolve.State);
        Assert.False(s.ActiveResolve.ProxyAnswered);
        Assert.Equal(HealthState.Fail, s.Overall);
    }

    [Fact]
    public void SmhnrOrParallelDisabledFalse_makesHardeningWarn()
    {
        var s = DiagnosticsEvaluator.Evaluate(
            T,
            Listeners(udp4: true, udp6: true),
            Resolve(answered: true),
            ResolveV6(answered: true),
            new[] { Adapter("Ethernet", "Up", new[] { "127.0.0.1" }, allLoopback: true) },
            Harden(smhnr: false, parallel: true, ks: true, doh: true));

        Assert.Equal(HealthState.Warn, s.Hardening.State); // hardening shortfall is advisory, not a leak proof
        Assert.Equal(HealthState.Warn, s.Overall);
    }

    [Fact]
    public void NoAdapters_isUnknown_notPass()
    {
        var s = DiagnosticsEvaluator.Evaluate(
            T,
            Listeners(udp4: true, udp6: true),
            Resolve(answered: true),
            ResolveV6(answered: true),
            Array.Empty<AdapterObservation>(),
            Harden(smhnr: true, parallel: true, ks: true, doh: true));

        Assert.Equal(HealthState.Unknown, s.AdapterDns.State); // nothing to assert
        Assert.False(s.AdapterDns.AllLoopback);
    }

    [Fact]
    public void Snapshot_copiesObservationsIntoCheckRecords()
    {
        var s = DiagnosticsEvaluator.Evaluate(
            T,
            Listeners(udp4: true, udp6: true),
            Resolve(answered: true),
            ResolveV6(answered: true),
            new[] { Adapter("Ethernet", "Up", new[] { "127.0.0.1" }, allLoopback: true) },
            Harden(smhnr: true, parallel: true, ks: true, doh: true));

        Assert.True(s.Listeners.Udp_127_0_0_1_53);
        Assert.Equal(new[] { "127.0.0.1:53" }, s.Listeners.ObservedPort53Listeners);
        Assert.Equal("selfcheck.test", s.ActiveResolve.QueriedName);
        Assert.Equal("RCODE=0", s.ActiveResolve.Detail);
        var a = Assert.Single(s.AdapterDns.Adapters);
        Assert.Equal("Ethernet", a.Name);
        Assert.Equal(new[] { "127.0.0.1" }, a.DnsServers);
        Assert.True(s.Hardening.KillSwitchRulesPresent);
        Assert.True(s.Hardening.BrowserDohPoliciesPresent);
    }

    // -------- IPv6 active-resolve (Fix 3): symmetric to v4 but policy-aware --------

    [Fact]
    public void V6ActiveResolve_noError_isPass()
    {
        var s = DiagnosticsEvaluator.Evaluate(
            T,
            Listeners(udp4: true, udp6: true),   // v6 listener present
            Resolve(answered: true),
            ResolveV6(answered: true),           // [::1]:53 gave an accepted answer
            new[] { Adapter("Ethernet", "Up", new[] { "127.0.0.1", "::1" }, allLoopback: true) },
            Harden(smhnr: true, parallel: true, ks: true, doh: true));

        Assert.Equal(HealthState.Pass, s.ActiveResolveV6.State);
        Assert.True(s.ActiveResolveV6.ProxyAnswered);
        Assert.Equal(HealthState.Pass, s.Overall);
    }

    [Fact]
    public void V6ActiveResolve_listenerPresentButNotNoError_isFail_andDragsOverall()
    {
        // The [::1]:53 listener is up but the proxy gives no accepted answer on v6 — a v6 leak risk
        // that a v4-only attestation would have missed. This is a Fail, not a Warn.
        var s = DiagnosticsEvaluator.Evaluate(
            T,
            Listeners(udp4: true, udp6: true),   // v6 listener PRESENT
            Resolve(answered: true),             // v4 fully healthy
            ResolveV6(answered: false),          // v6 SERVFAIL/no-answer
            new[] { Adapter("Ethernet", "Up", new[] { "127.0.0.1", "::1" }, allLoopback: true) },
            Harden(smhnr: true, parallel: true, ks: true, doh: true));

        Assert.Equal(HealthState.Pass, s.ActiveResolve.State); // v4 unaffected
        Assert.Equal(HealthState.Fail, s.ActiveResolveV6.State);
        Assert.False(s.ActiveResolveV6.ProxyAnswered);
        Assert.Equal(HealthState.Fail, s.Overall);
    }

    [Fact]
    public void V6ActiveResolve_listenerAbsent_isWarn_notFail()
    {
        // No [::1]:53 listener — IPv6 may be intentionally disabled on this box. Policy: Warn, never Fail.
        var s = DiagnosticsEvaluator.Evaluate(
            T,
            Listeners(udp4: true, udp6: false),  // v6 listener ABSENT
            Resolve(answered: true),
            ResolveV6(answered: false),          // no answer (because there is no v6 listener)
            new[] { Adapter("Ethernet", "Up", new[] { "127.0.0.1" }, allLoopback: true) },
            Harden(smhnr: true, parallel: true, ks: true, doh: true));

        Assert.Equal(HealthState.Warn, s.ActiveResolveV6.State); // advisory, not a Fail
        Assert.NotEqual(HealthState.Fail, s.Overall);            // v6 absence must not Fail overall
    }
}
