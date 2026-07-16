using System;
using System.Collections.Generic;
using DnsCryptControl.Platform.Diagnostics;

namespace DnsCryptControl.Service.Windows;

/// <summary>Pure verdict logic: turns the four raw probe observations into per-check HealthStates and a
/// worst-of overall verdict. No I/O — this is the unit-testable heart of RunDiagnostics. Policy:
/// missing UDP/53 IPv4, a non-answering proxy, or any non-loopback Up adapter is a Fail (leak proof);
/// missing only the IPv6 loopback listener, or a hardening shortfall, is a Warn (advisory).</summary>
internal static class DiagnosticsEvaluator
{
    internal static DiagnosticsSnapshot Evaluate(
        DateTimeOffset takenUtc,
        ListenerObservation l,
        ActiveResolveObservation r,
        ActiveResolveObservation r6,
        IReadOnlyList<AdapterObservation> adapters,
        HardeningObservation h)
    {
        ArgumentNullException.ThrowIfNull(l);
        ArgumentNullException.ThrowIfNull(r);
        ArgumentNullException.ThrowIfNull(r6);
        ArgumentNullException.ThrowIfNull(adapters);
        ArgumentNullException.ThrowIfNull(h);

        var listeners = new ListenerCheck(
            State: ListenerState(l),
            Udp_127_0_0_1_53: l.Udp_127_0_0_1_53,
            Udp_IPv6Loopback_53: l.Udp_IPv6Loopback_53,
            Tcp_127_0_0_1_53: l.Tcp_127_0_0_1_53,
            Tcp_IPv6Loopback_53: l.Tcp_IPv6Loopback_53,
            ObservedPort53Listeners: l.ObservedPort53Listeners);

        var activeResolve = new ActiveResolveCheck(
            State: r.ProxyAnswered ? HealthState.Pass : HealthState.Fail,
            QueriedName: r.QueriedName,
            ProxyAnswered: r.ProxyAnswered,
            ElapsedMs: r.ElapsedMs,
            Detail: r.Detail);

        // IPv6 active-resolve is symmetric to v4 but policy-aware: the system pins ::1 on every adapter,
        // so a proxy that answers on 127.0.0.1:53 but not on [::1]:53 is a v6 leak risk. However, if the
        // [::1]:53 listener is ABSENT, IPv6 may be intentionally disabled on the box — that is a Warn
        // (advisory), consistent with how ListenerState treats a missing IPv6 loopback listener. The v6
        // listener-present signal is the UDP/53 [::1] socket (UDP is authoritative; TCP is advisory).
        var v6ListenerPresent = l.Udp_IPv6Loopback_53;
        var activeResolveV6State = r6.ProxyAnswered
            ? HealthState.Pass
            : v6ListenerPresent
                ? HealthState.Fail   // listener up but proxy gave no accepted answer on v6 => leak risk
                : HealthState.Warn;  // no v6 listener => IPv6 may be intentionally off (advisory)
        var activeResolveV6 = new ActiveResolveCheck(
            State: activeResolveV6State,
            QueriedName: r6.QueriedName,
            ProxyAnswered: r6.ProxyAnswered,
            ElapsedMs: r6.ElapsedMs,
            Detail: r6.Detail);

        var adapterEntries = new List<AdapterDnsEntry>(adapters.Count);
        var allLoopback = adapters.Count > 0;
        foreach (var a in adapters)
        {
            if (!a.DnsAllLoopback) allLoopback = false;
            adapterEntries.Add(new AdapterDnsEntry(
                Name: a.Name,
                Description: a.Description,
                OperationalStatus: a.OperationalStatus,
                DnsServers: a.DnsServers,
                DnsAllLoopback: a.DnsAllLoopback));
        }

        var adapterState = adapters.Count == 0
            ? HealthState.Unknown          // nothing to assert
            : allLoopback ? HealthState.Pass : HealthState.Fail;

        var adapterDns = new AdapterDnsCheck(adapterState, allLoopback, adapterEntries);

        var hardeningState = (h.SmhnrDisabled && h.ParallelAAaaaDisabled
                              && h.KillSwitchRulesPresent && h.BrowserDohPoliciesPresent)
            ? HealthState.Pass
            : HealthState.Warn;            // hardening shortfall is advisory, not direct leak proof
        var hardening = new HardeningCheck(
            State: hardeningState,
            SmhnrDisabled: h.SmhnrDisabled,
            ParallelAAaaaDisabled: h.ParallelAAaaaDisabled,
            KillSwitchRulesPresent: h.KillSwitchRulesPresent,
            BrowserDohPoliciesPresent: h.BrowserDohPoliciesPresent,
            Notes: h.Notes);

        var overall = WorstOf(
            listeners.State, activeResolve.State, activeResolveV6.State, adapterDns.State, hardening.State);

        return new DiagnosticsSnapshot(
            takenUtc, overall, listeners, activeResolve, activeResolveV6, adapterDns, hardening);
    }

    private static HealthState ListenerState(ListenerObservation l)
    {
        if (!l.Udp_127_0_0_1_53) return HealthState.Fail; // IPv4 UDP/53 is the authoritative listener
        if (!l.Udp_IPv6Loopback_53) return HealthState.Warn; // IPv6 loopback may be intentionally off
        return HealthState.Pass;
    }

    /// <summary>Worst-of across checks. Severity order: Fail &gt; Warn &gt; Unknown &gt; Pass. (A missing
    /// adapter set is Unknown, which is worse than Pass but never masks a real Fail/Warn elsewhere.)</summary>
    private static HealthState WorstOf(params HealthState[] states)
    {
        var worst = HealthState.Pass;
        foreach (var s in states)
            if (Rank(s) > Rank(worst)) worst = s;
        return worst;
    }

    private static int Rank(HealthState s) => s switch
    {
        HealthState.Pass => 0,
        HealthState.Unknown => 1,
        HealthState.Warn => 2,
        HealthState.Fail => 3,
        _ => 1,
    };
}
