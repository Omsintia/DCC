namespace DnsCryptControl.Platform.Diagnostics;

/// <summary>Per-check and overall verdict for the read-only DNS-leak self-check.</summary>
public enum HealthState { Pass, Warn, Fail, Unknown }

/// <summary>Immutable result of a single RunDiagnostics pass: the independent probes plus a
/// worst-of overall verdict. Read-only — computing it never mutates system state.
/// <para><see cref="ActiveResolve"/> proves resolution against 127.0.0.1:53; <see cref="ActiveResolveV6"/>
/// proves it against [::1]:53. The v6 check is symmetric to the v4 one but policy-aware: if the IPv6
/// loopback listener is absent (IPv6 may be intentionally disabled) it is a Warn, not a Fail.</para></summary>
public sealed record DiagnosticsSnapshot(
    DateTimeOffset TakenUtc,
    HealthState Overall,                 // worst-of the probes
    ListenerCheck Listeners,
    ActiveResolveCheck ActiveResolve,
    ActiveResolveCheck ActiveResolveV6,
    AdapterDnsCheck AdapterDns,
    HardeningCheck Hardening);

/// <summary>Whether the loopback proxy is listening on port 53. UDP is authoritative; TCP is advisory
/// because idle TCP-Listen sockets may not appear in the active-listener table.
/// (CA1707 — the IP:port-encoding property names below are intentional per contracts §3; the
/// suppression is file-scoped in .editorconfig, not an in-code pragma.)</summary>
public sealed record ListenerCheck(
    HealthState State,
    bool Udp_127_0_0_1_53,
    bool Udp_IPv6Loopback_53,
    bool Tcp_127_0_0_1_53,        // advisory: idle TCP-Listen sockets may not appear
    bool Tcp_IPv6Loopback_53,    // advisory
    IReadOnlyList<string> ObservedPort53Listeners);

/// <summary>Result of sending a hand-built DNS query straight to 127.0.0.1:53 and confirming the
/// loopback proxy answered (proves the proxy is live, bypassing the Windows resolver).</summary>
public sealed record ActiveResolveCheck(
    HealthState State,
    string QueriedName,
    bool ProxyAnswered,
    int ElapsedMs,
    string? Detail);

/// <summary>Per-adapter DNS leak verdict: every Up non-loopback adapter must point at loopback DNS.</summary>
public sealed record AdapterDnsCheck(
    HealthState State,
    bool AllLoopback,
    IReadOnlyList<AdapterDnsEntry> Adapters);

/// <summary>One adapter's configured DNS servers and whether they are all loopback.</summary>
public sealed record AdapterDnsEntry(
    string Name,
    string Description,
    string OperationalStatus,
    IReadOnlyList<string> DnsServers,
    bool DnsAllLoopback);

/// <summary>OS- and policy-level hardening: SMHNR/parallel-A-AAAA disabled, kill-switch firewall rules
/// present, browser DoH-disable policies present.</summary>
public sealed record HardeningCheck(
    HealthState State,
    bool SmhnrDisabled,
    bool ParallelAAaaaDisabled,
    bool KillSwitchRulesPresent,
    bool BrowserDohPoliciesPresent,
    IReadOnlyList<string> Notes);
