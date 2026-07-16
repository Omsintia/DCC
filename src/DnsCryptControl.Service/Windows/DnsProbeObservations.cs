using System.Collections.Generic;

namespace DnsCryptControl.Service.Windows;

/// <summary>Raw, pre-verdict listener observation: which loopback :53 sockets were seen.</summary>
internal sealed record ListenerObservation(
    bool Udp_127_0_0_1_53,
    bool Udp_IPv6Loopback_53,
    bool Tcp_127_0_0_1_53,
    bool Tcp_IPv6Loopback_53,
    IReadOnlyList<string> ObservedPort53Listeners);

/// <summary>Raw active-resolve observation: did the loopback proxy answer a hand-built query.</summary>
internal sealed record ActiveResolveObservation(
    string QueriedName,
    bool ProxyAnswered,
    int ElapsedMs,
    string? Detail);

/// <summary>Raw per-adapter observation: configured DNS servers + whether they are all loopback.</summary>
internal sealed record AdapterObservation(
    string Name,
    string Description,
    string OperationalStatus,
    IReadOnlyList<string> DnsServers,
    bool DnsAllLoopback);

/// <summary>Raw hardening observation: registry/firewall/browser-policy presence booleans.</summary>
internal sealed record HardeningObservation(
    bool SmhnrDisabled,
    bool ParallelAAaaaDisabled,
    bool KillSwitchRulesPresent,
    bool BrowserDohPoliciesPresent,
    IReadOnlyList<string> Notes);
