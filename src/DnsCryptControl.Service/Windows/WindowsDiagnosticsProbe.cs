using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using DnsCryptControl.Platform;
using DnsCryptControl.Platform.Diagnostics;
using DnsCryptControl.Service.Windows.Registry;
using Microsoft.Win32;

namespace DnsCryptControl.Service.Windows;

/// <summary>Live, read-only DNS-leak self-check. Implements IDnsProbeInputs with managed BCL only
/// (IPGlobalProperties listeners, a Connect-pinned UDP query, NetworkInterface DNS enumeration, registry
/// reads via IRegistryRoot + reused kill-switch/browser-DoH presence) and composes them through the pure
/// DiagnosticsEvaluator. Never mutates state. IC-1: uses the existing IRegistryRoot seam (not
/// Microsoft.Win32.Registry directly) so the hardening-registry reads are unit-testable.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsDiagnosticsProbe : IDiagnosticsProbe, IDnsProbeInputs
{
    private static readonly IPAddress IPv6Loopback = IPAddress.IPv6Loopback;
    private static readonly TimeSpan ResolveTimeout = TimeSpan.FromMilliseconds(1500);
    private const string SelfCheckName = "dnscrypt-resolver-selfcheck.test";

    // VerifyUpstreamResolution budget: a REAL internet round trip through the proxy's configured
    // route (2500 ms/attempt vs the 1500 ms loopback-liveness check), up to 3 attempts, first
    // ProxyAnswered wins, hard cumulative cap ~5 s so the serial pipe dispatch is never held long.
    private static readonly TimeSpan VerifyResolveTimeout = TimeSpan.FromMilliseconds(2500);
    private const int VerifyMaxAttempts = 3;
    private const int VerifyTotalBudgetMs = 5000;

    private readonly IFirewallKillSwitch _killSwitch;
    private readonly IBrowserDohPolicy _browserDoh;
    private readonly IRegistryRoot _hklm64;

    /// <summary>IC-2 production constructor: accepts all three injectable dependencies so the
    /// hardening registry reads are testable without touching the real registry. Internal because
    /// IRegistryRoot is internal; ServiceComposition wires this ctor from within the assembly.</summary>
    internal WindowsDiagnosticsProbe(
        IFirewallKillSwitch killSwitch,
        IBrowserDohPolicy browserDoh,
        IRegistryRoot hklm64)
    {
        ArgumentNullException.ThrowIfNull(killSwitch);
        ArgumentNullException.ThrowIfNull(browserDoh);
        ArgumentNullException.ThrowIfNull(hklm64);
        _killSwitch = killSwitch;
        _browserDoh = browserDoh;
        _hklm64 = hklm64;
    }

    /// <summary>Convenience overload for ManualIntegration live tests: creates a real
    /// Registry64Root internally so callers do not need to construct it.</summary>
    public WindowsDiagnosticsProbe(IFirewallKillSwitch killSwitch, IBrowserDohPolicy browserDoh)
        : this(killSwitch, browserDoh, new Registry64Root())
    {
    }

    public PlatformResult<DiagnosticsSnapshot> Run() => RunWith(this, DateTimeOffset.UtcNow);

    /// <summary>Proves the proxy's CONFIGURED UPSTREAM ROUTE resolves — the thing the continuous
    /// self-check structurally cannot (its undelegated .test name is answered locally by
    /// block_undelegated, so it false-greens on a dead anonymized route). Queries a random label
    /// under a REAL delegated zone (defeats both block_undelegated and negative caching); the
    /// answer for a name that does not exist is an authoritative NXDOMAIN, which
    /// <see cref="LoopbackResolveProbe.IsValidProxyResponse"/> already accepts (NOERROR|NXDOMAIN)
    /// — either RCODE proves the query egressed and came back. SERVFAIL/REFUSED/timeout across the
    /// budget ⇒ Resolved=false. Runs on an explicit user action only, never the badge poll.</summary>
    public PlatformResult<ResolveVerification> VerifyUpstreamResolution() =>
        VerifyWith(LoopbackResolveProbe.Probe, VerifyName());

    /// <summary>A fresh random 8-hex label under example.com per call, so no cache (positive or
    /// negative, local or upstream) can satisfy the query without an upstream round trip.</summary>
    internal static string VerifyName() =>
        $"{Random.Shared.Next():x8}.example.com";

    /// <summary>Composition seam for <see cref="VerifyUpstreamResolution"/> (mirrors
    /// <see cref="RunWith"/>): the retry/budget loop over any probe function, unit-testable with a
    /// fake. The target is PINNED to 127.0.0.1:53 HERE — the kill switch never blocks loopback, and
    /// only the loopback proxy exercises the configured route; a refactor that made this probe
    /// egress directly would be blocked by the kill switch and false-warn (see the loopback-pin
    /// test). Never throws: a thrown probe maps to a Fail PlatformResult; a dead route is an Ok
    /// result with Resolved=false.</summary>
    internal static PlatformResult<ResolveVerification> VerifyWith(
        Func<IPAddress, int, string, TimeSpan, ActiveResolveObservation> probe, string name)
    {
        ArgumentNullException.ThrowIfNull(probe);
        ArgumentException.ThrowIfNullOrEmpty(name);
        try
        {
            var totalMs = 0;
            ActiveResolveObservation? last = null;
            for (var attempt = 1; attempt <= VerifyMaxAttempts; attempt++)
            {
                var obs = probe(IPAddress.Loopback, 53, name, VerifyResolveTimeout);
                last = obs;
                totalMs += Math.Max(0, obs.ElapsedMs);
                if (obs.ProxyAnswered)
                    return PlatformResult<ResolveVerification>.Ok(
                        new ResolveVerification(true, totalMs, obs.Detail ?? "resolved"));
                if (totalMs >= VerifyTotalBudgetMs) break;
            }
            return PlatformResult<ResolveVerification>.Ok(
                new ResolveVerification(false, totalMs, last?.Detail ?? "no answer"));
        }
        catch (Exception ex)
        {
            return PlatformResult<ResolveVerification>.Fail(
                PlatformErrorKind.OperationFailed, $"resolve verification failed: {ex.Message}");
        }
    }

    /// <summary>Composition seam: builds the snapshot from any IDnsProbeInputs at a fixed timestamp so
    /// the rollup wiring is unit-testable with a fake. Never throws for a probe failure — a thrown probe
    /// maps to a Fail PlatformResult.</summary>
    internal static PlatformResult<DiagnosticsSnapshot> RunWith(IDnsProbeInputs inputs, DateTimeOffset takenUtc)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        try
        {
            var listeners = inputs.ObserveListeners();
            var resolve = inputs.ObserveActiveResolve();
            var resolveV6 = inputs.ObserveActiveResolveV6();
            var adapters = inputs.ObserveAdapters();
            var hardening = inputs.ObserveHardening();
            var snapshot = DiagnosticsEvaluator.Evaluate(
                takenUtc, listeners, resolve, resolveV6, adapters, hardening);
            return PlatformResult<DiagnosticsSnapshot>.Ok(snapshot);
        }
        catch (Exception ex)
        {
            return PlatformResult<DiagnosticsSnapshot>.Fail(
                PlatformErrorKind.OperationFailed, $"diagnostics probe failed: {ex.Message}");
        }
    }

    /// <summary>Every configured DNS server is loopback AND there is at least one server. Uses
    /// IPAddress.IsLoopback (accepts 127.0.0.0/8, ::1, IPv4-mapped loopback) — never string equality.</summary>
    internal static bool IsLoopbackDns(IReadOnlyList<IPAddress> servers)
    {
        if (servers.Count == 0) return false;
        foreach (var ip in servers)
            if (!IPAddress.IsLoopback(ip)) return false;
        return true;
    }

    // Explicit interface implementation for IDnsProbeInputs — the observation record types are
    // internal, so the methods cannot be public. Explicit implementation satisfies both constraints.

    ListenerObservation IDnsProbeInputs.ObserveListeners()
    {
        var props = IPGlobalProperties.GetIPGlobalProperties();
        var udp = props.GetActiveUdpListeners();
        var tcp = props.GetActiveTcpListeners();

        var observed = new List<string>();
        bool udp4 = false, udp6 = false, tcp4 = false, tcp6 = false;

        foreach (var ep in udp)
        {
            if (ep.Port != 53) continue;
            observed.Add(ep.ToString());
            if (ep.Address.Equals(IPAddress.Loopback)) udp4 = true;
            else if (ep.Address.Equals(IPv6Loopback)) udp6 = true;
        }
        foreach (var ep in tcp)
        {
            if (ep.Port != 53) continue;
            observed.Add(ep.ToString());
            if (ep.Address.Equals(IPAddress.Loopback)) tcp4 = true;
            else if (ep.Address.Equals(IPv6Loopback)) tcp6 = true;
        }

        return new ListenerObservation(udp4, udp6, tcp4, tcp6, observed);
    }

    ActiveResolveObservation IDnsProbeInputs.ObserveActiveResolve() =>
        LoopbackResolveProbe.Probe(IPAddress.Loopback, 53, SelfCheckName, ResolveTimeout);

    ActiveResolveObservation IDnsProbeInputs.ObserveActiveResolveV6() =>
        LoopbackResolveProbe.Probe(IPv6Loopback, 53, SelfCheckName, ResolveTimeout);

    IReadOnlyList<AdapterObservation> IDnsProbeInputs.ObserveAdapters()
    {
        var result = new List<AdapterObservation>();
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up) continue;
            if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

            var servers = new List<IPAddress>();
            foreach (var dns in ni.GetIPProperties().DnsAddresses)
                servers.Add(dns);

            var serverStrings = new List<string>(servers.Count);
            foreach (var s in servers) serverStrings.Add(s.ToString());

            result.Add(new AdapterObservation(
                Name: ni.Name,
                Description: ni.Description,
                OperationalStatus: ni.OperationalStatus.ToString(),
                DnsServers: serverStrings,
                DnsAllLoopback: IsLoopbackDns(servers)));
        }
        return result;
    }

    HardeningObservation IDnsProbeInputs.ObserveHardening()
    {
        var notes = new List<string>();

        // IC-1: use IRegistryRoot seam (not Registry.LocalMachine directly) for testability.
        // Reference RegistryLeakMitigationPolicy's own constants (same assembly) so the probe
        // can never check a different key/value than the policy writes.
        var smhnr = ReadDwordEquals(
            RegistryLeakMitigationPolicy.DnsClientSubKey,
            RegistryLeakMitigationPolicy.SmhnrValueName, 1, notes, "SMHNR");
        var parallel = ReadDwordEquals(
            RegistryLeakMitigationPolicy.DnscacheParametersSubKey,
            RegistryLeakMitigationPolicy.ParallelValueName, 1, notes, "ParallelAandAAAA");

        var killSwitch = _killSwitch.IsKillSwitchActive();
        var browserDoh = _browserDoh.IsBrowserDohPolicyApplied();

        return new HardeningObservation(smhnr, parallel, killSwitch, browserDoh, notes);
    }

    /// <summary>Reads HKLM\<paramref name="subKey"/>!<paramref name="valueName"/> via the injected
    /// IRegistryRoot seam and returns whether it equals <paramref name="expected"/>. A missing
    /// key/value is reported false (e.g. a missing DisableSmartNameResolution means SMHNR is
    /// ENABLED = leaky) and noted explicitly.</summary>
    private bool ReadDwordEquals(string subKey, string valueName, int expected, List<string> notes, string label)
    {
        using var key = _hklm64.OpenSubKey(subKey, writable: false);
        var raw = key?.GetValue(valueName);
        if (raw is null)
        {
            notes.Add($"{label}: {valueName} not present (treated as not hardened)");
            return false;
        }
        var value = Convert.ToInt32(raw, System.Globalization.CultureInfo.InvariantCulture);
        if (value != expected) notes.Add($"{label}: {valueName}={value}, expected {expected}");
        return value == expected;
    }
}
