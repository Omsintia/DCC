using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.State;

namespace DnsCryptControl.Service.Windows;

/// <summary>
/// Pins every eligible network interface's DNS to the loopback proxy (IPv4 127.0.0.1 + IPv6 ::1)
/// statically, captures prior per-interface DNS into the backup, and restores it on revert.
/// Enumerates ALL adapters (including down/VPN/vEthernet — a down adapter that later comes up with
/// DHCP DNS would otherwise leak); SKIPs <see cref="NetworkInterfaceType.Loopback"/> and the
/// proxy's own adapter (a configurable GUID predicate). OS-touching work is behind
/// <see cref="INetworkInterfaceQuery"/> + <see cref="IInterfaceDnsSetter"/> so the
/// selection/backup/restore logic is unit-testable. Runs as SYSTEM.
///
/// IC-5: DNS server strings from <see cref="AdapterInfo.DnsServers"/> are partitioned by address
/// family (IPv4 vs IPv6) before storing them in the backup, so each stack's prior state is
/// independently captured and restored.
///
/// IC-6: Backup capture is performed exclusively via
/// <see cref="DnsBackupStore.CaptureInterfacesIfAbsent"/> — the single gated path that
/// enforces "never overwrite an existing un-restored backup" + the single-writer lock.
/// </summary>
[SupportedOSPlatform("windows10.0.19041")]
public sealed class WindowsDnsAdapterConfigurator : IDnsAdapterConfigurator
{
    private const string LoopbackV4 = "127.0.0.1";
    private const string LoopbackV6 = "::1";

    private readonly INetworkInterfaceQuery _query;
    private readonly IInterfaceDnsSetter _setter;
    private readonly DnsBackupStore _backup;
    private readonly Func<AdapterInfo, bool> _skip;

    /// <summary>Production ctor: real enumeration + real IP Helper setter, default skip = Loopback only.</summary>
    public WindowsDnsAdapterConfigurator(DnsBackupStore backup)
        : this(new SystemNetworkInterfaceQuery(), new IpHlpInterfaceDnsSetter(), backup, skipPredicate: null) { }

    /// <summary>Test/seam ctor.</summary>
    internal WindowsDnsAdapterConfigurator(
        INetworkInterfaceQuery query,
        IInterfaceDnsSetter setter,
        DnsBackupStore backup,
        Func<AdapterInfo, bool>? skipPredicate = null)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(setter);
        ArgumentNullException.ThrowIfNull(backup);
        _query = query;
        _setter = setter;
        _backup = backup;
        // Default: skip the software loopback adapter only. Skipping the proxy's own adapter (if it has
        // one) is layered on by passing a wider predicate.
        _skip = skipPredicate ?? (a => a.Type == NetworkInterfaceType.Loopback);
    }

    private List<AdapterInfo> Eligible() =>
        _query.GetAdapters().Where(a => !_skip(a)).ToList();

    private static string Braced(Guid g) => "{" + g.ToString().ToUpperInvariant() + "}";

    /// <summary>
    /// Partition a flat DNS-server string list by address family (IC-5).
    /// Returns (<paramref name="ipv4"/>, <paramref name="ipv6"/>) where each list contains
    /// only servers of that family; entries that fail to parse are silently dropped.
    /// </summary>
    private static (List<string> ipv4, List<string> ipv6) SplitByFamily(IReadOnlyList<string> servers)
    {
        var v4 = new List<string>();
        var v6 = new List<string>();
        foreach (var s in servers)
        {
            if (IPAddress.TryParse(s, out var addr))
            {
                // IC-7: Exclude loopback addresses from the backup capture. An adapter whose DNS was
                // already pointing at 127.0.0.1/::1 (e.g. after a prior lockdown that wasn't restored)
                // must not have those loopback addresses written back by RestoreDns — that would
                // break working DNS instead of restoring it. Loopback-only adapters are therefore
                // treated as DHCP/automatic (WasXStatic=false, XServers=null), so RestoreDns calls
                // ClearToDhcp for that family rather than re-pinning loopback.
                if (IPAddress.IsLoopback(addr))
                    continue;

                if (addr.AddressFamily == AddressFamily.InterNetwork)
                    v4.Add(s);
                else if (addr.AddressFamily == AddressFamily.InterNetworkV6)
                    v6.Add(s);
                // else: some other family — skip
            }
        }
        return (v4, v6);
    }

    private static InterfaceDnsBackup BuildSlice(AdapterInfo a)
    {
        var (v4, v6) = SplitByFamily(a.DnsServers);
        return new InterfaceDnsBackup
        {
            InterfaceGuid = Braced(a.Guid),
            WasIpv4Static = v4.Count > 0,
            Ipv4Servers = v4.Count > 0 ? v4 : null,
            WasIpv6Static = v6.Count > 0,
            Ipv6Servers = v6.Count > 0 ? v6 : null,
        };
    }

    /// <inheritdoc/>
    public PlatformResult ApplyLoopbackToAllAdapters()
    {
        var eligible = Eligible();

        // IC-6: Use CaptureInterfacesIfAbsent — the single gated path that enforces idempotency
        // (never overwrites an existing un-restored backup) with the single-writer lock.
        // The lambda is only called when no interface slice exists yet.
        _backup.CaptureInterfacesIfAbsent(() =>
            eligible.Select(BuildSlice).ToList());

        // Mutate: pin loopback on every eligible adapter (v4 + v6).
        foreach (var a in eligible)
        {
            var rc = ApplyOne(a.Guid);
            if (rc != 0)
                return PlatformResult.Fail(PlatformErrorKind.OperationFailed,
                    $"SetInterfaceDnsSettings failed for {a.Name} ({Braced(a.Guid)}): Win32 error {rc}");
        }
        return PlatformResult.Ok();
    }

    /// <inheritdoc/>
    public PlatformResult ReassertLoopback()
    {
        // Re-pin loopback WITHOUT touching the backup.
        foreach (var a in Eligible())
        {
            var rc = ApplyOne(a.Guid);
            if (rc != 0)
                return PlatformResult.Fail(PlatformErrorKind.OperationFailed,
                    $"SetInterfaceDnsSettings failed for {a.Name} ({Braced(a.Guid)}): Win32 error {rc}");
        }
        return PlatformResult.Ok();
    }

    /// <inheritdoc/>
    public PlatformResult RestoreDns()
    {
        var state = _backup.Load();
        if (state is null || state.Interfaces.Count == 0)
            return PlatformResult.Ok();   // nothing recorded => already restored / never applied

        foreach (var slice in state.Interfaces)
        {
            if (!Guid.TryParse(slice.InterfaceGuid, out var guid))
                return PlatformResult.Fail(PlatformErrorKind.OperationFailed,
                    $"backup contains an unparseable interface GUID: {slice.InterfaceGuid}");

            // IPv4 stack: restore prior static servers, or revert to DHCP.
            var rc4 = slice.WasIpv4Static && slice.Ipv4Servers is { Count: > 0 }
                ? _setter.SetNameServer(guid, string.Join(",", slice.Ipv4Servers), ipv6: false)
                : _setter.ClearToDhcp(guid, ipv6: false);
            if (rc4 != 0)
                return PlatformResult.Fail(PlatformErrorKind.OperationFailed,
                    $"restore (v4) failed for {slice.InterfaceGuid}: Win32 error {rc4}");

            // IPv6 stack: restore prior static servers, or revert to DHCP.
            var rc6 = slice.WasIpv6Static && slice.Ipv6Servers is { Count: > 0 }
                ? _setter.SetNameServer(guid, string.Join(",", slice.Ipv6Servers), ipv6: true)
                : _setter.ClearToDhcp(guid, ipv6: true);
            if (rc6 != 0)
                return PlatformResult.Fail(PlatformErrorKind.OperationFailed,
                    $"restore (v6) failed for {slice.InterfaceGuid}: Win32 error {rc6}");
        }

        // Fully successful restore: clear the interface slice of the backup while preserving other slices.
        // Routed through SaveOrDeleteIfEmpty so the backup file is removed once this is the last slice.
        _backup.SaveOrDeleteIfEmpty(state with { Interfaces = Array.Empty<InterfaceDnsBackup>() });
        return PlatformResult.Ok();
    }

    /// <inheritdoc/>
    public bool IsLoopbackApplied() => _backup.Load() is { Interfaces.Count: > 0 };

    private uint ApplyOne(Guid guid)
    {
        var rc4 = _setter.SetNameServer(guid, LoopbackV4, ipv6: false);
        if (rc4 != 0) return rc4;
        return _setter.SetNameServer(guid, LoopbackV6, ipv6: true);
    }
}

/// <summary>Real enumeration seam: managed NetworkInterface.GetAllNetworkInterfaces() +
/// GetIPProperties().DnsAddresses (verified R[2]; includes down/VPN/vEthernet adapters,
/// no native free needed). NetworkInterface.Id is the braced adapter GUID → Guid.Parse.
/// DNS addresses are returned as plain strings; the configurator partitions them by address
/// family via IPAddress.Parse + AddressFamily (IC-5).</summary>
[SupportedOSPlatform("windows10.0.19041")]
internal sealed class SystemNetworkInterfaceQuery : INetworkInterfaceQuery
{
    public IReadOnlyList<AdapterInfo> GetAdapters()
    {
        var list = new List<AdapterInfo>();
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!Guid.TryParse(ni.Id, out var guid)) continue; // skip anything without a parseable adapter GUID
            IReadOnlyList<string> dns;
            try
            {
                dns = ni.GetIPProperties().DnsAddresses.Select(a => a.ToString()).ToList();
            }
            catch (NetworkInformationException)
            {
                dns = Array.Empty<string>();
            }
            list.Add(new AdapterInfo(guid, ni.Name, ni.NetworkInterfaceType, dns));
        }
        return list;
    }
}

/// <summary>Real DNS-write seam over IpHlpDnsApi (verified R[0]/R[1]). Returns Win32 error codes.</summary>
[SupportedOSPlatform("windows10.0.19041")]
internal sealed class IpHlpInterfaceDnsSetter : IInterfaceDnsSetter
{
    public uint SetNameServer(Guid interfaceGuid, string serverList, bool ipv6) =>
        IpHlpDnsApi.SetNameServer(interfaceGuid, serverList, ipv6);

    public uint ClearToDhcp(Guid interfaceGuid, bool ipv6) =>
        IpHlpDnsApi.ClearToDhcp(interfaceGuid, ipv6);
}
