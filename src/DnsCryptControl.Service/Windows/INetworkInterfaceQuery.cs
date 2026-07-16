using System.Collections.Generic;
using System.Net.NetworkInformation;

namespace DnsCryptControl.Service.Windows;

/// <summary>One enumerated network interface reduced to the fields the configurator needs.
/// <see cref="Guid"/> is parsed from <c>NetworkInterface.Id</c> (braced GUID), which the
/// IP Helper DNS API accepts by value (verified R[2]). <see cref="DnsServers"/> are the
/// adapter's current DNS server addresses as strings (managed read; captured for the backup).
/// The strings may be IPv4 or IPv6; callers split by parsing via <c>IPAddress.Parse</c> and
/// checking <c>AddressFamily</c>.</summary>
internal sealed record AdapterInfo(
    System.Guid Guid,
    string Name,
    NetworkInterfaceType Type,
    IReadOnlyList<string> DnsServers);

/// <summary>Seam over <c>NetworkInterface.GetAllNetworkInterfaces()</c> +
/// <c>GetIPProperties().DnsAddresses</c>. Extracted so the configurator's adapter-selection
/// and backup-capture logic is unit-testable without touching live adapters.</summary>
internal interface INetworkInterfaceQuery
{
    /// <summary>Enumerate every adapter (including down/VPN/vEthernet), as <see cref="AdapterInfo"/>.</summary>
    IReadOnlyList<AdapterInfo> GetAdapters();
}
