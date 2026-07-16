using System.Runtime.Versioning;
using DnsCryptControl.Service.Windows;
using Xunit;

namespace DnsCryptControl.Service.Tests;

public class IpHlpDnsApiTests
{
    private const uint Version1 = 1;
    private const ulong SettingIpv6 = 0x0001;
    private const ulong SettingNameServer = 0x0002;

    [Fact]
    public void BuildSetArguments_ipv4_set_usesNameServerFlagOnly_versionOne_nonEmpty()
    {
        var (version, flags, useEmpty) = IpHlpDnsFlags.BuildSetArguments(ipv6: false, clear: false);
        Assert.Equal(Version1, version);
        Assert.Equal(SettingNameServer, flags);
        Assert.False(useEmpty);
    }

    [Fact]
    public void BuildSetArguments_ipv6_set_orsInIpv6Flag()
    {
        var (version, flags, useEmpty) = IpHlpDnsFlags.BuildSetArguments(ipv6: true, clear: false);
        Assert.Equal(Version1, version);
        Assert.Equal(SettingIpv6 | SettingNameServer, flags);
        Assert.False(useEmpty);
    }

    [Fact]
    public void BuildSetArguments_ipv4_clear_keepsNameServerFlag_butEmptyNameServer()
    {
        var (version, flags, useEmpty) = IpHlpDnsFlags.BuildSetArguments(ipv6: false, clear: true);
        Assert.Equal(Version1, version);
        Assert.Equal(SettingNameServer, flags);
        Assert.True(useEmpty);
    }

    [Fact]
    public void BuildSetArguments_ipv6_clear_keepsBothFlags_butEmptyNameServer()
    {
        var (version, flags, useEmpty) = IpHlpDnsFlags.BuildSetArguments(ipv6: true, clear: true);
        Assert.Equal(Version1, version);
        Assert.Equal(SettingIpv6 | SettingNameServer, flags);
        Assert.True(useEmpty);
    }

    [Fact]
    [Trait("Category", "ManualIntegration")]
    [SupportedOSPlatform("windows10.0.19041")]
    public void RoundTrip_setsLoopbackThenRestores_onFirstNonLoopbackAdapter()
    {
        if (!System.OperatingSystem.IsWindowsVersionAtLeast(10, 0, 0, 19041))
            return; // fail-closed surface is exercised by the unit tests; live test is a no-op pre-19041.

        var nic = System.Linq.Enumerable.FirstOrDefault(
            System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces(),
            n => n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback);
        Assert.NotNull(nic);

        var guid = System.Guid.Parse(nic!.Id);
        var priorV4 = System.Linq.Enumerable.ToArray(
            System.Linq.Enumerable.Select(nic.GetIPProperties().DnsAddresses, a => a.ToString()));

        try
        {
            Assert.Equal(IpHlpDnsApi.NoError, IpHlpDnsApi.SetNameServer(guid, "127.0.0.1", ipv6: false));
            Assert.Equal(IpHlpDnsApi.NoError, IpHlpDnsApi.SetNameServer(guid, "::1", ipv6: true));

            var afterDns = System.Linq.Enumerable.ToArray(
                System.Linq.Enumerable.Select(
                    System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                        .First(n => n.Id == nic.Id).GetIPProperties().DnsAddresses,
                    a => a.ToString()));
            Assert.Contains("127.0.0.1", afterDns);
        }
        finally
        {
            // Restore: if there were prior static servers re-apply them, else revert to DHCP.
            if (priorV4.Length > 0)
                IpHlpDnsApi.SetNameServer(guid, string.Join(",", priorV4), ipv6: false);
            else
                IpHlpDnsApi.ClearToDhcp(guid, ipv6: false);
            IpHlpDnsApi.ClearToDhcp(guid, ipv6: true);
        }
    }
}
