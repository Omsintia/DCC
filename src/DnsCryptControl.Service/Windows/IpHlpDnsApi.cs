using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace DnsCryptControl.Service.Windows;

/// <summary>Pure decision helper for SetInterfaceDnsSettings arguments — unit-testable without the OS.
/// Set DNS: Flags=NAMESERVER, non-empty NameServer. Clear (revert to DHCP): same Flags, empty NameServer.
/// IPv6 stacks OR in DNS_SETTING_IPV6.</summary>
internal static class IpHlpDnsFlags
{
    /// <summary>Returns (Version, Flags, useEmptyNameServer) for a Set/clear call on the given stack.</summary>
    internal static (uint version, ulong flags, bool useEmptyNameServer) BuildSetArguments(bool ipv6, bool clear)
    {
        var flags = IpHlpDnsConstants.DNS_SETTING_NAMESERVER;
        if (ipv6) flags |= IpHlpDnsConstants.DNS_SETTING_IPV6;
        return (IpHlpDnsConstants.DNS_INTERFACE_SETTINGS_VERSION1, flags, clear);
    }
}

/// <summary>Managed wrapper over the iphlpapi DNS p/invokes. Performs the
/// Marshal.StringToHGlobalUni alloc + finally-free dance and returns the raw Win32 rc
/// (0 = NO_ERROR = success). Group B's adapter configurator consumes THESE, not the raw p/invokes.</summary>
[SupportedOSPlatform("windows10.0.19041")]
internal static class IpHlpDnsApi
{
    internal const uint NoError = 0;

    /// <summary>Set static DNS NameServer ("127.0.0.1" for v4, "::1" for v6) on the given stack.
    /// Returns the Win32 error code (0 = success).</summary>
    internal static uint SetNameServer(Guid interfaceGuid, string serverList, bool ipv6)
    {
        ArgumentException.ThrowIfNullOrEmpty(serverList);
        return Set(interfaceGuid, serverList, ipv6, clear: false);
    }

    /// <summary>Clear static DNS → revert that stack to DHCP/automatic (empty NameServer).
    /// Returns the Win32 error code (0 = success).</summary>
    internal static uint ClearToDhcp(Guid interfaceGuid, bool ipv6) =>
        Set(interfaceGuid, serverList: null, ipv6, clear: true);

    private static uint Set(Guid interfaceGuid, string? serverList, bool ipv6, bool clear)
    {
        var (version, flags, useEmpty) = IpHlpDnsFlags.BuildSetArguments(ipv6, clear);
        var nameServerPtr = nint.Zero;
        try
        {
            if (!useEmpty && serverList is not null)
                nameServerPtr = Marshal.StringToHGlobalUni(serverList);

            var settings = new IpHlpDnsNativeMethods.DNS_INTERFACE_SETTINGS
            {
                Version = version,
                Flags = flags,
                NameServer = nameServerPtr,
            };
            return IpHlpDnsNativeMethods.SetInterfaceDnsSettings(interfaceGuid, in settings);
        }
        finally
        {
            if (nameServerPtr != nint.Zero) Marshal.FreeHGlobal(nameServerPtr);
        }
    }
}
