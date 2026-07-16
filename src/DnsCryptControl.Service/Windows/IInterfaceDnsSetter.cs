namespace DnsCryptControl.Service.Windows;

/// <summary>Seam over the privileged IP Helper DNS write surface (<c>IpHlpDnsApi</c>).
/// Each method returns the Win32 error code (0 = NO_ERROR = success). Extracted so the
/// configurator logic is unit-testable; the live impl is exercised under ManualIntegration.</summary>
internal interface IInterfaceDnsSetter
{
    /// <summary>Set static DNS <paramref name="serverList"/> ("127.0.0.1" for v4, "::1" for v6)
    /// on the given stack. Returns the Win32 error code (0 = success).</summary>
    uint SetNameServer(System.Guid interfaceGuid, string serverList, bool ipv6);

    /// <summary>Clear static DNS → revert that stack to DHCP/automatic. Returns the Win32 error code.</summary>
    uint ClearToDhcp(System.Guid interfaceGuid, bool ipv6);
}
