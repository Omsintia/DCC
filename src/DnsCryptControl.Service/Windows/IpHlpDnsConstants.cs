namespace DnsCryptControl.Service.Windows;

/// <summary>
/// Compile-time constants for the IP Helper DNS interface settings API.
/// These are pure numeric literals — no OS call is needed to read them —
/// so this class carries no <c>[SupportedOSPlatform]</c> annotation and can
/// be referenced by platform-neutral unit tests.
/// </summary>
internal static class IpHlpDnsConstants
{
    internal const uint DNS_INTERFACE_SETTINGS_VERSION1 = 1;

    // DNS_SETTING_* bitmap (ULONG64) — the 8 MS-Learn-documented values (netioapi.h / DNS_INTERFACE_SETTINGS page).
    internal const ulong DNS_SETTING_IPV6 = 0x0001;
    internal const ulong DNS_SETTING_NAMESERVER = 0x0002;
    internal const ulong DNS_SETTING_SEARCHLIST = 0x0004;
    internal const ulong DNS_SETTING_REGISTRATION_ENABLED = 0x0008;
    internal const ulong DNS_SETTING_DOMAIN = 0x0020;
    internal const ulong DNS_SETTINGS_ENABLE_LLMNR = 0x0080;
    internal const ulong DNS_SETTINGS_QUERY_ADAPTER_NAME = 0x0100;
    internal const ulong DNS_SETTING_PROFILE_NAMESERVER = 0x0200;
}
