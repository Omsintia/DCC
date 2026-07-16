using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace DnsCryptControl.Service.Windows;

/// <summary>
/// Isolated IP Helper (iphlpapi.dll) P/Invoke surface for per-interface DNS configuration —
/// set the loopback NameServer lock. GUID is passed BY VALUE (confirmed: C signature is
/// <c>GUID Interface</c>, not a pointer). These NETIOAPI functions return the Win32 error code
/// directly (NO_ERROR=0); they do NOT use SetLastError. The struct is kept fully blittable
/// (PWSTR -> nint, ULONG64 Flags -> ulong) so LibraryImport source-gen emits a trivial stub and
/// the caller controls all PWSTR allocation/lifetime. Min OS Windows 10 build 19041.
/// </summary>
[SupportedOSPlatform("windows10.0.19041")]
internal static partial class IpHlpDnsNativeMethods
{
    // Layout note: ULONG Version (4) followed by ULONG64 Flags (8) — the natural 4-byte pad after
    // Version is REQUIRED. Do NOT add Pack. PWSTRs are nint so the struct stays blittable.
    [StructLayout(LayoutKind.Sequential)]
    internal struct DNS_INTERFACE_SETTINGS
    {
        public uint Version;
        public ulong Flags;
        public nint Domain;
        public nint NameServer;
        public nint SearchList;
        public uint RegistrationEnabled;
        public uint RegisterAdapterName;
        public uint EnableLLMNR;
        public uint QueryAdapterName;
        public nint ProfileNameServer;
    }

    // GUID by value (NOT const GUID*). Return = Win32 error (NO_ERROR=0). NO SetLastError.
    [LibraryImport("iphlpapi.dll")]
    internal static partial uint SetInterfaceDnsSettings(Guid interfaceGuid, in DNS_INTERFACE_SETTINGS settings);
}
