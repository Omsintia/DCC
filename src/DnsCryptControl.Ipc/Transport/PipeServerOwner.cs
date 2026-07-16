using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace DnsCryptControl.Ipc.Transport;

/// <summary>
/// F11: verifies a connected named-pipe's server-side owner SID is LocalSystem. Defeats a
/// user-level impostor pipe that won the create race and would otherwise feed the UI a
/// forged "protected" status. Fails closed (returns false) on any interop failure or
/// non-SYSTEM owner; throws nothing itself.
/// </summary>
[SupportedOSPlatform("windows")]
internal static partial class PipeServerOwner
{
    private const int SE_KERNEL_OBJECT = 6;
    private const uint OWNER_SECURITY_INFORMATION = 0x00000001;
    private const int ERROR_SUCCESS = 0;

    [LibraryImport("advapi32.dll", SetLastError = false)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int GetSecurityInfo(
        nint handle, int objectType, uint securityInfo,
        out nint ppsidOwner, nint ppsidGroup, nint ppDacl, nint ppSacl, out nint ppSecurityDescriptor);

    [LibraryImport("kernel32.dll", SetLastError = false)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial nint LocalFree(nint hMem);

    public static bool IsServerLocalSystem(SafePipeHandle pipe)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        if (pipe.IsInvalid || pipe.IsClosed) return false;
        var descriptor = nint.Zero;
        var added = false;
        try
        {
            pipe.DangerousAddRef(ref added);
            int rc = GetSecurityInfo(pipe.DangerousGetHandle(), SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION,
                out nint ownerPsid, nint.Zero, nint.Zero, nint.Zero, out descriptor);
            if (rc != ERROR_SUCCESS || ownerPsid == nint.Zero) return false;
            var owner = new SecurityIdentifier(ownerPsid);                       // deep-copies immediately
            return owner.Equals(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        }
        finally
        {
            if (descriptor != nint.Zero) LocalFree(descriptor);                  // free ONLY the descriptor
            if (added) pipe.DangerousRelease();
        }
    }
}
