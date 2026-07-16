using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace DnsCryptControl.Service.Windows;

/// <summary>Resolves the SID of the user owning the ACTIVE interactive session — the physical
/// console OR an RDP / Hyper-V Enhanced-Session — so the SYSTEM helper can grant exactly that user
/// ReadWrite on the pipe (spec §5.1). Uses <c>WTSEnumerateSessions</c> to find the active session
/// rather than only <c>WTSGetActiveConsoleSessionId</c>, so a user connected over RDP (whose session
/// is NOT the physical console) is found.
///
/// <para>Returns false when NO interactive user is active yet — e.g. the helper auto-started at boot
/// before anyone logged in. Callers must NOT fall back to a broad SID (BuiltinUsers); instead the
/// pipe accept loop re-resolves on each iteration and rebuilds the DACL, so the interactive user is
/// granted as soon as a session becomes active, WITHOUT a service restart (the "Phase 5 retry
/// logic"). Fails closed on any interop error.</para></summary>
[SupportedOSPlatform("windows")]
public static partial class ConsoleSessionUser
{
    private static readonly nint WtsCurrentServerHandle = nint.Zero; // WTS_CURRENT_SERVER_HANDLE

    [LibraryImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WTSEnumerateSessionsW(
        nint hServer, uint reserved, uint version, out nint ppSessionInfo, out uint pCount);

    [LibraryImport("wtsapi32.dll")]
    private static partial void WTSFreeMemory(nint pMemory);

    [LibraryImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WTSQueryUserToken(uint sessionId, out nint token);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint handle);

    // WTS_SESSION_INFOW: DWORD SessionId; LPWSTR pWinStationName; WTS_CONNECTSTATE_CLASS State;
    [StructLayout(LayoutKind.Sequential)]
    private struct WTS_SESSION_INFO
    {
        public uint SessionId;
        public nint pWinStationName; // LPWSTR — unused here; freed with the enumeration block
        public int State;            // WTS_CONNECTSTATE_CLASS
    }

    /// <summary>
    /// Resolves the SID of the user in the currently ACTIVE interactive session (console or RDP).
    /// Returns false if no such session exists yet (e.g. pre-login at boot) or the token cannot be
    /// obtained. Never falls back to a broad SID — fails closed.
    /// </summary>
    public static bool TryResolveActiveInteractiveUser(out SecurityIdentifier sid)
    {
        sid = null!;
        if (!WTSEnumerateSessionsW(WtsCurrentServerHandle, 0, 1, out var pInfo, out var count))
            return false;
        try
        {
            var size = Marshal.SizeOf<WTS_SESSION_INFO>();
            // Clamp the OS-supplied count to a safe non-negative bound (a pathological >int.MaxValue count
            // yields 0 iterations rather than wrapping negative) - see SessionUserSelection.
            var total = SessionUserSelection.ClampCount(count);
            for (var i = 0; i < total; i++)
            {
                var info = Marshal.PtrToStructure<WTS_SESSION_INFO>(pInfo + (i * size));
                // Only an ACTIVE, non-services (id 0 is the services session) interactive session.
                if (!SessionUserSelection.IsCandidateSession(info.State, info.SessionId))
                    continue;
                if (!WTSQueryUserToken(info.SessionId, out var token))
                    continue;
                try
                {
                    using var identity = new WindowsIdentity(token);
                    // Never grant the pipe ACE to a null OR broad SID (fail-closed belt-and-suspenders).
                    if (SessionUserSelection.IsBroadOrNullSid(identity.User))
                        continue;
                    sid = identity.User!;
                    return true;
                }
#pragma warning disable CA1031 // fail-closed boundary: ANY fault building/reading the token skips this session
                // and keeps scanning. WindowsIdentity can throw types beyond Security/Argument/UnauthorizedAccess
                // (e.g. Win32Exception from token marshalling); an unhandled type on the FIRST accept-loop tick
                // would otherwise fault the LocalSystem host at startup. This branch never yields a SID.
                catch (Exception)
#pragma warning restore CA1031
                {
                    // skip this session; try the next
                }
                finally
                {
                    CloseHandle(token);
                }
            }
            return false; // no active interactive session with a resolvable user
        }
        finally
        {
            WTSFreeMemory(pInfo);
        }
    }
}
