using System.Security.Principal;

namespace DnsCryptControl.Service.Windows;

/// <summary>
/// Pure, WTS-free decision helpers extracted from <see cref="ConsoleSessionUser"/> so the count-safety,
/// candidate-session, and never-broad-SID logic can be unit- and fuzz-tested without the native session
/// enumeration (finding 2026-07-08). The live WTS/token P/Invoke stays in ConsoleSessionUser; these deciders
/// are deterministic and never throw.
/// </summary>
internal static class SessionUserSelection
{
    private const int WTSActive = 0; // WTS_CONNECTSTATE_CLASS.WTSActive

    /// <summary>Clamps the OS-supplied session count to a safe non-negative loop bound. A pathological
    /// <paramref name="count"/> &gt; <see cref="int.MaxValue"/> yields 0 (fail-closed: zero iterations)
    /// instead of wrapping to a negative int, so the marshalling loop can never run a negative/overshooting
    /// bound.</summary>
    public static int ClampCount(uint count) => count > int.MaxValue ? 0 : (int)count;

    /// <summary>True for an ACTIVE, non-services session (session id 0 is the services session) - the only
    /// sessions whose interactive user may be granted the pipe ACE.</summary>
    public static bool IsCandidateSession(int state, uint sessionId) => state == WTSActive && sessionId != 0;

    /// <summary>True when <paramref name="sid"/> is null or a broad well-known group SID (World / BuiltinUsers
    /// / AuthenticatedUser / Anonymous / Network / Interactive). A belt-and-suspenders guard so the resolver
    /// can NEVER return a broad SID for the interactive-user pipe ACE - only a specific account SID.</summary>
    public static bool IsBroadOrNullSid(SecurityIdentifier? sid)
    {
        if (sid is null)
        {
            return true;
        }

        return sid.IsWellKnown(WellKnownSidType.WorldSid)
            || sid.IsWellKnown(WellKnownSidType.BuiltinUsersSid)
            || sid.IsWellKnown(WellKnownSidType.AuthenticatedUserSid)
            || sid.IsWellKnown(WellKnownSidType.AnonymousSid)
            || sid.IsWellKnown(WellKnownSidType.NetworkSid)
            || sid.IsWellKnown(WellKnownSidType.InteractiveSid);
    }
}
