using DnsCryptControl.Core.Stamps;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// Classifies whether a resolver endpoint is unreachable because of the kill switch, WITHOUT
/// probing it — from the stamp's protocol + port and the live kill-switch state. The kill switch
/// blocks outbound UDP/53, TCP/53, and TCP/853 machine-wide (see
/// <c>Service/Windows/FirewallKillSwitch.cs</c>), so such a row is truthfully "blocked" (the proxy
/// can't reach it either) and must be excluded from a probe rather than probed and mislabeled.
/// </summary>
public static class KillSwitchClassification
{
    /// <summary>
    /// True when the kill switch is on and it would block this endpoint: any port-53 endpoint (both
    /// UDP and TCP 53 are blocked), or a DoT endpoint on 853 (TCP/853 is blocked; DoQ is UDP/853, which
    /// the kill switch leaves open).
    /// </summary>
    public static bool IsBlockedByKillSwitch(StampProtocol protocol, int port, bool killSwitchEnabled)
    {
        if (!killSwitchEnabled) return false;
        if (port == 53) return true;                              // UDP/53 and TCP/53 both blocked
        if (port == 853 && protocol == StampProtocol.DoT) return true; // TCP/853 blocked; DoQ (UDP/853) is not
        return false;
    }
}
