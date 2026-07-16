namespace DnsCryptControl.Platform;

/// <summary>Adds/removes the opt-in Windows Defender Firewall outbound BLOCK rules for plaintext DNS
/// (UDP/53, TCP/53, TCP/853). Idempotent; only ever touches its own product-named rules.</summary>
public interface IFirewallKillSwitch
{
    PlatformResult SetKillSwitch(bool enable);
    bool IsKillSwitchActive();
}
