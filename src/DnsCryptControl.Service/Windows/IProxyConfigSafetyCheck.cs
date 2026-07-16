namespace DnsCryptControl.Service.Windows;

/// <summary>Validates that the active dnscrypt-proxy.toml can operate safely when all outbound
/// port 53 traffic is blocked. This is required before enabling the kill switch because Windows
/// Firewall BLOCK beats any per-app ALLOW, so the proxy MUST run off port 53.</summary>
internal interface IProxyConfigSafetyCheck
{
    /// <summary>True iff the ACTIVE dnscrypt-proxy.toml can operate with ALL outbound :53 blocked
    /// (netprobe disabled + not bootstrapping on plaintext :53). Reason is non-null when unsafe.</summary>
    (bool Safe, string? Reason) IsSafeUnderPort53Block();
}
