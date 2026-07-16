namespace DnsCryptControl.Platform;

/// <summary>Whether a system change needs a reboot to fully take effect (e.g. Dnscache cannot be
/// stopped at runtime, so SMHNR registry changes apply on next Dnscache start).</summary>
public enum RebootAdvisory { None, Recommended }
