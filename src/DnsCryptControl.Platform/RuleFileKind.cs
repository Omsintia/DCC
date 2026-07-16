namespace DnsCryptControl.Platform;

/// <summary>The closed set of rule-file kinds the helper will write. Each maps to a
/// fixed filename the store owns; the untrusted IPC string is parsed into this enum and
/// never used as a path component (CWE-22).</summary>
public enum RuleFileKind
{
    BlockedNames,
    AllowedNames,
    BlockedIps,
    AllowedIps,
    Cloaking,
    Forwarding,
    CaptivePortals,
}
