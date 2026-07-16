namespace DnsCryptControl.UI.Models;

/// <summary>
/// The UI's own copy of the authoritative "is protection on" intent, read off disk
/// (B3) so the master toggle shows last-known state even when the helper is
/// unreachable. Deliberately NOT a reference to <c>DnsCryptControl.Service.State.ProtectionState</c>
/// — the UI must not reference the Service project — but matches its property names
/// and on-disk JSON casing exactly (verified against
/// <c>src/DnsCryptControl.Service/State/ProtectionStateStore.cs</c>).
/// </summary>
public sealed record ProtectionIntent(bool ProtectionEnabled, bool KillSwitchEnabled, bool LeakMitigationsEnabled);
