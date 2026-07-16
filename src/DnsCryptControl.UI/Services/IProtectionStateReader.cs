using DnsCryptControl.UI.Models;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// Reads the authoritative "is protection on" intent off disk (B3) — the master
/// toggle's source of truth, which works even when the helper is unreachable.
/// </summary>
public interface IProtectionStateReader
{
    ProtectionIntent Read();
}
