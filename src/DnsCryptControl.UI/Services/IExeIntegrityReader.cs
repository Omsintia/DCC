namespace DnsCryptControl.UI.Services;

/// <summary>
/// Read-only, offline facts about an installed executable, for the Settings integrity panel (Phase 5f).
/// The SHA-256 is <b>display-only transparency</b> — it is NEVER compared to an embedded pin to produce a
/// verdict (that would be a UI-side pin, the drift class the design forbids). The trust verdict is derived
/// separately in <c>SettingsViewModel</c> from the helper's launch gate (a running proxy ⇒ verified).
/// </summary>
/// <param name="Path">The exe path that was inspected.</param>
/// <param name="FileVersion">The file version string, or null if unavailable / not a PE file.</param>
/// <param name="Sha256Hex">Lowercase-hex SHA-256 of the file bytes, or null if unreadable.</param>
/// <param name="Exists">Whether the file existed and was readable.</param>
public sealed record ExeIntegrityInfo(string Path, string? FileVersion, string? Sha256Hex, bool Exists);

/// <summary>Reads offline integrity facts about an executable. Fail-closed — never throws.</summary>
public interface IExeIntegrityReader
{
    /// <summary>Read path + file version + SHA-256 of the exe at <paramref name="exePath"/>. A missing or
    /// locked file yields <see cref="ExeIntegrityInfo.Exists"/> = false with null hash/version — never throws.</summary>
    ExeIntegrityInfo Read(string exePath);
}
