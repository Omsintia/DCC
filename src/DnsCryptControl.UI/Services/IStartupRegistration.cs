namespace DnsCryptControl.UI.Services;

/// <summary>
/// Registers/unregisters the app for launch at user logon (Phase 5f). A projection of
/// <see cref="Models.UiState.StartWithWindows"/> onto the per-user HKCU Run key — user-scope,
/// never elevates. All operations are fail-closed (a locked/denied hive degrades to
/// "not registered", never crashes the UI).
/// </summary>
public interface IStartupRegistration
{
    /// <summary>True if a launch-at-logon entry currently exists for this app.</summary>
    bool IsRegistered();

    /// <summary>Add the launch-at-logon entry (idempotent). Returns true if the Run key now holds it,
    /// false if the write was rejected (locked/denied hive) — the caller must not persist an intent the
    /// registry refused, or the checkbox and the real Run-key state would silently drift.</summary>
    bool Register();

    /// <summary>Remove the launch-at-logon entry (idempotent). Returns true on success (or already-absent),
    /// false if the delete was rejected.</summary>
    bool Unregister();
}

/// <summary>
/// Seam over the HKCU <c>...\CurrentVersion\Run</c> key so <see cref="StartupRegistration"/> is
/// unit-testable without touching the real registry hive (tests inject a fake).
/// </summary>
public interface IRunKeyAccess
{
    /// <summary>The string value stored under <paramref name="name"/>, or null if absent.</summary>
    string? GetValue(string name);

    /// <summary>Create or overwrite the string value under <paramref name="name"/>.</summary>
    void SetValue(string name, string value);

    /// <summary>Delete the value under <paramref name="name"/> (no-op if absent).</summary>
    void DeleteValue(string name);
}
