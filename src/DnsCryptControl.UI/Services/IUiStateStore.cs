using DnsCryptControl.UI.Models;

namespace DnsCryptControl.UI.Services;

/// <summary>Loads and persists the per-user <see cref="UiState"/>. Fail-closed reads; best-effort writes.</summary>
public interface IUiStateStore
{
    /// <summary>Reads the UI state, returning defaults on any missing/corrupt file (never throws).</summary>
    UiState Load();

    /// <summary>Persists the UI state atomically; failures are swallowed (these are non-critical prefs).</summary>
    void Save(UiState state);
}
