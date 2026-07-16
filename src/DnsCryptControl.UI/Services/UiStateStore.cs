using System;
using System.IO;
using System.Text.Json;
using DnsCryptControl.Core.Security;
using DnsCryptControl.UI.Models;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// Persists <see cref="UiState"/> to <c>%LOCALAPPDATA%\DnsCryptControl\ui-state.json</c> — the
/// app's first per-user store and its first file writer. Reads fail closed to defaults (a corrupt
/// or inaccessible file must never crash the UI); writes are atomic (temp + replace) and swallow
/// failures (losing a favorite is never worth an exception).
/// </summary>
public sealed class UiStateStore : IUiStateStore
{
    private readonly string _path;

    /// <param name="path">Defaults to <see cref="UiPaths.UiStateFile"/>. Tests inject a temp path.</param>
    public UiStateStore(string? path = null) => _path = path ?? UiPaths.UiStateFile;

    public UiState Load()
    {
        try
        {
            if (!File.Exists(_path)) return new UiState();
            if (JsonStateReadGuard.IsOversized(_path)) return new UiState();             // OOM/amplification guard
            var json = File.ReadAllText(_path);
            if (!JsonStateReadGuard.IsWellFormedWithinDepth(json)) return new UiState();  // depth/malformed guard
            return JsonSerializer.Deserialize(json, UiStateJsonContext.Default.UiState) ?? new UiState();
        }
        catch (IOException) { return new UiState(); }
        catch (UnauthorizedAccessException) { return new UiState(); }
        catch (JsonException) { return new UiState(); }
    }

    public void Save(UiState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        try
        {
            var dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            var json = JsonSerializer.Serialize(state, UiStateJsonContext.Default.UiState);
            var tmp = _path + ".tmp";
            File.WriteAllText(tmp, json);
            if (File.Exists(_path)) File.Replace(tmp, _path, destinationBackupFileName: null);
            else File.Move(tmp, _path);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
