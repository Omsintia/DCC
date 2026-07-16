using System;
using System.IO;
using System.Text.Json;
using DnsCryptControl.Core.Security;
using DnsCryptControl.UI.Models;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// Off-disk reader for the authoritative "is protection on" intent (B3). Reads the
/// exact file the helper's <c>ProtectionStateStore</c> writes — verified by reading
/// (not referencing) <c>src/DnsCryptControl.Service/State/ProtectionStateStore.cs</c>,
/// <c>ProtectionState</c>, and <c>ProtectedPaths.ProtectionStateFile</c> — without the
/// UI taking a project reference on Service. Fails closed to all-false
/// ("unprotected"/"off") on any read/parse failure so a corrupt or inaccessible file
/// never reports protection that isn't real.
/// </summary>
public sealed class ProtectionStateReader : IProtectionStateReader
{
    private static readonly ProtectionIntent AllFalse = new(false, false, false);

    private readonly string _stateFilePath;

    /// <param name="stateFilePath">Defaults to <see cref="UiPaths.ProtectionStateFile"/>
    /// (the real Service-owned path, matching <c>ProtectedPaths.ProtectionStateFile</c>).
    /// Tests inject a temp file path.</param>
    public ProtectionStateReader(string? stateFilePath = null)
    {
        _stateFilePath = stateFilePath ?? UiPaths.ProtectionStateFile;
    }

    public ProtectionIntent Read()
    {
        try
        {
            if (!File.Exists(_stateFilePath))
            {
                return AllFalse;
            }

            if (JsonStateReadGuard.IsOversized(_stateFilePath))
            {
                return AllFalse; // OOM/amplification guard: a corrupt/hostile oversized file reads as "off" (fail-closed)
            }

            var json = File.ReadAllText(_stateFilePath);
            if (!JsonStateReadGuard.IsWellFormedWithinDepth(json))
            {
                return AllFalse; // depth/malformed guard
            }

            return JsonSerializer.Deserialize(json, ProtectionIntentJsonContext.Default.ProtectionIntent) ?? AllFalse;
        }
        catch (IOException)
        {
            return AllFalse;
        }
        catch (UnauthorizedAccessException)
        {
            return AllFalse;
        }
        catch (JsonException)
        {
            return AllFalse;
        }
    }
}
