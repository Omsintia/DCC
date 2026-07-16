using System.IO;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;
using DnsCryptControl.Core.Security;
using DnsCryptControl.Service.Windows;

namespace DnsCryptControl.Service.State;

/// <summary>Persisted record of whether the user has protection ENABLED, so boot reconciliation can
/// re-assert fail-closed after a crash/reboot. Distinct from the backup (which records prior system
/// state). JSON, atomic, ACL'd. Defaults to all-false when absent or unreadable (never throws on Load).</summary>
public sealed record ProtectionState(bool ProtectionEnabled, bool KillSwitchEnabled, bool LeakMitigationsEnabled);

// Source-gen (no reflection) — same discipline as the rest of the service state.
[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(ProtectionState))]
internal sealed partial class ProtectionStateJsonContext : JsonSerializerContext
{
}

[SupportedOSPlatform("windows")]
public sealed class ProtectionStateStore
{
    private static readonly ProtectionState Default = new(false, false, false);
    private readonly string _stateFilePath;
    private readonly object _gate = new();

    public ProtectionStateStore(string stateFilePath)
    {
        ArgumentException.ThrowIfNullOrEmpty(stateFilePath);
        _stateFilePath = stateFilePath;
    }

    public ProtectionState Load()
    {
        lock (_gate) { return LoadNoLock(); }
    }

    private ProtectionState LoadNoLock()
    {
        try
        {
            if (!File.Exists(_stateFilePath)) return Default;
            if (JsonStateReadGuard.IsOversized(_stateFilePath)) return Default;             // OOM/amplification guard
            var json = File.ReadAllText(_stateFilePath);
            if (!JsonStateReadGuard.IsWellFormedWithinDepth(json)) return Default;          // depth/malformed guard
            return JsonSerializer.Deserialize(json, ProtectionStateJsonContext.Default.ProtectionState) ?? Default;
        }
        catch (IOException) { return Default; }
        catch (UnauthorizedAccessException) { return Default; }
        catch (JsonException) { return Default; }
    }

    /// <summary>Failure-VISIBLE read (B3). Unlike <see cref="Load"/> (which silently defaults on
    /// ANY failure — the right contract for display/reconciliation callers), this distinguishes
    /// "no state has ever been saved" from "state exists but cannot be read":
    /// file ABSENT → <c>true</c> + all-false default (a fresh install is legitimately unprotected,
    /// matching BootReconciler semantics); file PRESENT but unreadable or undeserializable
    /// (IO/UAC/malformed JSON, incl. a literal <c>null</c>) → <c>false</c> + all-false default.
    /// Enforcement callers (the config write policy) treat <c>false</c> as PROTECTED — fail-closed:
    /// calling <see cref="Load"/> there would fail OPEN on a corrupt state file. Never throws.</summary>
    public bool TryLoad(out ProtectionState state)
    {
        lock (_gate)
        {
            // Oversized present file = corrupt/hostile = unreadable (fail-closed false); an ABSENT file is
            // handled below as a fresh install (IsOversized returns false for a non-existent path).
            if (JsonStateReadGuard.IsOversized(_stateFilePath)) { state = Default; return false; }

            string json;
            try
            {
                json = File.ReadAllText(_stateFilePath);
            }
            // Absent file/directory = fresh install, not a failure. Caught here (instead of a
            // File.Exists pre-check) so a delete between check and read can't misreport.
            catch (FileNotFoundException) { state = Default; return true; }
            catch (DirectoryNotFoundException) { state = Default; return true; }
            catch (IOException) { state = Default; return false; }
            catch (UnauthorizedAccessException) { state = Default; return false; }

            if (!JsonStateReadGuard.IsWellFormedWithinDepth(json)) { state = Default; return false; }

            try
            {
                var loaded = JsonSerializer.Deserialize(json, ProtectionStateJsonContext.Default.ProtectionState);
                if (loaded is null) { state = Default; return false; } // literal "null" carries no state
                state = loaded;
                return true;
            }
            catch (JsonException) { state = Default; return false; }
        }
    }

    public void Save(ProtectionState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        lock (_gate) { SaveNoLock(state); }
    }

    private void SaveNoLock(ProtectionState state)
    {
        var dir = Path.GetDirectoryName(_stateFilePath)!;
        Directory.CreateDirectory(dir);
        AclHelper.TryHardenAcl(dir);

        var json = JsonSerializer.Serialize(state, ProtectionStateJsonContext.Default.ProtectionState);
        var temp = _stateFilePath + ".tmp";
        File.WriteAllText(temp, json);
        AclHelper.TryHardenAcl(temp);

        if (File.Exists(_stateFilePath))
            File.Replace(temp, _stateFilePath, destinationBackupFileName: null);
        else
            File.Move(temp, _stateFilePath, overwrite: true);

        AclHelper.TryHardenAcl(_stateFilePath);
    }

    /// <summary>Atomic read-modify-write under the single-writer lock so concurrent intent updates can't
    /// lose each other's sub-flag (apply/restore/kill-switch/leak-mitigation each flip one field). Load
    /// defaults to all-false when the file is absent/unreadable; <paramref name="transform"/> must return
    /// non-null. Returns the persisted state. May throw IOException/UnauthorizedAccessException from the
    /// write — the caller (ProtectionStateWriter) maps that to a fail-closed PlatformResult.</summary>
    public ProtectionState Update(Func<ProtectionState, ProtectionState> transform)
    {
        ArgumentNullException.ThrowIfNull(transform);
        lock (_gate)
        {
            var current = LoadNoLock();
            var next = transform(current);
            ArgumentNullException.ThrowIfNull(next);
            SaveNoLock(next);
            return next;
        }
    }

}
