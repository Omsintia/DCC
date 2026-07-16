using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;
using System.Text.Json;
using DnsCryptControl.Core.Security;
using DnsCryptControl.Service.Windows;

namespace DnsCryptControl.Service.State;

/// <summary>Atomic, ACL'd persistence for the unified DNS backup (state\backup.json). Writes via
/// temp + File.Replace/File.Move and tightens the file/dir DACL to SYSTEM+Administrators (Users-Read),
/// gated to elevated, mirroring FileSystemConfigStore. A single internal lock guarantees single-writer
/// safety. The CaptureXxxIfAbsent helpers merge ONLY a missing slice so an un-restored pristine capture
/// is never overwritten (R[10] idempotency rule).</summary>
[SupportedOSPlatform("windows")]
public sealed class DnsBackupStore
{
    private readonly string _backupFilePath;
    private readonly object _gate = new();

    public DnsBackupStore(string backupFilePath)
    {
        ArgumentException.ThrowIfNullOrEmpty(backupFilePath);
        _backupFilePath = backupFilePath;
    }

    public bool Exists => File.Exists(_backupFilePath);

    public DnsBackupState? Load()
    {
        lock (_gate)
        {
            return LoadNoLock();
        }
    }

    private DnsBackupState? LoadNoLock()
    {
        try
        {
            if (!File.Exists(_backupFilePath)) return null;
            if (JsonStateReadGuard.IsOversized(_backupFilePath)) return null;             // OOM/amplification guard
            var json = File.ReadAllText(_backupFilePath);
            if (!JsonStateReadGuard.IsWellFormedWithinDepth(json)) return null;            // depth/malformed guard
            return JsonSerializer.Deserialize(json, DnsBackupJsonContext.Default.DnsBackupState);
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
        catch (JsonException) { return null; }
    }

    public void Save(DnsBackupState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        lock (_gate)
        {
            SaveNoLock(state);
        }
    }

    private void SaveNoLock(DnsBackupState state)
    {
        var dir = Path.GetDirectoryName(_backupFilePath)!;
        Directory.CreateDirectory(dir);
        AclHelper.TryHardenAcl(dir);

        var json = JsonSerializer.Serialize(state, DnsBackupJsonContext.Default.DnsBackupState);
        var temp = _backupFilePath + ".tmp";
        File.WriteAllText(temp, json);
        AclHelper.TryHardenAcl(temp);

        if (File.Exists(_backupFilePath))
            File.Replace(temp, _backupFilePath, destinationBackupFileName: null);
        else
            File.Move(temp, _backupFilePath, overwrite: true);

        AclHelper.TryHardenAcl(_backupFilePath);
    }

    public void Delete()
    {
        lock (_gate)
        {
            DeleteNoLock();
        }
    }

    private void DeleteNoLock()
    {
        try { if (File.Exists(_backupFilePath)) File.Delete(_backupFilePath); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    /// <summary>Revert-path save: if EVERY slice in <paramref name="state"/> is empty (nothing left to
    /// restore), delete the backup file so a clean disable-all leaves zero residue; otherwise Save
    /// normally. Each subsystem's revert clears its own slice and routes through here, so the file
    /// disappears exactly when the LAST remaining slice is cleared. Runs under the single-writer lock.</summary>
    public void SaveOrDeleteIfEmpty(DnsBackupState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        lock (_gate)
        {
            if (state.Interfaces.Count == 0
                && state.RegistryValues.Count == 0
                && state.AddedFirewallRuleNames.Count == 0
                && state.BrowserPolicyValues.Count == 0)
            {
                DeleteNoLock();
            }
            else
            {
                SaveNoLock(state);
            }
        }
    }

    /// <summary>Capture the interface slice ONLY if not already present in an existing backup.</summary>
    public void CaptureInterfacesIfAbsent(Func<IReadOnlyList<InterfaceDnsBackup>> capture)
    {
        ArgumentNullException.ThrowIfNull(capture);
        lock (_gate)
        {
            var existing = LoadNoLock();
            if (existing is not null && existing.Interfaces.Count > 0) return;
            var slice = capture();
            SaveNoLock(Merge(existing) with { Interfaces = slice });
        }
    }

    /// <summary>Capture the SMHNR registry slice ONLY if not already present.</summary>
    public void CaptureRegistryValuesIfAbsent(Func<IReadOnlyList<RegistryValueBackup>> capture)
    {
        ArgumentNullException.ThrowIfNull(capture);
        lock (_gate)
        {
            var existing = LoadNoLock();
            if (existing is not null && existing.RegistryValues.Count > 0) return;
            var slice = capture();
            SaveNoLock(Merge(existing) with { RegistryValues = slice });
        }
    }

    /// <summary>Capture the added-firewall-rule-names slice ONLY if not already present.</summary>
    public void CaptureFirewallRulesIfAbsent(Func<IReadOnlyList<string>> capture)
    {
        ArgumentNullException.ThrowIfNull(capture);
        lock (_gate)
        {
            var existing = LoadNoLock();
            if (existing is not null && existing.AddedFirewallRuleNames.Count > 0) return;
            var slice = capture();
            SaveNoLock(Merge(existing) with { AddedFirewallRuleNames = slice });
        }
    }

    /// <summary>Capture the browser-policy slice ONLY if not already present.</summary>
    public void CaptureBrowserPolicyIfAbsent(Func<IReadOnlyList<RegistryValueBackup>> capture)
    {
        ArgumentNullException.ThrowIfNull(capture);
        lock (_gate)
        {
            var existing = LoadNoLock();
            if (existing is not null && existing.BrowserPolicyValues.Count > 0) return;
            var slice = capture();
            SaveNoLock(Merge(existing) with { BrowserPolicyValues = slice });
        }
    }

    private static DnsBackupState Merge(DnsBackupState? existing) => existing ?? new DnsBackupState
    {
        SchemaVersion = DnsBackupState.CurrentSchemaVersion,
        CreatedUtc = DateTimeOffset.UtcNow.ToString("O"),
        Interfaces = Array.Empty<InterfaceDnsBackup>(),
        RegistryValues = Array.Empty<RegistryValueBackup>(),
        AddedFirewallRuleNames = Array.Empty<string>(),
        BrowserPolicyValues = Array.Empty<RegistryValueBackup>(),
    };

}
