using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.Versioning;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.State;
using DnsCryptControl.Service.Windows.Registry;
using Microsoft.Win32;

namespace DnsCryptControl.Service.Windows;

/// <summary>Forces Chrome/Edge/Firefox browser-internal DoH OFF via HKLM enterprise policy
/// (Registry64 view), capturing prior values into the unified backup's BrowserPolicyValues
/// slice for an exact revert.
/// <para>
/// Only ever touches five known policy values plus the Firefox \DNSOverHTTPS leaf it may create;
/// never deletes shared parent policy keys (…\Chrome, …\Edge, …\Firefox) and never touches the
/// *Templates values.  Logic runs against the injectable <see cref="IRegistryRoot"/> seam so it
/// is unit-testable with an in-memory fake; the live-registry path is covered by ManualIntegration.
/// </para>
/// <para>
/// <b>Applied predicate:</b> <see cref="IsBrowserDohPolicyApplied"/> returns <c>true</c> iff
/// Chrome <em>and</em> Edge <c>DnsOverHttpsMode</c> both equal the string <c>"off"</c> (ordinal,
/// case-sensitive). Firefox is advisory-only and does not gate the predicate.
/// </para></summary>
[SupportedOSPlatform("windows")]
internal sealed class BrowserDohPolicy : IBrowserDohPolicy
{
    // -----------------------------------------------------------------
    // Registry key paths and value names (HKLM 64-bit view).
    // -----------------------------------------------------------------

    /// <summary>HKLM path for the Chrome enterprise policy key.</summary>
    internal const string ChromeKey = @"SOFTWARE\Policies\Google\Chrome";

    /// <summary>HKLM path for the Edge enterprise policy key.</summary>
    internal const string EdgeKey = @"SOFTWARE\Policies\Microsoft\Edge";

    /// <summary>HKLM path for the Firefox DNSOverHTTPS policy key (leaf we may create).</summary>
    internal const string FirefoxDohKey = @"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS";

    /// <summary>The value name written to Chrome and Edge keys.</summary>
    internal const string ModeValue = "DnsOverHttpsMode";

    /// <summary>The REG_SZ value that disables browser-internal DoH.</summary>
    internal const string OffMode = "off";

    // -----------------------------------------------------------------

    private readonly IRegistryRoot _hklm64;
    private readonly DnsBackupStore _backupStore;

    /// <summary>Initializes a new instance with the injected registry root and backup store.
    /// Pass <c>new Registry64Root()</c> for the production wiring (done by Group I).</summary>
    public BrowserDohPolicy(IRegistryRoot hklm64, DnsBackupStore backupStore)
    {
        ArgumentNullException.ThrowIfNull(hklm64);
        ArgumentNullException.ThrowIfNull(backupStore);
        _hklm64 = hklm64;
        _backupStore = backupStore;
    }

    // -----------------------------------------------------------------
    // IBrowserDohPolicy
    // -----------------------------------------------------------------

    /// <inheritdoc/>
    public PlatformResult SetBrowserDohPolicy(bool enable) =>
        enable ? Enable() : Revert();

    /// <summary>Returns <c>true</c> iff Chrome AND Edge <c>DnsOverHttpsMode</c> currently equal
    /// <c>"off"</c> (ordinal). Firefox is advisory only.</summary>
    public bool IsBrowserDohPolicyApplied() =>
        ReadModeIsOff(ChromeKey) && ReadModeIsOff(EdgeKey);

    // -----------------------------------------------------------------
    // Enable (capture + write)
    // -----------------------------------------------------------------

    private PlatformResult Enable()
    {
        try
        {
            // IC-6: gated capture — CaptureBrowserPolicyIfAbsent ensures the pristine snapshot is
            // written exactly once; subsequent calls re-assert the writes without touching the backup.
            _backupStore.CaptureBrowserPolicyIfAbsent(BuildCaptureSlice);

            // (Re-)assert all five policy writes regardless of whether the slice was just captured.
            using (var k = _hklm64.CreateSubKey(ChromeKey))
                k.SetValue(ModeValue, OffMode, RegistryValueKind.String);

            using (var k = _hklm64.CreateSubKey(EdgeKey))
                k.SetValue(ModeValue, OffMode, RegistryValueKind.String);

            using (var k = _hklm64.CreateSubKey(FirefoxDohKey))
            {
                k.SetValue("Enabled", 0, RegistryValueKind.DWord);
                k.SetValue("Locked", 1, RegistryValueKind.DWord);
            }

            return PlatformResult.Ok();
        }
        catch (Exception ex) when (
            ex is System.Security.SecurityException
            or UnauthorizedAccessException
            or System.IO.IOException)
        {
            return PlatformResult.Fail(
                PlatformErrorKind.OperationFailed,
                $"failed to apply browser DoH policy: {ex.Message}");
        }
    }

    /// <summary>Snapshot delegate passed to <see cref="DnsBackupStore.CaptureBrowserPolicyIfAbsent"/>.
    /// Called at most once (the gate enforces this). Captures: Chrome mode, Edge mode, Firefox
    /// Enabled, Firefox Locked, and a subkey-existence marker for the Firefox DNSOverHTTPS leaf.</summary>
    private IReadOnlyList<RegistryValueBackup> BuildCaptureSlice()
    {
        var list = new List<RegistryValueBackup>(6)
        {
            // Chrome + Edge: REG_SZ DnsOverHttpsMode
            Snapshot(ChromeKey, ModeValue),
            Snapshot(EdgeKey, ModeValue),
            // Firefox subkey-existence marker (ValueName = "" sentinel)
            SubKeyMarker(FirefoxDohKey),
            // Firefox DWORD values
            Snapshot(FirefoxDohKey, "Enabled"),
            Snapshot(FirefoxDohKey, "Locked"),
        };
        return list;
    }

    // -----------------------------------------------------------------
    // Revert (exact restore)
    // -----------------------------------------------------------------

    private PlatformResult Revert()
    {
        var state = _backupStore.Load();
        if (state is null || state.BrowserPolicyValues.Count == 0)
            return PlatformResult.Ok(); // nothing captured -> already reverted (idempotent)

        try
        {
            // Pass 1: restore or delete individual values.
            foreach (var entry in state.BrowserPolicyValues)
            {
                if (entry.ValueName.Length == 0)
                    continue; // subkey-existence marker — handled in pass 2

                if (entry.Existed)
                {
                    // Restore exact prior data + kind.
                    using var k = _hklm64.CreateSubKey(entry.SubKey);
                    k.SetValue(entry.ValueName, MaterializePrior(entry), entry.Kind);
                }
                else
                {
                    // We created this value — delete it (no-op if already absent; idempotent).
                    using var k = _hklm64.OpenSubKey(entry.SubKey, writable: true);
                    k?.DeleteValue(entry.ValueName, throwIfMissing: false);
                }
            }

            // Pass 2: if we created the Firefox \DNSOverHTTPS leaf and it is now empty, remove it.
            // Never delete the shared parent …\Firefox key.
            foreach (var marker in state.BrowserPolicyValues)
            {
                if (marker.ValueName.Length != 0 || marker.Existed)
                    continue; // not a "we-created-the-subkey" marker

                using var leaf = _hklm64.OpenSubKey(marker.SubKey, writable: false);
                if (leaf is not null
                    && leaf.GetValueNames().Count == 0
                    && leaf.GetSubKeyNames().Count == 0)
                {
                    // Empty leaf we created — safe to remove.
                    _hklm64.DeleteSubKeyTree(marker.SubKey, throwIfMissing: false);
                }
            }

            // Clear our slice; all other backup slices are left intact. Routed through
            // SaveOrDeleteIfEmpty so the backup file is removed once this is the last slice.
            _backupStore.SaveOrDeleteIfEmpty(state with { BrowserPolicyValues = Array.Empty<RegistryValueBackup>() });
            return PlatformResult.Ok();
        }
        catch (Exception ex) when (
            ex is System.Security.SecurityException
            or UnauthorizedAccessException
            or System.IO.IOException)
        {
            return PlatformResult.Fail(
                PlatformErrorKind.OperationFailed,
                $"failed to revert browser DoH policy: {ex.Message}");
        }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private bool ReadModeIsOff(string key)
    {
        using var k = _hklm64.OpenSubKey(key, writable: false);
        return k?.GetValue(ModeValue) is string s
            && string.Equals(s, OffMode, StringComparison.Ordinal);
    }

    /// <summary>Takes a snapshot of a single named value under the given subkey.</summary>
    private RegistryValueBackup Snapshot(string subKey, string name)
    {
        using var k = _hklm64.OpenSubKey(subKey, writable: false);
        var prior = k?.GetValue(name);
        var existed = prior is not null;
        return new RegistryValueBackup
        {
            Hive = "HKLM",
            SubKey = subKey,
            ValueName = name,
            Existed = existed,
            Kind = existed ? k!.GetValueKind(name) : RegistryValueKind.Unknown,
            Data = existed ? Convert.ToString(prior, CultureInfo.InvariantCulture) : null,
        };
    }

    /// <summary>Records whether the subkey itself existed, using an empty <c>ValueName</c> as the
    /// sentinel.  On revert, a marker with <c>Existed = false</c> means we created the leaf and
    /// may remove it once all its values have been cleaned up.</summary>
    private RegistryValueBackup SubKeyMarker(string subKey)
    {
        using var k = _hklm64.OpenSubKey(subKey, writable: false);
        return new RegistryValueBackup
        {
            Hive = "HKLM",
            SubKey = subKey,
            ValueName = "",              // sentinel: subkey-existence marker
            Existed = k is not null,
            Kind = RegistryValueKind.Unknown,
            Data = null,
        };
    }

    /// <summary>Re-materializes the typed value object from its invariant-string serialization.
    /// REG_DWORD -> int; REG_QWORD -> long; everything else -> the raw string.</summary>
    private static object MaterializePrior(RegistryValueBackup entry)
    {
        var data = entry.Data ?? string.Empty;
        return entry.Kind switch
        {
            RegistryValueKind.DWord => int.Parse(data, CultureInfo.InvariantCulture),
            RegistryValueKind.QWord => long.Parse(data, CultureInfo.InvariantCulture),
            _ => data,
        };
    }
}
