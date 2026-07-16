using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Versioning;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.State;
using DnsCryptControl.Service.Windows.Registry;
using Microsoft.Win32;

namespace DnsCryptControl.Service.Windows;

/// <summary>SMHNR + parallel-A/AAAA leak mitigations via the managed registry. Captures prior
/// values for exact revert, then writes/clears the two DWORDs. Because Dnscache refuses runtime
/// stop, the best-effort restart delegate typically reports RebootAdvisory.Recommended.</summary>
[SupportedOSPlatform("windows")]
internal sealed class RegistryLeakMitigationPolicy : ILeakMitigationPolicy
{
    internal const string HiveName = "HKLM";
    internal const string DnsClientSubKey = @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
    internal const string DnscacheParametersSubKey = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";
    internal const string SmhnrValueName = "DisableSmartNameResolution";
    internal const string ParallelValueName = "DisableParallelAandAAAA";

    private readonly IRegistryRoot _registry;
    private readonly DnsBackupStore _backup;
    private readonly Func<RebootAdvisory> _restartDnscache;

    /// <summary>Production constructor. Wires <see cref="BestEffortRestartDnscache"/> as the restart
    /// delegate so the real SCM path is only taken in production / ManualIntegration tests.</summary>
    internal RegistryLeakMitigationPolicy(IRegistryRoot hklm64, DnsBackupStore backup)
        : this(hklm64, backup, BestEffortRestartDnscache)
    {
    }

    /// <summary>Test constructor: inject a deterministic restart result without touching the SCM.</summary>
    internal RegistryLeakMitigationPolicy(
        IRegistryRoot hklm64,
        DnsBackupStore backup,
        Func<RebootAdvisory> restartDnscache)
    {
        ArgumentNullException.ThrowIfNull(hklm64);
        ArgumentNullException.ThrowIfNull(backup);
        ArgumentNullException.ThrowIfNull(restartDnscache);
        _registry = hklm64;
        _backup = backup;
        _restartDnscache = restartDnscache;
    }

    // -----------------------------------------------------------------------
    // ILeakMitigationPolicy
    // -----------------------------------------------------------------------

    public bool AreLeakMitigationsEnabled() =>
        ReadsDwordOne(DnsClientSubKey, SmhnrValueName)
        && ReadsDwordOne(DnscacheParametersSubKey, ParallelValueName);

    public PlatformResult<RebootAdvisory> SetLeakMitigations(bool enable) =>
        enable ? Enable() : Disable();

    // -----------------------------------------------------------------------
    // Enable / Disable implementation
    // -----------------------------------------------------------------------

    private PlatformResult<RebootAdvisory> Enable()
    {
        try
        {
            // IC-6: capture ONLY via the gated CaptureRegistryValuesIfAbsent helper.
            // This enforces the "never overwrite an un-restored backup" single-writer rule.
            _backup.CaptureRegistryValuesIfAbsent(CaptureCurrentValues);

            using (var smhnrSub = _registry.CreateSubKey(DnsClientSubKey))
                smhnrSub.SetValue(SmhnrValueName, 1, RegistryValueKind.DWord);

            using (var parSub = _registry.CreateSubKey(DnscacheParametersSubKey))
                parSub.SetValue(ParallelValueName, 1, RegistryValueKind.DWord);

            var advisory = _restartDnscache();
            return PlatformResult<RebootAdvisory>.Ok(advisory);
        }
        catch (Exception ex) when (
            ex is UnauthorizedAccessException
            or System.Security.SecurityException
            or System.IO.IOException)
        {
            return PlatformResult<RebootAdvisory>.Fail(
                PlatformErrorKind.OperationFailed,
                $"failed to write leak-mitigation registry values: {ex.Message}");
        }
    }

    private PlatformResult<RebootAdvisory> Disable()
    {
        try
        {
            var state = _backup.Load();
            var slice = state?.RegistryValues
                .Where(r => r.ValueName is SmhnrValueName or ParallelValueName)
                .ToList() ?? new List<RegistryValueBackup>();

            foreach (var record in slice)
            {
                if (record.Existed)
                {
                    // Restore exact kind + data captured before the mitigation was applied.
                    using var sub = _registry.CreateSubKey(record.SubKey);
                    sub.SetValue(record.ValueName, ToTyped(record), record.Kind);
                }
                else
                {
                    // Value did not exist before — delete it (no-op if already gone).
                    using var sub = _registry.OpenSubKey(record.SubKey, writable: true);
                    sub?.DeleteValue(record.ValueName, throwIfMissing: false);
                }
            }

            // Clear the registry slice from the backup; preserve other slices. Routed through
            // SaveOrDeleteIfEmpty so the backup file is removed once this is the last slice.
            if (state is not null && slice.Count > 0)
            {
                var remaining = state.RegistryValues
                    .Where(r => r.ValueName is not (SmhnrValueName or ParallelValueName))
                    .ToList();
                _backup.SaveOrDeleteIfEmpty(state with { RegistryValues = remaining });
            }

            // Only restart Dnscache when something was actually reverted; a no-op disable
            // (empty backup slice) must not issue an SCM restart.
            var advisory = slice.Count > 0 ? _restartDnscache() : RebootAdvisory.None;
            return PlatformResult<RebootAdvisory>.Ok(advisory);
        }
        catch (Exception ex) when (
            ex is UnauthorizedAccessException
            or System.Security.SecurityException
            or System.IO.IOException)
        {
            return PlatformResult<RebootAdvisory>.Fail(
                PlatformErrorKind.OperationFailed,
                $"failed to revert leak-mitigation registry values: {ex.Message}");
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private bool ReadsDwordOne(string subKey, string valueName)
    {
        using var sub = _registry.OpenSubKey(subKey, writable: false);
        if (sub is null) return false;
        var val = sub.GetValue(valueName);
        if (val is null) return false;
        var kind = sub.GetValueKind(valueName);
        return kind == RegistryValueKind.DWord && val is int i && i == 1;
    }

    /// <summary>Snapshot delegate passed to <see cref="DnsBackupStore.CaptureRegistryValuesIfAbsent"/>.
    /// Called at most once (the gate ensures this).</summary>
    private IReadOnlyList<RegistryValueBackup> CaptureCurrentValues() =>
        new List<RegistryValueBackup>
        {
            CaptureValue(DnsClientSubKey, SmhnrValueName),
            CaptureValue(DnscacheParametersSubKey, ParallelValueName),
        };

    private RegistryValueBackup CaptureValue(string subKey, string valueName)
    {
        using var sub = _registry.OpenSubKey(subKey, writable: false);
        var raw = sub?.GetValue(valueName);
        var existed = raw is not null;
        return new RegistryValueBackup
        {
            Hive = HiveName,
            SubKey = subKey,
            ValueName = valueName,
            Existed = existed,
            Kind = existed ? sub!.GetValueKind(valueName) : default,
            Data = existed ? Convert.ToString(raw, System.Globalization.CultureInfo.InvariantCulture) : null,
        };
    }

    /// <summary>Re-type a captured invariant-string Data back to the object the registry kind expects.
    /// Only DWord/QWord/String/ExpandString are in scope for the two leak-mitigation DWORDs; anything
    /// else round-trips as its string form (lossless for the values we write).</summary>
    private static object ToTyped(RegistryValueBackup record)
    {
        var data = record.Data ?? string.Empty;
        return record.Kind switch
        {
            RegistryValueKind.DWord => int.Parse(data, System.Globalization.CultureInfo.InvariantCulture),
            RegistryValueKind.QWord => long.Parse(data, System.Globalization.CultureInfo.InvariantCulture),
            _ => data,
        };
    }

    // -----------------------------------------------------------------------
    // Best-effort Dnscache restart (production path)
    // -----------------------------------------------------------------------

    /// <summary>Best-effort Dnscache restart. The DNS Client service refuses
    /// SERVICE_CONTROL_STOP at the handler level (Win32 1052) even as LocalSystem, so this is
    /// EXPECTED to fail → reboot recommended. Any failure (CanStop=false, timeout, Win32, SCM
    /// error) degrades gracefully to RebootAdvisory.Recommended.</summary>
    public static RebootAdvisory BestEffortRestartDnscache()
    {
        try
        {
            using var sc = new System.ServiceProcess.ServiceController("Dnscache");
            if (sc.CanStop &&
                sc.Status == System.ServiceProcess.ServiceControllerStatus.Running)
            {
                sc.Stop();
                sc.WaitForStatus(
                    System.ServiceProcess.ServiceControllerStatus.Stopped,
                    TimeSpan.FromSeconds(20));
                sc.Start();
                sc.WaitForStatus(
                    System.ServiceProcess.ServiceControllerStatus.Running,
                    TimeSpan.FromSeconds(20));
                return RebootAdvisory.None;
            }

            return RebootAdvisory.Recommended; // CanStop is typically false for Dnscache
        }
        catch (System.ServiceProcess.TimeoutException)
        {
            return RebootAdvisory.Recommended;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return RebootAdvisory.Recommended; // error 1052 / access denied
        }
        catch (InvalidOperationException)
        {
            return RebootAdvisory.Recommended; // underlying SCM error
        }
    }
}
