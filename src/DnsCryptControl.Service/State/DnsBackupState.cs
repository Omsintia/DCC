using System.Collections.Generic;
using Microsoft.Win32;

namespace DnsCryptControl.Service.State;

/// <summary>Single source of truth for every Phase 3 mutation's prior state, written atomically to
/// %ProgramData%\DnsCryptControl\state\backup.json. Captured once before the first mutation; replayed
/// by RestoreDns/uninstall (delete-if-was-absent, restore-value-if-was-present).</summary>
public sealed record DnsBackupState
{
    public const int CurrentSchemaVersion = 1;

    public required int SchemaVersion { get; init; }
    public required string CreatedUtc { get; init; }             // DateTimeOffset.UtcNow.ToString("O")
    public required IReadOnlyList<InterfaceDnsBackup> Interfaces { get; init; }
    public required IReadOnlyList<RegistryValueBackup> RegistryValues { get; init; }
    public required IReadOnlyList<string> AddedFirewallRuleNames { get; init; }
    public required IReadOnlyList<RegistryValueBackup> BrowserPolicyValues { get; init; }
}

public sealed record InterfaceDnsBackup
{
    public required string InterfaceGuid { get; init; }          // braced GUID string "{...}"
    public required bool WasIpv4Static { get; init; }            // false => was DHCP/automatic
    public IReadOnlyList<string>? Ipv4Servers { get; init; }     // null if was DHCP
    public required bool WasIpv6Static { get; init; }
    public IReadOnlyList<string>? Ipv6Servers { get; init; }
}

public sealed record RegistryValueBackup
{
    public required string Hive { get; init; }                  // "HKLM"
    public required string SubKey { get; init; }                // e.g. SYSTEM\CurrentControlSet\Services\Dnscache\Parameters
    public required string ValueName { get; init; }
    public required bool Existed { get; init; }                 // false => delete on restore
    public RegistryValueKind Kind { get; init; }                // meaningful only if Existed
    public string? Data { get; init; }                          // invariant-string form of prior value; null if !Existed
}
