using System.Runtime.Versioning;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.State;

namespace DnsCryptControl.Service.Windows;

/// <summary>
/// Opt-in DNS-leak kill switch: three outbound BLOCK rules for plaintext DNS — UDP/53, TCP/53,
/// TCP/853 — added via the injected <see cref="IFirewallRuleStore"/> (COM-backed in production,
/// in-memory fake under test). Idempotent (Remove-before-Add), detect-by-name, fully reversible
/// (we only ever touch our own product-prefixed rules; we never alter DefaultOutboundAction or any
/// third-party rule).
///
/// <para><b>PROXY-OFF-53 DEPENDENCY (IC-4):</b> Windows Firewall evaluates an explicit BLOCK before any
/// per-app ALLOW (BLOCK wins; the only override is IPsec authenticated-bypass, which does not apply),
/// so a per-application allow for dnscrypt-proxy.exe CANNOT rescue it. Therefore enabling the kill
/// switch is GATED on <see cref="IProxyConfigSafetyCheck"/>: the active dnscrypt-proxy.toml must have
/// <c>netprobe_timeout=0</c>, <c>ignore_system_dns=true</c>, and no bootstrap_resolvers entry targeting
/// port 53. A missing or unparseable config is treated as unsafe (fail-closed).</para>
///
/// <para><b>BACKUP RECORDING (IC-6):</b> The three product-prefixed rule names we add are recorded into
/// the <see cref="DnsBackupStore"/> <c>AddedFirewallRuleNames</c> slice via
/// <c>CaptureFirewallRulesIfAbsent</c> — captured exactly once, never overwritten.</para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class FirewallKillSwitch : IFirewallKillSwitch
{
    // Fixed product-prefixed display names (stable; used both as rule Name and for detection).
    public const string RuleNameUdp53  = "DnsCryptControl KillSwitch UDP53";
    public const string RuleNameTcp53  = "DnsCryptControl KillSwitch TCP53";
    public const string RuleNameTcp853 = "DnsCryptControl KillSwitch TCP853";
    public const string RuleDescription = "DnsCryptControl DNS leak kill switch";

    internal const int ProtocolUdp = 17; // IANA UDP (also referenced by NetshFirewallRuleStore)
    private const int ProtocolTcp = 6;  // IANA TCP

    /// <summary>The three product-prefixed rule names, in master-apply order.</summary>
    public static IReadOnlyList<string> AllRuleNames { get; } =
        new[] { RuleNameUdp53, RuleNameTcp53, RuleNameTcp853 };

    private static IReadOnlyList<FirewallRuleDescriptor> Descriptors { get; } = new[]
    {
        new FirewallRuleDescriptor(RuleNameUdp53,  RuleDescription, ProtocolUdp, "53"),
        new FirewallRuleDescriptor(RuleNameTcp53,  RuleDescription, ProtocolTcp, "53"),
        new FirewallRuleDescriptor(RuleNameTcp853, RuleDescription, ProtocolTcp, "853"),
    };

    private readonly IFirewallRuleStore _store;
    private readonly DnsBackupStore _backup;
    private readonly IProxyConfigSafetyCheck _configCheck;

    /// <summary>Production constructor (IC-2). Internal because the seam interfaces are internal;
    /// wiring to the DI container happens in Group I (ServiceComposition).</summary>
    /// <param name="ruleStore">Firewall backend seam (COM or netsh).</param>
    /// <param name="backup">Backup store — the three added rule names are captured here via
    /// <c>CaptureFirewallRulesIfAbsent</c> so they are recorded exactly once.</param>
    /// <param name="configCheck">Off-53 safety guard — gates enabling the kill switch.</param>
    internal FirewallKillSwitch(
        IFirewallRuleStore ruleStore,
        DnsBackupStore backup,
        IProxyConfigSafetyCheck configCheck)
    {
        ArgumentNullException.ThrowIfNull(ruleStore);
        ArgumentNullException.ThrowIfNull(backup);
        ArgumentNullException.ThrowIfNull(configCheck);
        _store = ruleStore;
        _backup = backup;
        _configCheck = configCheck;
    }

    /// <inheritdoc/>
    public PlatformResult SetKillSwitch(bool enable) => enable ? Enable() : Disable();

    private PlatformResult Enable()
    {
        // IC-4: off-53 safety guard — fail-closed before touching any rules.
        var (safe, reason) = _configCheck.IsSafeUnderPort53Block();
        if (!safe)
            return PlatformResult.Fail(PlatformErrorKind.InvalidArgument,
                $"kill switch blocked: proxy config is not safe under port-53 block — {reason}");

        var added = new List<string>(Descriptors.Count);
        try
        {
            foreach (var d in Descriptors)
            {
                _store.Remove(d.Name); // Remove-before-Add: idempotent (no duplicate DisplayNames).
                _store.Add(d);
                added.Add(d.Name);
            }
        }
        catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or InvalidOperationException)
        {
            // Best-effort rollback of any rules we managed to add before the failure.
            foreach (var name in added)
            {
                try { _store.Remove(name); }
                catch (Exception inner) when (inner is System.Runtime.InteropServices.COMException or InvalidOperationException) { }
            }
            return PlatformResult.Fail(PlatformErrorKind.OperationFailed,
                $"failed to add kill-switch rule: {ex.Message}");
        }

        // IC-6: record the three added rule names into the backup's AddedFirewallRuleNames slice
        // via the gated helper — captured exactly once, never overwritten.
        _backup.CaptureFirewallRulesIfAbsent(() => AllRuleNames);

        return PlatformResult.Ok();
    }

    private PlatformResult Disable()
    {
        // IC-4 guard is intentionally SKIPPED for disable — always allowed to remove.
        try
        {
            foreach (var name in AllRuleNames)
                _store.Remove(name); // idempotent: no effect if absent.
        }
        catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or InvalidOperationException)
        {
            return PlatformResult.Fail(PlatformErrorKind.OperationFailed,
                $"failed to remove kill-switch rule: {ex.Message}");
        }

        // Clear our own backup slice (mirrors the other three subsystems' reverts). Routed through
        // SaveOrDeleteIfEmpty so the backup file vanishes once this is the last remaining slice.
        var state = _backup.Load();
        if (state is not null && state.AddedFirewallRuleNames.Count > 0)
            _backup.SaveOrDeleteIfEmpty(state with { AddedFirewallRuleNames = Array.Empty<string>() });

        return PlatformResult.Ok();
    }

    /// <inheritdoc/>
    public bool IsKillSwitchActive()
    {
        HashSet<string> present;
        try
        {
            present = new HashSet<string>(_store.ListNames(), StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or InvalidOperationException)
        {
            // cannot enumerate -> report inactive (fail-safe for status reporting).
            return false;
        }

        return AllRuleNames.All(present.Contains);
    }
}
