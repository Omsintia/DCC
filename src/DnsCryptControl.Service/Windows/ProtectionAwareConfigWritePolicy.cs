using System.Runtime.Versioning;
using DnsCryptControl.Core.Toml;
using DnsCryptControl.Core.Validation;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.State;

namespace DnsCryptControl.Service.Windows;

/// <summary>
/// Production <see cref="IConfigWritePolicy"/> (P5b-U1): while protection is enabled, refuses to
/// save a candidate dnscrypt-proxy.toml that raises any <see cref="OpsecConcernSeverity.KillSwitchCritical"/>
/// or <see cref="OpsecConcernSeverity.ProtectionCritical"/> concern from <see cref="OpsecConfigRules"/>
/// (IC-4 — the ONE place the rules live, shared with the kill-switch gate and the UI warnings).
/// Advisory concerns never block. This is the server-side trust-boundary enforcement; the UI's
/// mirrored check is UX only. FAIL-CLOSED on protection-state uncertainty: a PRESENT-but-unreadable
/// state file (<see cref="ProtectionStateStore.TryLoad"/> == false) is treated as PROTECTED — a
/// wrongly-blocked save is a nuisance, a wrongly-allowed unsafe save under an active kill switch
/// strands DNS. An ABSENT state file is a fresh install: legitimately unprotected.
/// Recorded non-goal (P5b-U1): this prevents ACCIDENTAL config-strands only — an authenticated
/// signed caller can always DisableProtection first.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ProtectionAwareConfigWritePolicy : IConfigWritePolicy
{
    private readonly ProtectionStateStore _store;

    public ProtectionAwareConfigWritePolicy(ProtectionStateStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        _store = store;
    }

    /// <inheritdoc/>
    public PlatformResult Check(string candidateTomlText)
    {
        ArgumentNullException.ThrowIfNull(candidateTomlText);

        // TryLoad == false → the state file EXISTS but cannot be read (IO/UAC/corrupt JSON):
        // enforcement cannot prove protection is off, so it assumes ON (fail-closed). Load()
        // would silently default to unprotected here — exactly the fail-open the pre-flight
        // review flagged; never substitute it.
        var protectionEnabled = !_store.TryLoad(out var state) || state.ProtectionEnabled;
        if (!protectionEnabled)
            return PlatformResult.Ok();

        // Parse never throws (Tomlyn's non-strict SyntaxParser); an unparseable candidate
        // yields Evaluate's single fail-closed KillSwitchCritical concern, so it is blocked
        // while protected. Schema validation upstream also rejects it (IC-3 ordering) —
        // belt and suspenders.
        var doc = TomlConfigDocument.Parse(candidateTomlText);
        var blocking = OpsecConfigRules.Evaluate(doc)
            .Where(c => c.Severity is OpsecConcernSeverity.KillSwitchCritical or OpsecConcernSeverity.ProtectionCritical)
            .Select(c => c.Message)
            .ToList();
        if (blocking.Count == 0)
            return PlatformResult.Ok();

        // IC-10: human-actionable, "OPSEC guard: "-prefixed — the UI shows this verbatim.
        // InvalidArgument (→ ValidationFailed on the wire); Conflict is reserved for the
        // base-sha race, never for a policy refusal.
        return PlatformResult.Fail(
            PlatformErrorKind.InvalidArgument,
            "OPSEC guard: " + string.Join("; ", blocking));
    }
}
