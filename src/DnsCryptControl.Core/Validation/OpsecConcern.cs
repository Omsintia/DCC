namespace DnsCryptControl.Core.Validation;

/// <summary>
/// Severity of an OPSEC config concern raised by <see cref="OpsecConfigRules.Evaluate"/> (IC-4):
/// <list type="bullet">
///   <item><description><see cref="KillSwitchCritical"/> — the config would strand or leak DNS under
///   the outbound-53 kill switch; these are exactly the kill-switch enable gate's reject conditions
///   and they block a protected save.</description></item>
///   <item><description><see cref="ProtectionCritical"/> — safe for the kill switch itself, but breaks
///   protection's loopback re-point (system DNS targets 127.0.0.1:53); blocks a protected save.</description></item>
///   <item><description><see cref="Advisory"/> — worth a prominent warning; never blocks anything.</description></item>
/// </list>
/// </summary>
public enum OpsecConcernSeverity { KillSwitchCritical, ProtectionCritical, Advisory }

/// <summary>
/// One OPSEC rule violation found by <see cref="OpsecConfigRules.Evaluate"/>. <c>RuleId</c> is a
/// stable identifier (the <c>OpsecConfigRules.*RuleId</c> constants); <c>Message</c> is
/// human-actionable and shown verbatim by consumers (IC-10).
/// </summary>
public sealed record OpsecConcern(string RuleId, string KeyPath, string Message, OpsecConcernSeverity Severity);
