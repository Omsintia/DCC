namespace DnsCryptControl.Core.Rules;

/// <summary>Severity of a rule lint finding, mapped to the real proxy consequence (IC-11).</summary>
public enum RuleLintSeverity
{
    /// <summary>The proxy would silently skip this rule (fail-open / silent no-op) — block on save.</summary>
    Error,

    /// <summary>The rule loads but may not behave as intended (e.g. an undefined <c>@schedule</c>).</summary>
    Warning,
}

/// <summary>
/// One lint finding for a rule line. Line numbers are 1-based (IC-10), the message is
/// human-actionable and names the offending value.
/// </summary>
/// <param name="Severity">Warn vs error, per the family's real proxy strictness.</param>
/// <param name="LineNumber">1-based line number in the source file.</param>
/// <param name="Message">A human-actionable description naming the offending value.</param>
public sealed record RuleLintFinding(RuleLintSeverity Severity, int LineNumber, string Message);

/// <summary>
/// One line in a parsed rule file — a discriminated set shared by every Phase 5d rule family
/// (A1 names, A2 IPs, A3 cloaking, A4 forwarding). A concrete line is either a family-specific
/// understood-rule line (e.g. <see cref="NameRuleLine"/>, <see cref="IpRuleLine"/>), a
/// <see cref="BlankLine"/>, a <see cref="CommentLine"/> (a full-line <c>'#'…</c>), or an
/// <see cref="UnparsedLine"/> (a proxy-legal-but-invalid line that carries a lint finding). Every
/// line preserves enough provenance to be re-emitted verbatim so <c>parse → serialize → parse</c>
/// is a fixed point (IC-4). The three non-rule kinds are family-agnostic and shared here; each
/// family adds its own understood-rule subtype.
/// </summary>
public abstract record RuleFileLine;

/// <summary>A blank (whitespace-only) line. Re-emitted as an empty line.</summary>
public sealed record BlankLine : RuleFileLine;

/// <summary>A full-line comment (<c>Text</c> is the raw <c>'#'…</c>, preserved verbatim).</summary>
public sealed record CommentLine(string Text) : RuleFileLine;

/// <summary>
/// A line the proxy would reject/skip (a silently-ineffective form). The raw content is preserved
/// verbatim for round-trip; a <see cref="RuleLintFinding"/> is recorded separately.
/// <see cref="Comment"/> holds any preserved inline comment so it survives serialization too.
/// </summary>
public sealed record UnparsedLine(string Content, string? Comment) : RuleFileLine;
