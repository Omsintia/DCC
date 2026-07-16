using System.Text;

namespace DnsCryptControl.Core.Rules;

/// <summary>
/// An understood name rule line. Re-emitted canonically (comment re-attached verbatim). Derives
/// from the shared <see cref="RuleFileLine"/> so blank/comment/unparsed provenance is common
/// across every Phase 5d rule family (see <c>RuleFileLine.cs</c>).
/// </summary>
public sealed record NameRuleLine(NameRule Rule) : RuleFileLine;

/// <summary>
/// A parsed blocked_names / allowed_names file: an ordered list of typed line-models plus the
/// lint findings. Parsing replicates dnscrypt-proxy 2.1.16's shared loader spine
/// (<see cref="RuleTextLines"/>) then <c>ParseTimeBasedRule</c> (the <c>@schedule</c> split) and
/// <c>PatternMatcher.Add</c> (<see cref="NameRule.Classify"/>). Names are SKIP-AND-CONTINUE in
/// the proxy, so our lint is a save-time guard (warn/error), never a start-blocker, and parsing
/// NEVER throws (except <see cref="ArgumentNullException"/> for null args, of which there are
/// none on the parse path — a null file is treated as empty).
/// </summary>
public sealed class NameRuleFile
{
    private NameRuleFile(IReadOnlyList<RuleFileLine> lines, IReadOnlyList<RuleLintFinding> findings)
    {
        Lines = lines;
        Findings = findings;
    }

    /// <summary>Every line in file order, as a typed model (round-trip provenance).</summary>
    public IReadOnlyList<RuleFileLine> Lines { get; }

    /// <summary>All lint findings across the file (1-based line numbers), in line order.</summary>
    public IReadOnlyList<RuleLintFinding> Findings { get; }

    /// <summary>
    /// Parses <paramref name="text"/> into an ordered, typed line list plus lint findings. A
    /// <see langword="null"/> or empty input yields an empty file. Never throws.
    /// </summary>
    public static NameRuleFile Parse(string? text)
    {
        var lines = new List<RuleFileLine>();
        var findings = new List<RuleLintFinding>();

        var rawLines = RuleTextLines.SplitLines(text);
        for (var i = 0; i < rawLines.Count; i++)
        {
            var lineNumber = i + 1; // 1-based
            var raw = rawLines[i];
            var (content, comment) = RuleTextLines.StripInlineComment(raw);

            // Full-line comment: no content, the whole line is the comment.
            if (content.Length == 0 && comment is not null)
            {
                lines.Add(new CommentLine(comment));
                continue;
            }

            // Blank line (no content, no comment).
            if (content.Length == 0)
            {
                lines.Add(new BlankLine());
                continue;
            }

            // Content present: split the @schedule, then classify the pattern.
            if (!TrySplitSchedule(content, out var pattern, out var schedule, out var scheduleError, out var scheduleWarning))
            {
                findings.Add(new RuleLintFinding(RuleLintSeverity.Error, lineNumber, scheduleError!));
                lines.Add(new UnparsedLine(content, comment));
                continue;
            }

            if (!NameRule.Classify(pattern, out var kind, out var classifyError))
            {
                findings.Add(new RuleLintFinding(RuleLintSeverity.Error, lineNumber, classifyError!));
                lines.Add(new UnparsedLine(content, comment));
                continue;
            }

            // A bare trailing '@' (empty schedule name) is proxy-valid: ParseTimeBasedRule skips the
            // schedule lookup when len(timeRangeName)==0 and returns a plain unconditional block rule.
            // We keep the rule (schedule==null) but WARN — emitted only now that the pattern classified,
            // so a line that would anyway be an Error carries only the Error.
            if (scheduleWarning is not null)
            {
                findings.Add(new RuleLintFinding(RuleLintSeverity.Warning, lineNumber, scheduleWarning));
            }

            lines.Add(new NameRuleLine(new NameRule(pattern, kind, schedule, raw, comment)));
        }

        return new NameRuleFile(lines, findings);
    }

    /// <summary>
    /// Serializes the line list back to text. Understood rules re-emit CANONICALLY (the classified
    /// pattern, plus <c>' @schedule'</c> when present, plus the preserved inline comment); blank,
    /// comment, and unparsed lines re-emit their preserved raw form. Line order is verbatim. Lines
    /// are joined with <c>'\n'</c> (the loader's separator); the result matches the file's line
    /// count so <c>parse → serialize → parse</c> is a fixed point.
    /// </summary>
    public string Serialize()
    {
        var sb = new StringBuilder();
        for (var i = 0; i < Lines.Count; i++)
        {
            if (i > 0)
            {
                sb.Append('\n');
            }

            switch (Lines[i])
            {
                case NameRuleLine { Rule: var rule }:
                    sb.Append(rule.Pattern);
                    if (rule.Schedule is not null)
                    {
                        sb.Append(" @").Append(rule.Schedule);
                    }

                    if (rule.TrailingComment is not null)
                    {
                        sb.Append(' ').Append(rule.TrailingComment);
                    }

                    break;

                case CommentLine { Text: var textLine }:
                    sb.Append(textLine);
                    break;

                case UnparsedLine { Content: var content, Comment: var comment }:
                    sb.Append(content);
                    if (comment is not null)
                    {
                        sb.Append(' ').Append(comment);
                    }

                    break;

                case BlankLine:
                default:
                    // Blank line: append nothing (the separator already produced the newline).
                    break;
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Replicates <c>ParseTimeBasedRule</c>'s <c>@</c>-split: a line with no <c>@</c> is a bare
    /// pattern; exactly one <c>@</c> yields <c>pattern @schedule</c> (both sides trimmed); two or
    /// more <c>@</c> is a per-line error, as is an empty pattern before the <c>@</c>. An EMPTY
    /// schedule name (a bare trailing <c>'@'</c>) is NOT an error: <c>ParseTimeBasedRule</c> only
    /// resolves the schedule <c>if len(timeRangeName) &gt; 0</c>, so an empty name skips the lookup
    /// and returns a plain unconditional block rule — we drop the schedule (return <c>null</c>) and
    /// surface a <paramref name="warning"/> instead.
    /// </summary>
    private static bool TrySplitSchedule(string content, out string pattern, out string? schedule, out string? error, out string? warning)
    {
        pattern = content;
        schedule = null;
        error = null;
        warning = null;

        var at = content.IndexOf('@', StringComparison.Ordinal);
        if (at < 0)
        {
            return true; // no schedule
        }

        if (content.IndexOf('@', at + 1) >= 0)
        {
            error = $"rule '{content}' has more than one '@' (a schedule uses exactly one)";
            return false;
        }

        pattern = content[..at].Trim();
        var scheduleName = content[(at + 1)..].Trim();

        if (pattern.Length == 0)
        {
            error = $"rule '{content}' has an empty pattern before '@'";
            return false;
        }

        if (scheduleName.Length == 0)
        {
            // Bare trailing '@': the proxy treats it as a plain unconditional block (no schedule).
            schedule = null;
            warning = $"rule '{content}' ends with a bare '@' and no schedule name — the proxy treats it as an unconditional block (matching dnscrypt-proxy 2.1.16)";
            return true;
        }

        schedule = scheduleName;
        return true;
    }
}
