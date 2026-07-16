using System.Text;

namespace DnsCryptControl.Core.Rules;

/// <summary>An understood IP rule line. Re-emitted canonically (comment re-attached verbatim).</summary>
public sealed record IpRuleLine(IpRule Rule) : RuleFileLine;

/// <summary>
/// A parsed blocked_ips / allowed_ips file: an ordered list of typed line-models
/// (<see cref="IpRuleLine"/> | <see cref="BlankLine"/> | <see cref="CommentLine"/> |
/// <see cref="UnparsedLine"/>) plus the lint findings. Parsing replicates dnscrypt-proxy 2.1.16's
/// shared loader spine (<see cref="RuleTextLines"/> — the byte-exact BOM strip / LF split /
/// <c>TrimAndStripInlineComments</c>) then <c>LoadIPRules</c>/<c>ParseIPRule</c> classification via
/// <see cref="IpRule.Classify"/>.
/// <para>
/// IP rules are SKIP-AND-CONTINUE in the proxy (a bad rule is silently ineffective = fail-open),
/// so our lint is STRICTER: silently-ineffective forms (non-canonical exact IPs, <c>'@'</c>,
/// brackets, interior <c>'*'</c>, unparseable literals, malformed CIDR) are Errors that make the
/// line an <see cref="UnparsedLine"/> (preserved verbatim, blocked on save); host-bits-set CIDR
/// and too-short textual prefixes are Warnings that KEEP the (canonicalized) rule. Parsing NEVER
/// throws (except <see cref="ArgumentNullException"/> for null args, of which the parse path has
/// none — a null file is treated as empty).
/// </para>
/// </summary>
public sealed class IpRuleFile
{
    private IpRuleFile(IReadOnlyList<RuleFileLine> lines, IReadOnlyList<RuleLintFinding> findings)
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
    public static IpRuleFile Parse(string? text)
    {
        var lines = new List<RuleFileLine>();
        var findings = new List<RuleLintFinding>();

        var rawLines = RuleTextLines.SplitLines(text);
        for (var i = 0; i < rawLines.Count; i++)
        {
            var lineNumber = i + 1; // 1-based (IC-10; our editor gutter is 1-indexed)
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

            // Content present: classify the single IP-rule token.
            if (!IpRule.Classify(content, out var value, out var kind, out var severity, out var message, out var prefixSeparator))
            {
                // Error: preserve the line verbatim, record the finding.
                findings.Add(new RuleLintFinding(RuleLintSeverity.Error, lineNumber, message!));
                lines.Add(new UnparsedLine(content, comment));
                continue;
            }

            // Accepted rule. A Warning (host-bits CIDR, too-short prefix) still keeps the rule but
            // records a finding.
            if (message is not null)
            {
                findings.Add(new RuleLintFinding(severity, lineNumber, message));
            }

            lines.Add(new IpRuleLine(new IpRule(value, kind, raw, comment, prefixSeparator)));
        }

        return new IpRuleFile(lines, findings);
    }

    /// <summary>
    /// Serializes the line list back to text. Understood rules re-emit CANONICALLY (the canonical
    /// value; a trailing <c>'*'</c> re-added for a <see cref="IpRuleKind.TextPrefix"/>; the
    /// preserved inline comment re-attached verbatim); blank, comment, and unparsed lines re-emit
    /// their preserved raw form. Line order is verbatim. Lines are joined with <c>'\n'</c> (the
    /// loader's separator) and the result matches the file's line count so
    /// <c>parse → serialize → parse</c> is a fixed point.
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
                case IpRuleLine { Rule: var rule }:
                    sb.Append(rule.Value);
                    if (rule.Kind == IpRuleKind.TextPrefix)
                    {
                        // Re-append the separator the classifier stripped (e.g. the ':' of
                        // 'fe80::*' whose canonical Value is 'fe80:') BEFORE the '*', so the
                        // re-emitted text re-parses to the same Value — the IC-4 fixed point.
                        if (rule.PrefixSeparator is char separator)
                        {
                            sb.Append(separator);
                        }

                        sb.Append('*');
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
}
