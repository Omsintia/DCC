using System.Text;

namespace DnsCryptControl.Core.Rules;

/// <summary>An understood cloaking rule line. Re-emitted canonically (comment re-attached verbatim).</summary>
public sealed record CloakRuleLine(CloakRule Rule) : RuleFileLine;

/// <summary>
/// A parsed cloaking_rules file: an ordered list of typed line-models
/// (<see cref="CloakRuleLine"/> | <see cref="BlankLine"/> | <see cref="CommentLine"/> |
/// <see cref="UnparsedLine"/>) plus the lint findings. Parsing replicates dnscrypt-proxy 2.1.16's
/// shared loader spine (<see cref="RuleTextLines"/> — byte-exact BOM strip / LF split /
/// <c>TrimAndStripInlineComments</c>) then <c>plugin_cloak.go</c> <c>loadRules</c>: a
/// <c>FieldsFunc(unicode.IsSpace)</c> tokenize requiring EXACTLY TWO tokens, IP-vs-CNAME target by
/// <c>net.ParseIP</c>, and NAME classification via the shared <see cref="NameRule.Classify"/>.
/// <para>
/// Cloaking is STRICTER than names/IPs: it has TWO FATAL start-blockers surfaced as
/// <see cref="RuleLintSeverity.Error"/>:
/// <list type="number">
///   <item>a degenerate NAME pattern (<c>*</c>, <c>=</c>, <c>.</c>, <c>**</c>, empty-after-strip, a
///     glob <c>filepath.Match</c> rejects) — <c>Add</c> propagates the error → <c>Init</c> aborts;</item>
///   <item>a RECURSIVE CNAME — a <c>=cname</c> target that itself matches a cloak name pattern in
///     the file (a two-pass whole-file check via <see cref="CloakRule.PatternMatches"/>).</item>
/// </list>
/// Per-line structural problems (a <c>&gt;2</c>-token line, a missing field) are the proxy's
/// per-line skip-and-continue; they are still Errors here (the line is silently dropped otherwise).
/// Parsing NEVER throws (except <see cref="ArgumentNullException"/> for null args, of which the
/// parse path has none — a null file is empty).
/// </para>
/// </summary>
public sealed class CloakRuleFile
{
    private CloakRuleFile(IReadOnlyList<RuleFileLine> lines, IReadOnlyList<RuleLintFinding> findings)
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
    public static CloakRuleFile Parse(string? text)
    {
        var lines = new List<RuleFileLine>();
        var findings = new List<RuleLintFinding>();

        // Track (1-based line number, rule) for accepted rules so the second pass can run the
        // whole-file recursive-CNAME check with correct line numbers.
        var accepted = new List<(int lineNumber, CloakRule rule)>();

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

            // Tokenize on ANY run of Unicode whitespace (FieldsFunc(unicode.IsSpace)): runs collapse,
            // leading/trailing whitespace is ignored. The proxy demands EXACTLY two tokens.
            var tokens = SplitFields(content);
            if (tokens.Count != 2)
            {
                var message = tokens.Count > 2
                    ? $"cloaking rule '{content}' has {tokens.Count} tokens — exactly two are allowed (name target); the proxy drops this line"
                    : $"cloaking rule '{content}' is missing a field — a rule is 'name target' (two whitespace-separated tokens)";
                findings.Add(new RuleLintFinding(RuleLintSeverity.Error, lineNumber, message));
                lines.Add(new UnparsedLine(content, comment));
                continue;
            }

            var name = tokens[0];
            var target = tokens[1];

            if (!CloakRule.Classify(name, target, out var isIp, out var classifyError))
            {
                findings.Add(new RuleLintFinding(RuleLintSeverity.Error, lineNumber, classifyError!));
                lines.Add(new UnparsedLine(content, comment));
                continue;
            }

            var rule = new CloakRule(name, target, isIp, raw, comment);
            lines.Add(new CloakRuleLine(rule));
            accepted.Add((lineNumber, rule));
        }

        // SECOND PASS — recursive-cloaking detection (FATAL start-blocker). For every CNAME target,
        // if it matches ANY cloak name pattern in the file, the proxy aborts at startup. IP targets
        // can never be recursive (they are not names). We only flag it via an Error finding
        // (blocking save); the line stays a CloakRuleLine so its content round-trips verbatim
        // (the user must fix the loop).
        foreach (var (lineNumber, rule) in accepted)
        {
            if (rule.IsIp)
            {
                continue;
            }

            foreach (var (_, other) in accepted)
            {
                if (CloakRule.PatternMatches(other.NamePattern, rule.Target))
                {
                    findings.Add(new RuleLintFinding(
                        RuleLintSeverity.Error,
                        lineNumber,
                        $"recursive cloaking rule: target '{rule.Target}' matches cloak pattern '{other.NamePattern}' — the proxy would refuse to start"));
                    break; // one finding per recursive line is enough
                }
            }
        }

        // Re-sort findings by line number so callers see them in file order (the recursion pass
        // appends after the per-line findings).
        findings.Sort((a, b) => a.LineNumber.CompareTo(b.LineNumber));

        return new CloakRuleFile(lines, findings);
    }

    /// <summary>
    /// Serializes the line list back to text. Understood rules re-emit CANONICALLY as
    /// <c>name target</c> with a SINGLE space separator (whatever whitespace run the user typed
    /// collapses), plus the preserved inline comment re-attached verbatim; blank, comment, and
    /// unparsed lines re-emit their preserved raw form. Multi-IP names are already separate lines
    /// (one target each) — the serializer NEVER emits a comma or a second target. Line order is
    /// verbatim. Lines are joined with <c>'\n'</c> (the loader's separator) and the result matches
    /// the file's line count so <c>parse → serialize → parse</c> is a fixed point.
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
                case CloakRuleLine { Rule: var rule }:
                    sb.Append(rule.NamePattern).Append(' ').Append(rule.Target);
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
    /// Replicates Go's <c>strings.FieldsFunc(line, unicode.IsSpace)</c>: splits on runs of any
    /// Unicode whitespace, collapsing consecutive whitespace and ignoring leading/trailing
    /// whitespace, so empty fields are never produced. The content is already comment-stripped and
    /// trimmed by <see cref="RuleTextLines.StripInlineComment"/>.
    /// </summary>
    private static List<string> SplitFields(string content)
    {
        var fields = new List<string>();
        var start = -1;
        for (var i = 0; i < content.Length; i++)
        {
            if (char.IsWhiteSpace(content[i]))
            {
                if (start >= 0)
                {
                    fields.Add(content[start..i]);
                    start = -1;
                }
            }
            else if (start < 0)
            {
                start = i;
            }
        }

        if (start >= 0)
        {
            fields.Add(content[start..]);
        }

        return fields;
    }
}
