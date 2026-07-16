using System.Text;

namespace DnsCryptControl.Core.Rules;

/// <summary>An understood forwarding rule line. Re-emitted canonically (comment re-attached verbatim).</summary>
public sealed record ForwardRuleLine(ForwardRule Rule) : RuleFileLine;

/// <summary>
/// A parsed forwarding_rules file: an ordered list of typed line-models
/// (<see cref="ForwardRuleLine"/> | <see cref="BlankLine"/> | <see cref="CommentLine"/> |
/// <see cref="UnparsedLine"/>) plus the lint findings. Parsing replicates dnscrypt-proxy 2.1.16's
/// shared loader spine (<see cref="RuleTextLines"/> — byte-exact BOM strip / LF split /
/// <c>TrimAndStripInlineComments</c>) then <c>parseForwardFile</c> in <c>plugin_forward.go</c>: a
/// split on the FIRST whitespace only (domain, then the entire trimmed remainder as a
/// comma-separated server list).
/// <para>
/// Forwarding is STRICT: several problems are FATAL start-blockers surfaced as
/// <see cref="RuleLintSeverity.Error"/> — a stray <c>*</c> in the domain, a missing separator, a
/// missing server. A bad server token (invalid IP, wrong-case/unknown keyword, trailing junk) is a
/// per-server skip in the proxy (the rule silently loses a resolver) — still an Error here, since a
/// silently-shortened rule is a footgun. A <c>$RESOLVCONF:</c> RELATIVE path is a
/// <see cref="RuleLintSeverity.Warning"/> (a filesystem-path sink, IC-7). ORDER IS LOAD-BEARING
/// (first-match-wins) — it is preserved verbatim and NEVER reordered; a broader suffix preceding a
/// narrower one is a shadowing <see cref="RuleLintSeverity.Warning"/>. Parsing NEVER throws (except
/// <see cref="ArgumentNullException"/> for null args, of which the parse path has none — a null
/// file is empty).
/// </para>
/// </summary>
public sealed class ForwardRuleFile
{
    private ForwardRuleFile(IReadOnlyList<RuleFileLine> lines, IReadOnlyList<RuleLintFinding> findings)
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
    public static ForwardRuleFile Parse(string? text)
    {
        var lines = new List<RuleFileLine>();
        var findings = new List<RuleLintFinding>();

        // Track (1-based line number, rule) for accepted rules so the shadowing pass can compare
        // each rule against the ones ABOVE it in file order (first-match-wins).
        var accepted = new List<(int lineNumber, ForwardRule rule)>();

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

            // Split on the FIRST whitespace only: domain = before it, servers = the entire trimmed
            // remainder. No whitespace at all => a single token (a domain with no server) => fatal.
            var sep = IndexOfFirstWhitespace(content);
            if (sep < 0)
            {
                findings.Add(new RuleLintFinding(
                    RuleLintSeverity.Error,
                    lineNumber,
                    $"forwarding rule '{content}' has no server — a rule is 'domain servers' (e.g. example.com 9.9.9.9,8.8.8.8); the proxy won't start without a resolver"));
                lines.Add(new UnparsedLine(content, comment));
                continue;
            }

            var rawDomain = content[..sep];
            var serversStr = content[(sep + 1)..].Trim();

            if (serversStr.Length == 0)
            {
                findings.Add(new RuleLintFinding(
                    RuleLintSeverity.Error,
                    lineNumber,
                    $"forwarding rule '{content}' is missing a server after the domain — the proxy won't start"));
                lines.Add(new UnparsedLine(content, comment));
                continue;
            }

            if (!ForwardRule.NormalizeDomain(rawDomain, out var domain, out var domainError))
            {
                findings.Add(new RuleLintFinding(RuleLintSeverity.Error, lineNumber, domainError!));
                lines.Add(new UnparsedLine(content, comment));
                continue;
            }

            // Comma-split the server list; canonicalize each. A single bad server token is an Error
            // (the proxy would drop it), but we KEEP the whole rule (with a finding) so it survives
            // round-trip and the user can fix it — mirroring the cloaking/IP precedent where a
            // flagged line still carries verbatim provenance. We flag every bad token.
            var rawServers = serversStr.Split(',');
            var canonicalServers = new List<string>(rawServers.Length);
            var hadError = false;
            foreach (var rawServer in rawServers)
            {
                var serverToken = rawServer.Trim();
                if (ForwardRule.ClassifyServer(serverToken, out var canonical, out var severity, out var serverError))
                {
                    canonicalServers.Add(canonical);
                    if (serverError is not null)
                    {
                        // A KEPT token with a warning (e.g. a relative $RESOLVCONF path).
                        findings.Add(new RuleLintFinding(severity, lineNumber, serverError));
                    }
                }
                else
                {
                    hadError = true;
                    findings.Add(new RuleLintFinding(severity, lineNumber, serverError!));
                }
            }

            // If any server token was rejected outright, the rule is invalid content — keep it
            // verbatim as an UnparsedLine (never emit a partially-canonicalized rewrite that could
            // silently change meaning). The findings above already name every offending token.
            if (hadError)
            {
                lines.Add(new UnparsedLine(content, comment));
                continue;
            }

            var rule = new ForwardRule(domain, canonicalServers, raw, comment);
            lines.Add(new ForwardRuleLine(rule));
            accepted.Add((lineNumber, rule));
        }

        DetectShadowing(accepted, findings);

        // Re-sort findings by line number so callers see them in file order (the shadowing pass
        // appends after the per-line findings).
        findings.Sort((a, b) => a.LineNumber.CompareTo(b.LineNumber));

        return new ForwardRuleFile(lines, findings);
    }

    /// <summary>
    /// Serializes the line list back to text. Understood rules re-emit CANONICALLY as
    /// <c>domain servers</c> — the normalized domain, a single space, the canonical server list
    /// joined by <c>','</c> (no spaces), plus the preserved inline comment re-attached verbatim;
    /// blank, comment, and unparsed lines re-emit their preserved raw form. LINE ORDER IS VERBATIM
    /// (never reordered — order is load-bearing for first-match). Lines are joined with <c>'\n'</c>
    /// (the loader's separator) and the result matches the file's line count so
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
                case ForwardRuleLine { Rule: var rule }:
                    sb.Append(rule.Domain).Append(' ').Append(string.Join(",", rule.Servers));
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
    /// Returns the index of the FIRST Unicode-whitespace char in <paramref name="content"/>, or -1
    /// if none — replicating Go's <c>strings.IndexFunc(str, unicode.IsSpace)</c> that
    /// <c>StringTwoFields</c> uses for the domain/servers split.
    /// </summary>
    private static int IndexOfFirstWhitespace(string content)
    {
        for (var i = 0; i < content.Length; i++)
        {
            if (char.IsWhiteSpace(content[i]))
            {
                return i;
            }
        }

        return -1;
    }

    /// <summary>
    /// Warns when a rule is SHADOWED by a broader suffix earlier in the file. Because matching is
    /// first-match-in-file-order, a rule is unreachable if any rule ABOVE it (a) is the root
    /// <c>"."</c> catch-all, or (b) is a suffix that the later rule's domain is equal to or a
    /// subdomain of. The warning anchors on the SHADOWED (later, more-specific) line so the user
    /// sees which rule never fires. Order is never changed — this is advisory only.
    /// </summary>
    private static void DetectShadowing(
        List<(int lineNumber, ForwardRule rule)> accepted,
        List<RuleLintFinding> findings)
    {
        for (var later = 0; later < accepted.Count; later++)
        {
            var (lineNumber, rule) = accepted[later];
            for (var earlier = 0; earlier < later; earlier++)
            {
                var broader = accepted[earlier].rule;
                if (Shadows(broader.Domain, rule.Domain))
                {
                    findings.Add(new RuleLintFinding(
                        RuleLintSeverity.Warning,
                        lineNumber,
                        $"rule for '{rule.Domain}' is shadowed by the broader rule for '{broader.Domain}' on line {accepted[earlier].lineNumber} — forwarding is first-match-in-file-order, so this rule never fires; move it ABOVE the broader one"));
                    break; // one shadowing warning per line is enough
                }
            }
        }
    }

    /// <summary>
    /// True when a rule for <paramref name="broader"/> (earlier in the file) would match every name
    /// the rule for <paramref name="narrower"/> (later) matches — i.e. the later rule is
    /// unreachable. The root <c>"."</c> matches everything; otherwise <c>broader</c> shadows
    /// <c>narrower</c> when <c>narrower</c> is a strict subdomain of it (equal domains are
    /// duplicates, not shadowing, and are deliberately not flagged here). Both domains
    /// are already normalized (lowercased). The narrower <c>"."</c> is only shadowed by another
    /// <c>"."</c>.
    /// </summary>
    private static bool Shadows(string broader, string narrower)
    {
        // The root catch-all above anything more specific shadows it (but not another '.').
        if (broader == ".")
        {
            return narrower != ".";
        }

        if (narrower == ".")
        {
            return false; // only '.' above shadows '.', handled above.
        }

        // A strict-subdomain suffix relationship: 'example.com' shadows 'sub.example.com'. Equal
        // domains are duplicates, not shadowing — a first-write-wins duplicate is a separate concern.
        return narrower.EndsWith("." + broader, StringComparison.Ordinal);
    }
}
