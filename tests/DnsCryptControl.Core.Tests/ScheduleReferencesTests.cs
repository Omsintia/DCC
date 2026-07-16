using System;
using System.Collections.Generic;
using System.Linq;
using DnsCryptControl.Core.Rules;
using Xunit;

namespace DnsCryptControl.Core.Tests;

/// <summary>
/// A5: <see cref="ScheduleReferences"/> is a READ-ONLY cross-validation (there is no structured
/// [schedules] editor in scope). Given the set of schedule names defined in the config's
/// [schedules] table and a parsed <see cref="NameRuleFile"/> (A1), it returns the set of
/// <c>@name</c> references that are UNDEFINED (the schedule name is not in the defined set), each
/// as a <see cref="RuleLintSeverity.Warning"/> <see cref="RuleLintFinding"/> with a 1-based line
/// number — because an undefined <c>@schedule</c> is a SILENT no-op in the proxy
/// (ParseTimeBasedRule drops the rule; it blocks nothing) per research-grammar-names.md.
/// Never throws except <see cref="ArgumentNullException"/> for null args (IC-3).
/// </summary>
public class ScheduleReferencesTests
{
    // ---------------------------------------------------------------- null guards (IC-3)

    [Fact]
    public void FindUndefined_nullFile_throwsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(
            () => ScheduleReferences.FindUndefined(null!, new HashSet<string>()));
    }

    [Fact]
    public void FindUndefined_nullDefinedSet_throwsArgumentNullException()
    {
        var file = NameRuleFile.Parse("ads.example @evenings\n");
        Assert.Throws<ArgumentNullException>(
            () => ScheduleReferences.FindUndefined(file, null!));
    }

    // ---------------------------------------------------------------- undefined surfaced

    [Fact]
    public void FindUndefined_undefinedReference_surfacedAsWarning_withLineNumber()
    {
        // 'evenings' is not in the defined set => undefined => a Warning on its 1-based line.
        var file = NameRuleFile.Parse("ads.example @evenings\n");
        var defined = new HashSet<string>(StringComparer.Ordinal) { "work" };

        var findings = ScheduleReferences.FindUndefined(file, defined);

        var finding = Assert.Single(findings);
        Assert.Equal(RuleLintSeverity.Warning, finding.Severity);
        Assert.Equal(1, finding.LineNumber);
        Assert.Contains("evenings", finding.Message);
    }

    [Fact]
    public void FindUndefined_lineNumberIsOneBased_acrossBlanksAndComments()
    {
        // Line 1 comment, line 2 blank, line 3 a rule with an undefined schedule.
        var file = NameRuleFile.Parse("# header\n\nads.example @evenings\n");
        var defined = new HashSet<string>(StringComparer.Ordinal) { "work" };

        var finding = Assert.Single(ScheduleReferences.FindUndefined(file, defined));
        Assert.Equal(3, finding.LineNumber);
    }

    // ---------------------------------------------------------------- defined => clean

    [Fact]
    public void FindUndefined_definedReference_isClean()
    {
        var file = NameRuleFile.Parse("ads.example @work\n");
        var defined = new HashSet<string>(StringComparer.Ordinal) { "work" };

        Assert.Empty(ScheduleReferences.FindUndefined(file, defined));
    }

    // ---------------------------------------------------------------- no schedule => ignored

    [Fact]
    public void FindUndefined_ruleWithoutSchedule_isIgnored()
    {
        // A bare pattern (no '@') carries no reference => never a finding, defined set empty.
        var file = NameRuleFile.Parse("ads.example\n");
        var defined = new HashSet<string>(StringComparer.Ordinal);

        Assert.Empty(ScheduleReferences.FindUndefined(file, defined));
    }

    // ---------------------------------------------------------------- empty defined set

    [Fact]
    public void FindUndefined_emptyDefinedSet_everyReferenceIsUndefined()
    {
        var file = NameRuleFile.Parse("a.example @s1\nb.example @s2\nc.example\n");
        var defined = new HashSet<string>(StringComparer.Ordinal);

        var findings = ScheduleReferences.FindUndefined(file, defined);

        // Two @refs (s1, s2) => two warnings; the bare c.example rule is ignored.
        Assert.Equal(2, findings.Count);
        Assert.Equal(new[] { 1, 2 }, findings.Select(f => f.LineNumber).ToArray());
        Assert.All(findings, f => Assert.Equal(RuleLintSeverity.Warning, f.Severity));
    }

    // ---------------------------------------------------------------- multiple, order preserved

    [Fact]
    public void FindUndefined_returnsFindingsInLineOrder()
    {
        // Lines: 1 defined, 2 undefined, 3 defined, 4 undefined.
        var file = NameRuleFile.Parse(
            "a.example @work\nb.example @evenings\nc.example @work\nd.example @nights\n");
        var defined = new HashSet<string>(StringComparer.Ordinal) { "work" };

        var findings = ScheduleReferences.FindUndefined(file, defined);
        Assert.Equal(new[] { 2, 4 }, findings.Select(f => f.LineNumber).ToArray());
    }

    // ---------------------------------------------------------------- case caveat

    [Fact]
    public void FindUndefined_isCaseSensitive_byDefault_matchingAsIsGoTomlKey()
    {
        // The '@name' reference is matched against the [schedules.<name>] map key AS-IS. A defined
        // set built with the default ordinal comparer treats 'Work' != 'work' => undefined warning.
        // (go-toml's key case-folding caveat is the CALLER's choice of comparer for `defined`.)
        var file = NameRuleFile.Parse("ads.example @Work\n");
        var defined = new HashSet<string>(StringComparer.Ordinal) { "work" };

        Assert.Single(ScheduleReferences.FindUndefined(file, defined));
    }

    [Fact]
    public void FindUndefined_honorsCallerSuppliedCaseInsensitiveComparer()
    {
        // If the caller mirrors go-toml's case-insensitive key matching by supplying an
        // OrdinalIgnoreCase set, '@Work' resolves to the defined 'work' => clean.
        var file = NameRuleFile.Parse("ads.example @Work\n");
        var defined = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "work" };

        Assert.Empty(ScheduleReferences.FindUndefined(file, defined));
    }

    // ---------------------------------------------------------------- unparsed lines ignored

    [Fact]
    public void FindUndefined_ignoresUnparsedLines()
    {
        // 'a @x @y' is an UnparsedLine (>=2 '@', a per-line parse error in A1) — it carries no
        // NameRule, so there is no schedule reference to cross-validate here.
        var file = NameRuleFile.Parse("a @x @y\n");
        var defined = new HashSet<string>(StringComparer.Ordinal);

        Assert.Empty(ScheduleReferences.FindUndefined(file, defined));
    }
}
