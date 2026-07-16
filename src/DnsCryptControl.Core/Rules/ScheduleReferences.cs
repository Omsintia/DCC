namespace DnsCryptControl.Core.Rules;

/// <summary>
/// READ-ONLY cross-validation of the <c>@schedule</c> references in a blocked_names /
/// allowed_names file against the set of schedule names actually defined in the config's
/// <c>[schedules]</c> TOML table. Phase 5d ships NO structured <c>[schedules]</c> editor (out of
/// scope, design P5d-U1); the table rides the existing raw TOML path. This helper exists purely so
/// the Filtering tab can WARN when a rule references a schedule that does not exist.
/// <para>
/// Why a warning and not an error: per <c>research-grammar-names.md</c> (and
/// <c>raw-grammar-schedules.json</c>), an undefined <c>@name</c> makes the proxy's
/// <c>ParseTimeBasedRule</c> return <c>"time range [name] not found"</c>, which
/// <c>plugin_block_name.go</c>/<c>plugin_allow_name.go</c> handle as
/// <c>dlog.Error(err); return nil</c> — the offending rule is logged and SILENTLY DROPPED (it
/// blocks/allows nothing), but the proxy still starts. That silent no-op is security-relevant for a
/// blocking tool (the user believes a domain is scheduled-blocked when it is not), so we surface it
/// as a prominent <see cref="RuleLintSeverity.Warning"/> rather than a start-blocking error.
/// </para>
/// <para>
/// <b>Case caveat.</b> In the proxy the <c>@name</c> reference resolves against the
/// <c>AllWeeklyRanges</c> map whose keys are the <c>[schedules.&lt;name&gt;]</c> TOML keys, and
/// go-toml key matching is case-insensitive (the shipped example uses lowercase <c>mon</c>/<c>tue</c>
/// day keys) — but that folding is applied when the TOML is decoded, not here. This helper matches
/// the reference against <paramref name="definedSchedules"/> <b>as-is</b>, delegating the equality
/// policy to the set's comparer: the caller picks <see cref="System.StringComparer.Ordinal"/> for a
/// literal check or <see cref="System.StringComparer.OrdinalIgnoreCase"/> to mirror go-toml's
/// case-folding on whatever key strings it extracted from the table.
/// </para>
/// Fail-closed and pure: never throws except <see cref="System.ArgumentNullException"/> for a null
/// argument (IC-3); no I/O, no mutation.
/// </summary>
public static class ScheduleReferences
{
    /// <summary>
    /// Returns, in file order, one <see cref="RuleLintSeverity.Warning"/>
    /// <see cref="RuleLintFinding"/> per understood name rule whose <c>@schedule</c> reference is
    /// NOT present in <paramref name="definedSchedules"/>. Rules with no schedule are ignored;
    /// non-rule lines (blank / comment / unparsed) carry no reference and are ignored. Line numbers
    /// are 1-based (IC-10), derived from each line's position in <see cref="NameRuleFile.Lines"/>
    /// (A1 emits exactly one <see cref="RuleFileLine"/> per source line, so the index + 1 is the
    /// source line number).
    /// </summary>
    /// <param name="file">A parsed name-rule file (A1). Not <see langword="null"/>.</param>
    /// <param name="definedSchedules">
    /// The set of schedule names defined in <c>[schedules]</c>. Its comparer decides the case policy
    /// (see the type remarks). Not <see langword="null"/>.
    /// </param>
    /// <returns>Undefined-reference warnings in file order (empty when every reference resolves).</returns>
    public static IReadOnlyList<RuleLintFinding> FindUndefined(
        NameRuleFile file,
        ISet<string> definedSchedules)
    {
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(definedSchedules);

        var findings = new List<RuleLintFinding>();

        var lines = file.Lines;
        for (var i = 0; i < lines.Count; i++)
        {
            // Only understood name rules carry a schedule reference; blank / comment / unparsed
            // lines are skipped (an UnparsedLine may textually contain '@' but it was rejected by
            // A1's ParseTimeBasedRule, so there is no valid reference to validate).
            if (lines[i] is not NameRuleLine { Rule.Schedule: { } schedule })
            {
                continue;
            }

            if (definedSchedules.Contains(schedule))
            {
                continue;
            }

            var lineNumber = i + 1; // 1-based
            findings.Add(new RuleLintFinding(
                RuleLintSeverity.Warning,
                lineNumber,
                $"schedule '@{schedule}' is not defined in [schedules] — the proxy silently drops this rule (it will block nothing)"));
        }

        return findings;
    }
}
