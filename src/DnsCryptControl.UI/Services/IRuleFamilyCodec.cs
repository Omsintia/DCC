using DnsCryptControl.Core.Rules;
using DnsCryptControl.Platform;

namespace DnsCryptControl.UI.Services;

/// <summary>
/// One display-neutral row projected from a parsed rule file (C1). Each row corresponds 1:1 to a
/// physical line in the family's <c>.txt</c> so the structured editor's rows and the raw text stay
/// in lockstep (IC-1). The <see cref="RuleRowKind"/> classifies the line for rendering (an understood
/// rule vs a blank/comment/unparsed line); <see cref="Text"/> is the canonical serialization of THAT
/// line alone (understood rules re-emit canonically, other kinds re-emit verbatim), so a structured
/// list is losslessly reconstructable back into raw text by joining every row's <see cref="Text"/>
/// with <c>'\n'</c>. Findings anchored to this line are carried on the row so the view can mark it.
/// </summary>
/// <param name="Kind">How to render/treat this line.</param>
/// <param name="Text">The line's canonical serialized text (no trailing newline).</param>
/// <param name="Findings">The lint findings anchored to this 1-based line, in severity/order.</param>
public sealed record RuleRowModel(
    RuleRowKind Kind,
    string Text,
    IReadOnlyList<RuleLintFinding> Findings);

/// <summary>The render classification of a projected <see cref="RuleRowModel"/>.</summary>
public enum RuleRowKind
{
    /// <summary>An understood, canonically re-emitted rule line.</summary>
    Rule,

    /// <summary>A blank (whitespace-only) line.</summary>
    Blank,

    /// <summary>A full-line comment.</summary>
    Comment,

    /// <summary>A proxy-legal-but-invalid line (preserved verbatim, carries an Error finding).</summary>
    Unparsed,
}

/// <summary>
/// The outcome of parsing one family's raw <c>.txt</c> through its <see cref="IRuleFamilyCodec"/>:
/// the ordered per-line row projection, the canonical re-serialization of the whole file, and every
/// lint finding (also duplicated onto the owning row). <see cref="CanonicalText"/> is
/// <c>parse → serialize</c> of the input; the editor uses it to detect whether the user's raw text is
/// already canonical and to regenerate raw text after a structured edit (IC-1/IC-4).
/// </summary>
/// <param name="Rows">The per-line rows in file order (one per physical line).</param>
/// <param name="CanonicalText">The whole file re-serialized canonically.</param>
/// <param name="Findings">All findings across the file, in line order.</param>
public sealed record RuleParseResult(
    IReadOnlyList<RuleRowModel> Rows,
    string CanonicalText,
    IReadOnlyList<RuleLintFinding> Findings);

/// <summary>
/// A SMALL family-agnostic seam over the four Core rule parsers (A1–A4). Because the Core row types
/// differ per family (<see cref="NameRule"/> / <see cref="IpRule"/> / <see cref="CloakRule"/> /
/// <see cref="ForwardRule"/>), a thin adapter per family lets ONE
/// <see cref="ViewModels.RuleFamilyEditorViewModel"/> drive every family. The codec NEVER duplicates
/// parsing/serialization logic — it only delegates to the Core <c>XxxRuleFile.Parse</c>/<c>Serialize</c>
/// and projects the shared <see cref="RuleFileLine"/> discriminants into display-neutral
/// <see cref="RuleRowModel"/>s. Pure and total: <see cref="Parse"/> never throws (Core parsing is
/// fail-closed, IC-3); a <see langword="null"/> input parses as empty.
/// </summary>
public interface IRuleFamilyCodec
{
    /// <summary>The helper's fixed rule-file kind this codec parses/serializes (maps to a fixed filename).</summary>
    RuleFileKind Kind { get; }

    /// <summary>
    /// Parses <paramref name="text"/> (a family's raw <c>.txt</c>) into the shared row projection plus
    /// findings plus the canonical re-serialization. Never throws (Core parsing is fail-closed).
    /// </summary>
    RuleParseResult Parse(string? text);
}
