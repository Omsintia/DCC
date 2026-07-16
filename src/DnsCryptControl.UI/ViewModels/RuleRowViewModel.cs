using CommunityToolkit.Mvvm.ComponentModel;
using DnsCryptControl.Core.Rules;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.ViewModels;

/// <summary>
/// One row in a family's structured editor (C1): the projection of a single physical line in the
/// rule <c>.txt</c>. Pure POCO <see cref="ObservableObject"/> (IC-5) — zero WPF types. Each row
/// carries the line's render classification (<see cref="Kind"/>), its canonical serialized
/// <see cref="Text"/>, and the lint findings anchored to it, so the view can mark an offending line
/// with its severity and message (IC-10/IC-16). The row is a DISPLAY projection: structured edits go
/// through <see cref="RuleFamilyEditorViewModel"/> which rebuilds the raw text and re-parses, so a
/// row never mutates the shared document directly (mirrors <c>SettingEntryViewModel</c>).
/// </summary>
public sealed partial class RuleRowViewModel : ObservableObject
{
    /// <summary>Constructs a row from a codec's display-neutral projection.</summary>
    public RuleRowViewModel(int lineNumber, RuleRowModel model)
    {
        ArgumentNullException.ThrowIfNull(model);
        LineNumber = lineNumber;
        _kind = model.Kind;
        _text = model.Text;
        _findings = model.Findings;
        _worstSeverity = ComputeWorst(model.Findings);
    }

    /// <summary>The 1-based line number this row occupies in the file (matches lint anchors, IC-10).</summary>
    public int LineNumber { get; }

    /// <summary>How to render/treat this line (rule vs blank/comment/unparsed).</summary>
    [ObservableProperty]
    private RuleRowKind _kind;

    /// <summary>The line's canonical serialized text (understood rules canonical; others verbatim).</summary>
    [ObservableProperty]
    private string _text;

    /// <summary>The lint findings anchored to this line, in severity/order.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasFindings))]
    private IReadOnlyList<RuleLintFinding> _findings;

    /// <summary>The worst severity among this row's findings (Error &gt; Warning), or null when clean.</summary>
    [ObservableProperty]
    private RuleLintSeverity? _worstSeverity;

    /// <summary>True when this row carries at least one lint finding (drives the view's line marker).</summary>
    public bool HasFindings => Findings.Count > 0;

    private static RuleLintSeverity? ComputeWorst(IReadOnlyList<RuleLintFinding> findings)
    {
        RuleLintSeverity? worst = null;
        foreach (var finding in findings)
        {
            // Error sorts before Warning in the enum (0 < 1); the worst is the numeric minimum.
            if (worst is null || finding.Severity < worst)
            {
                worst = finding.Severity;
            }
        }

        return worst;
    }
}
