using DnsCryptControl.Core.Schema;
using DnsCryptControl.UI.Converters;
using DnsCryptControl.UI.ViewModels;

namespace DnsCryptControl.UI.Views;

/// <summary>
/// The structured pane's commit-decision logic (F1). <see cref="ConfigurationView"/>'s
/// code-behind commits editors on focus loss — but LostFocus fires on EVERY focus
/// traversal, so an unconditional <c>ApplyEdit</c> would dirty the editor (and mutate
/// the shared document) just by tabbing through the form. Each <c>TryPrepare*</c>
/// decides whether the control's current content is a REAL change against the entry's
/// doc-projected <see cref="SettingEntryViewModel.Value"/> and, when it is, produces
/// the exact typed value <c>ConfigurationViewModel.ApplyEdit</c> expects. Pure POCO —
/// kept out of the code-behind so the decisions are unit-testable (TDD honesty);
/// the event wiring in the view is compile-verified plumbing.
/// </summary>
public static class StructuredEditCommit
{
    /// <summary>A toggle click that lands on the value the doc already holds (or an
    /// unset key's first explicit choice) — only a real flip (or first set) commits.</summary>
    public static bool TryPrepareBool(SettingEntryViewModel entry, bool newValue, out object? value)
    {
        ArgumentNullException.ThrowIfNull(entry);
        value = newValue;
        return entry.Value is not bool current || current != newValue;
    }

    /// <summary>Unchanged text never commits; empty text on an UNSET key never creates
    /// it (focus-through safety) — but clearing a SET key commits an explicit <c>""</c>.</summary>
    public static bool TryPrepareText(SettingEntryViewModel entry, string newText, out object? value)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(newText);
        value = newText;
        if (entry.Value is string current)
        {
            return !string.Equals(current, newText, StringComparison.Ordinal);
        }

        return newText.Length > 0;
    }

    /// <summary>
    /// Numeric commit for Long/Float entries from a <c>NumberBox</c>'s nullable double:
    /// an empty box commits nothing (clearing is not a removal gesture); Long values
    /// round away from zero and refuse doubles outside long's exact range; Float
    /// commits the double verbatim (A2's <c>TryGetDouble</c> widens TOML integers, so
    /// the current value is always a boxed double and echo-compares exactly).
    /// </summary>
    public static bool TryPrepareNumber(SettingEntryViewModel entry, double? newValue, out object? value)
    {
        ArgumentNullException.ThrowIfNull(entry);
        value = null;
        if (newValue is not double typed || !double.IsFinite(typed))
        {
            return false;
        }

        switch (entry.ValueType)
        {
            case SettingValueType.Long:
                // (double)long.MaxValue rounds UP to 2^63, so >= excludes every double
                // that would overflow the checked-less (long) cast below.
                if (typed < long.MinValue || typed >= 9223372036854775808d)
                {
                    return false;
                }

                var rounded = (long)Math.Round(typed, MidpointRounding.AwayFromZero);
                value = rounded;
                return entry.Value is not long currentLong || currentLong != rounded;

            case SettingValueType.Float:
                value = typed;
                return entry.Value is not double currentDouble || currentDouble != typed;

            default:
                return false;
        }
    }

    /// <summary>One-per-line array commit: compares the PARSED lines (trimmed, blanks
    /// dropped — <see cref="StringArrayToLinesConverter.ParseLines"/>, the same logic
    /// the display converter round-trips) against the current array, so CRLF/LF or
    /// whitespace-only touch-ups never dirty the editor; clearing a SET key commits an
    /// explicit empty array.</summary>
    public static bool TryPrepareLines(SettingEntryViewModel entry, string linesText, out object? value)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(linesText);
        var parsed = StringArrayToLinesConverter.ParseLines(linesText);
        value = parsed;
        if (entry.Value is IReadOnlyList<string> current)
        {
            return !current.SequenceEqual(parsed, StringComparer.Ordinal);
        }

        return parsed.Count > 0;
    }
}
