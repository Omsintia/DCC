using DnsCryptControl.UI.ViewModels;

namespace DnsCryptControl.UI.Views;

/// <summary>
/// Pure lookup behind <see cref="ConfigurationView.FocusSection"/> (5g-2 deep-link): finds
/// the section-nav item the requested name targets, or null when the current list has no
/// match (not loaded yet, hidden by an active filter, or a stale/renamed name). Factored
/// out of the view so the name-matching contract is unit-testable without a dispatcher;
/// the surrounding pending-name plumbing (arm, re-apply once on the VisibleSections
/// replacement, unsubscribe) is WPF event wiring and stays in the view code-behind — it is
/// three lines of subscribe/unsubscribe with no decision beyond "was a change observed",
/// so there is nothing further to factor.
/// </summary>
public static class SectionFocus
{
    /// <summary>Ordinal, case-sensitive exact match on <see cref="ConfigSectionViewModel.Name"/>:
    /// section names are curated catalog group strings, and callers pass the literal name
    /// (e.g. "Server selection") — a near-miss should FAIL here and surface in tests rather
    /// than fuzzily land on the wrong section.</summary>
    public static ConfigSectionViewModel? Find(IReadOnlyList<ConfigSectionViewModel>? sections, string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (sections is null)
        {
            return null;
        }

        foreach (var section in sections)
        {
            if (string.Equals(section.Name, name, StringComparison.Ordinal))
            {
                return section;
            }
        }

        return null;
    }
}
