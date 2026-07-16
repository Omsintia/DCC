using CommunityToolkit.Mvvm.ComponentModel;

namespace DnsCryptControl.UI.ViewModels;

/// <summary>
/// One curated section of the Configuration tab's left nav — a display group promoted
/// from the catalog's comment banners (A4) and its member entries. PURE POCO
/// <see cref="ObservableObject"/> — zero WPF type references (IC-5).
/// </summary>
public partial class ConfigSectionViewModel : ObservableObject
{
    public ConfigSectionViewModel(
        string name,
        IReadOnlyList<SettingEntryViewModel> entries,
        string? description = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(entries);
        Name = name;
        Entries = entries;
        Description = description;
        _visibleEntries = entries;
    }

    public string Name { get; }

    /// <summary>5g-3: optional plain-language explainer for the whole group, rendered
    /// as a wrapped caption under the section header; null (caption collapsed) for
    /// groups nobody has authored one for yet (see <see cref="ConfigSectionDescriptions"/>).</summary>
    public string? Description { get; }

    /// <summary>Every entry in this group (immutable per load).</summary>
    public IReadOnlyList<SettingEntryViewModel> Entries { get; }

    /// <summary>The subset of <see cref="Entries"/> matching the current filter text
    /// (all of them when no filter is active).</summary>
    [ObservableProperty]
    private IReadOnlyList<SettingEntryViewModel> _visibleEntries;

    /// <summary>Recomputes <see cref="VisibleEntries"/>; empty filter shows everything.</summary>
    internal void ApplyFilter(string filterText)
    {
        VisibleEntries = filterText.Length == 0
            ? Entries
            : Entries.Where(e => e.MatchesFilter(filterText)).ToArray();
    }
}
