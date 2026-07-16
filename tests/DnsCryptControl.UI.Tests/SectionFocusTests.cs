using DnsCryptControl.Core.Schema;
using DnsCryptControl.UI.ViewModels;
using DnsCryptControl.UI.Views;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// 5g-2 deep-link: the pure lookup behind <c>ConfigurationView.FocusSection</c>. Per the
/// TDD-honesty rule the WPF plumbing around it (SectionNav.SelectedItem, the one-shot
/// PropertyChanged re-apply) is dispatcher-affine view wiring and is exercised live; the
/// DECISION — which section a name lands on, and that a miss stays a miss rather than a
/// fuzzy match — is pinned here. Plus the catalog pin: the literal name the Resolvers link
/// navigates with must remain a REAL ConfigCatalog group, or the deep-link silently lands
/// nowhere.
/// </summary>
public class SectionFocusTests
{
    private static ConfigSectionViewModel Section(string name) =>
        new(name, Array.Empty<SettingEntryViewModel>());

    [Fact]
    public void find_returns_the_section_matching_the_requested_name()
    {
        var target = Section("Server selection");
        var sections = new[] { Section("General"), target, Section("Filtering") };

        Assert.Same(target, SectionFocus.Find(sections, "Server selection"));
    }

    [Fact]
    public void find_misses_are_null_never_a_fuzzy_match()
    {
        var sections = new[] { Section("Server selection") };

        // Case and whitespace matter (ordinal): a near-miss must FAIL loudly in tests,
        // not land on the wrong section at runtime.
        Assert.Null(SectionFocus.Find(sections, "server selection"));
        Assert.Null(SectionFocus.Find(sections, "Server selection "));
        Assert.Null(SectionFocus.Find(sections, "No such section"));
    }

    [Fact]
    public void find_tolerates_a_not_yet_loaded_section_list()
    {
        // Before the first LoadAsync publication VisibleSections is empty (or the caller
        // may hold no list at all) — the immediate attempt must simply miss, leaving the
        // armed re-apply to land the focus after the reload replaces the collection.
        Assert.Null(SectionFocus.Find(null, "Server selection"));
        Assert.Null(SectionFocus.Find(Array.Empty<ConfigSectionViewModel>(), "Server selection"));
    }

    [Fact]
    public void the_deep_link_target_is_a_real_catalog_group()
    {
        // ResolversView navigates with the literal "Server selection". BuildSections derives
        // section names from ConfigCatalog group strings, so if the group is ever renamed
        // this pin fails instead of the link silently focusing nothing.
        Assert.Contains(ConfigCatalog.All, d => d.Group == "Server selection");
    }
}
