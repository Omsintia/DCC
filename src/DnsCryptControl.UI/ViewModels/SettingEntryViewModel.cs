using CommunityToolkit.Mvvm.ComponentModel;
using DnsCryptControl.Core.Schema;
using DnsCryptControl.Core.Toml;

namespace DnsCryptControl.UI.ViewModels;

/// <summary>
/// One catalogued setting in the Configuration tab's structured pane: the immutable
/// <see cref="SettingDescriptor"/> metadata plus the observable CURRENT state read
/// from the shared <see cref="TomlConfigDocument"/> (IC-1: the doc is the single
/// source of truth — this VM never owns a value, it only projects the doc's).
/// PURE POCO <see cref="ObservableObject"/> — zero WPF type references (IC-5).
/// </summary>
public partial class SettingEntryViewModel : ObservableObject
{
    /// <summary>
    /// Sections whose real-file key paths are user-named (<c>[sources.public-resolvers]</c>,
    /// <c>[schedules.work]</c>, <c>[static.myserver]</c>) — the catalog path cannot
    /// structurally address them, so every entry under them is raw-only in 5b (P5b-E3).
    /// </summary>
    private static readonly string[] DynamicSections = { "sources", "schedules", "static" };

    public SettingEntryViewModel(SettingDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        KeyPath = descriptor.KeyPath;
        ValueType = descriptor.Type;
        Doc = descriptor.Doc;
        Friendly = descriptor.Friendly;
        DefaultDisplay = descriptor.DefaultDisplay;
        Group = descriptor.Group;
        Deprecated = descriptor.Deprecated;
        ReplacedBy = descriptor.ReplacedBy;
        IsRawOnly = descriptor.Type is SettingValueType.Table or SettingValueType.TableArray
            || DynamicSections.Contains(descriptor.Section, StringComparer.Ordinal);
    }

    public string KeyPath { get; }

    public SettingValueType ValueType { get; }

    /// <summary>The catalog's one-line documentation for this key.</summary>
    public string Doc { get; }

    /// <summary>5g-6: the catalog's optional plain-language second line, rendered
    /// above the technical <see cref="Doc"/> (which it never replaces); null until
    /// the catalog authors one for this key.</summary>
    public string? Friendly { get; }

    /// <summary>Display-only default prose from the catalog (not a typed default).</summary>
    public string DefaultDisplay { get; }

    /// <summary>The curated A4 display group this entry's section derives from.</summary>
    public string Group { get; }

    public bool Deprecated { get; }

    public string? ReplacedBy { get; }

    /// <summary>P5b-E3: no structured editor in 5b — the card links to the Raw view.</summary>
    public bool IsRawOnly { get; }

    /// <summary>Whether the key is PRESENT in the document (even with a value of an
    /// unexpected type — then <see cref="Value"/> is null but the key is still set).</summary>
    [ObservableProperty]
    private bool _isSet;

    /// <summary>The typed current value read from the doc (bool/long/double/string/
    /// IReadOnlyList&lt;string&gt; per <see cref="ValueType"/>), or null when the key is
    /// absent, type-mismatched, raw-only Table, or the doc has parse errors.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(EffectiveBool))]
    private object? _value;

    /// <summary>The catalog's typed default for a Bool key, parsed from <see cref="DefaultDisplay"/>
    /// ("true"/"false"). Meaningless for non-bool types (returns false).</summary>
    public bool DefaultBool => string.Equals(DefaultDisplay, "true", StringComparison.OrdinalIgnoreCase);

    /// <summary>5j (honesty): the EFFECTIVE bool the proxy actually uses — the doc value when the key
    /// is set, else the catalog default. The Bool toggle binds to THIS (not the raw <see cref="Value"/>),
    /// so an unset default-true key shows "on" instead of a misleading "off" under "Default: true".
    /// The set-vs-unset distinction is preserved separately via <see cref="IsSet"/> (a "(default)" marker).</summary>
    public bool EffectiveBool => Value is bool b ? b : DefaultBool;

    /// <summary>§8.3 search: case-insensitive contains over the key path AND the doc
    /// text, so "oblivious" finds <c>odoh_servers</c> by its documentation alone.
    /// 5g-6: the plain-language <see cref="Friendly"/> line is searched too (null-safe),
    /// so users can find keys by everyday words.</summary>
    internal bool MatchesFilter(string filterText) =>
        KeyPath.Contains(filterText, StringComparison.OrdinalIgnoreCase)
        || Doc.Contains(filterText, StringComparison.OrdinalIgnoreCase)
        || (Friendly?.Contains(filterText, StringComparison.OrdinalIgnoreCase) ?? false);

    /// <summary>Re-projects this entry's observable state from <paramref name="doc"/>.</summary>
    internal void RefreshFrom(TomlConfigDocument doc)
    {
        IsSet = doc.GetRaw(KeyPath) is not null;
        Value = ValueType switch
        {
            SettingValueType.Bool when doc.TryGetBool(KeyPath, out var b) => b,
            SettingValueType.Long when doc.TryGetLong(KeyPath, out var l) => l,
            SettingValueType.Float when doc.TryGetDouble(KeyPath, out var d) => d,
            SettingValueType.String when doc.TryGetString(KeyPath, out var s) => s,
            SettingValueType.StringArray when doc.TryGetStringArray(KeyPath, out var a) => a,
            _ => null,
        };
    }
}
