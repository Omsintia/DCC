using Tomlyn.Model;

namespace DnsCryptControl.Core.Toml;

/// <summary>
/// A read-only view of one child table under a section (e.g. <c>[sources.'public-resolvers']</c>
/// under <c>[sources]</c>). Returned by <see cref="TomlConfigDocument.TryGetSubTables"/> so a
/// caller can enumerate configured sources without hardcoding their names.
/// </summary>
public sealed class TomlSubTable
{
    private readonly TomlTable _table;

    internal TomlSubTable(string name, TomlTable table)
    {
        Name = name;
        _table = table;
    }

    /// <summary>The child table's semantic name (unquoted — e.g. <c>public-resolvers</c>).</summary>
    public string Name { get; }

    /// <summary>Reads a string key from this sub-table.</summary>
    public bool TryGetString(string key, out string? value)
    {
        value = _table.TryGetValue(key, out var v) ? v as string : null;
        return value is not null;
    }

    /// <summary>Reads an integer key from this sub-table (e.g. <c>refresh_delay</c>). TOML integers
    /// decode to <see cref="long"/>; a non-integer value fails closed.</summary>
    public bool TryGetLong(string key, out long value)
    {
        if (_table.TryGetValue(key, out var v) && v is long l) { value = l; return true; }
        value = 0;
        return false;
    }

    /// <summary>Reads a string-array key from this sub-table (mixed-element arrays fail closed).</summary>
    public bool TryGetStringArray(string key, out IReadOnlyList<string> value)
    {
        if (_table.TryGetValue(key, out var v) && v is TomlArray array)
        {
            var items = new List<string>(array.Count);
            foreach (var item in array)
            {
                if (item is not string s) { value = Array.Empty<string>(); return false; }
                items.Add(s);
            }
            value = items;
            return true;
        }
        value = Array.Empty<string>();
        return false;
    }
}
