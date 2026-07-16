namespace DnsCryptControl.Core.Toml;

/// <summary>
/// The ordered fields of ONE TOML inline table (e.g. an <c>[anonymized_dns].routes</c>
/// element: <c>{ server_name = "x", via = ["r1", "r2"] }</c>). Field values are limited
/// to a string or a string list — all Phase 5c's structured writes need. Keys must be
/// bare (<c>[A-Za-z0-9_-]+</c>), validated at <see cref="AddString"/>/<see cref="AddStringArray"/>
/// time because <see cref="TomlConfigDocument.SetInlineTableArray"/> emits them as bare keys.
/// </summary>
/// <remarks>
/// Fields preserve insertion order (the emitted key order). Instances are mutable
/// builders; construct one per inline table, add fields, then pass a list to
/// <see cref="TomlConfigDocument.SetInlineTableArray"/>.
/// </remarks>
public sealed class TomlInlineTableValue
{
    private readonly List<Field> _fields = new();

    internal IReadOnlyList<Field> Fields => _fields;

    /// <summary>Appends a string field. Returns <c>this</c> for chaining.</summary>
    /// <exception cref="ArgumentException"><paramref name="key"/> is not a bare key.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="value"/> is null.</exception>
    public TomlInlineTableValue AddString(string key, string value)
    {
        ValidateKey(key);
        ArgumentNullException.ThrowIfNull(value);
        _fields.Add(new Field(key, value, null));
        return this;
    }

    /// <summary>Appends a string-array field (emitted as <c>["a", "b"]</c>, or <c>[]</c> when empty). Returns <c>this</c> for chaining.</summary>
    /// <exception cref="ArgumentException"><paramref name="key"/> is not a bare key, or any item is null.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="values"/> is null.</exception>
    public TomlInlineTableValue AddStringArray(string key, IReadOnlyList<string> values)
    {
        ValidateKey(key);
        ArgumentNullException.ThrowIfNull(values);
        var items = values.ToArray();
        if (Array.Exists(items, static v => v is null))
            throw new ArgumentException("Array items must not be null.", nameof(values));
        _fields.Add(new Field(key, null, items));
        return this;
    }

    private static void ValidateKey(string key)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        var bare = key.All(static c =>
            c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '_' or '-');
        if (!bare)
            throw new ArgumentException(
                $"Inline-table key '{key}' is not a bare key ([A-Za-z0-9_-]+).", nameof(key));
    }

    /// <summary>One field: exactly one of <see cref="StringValue"/> / <see cref="ArrayValue"/> is non-null.</summary>
    internal readonly record struct Field(string Key, string? StringValue, string[]? ArrayValue);
}
