using Tomlyn.Model;
using Tomlyn.Parsing;
using Tomlyn.Syntax;

namespace DnsCryptControl.Core.Toml;

/// <summary>
/// A parsed dnscrypt-proxy.toml document. Wraps Tomlyn's syntax tree so the raw
/// text round-trips losslessly (comments and formatting preserved), which is required
/// for the structured editor and the raw editor to share one source of truth.
/// </summary>
public sealed class TomlConfigDocument
{
    private readonly DocumentSyntax _syntax;
    private readonly IReadOnlyList<string> _errors;

    /// <summary>Set when Tomlyn THREW during <see cref="Parse"/> (rather than reporting diagnostics)
    /// and we synthesised a fail-closed errored document.</summary>
    private readonly bool _unparseable;

    /// <summary>The exact text <see cref="Parse"/> received, kept so the read model can deserialize
    /// from IT rather than from a redundant <see cref="ToText"/> re-serialization (6d: the model build
    /// was ~1 parse + 1 serialize per validation run). Nulled by <see cref="InvalidateModelCache"/> on
    /// every mutation, so a mutated document re-derives the model from its (now-authoritative) syntax
    /// via <c>ToText()</c>. Safe because for a clean parse the source text and <c>ToText()</c> carry
    /// identical semantic content (Tomlyn's ToString is value-lossless), so the model is the same.</summary>
    private string? _sourceText;

    private TomlConfigDocument(DocumentSyntax syntax, string? sourceText)
    {
        _syntax = syntax;
        _errors = syntax.Diagnostics.Select(d => d.ToString()).ToArray();
        _sourceText = sourceText;
    }

    /// <summary>Fail-closed fallback document, used when Tomlyn throws instead of diagnosing. Carries a
    /// generic error (never the raw exception/input, to avoid echoing hostile config back to the UI) and
    /// an empty placeholder syntax that callers never reach (they gate on <see cref="HasErrors"/>).</summary>
    private TomlConfigDocument(IReadOnlyList<string> forcedErrors)
    {
        _syntax = SyntaxParser.Parse(string.Empty, sourceName: null, validate: false);
        _errors = forcedErrors;
        _unparseable = true;
    }

    /// <summary>Underlying syntax tree (read access for validators/readers).</summary>
    internal DocumentSyntax Syntax => _syntax;

    public bool HasErrors => _unparseable || _syntax.HasErrors;

    public IReadOnlyList<string> Errors => _errors;

    /// <summary>Generic fail-closed error for a config Tomlyn could not parse. Deliberately carries no
    /// input/exception detail (avoids echoing hostile config to the UI) and is shared (never mutated).</summary>
    private static readonly string[] UnparseableError = { "config could not be parsed (malformed TOML)" };

    public static TomlConfigDocument Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        try
        {
            return new TomlConfigDocument(SyntaxParser.Parse(text, sourceName: null, validate: true), text);
        }
        // Parse is a TOTALITY boundary: any internal Tomlyn failure must fail CLOSED to an errored
        // document, because every caller treats an un-loadable config as HasErrors, never as a crash.
        // Tomlyn's lexer can THROW rather than diagnose - e.g. ArgumentOutOfRangeException from
        // Char.ConvertFromUtf32 while formatting a diagnostic for a surrogate/out-of-range \u escape
        // (found by fuzzing, 2026-07-08). OOM is left to propagate (not a parse failure).
#pragma warning disable CA1031 // deliberate broad catch at a fail-closed recovery boundary
        catch (Exception ex) when (ex is not OutOfMemoryException)
#pragma warning restore CA1031
        {
            return new TomlConfigDocument(UnparseableError);
        }
    }

    /// <summary>Re-serializes the document back to text (lossless for a parsed doc).</summary>
    public string ToText() => _syntax.ToString();

    private TomlTable? _model;

    /// <summary>Nulls the derived-model cache after a mutation. Also drops <see cref="_sourceText"/>:
    /// once the syntax is mutated the original parse text is stale, so the model must next re-derive
    /// from the (authoritative) syntax via <c>ToText()</c>. Every mutation MUST route through here.</summary>
    private void InvalidateModelCache()
    {
        _model = null;
        _sourceText = null;
    }

    // Deserialize the read model from the SOURCE text on the clean read-only path (no ToText()
    // re-serialization), falling back to ToText() after a mutation has dropped _sourceText. This is the
    // 6d single-parse-path fix: the old Deserialize(ToText()) added a redundant serialize to every
    // validation run. (A true syntax->model transform with no re-parse is not exposed by this Tomlyn.)
    // Only reached when !HasErrors (readers guard on it), so Deserialize never sees diagnostics.
    private TomlTable Model => _model ??= Tomlyn.TomlSerializer.Deserialize<TomlTable>(_sourceText ?? ToText())!;

    /// <summary>
    /// Returns the root model table. Only valid when <see cref="HasErrors"/> is false
    /// (the model deserializes lazily and throws on invalid TOML); callers must check
    /// <see cref="HasErrors"/> first — <c>ConfigValidator</c> does.
    /// </summary>
    internal object GetRaw0() => Model;

    /// <summary>Resolves a dotted key path to its raw model value, or null if absent.</summary>
    public object? GetRaw(string keyPath)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyPath);
        if (HasErrors) return null; // model is only meaningful for a valid document; readers never throw
        object current = Model;
        foreach (var segment in keyPath.Split('.'))
        {
            if (segment.Length == 0) return null; // reject malformed paths like "a." or ".b"
            if (current is not TomlTable table || !table.TryGetValue(segment, out var next))
                return null;
            current = next;
        }
        return current;
    }

    public bool TryGetString(string keyPath, out string? value)
    {
        value = GetRaw(keyPath) as string;
        return value is not null;
    }

    public bool TryGetBool(string keyPath, out bool value)
    {
        if (GetRaw(keyPath) is bool b) { value = b; return true; }
        value = default;
        return false;
    }

    public bool TryGetLong(string keyPath, out long value)
    {
        // Tomlyn models TOML integers as long.
        if (GetRaw(keyPath) is long l) { value = l; return true; }
        value = default;
        return false;
    }

    public bool TryGetDouble(string keyPath, out double value)
    {
        // Mirrors ConfigValidator's Float semantics ("value is double or long"): TOML
        // floats read directly and TOML integers widen to double, so a file with
        // `timeout_load_reduction = 1` reads back as 1.0 instead of failing.
        switch (GetRaw(keyPath))
        {
            case double d: value = d; return true;
            case long l: value = l; return true;
            default: value = default; return false;
        }
    }

    public bool TryGetStringArray(string keyPath, out IReadOnlyList<string> value)
    {
        if (GetRaw(keyPath) is TomlArray array)
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

    /// <summary>
    /// Enumerates the child tables directly under <paramref name="section"/> (e.g. the
    /// <c>[sources.&lt;name&gt;]</c> tables under <c>[sources]</c>), so callers can discover
    /// configured sources without hardcoding their names. An absent section yields
    /// <c>true</c> with an empty list; a present-but-non-table value fails closed
    /// (<c>false</c>). Only child values that are themselves tables are returned.
    /// </summary>
    public bool TryGetSubTables(string section, out IReadOnlyList<TomlSubTable> subTables)
    {
        ArgumentException.ThrowIfNullOrEmpty(section);
        var raw = GetRaw(section);
        if (raw is null) { subTables = Array.Empty<TomlSubTable>(); return true; }  // absent → no sub-tables
        if (raw is not TomlTable table) { subTables = Array.Empty<TomlSubTable>(); return false; } // not a section

        var result = new List<TomlSubTable>();
        foreach (var pair in table)
        {
            if (pair.Value is TomlTable child)
                result.Add(new TomlSubTable(pair.Key, child));
        }
        subTables = result;
        return true;
    }

    // ------------------------------------------------------------------------------
    // Surgical mutation API (IC-1: NEVER regenerate text from the derived TomlTable
    // model — that drops comments, formatting, and un-catalogued keys).
    //
    // APPROACH (pinned by the A1 spike): direct in-place syntax-tree mutation.
    // Facts verified hands-on against Tomlyn 2.3.2 (compiled probes, not memory):
    //  - Syntax nodes are fully MUTABLE: KeyValueSyntax.Value, SyntaxToken.Text and
    //    SyntaxToken.TokenKind all have plain public setters (not init-only), so the
    //    plan's span-splice escape hatch is NOT needed.
    //  - DocumentSyntax.ToString() prints Token.Text, NOT the semantic Value property:
    //    setting BooleanValueSyntax.Value alone changes NOTHING in the output. A value
    //    edit must rewrite the token (Text + TokenKind); we keep Value in sync too.
    //    Same-type scalar writes therefore copy Text/TokenKind from a freshly built
    //    Tomlyn node onto the EXISTING token, so Tomlyn owns all value formatting and
    //    escaping (basic-string escapes, "1.0" floats, inf/nan token kinds).
    //  - Inline trailing comments attach to the VALUE TOKEN's TrailingTrivia (e.g.
    //    [Whitespaces ' '][Comment '# …']), so editing Token.Text in place leaves them
    //    untouched — output is byte-identical except the value token (test-pinned).
    //  - Whole-node replacement (kv.Value = newNode) DROPS that inline comment unless
    //    the old node's first-token LeadingTrivia / last-token TrailingTrivia are first
    //    copied onto the new node — verified working; used ONLY where in-place token
    //    editing is impossible (type-changing writes, array rewrites).
    //  - Top-level pairs live in DocumentSyntax.KeyValues; [table] sections are the
    //    TableSyntax entries of DocumentSyntax.Tables ([[array-of-tables]] is
    //    TableArraySyntax and is intentionally NOT traversed, matching GetRaw's
    //    segment=table semantics). Names are resolved SEMANTICALLY via the KeySyntax
    //    structure (bare token text / quoted-string value), never via ToString(), so
    //    quoted keys ("cache") and spaced dotted headers ([ a . b ]) address exactly
    //    like the model-based readers.
    // Every mutation MUST end with InvalidateModelCache(), or readers serve stale values.
    // ------------------------------------------------------------------------------

    /// <summary>
    /// Sets a boolean at <paramref name="keyPath"/> (dotted path, segment = table).
    /// Comments, formatting, and unknown keys are preserved byte-for-byte.
    /// </summary>
    /// <exception cref="InvalidOperationException">The document has parse errors.</exception>
    public void SetBool(string keyPath, bool value)
        => SetValue(keyPath, () => new BooleanValueSyntax(value));

    /// <summary>
    /// Sets a string at <paramref name="keyPath"/>; the value is emitted as an escaped
    /// TOML basic string ("…") regardless of the original quoting style.
    /// </summary>
    /// <exception cref="InvalidOperationException">The document has parse errors.</exception>
    public void SetString(string keyPath, string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        SetValue(keyPath, () => new StringValueSyntax(value)); // Tomlyn escapes \ " and control chars
    }

    /// <summary>Sets an integer at <paramref name="keyPath"/>.</summary>
    /// <exception cref="InvalidOperationException">The document has parse errors.</exception>
    public void SetLong(string keyPath, long value)
        => SetValue(keyPath, () => new IntegerValueSyntax(value));

    /// <summary>
    /// Sets a float at <paramref name="keyPath"/>. Whole numbers are emitted with a
    /// decimal point ("1.0") so the value stays a TOML float. (The catalog calls this
    /// type <c>SettingValueType.Float</c>; the CLR value is a double.)
    /// </summary>
    /// <exception cref="InvalidOperationException">The document has parse errors.</exception>
    public void SetDouble(string keyPath, double value)
        => SetValue(keyPath, () => new FloatValueSyntax(value));

    /// <summary>
    /// Sets a string array at <paramref name="keyPath"/>. The array node is rewritten
    /// wholesale (escaped basic strings, ", " separators); an inline comment after the
    /// closing bracket survives via the replacement's trivia copy. An empty list
    /// emits <c>[]</c>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The document has parse errors.</exception>
    public void SetStringArray(string keyPath, IReadOnlyList<string> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        var items = values.ToArray();
        if (Array.Exists(items, static v => v is null))
            throw new ArgumentException("Array items must not be null.", nameof(values));
        SetValue(keyPath, () => new ArraySyntax(items)); // Tomlyn escapes items; empty input still prints []
    }

    /// <summary>
    /// True when <paramref name="keyPath"/> is defined via <c>[[array-of-tables]]</c>
    /// syntax anywhere in the document. Such a key is READABLE via
    /// <see cref="TryGetTableArray"/> (the model exposes it) but UNWRITABLE by the
    /// structured mutators: <see cref="FindKeyValueAndOwner"/> deliberately skips
    /// <c>TableArraySyntax</c>, so a naive write would append a second
    /// <c>key = value</c> definition and produce a duplicate-key document that
    /// <see cref="HasErrors"/>, the model, and the validator all silently accept
    /// (the A1 spike, probe P3-3). <see cref="SetInlineTableArray"/> fails closed on it.
    /// </summary>
    public bool UsesTableArraySyntax(string keyPath)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyPath);
        foreach (var table in _syntax.Tables)
        {
            if (table is not TableArraySyntax ta) continue;
            var name = GetSemanticName(ta.Name);
            if (name is null) continue;
            // Match the key itself OR any ANCESTOR: writing `a.b` when `[[a]]` exists (parent
            // array-of-tables) would append a duplicate `[a]` table — the same P3-3 duplicate-
            // definition hazard as the exact `[[a.b]]` form (Core review 2026-07-02).
            if (name == keyPath || keyPath.StartsWith(name + ".", StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Sets <paramref name="keyPath"/> to an array of single-line inline tables in
    /// canonical MULTI-LINE form (one item per line, two-space indent, trailing comma);
    /// an empty list emits <c>[]</c>. Like <see cref="SetStringArray"/>, the array node
    /// is rewritten wholesale (any comment INSIDE the old array value is dropped), but
    /// an inline comment after the closing bracket and every surrounding line survive
    /// via the replacement's trivia copy.
    /// </summary>
    /// <remarks>
    /// Each inner key/value prints on the item's single line — the builder sets
    /// <c>EndOfLineToken = null</c> on every inner <c>KeyValueSyntax</c> (the A1 spike's
    /// landmine (a): a plain <c>new KeyValueSyntax(k, v)</c> injects a newline inside the
    /// <c>{ }</c> that Tomlyn re-parses cleanly but that violates TOML 1.0 and pre-1.1
    /// parsers). Values come from <see cref="TomlInlineTableValue"/>; Tomlyn owns all
    /// escaping (basic strings, array separators).
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// The document has parse errors, OR <see cref="UsesTableArraySyntax"/> is true for
    /// <paramref name="keyPath"/> (fail-closed: writing would create a duplicate definition).
    /// </exception>
    public void SetInlineTableArray(string keyPath, IReadOnlyList<TomlInlineTableValue> items)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyPath);
        ArgumentNullException.ThrowIfNull(items);
        EnsureMutable();
        if (UsesTableArraySyntax(keyPath))
            throw new InvalidOperationException(
                $"Cannot write '{keyPath}' as an inline-table array: it is defined as a [[array-of-tables]] " +
                "in this document. Edit it in the raw editor.");
        SetValue(keyPath, () => BuildInlineTableArray(items));
    }

    /// <summary>
    /// Reads <paramref name="keyPath"/> as a list of tables regardless of on-disk form —
    /// inline (<c>routes = [ { … } ]</c> ⇒ model <c>TomlArray</c> of <c>TomlTable</c>),
    /// dotted top-level, or <c>[[array-of-tables]]</c> (⇒ model <c>TomlTableArray</c>).
    /// Each element is copied into a fresh dictionary of raw model values (string / bool /
    /// long / <c>TomlArray</c> …) so callers never depend on Tomlyn types. Returns false
    /// when absent, when the value is not an array-of-tables, or when any element is not a
    /// table (fail-closed).
    /// </summary>
    public bool TryGetTableArray(string keyPath, out IReadOnlyList<IReadOnlyDictionary<string, object?>> items)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyPath);
        IEnumerable<object?>? elements = GetRaw(keyPath) switch
        {
            TomlTableArray tableArray => tableArray,       // [[key]] form
            TomlArray array => array,                       // inline / dotted form
            _ => null,                                      // absent or not an array
        };
        if (elements is null) { items = Array.Empty<IReadOnlyDictionary<string, object?>>(); return false; }

        var result = new List<IReadOnlyDictionary<string, object?>>();
        foreach (var element in elements)
        {
            if (element is not TomlTable table) // e.g. a plain string array — not tables
            {
                items = Array.Empty<IReadOnlyDictionary<string, object?>>();
                return false;
            }
            var copy = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var pair in table) copy[pair.Key] = pair.Value;
            result.Add(copy);
        }
        items = result;
        return true;
    }

    /// <summary>Builds the canonical multi-line inline-table array value node (A1 spike, probe P3-2).</summary>
    private static ArraySyntax BuildInlineTableArray(IReadOnlyList<TomlInlineTableValue> items)
    {
        var array = new ArraySyntax
        {
            // Landmine (b): the parameterless ctor leaves both bracket tokens null and
            // prints nothing — set them explicitly.
            OpenBracket = SyntaxFactory.Token(TokenKind.OpenBracket),
            CloseBracket = SyntaxFactory.Token(TokenKind.CloseBracket),
        };
        if (items.Count == 0)
            return array; // prints "[]"

        // Open bracket then newline + indent so the first item starts on its own line.
        array.OpenBracket.TrailingTrivia = new List<SyntaxTrivia>
            { SyntaxFactory.NewLineTrivia(), new(TokenKind.Whitespaces, "  ") };

        for (var i = 0; i < items.Count; i++)
        {
            var item = new ArrayItemSyntax
            {
                Value = BuildInlineTable(items[i]),
                Comma = SyntaxFactory.Token(TokenKind.Comma),
            };
            // Trailing comma on every item (legal TOML); newline + indent before the next
            // item, newline only before the closing bracket so it lands at column 0.
            item.Comma.TrailingTrivia = i < items.Count - 1
                ? new List<SyntaxTrivia> { SyntaxFactory.NewLineTrivia(), new(TokenKind.Whitespaces, "  ") }
                : new List<SyntaxTrivia> { SyntaxFactory.NewLineTrivia() };
            array.Items.Add(item);
        }
        return array;
    }

    /// <summary>Builds one single-line inline table (A1 spike landmine (a): inner kvs carry no EndOfLineToken).</summary>
    private static InlineTableSyntax BuildInlineTable(TomlInlineTableValue value)
    {
        var kvs = new KeyValueSyntax[value.Fields.Count];
        for (var i = 0; i < value.Fields.Count; i++)
        {
            var field = value.Fields[i];
            ValueSyntax valueSyntax = field.StringValue is not null
                ? new StringValueSyntax(field.StringValue)    // Tomlyn escapes to a basic string
                : new ArraySyntax(field.ArrayValue!);         // ["a", "b"] / [] — Tomlyn owns separators
            kvs[i] = new KeyValueSyntax(field.Key, valueSyntax) { EndOfLineToken = null };
        }
        return new InlineTableSyntax(kvs);
    }

    /// <summary>
    /// Removes the key at <paramref name="keyPath"/> — the whole <c>key = value</c>
    /// line goes, including its own trivia (its inline comment; a full-line comment
    /// ABOVE the pair belongs to the previous line's trailing trivia and stays).
    /// Returns whether the key existed; an absent key is a no-op.
    /// </summary>
    /// <exception cref="InvalidOperationException">The document has parse errors.</exception>
    public bool RemoveKey(string keyPath)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyPath);
        EnsureMutable();

        var (owner, kv) = FindKeyValueAndOwner(keyPath);
        if (owner is null || kv is null) return false;
        owner.RemoveChild(kv);
        InvalidateModelCache(); // readers must see the removal
        return true;
    }

    private void SetValue(string keyPath, Func<ValueSyntax> createValue)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyPath);
        EnsureMutable();

        var (_, kv) = FindKeyValueAndOwner(keyPath);
        if (kv is null)
            InsertKeyValue(keyPath, createValue());
        else
            WriteValue(kv, createValue());
        InvalidateModelCache(); // readers must see the mutation
    }

    /// <summary>Creates a missing key (dotted path, segment = table) with <paramref name="value"/>.</summary>
    private void InsertKeyValue(string keyPath, ValueSyntax value)
    {
        // Defense in depth for the scalar mutators (SetBool/SetString/… which don't pre-check
        // UsesTableArraySyntax): refuse to create a key whose section — or an ancestor of it — is
        // defined as an [[array-of-tables]], which would emit a duplicate table definition and
        // corrupt the document into invalid TOML that HasErrors/the model would not catch.
        if (UsesTableArraySyntax(keyPath))
            throw new InvalidOperationException(
                $"Cannot create key '{keyPath}': it (or an ancestor) is defined as an [[array-of-tables]].");

        var segments = keyPath.Split('.');
        foreach (var segment in segments)
        {
            if (!IsBareKey(segment))
                throw new ArgumentException(
                    $"Cannot create TOML key '{keyPath}': segment '{segment}' is not a bare key ([A-Za-z0-9_-]+).",
                    nameof(keyPath));
        }

        var kv = new KeyValueSyntax(segments[^1], value); // Tomlyn prints "key = value" + newline

        if (segments.Length == 1)
        {
            // Top-level key: DocumentSyntax prints its KeyValues region BEFORE its
            // Tables region, so appending here lands before the first [table] header —
            // a top-level key printed after a header would change its owning table.
            if (_syntax.KeyValues.ChildrenCount > 0)
                EnsureEndOfLine(_syntax.KeyValues);
            _syntax.KeyValues.Add(kv);
            return;
        }

        var tablePath = string.Join('.', segments[..^1]);
        foreach (var table in _syntax.Tables)
        {
            if (table is not TableSyntax t || GetSemanticName(t.Name) != tablePath) continue;

            // Append as the table's last item. Blank lines/comments that FOLLOW the
            // last item belong to its trailing trivia (probe-verified), so they stay
            // put and the new line prints after them, before the next [table] header.
            if (t.Items.ChildrenCount > 0)
                EnsureEndOfLine(t.Items);
            else
                t.EndOfLineToken ??= SyntaxFactory.NewLine(); // bare "[t]" at EOF without newline
            t.Items.Add(kv);
            return;
        }

        // No matching [table]: create it at end-of-document (Tables print after
        // KeyValues), blank-line separated when the document already has content.
        var hasContent = _syntax.KeyValues.ChildrenCount > 0 || _syntax.Tables.ChildrenCount > 0;
        if (_syntax.Tables.ChildrenCount > 0)
        {
            if (_syntax.Tables.GetChild(_syntax.Tables.ChildrenCount - 1) is { } lastTable)
            {
                if (lastTable.Items.ChildrenCount > 0)
                    EnsureEndOfLine(lastTable.Items);
                else
                    lastTable.EndOfLineToken ??= SyntaxFactory.NewLine();
            }
        }
        else if (_syntax.KeyValues.ChildrenCount > 0)
        {
            EnsureEndOfLine(_syntax.KeyValues);
        }

        var newTable = new TableSyntax(BuildKey(segments[..^1])); // header prints "[name]" + newline
        if (hasContent && newTable.OpenBracket is not null)
            newTable.OpenBracket.LeadingTrivia = new List<SyntaxTrivia> { new(TokenKind.NewLine, "\n") };
        newTable.Items.Add(kv);
        _syntax.Tables.Add(newTable);
    }

    /// <summary>Builds a (possibly dotted) bare-key header name; segments pre-validated.</summary>
    private static KeySyntax BuildKey(string[] segments)
    {
        var key = new KeySyntax(segments[0]);
        for (var i = 1; i < segments.Length; i++)
            key.DotKeys.Add(new DottedKeyItemSyntax(segments[i]));
        return key;
    }

    /// <summary>
    /// A file ending without '\n' leaves the last pair's EndOfLineToken null; appending
    /// after it would run two lines together into invalid TOML — add the newline first.
    /// </summary>
    private static void EnsureEndOfLine(SyntaxList<KeyValueSyntax> items)
    {
        var last = items.GetChild(items.ChildrenCount - 1);
        if (last is null) return; // defensive: SyntaxList slots are nullable-annotated
        last.EndOfLineToken ??= SyntaxFactory.NewLine();
    }

    private static bool IsBareKey(string segment)
        => segment.Length > 0 && segment.All(static c =>
            c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '_' or '-');

    private void EnsureMutable()
    {
        if (HasErrors)
            throw new InvalidOperationException("Cannot mutate a TOML document that has parse errors; callers must gate on a clean parse.");
    }

    private static void WriteValue(KeyValueSyntax kv, ValueSyntax newValue)
    {
        // Same-type scalar writes: edit the existing token IN PLACE (Text + TokenKind
        // from the freshly built node) — all trivia, including an inline comment in the
        // value token's TrailingTrivia, stays untouched.
        switch (kv.Value, newValue)
        {
            case (BooleanValueSyntax { Token: not null } o, BooleanValueSyntax { Token: not null } n):
                CopyToken(o.Token, n.Token);
                o.Value = n.Value; // semantic field only; output comes from Token.Text
                return;
            case (IntegerValueSyntax { Token: not null } o, IntegerValueSyntax { Token: not null } n):
                CopyToken(o.Token, n.Token);
                o.Value = n.Value;
                return;
            case (FloatValueSyntax { Token: not null } o, FloatValueSyntax { Token: not null } n):
                CopyToken(o.Token, n.Token);
                o.Value = n.Value;
                return;
            case (StringValueSyntax { Token: not null } o, StringValueSyntax { Token: not null } n):
                // Also converts literal ('…') / multi-line strings to a basic string.
                CopyToken(o.Token, n.Token);
                o.Value = n.Value;
                return;
            default:
                break; // type-changing or non-scalar write: replace the node below
        }

        // Replacement + trivia copy: move the old node's first-token leading trivia and
        // last-token trailing trivia (where an inline comment lives) onto the new node.
        var oldFirst = kv.Value is null ? null : FirstToken(kv.Value);
        var oldLast = kv.Value is null ? null : LastToken(kv.Value);
        var newFirst = FirstToken(newValue);
        var newLast = LastToken(newValue);
        if (oldFirst is not null && newFirst is not null)
            newFirst.LeadingTrivia = oldFirst.LeadingTrivia;
        if (oldLast is not null && newLast is not null)
            newLast.TrailingTrivia = oldLast.TrailingTrivia;
        kv.Value = newValue;
    }

    private static void CopyToken(SyntaxToken target, SyntaxToken source)
    {
        target.TokenKind = source.TokenKind;
        target.Text = source.Text;
    }

    private static SyntaxToken? FirstToken(SyntaxNode node)
    {
        if (node is SyntaxToken token) return token;
        for (var i = 0; i < node.ChildrenCount; i++)
        {
            var child = node.GetChild(i);
            if (child is null) continue;
            if (FirstToken(child) is { } result) return result;
        }
        return null;
    }

    private static SyntaxToken? LastToken(SyntaxNode node)
    {
        if (node is SyntaxToken token) return token;
        for (var i = node.ChildrenCount - 1; i >= 0; i--)
        {
            var child = node.GetChild(i);
            if (child is null) continue;
            if (LastToken(child) is { } result) return result;
        }
        return null;
    }

    /// <summary>
    /// Resolves a dotted key path (segment = table, mirroring <see cref="GetRaw"/>) to
    /// its <see cref="KeyValueSyntax"/> plus the <see cref="SyntaxList{T}"/> that owns
    /// it. Names are matched semantically (quoted keys and spaced dotted headers
    /// resolve to their model names), so syntax addressing can never diverge from the
    /// model-based readers. Returns (null, null) when absent.
    /// </summary>
    private (SyntaxList<KeyValueSyntax>? Owner, KeyValueSyntax? Kv) FindKeyValueAndOwner(string keyPath)
    {
        foreach (var kv in _syntax.KeyValues)
        {
            if (GetSemanticName(kv.Key) == keyPath)
                return (_syntax.KeyValues, kv);
        }

        foreach (var table in _syntax.Tables)
        {
            if (table is not TableSyntax t) continue; // [[array-of-tables]] deliberately not traversed
            var name = GetSemanticName(t.Name);
            if (name is null || !keyPath.StartsWith(name + ".", StringComparison.Ordinal)) continue;
            var rest = keyPath[(name.Length + 1)..];
            foreach (var kv in t.Items)
            {
                if (GetSemanticName(kv.Key) == rest)
                    return (t.Items, kv);
            }
        }

        return (null, null);
    }

    /// <summary>
    /// Semantic (model) name of a possibly-dotted key: parts joined with '.'.
    /// Null when any part is unresolvable or unaddressable.
    /// </summary>
    private static string? GetSemanticName(KeySyntax? key)
    {
        if (key is null) return null;
        var name = GetKeyPartName(key.Key);
        if (name is null) return null;
        foreach (var dotted in key.DotKeys)
        {
            var part = GetKeyPartName(dotted.Key);
            if (part is null) return null;
            name = name + "." + part;
        }
        return name;
    }

    /// <summary>
    /// Semantic name of one key part. A quoted key whose content contains a dot
    /// ("a.b" = 1 names a SINGLE key) is unreachable by dotted-path addressing —
    /// <see cref="GetRaw"/> splits on '.' — so it maps to null and is skipped,
    /// keeping reader/mutator parity.
    /// </summary>
    private static string? GetKeyPartName(BareKeyOrStringValueSyntax? part) => part switch
    {
        BareKeySyntax bare => bare.Key?.Text,
        StringValueSyntax quoted when quoted.Value is { } v && !v.Contains('.') => v,
        _ => null,
    };
}
