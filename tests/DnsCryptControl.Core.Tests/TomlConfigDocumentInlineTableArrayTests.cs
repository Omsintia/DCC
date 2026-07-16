using DnsCryptControl.Core.Toml;
using Xunit;

namespace DnsCryptControl.Core.Tests;

/// <summary>
/// A1 spike: <see cref="TomlConfigDocument.SetInlineTableArray"/> /
/// <see cref="TomlConfigDocument.UsesTableArraySyntax"/> /
/// <see cref="TomlConfigDocument.TryGetTableArray"/> — the inline-table-array mutation
/// surface Phase 5c writes <c>[anonymized_dns].routes</c> through. IC-1: comments,
/// formatting, and unknown keys survive byte-for-byte outside the rewritten value;
/// IC-4: canonical multi-line form, single-line inline tables; IC-12: the mutator itself
/// fails closed on the <c>[[array-of-tables]]</c> duplicate-definition hazard.
/// </summary>
public class TomlConfigDocumentInlineTableArrayTests
{
    private static TomlInlineTableValue Route(string serverName, params string[] via)
        => new TomlInlineTableValue()
            .AddString("server_name", serverName)
            .AddStringArray("via", via);

    // ---- byte-exact REPLACE: preserve banner / above-key / inline / neighbour comments ----

    private const string ReplaceSample =
        "# banner comment\n" +
        "[anonymized_dns]\n" +
        "# routes comment above the key\n" +
        "routes = [ { server_name = 'old', via = ['r0'] } ] # inline note\n" +
        "skip_incompatible = false # keep me\n";

    private const string ReplaceExpected =
        "# banner comment\n" +
        "[anonymized_dns]\n" +
        "# routes comment above the key\n" +
        "routes = [\n" +
        "  { server_name = \"server-1\", via = [\"anon-relay-1\", \"anon-relay-2\"] },\n" +
        "  { server_name = \"server-2\", via = [\"anon-relay-3\"] },\n" +
        "] # inline note\n" +
        "skip_incompatible = false # keep me\n";

    [Fact]
    public void SetInlineTableArray_replace_isCanonicalMultiline_andPreservesSurroundingComments()
    {
        var doc = TomlConfigDocument.Parse(ReplaceSample);

        doc.SetInlineTableArray("anonymized_dns.routes", new[]
        {
            Route("server-1", "anon-relay-1", "anon-relay-2"),
            Route("server-2", "anon-relay-3"),
        });

        Assert.Equal(ReplaceExpected, doc.ToText());
        Assert.False(TomlConfigDocument.Parse(doc.ToText()).HasErrors); // round-trips to valid TOML
    }

    // ---- byte-exact INSERT: routes absent (the stock-config case — routes ships commented out) ----

    private const string InsertSample =
        "[anonymized_dns]\n" +
        "skip_incompatible = true # kept\n";

    private const string InsertExpected =
        "[anonymized_dns]\n" +
        "skip_incompatible = true # kept\n" +
        "routes = [\n" +
        "  { server_name = \"cloudflare\", via = [\"anon-cs-fr\"] },\n" +
        "]\n";

    [Fact]
    public void SetInlineTableArray_insertWhenAbsent_appendsCanonicalBlock()
    {
        var doc = TomlConfigDocument.Parse(InsertSample);

        doc.SetInlineTableArray("anonymized_dns.routes", new[] { Route("cloudflare", "anon-cs-fr") });

        Assert.Equal(InsertExpected, doc.ToText());
        Assert.False(TomlConfigDocument.Parse(doc.ToText()).HasErrors);
    }

    // ---- empty list emits [] ----

    [Fact]
    public void SetInlineTableArray_emptyList_emitsEmptyBrackets_andKeepsInlineComment()
    {
        var doc = TomlConfigDocument.Parse(
            "[anonymized_dns]\n" +
            "routes = [ { server_name = 'x', via = ['y'] } ] # note\n");

        doc.SetInlineTableArray("anonymized_dns.routes", Array.Empty<TomlInlineTableValue>());

        Assert.Equal(
            "[anonymized_dns]\n" +
            "routes = [] # note\n",
            doc.ToText());
    }

    // ---- single-line inline-table invariant (IC-4 landmine (a)) ----

    [Fact]
    public void SetInlineTableArray_inlineTablesNeverContainNewlines()
    {
        var doc = TomlConfigDocument.Parse("[anonymized_dns]\nroutes = []\n");

        doc.SetInlineTableArray("anonymized_dns.routes", new[]
        {
            Route("server-1", "r1", "r2"),
            Route("server-2", "r3"),
        });

        // Every line carrying an inline table opens and closes its braces on that line.
        foreach (var line in doc.ToText().Split('\n'))
        {
            if (line.Contains('{'))
                Assert.Contains('}', line);
        }
    }

    // ---- hostile string escaping is Tomlyn-owned and round-trips ----

    [Fact]
    public void SetInlineTableArray_escapesHostileStrings()
    {
        var doc = TomlConfigDocument.Parse("[anonymized_dns]\nroutes = []\n");

        doc.SetInlineTableArray("anonymized_dns.routes", new[]
        {
            new TomlInlineTableValue()
                .AddString("server_name", "quote\"and\\slash")
                .AddStringArray("via", new[] { "r\"1" }),
        });

        var text = doc.ToText();
        Assert.False(TomlConfigDocument.Parse(text).HasErrors);
        Assert.Contains("server_name = \"quote\\\"and\\\\slash\"", text);
        // read back through the model to prove the escapes are semantically correct
        Assert.True(doc.TryGetTableArray("anonymized_dns.routes", out var items));
        Assert.Equal("quote\"and\\slash", Assert.Single(items)["server_name"]);
    }

    // ---- model-cache invalidation ----

    [Fact]
    public void SetInlineTableArray_invalidatesModelCache()
    {
        var doc = TomlConfigDocument.Parse("[anonymized_dns]\nroutes = []\n");

        // Prime the lazy model so the post-write read proves invalidation.
        Assert.True(doc.TryGetTableArray("anonymized_dns.routes", out var before));
        Assert.Empty(before);

        doc.SetInlineTableArray("anonymized_dns.routes", new[] { Route("cloudflare", "anon-cs-fr") });

        Assert.True(doc.TryGetTableArray("anonymized_dns.routes", out var after));
        Assert.Equal("cloudflare", Assert.Single(after)["server_name"]);
    }

    // ---- interior comment inside the array value is dropped (deliberate, like SetStringArray) ----

    [Fact]
    public void SetInlineTableArray_dropsCommentsInsideTheOldArray_keepsTrailingComment()
    {
        var doc = TomlConfigDocument.Parse(
            "[anonymized_dns]\n" +
            "routes = [ # head\n" +
            "  { server_name = 'old', via = ['r'] }, # per-route\n" +
            "] # tail\n");

        doc.SetInlineTableArray("anonymized_dns.routes", new[] { Route("new", "r1") });

        var text = doc.ToText();
        Assert.DoesNotContain("# head", text);
        Assert.DoesNotContain("# per-route", text);
        Assert.Contains("] # tail", text); // the after-bracket comment survives via trivia copy
    }

    // ---- [[array-of-tables]] form: readable, but writes fail closed (IC-12, probe P3-3) ----

    private const string TableArrayForm =
        "[anonymized_dns]\n" +
        "skip_incompatible = false\n" +
        "\n" +
        "[[anonymized_dns.routes]]\n" +
        "server_name = 'example'\n" +
        "via = ['relay1']\n";

    [Fact]
    public void UsesTableArraySyntax_detectsDoubleBracketForm()
    {
        var doc = TomlConfigDocument.Parse(TableArrayForm);
        Assert.True(doc.UsesTableArraySyntax("anonymized_dns.routes"));
        Assert.False(doc.UsesTableArraySyntax("anonymized_dns.skip_incompatible"));
    }

    [Fact]
    public void SetInlineTableArray_onDoubleBracketForm_throws_andLeavesDocumentUnchanged()
    {
        var doc = TomlConfigDocument.Parse(TableArrayForm);

        var ex = Assert.Throws<InvalidOperationException>(
            () => doc.SetInlineTableArray("anonymized_dns.routes", new[] { Route("x", "y") }));
        Assert.Contains("[[array-of-tables]]", ex.Message);

        // The duplicate-definition hazard (probe P3-3) is unreachable: the doc is untouched.
        Assert.Equal(TableArrayForm, doc.ToText());
    }

    [Fact]
    public void UsesTableArraySyntax_detectsParentDoubleBracketForm()
    {
        // Core review CRITICAL: a PARENT [[anonymized_dns]] must also block writing anonymized_dns.routes
        // (writing would append a duplicate [anonymized_dns] table -> invalid TOML).
        var doc = TomlConfigDocument.Parse("[[anonymized_dns]]\nroutes = [ { server_name = 'a', via = ['r'] } ]\n");
        Assert.True(doc.UsesTableArraySyntax("anonymized_dns.routes"));
        Assert.Throws<InvalidOperationException>(
            () => doc.SetInlineTableArray("anonymized_dns.routes", new[] { Route("x", "r") }));
    }

    [Fact]
    public void SetBool_underParentDoubleBracketForm_throws_notCorrupts()
    {
        // The scalar mutators must also fail closed on an ancestor [[array-of-tables]] (defense in depth).
        var doc = TomlConfigDocument.Parse("[[server]]\nname = 'a'\n");
        Assert.Throws<InvalidOperationException>(() => doc.SetBool("server.enabled", true));
    }

    [Fact]
    public void TryGetTableArray_readsDoubleBracketForm()
    {
        var doc = TomlConfigDocument.Parse(TableArrayForm);

        Assert.True(doc.TryGetTableArray("anonymized_dns.routes", out var items));
        var route = Assert.Single(items);
        Assert.Equal("example", route["server_name"]);
    }

    // ---- TryGetTableArray reads the inline + dotted forms, and fails closed otherwise ----

    [Fact]
    public void TryGetTableArray_readsInlineForm()
    {
        var doc = TomlConfigDocument.Parse(
            "[anonymized_dns]\n" +
            "routes = [ { server_name = 'a', via = ['r1', 'r2'] }, { server_name = 'b', via = ['*'] } ]\n");

        Assert.True(doc.TryGetTableArray("anonymized_dns.routes", out var items));
        Assert.Equal(2, items.Count);
        Assert.Equal("a", items[0]["server_name"]);
        Assert.Equal("b", items[1]["server_name"]);
    }

    [Fact]
    public void TryGetTableArray_readsTopLevelDottedForm()
    {
        // dnscrypt-proxy configs occasionally use a top-level dotted key (probe P3-5).
        var doc = TomlConfigDocument.Parse(
            "anonymized_dns.routes = [ { server_name = 'x', via = ['y'] } ]\n");

        Assert.True(doc.TryGetTableArray("anonymized_dns.routes", out var items));
        Assert.Equal("x", Assert.Single(items)["server_name"]);
    }

    [Fact]
    public void TryGetTableArray_absentKey_returnsFalse()
    {
        var doc = TomlConfigDocument.Parse("[anonymized_dns]\nskip_incompatible = false\n");
        Assert.False(doc.TryGetTableArray("anonymized_dns.routes", out var items));
        Assert.Empty(items);
    }

    [Fact]
    public void TryGetTableArray_nonTableArray_returnsFalse()
    {
        // A plain string array is not an array-of-tables — fail closed.
        var doc = TomlConfigDocument.Parse("server_names = ['a', 'b']\n");
        Assert.False(doc.TryGetTableArray("server_names", out var items));
        Assert.Empty(items);
    }

    // ---- guards ----

    [Fact]
    public void SetInlineTableArray_onDocumentWithParseErrors_throws()
    {
        var doc = TomlConfigDocument.Parse("this is = = not valid toml\n");
        Assert.True(doc.HasErrors);
        Assert.Throws<InvalidOperationException>(
            () => doc.SetInlineTableArray("anonymized_dns.routes", Array.Empty<TomlInlineTableValue>()));
    }

    [Fact]
    public void TomlInlineTableValue_rejectsNonBareKeys()
    {
        Assert.Throws<ArgumentException>(() => new TomlInlineTableValue().AddString("bad.key", "v"));
        Assert.Throws<ArgumentException>(() => new TomlInlineTableValue().AddStringArray("has space", new[] { "v" }));
    }

    [Fact]
    public void TomlInlineTableValue_rejectsNullValues()
    {
        Assert.Throws<ArgumentNullException>(() => new TomlInlineTableValue().AddString("k", null!));
        Assert.Throws<ArgumentNullException>(() => new TomlInlineTableValue().AddStringArray("k", null!));
        Assert.Throws<ArgumentException>(() => new TomlInlineTableValue().AddStringArray("k", new string[] { null! }));
    }
}
