using DnsCryptControl.Core.Toml;
using Xunit;

namespace DnsCryptControl.Core.Tests;

/// <summary>
/// A2: the full surgical mutation API on <see cref="TomlConfigDocument"/> (absorbs the
/// A1 spike). IC-1: never regenerate text from the derived TomlTable model — comments,
/// formatting, and unknown keys must survive byte-for-byte outside the mutated token.
/// </summary>
public class TomlConfigDocumentMutationTests
{
    // ---------------------------------------------------------------- A1 spike (SetBool)

    // Deliberately hostile to model round-tripping: a full-line comment, an inline
    // trailing comment on the mutated line, and an un-catalogued key.
    private const string TopLevelSample =
        "# dnscrypt-proxy configuration (managed by DnsCryptControl)\n" +
        "require_dnssec = false # keep in sync with resolver capabilities\n" +
        "x_custom = 1\n";

    private const string TopLevelExpected =
        "# dnscrypt-proxy configuration (managed by DnsCryptControl)\n" +
        "require_dnssec = true # keep in sync with resolver capabilities\n" +
        "x_custom = 1\n";

    [Fact]
    public void SetBool_topLevel_changesOnlyTheValueToken_andInvalidatesModelCache()
    {
        var doc = TomlConfigDocument.Parse(TopLevelSample);

        // Prime the lazy model cache so the post-mutation read proves invalidation
        // rather than passing vacuously on a never-populated cache.
        Assert.True(doc.TryGetBool("require_dnssec", out var before));
        Assert.False(before);

        doc.SetBool("require_dnssec", true);

        // Full-string assertion: the leading comment, the inline comment, the unknown
        // key, and every byte of whitespace must be intact — only false -> true.
        Assert.Equal(TopLevelExpected, doc.ToText());

        // Cache invalidation: the reader must serve the NEW value, not the stale model.
        Assert.True(doc.TryGetBool("require_dnssec", out var after));
        Assert.True(after);
    }

    // Table traversal fixture: the same key path shape the dotted-path cases build on.
    private const string TableSample =
        "# main section\n" +
        "listen_addresses = ['127.0.0.1:53']\n" +
        "\n" +
        "[anonymized_dns]\n" +
        "# relay routing\n" +
        "skip_incompatible = false # inline note\n";

    private const string TableExpected =
        "# main section\n" +
        "listen_addresses = ['127.0.0.1:53']\n" +
        "\n" +
        "[anonymized_dns]\n" +
        "# relay routing\n" +
        "skip_incompatible = true # inline note\n";

    [Fact]
    public void SetBool_insideTable_changesOnlyTheValueToken_andInvalidatesModelCache()
    {
        var doc = TomlConfigDocument.Parse(TableSample);

        Assert.True(doc.TryGetBool("anonymized_dns.skip_incompatible", out var before));
        Assert.False(before);

        doc.SetBool("anonymized_dns.skip_incompatible", true);

        Assert.Equal(TableExpected, doc.ToText());

        Assert.True(doc.TryGetBool("anonymized_dns.skip_incompatible", out var after));
        Assert.True(after);
    }

    // ---------------------------------------------------------------- TryGetDouble (A2 reader)
    // The reader ships with A2 (plan: "the missing float reader"); it lives here because
    // A2's file scope is this test file plus TomlConfigDocument.cs.

    [Fact]
    public void TryGetDouble_tomlFloat_returnsValue()
    {
        var doc = TomlConfigDocument.Parse("timeout_load_reduction = 0.75\n");
        Assert.True(doc.TryGetDouble("timeout_load_reduction", out var v));
        Assert.Equal(0.75, v);
    }

    [Fact]
    public void TryGetDouble_tomlInteger_widensToDouble()
    {
        // Mirrors ConfigValidator's Float semantics (value is double or long), so
        // `timeout_load_reduction = 1` reads back as 1.0 instead of failing.
        var doc = TomlConfigDocument.Parse("timeout_load_reduction = 1\n");
        Assert.True(doc.TryGetDouble("timeout_load_reduction", out var v));
        Assert.Equal(1.0, v);
    }

    [Fact]
    public void TryGetDouble_stringValue_returnsFalse()
    {
        var doc = TomlConfigDocument.Parse("timeout_load_reduction = 'fast'\n");
        Assert.False(doc.TryGetDouble("timeout_load_reduction", out _));
    }

    [Fact]
    public void TryGetDouble_missingKey_returnsFalse()
    {
        var doc = TomlConfigDocument.Parse("max_clients = 250\n");
        Assert.False(doc.TryGetDouble("timeout_load_reduction", out _));
    }

    [Fact]
    public void TryGetDouble_insideTable_returnsValue()
    {
        var doc = TomlConfigDocument.Parse("[broken_implementations]\nx_ratio = 2.5\n");
        Assert.True(doc.TryGetDouble("broken_implementations.x_ratio", out var v));
        Assert.Equal(2.5, v);
    }

    // ---------------------------------------------------------------- scalar Set* (A2 cycle 2)

    [Fact]
    public void SetString_topLevel_convertsLiteralToBasicString_preservingInlineComment()
    {
        var doc = TomlConfigDocument.Parse("forwarding_rules = 'forwarding-rules.txt' # path\n");
        Assert.True(doc.TryGetString("forwarding_rules", out _)); // prime the model cache

        doc.SetString("forwarding_rules", "other.txt");

        // Tomlyn re-emits the value as an escaped BASIC string ("..."); the original
        // literal-string quoting is not preserved — only the value token changes.
        Assert.Equal("forwarding_rules = \"other.txt\" # path\n", doc.ToText());
        Assert.True(doc.TryGetString("forwarding_rules", out var after));
        Assert.Equal("other.txt", after);
    }

    [Fact]
    public void SetString_insideTable_changesOnlyTheValueToken()
    {
        var doc = TomlConfigDocument.Parse("[query_log]\nformat = 'tsv' # fmt\n");

        doc.SetString("query_log.format", "ltsv");

        Assert.Equal("[query_log]\nformat = \"ltsv\" # fmt\n", doc.ToText());
        Assert.True(doc.TryGetString("query_log.format", out var after));
        Assert.Equal("ltsv", after);
    }

    [Fact]
    public void SetString_escapesBackslashAndQuote_andRoundTrips()
    {
        // Adversarial escaping per the plan: back\slash and quote"quote must emit a
        // valid TOML basic string and read back unchanged.
        var doc = TomlConfigDocument.Parse("log_file = 'x'\n");

        doc.SetString("log_file", "back\\slash");
        Assert.Equal("log_file = \"back\\\\slash\"\n", doc.ToText());

        doc.SetString("log_file", "quote\"quote");
        Assert.Equal("log_file = \"quote\\\"quote\"\n", doc.ToText());

        var reparsed = TomlConfigDocument.Parse(doc.ToText());
        Assert.False(reparsed.HasErrors);
        Assert.True(reparsed.TryGetString("log_file", out var roundTripped));
        Assert.Equal("quote\"quote", roundTripped);
    }

    [Fact]
    public void SetLong_topLevel_inPlace_preservingInlineComment()
    {
        var doc = TomlConfigDocument.Parse("max_clients = 250 # connection cap\n");
        Assert.True(doc.TryGetLong("max_clients", out _)); // prime the model cache

        doc.SetLong("max_clients", 500);

        Assert.Equal("max_clients = 500 # connection cap\n", doc.ToText());
        Assert.True(doc.TryGetLong("max_clients", out var after));
        Assert.Equal(500, after);
    }

    [Fact]
    public void SetDouble_existingFloat_inPlace_preservingInlineComment()
    {
        var doc = TomlConfigDocument.Parse("timeout_load_reduction = 0.75 # ratio\n");
        Assert.True(doc.TryGetDouble("timeout_load_reduction", out _)); // prime the model cache

        doc.SetDouble("timeout_load_reduction", 0.5);

        Assert.Equal("timeout_load_reduction = 0.5 # ratio\n", doc.ToText());
        Assert.True(doc.TryGetDouble("timeout_load_reduction", out var after));
        Assert.Equal(0.5, after);
    }

    [Fact]
    public void SetDouble_wholeNumber_emitsValidTomlFloat()
    {
        // 1.0 must print as "1.0" (a bare "1" would silently become a TOML integer).
        var doc = TomlConfigDocument.Parse("timeout_load_reduction = 0.75\n");

        doc.SetDouble("timeout_load_reduction", 1.0);

        Assert.Equal("timeout_load_reduction = 1.0\n", doc.ToText());
        var reparsed = TomlConfigDocument.Parse(doc.ToText());
        Assert.False(reparsed.HasErrors);
        Assert.True(reparsed.TryGetDouble("timeout_load_reduction", out var v));
        Assert.Equal(1.0, v);
    }

    [Fact]
    public void SetLong_onStringValue_replacesNodeType_preservingInlineComment()
    {
        // Type-changing write: replacement + trivia copy (the A1-pinned fallback for
        // writes where in-place token editing is impossible).
        var doc = TomlConfigDocument.Parse("max_clients = 'lots' # cap\n");

        doc.SetLong("max_clients", 250);

        Assert.Equal("max_clients = 250 # cap\n", doc.ToText());
        Assert.True(doc.TryGetLong("max_clients", out var after));
        Assert.Equal(250, after);
    }

    [Fact]
    public void SetDouble_onIntegerValue_replacesNodeType_preservingInlineComment()
    {
        // A Float catalog entry can legitimately hold integer syntax on disk
        // (timeout_load_reduction = 1); writing a double converts the node.
        var doc = TomlConfigDocument.Parse("timeout_load_reduction = 1 # reduction\n");

        doc.SetDouble("timeout_load_reduction", 0.25);

        Assert.Equal("timeout_load_reduction = 0.25 # reduction\n", doc.ToText());
        Assert.True(doc.TryGetDouble("timeout_load_reduction", out var after));
        Assert.Equal(0.25, after);
    }

    [Fact]
    public void SetBool_quotedKey_resolvesSemantically_keepingTheKeyQuoted()
    {
        // Quoted-key hardening: "cache" prints quoted but its model name is bare, so
        // dotted-path addressing must reach it — and the key spelling must survive.
        var doc = TomlConfigDocument.Parse("\"cache\" = false # quoted key\n");

        doc.SetBool("cache", true);

        Assert.Equal("\"cache\" = true # quoted key\n", doc.ToText());
        Assert.True(doc.TryGetBool("cache", out var after));
        Assert.True(after);
    }

    [Fact]
    public void SetString_dottedHeaderWithInnerSpacing_resolvesSemantically()
    {
        // [ a . b ] carries inner spacing in its syntax; the semantic table name is
        // "a.b" and must match GetRaw's model addressing.
        var doc = TomlConfigDocument.Parse("[ anonymized_dns . inner ]\nvia = 'x' # v\n");
        Assert.True(doc.TryGetString("anonymized_dns.inner.via", out _)); // model reaches it

        doc.SetString("anonymized_dns.inner.via", "y");

        Assert.Equal("[ anonymized_dns . inner ]\nvia = \"y\" # v\n", doc.ToText());
        Assert.True(doc.TryGetString("anonymized_dns.inner.via", out var after));
        Assert.Equal("y", after);
    }

    [Fact]
    public void Mutators_onDocumentWithParseErrors_throwInvalidOperation()
    {
        var doc = TomlConfigDocument.Parse("x = = 1"); // invalid -> HasErrors
        Assert.True(doc.HasErrors);
        Assert.Throws<InvalidOperationException>(() => doc.SetBool("x", true));
        Assert.Throws<InvalidOperationException>(() => doc.SetString("x", "v"));
        Assert.Throws<InvalidOperationException>(() => doc.SetLong("x", 1));
        Assert.Throws<InvalidOperationException>(() => doc.SetDouble("x", 1.0));
    }

    [Fact]
    public void SetString_nullValue_throws()
    {
        var doc = TomlConfigDocument.Parse("log_file = 'x'\n");
        Assert.Throws<ArgumentNullException>(() => doc.SetString("log_file", null!));
    }

    [Fact]
    public void Mutators_emptyKeyPath_throw()
    {
        var doc = TomlConfigDocument.Parse("max_clients = 250\n");
        Assert.Throws<ArgumentException>(() => doc.SetLong("", 1));
        Assert.Throws<ArgumentNullException>(() => doc.SetString(null!, "v"));
    }

    // ---------------------------------------------------------------- SetStringArray (A2 cycle 3)

    [Fact]
    public void SetStringArray_replacesExistingArray_preservingInlineCommentAfterBracket()
    {
        var doc = TomlConfigDocument.Parse("server_names = ['a', 'b'] # resolver picks\n");
        Assert.True(doc.TryGetStringArray("server_names", out _)); // prime the model cache

        doc.SetStringArray("server_names", new[] { "cloudflare", "quad9" });

        // The whole array node is rewritten (basic strings, ", " separators); the
        // inline comment after the closing bracket must survive the replacement.
        Assert.Equal("server_names = [\"cloudflare\", \"quad9\"] # resolver picks\n", doc.ToText());
        Assert.True(doc.TryGetStringArray("server_names", out var after));
        Assert.Equal(new[] { "cloudflare", "quad9" }, after);
    }

    [Fact]
    public void SetStringArray_insideTable_changesOnlyTheValueNode()
    {
        var doc = TomlConfigDocument.Parse("[query_log]\nignored_qtypes = ['DNSKEY'] # noise\n");

        doc.SetStringArray("query_log.ignored_qtypes", new[] { "DNSKEY", "NS" });

        Assert.Equal("[query_log]\nignored_qtypes = [\"DNSKEY\", \"NS\"] # noise\n", doc.ToText());
        Assert.True(doc.TryGetStringArray("query_log.ignored_qtypes", out var after));
        Assert.Equal(new[] { "DNSKEY", "NS" }, after);
    }

    [Fact]
    public void SetStringArray_emptyList_emitsEmptyBrackets()
    {
        var doc = TomlConfigDocument.Parse("server_names = ['a']\n");

        doc.SetStringArray("server_names", Array.Empty<string>());

        Assert.Equal("server_names = []\n", doc.ToText());
        var reparsed = TomlConfigDocument.Parse(doc.ToText());
        Assert.False(reparsed.HasErrors);
        Assert.True(reparsed.TryGetStringArray("server_names", out var after));
        Assert.Empty(after);
    }

    [Fact]
    public void SetStringArray_escapesHostileItems_andRoundTrips()
    {
        var doc = TomlConfigDocument.Parse("server_names = ['a']\n");

        doc.SetStringArray("server_names", new[] { "back\\slash", "quote\"quote" });

        Assert.Equal("server_names = [\"back\\\\slash\", \"quote\\\"quote\"]\n", doc.ToText());
        var reparsed = TomlConfigDocument.Parse(doc.ToText());
        Assert.False(reparsed.HasErrors);
        Assert.True(reparsed.TryGetStringArray("server_names", out var after));
        Assert.Equal(new[] { "back\\slash", "quote\"quote" }, after);
    }

    [Fact]
    public void SetStringArray_onScalarValue_replacesNodeType_preservingInlineComment()
    {
        var doc = TomlConfigDocument.Parse("server_names = 'single' # keep\n");

        doc.SetStringArray("server_names", new[] { "one", "two" });

        Assert.Equal("server_names = [\"one\", \"two\"] # keep\n", doc.ToText());
        Assert.True(doc.TryGetStringArray("server_names", out var after));
        Assert.Equal(new[] { "one", "two" }, after);
    }

    [Fact]
    public void SetStringArray_nullArguments_throw()
    {
        var doc = TomlConfigDocument.Parse("server_names = ['a']\n");
        Assert.Throws<ArgumentNullException>(() => doc.SetStringArray("server_names", null!));
        Assert.Throws<ArgumentException>(() => doc.SetStringArray("server_names", new[] { "ok", null! }));
    }

    [Fact]
    public void SetStringArray_onDocumentWithParseErrors_throwsInvalidOperation()
    {
        var doc = TomlConfigDocument.Parse("x = = 1");
        Assert.True(doc.HasErrors);
        Assert.Throws<InvalidOperationException>(() => doc.SetStringArray("x", new[] { "v" }));
    }

    // ---------------------------------------------------------------- insertion: existing table (A2 cycle 4)

    [Fact]
    public void SetBool_missingKeyInExistingTable_appendsAtTableEnd()
    {
        var doc = TomlConfigDocument.Parse(
            "[query_log]\n" +
            "format = 'tsv'\n" +
            "[nx_log]\n" +
            "file = 'nx.log'\n");
        Assert.False(doc.TryGetBool("query_log.cache", out _)); // prime the model cache

        doc.SetBool("query_log.cache", true);

        // Appended as the table's last item: "key = value" + newline, every
        // pre-existing byte intact, and the key lands in the RIGHT table.
        Assert.Equal(
            "[query_log]\n" +
            "format = 'tsv'\n" +
            "cache = true\n" +
            "[nx_log]\n" +
            "file = 'nx.log'\n",
            doc.ToText());
        Assert.True(doc.TryGetBool("query_log.cache", out var after));
        Assert.True(after);
    }

    [Fact]
    public void SetBool_missingKeyInTable_trailingBannerTriviaStaysPut()
    {
        // Tomlyn attaches a blank line + comment that FOLLOW a table's last item to
        // that item's trailing trivia (verified by probe): an appended item therefore
        // prints after them, immediately before the next [table] header. Neighbor
        // bytes are untouched — pinned here so the disposition is deliberate.
        var doc = TomlConfigDocument.Parse(
            "[query_log]\n" +
            "format = 'tsv'\n" +
            "\n" +
            "# ---- NX log ----\n" +
            "[nx_log]\n" +
            "file = 'nx.log'\n");

        doc.SetBool("query_log.cache", false);

        Assert.Equal(
            "[query_log]\n" +
            "format = 'tsv'\n" +
            "\n" +
            "# ---- NX log ----\n" +
            "cache = false\n" +
            "[nx_log]\n" +
            "file = 'nx.log'\n",
            doc.ToText());
        Assert.True(doc.TryGetBool("query_log.cache", out var inserted));
        Assert.False(inserted);
        Assert.True(doc.TryGetString("nx_log.file", out var neighbor)); // neighbor table unharmed
        Assert.Equal("nx.log", neighbor);
    }

    [Fact]
    public void SetString_missingKeyInLastTable_atEofWithoutTrailingNewline_insertsOwnLine()
    {
        // The last line has NO trailing newline: the insert must add one first or the
        // two lines would run together into invalid TOML.
        var doc = TomlConfigDocument.Parse("[query_log]\nformat = 'tsv'");

        doc.SetString("query_log.file", "query.log");

        Assert.Equal("[query_log]\nformat = 'tsv'\nfile = \"query.log\"\n", doc.ToText());
        var reparsed = TomlConfigDocument.Parse(doc.ToText());
        Assert.False(reparsed.HasErrors);
        Assert.True(reparsed.TryGetString("query_log.file", out var v));
        Assert.Equal("query.log", v);
    }

    [Fact]
    public void SetLong_missingKeyInEmptyHeaderOnlyTable_atEof_insertsFirstItem()
    {
        // "[query_log]" with no items and no trailing newline: the header itself needs
        // the end-of-line guard before the first item can follow.
        var doc = TomlConfigDocument.Parse("[query_log]");

        doc.SetLong("query_log.max_size", 100);

        Assert.Equal("[query_log]\nmax_size = 100\n", doc.ToText());
        Assert.True(doc.TryGetLong("query_log.max_size", out var v));
        Assert.Equal(100, v);
    }

    [Fact]
    public void SetDouble_andSetStringArray_insertIntoExistingTable()
    {
        var doc = TomlConfigDocument.Parse("[query_log]\nformat = 'tsv'\n");

        doc.SetDouble("query_log.x_ratio", 0.5);
        doc.SetStringArray("query_log.ignored_qtypes", new[] { "DNSKEY" });

        Assert.Equal(
            "[query_log]\n" +
            "format = 'tsv'\n" +
            "x_ratio = 0.5\n" +
            "ignored_qtypes = [\"DNSKEY\"]\n",
            doc.ToText());
        Assert.True(doc.TryGetDouble("query_log.x_ratio", out var ratio));
        Assert.Equal(0.5, ratio);
        Assert.True(doc.TryGetStringArray("query_log.ignored_qtypes", out var qtypes));
        Assert.Equal(new[] { "DNSKEY" }, qtypes);
    }

    [Fact]
    public void Insertion_nonBareKeySegment_throwsArgumentException()
    {
        // Creating a key requires bare segments ([A-Za-z0-9_-]+); anything else would
        // print invalid TOML. Mutating an EXISTING quoted key still works (matched
        // semantically) — only creation is gated.
        var doc = TomlConfigDocument.Parse("[query_log]\nformat = 'tsv'\n");
        Assert.Throws<ArgumentException>(() => doc.SetBool("query_log.bad key", true));
    }

    // ---------------------------------------------------------------- insertion: top level (A2 cycle 5)

    [Fact]
    public void SetBool_missingTopLevelKey_appendsBeforeFirstTableHeader()
    {
        // A top-level key printed AFTER a [table] header would belong to that table;
        // the insert must land at the end of the top-level region, before the header.
        // Trailing trivia of that region (the banner) stays put — probe-verified
        // Tomlyn ownership, pinned deliberately (bytes intact, ownership correct).
        var doc = TomlConfigDocument.Parse(
            "max_clients = 250\n" +
            "\n" +
            "# ---- Query logging ----\n" +
            "[query_log]\n" +
            "format = 'tsv'\n");
        Assert.False(doc.TryGetBool("ignore_system_dns", out _)); // prime the model cache

        doc.SetBool("ignore_system_dns", true);

        Assert.Equal(
            "max_clients = 250\n" +
            "\n" +
            "# ---- Query logging ----\n" +
            "ignore_system_dns = true\n" +
            "[query_log]\n" +
            "format = 'tsv'\n",
            doc.ToText());
        Assert.True(doc.TryGetBool("ignore_system_dns", out var after));
        Assert.True(after);
        Assert.True(doc.TryGetString("query_log.format", out _)); // table untouched
    }

    [Fact]
    public void SetLong_missingTopLevelKey_noTables_noTrailingNewline_insertsOwnLine()
    {
        var doc = TomlConfigDocument.Parse("max_clients = 250");

        doc.SetLong("netprobe_timeout", 60);

        Assert.Equal("max_clients = 250\nnetprobe_timeout = 60\n", doc.ToText());
        Assert.True(doc.TryGetLong("netprobe_timeout", out var v));
        Assert.Equal(60, v);
    }

    [Fact]
    public void SetString_missingTopLevelKey_whenOnlyTablesExist_printsBeforeThem()
    {
        // The leading file comment is the header's leading trivia; the new top-level
        // key prints before it (start of the empty top-level region), which keeps its
        // ownership out of [query_log].
        var doc = TomlConfigDocument.Parse("# file comment\n[query_log]\nformat = 'tsv'\n");

        doc.SetString("log_file", "app.log");

        Assert.Equal("log_file = \"app.log\"\n# file comment\n[query_log]\nformat = 'tsv'\n", doc.ToText());
        Assert.True(doc.TryGetString("log_file", out var v));
        Assert.Equal("app.log", v);
    }

    [Fact]
    public void SetBool_missingTopLevelKey_emptyDocument_createsTheOnlyLine()
    {
        var doc = TomlConfigDocument.Parse("");
        Assert.False(doc.HasErrors);

        doc.SetBool("ignore_system_dns", false);

        Assert.Equal("ignore_system_dns = false\n", doc.ToText());
        Assert.True(doc.TryGetBool("ignore_system_dns", out var v));
        Assert.False(v);
    }

    [Fact]
    public void Insertion_nonBareTopLevelKey_throwsArgumentException()
    {
        var doc = TomlConfigDocument.Parse("max_clients = 250\n");
        Assert.Throws<ArgumentException>(() => doc.SetString("bad key", "v"));
    }

    // ---------------------------------------------------------------- insertion: new table (A2 cycle 6)

    [Fact]
    public void SetBool_missingTable_createsTableAtDocumentEnd_blankLineSeparated()
    {
        var doc = TomlConfigDocument.Parse("max_clients = 250\n");
        Assert.False(doc.TryGetBool("query_log.cache", out _)); // prime the model cache

        doc.SetBool("query_log.cache", true);

        Assert.Equal("max_clients = 250\n\n[query_log]\ncache = true\n", doc.ToText());
        Assert.True(doc.TryGetBool("query_log.cache", out var after));
        Assert.True(after);
    }

    [Fact]
    public void SetString_missingTable_appendsAfterExistingTables()
    {
        var doc = TomlConfigDocument.Parse("[query_log]\nformat = 'tsv'\n");

        doc.SetString("nx_log.file", "nx.log");

        Assert.Equal("[query_log]\nformat = 'tsv'\n\n[nx_log]\nfile = \"nx.log\"\n", doc.ToText());
        Assert.True(doc.TryGetString("nx_log.file", out var v));
        Assert.Equal("nx.log", v);
        Assert.True(doc.TryGetString("query_log.format", out _)); // neighbor untouched
    }

    [Fact]
    public void SetLong_missingTable_emptyDocument_noLeadingBlankLine()
    {
        var doc = TomlConfigDocument.Parse("");

        doc.SetLong("query_log.max_size", 100);

        Assert.Equal("[query_log]\nmax_size = 100\n", doc.ToText());
        Assert.True(doc.TryGetLong("query_log.max_size", out var v));
        Assert.Equal(100, v);
    }

    [Fact]
    public void SetDouble_missingDottedTable_createsDottedHeader()
    {
        var doc = TomlConfigDocument.Parse("top = 1\n");

        doc.SetDouble("a.b.ratio", 0.5);

        Assert.Equal("top = 1\n\n[a.b]\nratio = 0.5\n", doc.ToText());
        var reparsed = TomlConfigDocument.Parse(doc.ToText());
        Assert.False(reparsed.HasErrors);
        Assert.True(reparsed.TryGetDouble("a.b.ratio", out var v));
        Assert.Equal(0.5, v);
    }

    [Fact]
    public void SetBool_missingTable_afterEofWithoutTrailingNewline_staysValid()
    {
        var doc = TomlConfigDocument.Parse("[query_log]\nformat = 'tsv'");

        doc.SetBool("nx_log.cache", false);

        Assert.Equal("[query_log]\nformat = 'tsv'\n\n[nx_log]\ncache = false\n", doc.ToText());
        var reparsed = TomlConfigDocument.Parse(doc.ToText());
        Assert.False(reparsed.HasErrors);
        Assert.True(reparsed.TryGetBool("nx_log.cache", out var v));
        Assert.False(v);
    }

    // ---------------------------------------------------------------- RemoveKey (A2 cycle 7)

    [Fact]
    public void RemoveKey_topLevel_removesTheWholeLine_includingInlineComment()
    {
        var doc = TomlConfigDocument.Parse("a = 1\nb = 2 # gone with the line\nc = 3\n");
        Assert.True(doc.TryGetLong("b", out _)); // prime the model cache

        Assert.True(doc.RemoveKey("b"));

        Assert.Equal("a = 1\nc = 3\n", doc.ToText());
        Assert.False(doc.TryGetLong("b", out _)); // cache invalidated — key really gone
        Assert.True(doc.TryGetLong("c", out var c));
        Assert.Equal(3, c);
    }

    [Fact]
    public void RemoveKey_insideTable_removesOnlyThatLine()
    {
        var doc = TomlConfigDocument.Parse(
            "[query_log]\nformat = 'tsv'\ncache = true\n[nx_log]\nfile = 'x'\n");

        Assert.True(doc.RemoveKey("query_log.cache"));

        Assert.Equal("[query_log]\nformat = 'tsv'\n[nx_log]\nfile = 'x'\n", doc.ToText());
        Assert.False(doc.TryGetBool("query_log.cache", out _));
    }

    [Fact]
    public void RemoveKey_absentKey_returnsFalse_documentUnchanged()
    {
        const string Fixture = "a = 1\n[query_log]\nformat = 'tsv'\n";
        var doc = TomlConfigDocument.Parse(Fixture);

        Assert.False(doc.RemoveKey("missing"));
        Assert.False(doc.RemoveKey("query_log.missing"));
        Assert.False(doc.RemoveKey("no_such_table.key"));

        Assert.Equal(Fixture, doc.ToText());
    }

    [Fact]
    public void RemoveKey_fullLineCommentAboveTheKey_staysInTheDocument()
    {
        // Tomlyn attaches a full-line comment ABOVE a pair to the PREVIOUS line's
        // trailing trivia (empirically pinned), so removing the pair leaves the
        // comment in place. Removal takes exactly the pair's own line.
        var doc = TomlConfigDocument.Parse("a = 1\n# about b\nb = 2\nc = 3\n");

        Assert.True(doc.RemoveKey("b"));

        Assert.Equal("a = 1\n# about b\nc = 3\n", doc.ToText());
    }

    [Fact]
    public void RemoveKey_onDocumentWithParseErrors_throwsInvalidOperation()
    {
        var doc = TomlConfigDocument.Parse("x = = 1");
        Assert.True(doc.HasErrors);
        Assert.Throws<InvalidOperationException>(() => doc.RemoveKey("x"));
    }

    [Fact]
    public void RemoveKey_emptyKeyPath_throws()
    {
        var doc = TomlConfigDocument.Parse("a = 1\n");
        Assert.Throws<ArgumentException>(() => doc.RemoveKey(""));
        Assert.Throws<ArgumentNullException>(() => doc.RemoveKey(null!));
    }

    // ---------------------------------------------------------------- duplicate bare names
    // Plan fixture: top-level `cache` AND [query_log].`cache` — the same bare name in
    // two scopes; every operation must touch EXACTLY the addressed line.

    private const string DuplicateNameFixture =
        "cache = true\n" +
        "\n" +
        "[query_log]\n" +
        "cache = false\n";

    [Fact]
    public void SetBool_duplicateBareName_topLevelPath_mutatesOnlyTheTopLevelLine()
    {
        var doc = TomlConfigDocument.Parse(DuplicateNameFixture);

        doc.SetBool("cache", false);

        // The [query_log] line is byte-identical; only the top-level value flipped.
        Assert.Equal("cache = false\n\n[query_log]\ncache = false\n", doc.ToText());
        Assert.True(doc.TryGetBool("cache", out var top));
        Assert.False(top);
    }

    [Fact]
    public void SetBool_duplicateBareName_tablePath_mutatesOnlyTheTableLine()
    {
        var doc = TomlConfigDocument.Parse(DuplicateNameFixture);

        doc.SetBool("query_log.cache", true);

        // The top-level line is byte-identical; only the table value flipped.
        Assert.Equal("cache = true\n\n[query_log]\ncache = true\n", doc.ToText());
        Assert.True(doc.TryGetBool("query_log.cache", out var table));
        Assert.True(table);
    }

    [Fact]
    public void RemoveKey_duplicateBareName_topLevelPath_removesOnlyTheTopLevelLine()
    {
        var doc = TomlConfigDocument.Parse(DuplicateNameFixture);

        Assert.True(doc.RemoveKey("cache"));

        // The removed node takes its trailing blank line with it (Tomlyn attaches the
        // blank to the pair's end-of-line trivia); the table line is untouched.
        Assert.Equal("[query_log]\ncache = false\n", doc.ToText());
        Assert.False(doc.TryGetBool("cache", out _));
        Assert.True(doc.TryGetBool("query_log.cache", out var table));
        Assert.False(table);
    }

    [Fact]
    public void RemoveKey_duplicateBareName_tablePath_removesOnlyTheTableLine()
    {
        var doc = TomlConfigDocument.Parse(DuplicateNameFixture);

        Assert.True(doc.RemoveKey("query_log.cache"));

        Assert.Equal("cache = true\n\n[query_log]\n", doc.ToText());
        Assert.True(doc.TryGetBool("cache", out var top));
        Assert.True(top);
        Assert.False(doc.TryGetBool("query_log.cache", out _));
    }

    // ---------------------------------------------------------------- spec acceptance
    // Plan A2: load a fixture with comments + unknown key + deprecated key -> toggle one
    // value -> ToText() -> re-parse -> comments, unknown key, deprecated key, and
    // formatting all survive; unchanged regions byte-identical.

    private const string SpecFixture =
        "# Managed by DnsCryptControl — do not hand-edit while protection is enabled\n" +
        "listen_addresses = ['127.0.0.1:53']\n" +
        "require_dnssec = false # resolver capability gate\n" +
        "fallback_resolvers = ['9.9.9.9:53'] # deprecated key (bootstrap_resolvers replaces it)\n" +
        "x_experimental_flag = 'keep-me' # unknown, un-catalogued key\n" +
        "\n" +
        "# ---- Query logging ----\n" +
        "[query_log]\n" +
        "format = 'tsv'\n";

    private const string SpecFixtureExpected =
        "# Managed by DnsCryptControl — do not hand-edit while protection is enabled\n" +
        "listen_addresses = ['127.0.0.1:53']\n" +
        "require_dnssec = true # resolver capability gate\n" +
        "fallback_resolvers = ['9.9.9.9:53'] # deprecated key (bootstrap_resolvers replaces it)\n" +
        "x_experimental_flag = 'keep-me' # unknown, un-catalogued key\n" +
        "\n" +
        "# ---- Query logging ----\n" +
        "[query_log]\n" +
        "format = 'tsv'\n";

    [Fact]
    public void StructuredToggle_thenRoundTrip_preservesCommentsUnknownAndDeprecatedKeys()
    {
        var doc = TomlConfigDocument.Parse(SpecFixture);
        Assert.False(doc.HasErrors);

        doc.SetBool("require_dnssec", true);

        // Byte-identical outside the single mutated token (full-string pin).
        var text = doc.ToText();
        Assert.Equal(SpecFixtureExpected, text);

        // The regenerated text re-parses cleanly and every survivor is still readable.
        var reparsed = TomlConfigDocument.Parse(text);
        Assert.False(reparsed.HasErrors);
        Assert.True(reparsed.TryGetBool("require_dnssec", out var toggled));
        Assert.True(toggled);
        Assert.True(reparsed.TryGetStringArray("fallback_resolvers", out var deprecated));
        Assert.Equal(new[] { "9.9.9.9:53" }, deprecated);
        Assert.True(reparsed.TryGetString("x_experimental_flag", out var unknown));
        Assert.Equal("keep-me", unknown);
        Assert.True(reparsed.TryGetString("query_log.format", out var fmt));
        Assert.Equal("tsv", fmt);
    }
}
