using DnsCryptControl.Core.Toml;
using Xunit;

namespace DnsCryptControl.Core.Tests;

/// <summary>
/// A3.5: <see cref="TomlConfigDocument.TryGetSubTables"/> — enumerating <c>[sources.&lt;name&gt;]</c>
/// child tables so the resolver-list reader discovers sources (cache_file + prefix) from the
/// config instead of hardcoding list names.
/// </summary>
public class TomlConfigDocumentSubTableTests
{
    private const string SourcesSample =
        "[sources]\n" +
        "\n" +
        "[sources.'public-resolvers']\n" +
        "urls = ['https://example/public-resolvers.md']\n" +
        "cache_file = 'public-resolvers.md'\n" +
        "minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'\n" +
        "\n" +
        "[sources.relays]\n" +
        "cache_file = 'relays.md'\n" +
        "prefix = 'anon-'\n";

    [Fact]
    public void TryGetSubTables_enumeratesSourcesWithQuotedAndBareNames()
    {
        var doc = TomlConfigDocument.Parse(SourcesSample);

        Assert.True(doc.TryGetSubTables("sources", out var sources));
        Assert.Equal(2, sources.Count);

        var pub = sources.Single(s => s.Name == "public-resolvers");
        Assert.True(pub.TryGetString("cache_file", out var pubCache));
        Assert.Equal("public-resolvers.md", pubCache);
        Assert.True(pub.TryGetStringArray("urls", out var urls));
        Assert.Single(urls);
        Assert.False(pub.TryGetString("prefix", out _)); // absent

        var relays = sources.Single(s => s.Name == "relays");
        Assert.True(relays.TryGetString("cache_file", out var relayCache));
        Assert.Equal("relays.md", relayCache);
        Assert.True(relays.TryGetString("prefix", out var prefix));
        Assert.Equal("anon-", prefix);
    }

    [Fact]
    public void TryGetSubTables_absentSection_returnsTrueEmpty()
    {
        var doc = TomlConfigDocument.Parse("server_names = ['cloudflare']\n");
        Assert.True(doc.TryGetSubTables("sources", out var sources));
        Assert.Empty(sources);
    }

    [Fact]
    public void TryGetSubTables_sectionIsNotATable_failsClosed()
    {
        var doc = TomlConfigDocument.Parse("sources = 'not a table'\n");
        Assert.False(doc.TryGetSubTables("sources", out var sources));
        Assert.Empty(sources);
    }

    [Fact]
    public void TryGetSubTables_onParseErrors_returnsEmpty()
    {
        var doc = TomlConfigDocument.Parse("garbage = = =\n");
        Assert.True(doc.HasErrors);
        Assert.True(doc.TryGetSubTables("sources", out var sources)); // GetRaw returns null on errors
        Assert.Empty(sources);
    }
}
