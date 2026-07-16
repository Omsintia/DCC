using DnsCryptControl.Core.Toml;
using Xunit;

namespace DnsCryptControl.Core.Tests;

public class TomlConfigDocumentReadTests
{
    private static TomlConfigDocument Doc() => TomlConfigDocument.Parse(
        "max_clients = 250\n" +
        "require_nolog = true\n" +
        "server_names = ['cloudflare', 'google']\n" +
        "[query_log]\n" +
        "format = 'tsv'\n");

    [Fact]
    public void TryGetLong_topLevel_returnsValue()
    {
        Assert.True(Doc().TryGetLong("max_clients", out var v));
        Assert.Equal(250, v);
    }

    [Fact]
    public void TryGetBool_topLevel_returnsValue()
    {
        Assert.True(Doc().TryGetBool("require_nolog", out var v));
        Assert.True(v);
    }

    [Fact]
    public void TryGetStringArray_returnsAllItems()
    {
        Assert.True(Doc().TryGetStringArray("server_names", out var v));
        Assert.Equal(new[] { "cloudflare", "google" }, v);
    }

    [Fact]
    public void TryGetString_inSection_returnsValue()
    {
        Assert.True(Doc().TryGetString("query_log.format", out var v));
        Assert.Equal("tsv", v);
    }

    [Fact]
    public void TryGetString_missingKey_returnsFalse()
    {
        Assert.False(Doc().TryGetString("does_not_exist", out _));
    }

    [Fact]
    public void TryGetLong_wrongType_returnsFalse()
    {
        // require_nolog is a bool, so asking for a long must return false (not throw)
        Assert.False(Doc().TryGetLong("require_nolog", out _));
    }

    [Fact]
    public void TryGetString_topLevel_returnsValue()
    {
        var doc = TomlConfigDocument.Parse("log_file = 'app.log'\n");
        Assert.True(doc.TryGetString("log_file", out var v));
        Assert.Equal("app.log", v);
    }

    [Fact]
    public void Readers_onInvalidDocument_returnFalse_neverThrow()
    {
        var doc = TomlConfigDocument.Parse("x = = 1"); // invalid -> HasErrors
        Assert.True(doc.HasErrors);
        Assert.Null(doc.GetRaw("x"));
        Assert.False(doc.TryGetLong("x", out _));
        Assert.False(doc.TryGetString("x", out _));
    }
}
