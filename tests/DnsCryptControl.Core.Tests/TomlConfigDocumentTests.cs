using DnsCryptControl.Core.Toml;
using Xunit;

namespace DnsCryptControl.Core.Tests;

public class TomlConfigDocumentTests
{
    private const string Sample =
        "# heading comment\n" +
        "listen_addresses = ['127.0.0.1:53']\n" +
        "max_clients = 250\n" +
        "\n" +
        "[query_log]\n" +
        "format = 'tsv'\n";

    [Fact]
    public void Parse_validToml_hasNoErrors()
    {
        var doc = TomlConfigDocument.Parse(Sample);
        Assert.False(doc.HasErrors);
        Assert.Empty(doc.Errors);
    }

    [Fact]
    public void ToText_roundTrips_losslessly_preservingComments()
    {
        var doc = TomlConfigDocument.Parse(Sample);
        Assert.Equal(Sample, doc.ToText());
    }

    [Fact]
    public void Parse_invalidToml_reportsErrors()
    {
        var doc = TomlConfigDocument.Parse("max_clients = = 3");
        Assert.True(doc.HasErrors);
        Assert.NotEmpty(doc.Errors);
    }

    [Theory]
    [InlineData("x = \"\\uD800\"")]   // a \u escape decoding to a lone surrogate (invalid UTF-32 scalar)
    [InlineData("vV^71\"\\")]          // the fuzzer's shrunk reproducer (CsCheck_Seed=0i6BDFROMtI4)
    public void Parse_pathological_escape_fails_closed_not_throws(string toml)
    {
        // Regression (found by fuzzing, 2026-07-08): Tomlyn's lexer THROWS ArgumentOutOfRangeException
        // (Char.ConvertFromUtf32) while FORMATTING a diagnostic for a surrogate/out-of-range \u escape.
        // Parse must be total and fail CLOSED to HasErrors - every caller treats an un-loadable config
        // that way, never as a crash.
        var doc = TomlConfigDocument.Parse(toml);
        Assert.True(doc.HasErrors);
        Assert.NotEmpty(doc.Errors);
    }

    [Fact]
    public void Parse_nullInput_throws()
    {
        Assert.Throws<ArgumentNullException>(() => TomlConfigDocument.Parse(null!));
    }
}
