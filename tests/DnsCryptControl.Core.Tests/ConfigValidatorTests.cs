using System.Linq;
using DnsCryptControl.Core.Toml;
using DnsCryptControl.Core.Validation;
using Xunit;

namespace DnsCryptControl.Core.Tests;

public class ConfigValidatorTests
{
    [Fact]
    public void Validate_syntaxError_isError()
    {
        var report = ConfigValidator.Validate(TomlConfigDocument.Parse("x = = 1"));
        Assert.False(report.IsValid);
        Assert.Contains(report.Issues, i => i.Severity == ValidationSeverity.Error);
    }

    [Fact]
    public void Validate_validKnownConfig_isValid()
    {
        var report = ConfigValidator.Validate(TomlConfigDocument.Parse(
            "max_clients = 250\nrequire_nolog = true\n"));
        Assert.True(report.IsValid);
    }

    [Fact]
    public void Validate_wrongType_isError()
    {
        // max_clients must be an integer, not a string
        var report = ConfigValidator.Validate(TomlConfigDocument.Parse("max_clients = 'lots'"));
        Assert.Contains(report.Issues,
            i => i.KeyPath == "max_clients" && i.Severity == ValidationSeverity.Error);
    }

    [Fact]
    public void Validate_unknownTopLevelKey_isWarning()
    {
        var report = ConfigValidator.Validate(TomlConfigDocument.Parse("totally_made_up = 1"));
        Assert.Contains(report.Issues,
            i => i.KeyPath == "totally_made_up" && i.Severity == ValidationSeverity.Warning);
    }

    [Fact]
    public void Validate_deprecatedKey_warnsWithReplacement()
    {
        var report = ConfigValidator.Validate(TomlConfigDocument.Parse("fallback_resolvers = ['9.9.9.9:53']"));
        Assert.Contains(report.Issues,
            i => i.KeyPath == "fallback_resolvers"
              && i.Severity == ValidationSeverity.Warning
              && i.Message.Contains("bootstrap_resolvers"));
    }

    [Fact]
    public void Validate_dynamicSourcesSection_producesNoSpuriousWarnings()
    {
        var report = ConfigValidator.Validate(TomlConfigDocument.Parse(
            "[sources.public-resolvers]\n" +
            "urls = ['https://example.test/public-resolvers.md']\n" +
            "cache_file = 'public-resolvers.md'\n" +
            "minisign_key = 'RWQexample'\n" +
            "refresh_delay = 73\n"));
        Assert.True(report.IsValid);
        Assert.DoesNotContain(report.Issues, i => i.Severity == ValidationSeverity.Warning);
    }

    [Fact]
    public void Validate_unknownKeyInFixedSection_isWarning()
    {
        var report = ConfigValidator.Validate(TomlConfigDocument.Parse(
            "[query_log]\nformat = 'tsv'\nbogus_key = 1\n"));
        Assert.Contains(report.Issues,
            i => i.KeyPath == "query_log.bogus_key" && i.Severity == ValidationSeverity.Warning);
    }

    [Fact]
    public void Validate_syntaxError_usesSyntaxKeyPath()
    {
        var report = ConfigValidator.Validate(TomlConfigDocument.Parse("x = = 1"));
        Assert.Contains(report.Issues, i => i.KeyPath == "(syntax)" && i.Severity == ValidationSeverity.Error);
    }

    // Phase 5c regression (live VM run): anonymized_dns.routes is an ARRAY of inline tables, not a Table.
    // The catalog mis-typed it as Table, so the helper's ConfigValidator rejected EVERY AnonDNS save as
    // "expects Table but got TomlArray" — blocking the whole feature. Fixed by the TableArray type.

    [Fact]
    public void Validate_anonymizedDnsRoutes_inlineTableArray_isValid()
    {
        var report = ConfigValidator.Validate(TomlConfigDocument.Parse(
            "[anonymized_dns]\n" +
            "routes = [{ server_name = 'example', via = ['anon-relay'] }]\n" +
            "skip_incompatible = true\n" +
            "direct_cert_fallback = false\n"));
        Assert.DoesNotContain(report.Issues,
            i => i.KeyPath == "anonymized_dns.routes" && i.Severity == ValidationSeverity.Error);
    }

    [Fact]
    public void Validate_anonymizedDnsRoutes_emptyArray_isValid()
    {
        // Enable-with-0-routes writes routes = [] — the exact save that failed in the §5 VM run.
        var report = ConfigValidator.Validate(TomlConfigDocument.Parse(
            "[anonymized_dns]\nroutes = []\nskip_incompatible = true\ndirect_cert_fallback = false\n"));
        Assert.DoesNotContain(report.Issues,
            i => i.KeyPath == "anonymized_dns.routes" && i.Severity == ValidationSeverity.Error);
    }

    [Fact]
    public void Validate_anonymizedDnsRoutes_arrayOfTablesForm_isValid()
    {
        // The [[anonymized_dns.routes]] array-of-tables form (Tomlyn: TomlTableArray) also validates.
        var report = ConfigValidator.Validate(TomlConfigDocument.Parse(
            "[[anonymized_dns.routes]]\nserver_name = 'example'\nvia = ['anon-relay']\n"));
        Assert.DoesNotContain(report.Issues,
            i => i.KeyPath == "anonymized_dns.routes" && i.Severity == ValidationSeverity.Error);
    }
}
