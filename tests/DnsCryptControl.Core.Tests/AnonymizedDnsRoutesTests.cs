using DnsCryptControl.Core.AnonymizedDns;
using DnsCryptControl.Core.Toml;
using Xunit;

namespace DnsCryptControl.Core.Tests;

/// <summary>
/// A4: <see cref="AnonymizedDnsRoutes"/> — the routes domain over the A1 inline-table-array
/// mutators. Reads both forms; writes only the inline form; fails closed (CanWrite) on the
/// [[…]] form and malformed/extra-key elements; IC-7 name validation on write.
/// </summary>
public class AnonymizedDnsRoutesTests
{
    [Fact]
    public void TryRead_absent_returnsTrueEmpty()
    {
        var doc = TomlConfigDocument.Parse("[anonymized_dns]\nskip_incompatible = true\n");
        Assert.True(AnonymizedDnsRoutes.TryRead(doc, out var routes, out _));
        Assert.Empty(routes);
    }

    [Fact]
    public void TryRead_inlineForm_readsRoutes()
    {
        var doc = TomlConfigDocument.Parse(
            "[anonymized_dns]\n" +
            "routes = [ { server_name = 'cloudflare', via = ['anon-cs-fr', 'anon-x'] }, { server_name = '*', via = ['*'] } ]\n");

        Assert.True(AnonymizedDnsRoutes.TryRead(doc, out var routes, out _));
        Assert.Equal(2, routes.Count);
        Assert.Equal("cloudflare", routes[0].ServerName);
        Assert.Equal(new[] { "anon-cs-fr", "anon-x" }, routes[0].Via);
        Assert.Equal("*", routes[1].ServerName);
        Assert.Equal(new[] { "*" }, routes[1].Via);
    }

    [Fact]
    public void TryRead_doubleBracketForm_readsRoutes()
    {
        var doc = TomlConfigDocument.Parse(
            "[[anonymized_dns.routes]]\n" +
            "server_name = 'example'\n" +
            "via = ['relay1']\n");

        Assert.True(AnonymizedDnsRoutes.TryRead(doc, out var routes, out _));
        Assert.Equal("example", Assert.Single(routes).ServerName);
    }

    [Fact]
    public void TryRead_missingServerName_failsClosed()
    {
        var doc = TomlConfigDocument.Parse("[anonymized_dns]\nroutes = [ { via = ['r'] } ]\n");
        Assert.False(AnonymizedDnsRoutes.TryRead(doc, out _, out var errors));
        Assert.NotEmpty(errors);
    }

    [Fact]
    public void TryRead_extraKey_failsClosed()
    {
        var doc = TomlConfigDocument.Parse(
            "[anonymized_dns]\nroutes = [ { server_name = 'x', via = ['r'], note = 'hi' } ]\n");
        Assert.False(AnonymizedDnsRoutes.TryRead(doc, out _, out var errors));
        Assert.Contains(errors, e => e.Contains("note"));
    }

    [Fact]
    public void CanWrite_cleanInlineDoc_isTrue()
    {
        var doc = TomlConfigDocument.Parse("[anonymized_dns]\nroutes = [ { server_name = 'x', via = ['r'] } ]\n");
        Assert.True(AnonymizedDnsRoutes.CanWrite(doc, out var reason));
        Assert.Null(reason);
    }

    [Fact]
    public void CanWrite_doubleBracketForm_isFalse_withRawEditorReason()
    {
        var doc = TomlConfigDocument.Parse("[[anonymized_dns.routes]]\nserver_name = 'x'\nvia = ['r']\n");
        Assert.False(AnonymizedDnsRoutes.CanWrite(doc, out var reason));
        Assert.Contains("raw editor", reason);
    }

    [Fact]
    public void CanWrite_extraKeyElement_isFalse()
    {
        var doc = TomlConfigDocument.Parse("[anonymized_dns]\nroutes = [ { server_name = 'x', via = ['r'], note = 1 } ]\n");
        Assert.False(AnonymizedDnsRoutes.CanWrite(doc, out _));
    }

    [Fact]
    public void Write_thenRead_roundTrips()
    {
        var doc = TomlConfigDocument.Parse("[anonymized_dns]\nskip_incompatible = true\n");

        AnonymizedDnsRoutes.Write(doc, new[]
        {
            new AnonRoute("cloudflare", new[] { "anon-cs-fr" }),
            new AnonRoute("*", new[] { "*" }),
        });

        Assert.True(AnonymizedDnsRoutes.TryRead(doc, out var routes, out _));
        Assert.Equal(2, routes.Count);
        Assert.Equal("cloudflare", routes[0].ServerName);
        Assert.Equal("*", routes[1].ServerName);
        Assert.False(TomlConfigDocument.Parse(doc.ToText()).HasErrors);
    }

    [Fact]
    public void Write_emptyList_clearsRoutes()
    {
        var doc = TomlConfigDocument.Parse("[anonymized_dns]\nroutes = [ { server_name = 'x', via = ['r'] } ]\n");
        AnonymizedDnsRoutes.Write(doc, Array.Empty<AnonRoute>());
        Assert.True(AnonymizedDnsRoutes.TryRead(doc, out var routes, out _));
        Assert.Empty(routes);
    }

    [Fact]
    public void Write_viaSdnsRelayStamp_isAccepted()
    {
        var doc = TomlConfigDocument.Parse("[anonymized_dns]\nskip_incompatible = true\n");
        // a real relay stamp in via[]
        AnonymizedDnsRoutes.Write(doc, new[]
        {
            new AnonRoute("cloudflare", new[] { "sdns://gQ8xNDYuNzAuODIuMzo0NDM" }),
        });
        Assert.False(TomlConfigDocument.Parse(doc.ToText()).HasErrors);
    }

    [Fact]
    public void Write_invalidServerName_throws()
    {
        var doc = TomlConfigDocument.Parse("[anonymized_dns]\nskip_incompatible = true\n");
        Assert.Throws<ArgumentException>(() =>
            AnonymizedDnsRoutes.Write(doc, new[] { new AnonRoute("bad name\"", new[] { "r" }) }));
    }

    [Fact]
    public void Write_viaNonRelayStamp_throws()
    {
        var doc = TomlConfigDocument.Parse("[anonymized_dns]\nskip_incompatible = true\n");
        // a DoH (server) stamp is not a valid relay via entry
        Assert.Throws<ArgumentException>(() =>
            AnonymizedDnsRoutes.Write(doc, new[]
            {
                new AnonRoute("x", new[] { "sdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5" }),
            }));
    }

    [Fact]
    public void Write_onDoubleBracketForm_throws()
    {
        var doc = TomlConfigDocument.Parse("[[anonymized_dns.routes]]\nserver_name = 'x'\nvia = ['r']\n");
        Assert.Throws<InvalidOperationException>(() =>
            AnonymizedDnsRoutes.Write(doc, new[] { new AnonRoute("y", new[] { "r" }) }));
    }
}
