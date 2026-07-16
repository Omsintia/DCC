using System.Text;
using CsCheck;
using DnsCryptControl.Core.Toml;

namespace DnsCryptControl.Fuzzing.Properties;

/// <summary>
/// Fuzz properties for the TOML document boundary (<see cref="TomlConfigDocument"/>) - the semi-trusted
/// config the whole app reads and rewrites. The headline invariant is ENCODING STABILITY: a parse ->
/// serialize round-trip is a byte-exact FIXED POINT that never grows, and non-ASCII content survives it
/// intact. That is the app-side guard against the encoding-amplification class that ballooned a config to
/// 2.26 GB (a single em-dash re-encoded ~2.7x per external round-trip; fixed in master 0a5a15a). Also
/// pins lossless round-trip of real configs. Parse totality itself is asserted via the OPSEC gate
/// property (found + fixed a Tomlyn throw). See the fuzzing design notes.
/// </summary>
public class TomlConfigDocumentProperties
{
    [Fact]
    [Trait("Category", "Fuzz")]
    public void Roundtrip_is_a_byte_stable_fixed_point_with_no_encoding_amplification() =>
        UnicodeishGen.Sample(s =>
        {
            // A single-quoted TOML literal string (no escape processing); the generator excludes the
            // single-quote and newlines that would break the literal, so this always forms valid TOML.
            var d1 = TomlConfigDocument.Parse($"name = '{s}'\n");
            if (d1.HasErrors) return true; // out of scope: a value that doesn't form valid TOML
            var t1 = d1.ToText();
            var t2 = TomlConfigDocument.Parse(t1).ToText();
            // Anti-amplification: re-serializing a serialized doc is a byte-exact fixed point (the 2.26 GB
            // class was unbounded growth PER round-trip). UTF-8 byte length must not grow either.
            var fixedPoint = string.Equals(t1, t2, StringComparison.Ordinal)
                && Encoding.UTF8.GetByteCount(t2) == Encoding.UTF8.GetByteCount(t1);
            // And the value survives the round-trip intact (no mojibake / re-encoding).
            var valuePreserved = d1.TryGetString("name", out var v) && string.Equals(v, s, StringComparison.Ordinal);
            return fixedPoint && valuePreserved;
        }, iter: Fuzz.Iter);

    [Theory]
    [InlineData("listen_addresses = ['127.0.0.1:53']\nmax_clients = 250\n")]
    [InlineData("# heading\nignore_system_dns = true\n\n[query_log]\nformat = 'tsv'\n")]
    [InlineData("server_names = ['cloudflare', 'quad9-dnscrypt-ip4-nofilter-pri']\n")]
    public void Roundtrip_preserves_a_valid_config_byte_for_byte(string toml)
    {
        var doc = TomlConfigDocument.Parse(toml);
        Assert.False(doc.HasErrors);
        Assert.Equal(toml, doc.ToText());
    }

    /// <summary>Unicode-heavy but TOML-literal-safe values (no single-quote / newline), foregrounding the
    /// exact hostile classes behind the amplification bug: em-dash (U+2014), accents, CJK, and emoji
    /// (surrogate pairs). Mixed with random alphanumerics for breadth.</summary>
    private static readonly Gen<string> UnicodeishGen = Gen.OneOf(
        Gen.Const("—"),                       // em-dash - the 2.26 GB seed
        Gen.Const("———"),
        Gen.Const("café naïve"),         // Latin-1 accents
        Gen.Const("日本語"),           // CJK
        Gen.Const("\U0001F600\U0001F510\U0001F4A1"), // emoji (surrogate pairs)
        Gen.Const("﻿"),                        // BOM as content
        Gen.String[Gen.Char.AlphaNumeric, 0, 24]);
}
