using System.IO;
using System.Text;
using CsCheck;
using DnsCryptControl.Core.Security;

namespace DnsCryptControl.Fuzzing.Properties;

/// <summary>
/// Fuzz + regression properties for <see cref="JsonStateReadGuard"/> - the fix for the unguarded JSON
/// state-store finding (2026-07-08): protection.json / ui-state.json / backup.json / installed-binary.json
/// were read with File.ReadAllText + the default MaxDepth 64 and NO size cap, so a ballooned/amplified or
/// deeply-nested state file could OOM the process or be accepted deeper than the IPC-hardened cap - and
/// ProtectionStateStore is the FAIL-CLOSED AUTHORITY the config write policy + BootReconciler depend on.
/// Oracles: IsWellFormedWithinDepth never throws and rejects anything nested past the cap; IsOversized
/// flags a file past the byte cap without reading it. See the fuzzing design notes.
/// </summary>
public class JsonStateReadGuardProperties
{
    [Fact]
    [Trait("Category", "Fuzz")]
    public void IsWellFormedWithinDepth_never_throws_and_is_deterministic() =>
        Gen.String.Sample(s =>
        {
            // The totality oracle: a throw would fail the property. Also asserts determinism.
            var a = JsonStateReadGuard.IsWellFormedWithinDepth(s);
            var b = JsonStateReadGuard.IsWellFormedWithinDepth(s);
            return a == b;
        }, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void IsWellFormedWithinDepth_rejects_nesting_past_the_cap() =>
        Gen.Int[0, 40].Sample(d =>
            // d nested objects reach JSON depth d; the guard accepts IFF d is within MaxStateDepth.
            JsonStateReadGuard.IsWellFormedWithinDepth(Nest(d)) == (d <= JsonStateReadGuard.MaxStateDepth),
            iter: Fuzz.Iter);

    [Theory]
    [InlineData("{\"protectionEnabled\":true,\"killSwitchEnabled\":false}", true)] // real flat state record
    [InlineData("[1,2,3]", true)]      // shallow array
    [InlineData("", false)]            // empty
    [InlineData("   ", false)]         // whitespace only (not well-formed)
    [InlineData("{", false)]           // truncated
    [InlineData("{\"a\":}", false)]    // malformed value
    public void IsWellFormedWithinDepth_examples(string json, bool expected) =>
        Assert.Equal(expected, JsonStateReadGuard.IsWellFormedWithinDepth(json));

    [Fact]
    public void IsOversized_flags_a_file_past_the_cap_without_reading_it()
    {
        // A sparse file sized just past the cap reproduces the OOM shape instantly, without writing GBs.
        var path = Path.GetTempFileName();
        try
        {
            using (var fs = File.Create(path))
            {
                fs.SetLength(JsonStateReadGuard.MaxStateBytes + 1);
            }

            Assert.True(JsonStateReadGuard.IsOversized(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void IsOversized_allows_a_file_at_the_cap_and_reports_absent_as_not_oversized()
    {
        Assert.False(JsonStateReadGuard.IsOversized(
            Path.Combine(Path.GetTempPath(), "dnscrypt-state-guard-absent.json")));

        var path = Path.GetTempFileName();
        try
        {
            using (var fs = File.Create(path))
            {
                fs.SetLength(JsonStateReadGuard.MaxStateBytes); // exactly at the cap is allowed (strictly-greater rejects)
            }

            Assert.False(JsonStateReadGuard.IsOversized(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>A JSON string of <paramref name="depth"/> nested objects (<c>{"a":{"a":...0...}}</c>),
    /// reaching reader depth <paramref name="depth"/>.</summary>
    private static string Nest(int depth)
    {
        var sb = new StringBuilder(depth * 6 + 2);
        for (var i = 0; i < depth; i++)
        {
            sb.Append("{\"a\":");
        }

        sb.Append('0');
        for (var i = 0; i < depth; i++)
        {
            sb.Append('}');
        }

        return sb.ToString();
    }
}
