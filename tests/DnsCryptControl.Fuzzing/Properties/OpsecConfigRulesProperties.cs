using CsCheck;
using DnsCryptControl.Core.Toml;
using DnsCryptControl.Core.Validation;

namespace DnsCryptControl.Fuzzing.Properties;

/// <summary>
/// Fuzz properties for the OPSEC kill-switch gate (<see cref="OpsecConfigRules.Evaluate"/>) - THE single
/// source of the config rules the Service kill-switch enable gate, the helper write policy, and the UI
/// editor all share. Two invariants matter most: (1) TOTALITY + FAIL-CLOSED - Evaluate never throws, and
/// an unparseable config yields exactly one KillSwitchCritical concern (an unparseable config can hide any
/// violation); (2) the LOOPBACK-EXEMPTION BOUNDARY - a remote port-53 bootstrap must always trip
/// KillSwitchCritical, while a loopback port-53 bootstrap (the sanctioned kill-switch-safe ODoH bootstrap)
/// must never be flagged. A regression that narrowed the exemption to a literal 127.0.0.1 (breaking
/// 127.0.0.53) or widened it past 127.0.0.0/8 (leaking a remote :53) is caught here.
/// See the fuzzing design notes.
/// </summary>
public class OpsecConfigRulesProperties
{
    [Fact]
    [Trait("Category", "Fuzz")]
    public void Evaluate_never_throws_and_fails_closed_on_unparseable_config() =>
        Gen.String.Sample(EvaluateTotality, iter: Fuzz.Iter);

    /// <summary>Totality oracle: Evaluate never throws for any config text. Fail-closed oracle: when the
    /// TOML does not parse, the result is exactly one KillSwitchCritical UnparseableConfig concern.</summary>
    private static bool EvaluateTotality(string tomlText)
    {
        var doc = TomlConfigDocument.Parse(tomlText);
        var concerns = OpsecConfigRules.Evaluate(doc);
        if (!doc.HasErrors)
            return true; // parseable: only the never-throw half is asserted here (rule content is below)
        return concerns.Count == 1
            && concerns[0].RuleId == OpsecConfigRules.UnparseableConfigRuleId
            && concerns[0].Severity == OpsecConcernSeverity.KillSwitchCritical;
    }

    [Fact]
    [Trait("Category", "Fuzz")]
    public void Bootstrap_port53_flags_remote_and_exempts_loopback_across_the_ipv4_space() =>
        Ipv4HostGen.Sample(hp =>
        {
            // Single-quoted TOML literal string; a dotted-quad host contains only digits/dots so it can
            // never break the parse (the HasErrors guard catches any surprise from the generator).
            var doc = TomlConfigDocument.Parse($"bootstrap_resolvers = ['{hp.Host}:53']\n");
            if (doc.HasErrors) return false;
            var flagged = HasBootstrap53Concern(doc);
            // The security boundary: loopback (127.0.0.0/8) is exempt; every other address must be flagged.
            return flagged == !hp.IsLoopback;
        }, iter: Fuzz.Iter);

    [Theory]
    [InlineData("[::1]", false)]        // IPv6 loopback -> exempt (the sanctioned bootstrap)
    [InlineData("[fe80::1]", true)]     // link-local, remote -> flagged
    [InlineData("[2001:4860:4860::8888]", true)] // public IPv6 -> flagged
    [InlineData("9.9.9.9", true)]       // public IPv4 -> flagged
    [InlineData("192.168.1.1", true)]   // private LAN, still remote to loopback -> flagged (KS would strand it)
    [InlineData("127.0.0.53", false)]   // 127/8 but not .1 -> still loopback, exempt (regression anchor)
    [InlineData("127.255.255.254", false)] // top of 127/8 -> exempt
    public void Bootstrap_port53_boundary_examples(string host, bool shouldFlag)
    {
        var doc = TomlConfigDocument.Parse($"bootstrap_resolvers = ['{host}:53']\n");
        Assert.False(doc.HasErrors);
        Assert.Equal(shouldFlag, HasBootstrap53Concern(doc));
    }

    private static bool HasBootstrap53Concern(TomlConfigDocument doc) =>
        OpsecConfigRules.Evaluate(doc).Any(c => c.RuleId == OpsecConfigRules.BootstrapResolverOn53RuleId);

    /// <summary>Random dotted-quad IPv4 host paired with its ground-truth loopback classification
    /// (127.0.0.0/8, matching <see cref="System.Net.IPAddress.IsLoopback"/>). Fuzzes the full address
    /// space so the exemption boundary is exercised on both sides, not just the 127.0.0.1 literal.</summary>
    private static readonly Gen<(string Host, bool IsLoopback)> Ipv4HostGen =
        Gen.Select(Gen.Int[0, 255], Gen.Int[0, 255], Gen.Int[0, 255], Gen.Int[0, 255],
            (a, b, c, d) => ($"{a}.{b}.{c}.{d}", a == 127));
}
