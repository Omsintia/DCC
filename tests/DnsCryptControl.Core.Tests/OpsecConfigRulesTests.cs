using DnsCryptControl.Core.Toml;
using DnsCryptControl.Core.Validation;
using Xunit;

namespace DnsCryptControl.Core.Tests;

/// <summary>
/// A3: <see cref="OpsecConfigRules"/> is the ONE place the OPSEC key rules live (IC-4).
/// Consumers (the Service kill-switch guard, the helper write policy, the UI warnings)
/// all delegate here, so rule-by-rule coverage lives here too: violating, satisfied,
/// absent-key, and malformed-value cases per rule.
/// </summary>
public class OpsecConfigRulesTests
{
    private static IReadOnlyList<OpsecConcern> Evaluate(string toml)
        => OpsecConfigRules.Evaluate(TomlConfigDocument.Parse(toml));

    // A fully OPSEC-clean config: every rule satisfied (listen_addresses/netprobe_address
    // absent = safe; bootstrap entries off :53).
    private const string SafeToml =
        "netprobe_timeout = 0\n" +
        "ignore_system_dns = true\n" +
        "bootstrap_resolvers = ['9.9.9.9:443', '1.1.1.1:443']\n";

    // ---------------------------------------------------------------- shape + fail-closed

    [Fact]
    public void Evaluate_nullDoc_throws()
    {
        Assert.Throws<ArgumentNullException>(() => OpsecConfigRules.Evaluate(null!));
    }

    [Fact]
    public void Evaluate_safeConfig_returnsNoConcerns()
    {
        Assert.Empty(Evaluate(SafeToml));
    }

    [Fact]
    public void Evaluate_unparseableDoc_returnsSingleKillSwitchCriticalConcern_failClosed()
    {
        var concerns = Evaluate("[[[ not valid toml ]]]]");

        var concern = Assert.Single(concerns);
        Assert.Equal(OpsecConfigRules.UnparseableConfigRuleId, concern.RuleId);
        Assert.Equal(OpsecConcernSeverity.KillSwitchCritical, concern.Severity);
        Assert.Contains("parse", concern.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ---------------------------------------------------------------- NetprobeTimeoutNotZero

    [Fact]
    public void NetprobeTimeout_nonZero_isKillSwitchCritical()
    {
        var concerns = Evaluate("netprobe_timeout = 60\nignore_system_dns = true\n");

        var concern = Assert.Single(concerns, c => c.RuleId == OpsecConfigRules.NetprobeTimeoutNotZeroRuleId);
        Assert.Equal(OpsecConcernSeverity.KillSwitchCritical, concern.Severity);
        Assert.Equal("netprobe_timeout", concern.KeyPath);
        Assert.Contains("netprobe_timeout", concern.Message, StringComparison.Ordinal);
        Assert.Contains("60", concern.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void NetprobeTimeout_missing_isKillSwitchCritical()
    {
        // dnscrypt-proxy's default is 60 — a missing key re-enables the cleartext probe.
        var concerns = Evaluate("ignore_system_dns = true\n");

        var concern = Assert.Single(concerns, c => c.RuleId == OpsecConfigRules.NetprobeTimeoutNotZeroRuleId);
        Assert.Equal(OpsecConcernSeverity.KillSwitchCritical, concern.Severity);
    }

    [Fact]
    public void NetprobeTimeout_malformed_nonInteger_isKillSwitchCritical()
    {
        // A string '0' is not the integer 0 — fail closed on the unreadable value.
        var concerns = Evaluate("netprobe_timeout = '0'\nignore_system_dns = true\n");

        Assert.Single(concerns, c => c.RuleId == OpsecConfigRules.NetprobeTimeoutNotZeroRuleId);
    }

    [Fact]
    public void NetprobeTimeout_zero_isSatisfied()
    {
        var concerns = Evaluate("netprobe_timeout = 0\n");

        Assert.DoesNotContain(concerns, c => c.RuleId == OpsecConfigRules.NetprobeTimeoutNotZeroRuleId);
    }

    // ---------------------------------------------------------------- IgnoreSystemDnsOff

    [Fact]
    public void IgnoreSystemDns_false_isKillSwitchCritical()
    {
        var concerns = Evaluate("netprobe_timeout = 0\nignore_system_dns = false\n");

        var concern = Assert.Single(concerns, c => c.RuleId == OpsecConfigRules.IgnoreSystemDnsOffRuleId);
        Assert.Equal(OpsecConcernSeverity.KillSwitchCritical, concern.Severity);
        Assert.Equal("ignore_system_dns", concern.KeyPath);
        Assert.Contains("ignore_system_dns", concern.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void IgnoreSystemDns_missing_isKillSwitchCritical()
    {
        // dnscrypt-proxy's default is false — a missing key allows cleartext system-DNS fallback.
        var concerns = Evaluate("netprobe_timeout = 0\n");

        var concern = Assert.Single(concerns, c => c.RuleId == OpsecConfigRules.IgnoreSystemDnsOffRuleId);
        Assert.Equal(OpsecConcernSeverity.KillSwitchCritical, concern.Severity);
    }

    [Fact]
    public void IgnoreSystemDns_malformed_nonBool_isKillSwitchCritical()
    {
        // An integer 1 is not the boolean true — fail closed on the unreadable value.
        var concerns = Evaluate("netprobe_timeout = 0\nignore_system_dns = 1\n");

        Assert.Single(concerns, c => c.RuleId == OpsecConfigRules.IgnoreSystemDnsOffRuleId);
    }

    [Fact]
    public void IgnoreSystemDns_true_isSatisfied()
    {
        var concerns = Evaluate("ignore_system_dns = true\n");

        Assert.DoesNotContain(concerns, c => c.RuleId == OpsecConfigRules.IgnoreSystemDnsOffRuleId);
    }

    // ---------------------------------------------------------------- BootstrapResolverOn53

    [Fact]
    public void BootstrapResolvers_entryOnPort53_isKillSwitchCritical()
    {
        var concerns = Evaluate(SafeToml.Replace(
            "bootstrap_resolvers = ['9.9.9.9:443', '1.1.1.1:443']",
            "bootstrap_resolvers = ['9.9.9.11:53']", StringComparison.Ordinal));

        var concern = Assert.Single(concerns, c => c.RuleId == OpsecConfigRules.BootstrapResolverOn53RuleId);
        Assert.Equal(OpsecConcernSeverity.KillSwitchCritical, concern.Severity);
        Assert.Equal("bootstrap_resolvers", concern.KeyPath);
        Assert.Contains("9.9.9.11:53", concern.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void BootstrapResolvers_mixedList_flagsEveryPort53Entry()
    {
        // Even one entry ending :53 violates; every violating entry gets its own concern
        // so the UI panel can list them all.
        var concerns = Evaluate(SafeToml.Replace(
            "bootstrap_resolvers = ['9.9.9.9:443', '1.1.1.1:443']",
            "bootstrap_resolvers = ['9.9.9.9:443', '1.1.1.1:53', '8.8.8.8:53']", StringComparison.Ordinal));

        var flagged = concerns.Where(c => c.RuleId == OpsecConfigRules.BootstrapResolverOn53RuleId).ToList();
        Assert.Equal(2, flagged.Count);
        Assert.All(flagged, c => Assert.Equal(OpsecConcernSeverity.KillSwitchCritical, c.Severity));
    }

    [Fact]
    public void BootstrapResolvers_allOff53_isSatisfied()
    {
        Assert.Empty(Evaluate(SafeToml));
    }

    [Fact]
    public void BootstrapResolvers_absent_isSafe()
    {
        var concerns = Evaluate("netprobe_timeout = 0\nignore_system_dns = true\n");

        Assert.DoesNotContain(concerns, c => c.RuleId == OpsecConfigRules.BootstrapResolverOn53RuleId);
    }

    [Fact]
    public void BootstrapResolvers_malformed_wrongType_isKillSwitchCritical_deliberateTightening()
    {
        // DELIBERATE TIGHTENING (A3): the pre-5b guard silently SKIPPED a present-but-
        // unreadable bootstrap_resolvers (TryGetStringArray false -> check passed). An
        // unreadable value can hide a plaintext :53 bootstrap — it now fails CLOSED.
        var concerns = Evaluate(SafeToml.Replace(
            "bootstrap_resolvers = ['9.9.9.9:443', '1.1.1.1:443']",
            "bootstrap_resolvers = 'not-an-array'", StringComparison.Ordinal));

        var concern = Assert.Single(concerns, c => c.RuleId == OpsecConfigRules.BootstrapResolverOn53RuleId);
        Assert.Equal(OpsecConcernSeverity.KillSwitchCritical, concern.Severity);
        Assert.Contains("malformed", concern.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BootstrapResolvers_malformed_mixedElements_isKillSwitchCritical_deliberateTightening()
    {
        var concerns = Evaluate(SafeToml.Replace(
            "bootstrap_resolvers = ['9.9.9.9:443', '1.1.1.1:443']",
            "bootstrap_resolvers = ['9.9.9.9:443', 42]", StringComparison.Ordinal));

        var concern = Assert.Single(concerns, c => c.RuleId == OpsecConfigRules.BootstrapResolverOn53RuleId);
        Assert.Equal(OpsecConcernSeverity.KillSwitchCritical, concern.Severity);
        Assert.Contains("malformed", concern.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BootstrapResolvers_loopbackIpv4On53_isExempt()
    {
        // The kill-switch-safe ODoH bootstrap: 127.0.0.1:53 is the proxy's OWN loopback listener — Windows
        // Firewall exempts loopback and the proxy re-encrypts upstream, so this is NOT a plaintext leak.
        var concerns = Evaluate(SafeToml.Replace(
            "bootstrap_resolvers = ['9.9.9.9:443', '1.1.1.1:443']",
            "bootstrap_resolvers = ['127.0.0.1:53']", StringComparison.Ordinal));

        Assert.DoesNotContain(concerns, c => c.RuleId == OpsecConfigRules.BootstrapResolverOn53RuleId);
    }

    [Fact]
    public void BootstrapResolvers_loopbackIpv6On53_isExempt()
    {
        var concerns = Evaluate(SafeToml.Replace(
            "bootstrap_resolvers = ['9.9.9.9:443', '1.1.1.1:443']",
            "bootstrap_resolvers = ['[::1]:53']", StringComparison.Ordinal));

        Assert.DoesNotContain(concerns, c => c.RuleId == OpsecConfigRules.BootstrapResolverOn53RuleId);
    }

    [Fact]
    public void BootstrapResolvers_loopbackOn53_wholeConfigIsOpsecClean()
    {
        // The EXACT config the ODoH-behind-kill-switch feature writes must raise ZERO concerns, so the
        // kill-switch enable gate (which rejects on the first KillSwitchCritical) still arms.
        var concerns = Evaluate(SafeToml.Replace(
            "bootstrap_resolvers = ['9.9.9.9:443', '1.1.1.1:443']",
            "bootstrap_resolvers = ['127.0.0.1:53']", StringComparison.Ordinal));

        Assert.Empty(concerns);
    }

    [Fact]
    public void BootstrapResolvers_remoteOn53_stillFlagged_evenBesideLoopback()
    {
        // SECURITY: the loopback exemption must NOT let a real REMOTE :53 leak ride along. A loopback entry
        // sitting next to a remote :53 entry flags ONLY the remote one — the leak still fails the gate.
        var concerns = Evaluate(SafeToml.Replace(
            "bootstrap_resolvers = ['9.9.9.9:443', '1.1.1.1:443']",
            "bootstrap_resolvers = ['127.0.0.1:53', '9.9.9.9:53']", StringComparison.Ordinal));

        var concern = Assert.Single(concerns, c => c.RuleId == OpsecConfigRules.BootstrapResolverOn53RuleId);
        Assert.Equal(OpsecConcernSeverity.KillSwitchCritical, concern.Severity);
        Assert.Contains("9.9.9.9:53", concern.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("127.0.0.1:53", concern.Message, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- ListenAddressesOffLoopback53

    [Fact]
    public void ListenAddresses_presentWithoutLoopback53_isProtectionCritical()
    {
        // Protection re-points system DNS at 127.0.0.1:53 — a proxy not listening there
        // breaks resolution while protected, but does not affect the kill switch itself.
        var concerns = Evaluate(SafeToml + "listen_addresses = ['0.0.0.0:5353']\n");

        var concern = Assert.Single(concerns, c => c.RuleId == OpsecConfigRules.ListenAddressesOffLoopback53RuleId);
        Assert.Equal(OpsecConcernSeverity.ProtectionCritical, concern.Severity);
        Assert.Equal("listen_addresses", concern.KeyPath);
        Assert.Contains("127.0.0.1:53", concern.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ListenAddresses_containingLoopback53_isSatisfied()
    {
        var concerns = Evaluate(SafeToml + "listen_addresses = ['127.0.0.1:53', '[::1]:53']\n");

        Assert.DoesNotContain(concerns, c => c.RuleId == OpsecConfigRules.ListenAddressesOffLoopback53RuleId);
    }

    [Fact]
    public void ListenAddresses_absent_isSafe()
    {
        // dnscrypt-proxy's built-in default is ['127.0.0.1:53'] — absent key is safe.
        Assert.Empty(Evaluate(SafeToml));
    }

    [Fact]
    public void ListenAddresses_malformed_isProtectionCritical()
    {
        var concerns = Evaluate(SafeToml + "listen_addresses = 'oops'\n");

        var concern = Assert.Single(concerns, c => c.RuleId == OpsecConfigRules.ListenAddressesOffLoopback53RuleId);
        Assert.Equal(OpsecConcernSeverity.ProtectionCritical, concern.Severity);
        Assert.Contains("malformed", concern.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ---------------------------------------------------------------- NetprobeAddressOn53

    [Fact]
    public void NetprobeAddress_onPort53_isAdvisory()
    {
        var concerns = Evaluate(SafeToml + "netprobe_address = '9.9.9.9:53'\n");

        var concern = Assert.Single(concerns, c => c.RuleId == OpsecConfigRules.NetprobeAddressOn53RuleId);
        Assert.Equal(OpsecConcernSeverity.Advisory, concern.Severity);
        Assert.Equal("netprobe_address", concern.KeyPath);
        Assert.Contains("9.9.9.9:53", concern.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void NetprobeAddress_off53_isSatisfied()
    {
        var concerns = Evaluate(SafeToml + "netprobe_address = '9.9.9.9:9'\n");

        Assert.DoesNotContain(concerns, c => c.RuleId == OpsecConfigRules.NetprobeAddressOn53RuleId);
    }

    [Fact]
    public void NetprobeAddress_loopbackOn53_isExempt()
    {
        // Loopback :53 never leaves the machine even if the probe re-enables — not a leak landmine.
        var concerns = Evaluate(SafeToml + "netprobe_address = '127.0.0.1:53'\n");

        Assert.DoesNotContain(concerns, c => c.RuleId == OpsecConfigRules.NetprobeAddressOn53RuleId);
    }

    [Fact]
    public void NetprobeAddress_absent_isSafe()
    {
        Assert.Empty(Evaluate(SafeToml));
    }

    [Fact]
    public void NetprobeAddress_malformed_nonString_yieldsNoAdvisory_schemaValidatorOwnsTypeErrors()
    {
        // Documented disposition: a non-string netprobe_address cannot end in :53; the
        // wrong TYPE is a schema Error (ConfigValidator flags known-key type mismatches),
        // so this Advisory-only rule stays silent rather than duplicating it. The probe
        // is disabled anyway whenever NetprobeTimeoutNotZero is satisfied.
        var concerns = Evaluate(SafeToml + "netprobe_address = 53\n");

        Assert.DoesNotContain(concerns, c => c.RuleId == OpsecConfigRules.NetprobeAddressOn53RuleId);
    }

    // ---------------------------------------------------------------- severity split sanity

    [Fact]
    public void Evaluate_collectsConcernsAcrossRules_withDistinctSeverities()
    {
        // One config violating a KillSwitchCritical, a ProtectionCritical, and an Advisory
        // rule at once: Evaluate returns ALL of them (consumers filter by severity).
        var toml =
            "netprobe_timeout = 60\n" +          // KillSwitchCritical
            "ignore_system_dns = true\n" +
            "listen_addresses = ['0.0.0.0:5353']\n" + // ProtectionCritical
            "netprobe_address = '9.9.9.9:53'\n";      // Advisory

        var concerns = Evaluate(toml);

        Assert.Contains(concerns, c => c.Severity == OpsecConcernSeverity.KillSwitchCritical);
        Assert.Contains(concerns, c => c.Severity == OpsecConcernSeverity.ProtectionCritical);
        Assert.Contains(concerns, c => c.Severity == OpsecConcernSeverity.Advisory);
        Assert.Equal(3, concerns.Count);
    }
}
