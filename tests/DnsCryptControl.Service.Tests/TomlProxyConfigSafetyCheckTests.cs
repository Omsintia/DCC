using System.IO;
using DnsCryptControl.Service;
using DnsCryptControl.Service.Windows;
using Xunit;

namespace DnsCryptControl.Service.Tests;

/// <summary>
/// IC-4 MEANINGFUL guard tests: verify that TomlProxyConfigSafetyCheck accepts configs carrying
/// the opsec defaults and rejects configs with unsafe values.
/// These tests are NOT tautological — they parse real TOML content and check the guard logic,
/// not the constants against themselves.
/// </summary>
public class TomlProxyConfigSafetyCheckTests
{
    // Helper: write TOML to a temp file and build a ProtectedPaths pointing to it.
    private static (ProtectedPaths paths, string tempFile) WriteTempConfig(string toml)
    {
        var dir = Path.Combine(Path.GetTempPath(), "D2Test_" + System.Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, "dnscrypt-proxy.toml");
        File.WriteAllText(file, toml);
        return (new ProtectedPaths(dir), file);
    }

    // ---------------------------------------------------------------------------
    // SAFE configs — should pass the guard
    // ---------------------------------------------------------------------------

    [Fact]
    public void Safe_whenNetprobeTimeoutZero_ignoreSysDnsTrue_noBootstrap53()
    {
        var (paths, _) = WriteTempConfig(@"
netprobe_timeout = 0
ignore_system_dns = true
bootstrap_resolvers = ['9.9.9.9:443', '1.1.1.1:443']
");
        var check = new TomlProxyConfigSafetyCheck(paths);
        var (safe, reason) = check.IsSafeUnderPort53Block();
        Assert.True(safe, $"expected safe but got reason: {reason}");
        Assert.Null(reason);
    }

    [Fact]
    public void Safe_whenBootstrapResolversAbsent_andOtherSettingsCorrect()
    {
        // No bootstrap_resolvers key at all — that is safe (no port-53 entries).
        var (paths, _) = WriteTempConfig(@"
netprobe_timeout = 0
ignore_system_dns = true
");
        var check = new TomlProxyConfigSafetyCheck(paths);
        var (safe, reason) = check.IsSafeUnderPort53Block();
        Assert.True(safe, $"expected safe but got reason: {reason}");
    }

    [Fact]
    public void Safe_whenBootstrapResolverIsLoopbackPort53()
    {
        // The kill-switch-safe ODoH bootstrap: 127.0.0.1:53 is loopback (firewall-exempt, re-encrypted
        // upstream) — the enable gate must ACCEPT it so ODoH can bootstrap behind the ARMED kill switch.
        var (paths, _) = WriteTempConfig(@"
netprobe_timeout = 0
ignore_system_dns = true
bootstrap_resolvers = ['127.0.0.1:53']
");
        var check = new TomlProxyConfigSafetyCheck(paths);
        var (safe, reason) = check.IsSafeUnderPort53Block();
        Assert.True(safe, $"expected safe but got reason: {reason}");
        Assert.Null(reason);
    }

    [Fact]
    public void Safe_whenBootstrapResolverIsLoopbackIpv6Port53()
    {
        var (paths, _) = WriteTempConfig(@"
netprobe_timeout = 0
ignore_system_dns = true
bootstrap_resolvers = ['[::1]:53']
");
        var check = new TomlProxyConfigSafetyCheck(paths);
        var (safe, reason) = check.IsSafeUnderPort53Block();
        Assert.True(safe, $"expected safe but got reason: {reason}");
    }

    [Fact]
    public void Unsafe_whenLoopbackBesideRemotePort53_remoteStillRejected()
    {
        // SECURITY: the loopback exemption must not let a REAL remote :53 ride along.
        var (paths, _) = WriteTempConfig(@"
netprobe_timeout = 0
ignore_system_dns = true
bootstrap_resolvers = ['127.0.0.1:53', '9.9.9.9:53']
");
        var check = new TomlProxyConfigSafetyCheck(paths);
        var (safe, reason) = check.IsSafeUnderPort53Block();
        Assert.False(safe);
        Assert.NotNull(reason);
        Assert.Contains("9.9.9.9:53", reason);
    }

    // ---------------------------------------------------------------------------
    // UNSAFE configs — should be REJECTED by the guard (IC-4)
    // ---------------------------------------------------------------------------

    [Fact]
    public void Unsafe_whenNetprobeTimeoutIs60()
    {
        var (paths, _) = WriteTempConfig(@"
netprobe_timeout = 60
ignore_system_dns = true
");
        var check = new TomlProxyConfigSafetyCheck(paths);
        var (safe, reason) = check.IsSafeUnderPort53Block();
        Assert.False(safe);
        Assert.NotNull(reason);
        Assert.Contains("netprobe_timeout", reason);
    }

    [Fact]
    public void Unsafe_whenIgnoreSystemDnsIsFalse()
    {
        var (paths, _) = WriteTempConfig(@"
netprobe_timeout = 0
ignore_system_dns = false
");
        var check = new TomlProxyConfigSafetyCheck(paths);
        var (safe, reason) = check.IsSafeUnderPort53Block();
        Assert.False(safe);
        Assert.NotNull(reason);
        Assert.Contains("ignore_system_dns", reason);
    }

    [Fact]
    public void Unsafe_whenBootstrapResolverTargetsPort53()
    {
        var (paths, _) = WriteTempConfig(@"
netprobe_timeout = 0
ignore_system_dns = true
bootstrap_resolvers = ['9.9.9.11:53']
");
        var check = new TomlProxyConfigSafetyCheck(paths);
        var (safe, reason) = check.IsSafeUnderPort53Block();
        Assert.False(safe);
        Assert.NotNull(reason);
        Assert.Contains("bootstrap_resolvers", reason);
    }

    [Fact]
    public void Unsafe_whenBootstrapResolversMixedAndOneIsPort53()
    {
        // Mixed list — even one entry ending in :53 must reject.
        var (paths, _) = WriteTempConfig(@"
netprobe_timeout = 0
ignore_system_dns = true
bootstrap_resolvers = ['9.9.9.9:443', '1.1.1.1:53']
");
        var check = new TomlProxyConfigSafetyCheck(paths);
        var (safe, reason) = check.IsSafeUnderPort53Block();
        Assert.False(safe);
        Assert.NotNull(reason);
        Assert.Contains("bootstrap_resolvers", reason);
    }

    [Fact]
    public void Unsafe_whenIgnoreSystemDnsAbsent_treatedAsDefaultFalse()
    {
        // Missing key means default (false for bool) — must be treated as unsafe.
        var (paths, _) = WriteTempConfig(@"
netprobe_timeout = 0
");
        var check = new TomlProxyConfigSafetyCheck(paths);
        var (safe, reason) = check.IsSafeUnderPort53Block();
        Assert.False(safe);
        Assert.NotNull(reason);
        Assert.Contains("ignore_system_dns", reason);
    }

    [Fact]
    public void Unsafe_whenConfigFileMissing_failsClosed()
    {
        // Missing file -> fail-closed: never enable the kill switch over an unknown config.
        var paths = new ProtectedPaths(Path.Combine(Path.GetTempPath(), "D2_nonexistent_" + System.Guid.NewGuid().ToString("N")));
        var check = new TomlProxyConfigSafetyCheck(paths);
        var (safe, reason) = check.IsSafeUnderPort53Block();
        Assert.False(safe);
        Assert.NotNull(reason);
    }

    [Fact]
    public void Unsafe_whenConfigFileUnparseable_failsClosed()
    {
        var (paths, _) = WriteTempConfig("[[[ not valid toml ]]]]");
        var check = new TomlProxyConfigSafetyCheck(paths);
        var (safe, reason) = check.IsSafeUnderPort53Block();
        Assert.False(safe);
        Assert.NotNull(reason);
    }

    [Fact]
    public void Unsafe_whenBootstrapResolversMalformed_wrongType_failsClosed()
    {
        // DELIBERATE TIGHTENING (A3, documented in the phase-5b plan): the pre-5b guard
        // silently SKIPPED a bootstrap_resolvers that is present but not a clean string
        // array (TryGetStringArray false -> check passed). An unreadable value can hide
        // a plaintext :53 bootstrap, so the delegated guard now fails CLOSED.
        var (paths, _) = WriteTempConfig(@"
netprobe_timeout = 0
ignore_system_dns = true
bootstrap_resolvers = 'not-an-array'
");
        var check = new TomlProxyConfigSafetyCheck(paths);
        var (safe, reason) = check.IsSafeUnderPort53Block();
        Assert.False(safe);
        Assert.NotNull(reason);
        Assert.Contains("bootstrap_resolvers", reason);
    }

    [Fact]
    public void Unsafe_whenBootstrapResolversMalformed_mixedElements_failsClosed()
    {
        // Same tightening: a mixed-element array is unreadable as a string array.
        var (paths, _) = WriteTempConfig(@"
netprobe_timeout = 0
ignore_system_dns = true
bootstrap_resolvers = ['9.9.9.9:443', 42]
");
        var check = new TomlProxyConfigSafetyCheck(paths);
        var (safe, reason) = check.IsSafeUnderPort53Block();
        Assert.False(safe);
        Assert.NotNull(reason);
        Assert.Contains("bootstrap_resolvers", reason);
    }

    [Fact]
    public void Safe_whenOnlyProtectionCriticalOrAdvisoryConcernsExist_killSwitchGateUnaffected()
    {
        // The kill-switch enable gate rejects ONLY KillSwitchCritical concerns: a
        // listen_addresses off loopback:53 (ProtectionCritical) and a netprobe_address
        // ending :53 (Advisory, inert while netprobe_timeout = 0) must NOT block enable.
        var (paths, _) = WriteTempConfig(@"
netprobe_timeout = 0
ignore_system_dns = true
bootstrap_resolvers = ['9.9.9.9:443']
listen_addresses = ['0.0.0.0:5353']
netprobe_address = '9.9.9.9:53'
");
        var check = new TomlProxyConfigSafetyCheck(paths);
        var (safe, reason) = check.IsSafeUnderPort53Block();
        Assert.True(safe, $"expected safe but got reason: {reason}");
        Assert.Null(reason);
    }

    // ---------------------------------------------------------------------------
    // IC-4 integration: FirewallKillSwitch refuses to enable with unsafe config
    // ---------------------------------------------------------------------------

    [Fact]
    public void FirewallKillSwitch_enable_withUnsafeTomlConfig_returnsInvalidArgument_noRulesAdded()
    {
        // Use the real TomlProxyConfigSafetyCheck backed by a TOML that has netprobe_timeout=60.
        var (paths, _) = WriteTempConfig(@"
netprobe_timeout = 60
ignore_system_dns = true
");
        var store = new FakeRuleStoreForSafetyTest();
        var backupStore = new DnsCryptControl.Service.State.DnsBackupStore(
            Path.Combine(Path.GetTempPath(), "D2_backup_" + System.Guid.NewGuid().ToString("N") + ".json"));

        var ks = new FirewallKillSwitch(store, backupStore, new TomlProxyConfigSafetyCheck(paths));

        var result = ks.SetKillSwitch(true);

        Assert.False(result.Success);
        Assert.Equal(DnsCryptControl.Platform.PlatformErrorKind.InvalidArgument, result.Error);
        Assert.Empty(store.Rules); // no rules added
    }

    [Fact]
    public void FirewallKillSwitch_enable_withSafeTomlConfig_succeeds_addsThreeRules()
    {
        var (paths, _) = WriteTempConfig(@"
netprobe_timeout = 0
ignore_system_dns = true
bootstrap_resolvers = ['9.9.9.9:443']
");
        var store = new FakeRuleStoreForSafetyTest();
        var backupStore = new DnsCryptControl.Service.State.DnsBackupStore(
            Path.Combine(Path.GetTempPath(), "D2_backup_" + System.Guid.NewGuid().ToString("N") + ".json"));

        var ks = new FirewallKillSwitch(store, backupStore, new TomlProxyConfigSafetyCheck(paths));

        var result = ks.SetKillSwitch(true);

        Assert.True(result.Success);
        Assert.Equal(3, store.Rules.Count);
    }

    [Fact]
    public void FirewallKillSwitch_enable_withLoopbackBootstrap_succeeds_addsThreeRules()
    {
        // The deterministic equivalent of the live VM re-arm: the REAL kill-switch enable path
        // (FirewallKillSwitch.SetKillSwitch -> TomlProxyConfigSafetyCheck) must ACCEPT a loopback bootstrap
        // and apply the 3 BLOCK rules — this is exactly what lets ODoH bootstrap behind the armed kill switch.
        // The OLD guard would have flagged '127.0.0.1:53' as KillSwitchCritical and refused (no rules).
        var (paths, _) = WriteTempConfig(@"
netprobe_timeout = 0
ignore_system_dns = true
bootstrap_resolvers = ['127.0.0.1:53']
");
        var store = new FakeRuleStoreForSafetyTest();
        var backupStore = new DnsCryptControl.Service.State.DnsBackupStore(
            Path.Combine(Path.GetTempPath(), "D2_backup_" + System.Guid.NewGuid().ToString("N") + ".json"));

        var ks = new FirewallKillSwitch(store, backupStore, new TomlProxyConfigSafetyCheck(paths));

        var result = ks.SetKillSwitch(true);

        Assert.True(result.Success, $"expected enable to SUCCEED over a loopback bootstrap; error: {result.Error}");
        Assert.Equal(3, store.Rules.Count);
    }

    // Minimal fake rule store for the integration tests above.
    private sealed class FakeRuleStoreForSafetyTest : IFirewallRuleStore
    {
        public System.Collections.Generic.List<FirewallRuleDescriptor> Rules { get; } = new();
        public void Add(FirewallRuleDescriptor rule)
        {
            Rules.RemoveAll(r => string.Equals(r.Name, rule.Name, System.StringComparison.OrdinalIgnoreCase));
            Rules.Add(rule);
        }
        public void Remove(string name) => Rules.RemoveAll(r => string.Equals(r.Name, name, System.StringComparison.OrdinalIgnoreCase));
        public System.Collections.Generic.IReadOnlyCollection<string> ListNames() => Rules.ConvertAll(r => r.Name);
    }
}
