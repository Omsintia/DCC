using System;
using System.IO;
using DnsCryptControl.Service.Windows;
using Xunit;

namespace DnsCryptControl.Service.Tests;

/// <summary>
/// Behavioral tests for <see cref="DnsCryptOpsecConfigDefaults"/>: the constants are exercised
/// through the real <see cref="TomlProxyConfigSafetyCheck"/> guard so that changing a constant to
/// an unsafe value will cause these tests to fail (falsifiable, not tautological).
/// </summary>
public class DnsCryptOpsecConfigDefaultsTests
{
    // Helper: write TOML to a temp file and return a ProtectedPaths pointing to it.
    private static ProtectedPaths WriteTempConfig(string toml)
    {
        var dir = Path.Combine(Path.GetTempPath(), "D2Defaults_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "dnscrypt-proxy.toml"), toml);
        return new ProtectedPaths(dir);
    }

    [Fact]
    public void DefaultConstants_buildASafeConfig_acceptedByTheGuard()
    {
        // Build TOML whose values are derived FROM the constants — not literals.
        // If any constant changes to an unsafe value this test will catch the regression.
        var toml = $"""
            netprobe_timeout = {DnsCryptOpsecConfigDefaults.NetprobeTimeout}
            ignore_system_dns = {DnsCryptOpsecConfigDefaults.IgnoreSystemDns.ToString().ToLowerInvariant()}
            bootstrap_resolvers = ['{DnsCryptOpsecConfigDefaults.NetprobeAddress}']
            """;

        var paths = WriteTempConfig(toml);
        var check = new TomlProxyConfigSafetyCheck(paths);

        var (safe, reason) = check.IsSafeUnderPort53Block();
        Assert.True(safe, $"defaults should produce a safe config, but guard rejected: {reason}");
        Assert.Null(reason);
    }

    [Fact]
    public void DeviatingNetprobeTimeout_isRejectedByTheGuard()
    {
        // netprobe_timeout deviates from the safe default — guard must reject it.
        var toml = $"""
            netprobe_timeout = 60
            ignore_system_dns = {DnsCryptOpsecConfigDefaults.IgnoreSystemDns.ToString().ToLowerInvariant()}
            """;

        var paths = WriteTempConfig(toml);
        var check = new TomlProxyConfigSafetyCheck(paths);

        var (safe, reason) = check.IsSafeUnderPort53Block();
        Assert.False(safe, "netprobe_timeout=60 should be unsafe");
        Assert.NotNull(reason);
        Assert.Contains("netprobe_timeout", reason);
    }

    [Fact]
    public void NetprobeAddress_doesNotContainPort53_safeIfNetprobeReEnabled()
    {
        // The address constant must not target :53 in case netprobe is ever re-enabled.
        Assert.DoesNotContain(":53", DnsCryptOpsecConfigDefaults.NetprobeAddress, StringComparison.Ordinal);
    }
}
