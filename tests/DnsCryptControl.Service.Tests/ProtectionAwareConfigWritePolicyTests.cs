using System;
using System.IO;
using DnsCryptControl.Platform;
using DnsCryptControl.Service.State;
using DnsCryptControl.Service.Windows;
using Xunit;

namespace DnsCryptControl.Service.Tests;

/// <summary>
/// B3: the server-side OPSEC save gate (P5b-U1, IC-4). Drives the protection state through
/// the REAL ProtectionStateStore against a temp dir (the established state-store fixture —
/// no new seam), so the fail-closed TryLoad path is exercised end-to-end.
/// </summary>
public class ProtectionAwareConfigWritePolicyTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "DnsCryptPolicyTest_" + Guid.NewGuid().ToString("N"));
    private readonly string _stateFile;
    private readonly ProtectionStateStore _store;
    private readonly ProtectionAwareConfigWritePolicy _policy;

    // Satisfies every OPSEC rule: probe off, no system-DNS fallback, encrypted-port
    // bootstrap, loopback:53 listener.
    private const string SafeConfig =
        "netprobe_timeout = 0\n" +
        "ignore_system_dns = true\n" +
        "bootstrap_resolvers = ['9.9.9.11:9953']\n" +
        "listen_addresses = ['127.0.0.1:53']\n";

    // Violates three KillSwitchCritical rules at once.
    private const string UnsafeConfig =
        "netprobe_timeout = 60\n" +
        "ignore_system_dns = false\n" +
        "bootstrap_resolvers = ['8.8.8.8:53']\n";

    public ProtectionAwareConfigWritePolicyTests()
    {
        _stateFile = Path.Combine(_dir, "state", "protection.json");
        _store = new ProtectionStateStore(_stateFile);
        _policy = new ProtectionAwareConfigWritePolicy(_store);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true); } catch (IOException) { }
        GC.SuppressFinalize(this);
    }

    private void SetProtection(bool enabled)
        => _store.Save(new ProtectionState(ProtectionEnabled: enabled, KillSwitchEnabled: enabled, LeakMitigationsEnabled: false));

    private void CorruptStateFile()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_stateFile)!);
        File.WriteAllText(_stateFile, "{ not valid json");
    }

    // ---- unprotected: the guard never blocks (P5b-U1 blocks only WHILE protected) ----

    [Fact]
    public void Check_whenUnprotected_allowsUnsafeConfig()
    {
        SetProtection(false);

        var result = _policy.Check(UnsafeConfig);

        Assert.True(result.Success);
    }

    [Fact]
    public void Check_whenStateFileAbsent_allowsUnsafeConfig()
    {
        // Fresh install: no state file has ever been written = legitimately unprotected.
        var result = _policy.Check(UnsafeConfig);

        Assert.True(result.Success);
    }

    // ---- protected: safe passes, each critical rule blocks ----

    [Fact]
    public void Check_whenProtected_safeCandidate_ok()
    {
        SetProtection(true);

        var result = _policy.Check(SafeConfig);

        Assert.True(result.Success);
    }

    [Theory]
    [InlineData("netprobe_timeout = 60\nignore_system_dns = true\n", "netprobe_timeout")]
    [InlineData("netprobe_timeout = 0\nignore_system_dns = false\n", "ignore_system_dns")]
    [InlineData("netprobe_timeout = 0\nignore_system_dns = true\nbootstrap_resolvers = ['8.8.8.8:53']\n", "8.8.8.8:53")]
    // listen_addresses off loopback:53 is ProtectionCritical — blocks exactly like KillSwitchCritical.
    [InlineData("netprobe_timeout = 0\nignore_system_dns = true\nlisten_addresses = ['0.0.0.0:5353']\n", "listen_addresses")]
    public void Check_whenProtected_criticalViolation_failsWithRuleMessage(string candidate, string expectedInMessage)
    {
        SetProtection(true);

        var result = _policy.Check(candidate);

        Assert.False(result.Success);
        Assert.Equal(PlatformErrorKind.InvalidArgument, result.Error);
        Assert.StartsWith("OPSEC guard: ", result.Message, StringComparison.Ordinal);
        Assert.Contains(expectedInMessage, result.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Check_whenProtected_multipleViolations_joinsAllConcernMessages()
    {
        SetProtection(true);

        var result = _policy.Check(UnsafeConfig);

        Assert.False(result.Success);
        Assert.Contains("netprobe_timeout", result.Message, StringComparison.Ordinal);
        Assert.Contains("ignore_system_dns", result.Message, StringComparison.Ordinal);
        Assert.Contains("8.8.8.8:53", result.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Check_whenProtected_advisoryOnly_ok()
    {
        // netprobe_address:53 is Advisory — warn-only in the editor, never a save block.
        SetProtection(true);

        var result = _policy.Check(SafeConfig + "netprobe_address = '9.9.9.9:53'\n");

        Assert.True(result.Success);
    }

    [Fact]
    public void Check_whenProtected_unparseableCandidate_blocked()
    {
        // Evaluate's fail-closed "unparseable" concern covers this; schema validation
        // upstream would also reject it (IC-3) — belt and suspenders.
        SetProtection(true);

        var result = _policy.Check("not [ valid toml ===");

        Assert.False(result.Success);
        Assert.StartsWith("OPSEC guard: ", result.Message, StringComparison.Ordinal);
    }

    // ---- THE pre-flight critical: corrupt state file must fail CLOSED (treated as protected) ----

    [Fact]
    public void Check_whenStateFileCorrupt_blocksUnsafeCandidate()
    {
        CorruptStateFile();

        var result = _policy.Check(UnsafeConfig);

        Assert.False(result.Success);
        Assert.Equal(PlatformErrorKind.InvalidArgument, result.Error);
        Assert.StartsWith("OPSEC guard: ", result.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Check_whenStateFileCorrupt_safeCandidate_stillOk()
    {
        // Fail-closed means "assume protected", NOT "refuse everything": a safe config
        // passes the OPSEC rules regardless of protection state.
        CorruptStateFile();

        var result = _policy.Check(SafeConfig);

        Assert.True(result.Success);
    }

    // ---- guards ----

    [Fact]
    public void Ctor_nullStore_throws()
    {
        Assert.Throws<ArgumentNullException>(() => new ProtectionAwareConfigWritePolicy(null!));
    }

    [Fact]
    public void Check_nullCandidate_throws()
    {
        Assert.Throws<ArgumentNullException>(() => _policy.Check(null!));
    }
}
