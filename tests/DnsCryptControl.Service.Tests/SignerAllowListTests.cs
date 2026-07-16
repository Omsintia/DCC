using System;
using DnsCryptControl.Service.Windows;
using Xunit;

namespace DnsCryptControl.Service.Tests;

public class SignerAllowListTests
{
    [Fact]
    public void IsAllowed_matchesThumbprint_caseInsensitively_trimmed()
    {
        var list = new SignerAllowList(new[] { "AABBCCDDEEFF00112233" });
        Assert.True(list.IsAllowed("aabbccddeeff00112233"));
        Assert.True(list.IsAllowed("  AABBCCDDEEFF00112233  "));
        Assert.False(list.IsAllowed("DEADBEEF"));
    }

    [Fact]
    public void IsAllowed_emptyOrNull_isFalse()
    {
        var list = new SignerAllowList(new[] { "AABB" });
        Assert.False(list.IsAllowed(""));
        Assert.False(list.IsAllowed(null!));
    }

    [Theory]
    [InlineData(true,  "AABB", true)]   // valid signature + allowed signer => trusted
    [InlineData(false, "AABB", false)]  // invalid signature => never trusted
    [InlineData(true,  "DEAD", false)]  // valid but signer not on allow-list
    [InlineData(true,  null,   false)]  // valid but no signer extracted => fail closed
    public void Decide_combinesValidityAndAllowList(bool valid, string? thumb, bool expected)
    {
        if (!OperatingSystem.IsWindows()) return;
        var verifier = new WinVerifyTrustCallerVerifier(new SignerAllowList(new[] { "AABB" }));
        Assert.Equal(expected, verifier.Decide(valid, thumb));
    }
}
