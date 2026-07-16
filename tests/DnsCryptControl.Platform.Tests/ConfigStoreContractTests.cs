using DnsCryptControl.Platform;
using Xunit;

namespace DnsCryptControl.Platform.Tests;

public class ConfigStoreContractTests
{
    private sealed class StubStore : IConfigStore
    {
        public PlatformResult<string> ReadConfig() => PlatformResult<string>.Ok("max_clients = 1\n");
        public PlatformResult WriteConfig(string tomlText) => PlatformResult.Ok();
        public PlatformResult WriteConfigIfBaseMatches(string tomlText, string expectedBaseSha256) => PlatformResult.Ok();
        public PlatformResult WriteRuleFile(RuleFileKind kind, string content) => PlatformResult.Ok();
        public PlatformResult PlaceOdohSourceCaches() => PlatformResult.Ok();
        public PlatformResult EnsureDefaultSourceCaches() => PlatformResult.Ok();
    }

    [Fact]
    public void Interface_isImplementable()
    {
        IConfigStore s = new StubStore();
        Assert.True(s.ReadConfig().Success);
        Assert.Equal("max_clients = 1\n", s.ReadConfig().Value);
        Assert.True(s.WriteConfig("x = 1").Success);
        Assert.True(s.WriteRuleFile(RuleFileKind.BlockedNames, "ads.example").Success);
        // B2: the compare-and-swap write is part of the store contract.
        Assert.True(s.WriteConfigIfBaseMatches("x = 1", new string('a', 64)).Success);
    }

    [Fact]
    public void RuleFileKind_coversTheClosedSet()
    {
        foreach (var k in new[]
        {
            RuleFileKind.BlockedNames, RuleFileKind.AllowedNames, RuleFileKind.BlockedIps,
            RuleFileKind.AllowedIps, RuleFileKind.Cloaking, RuleFileKind.Forwarding, RuleFileKind.CaptivePortals,
        })
        {
            Assert.True(System.Enum.IsDefined(k));
        }
        Assert.Equal(7, System.Enum.GetValues<RuleFileKind>().Length);
    }
}
