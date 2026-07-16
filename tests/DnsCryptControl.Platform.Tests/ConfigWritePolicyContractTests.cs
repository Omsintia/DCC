using DnsCryptControl.Platform;
using Xunit;

namespace DnsCryptControl.Platform.Tests;

public class ConfigWritePolicyContractTests
{
    private sealed class StubPolicy : IConfigWritePolicy
    {
        public PlatformResult ResultToReturn { get; set; } = PlatformResult.Ok();
        public string? LastCandidate { get; private set; }

        public PlatformResult Check(string candidateTomlText)
        {
            LastCandidate = candidateTomlText;
            return ResultToReturn;
        }
    }

    [Fact]
    public void Interface_isImplementable_okMeansSaveMayProceed()
    {
        var stub = new StubPolicy();
        IConfigWritePolicy p = stub;

        var result = p.Check("netprobe_timeout = 0\n");

        Assert.True(result.Success);
        Assert.Equal("netprobe_timeout = 0\n", stub.LastCandidate);
    }

    [Fact]
    public void Check_refusal_carriesKindAndVerbatimMessage()
    {
        // IC-10 shape: a refusal carries a human-actionable "OPSEC guard: "-prefixed
        // message the UI shows verbatim; InvalidArgument maps to ValidationFailed on
        // the wire (Conflict is reserved for the base-sha race).
        IConfigWritePolicy p = new StubPolicy
        {
            ResultToReturn = PlatformResult.Fail(
                PlatformErrorKind.InvalidArgument, "OPSEC guard: netprobe_timeout must be 0 (got 60)"),
        };

        var result = p.Check("netprobe_timeout = 60\n");

        Assert.False(result.Success);
        Assert.Equal(PlatformErrorKind.InvalidArgument, result.Error);
        Assert.StartsWith("OPSEC guard: ", result.Message, System.StringComparison.Ordinal);
    }
}
