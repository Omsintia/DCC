using DnsCryptControl.Platform;
using Xunit;

namespace DnsCryptControl.Platform.Tests;

public class PlatformResultTests
{
    [Fact]
    public void Ok_isSuccessWithNoError()
    {
        var r = PlatformResult.Ok();
        Assert.True(r.Success);
        Assert.Equal(PlatformErrorKind.None, r.Error);
        Assert.Null(r.Message);
    }

    [Fact]
    public void Fail_carriesKindAndMessage()
    {
        var r = PlatformResult.Fail(PlatformErrorKind.NotFound, "no service");
        Assert.False(r.Success);
        Assert.Equal(PlatformErrorKind.NotFound, r.Error);
        Assert.Equal("no service", r.Message);
    }

    [Fact]
    public void GenericOk_carriesValue()
    {
        var r = PlatformResult<int>.Ok(7);
        Assert.True(r.Success);
        Assert.Equal(7, r.Value);
        Assert.Equal(PlatformErrorKind.None, r.Error);
    }

    [Fact]
    public void GenericFail_hasDefaultValueAndKind()
    {
        var r = PlatformResult<string>.Fail(PlatformErrorKind.OperationFailed, "boom");
        Assert.False(r.Success);
        Assert.Null(r.Value);
        Assert.Equal(PlatformErrorKind.OperationFailed, r.Error);
    }
}
