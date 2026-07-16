using DnsCryptControl.Ipc;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

public class ResultTests
{
    [Fact]
    public void Ok_isSuccessWithNoError()
    {
        var r = Result.Ok();
        Assert.True(r.Success);
        Assert.Equal(IpcErrorCode.None, r.Code);
    }

    [Fact]
    public void Fail_carriesCodeAndMessage()
    {
        var r = Result.Fail(IpcErrorCode.ValidationFailed, "bad toml");
        Assert.False(r.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, r.Code);
        Assert.Equal("bad toml", r.Message);
    }

    [Fact]
    public void GenericOk_carriesValue()
    {
        var r = Result<int>.Ok(42);
        Assert.True(r.Success);
        Assert.Equal(42, r.Value);
    }

    [Fact]
    public void GenericFail_hasDefaultValueAndCode()
    {
        var r = Result<string>.Fail(IpcErrorCode.NotFound, "missing");
        Assert.False(r.Success);
        Assert.Null(r.Value);
        Assert.Equal(IpcErrorCode.NotFound, r.Code);
    }
}
