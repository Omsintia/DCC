using DnsCryptControl.Platform;
using Xunit;

namespace DnsCryptControl.Platform.Tests;

public class DnsCacheFlusherContractTests
{
    private sealed class FakeFlusher : IDnsCacheFlusher
    {
        public PlatformResult Next { get; set; } = PlatformResult.Ok();
        public int Calls { get; private set; }

        public PlatformResult Flush()
        {
            Calls++;
            return Next;
        }
    }

    [Fact]
    public void Interface_isImplementable_andFlushReturnsOk()
    {
        IDnsCacheFlusher flusher = new FakeFlusher();
        var result = flusher.Flush();
        Assert.True(result.Success);
        Assert.Equal(PlatformErrorKind.None, result.Error);
    }

    [Fact]
    public void Flush_canReportFailure_viaPlatformResult()
    {
        var fake = new FakeFlusher { Next = PlatformResult.Fail(PlatformErrorKind.OperationFailed, "flush failed") };
        IDnsCacheFlusher flusher = fake;

        var result = flusher.Flush();

        Assert.Equal(1, fake.Calls);
        Assert.False(result.Success);
        Assert.Equal(PlatformErrorKind.OperationFailed, result.Error);
        Assert.Equal("flush failed", result.Message);
    }
}
