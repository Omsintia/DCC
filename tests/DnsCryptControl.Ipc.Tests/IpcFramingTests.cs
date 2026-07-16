using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Ipc.Transport;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

public class IpcFramingTests
{
    [Fact]
    public async Task WriteThenRead_roundTrips()
    {
        using var ms = new MemoryStream();
        await IpcFraming.WriteFrameAsync(ms, "hello frame", CancellationToken.None);
        ms.Position = 0;
        var back = await IpcFraming.ReadFrameAsync(ms, CancellationToken.None);
        Assert.Equal("hello frame", back);
    }

    [Fact]
    public async Task ReadFrame_emptyStream_returnsNull()
    {
        using var ms = new MemoryStream();
        Assert.Null(await IpcFraming.ReadFrameAsync(ms, CancellationToken.None));
    }

    [Fact]
    public async Task ReadFrame_truncatedBody_returnsNull()
    {
        using var ms = new MemoryStream();
        // claim 100 bytes but provide 3
        ms.Write(BitConverter.GetBytes(100));
        ms.Write(Encoding.UTF8.GetBytes("abc"));
        ms.Position = 0;
        Assert.Null(await IpcFraming.ReadFrameAsync(ms, CancellationToken.None));
    }

    [Fact]
    public async Task ReadFrame_oversizedLengthPrefix_returnsNull_withoutAllocating()
    {
        using var ms = new MemoryStream();
        ms.Write(BitConverter.GetBytes(IpcSerializer.MaxBytes + 1)); // hostile length
        ms.Position = 0;
        Assert.Null(await IpcFraming.ReadFrameAsync(ms, CancellationToken.None));
    }

    [Fact]
    public async Task ReadFrame_nonPositiveLength_returnsNull()
    {
        using var ms = new MemoryStream();
        ms.Write(BitConverter.GetBytes(0));
        ms.Position = 0;
        Assert.Null(await IpcFraming.ReadFrameAsync(ms, CancellationToken.None));
    }

    [Fact]
    public async Task WriteFrame_overCap_throws()
    {
        using var ms = new MemoryStream();
        var huge = new string('a', IpcSerializer.MaxBytes + 1);
        await Assert.ThrowsAsync<ArgumentException>(
            () => IpcFraming.WriteFrameAsync(ms, huge, CancellationToken.None));
    }
}
