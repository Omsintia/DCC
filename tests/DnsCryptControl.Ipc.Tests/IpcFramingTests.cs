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
    public async Task ReadFrame_overACallerSuppliedSmallerCap_returnsNull_withoutAllocating()
    {
        // FIX H: the pipe server's deny path reads (and discards) an UNTRUSTED caller's frame
        // under a tighter pre-trust cap. A frame legal at the full transport limit must still be
        // rejected against the caller-supplied bound — before the body buffer is allocated.
        using var ms = new MemoryStream();
        await IpcFraming.WriteFrameAsync(ms, new string('a', 1_048_576 + 1), CancellationToken.None);
        ms.Position = 0;

        Assert.Null(await IpcFraming.ReadFrameAsync(ms, 1_048_576, CancellationToken.None));
    }

    [Fact]
    public async Task ReadFrame_atACallerSuppliedSmallerCap_stillRoundTrips()
    {
        // The tighter bound is inclusive: an exactly-at-cap frame passes.
        using var ms = new MemoryStream();
        var body = new string('a', 1024);
        await IpcFraming.WriteFrameAsync(ms, body, CancellationToken.None);
        ms.Position = 0;

        Assert.Equal(body, await IpcFraming.ReadFrameAsync(ms, 1024, CancellationToken.None));
    }

    [Fact]
    public async Task ReadFrame_capAboveTheTransportLimit_throws()
    {
        // The caller cap can only TIGHTEN the transport limit, never widen it.
        using var ms = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => IpcFraming.ReadFrameAsync(ms, IpcSerializer.MaxBytes + 1, CancellationToken.None));
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
