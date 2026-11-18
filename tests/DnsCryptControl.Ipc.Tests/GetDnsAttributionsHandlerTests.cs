using System;
using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Dispatch.Handlers;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

/// <summary>GetDnsAttributions (protocol v5, v1.3.0 per-app attribution): handler behavior + the
/// source-gen wire round-trip for <see cref="DnsAttributionBatch"/> — omission from IpcJsonContext
/// would be a SILENT serialize failure, so the round-trip tests are the registration's regression
/// guard. Mirrors <see cref="VerifyResolutionHandlerTests"/>; the read-only-verb payload contract
/// (null/absent/malformed ⇒ AfterSeq 0, never a failure) gets its own explicit coverage.</summary>
public class GetDnsAttributionsHandlerTests
{
    private static DnsAttributionRecord Record(long seq, string name = "example.com", int pid = 4242) =>
        new(seq, 1_752_800_000_000 + seq, pid, name, "chrome");

    [Fact]
    public void Batch_roundTripsThroughSourceGenSerializer()
    {
        var json = IpcSerializer.SerializePayload(new DnsAttributionBatch(
            7, new[] { new DnsAttributionEntry(7, 1_752_800_000_123, 4242, "example.com", "chrome") }));
        var back = IpcSerializer.DeserializePayload<DnsAttributionBatch>(json);

        Assert.NotNull(back);
        Assert.Equal(7, back!.LastSeq);
        var entry = Assert.Single(back.Entries);
        Assert.Equal(7, entry.Seq);
        Assert.Equal(1_752_800_000_123, entry.UnixTimeMs);
        Assert.Equal(4242, entry.ProcessId);
        Assert.Equal("example.com", entry.QueryName);
        Assert.Equal("chrome", entry.ProcessName);
    }

    [Fact]
    public void ResultOfBatch_roundTripsThroughSourceGenSerializer()
    {
        // A null ProcessName (the process had exited at capture) must survive the wire too.
        var json = IpcSerializer.SerializePayload(Result<DnsAttributionBatch>.Ok(new DnsAttributionBatch(
            3, new[] { new DnsAttributionEntry(3, 1_752_800_000_456, 999, "exited.example", null) })));
        var back = IpcSerializer.DeserializePayload<Result<DnsAttributionBatch>>(json);

        Assert.NotNull(back);
        Assert.True(back!.Success);
        Assert.Equal(3, back.Value!.LastSeq);
        Assert.Null(Assert.Single(back.Value.Entries).ProcessName);
    }

    [Fact]
    public void Payload_roundTripsThroughSourceGenSerializer()
    {
        var json = IpcSerializer.SerializePayload(new DnsAttributionsPayload(41));
        var back = IpcSerializer.DeserializePayload<DnsAttributionsPayload>(json);

        Assert.NotNull(back);
        Assert.Equal(41, back!.AfterSeq);
    }

    [Fact]
    public void Command_isGetDnsAttributions()
    {
        Assert.Equal(
            IpcCommandType.GetDnsAttributions,
            new GetDnsAttributionsHandler(new FakeDnsAttributionSource()).Command);
    }

    [Fact]
    public void Ctor_rejectsNullSource()
    {
        Assert.Throws<ArgumentNullException>(() => new GetDnsAttributionsHandler(null!));
    }

    [Fact]
    public void NullPayload_readsFromTheStart_neverFails()
    {
        // The read-only-verb contract: an absent cursor means AfterSeq 0, not a validation error.
        var source = new FakeDnsAttributionSource();
        var handler = new GetDnsAttributionsHandler(source);
        var json = handler.Handle(new IpcRequest(IpcCommandType.GetDnsAttributions, null));
        var result = IpcSerializer.DeserializePayload<Result<DnsAttributionBatch>>(json);

        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.Equal(0L, source.LastAfterSeq);
        Assert.Equal(1, source.GetSinceCalls);
    }

    [Fact]
    public void MalformedPayload_alsoReadsFromTheStart_neverFails()
    {
        // DeserializePayload fails closed to null on garbage; the handler treats that exactly like
        // an absent cursor (there is no wrong answer to reject on a read).
        var source = new FakeDnsAttributionSource();
        var handler = new GetDnsAttributionsHandler(source);
        var json = handler.Handle(new IpcRequest(IpcCommandType.GetDnsAttributions, "{not json"));
        var result = IpcSerializer.DeserializePayload<Result<DnsAttributionBatch>>(json);

        Assert.True(result!.Success);
        Assert.Equal(0L, source.LastAfterSeq);
    }

    [Fact]
    public void PayloadCursor_isPassedThroughToTheSource()
    {
        var source = new FakeDnsAttributionSource();
        var handler = new GetDnsAttributionsHandler(source);
        handler.Handle(new IpcRequest(
            IpcCommandType.GetDnsAttributions,
            IpcSerializer.SerializePayload(new DnsAttributionsPayload(17))));

        Assert.Equal(17L, source.LastAfterSeq);
    }

    [Fact]
    public void MapsRecordsVerbatim_inOrder_withLastSeq()
    {
        var source = new FakeDnsAttributionSource
        {
            Snapshot = new DnsAttributionSnapshot(9, new[]
            {
                Record(8, "a.example", pid: 100),
                new DnsAttributionRecord(9, 1_752_800_000_999, 200, "b.example", null),
            }),
        };
        var handler = new GetDnsAttributionsHandler(source);
        var json = handler.Handle(new IpcRequest(IpcCommandType.GetDnsAttributions, null));
        var result = IpcSerializer.DeserializePayload<Result<DnsAttributionBatch>>(json);

        Assert.True(result!.Success);
        Assert.Equal(9, result.Value!.LastSeq);
        Assert.Equal(2, result.Value.Entries.Count);
        Assert.Equal(8, result.Value.Entries[0].Seq);
        Assert.Equal("a.example", result.Value.Entries[0].QueryName);
        Assert.Equal(100, result.Value.Entries[0].ProcessId);
        Assert.Equal("chrome", result.Value.Entries[0].ProcessName);
        Assert.Equal(9, result.Value.Entries[1].Seq);
        Assert.Equal(1_752_800_000_999, result.Value.Entries[1].UnixTimeMs);
        Assert.Null(result.Value.Entries[1].ProcessName);
    }

    [Fact]
    public void Dispatch_routesTheVerbToTheRealHandler_happyPath()
    {
        // Through the REAL registry + dispatcher (like the v4 handler suites): proves the verb is
        // registered — an Unsupported result here means a HandlerRegistry miss.
        var dispatcher = TestHandlerRegistry.BuildDispatcher(
            new FakeProxyServiceController(), new FakeConfigStore());
        var request = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.GetDnsAttributions, null));
        var result = IpcSerializer.DeserializePayload<Result<DnsAttributionBatch>>(dispatcher.Dispatch(request));

        Assert.NotNull(result);
        Assert.True(result!.Success);
        Assert.Equal(IpcErrorCode.None, result.Code);
        Assert.NotNull(result.Value);
        Assert.Empty(result.Value!.Entries);
    }
}
