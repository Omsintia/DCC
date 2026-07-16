using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;
using DnsCryptControl.UI.Services;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// B1: the UI-side <c>WriteRuleFile</c> plumbing — the <see cref="HelperClient"/> verb and
/// the <see cref="UiPaths.RuleFileTooLarge"/> request-size pre-check. (The rule-file leaf
/// names live in <c>RuleFileService</c>; the cross-project pin against the real
/// <c>ProtectedPaths</c> lives in the E1 gate, which references the Service assembly.)
/// Tests inject a fake <c>send</c> delegate so they run headlessly and pin the exact
/// wire frame.
/// </summary>
public class WriteRuleFileClientTests
{
    /// <summary>The <c>WriteRuleFile</c> verb carries the non-generic <see cref="Result"/>
    /// (like WriteConfig), with NO baseSha — this pins the exact wire shape: verb +
    /// <c>Kind</c>/<c>Content</c> spelled PascalCase (source-gen case-SENSITIVE), where
    /// <c>Kind</c> is the <see cref="RuleFileKind"/> member NAME string.</summary>
    [Fact]
    public async Task WriteRuleFileAsync_serializes_verb_and_pascal_case_payload()
    {
        string? capturedRequestJson = null;
        Task<string?> Send(string requestJson, CancellationToken ct)
        {
            capturedRequestJson = requestJson;
            return Task.FromResult<string?>(IpcSerializer.SerializePayload(Result.Ok()));
        }

        var client = new HelperClient(Send);

        var result = await client.WriteRuleFileAsync(
            nameof(RuleFileKind.BlockedNames), "ads.example.com\n", CancellationToken.None);

        Assert.NotNull(capturedRequestJson);
        var captured = IpcSerializer.DeserializeRequest(capturedRequestJson!);
        Assert.NotNull(captured);
        Assert.Equal(IpcCommandType.WriteRuleFile, captured!.Command);
        Assert.NotNull(captured.PayloadJson);
        Assert.Contains("\"Kind\":", captured.PayloadJson!, StringComparison.Ordinal);
        Assert.Contains("\"Content\":", captured.PayloadJson!, StringComparison.Ordinal);
        var payload = IpcSerializer.DeserializePayload<WriteRuleFilePayload>(captured.PayloadJson!);
        Assert.NotNull(payload);
        Assert.Equal("BlockedNames", payload!.Kind);
        Assert.Equal("ads.example.com\n", payload.Content);
        Assert.NotNull(result);
        Assert.True(result!.Success);
    }

    /// <summary>The Kind string is passed through verbatim (the helper parses it into the
    /// enum and rejects anything unknown — the client never validates), so
    /// <c>nameof(RuleFileKind.X)</c> round-trips to the exact member name for every kind.</summary>
    [Theory]
    [InlineData(RuleFileKind.BlockedNames, "BlockedNames")]
    [InlineData(RuleFileKind.AllowedNames, "AllowedNames")]
    [InlineData(RuleFileKind.BlockedIps, "BlockedIps")]
    [InlineData(RuleFileKind.AllowedIps, "AllowedIps")]
    [InlineData(RuleFileKind.Cloaking, "Cloaking")]
    [InlineData(RuleFileKind.Forwarding, "Forwarding")]
    public async Task WriteRuleFileAsync_passes_kind_name_verbatim(RuleFileKind kind, string expectedName)
    {
        WriteRuleFilePayload? payload = null;
        Task<string?> Send(string requestJson, CancellationToken ct)
        {
            var req = IpcSerializer.DeserializeRequest(requestJson);
            payload = IpcSerializer.DeserializePayload<WriteRuleFilePayload>(req!.PayloadJson!);
            return Task.FromResult<string?>(IpcSerializer.SerializePayload(Result.Ok()));
        }

        var client = new HelperClient(Send);

        await client.WriteRuleFileAsync(kind.ToString(), "content\n", CancellationToken.None);

        Assert.NotNull(payload);
        Assert.Equal(expectedName, payload!.Kind);
    }

    /// <summary>Fail-closed: a broken pipe (null send) surfaces as a null result, never a
    /// silent success — mirrors WriteConfig.</summary>
    [Fact]
    public async Task WriteRuleFileAsync_null_send_yields_null()
    {
        Task<string?> Send(string requestJson, CancellationToken ct) =>
            Task.FromResult<string?>(null);

        var client = new HelperClient(Send);

        var result = await client.WriteRuleFileAsync(
            nameof(RuleFileKind.AllowedNames), "x\n", CancellationToken.None);

        Assert.Null(result);
    }

    /// <summary>A helper refusal (e.g. the 4096-cap or an unknown Kind) passes through with
    /// its code and message intact so the ViewModel can surface it verbatim (IC-10).</summary>
    [Fact]
    public async Task WriteRuleFileAsync_surfaces_failure_code_and_message()
    {
        var canned = Result.Fail(
            IpcErrorCode.ValidationFailed, "A rule line exceeds the 4096-character cap.");
        Task<string?> Send(string requestJson, CancellationToken ct) =>
            Task.FromResult<string?>(IpcSerializer.SerializePayload(canned));

        var client = new HelperClient(Send);

        var result = await client.WriteRuleFileAsync(
            nameof(RuleFileKind.Cloaking), "bad", CancellationToken.None);

        Assert.NotNull(result);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.Equal(canned.Message, result.Message);
    }

    /// <summary>Content that fits inside the exact request frame is NOT flagged. The
    /// pre-check mirrors ConfigFileService's size gate: it serializes the REAL
    /// envelope+payload the client would send and compares GetByteCount against MaxBytes
    /// (> rejects), so a payload sized to land exactly at MaxBytes is accepted.</summary>
    [Fact]
    public void RuleFileTooLarge_false_at_and_below_MaxBytes()
    {
        // Build a Content whose full request frame is exactly MaxBytes: measure the
        // envelope overhead with an empty content, then pad Content up to the boundary.
        var overhead = FrameByteCount(nameof(RuleFileKind.BlockedNames), string.Empty);
        var pad = IpcSerializer.MaxBytes - overhead;
        var atLimit = new string('a', pad);

        Assert.Equal(IpcSerializer.MaxBytes, FrameByteCount(nameof(RuleFileKind.BlockedNames), atLimit));
        Assert.False(UiPaths.RuleFileTooLarge(nameof(RuleFileKind.BlockedNames), atLimit));
        Assert.False(UiPaths.RuleFileTooLarge(nameof(RuleFileKind.BlockedNames), atLimit[1..]));
    }

    /// <summary>One byte over MaxBytes IS flagged (the transport itself rejects &gt; MaxBytes;
    /// this gives the friendly outcome without touching the pipe).</summary>
    [Fact]
    public void RuleFileTooLarge_true_one_over_MaxBytes()
    {
        var overhead = FrameByteCount(nameof(RuleFileKind.BlockedNames), string.Empty);
        var pad = IpcSerializer.MaxBytes - overhead + 1;
        var overLimit = new string('a', pad);

        Assert.Equal(IpcSerializer.MaxBytes + 1, FrameByteCount(nameof(RuleFileKind.BlockedNames), overLimit));
        Assert.True(UiPaths.RuleFileTooLarge(nameof(RuleFileKind.BlockedNames), overLimit));
    }

    private static int FrameByteCount(string kind, string content)
    {
        var payloadJson = IpcSerializer.SerializePayload(new WriteRuleFilePayload(kind, content));
        var requestJson = IpcSerializer.Serialize(new IpcRequest(IpcCommandType.WriteRuleFile, payloadJson));
        return System.Text.Encoding.UTF8.GetByteCount(requestJson);
    }
}
