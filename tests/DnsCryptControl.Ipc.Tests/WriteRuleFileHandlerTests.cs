using DnsCryptControl.Ipc;
using DnsCryptControl.Ipc.Commands;
using DnsCryptControl.Ipc.Dispatch.Handlers;
using DnsCryptControl.Ipc.Serialization;
using DnsCryptControl.Platform;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

public class WriteRuleFileHandlerTests
{
    private static IpcRequest Req(string kind, string content) =>
        new(IpcCommandType.WriteRuleFile, IpcSerializer.SerializePayload(new WriteRuleFilePayload(kind, content)));

    [Fact]
    public void KnownKind_isWritten()
    {
        var store = new FakeConfigStore();
        var json = new WriteRuleFileHandler(store).Handle(Req("BlockedNames", "ads.example\n*.tracker.test\n"));
        var result = IpcSerializer.DeserializePayload<Result>(json);
        Assert.True(result!.Success);
        Assert.Equal("ads.example\n*.tracker.test\n", store.RuleFiles[RuleFileKind.BlockedNames]);
    }

    [Fact]
    public void Kind_isCaseInsensitive()
    {
        var store = new FakeConfigStore();
        var json = new WriteRuleFileHandler(store).Handle(Req("blockedips", "10.0.0.0/8\n"));
        var result = IpcSerializer.DeserializePayload<Result>(json);
        Assert.True(result!.Success);
        Assert.True(store.RuleFiles.ContainsKey(RuleFileKind.BlockedIps));
    }

    [Theory]
    [InlineData("../../etc/passwd")]   // path-traversal disguised as a kind
    [InlineData("blocked-names.txt")]  // a filename is not a valid kind
    [InlineData("Nonsense")]
    [InlineData("")]
    [InlineData("0")]                  // numeric ordinal must be rejected
    [InlineData("999")]                // out-of-range numeric ordinal must be rejected
    public void UnknownKind_isRejected_andNothingWritten(string kind)
    {
        var store = new FakeConfigStore();
        var json = new WriteRuleFileHandler(store).Handle(Req(kind, "x\n"));
        var result = IpcSerializer.DeserializePayload<Result>(json);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.Empty(store.RuleFiles);
    }

    [Fact]
    public void ContentWithEmbeddedNul_isRejected()
    {
        var store = new FakeConfigStore();
        var json = new WriteRuleFileHandler(store).Handle(Req("BlockedNames", "ads.example\0evil"));
        var result = IpcSerializer.DeserializePayload<Result>(json);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.Empty(store.RuleFiles);
    }

    [Fact]
    public void OverlongLine_isRejected()
    {
        var store = new FakeConfigStore();
        var longLine = new string('a', 5000); // > 4096 per-line cap
        var json = new WriteRuleFileHandler(store).Handle(Req("BlockedNames", longLine));
        var result = IpcSerializer.DeserializePayload<Result>(json);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.Empty(store.RuleFiles);
    }

    [Fact]
    public void MissingPayload_isRejected()
    {
        var store = new FakeConfigStore();
        var json = new WriteRuleFileHandler(store).Handle(new IpcRequest(IpcCommandType.WriteRuleFile, null));
        var result = IpcSerializer.DeserializePayload<Result>(json);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
    }

    // ---- E1(b): the REAL handler's validation runs BEFORE the store is ever touched ----
    //
    // The existing tests above already exercise the REAL WriteRuleFileHandler (they construct
    // `new WriteRuleFileHandler(store)` and call Handle), and assert nothing was written on the
    // FakeConfigStore. But "nothing written" alone leaves a faked-seam gap: a handler that FIRST
    // called the store and only THEN noticed the bad input would ALSO leave the fake empty (its
    // write is a no-op on the fail path). To close that trap, the store below THROWS the instant
    // WriteRuleFile is reached — so a passing test PROVES every rejection short-circuits before the
    // (privileged) store call, exactly at handler lines :37 (ordinal), :40 (unknown Kind), :46 (NUL),
    // :49-53 (4096 cap). This is the real handler logic, not a fake-bypassed one.

    /// <summary>A store whose write path is a landmine: reaching it at all fails the test. Lets a
    /// validation-rejection assertion prove the guard fires BEFORE the store is consulted.</summary>
    private sealed class ThrowingConfigStore : IConfigStore
    {
        public PlatformResult<string> ReadConfig() => PlatformResult<string>.Fail(PlatformErrorKind.NotFound, "n/a");
        public PlatformResult WriteConfig(string tomlText) =>
            throw new Xunit.Sdk.XunitException("WriteConfig must never be reached on a rejected WriteRuleFile.");
        public PlatformResult WriteConfigIfBaseMatches(string tomlText, string expectedBaseSha256) =>
            throw new Xunit.Sdk.XunitException("WriteConfigIfBaseMatches must never be reached on a rejected WriteRuleFile.");
        public PlatformResult WriteRuleFile(RuleFileKind kind, string content) =>
            throw new Xunit.Sdk.XunitException(
                $"the store's WriteRuleFile was reached for a rejected input (kind={kind}) — validation did not short-circuit.");
        public PlatformResult PlaceOdohSourceCaches() =>
            throw new Xunit.Sdk.XunitException("PlaceOdohSourceCaches must never be reached on a rejected WriteRuleFile.");
        public PlatformResult EnsureDefaultSourceCaches() =>
            throw new Xunit.Sdk.XunitException("EnsureDefaultSourceCaches must never be reached on a rejected WriteRuleFile.");
    }

    [Theory]
    [InlineData("6")]                          // ordinal for CaptivePortals — must be rejected as a NAME, :37
    [InlineData("0")]                          // ordinal for BlockedNames — the int value is NOT a valid kind
    [InlineData("Nonsense")]                   // unknown member name, :40
    [InlineData("../../etc/passwd")]           // traversal disguised as a kind
    public void RealHandler_rejectsBadKind_beforeTouchingTheStore(string kind)
    {
        var json = new WriteRuleFileHandler(new ThrowingConfigStore()).Handle(Req(kind, "ads.example\n"));
        var result = IpcSerializer.DeserializePayload<Result>(json);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.Contains(kind, result.Message, StringComparison.Ordinal); // names the offending value (IC-10)
    }

    [Fact]
    public void RealHandler_rejectsEmbeddedNul_beforeTouchingTheStore()
    {
        // :46 — a NUL anywhere in the content is rejected before the store call.
        var json = new WriteRuleFileHandler(new ThrowingConfigStore()).Handle(Req("BlockedNames", "good.example\nbad\0line\n"));
        var result = IpcSerializer.DeserializePayload<Result>(json);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.Contains("NUL", result.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RealHandler_rejectsOverlongLine_beforeTouchingTheStore()
    {
        // :49-53 — one line over the 4096-char cap fails the whole payload, before the store call.
        var overlong = "ok.example\n" + new string('a', 4097) + "\nalso.ok\n";
        var json = new WriteRuleFileHandler(new ThrowingConfigStore()).Handle(Req("BlockedNames", overlong));
        var result = IpcSerializer.DeserializePayload<Result>(json);
        Assert.False(result!.Success);
        Assert.Equal(IpcErrorCode.ValidationFailed, result.Code);
        Assert.Contains("4096", result.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RealHandler_acceptsExactly4096_theCapIsInclusive()
    {
        // :51 caps at length > MaxLineLength, so a line of EXACTLY 4096 chars is accepted — pin the
        // inclusive boundary through the FakeConfigStore (the store IS reached on the accept path).
        var store = new FakeConfigStore();
        var atCap = new string('a', 4096);
        var json = new WriteRuleFileHandler(store).Handle(Req("BlockedNames", atCap + "\n"));
        var result = IpcSerializer.DeserializePayload<Result>(json);
        Assert.True(result!.Success);
        Assert.Equal(atCap + "\n", store.RuleFiles[RuleFileKind.BlockedNames]);
    }

    [Fact]
    public void RealHandler_measuresLineLength_afterStrippingTheCR_soCrLfAtCapIsAccepted()
    {
        // :51 trims a trailing '\r' before measuring, so a 4096-char line terminated CRLF (the '\r'
        // is the 4097th byte in the split segment) is still within the cap — CRLF content is not
        // spuriously rejected. The store IS reached on this accept path.
        var store = new FakeConfigStore();
        var line = new string('a', 4096);
        var content = line + "\r\n"; // split on '\n' yields "aaaa...\r" (4097 chars); :51 strips the \r → 4096
        var json = new WriteRuleFileHandler(store).Handle(Req("BlockedNames", content));
        var result = IpcSerializer.DeserializePayload<Result>(json);
        Assert.True(result!.Success);
        Assert.Equal(content, store.RuleFiles[RuleFileKind.BlockedNames]);
    }
}
