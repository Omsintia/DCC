using DnsCryptControl.Ipc.Commands;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

/// <summary>
/// Wire-vocabulary pins for the privileged IPC surface.
///
/// <para>HISTORY: through Phases 5c–5j this file ALSO ran a mechanical <c>git diff</c> gate asserting
/// ZERO source changes under the three privileged trees (Ipc/Service/Platform) — those phases were
/// UI-only by design. The post-5j ODoH fix DELIBERATELY ends that freeze: it adds the
/// <see cref="IpcCommandType.PlaceOdohCache"/> verb so the helper can place bundled, minisign-signed
/// ODoH source caches (without which adding ODoH sources bricks the whole proxy — dnscrypt-proxy
/// treats an un-downloadable source as FATAL). Phase 6 (offline hardening) will modify these trees
/// further still, so a blanket "no diffs" gate is no longer meaningful and has been retired.</para>
///
/// <para>What REMAINS is the precise part that still matters: the verb VOCABULARY and the handshake
/// VERSION must only ever change deliberately. These two pins fail loudly if a verb is added/removed
/// or the protocol version moves WITHOUT the author consciously updating them (and the mirrored pins
/// in <see cref="IpcMessagesTests"/> / <see cref="IpcProtocolTests"/>) in lockstep. Privileged-code
/// correctness beyond the vocabulary is guarded by each behavior's own unit tests + review, not by a
/// diff gate.</para>
/// </summary>
public class FrozenWireDiffGateTests
{
    [Fact]
    public void PrivilegedVerbCount_is21_afterGetDnsAttributions()
    {
        // 18 through Phase 5j; PlaceOdohCache made 19 (post-5j ODoH fix); VerifyResolution made 20
        // (v1.2.0, FIX #1 — the post-apply real-name resolve check); GetDnsAttributions made 21
        // (v1.3.0 per-app attribution — the read-only ETW-ring poll behind the Query Monitor's App
        // column). A 22nd member would silently widen the privileged surface — kept in lockstep
        // with IpcMessagesTests.
        Assert.Equal(21, System.Enum.GetValues<IpcCommandType>().Length);
        Assert.True(System.Enum.IsDefined(IpcCommandType.PlaceOdohCache));
        Assert.True(System.Enum.IsDefined(IpcCommandType.VerifyResolution));
        Assert.True(System.Enum.IsDefined(IpcCommandType.GetDnsAttributions));
    }

    [Fact]
    public void ProtocolVersion_isAt5()
    {
        // v2 (Phase 5b WriteConfig BaseSha256) → v3 (post-5j PlaceOdohCache verb) → v4 (v1.2.0
        // VerifyResolution verb) → v5 (v1.3.0: the framing cap rose 1 → 16 MiB for big-blocklist
        // WriteRuleFile — a mixed pair loses legal large frames at the transport). Moves only on a
        // deliberate, reviewed wire change; mirrored by IpcProtocolTests.
        Assert.Equal(5, IpcProtocol.Version);
    }
}
