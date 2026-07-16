using DnsCryptControl.Ipc.Commands;

namespace DnsCryptControl.Ipc.Tests;

/// <summary>
/// F20 handshake-version pin. v2 (Phase 5b) added a required WriteConfig BaseSha256. v3
/// (post-5j ODoH fix) added the <c>PlaceOdohCache</c> verb. v4 (v1.2.0, FIX #1) added the
/// <c>VerifyResolution</c> verb (post-apply real-name resolve check — the local .test self-check
/// false-greens on a dead anonymized route). An older helper lacks the newest verb and would
/// answer UnsupportedHandler, so the handshake must refuse a mixed pair up front rather than let
/// the UI issue a verb the helper can't honour. This pin moves ONLY on a deliberate, reviewed
/// wire change (kept in lockstep with the verb-count pin in <see cref="IpcMessagesTests"/>).
/// </summary>
public class IpcProtocolTests
{
    [Fact]
    public void Version_is4_afterTheVerifyResolutionVerbWasAdded()
    {
        Assert.Equal(4, IpcProtocol.Version);
    }
}
