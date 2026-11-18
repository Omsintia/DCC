using DnsCryptControl.Ipc.Commands;

namespace DnsCryptControl.Ipc.Tests;

/// <summary>
/// F20 handshake-version pin. v2 (Phase 5b) added a required WriteConfig BaseSha256. v3
/// (post-5j ODoH fix) added the <c>PlaceOdohCache</c> verb. v4 (v1.2.0, FIX #1) added the
/// <c>VerifyResolution</c> verb (post-apply real-name resolve check — the local .test self-check
/// false-greens on a dead anonymized route). v5 (v1.3.0) raised the FRAMING cap 1 → 16 MiB for
/// big-blocklist WriteRuleFile — not additive: a v4 helper would drop a legal v5 frame at the
/// transport (a lost reply), so BOTH write paths (the config save AND the rule-file save) run a
/// pre-write GetStatus version compare and refuse a mixed pair before sending, rather than let
/// the first large save fail like a dead helper. This pin moves ONLY on a deliberate, reviewed
/// wire change (kept in lockstep with the verb-count pin in <see cref="IpcMessagesTests"/>).
/// </summary>
public class IpcProtocolTests
{
    [Fact]
    public void Version_is5_afterTheFramingCapRoseForBigBlocklists()
    {
        Assert.Equal(5, IpcProtocol.Version);
    }
}
