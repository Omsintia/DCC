using System.Security.Principal;
using CsCheck;
using DnsCryptControl.Service.Windows;

namespace DnsCryptControl.Fuzzing.Properties;

/// <summary>
/// Fuzz + regression properties for SessionUserSelection - the pure deciders extracted from
/// ConsoleSessionUser for the WTS session-enumeration marshalling finding (2026-07-08). The interactive-user
/// SID these gate becomes the named-pipe DACL's ACE, so the security oracles are: the loop count bound never
/// wraps negative, session 0 / non-active sessions are always excluded, and a broad/null SID is never
/// accepted. See the fuzzing design notes.
/// </summary>
public class SessionUserSelectionProperties
{
    [Fact]
    [Trait("Category", "Fuzz")]
    public void ClampCount_is_never_negative_and_bounded() =>
        Gen.UInt.Sample(c =>
        {
            var r = SessionUserSelection.ClampCount(c);
            // Never negative; exactly (int)c when it fits, else 0 (fail-closed).
            return r >= 0 && (c > int.MaxValue ? r == 0 : r == (int)c);
        }, iter: Fuzz.Iter);

    [Fact]
    [Trait("Category", "Fuzz")]
    public void IsCandidateSession_excludes_session0_and_inactive() =>
        Gen.Select(Gen.Int, Gen.UInt, (state, sessionId) => (state, sessionId)).Sample(t =>
            SessionUserSelection.IsCandidateSession(t.state, t.sessionId) == (t.state == 0 && t.sessionId != 0),
            iter: Fuzz.Iter);

    [Fact]
    public void IsBroadOrNullSid_rejects_null_and_broad_sids()
    {
        Assert.True(SessionUserSelection.IsBroadOrNullSid(null));
        Assert.True(SessionUserSelection.IsBroadOrNullSid(new SecurityIdentifier(WellKnownSidType.WorldSid, null)));
        Assert.True(SessionUserSelection.IsBroadOrNullSid(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null)));
        Assert.True(SessionUserSelection.IsBroadOrNullSid(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null)));
        Assert.True(SessionUserSelection.IsBroadOrNullSid(new SecurityIdentifier(WellKnownSidType.AnonymousSid, null)));
        Assert.True(SessionUserSelection.IsBroadOrNullSid(new SecurityIdentifier(WellKnownSidType.NetworkSid, null)));
        // A specific service/account SID is NOT a broad group SID (so a real interactive user is accepted).
        Assert.False(SessionUserSelection.IsBroadOrNullSid(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null)));
    }
}
