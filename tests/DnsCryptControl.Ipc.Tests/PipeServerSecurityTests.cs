using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using DnsCryptControl.Ipc.Transport;
using Xunit;

namespace DnsCryptControl.Ipc.Tests;

[SupportedOSPlatform("windows")]
public class PipeServerSecurityTests
{
    [Fact]
    public void BuildDacl_grantsSystemFull_adminsFull_userReadWrite_ownerSystem()
    {
        if (!OperatingSystem.IsWindows()) return;

        var user = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null); // stand-in user SID
        var sec = PipeServerSecurity.BuildDacl(user);

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        Assert.Equal(system, sec.GetOwner(typeof(SecurityIdentifier)));

        var rules = sec.GetAccessRules(true, false, typeof(SecurityIdentifier))
                       .Cast<PipeAccessRule>()
                       .ToList();

        Assert.Contains(rules, r => r.IdentityReference.Equals(system)
            && r.PipeAccessRights.HasFlag(PipeAccessRights.FullControl)
            && r.AccessControlType == AccessControlType.Allow);
        Assert.Contains(rules, r => r.IdentityReference.Equals(admins)
            && r.PipeAccessRights.HasFlag(PipeAccessRights.FullControl));
        Assert.Contains(rules, r => r.IdentityReference.Equals(user)
            && r.PipeAccessRights.HasFlag(PipeAccessRights.ReadWrite)
            && r.PipeAccessRights.HasFlag(PipeAccessRights.CreateNewInstance));
        // The user must NOT have FullControl.
        Assert.DoesNotContain(rules, r => r.IdentityReference.Equals(user)
            && r.PipeAccessRights.HasFlag(PipeAccessRights.FullControl));
    }

    [Fact]
    public void BuildDacl_withNullUser_grantsOnlySystemAndAdmins_noUserAce_ownerSystem()
    {
        if (!OperatingSystem.IsWindows()) return;

        // A null interactive user (e.g. the helper auto-started at boot before anyone logged in)
        // must yield a SYSTEM + Administrators only pipe — never a broad fallback SID.
        var sec = PipeServerSecurity.BuildDacl(null);

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        Assert.Equal(system, sec.GetOwner(typeof(SecurityIdentifier)));

        var rules = sec.GetAccessRules(true, false, typeof(SecurityIdentifier))
                       .Cast<PipeAccessRule>()
                       .ToList();

        Assert.Contains(rules, r => r.IdentityReference.Equals(system)
            && r.PipeAccessRights.HasFlag(PipeAccessRights.FullControl));
        Assert.Contains(rules, r => r.IdentityReference.Equals(admins)
            && r.PipeAccessRights.HasFlag(PipeAccessRights.FullControl));
        // Exactly two ACEs (SYSTEM + Administrators) — no third, user ACE.
        Assert.Equal(2, rules.Count);
    }
}
