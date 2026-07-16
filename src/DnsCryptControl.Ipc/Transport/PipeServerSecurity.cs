using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace DnsCryptControl.Ipc.Transport;

/// <summary>
/// Builds the explicit DACL for the helper pipe from well-known SIDs (not localizable
/// names): SYSTEM FullControl, BuiltinAdministrators FullControl, and — when an interactive
/// user is currently active — that specific user ReadWrite|CreateNewInstance; owner = SYSTEM so
/// a non-admin cannot rewrite the DACL. Applied atomically at pipe creation via
/// NamedPipeServerStreamAcl.Create (the PipeSecurity-ctor overload is .NET Framework only;
/// SetAccessControl after creation races early connections; CurrentUserOnly is unusable across
/// SYSTEM/user accounts).
/// </summary>
[SupportedOSPlatform("windows")]
public static class PipeServerSecurity
{
    /// <param name="interactiveUserSid">The active interactive user's SID to grant ReadWrite, or
    /// <c>null</c> when no interactive user is active yet (e.g. the helper started at boot before
    /// login). A null user yields a SYSTEM+Administrators-only pipe — fail closed, never a broad
    /// fallback SID. The accept loop re-resolves and rebuilds this DACL, so the user is granted as
    /// soon as a session becomes active.</param>
    public static PipeSecurity BuildDacl(SecurityIdentifier? interactiveUserSid)
    {
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(system, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(admins, PipeAccessRights.FullControl, AccessControlType.Allow));
        if (interactiveUserSid is not null)
        {
            security.AddAccessRule(new PipeAccessRule(
                interactiveUserSid,
                PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
                AccessControlType.Allow));
        }
        security.SetOwner(system);
        return security;
    }
}
