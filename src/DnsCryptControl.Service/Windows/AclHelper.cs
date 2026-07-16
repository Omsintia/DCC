using System.IO;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace DnsCryptControl.Service.Windows;

[SupportedOSPlatform("windows")]
internal static class AclHelper
{
    /// <summary>Best-effort: restrict the file's DACL to SYSTEM + BUILTIN\Administrators (full
    /// control) plus BUILTIN\Users (read-only), disabling inheritance. Swallows failures (the file
    /// is already in an ACL'd ProgramData dir).</summary>
    internal static void TryHardenAcl(string path)
    {
        try
        {
            // Guard: only tighten ACLs when running elevated so tests (which run as a
            // non-elevated user and OWN their temp dirs) never lock themselves out.
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                return;

            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

            if (Directory.Exists(path))
            {
                var info = new DirectoryInfo(path);
                var sec = new DirectorySecurity();
                sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                sec.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                sec.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                sec.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.Read,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                info.SetAccessControl(sec);
            }
            else if (File.Exists(path))
            {
                var info = new FileInfo(path);
                var sec = new FileSecurity();
                sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                sec.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, AccessControlType.Allow));
                sec.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, AccessControlType.Allow));
                sec.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.Read, AccessControlType.Allow));
                info.SetAccessControl(sec);
            }
        }
        catch (UnauthorizedAccessException) { /* not the owner; skip */ }
        catch (IOException) { }
        catch (PlatformNotSupportedException) { }
    }
}
