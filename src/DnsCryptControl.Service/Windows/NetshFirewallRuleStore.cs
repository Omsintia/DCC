using System.Diagnostics;
using System.Runtime.Versioning;

namespace DnsCryptControl.Service.Windows;

/// <summary>
/// Fallback <see cref="IFirewallRuleStore"/> for when the Firewall COM API is unavailable: shells
/// out to <c>netsh advfirewall firewall</c> using ProcessStartInfo + ArgumentList + an absolute
/// System32 path (CWE-78; Process.Start(string) is banned). Each ArgumentList token is passed
/// verbatim, so a space-containing "name=..." token needs no manual quoting and cannot inject.
/// netsh advfirewall is in maintenance mode but fully supported on Win10 19041+/Win11.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class NetshFirewallRuleStore : IFirewallRuleStore
{
    /// <summary>Bounded wait for netsh to exit. The teardown (revert) path runs in the SYSTEM service, so
    /// an unbounded WaitForExit must never be able to hang reversible-state revert. ~15s is generous for a
    /// single advfirewall add/delete on Win10 19041+/Win11.</summary>
    private const int WaitTimeoutMs = 15_000;

    /// <summary>Sentinel exit code reported when netsh did not exit within <see cref="WaitTimeoutMs"/> and
    /// was force-killed. It is non-zero so callers treat a timeout as a failure, never as success.</summary>
    private const int TimeoutExitCode = -1;

    /// <summary>Builds the ProcessStartInfo for a netsh invocation. Extracted so unit tests can verify
    /// the security-relevant shape (absolute path, ArgumentList, no shell) without spawning a process.
    /// <para>We deliberately do NOT redirect stdout/stderr: the output is never consumed, and redirecting
    /// without draining the pipes risks a deadlock — if netsh writes more than a pipe buffer (~4KB) before
    /// exiting, the child blocks on the full pipe while the service blocks on WaitForExit forever. With
    /// UseShellExecute=false + CreateNoWindow=true there is no console window and no pipe to fill.</para></summary>
    internal static ProcessStartInfo BuildNetshCommand(params string[] args)
    {
        var netsh = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "netsh.exe");
        var psi = new ProcessStartInfo
        {
            FileName = netsh,
            UseShellExecute = false,
            CreateNoWindow = true,
            // No RedirectStandardOutput/Error: output is unused and draining-less redirection can deadlock.
        };
        foreach (var a in args)
            psi.ArgumentList.Add(a); // each token separate => no shell/quoting injection
        return psi;
    }

    private static int Run(params string[] args)
    {
        using var p = Process.Start(BuildNetshCommand(args))
            ?? throw new InvalidOperationException("failed to start netsh.exe");

        // Bounded wait: a hung netsh must never stall the SYSTEM service's revert path. On timeout, kill
        // the whole process tree and report a non-success exit so callers see failure, not a hang.
        if (!p.WaitForExit(WaitTimeoutMs))
        {
            try { p.Kill(entireProcessTree: true); }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
            return TimeoutExitCode; // treat timeout as failure
        }

        return p.ExitCode;
    }

    public void Add(FirewallRuleDescriptor descriptor)
    {
        // Idempotent: delete same-named rule(s) first (no effect if absent).
        Run("advfirewall", "firewall", "delete", "rule", $"name={descriptor.Name}");
        // Only TCP/UDP descriptors are ever produced (FirewallKillSwitch.Descriptors), so non-UDP means TCP.
        var protocol = descriptor.Protocol == FirewallKillSwitch.ProtocolUdp ? "UDP" : "TCP";
        var exit = Run(
            "advfirewall", "firewall", "add", "rule",
            $"name={descriptor.Name}",
            "dir=out", "action=block",
            $"protocol={protocol}", $"remoteport={descriptor.RemotePorts}",
            "profile=any", "enable=yes");
        if (exit != 0)
            throw new InvalidOperationException(
                $"netsh add rule '{descriptor.Name}' exited {exit}");
    }

    public void Remove(string name) =>
        Run("advfirewall", "firewall", "delete", "rule", $"name={name}"); // no effect if absent

    public IReadOnlyCollection<string> ListNames()
    {
        // Listing/parsing netsh text output is brittle; the COM-based ComFirewallRuleStore is the
        // detection authority. The netsh store is add/remove-only.
        throw new NotSupportedException(
            "Use ComFirewallRuleStore for kill-switch detection (ListNames).");
    }
}
