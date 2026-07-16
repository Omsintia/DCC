#requires -Version 5.1
<#
.SYNOPSIS
  IC-PKG fail-safe: the DUMB, deterministic uninstall cleanup that runs when the helper's own `--teardown`
  can't (a broken/missing helper exe). It undoes the two things that would otherwise leave the machine
  with NO working DNS: the kill-switch firewall rules, and adapter DNS pinned to loopback.

.DESCRIPTION
  Idempotent + best-effort (never throws, never blocks an uninstall): it always exits 0. Removes every
  `DnsCryptControl KillSwitch*` firewall rule, and resets any adapter whose configured DNS points at a
  loopback address (127.0.0.0/8 or ::1) back to DHCP/automatic. Worst case after this runs = DNS on DHCP
  = the machine resolves normally. Does NOT touch config/state (the MSI purges ProgramData separately).
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'   # best-effort: one failing step must not abort the rest

# 1. Kill-switch firewall rules (the primary DNS-blocking artifact).
try {
    Get-NetFirewallRule -DisplayName 'DnsCryptControl KillSwitch*' -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
}
catch { }

# 2. Any adapter whose DNS is pinned to loopback -> back to DHCP (the app points DNS at 127.0.0.1 while
#    protected; if the helper couldn't restore the backup, this is the safety net).
try {
    foreach ($cfg in Get-DnsClientServerAddress -ErrorAction SilentlyContinue) {
        if ($null -eq $cfg.ServerAddresses) { continue }
        $loopback = $cfg.ServerAddresses | Where-Object { $_ -like '127.*' -or $_ -eq '::1' }
        if ($loopback) {
            # ResetServerAddresses reverts the interface to DHCP-provided DNS (or none for static setups).
            Set-DnsClientServerAddress -InterfaceIndex $cfg.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue
        }
    }
}
catch { }

exit 0
