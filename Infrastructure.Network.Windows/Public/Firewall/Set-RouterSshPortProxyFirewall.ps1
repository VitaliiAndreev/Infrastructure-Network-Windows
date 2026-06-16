<#
.NOTES
    Do not run this file directly. Dot-sourced by provision.ps1.
#>

# ---------------------------------------------------------------------------
# Set-RouterSshPortProxyFirewall
#   Windows Defender Firewall companion to Set-RouterSshPortProxy.
#   Without an inbound allow the portproxy listens on 0.0.0.0:<port>
#   but the firewall silently drops inbound TCP from WSL, surfacing
#   later as the "Connection timed out during banner exchange" Ansible
#   UNREACHABLE.
#
#   Scoped by REMOTE ADDRESS (the WSL NAT range), NOT by interface.
#   An earlier -InterfaceAlias scope pinned the rule to the WSL
#   adapter's interface GUID, which WSL regenerates across
#   `wsl --shutdown`, host reboots, and feature toggles - stranding the
#   rule on a dead GUID so the live adapter's inbound 2222 fell through
#   to default-deny, and forcing a re-provision just to rebind it.
#   WSL2's NAT subnet always sits inside 172.16.0.0/12, while the host's
#   real LAN and the router's Internal-switch subnet do not, so scoping
#   the allow to that range keeps the router's password-auth SSH off the
#   physical LAN AND survives adapter GUID churn with no re-provision -
#   the rule has nothing volatile to go stale against.
#
#   Trade-off: scope is by source-IP range rather than ingress
#   interface, so any 172.16/12 peer (in practice only WSL) is allowed,
#   and a host that also joins a 172.16/12 network would widen it -
#   pass -WslNatRange to narrow the range if that applies.
#
#   Refreshed (delete + re-add) on every run so the rule always carries
#   the current scope; this also migrates any older interface-pinned
#   rule left by a previous version to the range-scoped form.
#
#   No-op on hosts without a WSL adapter installed; the rest of the
#   provisioner stays usable on Linux/Mac developer boxes that
#   exercise these helpers via Pester.
# ---------------------------------------------------------------------------

function Set-RouterSshPortProxyFirewall {
    [CmdletBinding()]
    param(
        # Listen port the inbound rule covers. Must match the
        # Set-RouterSshPortProxy listen port - same default.
        [int]    $ListenPort  = 2222,

        # Source-IP range the allow is scoped to. Defaults to the
        # private range WSL2's NAT always allocates from; narrow it if
        # the host also lives on a 172.16/12 network.
        [string] $WslNatRange = '172.16.0.0/12'
    )

    # Gate on WSL being installed (adapter present). Get-NetAdapter
    # returns nothing on hosts without WSL; the rule is pointless there,
    # and New-NetFirewallRule does not exist on Linux/Mac at all. The
    # adapter is used only as this presence signal - the rule's scope no
    # longer depends on it, which is what makes it reboot-durable.
    $wslAdapter = Get-NetAdapter -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -like 'vEthernet (WSL*' } |
                  Select-Object -First 1

    if (-not $wslAdapter) {
        Write-Host "  [firewall] no vEthernet (WSL*) adapter found; skipping firewall rule (WSL probably not installed)."
        return
    }

    $ruleName = "Vm-Provisioner: WSL -> router SSH portproxy (TCP/$ListenPort)"

    # Delete any existing same-named rule before re-adding so the rule
    # always carries the current range scope - and any older
    # interface-pinned rule from a previous version is migrated to it.
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  [firewall] inbound rule '$ruleName' present; refreshing to scope it to $WslNatRange."
        Remove-NetFirewallRule -DisplayName $ruleName
    } else {
        Write-Host "  [firewall] adding inbound TCP/$ListenPort allow from $WslNatRange (WSL NAT range)"
    }

    New-NetFirewallRule `
        -DisplayName   $ruleName `
        -Direction     Inbound `
        -LocalPort     $ListenPort `
        -Protocol      TCP `
        -Action        Allow `
        -RemoteAddress $WslNatRange | Out-Null
}
