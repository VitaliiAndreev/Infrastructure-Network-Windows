<#
.NOTES
    Do not run this file directly. Dot-sourced by provision.ps1.
#>

# ---------------------------------------------------------------------------
# Set-RouterSshPortProxyFirewall
#   Idempotent Windows Firewall companion to Set-RouterSshPortProxy.
#   Without an allow rule the portproxy listens on 0.0.0.0:<port> but the
#   firewall silently drops inbound TCP from WSL, yielding the
#   "Connection timed out during banner exchange" symptom Ansible
#   surfaces as UNREACHABLE.
#
#   Two firewall regimes, both handled:
#
#   1. Standard Windows Defender Firewall (Win10 WSL, or Win11 WSL with
#      the Hyper-V Firewall feature off). Inbound is filtered per host
#      interface, so an interface-scoped allow on the WSL vEthernet
#      adapter opens the path. Tight scoping: the rule applies ONLY to
#      the WSL vEthernet adapter (alias starts with "vEthernet (WSL");
#      the host's WiFi, Ethernet, and ICS adapters keep the OS-default
#      deny posture - a coffee-shop WiFi cannot reach the router VM.
#
#   2. Hyper-V Firewall (Win11 WSL2 default). WSL runs behind a separate
#      packet filter keyed by the WSL VM creator id, NOT the per-
#      interface Defender rules - so the regime-1 rule is bypassed and
#      its DefaultInboundAction (Block) drops WSL's SYN before it ever
#      reaches the portproxy listener. This is the exact failure the
#      interface rule alone could not fix. When that regime is present
#      we add the matching Hyper-V allow rule keyed to the WSL creator.
#
#   Both rules are additive and idempotent; on a given host only the
#   regime in force actually governs traffic, and adding the inert one
#   is harmless. No-op on hosts without a WSL adapter installed; the
#   rest of the provisioner stays usable on Linux/Mac developer boxes
#   that exercise these helpers via Pester.
# ---------------------------------------------------------------------------

function Set-RouterSshPortProxyFirewall {
    [CmdletBinding()]
    param(
        # Listen port the inbound rule covers. Must match the
        # Set-RouterSshPortProxy listen port - same default.
        [int] $ListenPort = 2222
    )

    # Discover the WSL vEthernet adapter (if any). Get-NetAdapter
    # returns nothing on hosts without WSL installed.
    $wslAdapter = Get-NetAdapter -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -like 'vEthernet (WSL*' } |
                  Select-Object -First 1

    if (-not $wslAdapter) {
        Write-Host "  [firewall] no vEthernet (WSL*) adapter found; skipping firewall rule (WSL probably not installed)."
        return
    }

    $ruleName = "Vm-Provisioner: WSL -> router SSH portproxy (TCP/$ListenPort)"

    # -----------------------------------------------------------------
    # Regime 1: standard Defender interface-scoped allow. Governs WSL
    # on Win10 and on Win11 hosts with the Hyper-V Firewall feature off.
    # -----------------------------------------------------------------
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  [firewall] inbound rule '$ruleName' already present on '$($wslAdapter.Name)', skipping."
    }
    else {
        Write-Host "  [firewall] adding inbound TCP/$ListenPort allow on '$($wslAdapter.Name)' (WSL-only scope)"
        New-NetFirewallRule `
            -DisplayName    $ruleName `
            -Direction      Inbound `
            -LocalPort      $ListenPort `
            -Protocol       TCP `
            -Action         Allow `
            -InterfaceAlias $wslAdapter.Name | Out-Null
    }

    # -----------------------------------------------------------------
    # Regime 2: Hyper-V Firewall allow keyed to the WSL VM creator.
    # Inert (early-returns) wherever the regime is not in force, guarded
    # three ways: the Hyper-V cmdlets must exist (older Windows lacks
    # them), a WSL VM creator must be registered (else WSL is not behind
    # the Hyper-V Firewall and regime 1 already governs it), and a
    # matching rule must not already exist (idempotency).
    # -----------------------------------------------------------------
    if (-not (Get-Command New-NetFirewallHyperVRule -ErrorAction SilentlyContinue)) {
        return
    }

    $wslCreator = Get-NetFirewallHyperVVMCreator -ErrorAction SilentlyContinue |
                  Where-Object { $_.FriendlyName -eq 'WSL' } |
                  Select-Object -First 1
    if (-not $wslCreator) {
        return
    }

    # Stable Name (not just DisplayName) so the idempotency lookup is
    # exact. DisplayName mirrors the Defender rule for operator parity.
    $hvRuleName = 'VmProvisioner-WSL-RouterSshPortproxy'

    $hvExisting = Get-NetFirewallHyperVRule -Name $hvRuleName -ErrorAction SilentlyContinue
    if ($hvExisting) {
        Write-Host "  [firewall] Hyper-V allow rule '$hvRuleName' already present, skipping."
        return
    }

    Write-Host "  [firewall] adding Hyper-V inbound TCP/$ListenPort allow for WSL creator '$($wslCreator.VMCreatorId)'"
    New-NetFirewallHyperVRule `
        -Name        $hvRuleName `
        -DisplayName $ruleName `
        -Direction   Inbound `
        -VMCreatorId $wslCreator.VMCreatorId `
        -Protocol    TCP `
        -LocalPorts  $ListenPort `
        -Action      Allow | Out-Null
}
