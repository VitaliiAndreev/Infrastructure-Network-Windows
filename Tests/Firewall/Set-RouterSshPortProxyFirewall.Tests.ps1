BeforeAll {
    # Stub the Windows Firewall + NetAdapter cmdlets so the source can
    # be dot-sourced and every call Mocked per test. Stubbing them as
    # functions also lets the source run on Linux/Mac CI where the real
    # cmdlets do not exist, and shields a Windows dev box that DOES have
    # them from a unit test mutating real firewall state.
    function Get-NetAdapter         { param($ErrorAction) }
    function Get-NetFirewallRule    { param([string] $DisplayName, $ErrorAction) }
    function Remove-NetFirewallRule { param([string] $DisplayName) }
    function New-NetFirewallRule {
        param(
            [string] $DisplayName,
            [string] $Direction,
            [int]    $LocalPort,
            [string] $Protocol,
            [string] $Action,
            [string] $RemoteAddress
        )
    }

    . "$PSScriptRoot\..\..\Infrastructure.Network.Windows\Public\Firewall\Set-RouterSshPortProxyFirewall.ps1"

    function New-WslAdapter {
        [PSCustomObject]@{ Name = 'vEthernet (WSL (Hyper-V firewall))' }
    }
}

Describe 'Set-RouterSshPortProxyFirewall' {

    Context 'no WSL adapter present' {

        It 'skips the rule add without erroring' {
            # Real Get-NetAdapter emits nothing (empty pipeline) on
            # hosts without a WSL adapter - not $null. Match that.
            Mock Get-NetAdapter         { }
            Mock New-NetFirewallRule    { }
            Mock Remove-NetFirewallRule { }

            Set-RouterSshPortProxyFirewall

            Should -Invoke New-NetFirewallRule    -Times 0
            Should -Invoke Remove-NetFirewallRule -Times 0
        }
    }

    Context 'WSL adapter present, no existing rule' {

        It 'creates an inbound TCP allow scoped to the WSL NAT range, not an interface' {
            Mock Get-NetAdapter         { New-WslAdapter }
            Mock Get-NetFirewallRule    { $null }
            Mock New-NetFirewallRule    { }
            Mock Remove-NetFirewallRule { }

            Set-RouterSshPortProxyFirewall

            Should -Invoke New-NetFirewallRule -Times 1 -Exactly -ParameterFilter {
                $Direction     -eq 'Inbound'        -and
                $LocalPort     -eq 2222             -and
                $Protocol      -eq 'TCP'            -and
                $Action        -eq 'Allow'          -and
                $RemoteAddress -eq '172.16.0.0/12'
            }
        }

        It 'does not attempt a delete when there is nothing to refresh' {
            Mock Get-NetAdapter         { New-WslAdapter }
            Mock Get-NetFirewallRule    { $null }
            Mock New-NetFirewallRule    { }
            Mock Remove-NetFirewallRule { }

            Set-RouterSshPortProxyFirewall

            Should -Invoke Remove-NetFirewallRule -Times 0
        }

        It 'passes the operator-supplied ListenPort through' {
            Mock Get-NetAdapter         { New-WslAdapter }
            Mock Get-NetFirewallRule    { $null }
            Mock New-NetFirewallRule    { }
            Mock Remove-NetFirewallRule { }

            Set-RouterSshPortProxyFirewall -ListenPort 8222

            Should -Invoke New-NetFirewallRule -Times 1 -Exactly -ParameterFilter {
                $LocalPort -eq 8222
            }
        }

        It 'passes an operator-supplied WslNatRange through' {
            Mock Get-NetAdapter         { New-WslAdapter }
            Mock Get-NetFirewallRule    { $null }
            Mock New-NetFirewallRule    { }
            Mock Remove-NetFirewallRule { }

            Set-RouterSshPortProxyFirewall -WslNatRange '172.29.96.0/20'

            Should -Invoke New-NetFirewallRule -Times 1 -Exactly -ParameterFilter {
                $RemoteAddress -eq '172.29.96.0/20'
            }
        }
    }

    Context 'WSL adapter present, matching rule already exists' {

        It 'refreshes the rule (delete + re-add) so it carries the current range scope' {
            # A same-named rule from a previous version may be pinned to
            # an interface; deleting and re-adding migrates it to the
            # range-scoped form. Both calls must fire.
            Mock Get-NetAdapter      { New-WslAdapter }
            Mock Get-NetFirewallRule {
                [PSCustomObject]@{
                    DisplayName = 'Vm-Provisioner: WSL -> router SSH portproxy (TCP/2222)'
                }
            }
            Mock New-NetFirewallRule    { }
            Mock Remove-NetFirewallRule { }

            Set-RouterSshPortProxyFirewall

            Should -Invoke Remove-NetFirewallRule -Times 1 -Exactly -ParameterFilter {
                $DisplayName -eq 'Vm-Provisioner: WSL -> router SSH portproxy (TCP/2222)'
            }
            Should -Invoke New-NetFirewallRule -Times 1 -Exactly -ParameterFilter {
                $RemoteAddress -eq '172.16.0.0/12'
            }
        }
    }
}
