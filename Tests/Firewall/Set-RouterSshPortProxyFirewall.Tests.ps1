BeforeAll {
    # Stub the Windows Firewall + NetAdapter cmdlets so the source
    # can be dot-sourced and the calls Mocked per test. Both firewall
    # regimes are stubbed: the Defender interface path and the Hyper-V
    # Firewall path.
    function Get-NetAdapter        { param($ErrorAction) }
    function Get-NetFirewallRule   { param([string] $DisplayName, $ErrorAction) }
    function New-NetFirewallRule {
        param(
            [string] $DisplayName,
            [string] $Direction,
            [int]    $LocalPort,
            [string] $Protocol,
            [string] $Action,
            [string] $InterfaceAlias
        )
    }
    function Get-NetFirewallHyperVVMCreator { param($ErrorAction) }
    function Get-NetFirewallHyperVRule      { param([string] $Name, $ErrorAction) }
    function New-NetFirewallHyperVRule {
        param(
            [string] $Name,
            [string] $DisplayName,
            [string] $Direction,
            [string] $VMCreatorId,
            [string] $Protocol,
            [int]    $LocalPorts,
            [string] $Action
        )
    }

    . "$PSScriptRoot\..\..\Infrastructure.Network.Windows\Public\Firewall\Set-RouterSshPortProxyFirewall.ps1"

    function New-WslAdapter {
        [PSCustomObject]@{ Name = 'vEthernet (WSL (Hyper-V firewall))' }
    }

    function New-WslCreator {
        [PSCustomObject]@{
            FriendlyName = 'WSL'
            VMCreatorId  = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'
        }
    }
}

Describe 'Set-RouterSshPortProxyFirewall' {

    Context 'no WSL adapter present' {

        It 'skips the rule add without erroring' {
            # Real Get-NetAdapter emits nothing (empty pipeline) on
            # hosts without a WSL adapter - not $null. Match that.
            Mock Get-NetAdapter { }
            Mock New-NetFirewallRule { }
            Mock New-NetFirewallHyperVRule { }

            Set-RouterSshPortProxyFirewall

            Should -Invoke New-NetFirewallRule -Times 0
            Should -Invoke New-NetFirewallHyperVRule -Times 0
        }
    }

    Context 'WSL adapter present, Defender regime only (no Hyper-V Firewall)' {

        # No WSL VM creator registered => the Hyper-V Firewall regime is
        # not in force, so only the Defender interface rule is added.
        BeforeEach {
            Mock Get-NetFirewallHyperVVMCreator { }
            Mock New-NetFirewallHyperVRule { }
        }

        It 'creates an inbound TCP allow rule scoped to the WSL adapter' {
            Mock Get-NetAdapter      { New-WslAdapter }
            Mock Get-NetFirewallRule { $null }
            Mock New-NetFirewallRule { }

            Set-RouterSshPortProxyFirewall

            Should -Invoke New-NetFirewallRule -Times 1 -Exactly -ParameterFilter {
                $Direction      -eq 'Inbound'     -and
                $LocalPort      -eq 2222          -and
                $Protocol       -eq 'TCP'         -and
                $Action         -eq 'Allow'       -and
                $InterfaceAlias -eq 'vEthernet (WSL (Hyper-V firewall))'
            }
            Should -Invoke New-NetFirewallHyperVRule -Times 0
        }

        It 'passes the operator-supplied ListenPort through' {
            Mock Get-NetAdapter      { New-WslAdapter }
            Mock Get-NetFirewallRule { $null }
            Mock New-NetFirewallRule { }

            Set-RouterSshPortProxyFirewall -ListenPort 8222

            Should -Invoke New-NetFirewallRule -Times 1 -Exactly -ParameterFilter {
                $LocalPort -eq 8222
            }
        }
    }

    Context 'WSL adapter present, matching Defender rule already exists' {

        # Hyper-V regime absent so the existing-rule skip is isolated to
        # the Defender path under test.
        BeforeEach {
            Mock Get-NetFirewallHyperVVMCreator { }
            Mock New-NetFirewallHyperVRule { }
        }

        It 'skips the Defender add (idempotency)' {
            Mock Get-NetAdapter      { New-WslAdapter }
            Mock Get-NetFirewallRule {
                [PSCustomObject]@{
                    DisplayName = 'Vm-Provisioner: WSL -> router SSH portproxy (TCP/2222)'
                }
            }
            Mock New-NetFirewallRule { }

            Set-RouterSshPortProxyFirewall

            Should -Invoke New-NetFirewallRule -Times 0
        }
    }

    Context 'Hyper-V Firewall regime present (WSL VM creator registered)' {

        # The Defender rule is treated as already present in every test
        # here so assertions focus on the Hyper-V path.
        BeforeEach {
            Mock Get-NetAdapter      { New-WslAdapter }
            Mock Get-NetFirewallRule {
                [PSCustomObject]@{
                    DisplayName = 'Vm-Provisioner: WSL -> router SSH portproxy (TCP/2222)'
                }
            }
            Mock New-NetFirewallRule { }
        }

        It 'adds a Hyper-V allow rule keyed to the WSL VM creator' {
            Mock Get-NetFirewallHyperVVMCreator { New-WslCreator }
            Mock Get-NetFirewallHyperVRule { $null }
            Mock New-NetFirewallHyperVRule { }

            Set-RouterSshPortProxyFirewall

            Should -Invoke New-NetFirewallHyperVRule -Times 1 -Exactly -ParameterFilter {
                $Direction   -eq 'Inbound'                                -and
                $LocalPorts  -eq 2222                                     -and
                $Protocol    -eq 'TCP'                                    -and
                $Action      -eq 'Allow'                                  -and
                $VMCreatorId -eq '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -and
                $Name        -eq 'VmProvisioner-WSL-RouterSshPortproxy'
            }
        }

        It 'passes the operator-supplied ListenPort to the Hyper-V rule' {
            Mock Get-NetFirewallHyperVVMCreator { New-WslCreator }
            Mock Get-NetFirewallHyperVRule { $null }
            Mock New-NetFirewallHyperVRule { }

            Set-RouterSshPortProxyFirewall -ListenPort 8222

            Should -Invoke New-NetFirewallHyperVRule -Times 1 -Exactly -ParameterFilter {
                $LocalPorts -eq 8222
            }
        }

        It 'skips the Hyper-V add when a matching rule already exists (idempotency)' {
            Mock Get-NetFirewallHyperVVMCreator { New-WslCreator }
            Mock Get-NetFirewallHyperVRule {
                [PSCustomObject]@{ Name = 'VmProvisioner-WSL-RouterSshPortproxy' }
            }
            Mock New-NetFirewallHyperVRule { }

            Set-RouterSshPortProxyFirewall

            Should -Invoke New-NetFirewallHyperVRule -Times 0
        }

        It 'adds no Hyper-V rule when no WSL VM creator is registered' {
            Mock Get-NetFirewallHyperVVMCreator { }
            Mock Get-NetFirewallHyperVRule { $null }
            Mock New-NetFirewallHyperVRule { }

            Set-RouterSshPortProxyFirewall

            Should -Invoke New-NetFirewallHyperVRule -Times 0
        }
    }
}
