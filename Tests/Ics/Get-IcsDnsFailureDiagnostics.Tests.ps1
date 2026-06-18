BeforeAll {
    # Get-Service is Windows-only and Test-HostDnsReachable hits the
    # network; stub both so the verdict logic is tested deterministically
    # on any runner.
    function Get-Service          { param([string] $Name, $ErrorAction) }
    function Test-HostDnsReachable { }

    . "$PSScriptRoot\..\..\Infrastructure.Network.Windows\Public\Ics\Get-IcsDnsFailureDiagnostics.ps1"
}

Describe 'Get-IcsDnsFailureDiagnostics' {

    Context 'SharedAccess service is not Running' {

        It 'names Start-Service as the fix and skips the proxy-wedged verdict' {
            Mock Get-Service { [PSCustomObject]@{ Status = 'Stopped' } }
            Mock Test-HostDnsReachable { $true }   # irrelevant - service wins

            $detail = Get-IcsDnsFailureDiagnostics -DnsProbeTarget '192.168.137.1'

            $detail | Should -Match 'SharedAccess=Stopped'
            $detail | Should -Match 'Start-Service SharedAccess'
            $detail | Should -Not -Match 'proxy is wedged'
        }

        It 'reports ''not found'' when the service is absent' {
            Mock Get-Service { $null }
            Mock Test-HostDnsReachable { $true }

            $detail = Get-IcsDnsFailureDiagnostics -DnsProbeTarget '192.168.137.1'

            $detail | Should -Match 'SharedAccess=not found'
            $detail | Should -Match 'Start-Service SharedAccess'
        }
    }

    Context 'service Running but host upstream DNS is also dead' {

        It 'blames the host network, not ICS' {
            Mock Get-Service { [PSCustomObject]@{ Status = 'Running' } }
            Mock Test-HostDnsReachable { $false }

            $detail = Get-IcsDnsFailureDiagnostics -DnsProbeTarget '192.168.137.1'

            $detail | Should -Match 'host upstream DNS=FAIL'
            $detail | Should -Match 'not ICS'
            $detail | Should -Not -Match 'Start-Service'
        }
    }

    Context 'service Running and host DNS fine - proxy itself wedged' {

        It 'points at restart + reboot and echoes the probe target' {
            Mock Get-Service { [PSCustomObject]@{ Status = 'Running' } }
            Mock Test-HostDnsReachable { $true }

            $detail = Get-IcsDnsFailureDiagnostics -DnsProbeTarget '10.20.30.40'

            $detail | Should -Match 'SharedAccess=Running'
            $detail | Should -Match 'host upstream DNS=OK'
            $detail | Should -Match 'proxy at 10\.20\.30\.40 does not answer'
            $detail | Should -Match 'reboot'
        }
    }
}
