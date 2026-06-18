BeforeAll {
    # Stub Resolve-DnsName so the wrapper can be loaded and the
    # underlying cmdlet mocked per test. The real cmdlet hits the
    # network; tests must be deterministic.
    function Resolve-DnsName {
        param(
            [string] $Name,
            [switch] $DnsOnly,
            $ErrorAction
        )
    }

    . "$PSScriptRoot\..\..\Infrastructure.Network.Windows\Public\Ics\Test-HostDnsReachable.ps1"
}

Describe 'Test-HostDnsReachable' {

    It 'returns $true when Resolve-DnsName returns an answer' {
        Mock Resolve-DnsName { [PSCustomObject]@{ IPAddress = '185.125.190.21' } }

        Test-HostDnsReachable | Should -BeTrue
    }

    It 'returns $false when Resolve-DnsName throws (timeout / RST / NXDOMAIN)' {
        Mock Resolve-DnsName { throw 'connection forcibly closed' }

        Test-HostDnsReachable | Should -BeFalse
    }

    It 'resolves via the host''s own resolver - no -Server is passed' {
        # The upstream probe must NOT pin a -Server; that is what makes it
        # the host-side counterpart to Test-IcsDnsReachable. A regression
        # that reintroduced -Server would test the wrong path.
        Mock Resolve-DnsName { [PSCustomObject]@{ IPAddress = '1.1.1.1' } }

        Test-HostDnsReachable | Should -BeTrue
        Should -Invoke Resolve-DnsName -Times 1 -Exactly `
            -ParameterFilter { -not $PSBoundParameters.ContainsKey('Server') }
    }

    It 'probes the fixed archive.ubuntu.com name' {
        Mock Resolve-DnsName { [PSCustomObject]@{ IPAddress = '1.1.1.1' } } `
            -ParameterFilter { $Name -eq 'archive.ubuntu.com' }

        Test-HostDnsReachable | Should -BeTrue
        Should -Invoke Resolve-DnsName -Times 1 -Exactly `
            -ParameterFilter { $Name -eq 'archive.ubuntu.com' }
    }
}
