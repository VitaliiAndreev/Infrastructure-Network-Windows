<#
.NOTES
    Do not run this file directly. Dot-sourced by provision.ps1.
#>

# ---------------------------------------------------------------------------
# Test-HostDnsReachable
#   Sibling of Test-IcsDnsReachable that resolves via the HOST'S OWN
#   configured resolver (no -Server) instead of a specific upstream.
#   This is the WiFi-side DNS that ICS's proxy forwards to, so it
#   answers a different question than Test-IcsDnsReachable: "can the
#   host resolve at all", not "does the ICS proxy answer".
#
#   The distinction is load-bearing for diagnosis. If the ICS proxy
#   probe fails but THIS succeeds, the proxy is wedged (toggle / restart
#   / reboot). If THIS also fails, the host's upstream network is down
#   and no amount of ICS toggling will help - the proxy has nothing to
#   forward to.
#
#   Same probe target (archive.ubuntu.com) and same any-error-is-false
#   contract as Test-IcsDnsReachable; see that file for the rationale on
#   both.
# ---------------------------------------------------------------------------

function Test-HostDnsReachable {
    [CmdletBinding()]
    param()

    try {
        $result = Resolve-DnsName -Name 'archive.ubuntu.com' `
                                  -DnsOnly `
                                  -ErrorAction Stop
        return [bool]$result
    } catch {
        return $false
    }
}
