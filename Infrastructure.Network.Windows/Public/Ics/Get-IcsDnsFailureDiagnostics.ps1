<#
.NOTES
    Do not run this file directly. Dot-sourced by provision.ps1. Called by
    Test-IcsDnsProxyReachable when the proxy stays unreachable after repair.
#>

# ---------------------------------------------------------------------------
# Get-IcsDnsFailureDiagnostics
#   Turns a dead ICS DNS proxy into a single next action. When the proxy
#   probe fails (and Reset-IcsSharing did not recover it), three very
#   different host states produce the SAME symptom, each with a
#   different fix:
#
#     1. SharedAccess service not Running - ICS's proxy + NAT are this
#        service; if it is stopped/hung nothing answers. Fix: start it.
#     2. Host's own upstream DNS also dead - the proxy has nothing to
#        forward to. Fix: the host network (WiFi / no internet), NOT ICS.
#     3. Service Running and host DNS fine, but the proxy still does not
#        answer - the proxy itself is wedged. Fix: restart + re-toggle,
#        then reboot (ICS state is sticky).
#
#   The terminal FAIL used to hand the operator a checklist of these to
#   walk by hand; this probes the two distinguishing signals (service
#   status + an upstream-side resolve) and returns the one verdict that
#   applies, so the FAIL detail names the fix instead of the checklist.
#
#   Read-only: Get-Service is a status read and Test-HostDnsReachable is
#   a resolve. Safe to call on the failure path without changing host
#   state further. Both signals degrade gracefully - a missing service
#   reads as 'not found', a failed resolve as $false - so gathering
#   diagnostics never masks the original proxy FAIL with an error.
# ---------------------------------------------------------------------------

function Get-IcsDnsFailureDiagnostics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $DnsProbeTarget
    )

    $svc       = Get-Service -Name 'SharedAccess' -ErrorAction SilentlyContinue
    $svcStatus = if ($svc) { [string]$svc.Status } else { 'not found' }
    $hostDnsOk = Test-HostDnsReachable

    # Order matters: a stopped service explains everything downstream, so
    # it is reported first; a dead upstream is the next most fundamental;
    # only when both are healthy is the proxy itself the culprit.
    $verdict =
        if ($svcStatus -ne 'Running') {
            "SharedAccess service is '$svcStatus' (not Running) - start it: Start-Service SharedAccess."
        }
        elseif (-not $hostDnsOk) {
            "Host's own upstream DNS cannot resolve archive.ubuntu.com either - " +
            "the fault is the host network (WiFi DNS / no internet), not ICS. " +
            "Toggling sharing will not help; restore host connectivity first."
        }
        else {
            "SharedAccess is Running and the host's own DNS resolves, but the " +
            "proxy at $DnsProbeTarget does not answer - the ICS proxy is wedged. " +
            "Restart-Service SharedAccess then re-toggle sharing; if it still " +
            "fails, reboot (ICS state is sticky)."
        }

    $hostDnsLabel = if ($hostDnsOk) { 'OK' } else { 'FAIL' }
    "SharedAccess=$svcStatus; host upstream DNS=$hostDnsLabel. $verdict"
}
