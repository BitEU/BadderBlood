################################
# ASREP_NotReqPreAuth.ps1 - BadderBlood Realistic AS-REP Roasting
# Only disables pre-auth on a small number of accounts
# to simulate the "vendor said to disable it" scenario.
################################
function ADREP_NotReqPreAuth {
    <#
        .SYNOPSIS
            Disables Kerberos pre-authentication on a small set of accounts.
        .DESCRIPTION
            Simulates the real-world scenario where a vendor or legacy application
            requires pre-auth to be disabled. Only affects a handful of accounts.
        .NOTES
            BadderBlood - Realistic AD Lab Generator
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [Object[]]$UserList
    )

    foreach ($user in $UserList) {
        $user | Set-ADAccountControl -DoesNotRequirePreAuth:$true
        Write-Host "    [!] AS-REP Roastable: $($user.SamAccountName)" -ForegroundColor Yellow
    }
}