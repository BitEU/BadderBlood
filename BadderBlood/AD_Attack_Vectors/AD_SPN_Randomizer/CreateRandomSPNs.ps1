################################
# CreateRandomSPNs.ps1 - BadderBlood Realistic SPN Assignment
# SPNs are assigned to service accounts (not random users) with
# realistic service types (MSSQLSvc, HTTP, etc.)
################################
Function CreateRandomSPNs {
    <#
        .SYNOPSIS
            Creates realistic SPNs on service accounts to simulate Kerberoasting targets.
        .DESCRIPTION
            Instead of spraying random SPNs on random users, this assigns realistic
            service SPNs (SQL, HTTP, etc.) primarily to service accounts, with a few
            on regular users to simulate real-world misconfiguration.
        .NOTES
            BadderBlood - Realistic AD Lab Generator
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [int32]$SPNCount = 12
    )

    $computers = Get-ADComputer -Filter *
    $allUsers = Get-ADUser -Filter *

    # Separate service accounts from regular users
    $serviceAccounts = $allUsers | Where-Object { $_.SamAccountName -like "*SA" -or $_.SamAccountName -like "svc_*" -or $_.SamAccountName -like "svc-*" }
    $regularUsers = $allUsers | Where-Object { $_.SamAccountName -notlike "*SA" -and $_.SamAccountName -notlike "svc_*" -and $_.SamAccountName -notlike "svc-*" }

    # If no service accounts found, use random users
    if (!$serviceAccounts -or $serviceAccounts.Count -eq 0) {
        $serviceAccounts = $allUsers | Get-Random -Count ([Math]::Min(10, $allUsers.Count))
    }

    # Realistic SPN service types
    $realisticSPNs = @(
        @{Service = 'MSSQLSvc'; Port = '1433'; Desc = 'SQL Server'},
        @{Service = 'MSSQLSvc'; Port = '1434'; Desc = 'SQL Browser'},
        @{Service = 'HTTP'; Port = ''; Desc = 'Web Application'},
        @{Service = 'HTTP'; Port = '8080'; Desc = 'Web App Alt Port'},
        @{Service = 'HTTP'; Port = '443'; Desc = 'HTTPS Application'},
        @{Service = 'TERMSRV'; Port = ''; Desc = 'Remote Desktop'},
        @{Service = 'exchangeMDB'; Port = ''; Desc = 'Exchange'},
        @{Service = 'SIP'; Port = ''; Desc = 'Skype/Lync'},
        @{Service = 'FTP'; Port = ''; Desc = 'Legacy FTP'},
        @{Service = 'CIFS'; Port = ''; Desc = 'File Share'},
        @{Service = 'MSSQLSvc'; Port = '4022'; Desc = 'SQL Broker'},
        @{Service = 'HTTP'; Port = '8443'; Desc = 'Management Console'}
    )

    $i = 0
    Do {
        $spnTemplate = $realisticSPNs | Get-Random
        $computer = $computers | Get-Random

        # 80% on service accounts, 20% on regular users (the misconfiguration)
        $targetRoll = Get-Random -Minimum 1 -Maximum 101
        if ($targetRoll -le 80 -and $serviceAccounts.Count -gt 0) {
            $user = $serviceAccounts | Get-Random
        } else {
            $user = $regularUsers | Get-Random
        }

        $cn = $computer.DNSHostName
        if (!$cn) { $cn = $computer.Name }

        if ($spnTemplate.Port -and $spnTemplate.Port -ne '') {
            $spn = "$($spnTemplate.Service)/${cn}:$($spnTemplate.Port)"
        } else {
            $spn = "$($spnTemplate.Service)/$cn"
        }

        Try {
            $user | Set-ADUser -ServicePrincipalNames @{Add = $spn } -ErrorAction Stop
            Write-Host "    [+] SPN '$spn' -> $($user.SamAccountName) ($($spnTemplate.Desc))" -ForegroundColor Gray
        } Catch { $i-- }

        $i++
    } While ($i -lt $SPNCount)
}