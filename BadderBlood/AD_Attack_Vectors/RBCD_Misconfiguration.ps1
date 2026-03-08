################################
# RBCD_Misconfiguration.ps1 - BadderBlood Resource-Based Constrained Delegation
# Simulates realistic RBCD misconfigurations where low-privilege accounts
# can impersonate any user to specific services.
# Common real-world scenario: admin configures RBCD for service migration
# but grants it to an overly broad principal.
################################
function Set-RBCDMisconfiguration {
    <#
        .SYNOPSIS
            Creates realistic Resource-Based Constrained Delegation misconfigurations.
        .DESCRIPTION
            Simulates scenarios where:
            1. A regular user/computer has msDS-AllowedToActOnBehalfOfOtherIdentity set,
               allowing them to impersonate users to that service.
            2. A low-privilege group was granted RBCD delegation to a server during
               a migration that was never cleaned up.
            These are discoverable via BloodHound and Rubeus.
        .PARAMETER RBCDCount
            Number of RBCD misconfigurations to create (default: 3)
        .NOTES
            BadderBlood - Realistic AD Lab Generator
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 20)]
        [int]$RBCDCount = 3
    )

    $dom = Get-ADDomain
    $setDC = $dom.PDCEmulator

    $allComputers = Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity -Server $setDC -ResultSetSize $null
    $allUsers = Get-ADUser -Filter * -Server $setDC -ResultSetSize $null

    # Separate service accounts from regular users
    $serviceAccounts = @($allUsers | Where-Object { $_.SamAccountName -like "*SA" -or $_.SamAccountName -like "svc_*" -or $_.SamAccountName -like "svc-*" })
    $regularUsers = @($allUsers | Where-Object { $_.SamAccountName -notlike "*SA" -and $_.SamAccountName -notlike "svc_*" -and $_.SamAccountName -notlike "svc-*" })

    if ($allComputers.Count -lt 2) {
        Write-Host "    [X] Not enough computers for RBCD misconfiguration" -ForegroundColor Red
        return
    }

    $configured = 0
    $attempts = 0
    $maxAttempts = $RBCDCount * 3

    while ($configured -lt $RBCDCount -and $attempts -lt $maxAttempts) {
        $attempts++

        # Target: a computer that will trust the attacker principal
        $targetComputer = $allComputers | Get-Random

        # Skip if already has RBCD configured
        if ($targetComputer.'msDS-AllowedToActOnBehalfOfOtherIdentity') { continue }

        # Scenario roll: what kind of principal gets RBCD?
        $scenarioRoll = Get-Random -Minimum 1 -Maximum 101

        if ($scenarioRoll -le 40 -and $allComputers.Count -ge 2) {
            # Scenario A (40%): Another computer can delegate to this one
            # Realistic: "We set up RBCD between servers for the migration"
            $sourceComputer = $allComputers | Where-Object { $_.DistinguishedName -ne $targetComputer.DistinguishedName } | Get-Random
            if (-not $sourceComputer) { continue }

            try {
                $sourcePrincipal = Get-ADComputer $sourceComputer -Server $setDC
                Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $sourcePrincipal -Server $setDC -ErrorAction Stop
                Write-Host "    [!] RBCD: '$($sourceComputer.Name)' can delegate to '$($targetComputer.Name)' (migration leftover)" -ForegroundColor Yellow
                $configured++
            } catch {}

        } elseif ($scenarioRoll -le 70 -and $serviceAccounts.Count -gt 0) {
            # Scenario B (30%): A service account can delegate to a server
            # Realistic: "The backup service account needs delegation"
            $svcAccount = $serviceAccounts | Get-Random

            try {
                $svcPrincipal = Get-ADUser $svcAccount -Server $setDC
                Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $svcPrincipal -Server $setDC -ErrorAction Stop
                Write-Host "    [!] RBCD: Service account '$($svcAccount.SamAccountName)' can delegate to '$($targetComputer.Name)'" -ForegroundColor Yellow
                $configured++
            } catch {}

        } else {
            # Scenario C (30%): A regular user can delegate to a server
            # Realistic: "An admin set RBCD on their own account for testing and forgot"
            if ($regularUsers.Count -eq 0) { continue }
            $regularUser = $regularUsers | Get-Random

            try {
                $userPrincipal = Get-ADUser $regularUser -Server $setDC
                Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $userPrincipal -Server $setDC -ErrorAction Stop
                Write-Host "    [!] RBCD: Regular user '$($regularUser.SamAccountName)' can delegate to '$($targetComputer.Name)' (testing leftover)" -ForegroundColor Yellow
                $configured++
            } catch {}
        }
    }

    Write-Host "    [+] Created $configured RBCD misconfigurations" -ForegroundColor Green
}
