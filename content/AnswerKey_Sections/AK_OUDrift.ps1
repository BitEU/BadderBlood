################################
# AK_OUDrift.ps1 - Section 3b: OU Drift Detection (Department Mismatch)
# Dot-sourced by BadderBloodAnswerKey.ps1
################################
function Invoke-AKOUDriftAudit {
    <#
        .SYNOPSIS
            Detects users placed in the wrong department OU.
        .PARAMETER DomainDN
            Domain distinguished name.
        .PARAMETER SetDC
            DC to query.
        .OUTPUTS
            List of findings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN,
        [Parameter(Mandatory)]
        [string]$SetDC
    )

    Write-Status "SECTION 3b: Checking for OU drift (users in wrong department OUs)..."

    $Findings = [System.Collections.Generic.List[PSObject]]::new()

    # Re-fetch users with departmentNumber attribute for drift detection
    $DriftCheckUsers = Get-ADUser -Filter * -Properties Description, departmentNumber, CanonicalName, DistinguishedName -Server $SetDC |
        Where-Object {
            Test-IsBadderBloodObject -Description $_.Description
        }

    $DepartmentCodes = @('BDE','HRE','FIN','OGC','FSR','AWS','ESM','SEC','ITS','GOO','AZR','TST')

    foreach ($user in $DriftCheckUsers) {
        $userDept = $user.departmentNumber
        if (-not $userDept) { continue }

        # Extract the department OU from the user's DN
        $dn = $user.DistinguishedName
        $ouDept = $null
        $dnParts = $dn -split ','
        foreach ($part in $dnParts) {
            $ouName = ($part -replace 'OU=','').Trim()
            if ($ouName -in $DepartmentCodes) {
                $ouDept = $ouName
                break
            }
        }

        # Only flag if both are known and they mismatch, and user is in People OU
        if ($ouDept -and $userDept -and ($ouDept -ne $userDept) -and $dn -like "*OU=People,*") {
            $ri = $SettingRiskExplanations["OUDrift"]
            $Findings.Add((Write-Finding -Category "OU Drift" `
                -Severity "MEDIUM" `
                -Finding "User '$($user.SamAccountName)' (dept: $userDept) is in the wrong department OU ($ouDept)" `
                -CurrentState "Department attribute: $userDept | OU placement: $ouDept" `
                -ExpectedState "Move user to OU=$userDept,OU=People or correct department attribute" `
                -WhyBad $ri.Why `
                -AttackScenario $ri.Attack `
                -Principle $ri.Principle `
                -ObjectDN $user.DistinguishedName))
        }

        # Also flag users in Stage OU (should have been moved)
        if ($dn -like "*OU=Stage,*") {
            $Findings.Add((Write-Finding -Category "OU Drift" `
                -Severity "LOW" `
                -Finding "User '$($user.SamAccountName)' is still in the Stage OU (should be in People)" `
                -CurrentState "Located in Stage OU" `
                -ExpectedState "Move to appropriate People > Department OU" `
                -ObjectDN $user.DistinguishedName))
        }

        # Flag users in Unassociated OU
        if ($dn -like "*OU=Unassociated,*") {
            $Findings.Add((Write-Finding -Category "OU Drift" `
                -Severity "LOW" `
                -Finding "User '$($user.SamAccountName)' is in the Unassociated OU (no department placement)" `
                -CurrentState "Located in Unassociated OU" `
                -ExpectedState "Move to appropriate People > Department OU" `
                -ObjectDN $user.DistinguishedName))
        }
    }

    $Findings
}
