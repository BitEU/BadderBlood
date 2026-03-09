################################
# AK_Computers.ps1 - Section 8: Computer Object Analysis
# Dot-sourced by BadderBloodAnswerKey.ps1
################################
function Invoke-AKComputerAudit {
    <#
        .SYNOPSIS
            Analyzes computer objects for delegation and group membership issues.
        .PARAMETER BadderBloodGroups
            Groups created by BadderBlood.
        .OUTPUTS
            PSCustomObject with Findings and Computers list.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$BadderBloodGroups
    )

    Write-Status "SECTION 8: Analyzing computer objects..."

    $Findings = [System.Collections.Generic.List[PSObject]]::new()

    $Computers = Get-ADComputer -Filter * -Properties Description, MemberOf, TrustedForDelegation, CanonicalName

    $BadderBloodGroupDNs = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($g in $BadderBloodGroups) { [void]$BadderBloodGroupDNs.Add($g.DistinguishedName) }

    foreach ($comp in $Computers) {
        if ($comp.TrustedForDelegation -and $comp.Name -notlike "*DC*") {
            $Findings.Add((Write-Finding -Category "Delegation" `
                -Severity "HIGH" `
                -Finding "Computer '$($comp.Name)' has unconstrained delegation enabled" `
                -CurrentState "TrustedForDelegation = True" `
                -ExpectedState "TrustedForDelegation = False (unless this is a DC)" `
                -ObjectDN $comp.DistinguishedName))
        }

        # Computer membership in BadderBlood-created security groups
        $bbGroupMemberships = @($comp.MemberOf | Where-Object { $BadderBloodGroupDNs.Contains($_) })
        if ($bbGroupMemberships.Count -gt 0) {
            $groupNames = $bbGroupMemberships | ForEach-Object {
                ($_ -split ',')[0] -replace '^CN=',''
            }
            $Findings.Add((Write-Finding -Category "Computer Group Membership" `
                -Severity "MEDIUM" `
                -Finding "Computer '$($comp.Name)' is a member of $($bbGroupMemberships.Count) BadderBlood-created security group(s)" `
                -CurrentState "Member of: $($groupNames -join ', ')" `
                -ExpectedState "Remove computer from BadderBlood-created groups (computers should not be members of random security groups)" `
                -WhyBad "Computer accounts in security groups can inherit group-based permissions, receive GPOs scoped to those groups, or be used as a lateral movement pivot if the group grants access to other resources." `
                -AttackScenario "Compromise computer account (e.g., via NTLM relay) -> inherit group permissions -> access group-scoped resources without valid user credentials." `
                -Principle "Computer objects should only be in groups where membership is intentional and documented (e.g., software deployment groups). Random group membership from BadderBlood is never intentional." `
                -ObjectDN $comp.DistinguishedName))
        }
    }

    [PSCustomObject]@{
        Findings  = $Findings
        Computers = $Computers
    }
}
