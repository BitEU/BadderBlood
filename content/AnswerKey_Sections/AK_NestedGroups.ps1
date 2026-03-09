################################
# AK_NestedGroups.ps1 - Section 4: Nested Group Membership Chains
# Dot-sourced by BadderBloodAnswerKey.ps1
################################
function Invoke-AKNestedGroupAudit {
    <#
        .SYNOPSIS
            Analyzes nested group membership chains in privileged groups.
        .OUTPUTS
            List of findings.
    #>
    [CmdletBinding()]
    param()

    Write-Status "SECTION 4: Analyzing nested group membership chains..."

    $Findings = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($groupName in $PrivilegedGroups) {
        try {
            $directMembers = Get-ADGroupMember $groupName -ErrorAction SilentlyContinue
            $nestedGroups = $directMembers | Where-Object { $_.objectClass -eq "group" }

            foreach ($nestedGroup in $nestedGroups) {
                $ngDesc = (Get-ADGroup $nestedGroup.SamAccountName -Properties Description).Description
                $isBB = Test-IsBadderBloodObject -Description $ngDesc

                $Findings.Add((Write-Finding -Category "Nested Group Membership" `
                    -Severity "HIGH" `
                    -Finding "Group '$($nestedGroup.SamAccountName)' is nested inside '$groupName'" `
                    -CurrentState "Nested member of $groupName (BadderBlood: $isBB)" `
                    -ExpectedState "REMOVE group nesting - evaluate each member individually" `
                    -ObjectDN $nestedGroup.distinguishedName))
            }
        }
        catch {}
    }

    $Findings
}
