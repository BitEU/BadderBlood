################################
# AK_SIDHistory.ps1 - Section 7b: SID History on Groups
# Dot-sourced by BadderBloodAnswerKey.ps1
################################
function Invoke-AKSIDHistoryAudit {
    <#
        .SYNOPSIS
            Checks for SID History entries on groups (hidden privilege escalation).
        .OUTPUTS
            List of findings.
    #>
    [CmdletBinding()]
    param()

    Write-Status "SECTION 7b: Checking for SID History on groups..."

    $Findings = [System.Collections.Generic.List[PSObject]]::new()

    $AllGroupsWithSIDHistory = Get-ADGroup -Filter * -Properties SIDHistory, Description
    foreach ($group in $AllGroupsWithSIDHistory) {
        if ($group.SIDHistory.Count -gt 0) {
            $Findings.Add((Write-Finding -Category "SID History" `
                -Severity "CRITICAL" `
                -Finding "Group '$($group.SamAccountName)' has SID History entries (hidden privilege escalation)" `
                -CurrentState "SIDHistory contains $($group.SIDHistory.Count) entries: $($group.SIDHistory -join ', ')" `
                -ExpectedState "SIDHistory should be empty (clear all entries)" `
                -WhyBad "SID History on a group grants ALL members invisible privileges. Standard group membership queries won't reveal the effective access." `
                -AttackScenario "Join the group -> inherit hidden SID (DA/EA/Administrators) -> invisible admin rights not shown by Get-ADGroupMember." `
                -Principle "SID History should be empty unless actively migrating domains. On groups it is especially dangerous as it multiplies the blast radius." `
                -ObjectDN $group.DistinguishedName))
        }
    }

    $Findings
}
