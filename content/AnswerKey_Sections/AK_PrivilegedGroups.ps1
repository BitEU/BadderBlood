################################
# AK_PrivilegedGroups.ps1 - Section 2: Privileged Group Membership Violations
# Dot-sourced by BadderBloodAnswerKey.ps1
################################
function Invoke-AKPrivilegedGroupAudit {
    <#
        .SYNOPSIS
            Audits privileged group memberships for unauthorized users.
        .PARAMETER AllUsers
            All AD users (pre-fetched).
        .PARAMETER BadderBloodUsers
            Users created by BadderBlood.
        .PARAMETER UserContextMap
            Hashtable mapping SamAccountName to context info.
        .OUTPUTS
            PSCustomObject with Findings (list) and PrivGroupReport (list).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$AllUsers,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$BadderBloodUsers,
        [Parameter(Mandatory)]
        [hashtable]$UserContextMap
    )

    Write-Status "SECTION 2: Auditing privileged group memberships..."

    $Findings = [System.Collections.Generic.List[PSObject]]::new()
    $PrivGroupReport = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($groupName in $PrivilegedGroups) {
        try {
            $group = Get-ADGroup $groupName -Properties Members
            $members = Get-ADGroupMember $groupName -Recursive -ErrorAction SilentlyContinue

            foreach ($member in $members) {
                $isLegitimate = $LegitimatePrivilegedAccounts -contains $member.SamAccountName
                $isBadderBlood = $false

                if ($member.objectClass -eq "user") {
                    $userObj = $AllUsers | Where-Object { $_.SamAccountName -eq $member.SamAccountName }
                    if ($userObj) {
                        $isBadderBlood = Test-IsBadderBloodObject -Description $userObj.Description
                    }
                }

                $ctx = $UserContextMap[$member.SamAccountName]
                $dept = if ($ctx) { $ctx.Department } else { "Unknown" }
                $ouPath = if ($ctx) { $ctx.FriendlyOU } else { "Unknown" }

                $privEntry = [PSCustomObject]@{
                    PrivilegedGroup      = $groupName
                    MemberName           = $member.SamAccountName
                    MemberType           = $member.objectClass
                    MemberDN             = $member.distinguishedName
                    Department           = $dept
                    OUPath               = $ouPath
                    IsLegitimate         = $isLegitimate
                    IsBadderBloodCreated = $isBadderBlood
                    Action               = if ($isLegitimate) { "KEEP" } else { "REMOVE" }
                }
                $PrivGroupReport.Add($privEntry)

                if (-not $isLegitimate) {
                    $sev = if ($groupName -in $Tier0Groups) { "CRITICAL" } else { "HIGH" }
                    $gi = $GroupRiskExplanations[$groupName]

                    $contextNote = "User is in '$ouPath' (Dept: $dept). "
                    if ($dept -ne "Admin" -and $dept -notlike "*Tier*") {
                        $contextNote += "As a regular departmental user, they have NO business reason to be in '$groupName'."
                    } else {
                        $contextNote += "Even in an admin OU, they should use a DEDICATED admin account."
                    }

                    $finding = Write-Finding -Category "Privileged Group Membership" `
                        -Severity $sev `
                        -Finding "User '$($member.SamAccountName)' (Dept: $dept, OU: $ouPath) is a member of '$groupName'" `
                        -CurrentState "Member of $groupName | Risk: $(if($gi){$gi.Risk}else{'ELEVATED'})" `
                        -ExpectedState "REMOVE from $groupName" `
                        -WhyBad $(if($gi){$gi.Why}else{"Elevated privileges regular users should not have."}) `
                        -AttackScenario $(if($gi){$gi.Attack}else{"Compromising this user inherits all $groupName privileges."}) `
                        -UserContext $contextNote `
                        -Principle $(if($gi){$gi.Principle}else{"Least Privilege."}) `
                        -ObjectDN $member.distinguishedName
                    $Findings.Add($finding)
                }
            }
        }
        catch {
            Write-Warning "Could not query group: $groupName - $_"
        }
    }

    $ViolationCount = ($PrivGroupReport | Where-Object { $_.Action -eq "REMOVE" }).Count
    Write-Status "Found $ViolationCount privileged group membership violations" "Red"

    [PSCustomObject]@{
        Findings       = $Findings
        PrivGroupReport = $PrivGroupReport
    }
}
