################################
# AK_OUStructure.ps1 - Section 5: OU Structure Analysis
# Dot-sourced by BadderBloodAnswerKey.ps1
################################
function Invoke-AKOUStructureAudit {
    <#
        .SYNOPSIS
            Analyzes OU placement of BadderBlood users relative to their privileges.
        .PARAMETER BadderBloodUsers
            Users created by BadderBlood.
        .OUTPUTS
            List of findings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$BadderBloodUsers
    )

    Write-Status "SECTION 5: Analyzing OU structure..."

    $Findings = [System.Collections.Generic.List[PSObject]]::new()

    # PRE-CALCULATE: Get all privileged members ONCE and store in a HashSet for instant lookup
    $PrivilegedMemberSIDs = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($grpName in $PrivilegedGroups) {
        try {
            Get-ADGroupMember -Identity $grpName -Recursive -ErrorAction SilentlyContinue |
                ForEach-Object { [void]$PrivilegedMemberSIDs.Add($_.SID.Value) }
        } catch {}
    }

    foreach ($user in $BadderBloodUsers) {
        $userOU = ($user.DistinguishedName -replace "^CN=[^,]+,", "")
        $canonPath = $user.CanonicalName

        # Check if user is in an Admin/Tier OU pattern
        $isInAdminOU = $false
        foreach ($pattern in $AdminOUPatterns) {
            if ($userOU -like $pattern) { $isInAdminOU = $true; break }
        }

        # INSTANT LOOKUP: check pre-built HashSet
        $isInPrivGroup = $PrivilegedMemberSIDs.Contains($user.SID.Value)

        # User in People OU but has admin privs -> violation
        if ($canonPath -like "*People*" -and $isInPrivGroup) {
            $Findings.Add((Write-Finding -Category "OU Misplacement" `
                -Severity "HIGH" `
                -Finding "User '$($user.SamAccountName)' is in People OU but has privileged group membership" `
                -CurrentState "Located in: $canonPath | Has privileged access" `
                -ExpectedState "Either remove from privileged groups OR move to appropriate Admin/Tier OU" `
                -ObjectDN $user.DistinguishedName))
        }

        # User in Admin/Tier OU but is a regular BadderBlood user
        if ($isInAdminOU -and -not $isInPrivGroup) {
            $Findings.Add((Write-Finding -Category "OU Misplacement" `
                -Severity "MEDIUM" `
                -Finding "User '$($user.SamAccountName)' is in Admin/Tier OU but has no privileged memberships" `
                -CurrentState "Located in: $canonPath | No privileged access" `
                -ExpectedState "Move to appropriate People/Department OU or grant appropriate Tier access" `
                -ObjectDN $user.DistinguishedName))
        }
    }

    $Findings
}
