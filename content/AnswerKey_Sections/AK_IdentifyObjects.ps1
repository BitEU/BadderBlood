################################
# AK_IdentifyObjects.ps1 - Section 1: Identify all BadderBlood-created objects
# Dot-sourced by BadderBloodAnswerKey.ps1
################################
function Invoke-AKIdentifyObjects {
    <#
        .SYNOPSIS
            Identifies all BadderBlood-created users and groups in the domain.
        .PARAMETER AllUsers
            All AD users (pre-fetched with required properties).
        .PARAMETER AllGroups
            All AD groups (pre-fetched with required properties).
        .OUTPUTS
            PSCustomObject with BadderBloodUsers, BadderBloodGroups, and UserContextMap.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$AllUsers,
        [Parameter(Mandatory)]
        [object[]]$AllGroups
    )

    Write-Status "SECTION 1: Identifying all BadderBlood-created objects..."

    $BadderBloodUsers = @($AllUsers | Where-Object {
        Test-IsBadderBloodObject -Description $_.Description
    })

    $BadderBloodGroups = @($AllGroups | Where-Object {
        Test-IsBadderBloodObject -Description $_.Description
    })

    Write-Status "Found $($BadderBloodUsers.Count) BadderBlood-created users" "Green"
    Write-Status "Found $($BadderBloodGroups.Count) BadderBlood-created security groups" "Green"

    # Build lookup: SamAccountName -> context info
    $UserContextMap = @{}
    foreach ($u in $AllUsers) {
        $UserContextMap[$u.SamAccountName] = @{
            CanonicalName = $u.CanonicalName
            Department    = Get-UserDepartment -CanonicalName $u.CanonicalName
            FriendlyOU    = Get-FriendlyOUPath -CanonicalName $u.CanonicalName
        }
    }

    [PSCustomObject]@{
        BadderBloodUsers  = $BadderBloodUsers
        BadderBloodGroups = $BadderBloodGroups
        UserContextMap    = $UserContextMap
    }
}
