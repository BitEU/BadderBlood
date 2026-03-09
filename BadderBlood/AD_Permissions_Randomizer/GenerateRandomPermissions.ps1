################################
# GenerateRandomPermissions.ps1 - BadderBlood Realistic ACL Misconfiguration
# Instead of random GenericAll on root, creates realistic delegation mistakes:
# - Helpdesk with too-broad password reset
# - IT groups with WriteDACL on wrong OUs
# - Leftover project permissions
# - Chained attack paths for BloodHound exercises
################################

function Get-ScriptDirectory {
    Split-Path -Parent $PSCommandPath
}
$scriptPath = Get-ScriptDirectory
$adplatformsourcedir = Split-Path -Path $scriptPath -Parent

# Import ACL function files
$ACLScriptspath = $adplatformsourcedir + "\AD_OU_SetACL"
$files = Get-ChildItem $ACLScriptspath -Name "*permissions.ps1"
foreach ($file in $files) {
    . ($ACLScriptspath + "\" + $file)
}

# =========================================================================
# Setup: Schema maps needed for ACL functions (cached across calls)
# Schema GUIDs and extended rights are static - no need to re-query
# =========================================================================
$dom = Get-ADDomain
$setDC = $dom.pdcemulator
$dn = $dom.distinguishedname
Set-Location AD:

# Cache schema GUID maps at script scope - they never change during a run
if (-not $script:_bbGuidMapCached) {
    $schemaPath = Get-ADRootDSE
    $script:_bbGuidMap = @{}
    Get-ADObject -SearchBase ($schemaPath.SchemaNamingContext) -LDAPFilter "(schemaidguid=*)" -Properties lDAPDisplayName, schemaIDGUID |
        ForEach-Object { $script:_bbGuidMap[$_.lDAPDisplayName] = [System.GUID]$_.schemaIDGUID }

    $script:_bbExtendedRightsMap = @{}
    Get-ADObject -SearchBase ($schemaPath.ConfigurationNamingContext) -LDAPFilter "(&(objectclass=controlAccessRight)(rightsguid=*))" -Properties displayName, rightsGuid |
        ForEach-Object { $script:_bbExtendedRightsMap[$_.displayName] = [System.GUID]$_.rightsGuid }

    $script:_bbGuidMapCached = $true
    Write-Host "    [perf] Cached $($script:_bbGuidMap.Count) schema GUIDs and $($script:_bbExtendedRightsMap.Count) extended rights" -ForegroundColor DarkGray
}
$guidmap = $script:_bbGuidMap
$extendedrightsmap = $script:_bbExtendedRightsMap

# Object queries - these change per run so always refresh, but use ResultSetSize for safety
$AllOUs = Get-ADOrganizationalUnit -Filter * -Server $setDC -ResultSetSize $null
$allUsers = Get-ADUser -Filter * -ResultSetSize 2500 -Server $setDC
$allGroups = Get-ADGroup -Filter * -ResultSetSize 2500 -Server $setDC
$allComputers = Get-ADComputer -Filter * -ResultSetSize 2500 -Server $setDC

# Non-critical groups - build in single pass instead of pipeline filter
$nonCritGroups = [System.Collections.Generic.List[object]]::new()
$allSecGlobalGroups = Get-ADGroup -Filter { GroupCategory -eq "Security" -and GroupScope -eq "Global" } -Properties isCriticalSystemObject -Server $setDC -ResultSetSize $null
foreach ($g in $allSecGlobalGroups) {
    if ($g.isCriticalSystemObject -ne $true) { $nonCritGroups.Add($g) }
}

# =========================================================================
# SCENARIO 1: Helpdesk group with password reset on too many OUs
# (Realistic: IT created a helpdesk delegation that covers admin OUs too)
# =========================================================================
Write-Host "  [*] Scenario 1: Overly broad helpdesk delegation..." -ForegroundColor Cyan

$helpdeskGroups = $allGroups | Where-Object { $_.Name -like "*Helpdesk*" -or $_.Name -like "*Service-Desk*" -or $_.Name -like "*PasswordReset*" }
if ($helpdeskGroups) {
    $helpdeskGroup = $helpdeskGroups | Get-Random
    # Grant password reset on People OU (intended) - this is fine
    $peopleOU = $AllOUs | Where-Object { $_.DistinguishedName -eq "OU=People,$dn" }
    if ($peopleOU) {
        try { ResetUserPasswords -objGroup $helpdeskGroup -objOU $peopleOU -inheritanceType 'Descendents' } catch {}
        try { UnlockUserAccount -objGroup $helpdeskGroup -objOU $peopleOU -inheritanceType 'Descendents' } catch {}
    }
    # MISCONFIGURATION: Also grant on Tier 1 OU (covers admin accounts!)
    $tier1OU = $AllOUs | Where-Object { $_.DistinguishedName -eq "OU=Tier 1,$dn" }
    if ($tier1OU) {
        try { ResetUserPasswords -objGroup $helpdeskGroup -objOU $tier1OU -inheritanceType 'Descendents' } catch {}
        Write-Host "    [!] Helpdesk '$($helpdeskGroup.Name)' has password reset on Tier 1 OU" -ForegroundColor Yellow
    }
}

# =========================================================================
# SCENARIO 2: IT group with FullControl on specific department OUs
# (Realistic: Departmental IT team got full control for "troubleshooting")
# =========================================================================
Write-Host "  [*] Scenario 2: IT group with excessive OU permissions..." -ForegroundColor Cyan

$itGroups = $allGroups | Where-Object { $_.Name -like "*Server-Admin*" -or $_.Name -like "*ADM-*" -or $_.Name -like "*Workstation-Admin*" }
if ($itGroups) {
    # Pick 2-3 IT groups and give them FullControl on department OUs
    $selectedITGroups = $itGroups | Get-Random -Count ([Math]::Min(3, $itGroups.Count))
    foreach ($itGroup in $selectedITGroups) {
        $targetOU = $AllOUs | Where-Object { $_.DistinguishedName -like "OU=*,OU=Tier 2,$dn" } | Get-Random
        if ($targetOU) {
            try {
                FullControl -objGroup $itGroup -objOU $targetOU -inheritanceType 'Descendents'
                Write-Host "    [!] '$($itGroup.Name)' has FullControl on '$($targetOU.Name)'" -ForegroundColor Yellow
            } catch {}
        }
    }
}

# =========================================================================
# SCENARIO 3: Individual users with GenericAll on specific OUs
# (Realistic: Someone was granted permissions directly instead of via group)
# =========================================================================
Write-Host "  [*] Scenario 3: Direct user ACL grants..." -ForegroundColor Cyan

$directPermUsers = $allUsers | Get-Random -Count ([Math]::Min(5, $allUsers.Count))
foreach ($user in $directPermUsers) {
    $targetOU = $AllOUs | Get-Random
    $permType = Get-Random -Minimum 1 -Maximum 101

    if ($permType -le 30) {
        try { ModifyUserProperties -objGroup $user -objOU $targetOU -inheritanceType 'Descendents' } catch {}
    } elseif ($permType -le 50) {
        try { ModifyComputerProperties -objGroup $user -objOU $targetOU -inheritanceType 'Descendents' } catch {}
    } elseif ($permType -le 70) {
        try { ModifyGroupMembership -objGroup $user -objOU $targetOU -inheritanceType 'Descendents' } catch {}
    } elseif ($permType -le 85) {
        try { ResetUserPasswords -objGroup $user -objOU $targetOU -inheritanceType 'Descendents' } catch {}
    } else {
        try { ForcePasswordChangeAtLogon -objGroup $user -objOU $targetOU -inheritanceType 'Descendents' } catch {}
    }
}

# =========================================================================
# SCENARIO 4: GenericAll on domain root - BUT only 1-2 objects, not dozens
# (Realistic: A migration tool service account that was never cleaned up)
# =========================================================================
Write-Host "  [*] Scenario 4: Leftover migration permissions on domain root..." -ForegroundColor Cyan

$rootPermRoll = Get-Random -Minimum 1 -Maximum 101
if ($rootPermRoll -le 60) {
    # One group with GenericAll on root (the "migration team" leftover)
    $migrationGroup = $nonCritGroups | Where-Object { $_.Name -like "PRJ-*" } | Get-Random
    if ($migrationGroup) {
        try {
            FullControl -objGroup $migrationGroup -objOU $dn -inheritanceType 'Descendents'
            Write-Host "    [!] '$($migrationGroup.Name)' has FullControl on domain root (migration leftover)" -ForegroundColor Yellow
        } catch {}
    }
}

# One user (service account) with GenericAll on root
$svcAccounts = $allUsers | Where-Object { $_.SamAccountName -like "*SA" }
if ($svcAccounts -and $svcAccounts.Count -gt 0) {
    $svcAccount = $svcAccounts | Get-Random
    $svcRoll = Get-Random -Minimum 1 -Maximum 101
    if ($svcRoll -le 40) {
        try {
            FullControl -objGroup $svcAccount -objOU $dn -inheritanceType 'Descendents'
            Write-Host "    [!] Service account '$($svcAccount.SamAccountName)' has FullControl on domain root" -ForegroundColor Yellow
        } catch {}
    }
}

# =========================================================================
# SCENARIO 5: WriteDACL / WriteOwner on critical containers
# (Realistic: Group that can modify ACLs = can grant itself anything)
# =========================================================================
Write-Host "  [*] Scenario 5: WriteDACL escalation paths..." -ForegroundColor Cyan

$writeDaclGroups = $nonCritGroups | Get-Random -Count ([Math]::Min(2, $nonCritGroups.Count))
foreach ($wdGroup in $writeDaclGroups) {
    $critOU = $AllOUs | Where-Object { $_.DistinguishedName -like "OU=Tier 0*" -or $_.DistinguishedName -like "OU=Admin*" } | Get-Random
    if ($critOU) {
        try {
            $groupSID = New-Object System.Security.Principal.SecurityIdentifier $wdGroup.SID
            $objAcl = Get-Acl $critOU
            $objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID, "WriteDacl", "Allow", "Descendents"))
            Set-Acl -AclObject $objAcl -Path $critOU
            Write-Host "    [!] '$($wdGroup.Name)' has WriteDACL on '$($critOU.Name)'" -ForegroundColor Yellow
        } catch {}
    }
}

# =========================================================================
# SCENARIO 6: Groups with permissions on other groups (membership modification)
# (Realistic: A group can add members to a privileged group)
# =========================================================================
Write-Host "  [*] Scenario 6: Group-to-group permission chains..." -ForegroundColor Cyan

# Pick a few non-critical groups and give them WriteProperty on member attribute of other groups
$chainSourceGroups = $nonCritGroups | Get-Random -Count ([Math]::Min(3, $nonCritGroups.Count))
foreach ($srcGroup in $chainSourceGroups) {
    $targetGroup = $allGroups | Where-Object { $_.DistinguishedName -ne $srcGroup.DistinguishedName } | Get-Random
    if ($targetGroup) {
        try {
            $groupSID = New-Object System.Security.Principal.SecurityIdentifier $srcGroup.SID
            $objAcl = Get-Acl "AD:\$($targetGroup.DistinguishedName)"
            $objAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $groupSID, "WriteProperty", "Allow", $guidmap["member"], "None"))
            Set-Acl -AclObject $objAcl -Path "AD:\$($targetGroup.DistinguishedName)"
        } catch {}
    }
}

Write-Host "  [+] Realistic ACL misconfiguration complete." -ForegroundColor Green