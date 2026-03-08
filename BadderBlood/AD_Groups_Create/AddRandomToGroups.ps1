################################
# AddRandomToGroups.ps1 - BadderBlood Realistic Group Membership
# Users are added to groups based on department affinity.
# Group nesting follows realistic patterns.
# Privileged group membership is minimal and intentional.
################################
Function AddRandomToGroups {
    <#
        .SYNOPSIS
            Adds users, groups, and computers to groups with realistic patterns.
        .DESCRIPTION
            Instead of random spray, users are added to groups matching their department.
            Privileged group additions are minimal (1-3 realistic misconfigurations).
            Group nesting simulates real organizational patterns.
        .NOTES
            BadderBlood - Realistic AD Lab Generator
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)][Object[]]$Domain,
        [Parameter(Mandatory = $false)][Object[]]$UserList,
        [Parameter(Mandatory = $false)][Object[]]$GroupList,
        [Parameter(Mandatory = $false)][Object[]]$LocalGroupList,
        [Parameter(Mandatory = $false)][Object[]]$CompList
    )

    # Resolve parameters
    if (!$PSBoundParameters.ContainsKey('Domain')) {
        $dom = Get-ADDomain; $setDC = $dom.pdcemulator; $dn = $dom.distinguishedname
    } else { $setDC = $Domain.pdcemulator; $dn = $Domain.distinguishedname }

    if (!$PSBoundParameters.ContainsKey('UserList')) { $allUsers = Get-ADUser -Filter * -Properties Department,departmentNumber -Server $setDC -ResultSetSize $null }
    else { $allUsers = $UserList }

    if (!$PSBoundParameters.ContainsKey('GroupList')) {
        $allGroups = Get-ADGroup -Filter { GroupCategory -eq "Security" -and GroupScope -eq "Global" } -Properties isCriticalSystemObject -Server $setDC -ResultSetSize $null
    } else { $allGroups = $GroupList }

    if (!$PSBoundParameters.ContainsKey('LocalGroupList')) {
        $allGroupsLocal = Get-ADGroup -Filter { GroupScope -eq "domainlocal" } -Properties isCriticalSystemObject -Server $setDC -ResultSetSize $null
    } else { $allGroupsLocal = $LocalGroupList }

    if (!$PSBoundParameters.ContainsKey('CompList')) { $allComps = Get-ADComputer -Filter * -Server $setDC -ResultSetSize $null }
    else { $allComps = $CompList }

    Set-Location AD:

    # Pre-split groups into critical/non-critical arrays once (not per-user)
    $allGroupsFiltered = [System.Collections.Generic.List[object]]::new()
    $allGroupsCrit = [System.Collections.Generic.List[object]]::new()
    foreach ($g in $allGroups) {
        if ($g.isCriticalSystemObject -eq $true) {
            if ($g.Name -ne "Domain Users" -and $g.Name -ne "Domain Guests") {
                $allGroupsCrit.Add($g)
            }
        } else {
            $allGroupsFiltered.Add($g)
        }
    }

    # =========================================================================
    # 1. DEPARTMENT-BASED GROUP MEMBERSHIP
    #    Users go into groups that match their department prefix
    # =========================================================================
    Write-Host "  [*] Adding users to department-matching groups..." -ForegroundColor Cyan

    # Pre-index groups by department code in a SINGLE PASS over all groups
    # instead of O(groups * deptCodes) nested Where-Object scans
    $deptCodes = @('BDE','HRE','FIN','OGC','FSR','AWS','ESM','SEC','ITS','GOO','AZR','TST')
    $deptCodesSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($dc in $deptCodes) { [void]$deptCodesSet.Add($dc) }

    $groupsByDept = @{}
    foreach ($dc in $deptCodes) { $groupsByDept[$dc] = [System.Collections.Generic.List[object]]::new() }

    foreach ($g in $allGroupsFiltered) {
        $gName = $g.Name
        foreach ($dc in $deptCodes) {
            if ($gName -like "*$dc*" -or $gName -like "DEPT-$dc*" -or $gName -like "DL-$dc*") {
                $groupsByDept[$dc].Add($g)
                break  # Each group only needs to match one department
            }
        }
    }
    Write-Host "    [perf] Pre-indexed groups by department (single-pass)" -ForegroundColor DarkGray

    $userIndex = 0
    foreach ($user in $allUsers) {
        $userDept = $null

        # Try departmentNumber attribute first
        if ($user.departmentNumber) { $userDept = $user.departmentNumber }

        # Try parsing from DN
        if (!$userDept) {
            $dnParts = $user.DistinguishedName -split ','
            foreach ($part in $dnParts) {
                $ouName = ($part -replace 'OU=','').Trim()
                if ($ouName -match '^(BDE|HRE|FIN|OGC|FSR|AWS|ESM|SEC|ITS|GOO|AZR|TST)$') {
                    $userDept = $ouName
                    break
                }
            }
        }

        # Add to 1-4 relevant groups
        $numGroups = Get-Random -Minimum 1 -Maximum 5
        $n = 0

        # Use pre-indexed dept groups (O(1) lookup instead of O(groups) scan)
        if ($userDept -and $groupsByDept.ContainsKey($userDept)) {
            $matchingGroups = $groupsByDept[$userDept]
            if ($matchingGroups.Count -gt 0) {
                $groupsToAdd = $matchingGroups | Get-Random -Count ([Math]::Min($numGroups, $matchingGroups.Count))
                foreach ($g in $groupsToAdd) {
                    try { Add-ADGroupMember -Identity $g -Members $user -Server $setDC -ErrorAction Stop } catch {}
                    $n++
                }
            }
        }

        # Fill remaining slots with random non-critical groups (cross-department access)
        while ($n -lt $numGroups) {
            $randoGroup = $allGroupsFiltered | Get-Random
            try { Add-ADGroupMember -Identity $randoGroup -Members $user -Server $setDC -ErrorAction Stop } catch {}
            $n++
        }

        $userIndex++
        if ($userIndex % 250 -eq 0) {
            Write-Progress -Activity "Group Memberships" -Status "Processing user $userIndex/$($allUsers.Count)" -PercentComplete ($userIndex / $allUsers.Count * 100)
        }
    }

    # =========================================================================
    # 2. REALISTIC GROUP NESTING
    #    DEPT groups nested under ROLE groups, project groups cross-department
    # =========================================================================
    Write-Host "  [*] Creating realistic group nesting..." -ForegroundColor Cyan

    # Nest ~15% of groups into 1-2 other groups
    $nestCount = [Math]::Round($allGroupsFiltered.Count * 0.15)
    $groupsToNest = $allGroupsFiltered | Get-Random -Count ([Math]::Min($nestCount, $allGroupsFiltered.Count))

    foreach ($group in $groupsToNest) {
        $numNests = Get-Random -Minimum 1 -Maximum 3
        $n = 0
        do {
            $targetGroup = $allGroupsFiltered | Get-Random
            # Avoid self-nesting
            if ($targetGroup.DistinguishedName -ne $group.DistinguishedName) {
                try { Add-ADGroupMember -Identity $targetGroup -Members $group -Server $setDC -ErrorAction Stop } catch {}
            }
            $n++
        } while ($n -lt $numNests)
    }

    # =========================================================================
    # 3. CONTROLLED PRIVILEGED GROUP MEMBERSHIP (the realistic misconfigs)
    #    Only 1-3 users per critical group, max. These are the "findings."
    # =========================================================================
    Write-Host "  [*] Adding controlled privileged group misconfigurations..." -ForegroundColor Cyan

    foreach ($critGroup in $allGroupsCrit) {
        # 1-2 users per critical group (not 5+ like old BadBlood)
        $numToAdd = Get-Random -Minimum 1 -Maximum 3
        $usersToAdd = $allUsers | Get-Random -Count ([Math]::Min($numToAdd, $allUsers.Count))
        foreach ($u in $usersToAdd) {
            try { Add-ADGroupMember -Identity $critGroup -Members $u -Server $setDC -ErrorAction Stop } catch {}
        }
    }

    # Only 1-2 users in domain-local critical groups
    foreach ($localGroup in $allGroupsLocal) {
        $addRoll = Get-Random -Minimum 1 -Maximum 101
        if ($addRoll -le 30) {
            $userToAdd = $allUsers | Get-Random
            try { Add-ADGroupMember -Identity $localGroup -Members $userToAdd -Server $setDC -ErrorAction Stop } catch {}
        }
    }

    # =========================================================================
    # 4. COMPUTERS IN GROUPS (realistic: server groups, workstation groups)
    # =========================================================================
    Write-Host "  [*] Adding computers to groups..." -ForegroundColor Cyan

    $compsInGroupCount = [Math]::Round($allComps.Count * 0.15)
    $compsToGroup = $allComps | Get-Random -Count ([Math]::Min($compsInGroupCount, $allComps.Count))

    foreach ($comp in $compsToGroup) {
        $numGroups = Get-Random -Minimum 1 -Maximum 3
        $n = 0
        do {
            $randoGroup = $allGroupsFiltered | Get-Random
            try { Add-ADGroupMember -Identity $randoGroup -Members $comp -Server $setDC -ErrorAction Stop } catch {}
            $n++
        } while ($n -lt $numGroups)
    }

    # =========================================================================
    # 5. ONE CRITICAL NESTED GROUP (realistic attack path)
    #    e.g., a project group nested in a group that has a member with priv access
    # =========================================================================
    Write-Host "  [*] Creating nested group attack path..." -ForegroundColor Cyan

    # Pick one critical group and nest a non-critical group into it
    # This simulates "someone added the project team group to Domain Admins temporarily"
    $nestCritRoll = Get-Random -Minimum 1 -Maximum 101
    if ($nestCritRoll -le 50 -and $allGroupsCrit.Count -gt 0 -and $allGroupsFiltered.Count -gt 0) {
        $critTarget = $allGroupsCrit | Get-Random
        $sourceGroup = $allGroupsFiltered | Get-Random
        try {
            Add-ADGroupMember -Identity $critTarget -Members $sourceGroup -Server $setDC -ErrorAction Stop
            Write-Host "    [!] Nested '$($sourceGroup.Name)' into '$($critTarget.Name)' (intentional attack path)" -ForegroundColor Yellow
        } catch {}
    }
}