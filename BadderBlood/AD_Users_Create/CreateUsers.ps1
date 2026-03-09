################################
# CreateUsers.ps1 - BadderBlood Realistic User Generator
# Users are placed in correct department OUs with full AD attributes.
# Org hierarchy is title-aware: only higher-level titles manage lower ones.
# Singleton roles (CEO, CFO, CISO, etc.) are enforced via MaxCount.
################################

# =====================================================================
# ONE-TIME CACHES (populated on first call, reused across all calls)
# =====================================================================
if (-not $script:_bbNamesCached) {
    $script:_bbNamesCached    = $false
    $script:_bbFamilyNames    = $null
    $script:_bbFemaleNames    = $null
    $script:_bbMaleNames      = $null
    $script:_bbWeightedDepts  = $null
    $script:_bbHierarchyMap   = $null   # Title -> ReportsTo
    $script:_bbTitleLevelMap  = $null   # Title -> Level (int)
    $script:_bbDeptMap        = $null   # Acronym -> Department Name
    $script:_bbTitlesByDept   = $null   # DeptCode -> @(title objects)
    $script:_bbUsersByTitle   = $null   # Title -> @(user objects) from ExistingUsers
    $script:_bbTitleCounts    = $null   # Title -> count (from ExistingUsers)
    $script:_bbLocalTitleCounts = @{}   # Title -> count (local running tally, always accurate for capped titles)
}

Function CreateUser {
    <#
        .SYNOPSIS
            Creates a realistic user in Active Directory with proper department placement and full attributes.
        .DESCRIPTION
            Generates users with department, title, phone, office, manager, and places them in the
            correct OU. Title-aware manager assignment ensures realistic reporting chains.
            Singleton roles (CEO, CFO, etc.) are enforced so only one can exist.
        .NOTES
            BadderBlood - Realistic AD Lab Generator
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [Object[]]$Domain,
        [Parameter(Mandatory = $false)]
        [Object[]]$OUList,
        [Parameter(Mandatory = $false)]
        [string]$ScriptDir,
        [Parameter(Mandatory = $false)]
        [Object[]]$DepartmentList,
        [Parameter(Mandatory = $false)]
        [Object[]]$JobTitleList,
        [Parameter(Mandatory = $false)]
        [Object[]]$OfficeList,
        [Parameter(Mandatory = $false)]
        [Object[]]$OrgHierarchy,
        [Parameter(Mandatory = $false)]
        [Object[]]$ExistingUsers,
        [Parameter(Mandatory = $false)]
        [ValidateRange(0,100)]
        [int]$DriftPercent = 8
    )

    # ----- Resolve parameters -----
    if (!$PSBoundParameters.ContainsKey('Domain')) {
        if ($args[0]) { $setDC = $args[0].pdcemulator; $dnsroot = $args[0].dnsroot; $dn = $args[0].distinguishedname }
        else { $d = Get-ADDomain; $setDC = $d.pdcemulator; $dnsroot = $d.dnsroot; $dn = $d.distinguishedname }
    } else { $setDC = $Domain.pdcemulator; $dnsroot = $Domain.dnsroot; $dn = $Domain.distinguishedname }

    if (!$PSBoundParameters.ContainsKey('OUList')) {
        $OUsAll = Get-ADOrganizationalUnit -Filter * -Server $setDC
    } else { $OUsAll = $OUList }

    if (!$PSBoundParameters.ContainsKey('ScriptDir')) {
        if ($args[2]) { $scriptPath = $args[2] }
        else { $scriptPath = "$((Get-Location).path)\AD_Users_Create\" }
    } else { $scriptpath = $ScriptDir }

    $scriptparent = (Get-Item $scriptpath).parent.fullname

    # ----- Load data files if not passed -----
    if (!$PSBoundParameters.ContainsKey('DepartmentList')) {
        $DepartmentList = Import-Csv ($scriptparent + "\AD_Data\AD_Departments.csv")
    }
    if (!$PSBoundParameters.ContainsKey('JobTitleList')) {
        $JobTitleList = Import-Csv ($scriptparent + "\AD_Data\JobTitles.csv")
    }
    if (!$PSBoundParameters.ContainsKey('OfficeList')) {
        $OfficeList = Import-Csv ($scriptparent + "\AD_Data\Offices.csv")
    }
    if (!$PSBoundParameters.ContainsKey('OrgHierarchy')) {
        $OrgHierarchy = Import-Csv ($scriptparent + "\AD_Data\org_hierarchy.csv")
    }

    # =====================================================================
    # INITIALIZE ONE-TIME CACHES (first call only)
    # =====================================================================
    if (-not $script:_bbNamesCached) {
        # Cache name lists from disk (eliminates ~7500 file reads over 2500 calls)
        $script:_bbFamilyNames = @(Get-Content ("$($scriptpath)\Names\familynames-usa-top1000.txt"))
        $script:_bbFemaleNames = @(Get-Content ("$($scriptpath)\Names\femalenames-usa-top1000.txt"))
        $script:_bbMaleNames   = @(Get-Content ("$($scriptpath)\Names\malenames-usa-top1000.txt"))

        # Pre-build weighted department array (eliminates rebuild per call)
        $deptWeights = @{
            'BDE' = 20; 'HRE' = 10; 'FIN' = 15; 'OGC' = 8; 'FSR' = 12
            'AWS' = 5;  'ESM' = 5;  'SEC' = 5;  'ITS' = 8; 'GOO' = 4
            'AZR' = 5;  'TST' = 3
        }
        $wd = [System.Collections.Generic.List[string]]::new(100)
        foreach ($d in $deptWeights.Keys) {
            for ($w = 0; $w -lt $deptWeights[$d]; $w++) { $wd.Add($d) }
        }
        $script:_bbWeightedDepts = $wd.ToArray()

        # Build hierarchy hashtable: Title -> ReportsTo (eliminates Where-Object per lookup)
        $script:_bbHierarchyMap = @{}
        foreach ($entry in $OrgHierarchy) {
            $script:_bbHierarchyMap[$entry.Title] = $entry.ReportsTo
        }

        # Build title -> level hashtable
        $script:_bbTitleLevelMap = @{}
        foreach ($t in $JobTitleList) {
            $script:_bbTitleLevelMap[$t.Title] = [int]$t.Level
        }

        # Build department -> name hashtable
        $script:_bbDeptMap = @{}
        foreach ($d in $DepartmentList) {
            $script:_bbDeptMap[$d.Acronym] = $d.'Department Name'
        }

        # Pre-group titles by department (eliminates Where-Object per call)
        $script:_bbTitlesByDept = @{}
        foreach ($t in $JobTitleList) {
            $key = $t.Acronym
            if (-not $script:_bbTitlesByDept.ContainsKey($key)) {
                $script:_bbTitlesByDept[$key] = [System.Collections.Generic.List[object]]::new()
            }
            $script:_bbTitlesByDept[$key].Add($t)
        }

        $script:_bbNamesCached = $true
        Write-Host "    [perf] Cached name files, weighted depts, hierarchy map, title lookups" -ForegroundColor DarkGray
    }

    # =====================================================================
    # REBUILD PER-REFRESH CACHES (when ExistingUsers changes)
    # The caller refreshes ExistingUsers periodically.
    # We detect the change by checking the count.
    # On subsequent refreshes, we only process NEW users (delta merge)
    # instead of rebuilding the entire index from scratch.
    # =====================================================================
    $euCount = if ($ExistingUsers) { $ExistingUsers.Count } else { 0 }
    if ($null -eq $script:_bbUsersByTitle) {
        # First-time build: index all existing users
        $script:_bbLastEUCount = $euCount
        $script:_bbUsersByTitle = @{}
        $script:_bbTitleCounts  = @{}
        $script:_bbIndexedDNs   = [System.Collections.Generic.HashSet[string]]::new()
        if ($ExistingUsers) {
            foreach ($u in $ExistingUsers) {
                $t = $u.Title
                if (-not $t) { continue }
                if (-not $script:_bbUsersByTitle.ContainsKey($t)) {
                    $script:_bbUsersByTitle[$t] = [System.Collections.Generic.List[object]]::new()
                }
                $script:_bbUsersByTitle[$t].Add($u)
                if ($script:_bbTitleCounts.ContainsKey($t)) {
                    $script:_bbTitleCounts[$t]++
                } else {
                    $script:_bbTitleCounts[$t] = 1
                }
                [void]$script:_bbIndexedDNs.Add($u.DistinguishedName)
            }
        }
        # Seed local title counts from ExistingUsers (handles partial reruns)
        if ($script:_bbLocalTitleCounts.Count -eq 0 -and $script:_bbTitleCounts.Count -gt 0) {
            foreach ($key in $script:_bbTitleCounts.Keys) {
                $script:_bbLocalTitleCounts[$key] = $script:_bbTitleCounts[$key]
            }
        }
        Write-Host "    [perf] Built user-by-title index ($euCount users)" -ForegroundColor DarkGray
    } elseif ($script:_bbLastEUCount -ne $euCount -and $ExistingUsers) {
        # Delta merge: only index users not already in our HashSet
        $newCount = 0
        foreach ($u in $ExistingUsers) {
            if ($script:_bbIndexedDNs.Contains($u.DistinguishedName)) { continue }
            $t = $u.Title
            if (-not $t) { continue }
            if (-not $script:_bbUsersByTitle.ContainsKey($t)) {
                $script:_bbUsersByTitle[$t] = [System.Collections.Generic.List[object]]::new()
            }
            $script:_bbUsersByTitle[$t].Add($u)
            if ($script:_bbTitleCounts.ContainsKey($t)) {
                $script:_bbTitleCounts[$t]++
            } else {
                $script:_bbTitleCounts[$t] = 1
            }
            [void]$script:_bbIndexedDNs.Add($u.DistinguishedName)
            $newCount++
        }
        $script:_bbLastEUCount = $euCount
        if ($newCount -gt 0) {
            Write-Host "    [perf] Delta-merged $newCount new users into title index" -ForegroundColor DarkGray
        }
    }

    # ----- Password Generator -----
    function New-SWRandomPassword {
        [CmdletBinding(DefaultParameterSetName='FixedLength')]
        [OutputType([String])]
        Param(
            [Parameter(ParameterSetName='RandomLength')][Alias('Min')][int]$MinPasswordLength = 8,
            [Parameter(ParameterSetName='RandomLength')][Alias('Max')][int]$MaxPasswordLength = 12,
            [Parameter(ParameterSetName='FixedLength')][int]$PasswordLength = 8,
            [String[]]$InputStrings = @('abcdefghijkmnpqrstuvwxyz','ABCEFGHJKLMNPQRSTUVWXYZ','23456789','!#%&'),
            [String]$FirstChar,
            [int]$Count = 1
        )
        Begin {
            Function Get-Seed {
                $RandomBytes = New-Object -TypeName 'System.Byte[]' 4
                $Random = New-Object -TypeName 'System.Security.Cryptography.RNGCryptoServiceProvider'
                $Random.GetBytes($RandomBytes)
                [BitConverter]::ToUInt32($RandomBytes, 0)
            }
        }
        Process {
            For ($iteration = 1; $iteration -le $Count; $iteration++) {
                $Password = @{}
                [char[][]]$CharGroups = $InputStrings
                $AllChars = $CharGroups | ForEach-Object { [Char[]]$_ }
                if ($PSCmdlet.ParameterSetName -eq 'RandomLength') {
                    if ($MinPasswordLength -eq $MaxPasswordLength) { $PasswordLength = $MinPasswordLength }
                    else { $PasswordLength = ((Get-Seed) % ($MaxPasswordLength + 1 - $MinPasswordLength)) + $MinPasswordLength }
                }
                if ($PSBoundParameters.ContainsKey('FirstChar')) {
                    $Password.Add(0, $FirstChar[((Get-Seed) % $FirstChar.Length)])
                }
                Foreach ($Group in $CharGroups) {
                    if ($Password.Count -lt $PasswordLength) {
                        $Index = Get-Seed
                        While ($Password.ContainsKey($Index)) { $Index = Get-Seed }
                        $Password.Add($Index, $Group[((Get-Seed) % $Group.Count)])
                    }
                }
                for ($i = $Password.Count; $i -lt $PasswordLength; $i++) {
                    $Index = Get-Seed
                    While ($Password.ContainsKey($Index)) { $Index = Get-Seed }
                    $Password.Add($Index, $AllChars[((Get-Seed) % $AllChars.Count)])
                }
                Write-Output -InputObject $(-join ($Password.GetEnumerator() | Sort-Object -Property Name | Select-Object -ExpandProperty Value))
            }
        }
    }

    # ----- Phone Number Generator -----
    function New-PhoneNumber {
        param([string]$AreaCode = '215')
        $exchange = Get-Random -Minimum 200 -Maximum 999
        $subscriber = Get-Random -Minimum 1000 -Maximum 9999
        return "+1 ($AreaCode) $exchange-$subscriber"
    }

    # ----- Employee ID Generator -----
    function New-EmployeeID {
        return "EMP" + (Get-Random -Minimum 100000 -Maximum 999999).ToString()
    }

    # ----- Title-aware manager resolver (hashtable-based, no Where-Object) -----
    function Get-HierarchyManager {
        param(
            [string]$Title,
            [int]$MaxAncestors = 5
        )
        $current = $Title
        for ($depth = 0; $depth -lt $MaxAncestors; $depth++) {
            if (-not $script:_bbHierarchyMap.ContainsKey($current)) { return $null }
            $parentTitle = $script:_bbHierarchyMap[$current]
            if ([string]::IsNullOrEmpty($parentTitle)) { return $null }

            if ($script:_bbUsersByTitle.ContainsKey($parentTitle)) {
                $candidates = $script:_bbUsersByTitle[$parentTitle]
                if ($candidates.Count -gt 0) {
                    return $candidates | Get-Random
                }
            }
            $current = $parentTitle
        }
        return $null
    }

    # ===================================================================
    # DECIDE: Regular user (97%) or Service account (3%)
    # ===================================================================
    $accountType = Get-Random -Minimum 1 -Maximum 101

    if ($accountType -le 3) {
        # ---- SERVICE ACCOUNT ----
        $nameSuffix = "SA"
        $name = "" + (Get-Random -Minimum 100 -Maximum 9999999999) + $nameSuffix
        if ($name.Length -gt 20) { $name = $name.Substring(0, 20) }

        # Service accounts go into Tier ServiceAccounts OUs
        $tier = @('Tier 1', 'Tier 2') | Get-Random
        $dept = ($DepartmentList | Where-Object { $_.Acronym -notin @('TST','CORP') } | Get-Random).Acronym
        $targetOU = "OU=ServiceAccounts,OU=$dept,OU=$tier,$dn"

        try { Get-ADOrganizationalUnit $targetOU -Server $setDC | Out-Null }
        catch { $targetOU = "OU=$tier,$dn" }

        $description = "Service Account - $dept - Created by BadderBlood"
        $pwd = New-SWRandomPassword -MinPasswordLength 22 -MaxPasswordLength 25

        $pwdLeak = Get-Random -Minimum 1 -Maximum 101
        if ($pwdLeak -le 5) {
            $description = "Service Account - $dept - pwd: $pwd"
        }

        $exists = $null
        try { $exists = Get-ADUser $name -Server $setDC -ErrorAction Stop } catch {}
        if ($exists) { return }

        New-ADUser -Server $setDC -Description $description -DisplayName $name -Name $name `
            -SamAccountName $name -Enabled $true -Path $targetOU `
            -AccountPassword (ConvertTo-SecureString $pwd -AsPlainText -Force) `
            -OtherAttributes @{
                'employeeType' = 'Service'
                'departmentNumber' = $dept
                'department' = $script:_bbDeptMap[$dept]
            }

        try { Set-ADUser -Identity $name -UserPrincipalName "$name@$dnsroot" -Server $setDC } catch {}

    } else {
        # ---- REGULAR USER ----
        # Use cached name lists instead of reading from disk each time
        $surname = $script:_bbFamilyNames | Get-Random
        $genderpreference = 0, 1 | Get-Random
        if ($genderpreference -eq 0) {
            $givenname = $script:_bbFemaleNames | Get-Random
        } else {
            $givenname = $script:_bbMaleNames | Get-Random
        }

        $givenname = (Get-Culture).TextInfo.ToTitleCase($givenname.Trim().ToLower())
        $surname = (Get-Culture).TextInfo.ToTitleCase($surname.Trim().ToLower())

        $name = $givenname + "_" + $surname
        if ($name.Length -gt 20) { $name = $name.Substring(0, 20) }

        $exists = $null
        try { $exists = Get-ADUser $name -Server $setDC -ErrorAction Stop } catch {}
        if ($exists) { return }

        # ---- ASSIGN DEPARTMENT (using cached weighted array) ----
        $deptCode = $script:_bbWeightedDepts | Get-Random
        $deptName = $script:_bbDeptMap[$deptCode]

        # ---- ASSIGN TITLE (with singleton enforcement) ----
        # Get titles for this dept + CORP titles, using cached per-dept grouping
        $deptTitles = @()
        if ($script:_bbTitlesByDept.ContainsKey($deptCode)) {
            $deptTitles += $script:_bbTitlesByDept[$deptCode]
        }
        if ($script:_bbTitlesByDept.ContainsKey('CORP')) {
            $deptTitles += $script:_bbTitlesByDept['CORP']
        }

        # Use local running tally for capped titles (always accurate, no stale cache)
        $eligibleTitles = @()
        foreach ($t in $deptTitles) {
            $cap = [int]$t.MaxCount
            if ($cap -eq 0) {
                # Unlimited role - weight toward lower-level roles for pyramid shape
                $icWeight = [math]::Max(1, 10 - [int]$t.Level)
                for ($w = 0; $w -lt $icWeight; $w++) { $eligibleTitles += $t }
            } else {
                # Use local running counter (updated immediately on every assignment)
                $existing = if ($script:_bbLocalTitleCounts.ContainsKey($t.Title)) { $script:_bbLocalTitleCounts[$t.Title] } else { 0 }
                if ($existing -lt $cap) {
                    $capWeight = [math]::Max(1, 6 - [int]$t.Level)
                    for ($w = 0; $w -lt $capWeight; $w++) { $eligibleTitles += $t }
                }
            }
        }

        # Fallback: if all capped roles are full, pick any IC title for this dept
        if ($eligibleTitles.Count -eq 0 -and $script:_bbTitlesByDept.ContainsKey($deptCode)) {
            $eligibleTitles = @($script:_bbTitlesByDept[$deptCode] | Where-Object { $_.MaxCount -eq '0' })
        }
        if ($eligibleTitles.Count -eq 0 -and $script:_bbTitlesByDept.ContainsKey($deptCode)) {
            $eligibleTitles = @($script:_bbTitlesByDept[$deptCode])
        }

        $selectedTitle = ($eligibleTitles | Get-Random)
        $title = $selectedTitle.Title

        # Immediately increment local counter for capped titles (prevents duplicates between cache refreshes)
        if ([int]$selectedTitle.MaxCount -gt 0) {
            if ($script:_bbLocalTitleCounts.ContainsKey($title)) {
                $script:_bbLocalTitleCounts[$title]++
            } else {
                $script:_bbLocalTitleCounts[$title] = 1
            }
        }

        # CORP-titled users (CEO etc.) use a pseudo-dept for OU placement
        if ($selectedTitle.Acronym -eq 'CORP') {
            $deptCode = 'ITS'
            $deptName = $script:_bbDeptMap[$deptCode]
        }

        # ---- ASSIGN OFFICE AND LOCATION ----
        $office = $OfficeList | Get-Random
        $phone = New-PhoneNumber -AreaCode $office.AreaCode
        $employeeID = New-EmployeeID

        # ---- DETERMINE OU PLACEMENT ----
        $targetOU = "OU=$deptCode,OU=People,$dn"

        # Drift: X% chance of being in a slightly wrong but plausible location
        $driftRoll = Get-Random -Minimum 1 -Maximum 101
        if ($driftRoll -le $DriftPercent) {
            $driftType = Get-Random -Minimum 1 -Maximum 101
            if ($driftType -le 40) {
                $wrongDept = ($DepartmentList | Where-Object { $_.Acronym -ne $deptCode -and $_.Acronym -notin @('TST','CORP') } | Get-Random).Acronym
                $targetOU = "OU=$wrongDept,OU=People,$dn"
            } elseif ($driftType -le 60) {
                $targetOU = "OU=$deptCode,OU=Stage,$dn"
            } elseif ($driftType -le 80) {
                $tierChoice = @('Tier 1', 'Tier 2') | Get-Random
                $subOU = @('ServiceAccounts', 'Groups', 'Devices') | Get-Random
                $targetOU = "OU=$subOU,OU=$deptCode,OU=$tierChoice,$dn"
            } else {
                $targetOU = "OU=People,$dn"
                try {
                    $unassoc = "OU=Unassociated,OU=People,$dn"
                    Get-ADOrganizationalUnit $unassoc -Server $setDC | Out-Null
                    $targetOU = $unassoc
                } catch {}
            }
        }

        try { Get-ADOrganizationalUnit $targetOU -Server $setDC | Out-Null }
        catch {
            $targetOU = "OU=People,$dn"
            try { Get-ADOrganizationalUnit $targetOU -Server $setDC | Out-Null }
            catch { $targetOU = $dn }
        }

        # ---- PASSWORD ----
        $pwd = New-SWRandomPassword -MinPasswordLength 22 -MaxPasswordLength 25
        $description = "Created with BadderBlood"

        $pwdLeak = Get-Random -Minimum 1 -Maximum 1001
        if ($pwdLeak -le 10) {
            $description = "Just so I dont forget my password is $pwd"
        }

        # ---- CREATE THE USER ----
        $displayName = "$givenname $surname"

        try {
            New-ADUser -Server $setDC `
                -Name $name `
                -DisplayName $displayName `
                -GivenName $givenname `
                -Surname $surname `
                -SamAccountName $name `
                -Description $description `
                -Department $deptName `
                -Title $title `
                -Office $office.Office `
                -StreetAddress $office.StreetAddress `
                -City $office.City `
                -State $office.State `
                -PostalCode $office.PostalCode `
                -Country $office.Country `
                -OfficePhone $phone `
                -Company "BadderBlood Corp" `
                -EmployeeID $employeeID `
                -Enabled $true `
                -Path $targetOU `
                -AccountPassword (ConvertTo-SecureString $pwd -AsPlainText -Force) `
                -OtherAttributes @{
                    'departmentNumber' = $deptCode
                    'employeeType' = 'Employee'
                }
        } catch {
            try {
                New-ADUser -Server $setDC -Name $name -DisplayName $displayName `
                    -GivenName $givenname -Surname $surname -SamAccountName $name `
                    -Description $description -Department $deptName -Title $title `
                    -Enabled $true -Path $targetOU `
                    -AccountPassword (ConvertTo-SecureString $pwd -AsPlainText -Force)
            } catch {}
        }

        # Set UPN, home folder (H:), roaming profile path, and logon script.
        # BadFS creates the actual directory at \\SERVER\CorpData\Users\<sam>.
        # These attributes just need to be present on the account for Group Policy
        # and logon scripts to wire up the drive mapping correctly.
        $upn     = $name + '@' + $dnsroot
        $homeUNC = "\\$setDC\CorpData\Users\$name"
        try {
            Set-ADUser -Identity $name -UserPrincipalName $upn `
                -HomeDirectory $homeUNC -HomeDrive 'H:' `
                -ProfilePath "$homeUNC\Profile" `
                -ScriptPath 'logon.bat' `
                -Server $setDC
        } catch {
            try { Set-ADUser -Identity $name -UserPrincipalName $upn -Server $setDC } catch {}
        }

        # ---- TITLE-AWARE MANAGER ASSIGNMENT ----
        # Uses cached hashtable lookups instead of Where-Object pipelines
        if ($ExistingUsers -and $ExistingUsers.Count -gt 5) {
            $manager = Get-HierarchyManager -Title $title
            if ($manager) {
                try { Set-ADUser -Identity $name -Manager $manager.DistinguishedName -Server $setDC } catch {}
            } else {
                # No hierarchy match yet - fall back to same-dept higher-level user (60% chance)
                $managerRoll = Get-Random -Minimum 1 -Maximum 101
                if ($managerRoll -le 60) {
                    $titleLevel = if ($script:_bbTitleLevelMap.ContainsKey($title)) { $script:_bbTitleLevelMap[$title] } else { 8 }
                    # Find any user with a higher-level title using cached title-level map
                    $seniorPool = @()
                    foreach ($t in $script:_bbUsersByTitle.Keys) {
                        $tLevel = if ($script:_bbTitleLevelMap.ContainsKey($t)) { $script:_bbTitleLevelMap[$t] } else { 8 }
                        if ($tLevel -gt 0 -and $tLevel -lt $titleLevel) {
                            $seniorPool += $script:_bbUsersByTitle[$t]
                        }
                    }
                    if ($seniorPool.Count -gt 0) {
                        try {
                            $potentialManager = $seniorPool | Get-Random
                            Set-ADUser -Identity $name -Manager $potentialManager.DistinguishedName -Server $setDC
                        } catch {}
                    }
                }
            }
        }
    }

    $pwd = ''
}
