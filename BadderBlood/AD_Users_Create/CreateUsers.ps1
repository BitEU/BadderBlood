################################
# CreateUsers.ps1 - BadderBlood Realistic User Generator
# Users are placed in correct department OUs with full AD attributes.
# Org hierarchy is title-aware: only higher-level titles manage lower ones.
# Singleton roles (CEO, CFO, CISO, etc.) are enforced via MaxCount.
################################
Function CreateUser {
    <#
        .SYNOPSIS
            Creates a realistic user in Active Directory with proper department placement and full attributes.
        .DESCRIPTION
            Generates users with department, title, phone, office, manager, and places them in the
            correct OU. Title-aware manager assignment ensures realistic reporting chains.
            Singleton roles (CEO, CFO, etc.) are enforced so only one can exist.
            A configurable percentage are intentionally drifted to wrong OUs.
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

    # ----- Password Generator -----
    function New-SWRandomPassword {
        [CmdletBinding(DefaultParameterSetName='FixedLength')]
        [OutputType([String])]
        Param(
            [Parameter(ParameterSetName='RandomLength')][Alias('Min')][int]$MinPasswordLength = 12,
            [Parameter(ParameterSetName='RandomLength')][Alias('Max')][int]$MaxPasswordLength = 20,
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

    # ----- Title-aware manager resolver -----
    # Given a title, find an AD user whose title is the direct ReportsTo parent (or any ancestor).
    # Falls back up the chain if no direct manager exists yet.
    function Get-HierarchyManager {
        param(
            [string]$Title,
            [Object[]]$Hierarchy,
            [Object[]]$CandidateUsers,
            [int]$MaxAncestors = 5
        )
        $current = $Title
        for ($depth = 0; $depth -lt $MaxAncestors; $depth++) {
            $entry = $Hierarchy | Where-Object { $_.Title -eq $current } | Select-Object -First 1
            if (!$entry -or [string]::IsNullOrEmpty($entry.ReportsTo)) { return $null }
            $parentTitle = $entry.ReportsTo
            $match = $CandidateUsers | Where-Object { $_.Title -eq $parentTitle } | Get-Random -ErrorAction SilentlyContinue
            if ($match) { return $match }
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
        if ($exists) { return $true }

        New-ADUser -Server $setDC -Description $description -DisplayName $name -Name $name `
            -SamAccountName $name -Enabled $true -Path $targetOU `
            -AccountPassword (ConvertTo-SecureString $pwd -AsPlainText -Force) `
            -OtherAttributes @{
                'employeeType' = 'Service'
                'departmentNumber' = $dept
                'department' = ($DepartmentList | Where-Object { $_.Acronym -eq $dept }).'Department Name'
            }

        try { Set-ADUser -Identity $name -UserPrincipalName "$name@$dnsroot" -Server $setDC } catch {}

    } else {
        # ---- REGULAR USER ----
        $surname = Get-Content ("$($scriptpath)\Names\familynames-usa-top1000.txt") | Get-Random
        $genderpreference = 0, 1 | Get-Random
        if ($genderpreference -eq 0) {
            $givenname = Get-Content ("$($scriptpath)\Names\femalenames-usa-top1000.txt") | Get-Random
        } else {
            $givenname = Get-Content ($scriptpath + '\Names\malenames-usa-top1000.txt') | Get-Random
        }

        $givenname = (Get-Culture).TextInfo.ToTitleCase($givenname.Trim().ToLower())
        $surname = (Get-Culture).TextInfo.ToTitleCase($surname.Trim().ToLower())

        $name = $givenname + "_" + $surname
        if ($name.Length -gt 20) { $name = $name.Substring(0, 20) }

        $exists = $null
        try { $exists = Get-ADUser $name -Server $setDC -ErrorAction Stop } catch {}
        if ($exists) { return $true }

        # ---- ASSIGN DEPARTMENT ----
        # Weight departments: business departments get more users than IT/security
        $deptWeights = @{
            'BDE' = 20; 'HRE' = 10; 'FIN' = 15; 'OGC' = 8; 'FSR' = 12
            'AWS' = 5;  'ESM' = 5;  'SEC' = 5;  'ITS' = 8; 'GOO' = 4
            'AZR' = 5;  'TST' = 3
        }
        $weightedDepts = @()
        foreach ($d in $deptWeights.Keys) {
            for ($w = 0; $w -lt $deptWeights[$d]; $w++) { $weightedDepts += $d }
        }
        $deptCode = $weightedDepts | Get-Random
        $deptInfo = $DepartmentList | Where-Object { $_.Acronym -eq $deptCode }
        $deptName = $deptInfo.'Department Name'

        # ---- ASSIGN TITLE (with singleton enforcement) ----
        # Titles with MaxCount > 0 are capped; MaxCount = 0 means unlimited IC roles.
        $deptTitles = $JobTitleList | Where-Object { $_.Acronym -eq $deptCode -or $_.Acronym -eq 'CORP' }

        # For each capped title, check how many already exist in AD
        $eligibleTitles = @()
        foreach ($t in $deptTitles) {
            $cap = [int]$t.MaxCount
            if ($cap -eq 0) {
                # Unlimited IC role — always eligible, but weight toward lower-level roles
                # Level 6 ICs get a higher weight than Level 5 managers to keep the pyramid shape
                $icWeight = [math]::Max(1, 8 - [int]$t.Level)
                for ($w = 0; $w -lt $icWeight; $w++) { $eligibleTitles += $t }
            } else {
                # Check current count in AD
                try {
                    $existing = (Get-ADUser -Filter "Title -eq '$($t.Title)'" -Server $setDC -ErrorAction Stop | Measure-Object).Count
                } catch { $existing = 0 }
                if ($existing -lt $cap) {
                    # Higher-level capped roles get lower weight (pyramid shape)
                    $capWeight = [math]::Max(1, 4 - [int]$t.Level)
                    for ($w = 0; $w -lt $capWeight; $w++) { $eligibleTitles += $t }
                }
            }
        }

        # Fallback: if all capped roles are full, pick any IC title for this dept
        if ($eligibleTitles.Count -eq 0) {
            $eligibleTitles = $JobTitleList | Where-Object { $_.Acronym -eq $deptCode -and $_.MaxCount -eq '0' }
        }
        if ($eligibleTitles.Count -eq 0) {
            $eligibleTitles = $JobTitleList | Where-Object { $_.Acronym -eq $deptCode }
        }

        $selectedTitle = ($eligibleTitles | Get-Random)
        $title = $selectedTitle.Title

        # CORP-titled users (CEO etc.) use a pseudo-dept for OU placement — put them in the most fitting dept
        if ($selectedTitle.Acronym -eq 'CORP') {
            # CEO/COO land in the ITS or root People OU; use a real dept for OU placement
            $deptCode = 'ITS'
            $deptInfo = $DepartmentList | Where-Object { $_.Acronym -eq $deptCode }
            $deptName = $deptInfo.'Department Name'
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

        # Set UPN
        $upn = $name + '@' + $dnsroot
        try { Set-ADUser -Identity $name -UserPrincipalName $upn -Server $setDC } catch {}

        # ---- TITLE-AWARE MANAGER ASSIGNMENT ----
        # Try to find a user whose title is the direct ReportsTo parent (walk up if needed).
        # Only assign manager if we have enough users to search through.
        if ($ExistingUsers -and $ExistingUsers.Count -gt 5) {
            $manager = Get-HierarchyManager -Title $title -Hierarchy $OrgHierarchy -CandidateUsers $ExistingUsers
            if ($manager) {
                try { Set-ADUser -Identity $name -Manager $manager.DistinguishedName -Server $setDC } catch {}
            } else {
                # No hierarchy match yet — fall back to same-dept higher-level user (60% chance)
                $managerRoll = Get-Random -Minimum 1 -Maximum 101
                if ($managerRoll -le 60) {
                    $titleLevel = [int]($JobTitleList | Where-Object { $_.Title -eq $title } | Select-Object -First 1).Level
                    $seniorPool = $ExistingUsers | Where-Object {
                        $userTitle = $_.Title
                        $userLevel = [int]($JobTitleList | Where-Object { $_.Title -eq $userTitle } | Select-Object -First 1).Level
                        $userLevel -gt 0 -and $userLevel -lt $titleLevel
                    }
                    if ($seniorPool) {
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
