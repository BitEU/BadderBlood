################################
# LAPS_Bypass.ps1 - BadderBlood LAPS Bypass Attack Vectors
# Simulates realistic LAPS misconfigurations beyond basic installation:
# - Overly broad ms-Mcs-AdmPwd read rights
# - LAPS not deployed to all OUs
# - Computers with LAPS password readable by non-admin groups
# - Legacy LAPS (ms-Mcs-AdmPwd) vs Windows LAPS (msLAPS-Password) gaps
################################
function Set-LAPSBypassMisconfiguration {
    <#
        .SYNOPSIS
            Creates realistic LAPS bypass scenarios for training.
        .DESCRIPTION
            Simulates common LAPS deployment mistakes:
            1. Non-admin groups with read access to LAPS passwords
            2. OUs where LAPS GPO is not linked (computers have no LAPS)
            3. Computers with LAPS password in an extended attribute
               readable by overly broad groups
            4. Service accounts with LAPS read permissions (lateral movement)
            Discoverable via LAPSToolkit, Get-LAPSPasswords, crackmapexec.
        .PARAMETER LAPSBypassCount
            Number of LAPS bypass paths to create (default: 4)
        .NOTES
            BadderBlood - Realistic AD Lab Generator
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 15)]
        [int]$LAPSBypassCount = 4
    )

    $dom = Get-ADDomain
    $setDC = $dom.PDCEmulator
    $dn = $dom.DistinguishedName
    Set-Location AD:

    # Detect which LAPS attribute exists in the schema
    $schemaNC = (Get-ADRootDSE).SchemaNamingContext
    $lapsAttrGuid = $null
    $lapsAttrName = $null

    # Try Windows LAPS first (Server 2019+)
    try {
        $wlapsAttr = Get-ADObject -SearchBase $schemaNC -LDAPFilter "(&(lDAPDisplayName=msLAPS-Password)(schemaidguid=*))" -Properties schemaIDGUID -ErrorAction Stop
        if ($wlapsAttr) {
            $lapsAttrGuid = [System.GUID]$wlapsAttr.schemaIDGUID
            $lapsAttrName = "msLAPS-Password"
        }
    } catch {}

    # Fall back to Legacy LAPS (ms-Mcs-AdmPwd)
    if (-not $lapsAttrGuid) {
        try {
            $legacyAttr = Get-ADObject -SearchBase $schemaNC -LDAPFilter "(&(lDAPDisplayName=ms-Mcs-AdmPwd)(schemaidguid=*))" -Properties schemaIDGUID -ErrorAction Stop
            if ($legacyAttr) {
                $lapsAttrGuid = [System.GUID]$legacyAttr.schemaIDGUID
                $lapsAttrName = "ms-Mcs-AdmPwd"
            }
        } catch {}
    }

    if (-not $lapsAttrGuid) {
        Write-Host "    [X] No LAPS schema attributes found (ms-Mcs-AdmPwd or msLAPS-Password). LAPS schema not extended?" -ForegroundColor Red
        return
    }

    Write-Host "    [*] Using LAPS attribute: $lapsAttrName" -ForegroundColor Cyan

    $allGroups = Get-ADGroup -Filter { GroupCategory -eq "Security" } -Properties isCriticalSystemObject -Server $setDC -ResultSetSize $null
    $nonCritGroups = @($allGroups | Where-Object { $_.isCriticalSystemObject -ne $true })
    $allUsers = Get-ADUser -Filter * -Server $setDC -ResultSetSize $null
    $allOUs = Get-ADOrganizationalUnit -Filter * -Server $setDC
    $allComputers = Get-ADComputer -Filter * -Server $setDC -ResultSetSize $null

    # Find computer-containing OUs
    $computerOUs = @{}
    foreach ($comp in $allComputers) {
        $parentOU = ($comp.DistinguishedName -split ',', 2)[1]
        if (-not $computerOUs.ContainsKey($parentOU)) {
            $computerOUs[$parentOU] = [System.Collections.Generic.List[object]]::new()
        }
        $computerOUs[$parentOU].Add($comp)
    }

    $configured = 0

    # =========================================================================
    # Scenario 1: Non-admin group has read access to LAPS password attribute
    # Realistic: "The helpdesk group was granted LAPS read for workstation support,
    # but it also covers server OUs"
    # =========================================================================
    if ($configured -lt $LAPSBypassCount -and $nonCritGroups.Count -gt 0) {
        foreach ($ouDN in ($computerOUs.Keys | Get-Random -Count ([Math]::Min(2, $computerOUs.Keys.Count)))) {
            if ($configured -ge $LAPSBypassCount) { break }

            $attackerGroup = $nonCritGroups | Get-Random
            $groupSID = New-Object System.Security.Principal.SecurityIdentifier $attackerGroup.SID

            try {
                $acl = Get-Acl "AD:\$ouDN"
                $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $groupSID,
                    "ReadProperty",
                    "Allow",
                    $lapsAttrGuid,
                    "Descendents"
                )
                $acl.AddAccessRule($rule)
                Set-Acl -AclObject $acl -Path "AD:\$ouDN" -ErrorAction Stop

                $ouName = ($ouDN -split ',')[0] -replace 'OU=',''
                Write-Host "    [!] LAPS Bypass: Group '$($attackerGroup.Name)' can read $lapsAttrName in OU '$ouName'" -ForegroundColor Yellow
                $configured++
            } catch {}
        }
    }

    # =========================================================================
    # Scenario 2: Individual user with LAPS read on specific computers
    # Realistic: "An admin granted their own account read access for quick access"
    # =========================================================================
    if ($configured -lt $LAPSBypassCount -and $allUsers.Count -gt 0 -and $allComputers.Count -gt 0) {
        $directAccessUser = $allUsers | Get-Random
        $targetComputers = $allComputers | Get-Random -Count ([Math]::Min(3, $allComputers.Count))
        $userSID = New-Object System.Security.Principal.SecurityIdentifier $directAccessUser.SID

        foreach ($comp in $targetComputers) {
            if ($configured -ge $LAPSBypassCount) { break }

            try {
                $compDN = "AD:\$($comp.DistinguishedName)"
                $acl = Get-Acl $compDN
                $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $userSID,
                    "ReadProperty",
                    "Allow",
                    $lapsAttrGuid,
                    "None"
                )
                $acl.AddAccessRule($rule)
                Set-Acl -AclObject $acl -Path $compDN -ErrorAction Stop

                Write-Host "    [!] LAPS Bypass: User '$($directAccessUser.SamAccountName)' can read $lapsAttrName on '$($comp.Name)'" -ForegroundColor Yellow
                $configured++
            } catch {}
        }
    }

    # =========================================================================
    # Scenario 3: GenericAll on computer objects (implies LAPS read)
    # Realistic: "Group has FullControl on an OU for management, which
    # includes the ability to read LAPS attributes"
    # =========================================================================
    if ($configured -lt $LAPSBypassCount -and $nonCritGroups.Count -gt 0 -and $computerOUs.Count -gt 0) {
        $targetOU = $computerOUs.Keys | Get-Random
        $attackerGroup = $nonCritGroups | Get-Random
        $groupSID = New-Object System.Security.Principal.SecurityIdentifier $attackerGroup.SID

        try {
            $acl = Get-Acl "AD:\$targetOU"
            $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $groupSID,
                "GenericAll",
                "Allow",
                "Descendents"
            )
            $acl.AddAccessRule($rule)
            Set-Acl -AclObject $acl -Path "AD:\$targetOU" -ErrorAction Stop

            $ouName = ($targetOU -split ',')[0] -replace 'OU=',''
            Write-Host "    [!] LAPS Bypass: Group '$($attackerGroup.Name)' has GenericAll on OU '$ouName' (implies LAPS read)" -ForegroundColor Yellow
            $configured++
        } catch {}
    }

    # =========================================================================
    # Scenario 4: Service account with LAPS read (lateral movement path)
    # Realistic: "Monitoring service needs LAPS passwords to rotate local admin"
    # =========================================================================
    if ($configured -lt $LAPSBypassCount) {
        $serviceAccounts = @($allUsers | Where-Object { $_.SamAccountName -like "*SA" -or $_.SamAccountName -like "svc_*" })
        if ($serviceAccounts.Count -gt 0 -and $computerOUs.Count -gt 0) {
            $svcAccount = $serviceAccounts | Get-Random
            $targetOU = $computerOUs.Keys | Get-Random
            $svcSID = New-Object System.Security.Principal.SecurityIdentifier $svcAccount.SID

            try {
                $acl = Get-Acl "AD:\$targetOU"
                $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $svcSID,
                    "ReadProperty",
                    "Allow",
                    $lapsAttrGuid,
                    "Descendents"
                )
                $acl.AddAccessRule($rule)
                Set-Acl -AclObject $acl -Path "AD:\$targetOU" -ErrorAction Stop

                $ouName = ($targetOU -split ',')[0] -replace 'OU=',''
                Write-Host "    [!] LAPS Bypass: Service account '$($svcAccount.SamAccountName)' can read $lapsAttrName in OU '$ouName'" -ForegroundColor Yellow
                $configured++
            } catch {}
        }
    }

    Write-Host "    [+] Created $configured LAPS bypass paths" -ForegroundColor Green
}
