################################
# CreateComputers.ps1 - BadderBlood Realistic Computer Generator
# Computers are named consistently, placed in correct OUs,
# and have location, description, and OS attributes.
################################
Function CreateComputer {
    <#
        .SYNOPSIS
            Creates a realistic computer object in Active Directory with proper naming, placement, and attributes.
        .DESCRIPTION
            Generates workstations and servers with consistent naming conventions, places them in
            appropriate OUs by department and type, and populates location/description attributes.
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
        [Object[]]$UserList,
        [Parameter(Mandatory = $false)]
        [string]$ScriptDir,
        [Parameter(Mandatory = $false)]
        [Object[]]$DepartmentList,
        [Parameter(Mandatory = $false)]
        [Object[]]$OfficeList
    )

    # ----- Resolve parameters -----
    if (!$PSBoundParameters.ContainsKey('Domain')) {
        if ($args[0]) { $setDC = $args[0].pdcemulator; $dn = $args[0].distinguishedname }
        else { $d = Get-ADDomain; $setDC = $d.pdcemulator; $dn = $d.distinguishedname }
    } else { $setDC = $Domain.pdcemulator; $dn = $Domain.distinguishedname }

    if (!$PSBoundParameters.ContainsKey('OUList')) {
        $OUsAll = Get-ADOrganizationalUnit -Filter * -Server $setDC
    } else { $OUsAll = $OUList }

    if (!$PSBoundParameters.ContainsKey('UserList')) {
        $UserList = Get-ADUser -ResultSetSize 1500 -Server $setDC -Filter *
    }

    if (!$PSBoundParameters.ContainsKey('ScriptDir')) {
        if ($args[2]) { $scriptpath = $args[2] }
        else { $scriptpath = "$((Get-Location).path)\AD_Computers_Create\" }
    } else { $scriptpath = $ScriptDir }

    $scriptparent = (Get-Item $scriptpath).parent.fullname

    if (!$PSBoundParameters.ContainsKey('DepartmentList')) {
        $DepartmentList = Import-Csv ($scriptparent + "\AD_Data\AD_Departments.csv")
    }
    if (!$PSBoundParameters.ContainsKey('OfficeList')) {
        $OfficeList = Import-Csv ($scriptparent + "\AD_Data\Offices.csv")
    }

    $3lettercodes = Import-Csv ($scriptparent + "\AD_OU_CreateStructure\3lettercodes.csv")

    # ----- Decide: Workstation (75%) or Server (25%) -----
    $machineType = Get-Random -Minimum 1 -Maximum 101

    if ($machineType -le 75) {
        # ==================== WORKSTATION ====================
        $dept = ($3lettercodes | Get-Random).NAME
        $office = $OfficeList | Get-Random

        # Workstation type
        $wsType = Get-Random -Minimum 1 -Maximum 101
        if ($wsType -le 55) {
            $typeCode = "WKS"  # Desktop
            $osName = "Windows 10 Enterprise"
            $osVersion = @("10.0 (19045)","10.0 (22631)") | Get-Random
            $descPrefix = "Desktop"
        } elseif ($wsType -le 85) {
            $typeCode = "LPT"  # Laptop
            $osName = "Windows 11 Enterprise"
            $osVersion = @("10.0 (22621)","10.0 (22631)","10.0 (26100)") | Get-Random
            $descPrefix = "Laptop"
        } else {
            $typeCode = "VDI"  # Virtual desktop
            $osName = "Windows 10 Enterprise"
            $osVersion = "10.0 (19045)"
            $descPrefix = "Virtual Desktop"
        }

        # Naming: DEPT-TYPE-NNNNN (e.g., BDE-WKS-00142)
        $seqNum = Get-Random -Minimum 100 -Maximum 99999
        $compName = "$dept-$typeCode-$($seqNum.ToString('D5'))"

        # Truncate to 15 chars (NetBIOS limit)
        if ($compName.Length -gt 15) { $compName = $compName.Substring(0, 15) }

        # OU Placement: Tier 2 > Department > Devices (workstations are Tier 2)
        $targetOU = "OU=Devices,OU=$dept,OU=Tier 2,$dn"
        try { Get-ADOrganizationalUnit $targetOU -Server $setDC | Out-Null }
        catch {
            # Fallback to Tier 2 root
            $targetOU = "OU=Tier 2,$dn"
            try { Get-ADOrganizationalUnit $targetOU -Server $setDC | Out-Null }
            catch { $targetOU = $dn }
        }

        $description = "$descPrefix - $($office.Office) - $(($DepartmentList | Where-Object { $_.Acronym -eq $dept }).'Department Name')"
        $location = $office.Office
        $ownerinfo = $UserList | Get-Random

    } else {
        # ==================== SERVER ====================
        $dept = ($3lettercodes | Get-Random).NAME
        $office = $OfficeList | Where-Object { $_.Office -like "DC-*" -or $_.Office -like "HQ-*" } | Get-Random
        if (!$office) { $office = $OfficeList | Get-Random }

        # Server role
        $srvRole = Get-Random -Minimum 1 -Maximum 101
        if ($srvRole -le 25) {
            $typeCode = "APP"; $descPrefix = "Application Server"
        } elseif ($srvRole -le 45) {
            $typeCode = "WEB"; $descPrefix = "Web Server"
        } elseif ($srvRole -le 60) {
            $typeCode = "SQL"; $descPrefix = "Database Server"
        } elseif ($srvRole -le 75) {
            $typeCode = "FIL"; $descPrefix = "File Server"
        } elseif ($srvRole -le 85) {
            $typeCode = "CTX"; $descPrefix = "Citrix Server"
        } else {
            $typeCode = "INF"; $descPrefix = "Infrastructure Server"
        }

        $osName = @("Windows Server 2019 Standard","Windows Server 2019 Datacenter","Windows Server 2022 Standard","Windows Server 2022 Datacenter","Windows Server 2016 Standard") | Get-Random
        $osVersion = @("10.0 (17763)","10.0 (20348)","10.0 (14393)") | Get-Random

        $seqNum = Get-Random -Minimum 1 -Maximum 999
        $compName = "$dept-$typeCode-$($seqNum.ToString('D3'))"
        if ($compName.Length -gt 15) { $compName = $compName.Substring(0, 15) }

        # OU Placement: Tier 1 > Department > Devices (servers are Tier 1)
        $targetOU = "OU=Devices,OU=$dept,OU=Tier 1,$dn"
        try { Get-ADOrganizationalUnit $targetOU -Server $setDC | Out-Null }
        catch {
            $targetOU = "OU=Tier 1,$dn"
            try { Get-ADOrganizationalUnit $targetOU -Server $setDC | Out-Null }
            catch { $targetOU = $dn }
        }

        $description = "$descPrefix - $($office.Office) - $(($DepartmentList | Where-Object { $_.Acronym -eq $dept }).'Department Name')"
        $location = $office.Office
        $ownerinfo = $UserList | Get-Random
    }

    # ---- Create the computer ----
    $sam = $compName + '$'
    $manager = $ownerinfo.DistinguishedName

    # Check for dupe
    $checkDupe = $null
    try { $checkDupe = Get-ADComputer $compName -Server $setDC -ErrorAction Stop } catch {}
    if ($checkDupe) { return }

    try {
        New-ADComputer -Server $setDC `
            -Name $compName `
            -DisplayName $compName `
            -SamAccountName $sam `
            -Description $description `
            -Location $location `
            -ManagedBy $manager `
            -OperatingSystem $osName `
            -OperatingSystemVersion $osVersion `
            -Enabled $true `
            -Path $targetOU
    } catch {
        # Fallback: simpler creation
        try {
            New-ADComputer -Server $setDC -Name $compName -DisplayName $compName `
                -SamAccountName $sam -Description $description -Enabled $true `
                -ManagedBy $manager -Path $targetOU
        } catch {
            try {
                New-ADComputer -Server $setDC -Name $compName -DisplayName $compName `
                    -SamAccountName $sam -Enabled $true -Description $description
            } catch {}
        }
    }
}