################################
# CreateGroup.ps1 - BadderBlood Realistic Group Generator
# Groups are named with department context and placed in proper OUs.
# Group types: departmental, project, application access, distribution lists
################################
Function CreateGroup {
    <#
        .SYNOPSIS
            Creates a realistic AD group with proper naming convention and placement.
        .DESCRIPTION
            Generates groups that look like a real company: department groups, application access
            groups, project groups, and distribution lists. All placed in appropriate OUs.
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
        [Object[]]$DepartmentList
    )

    # ----- Resolve parameters -----
    if (!$PSBoundParameters.ContainsKey('Domain')) {
        if ($args[0]) { $setDC = $args[0].pdcemulator; $dn = $args[0].distinguishedname; $domainDNS = $args[0].DNSRoot }
        else { $d = Get-ADDomain; $setDC = $d.pdcemulator; $dn = $d.distinguishedname; $domainDNS = $d.DNSRoot }
    } else { $setDC = $Domain.pdcemulator; $dn = $Domain.distinguishedname; $domainDNS = $Domain.DNSRoot }

    if (!$PSBoundParameters.ContainsKey('OUList')) {
        $OUsAll = Get-ADOrganizationalUnit -Filter * -Server $setDC
    } else { $OUsAll = $OUList }

    if (!$PSBoundParameters.ContainsKey('UserList')) {
        $UserList = Get-ADUser -ResultSetSize 1500 -Server $setDC -Filter *
    }

    if (!$PSBoundParameters.ContainsKey('ScriptDir')) {
        if ($args[3]) { $scriptpath = $args[3] }
        else { $scriptpath = "$((Get-Location).path)\AD_Groups_Create\" }
    } else { $scriptpath = $ScriptDir }

    $scriptparent = (Get-Item $scriptpath).parent.fullname

    if (!$PSBoundParameters.ContainsKey('DepartmentList')) {
        $DepartmentList = Import-Csv ($scriptparent + "\AD_Data\AD_Departments.csv")
    }

    # ----- Group naming components -----
    $appNames = @(
        'SharePoint','SAP','Salesforce','JIRA','Confluence','Teams','OneDrive',
        'ServiceNow','Workday','Concur','DocuSign','Slack','Zoom','ADP',
        'Oracle','NetSuite','Tableau','PowerBI','GitHub','Jenkins','Ansible',
        'Splunk','CrowdStrike','Qualys','Nessus','CyberArk','PaloAlto',
        'Fortinet','VMware','Citrix','Veeam','Commvault','Exchange',
        'FileshareHQ','FileshareDC','PrinterHQ','VPN','WiFi-Corp','WiFi-Guest',
        'RemoteDesktop','DuoMFA','Okta','PingID','ArcherGRC','Proofpoint'
    )

    $projectNames = @(
        'Phoenix','Atlas','Horizon','Mercury','Titan','Nebula','Catalyst',
        'Voyager','Summit','Pinnacle','Falcon','Eclipse','Quantum','Apex',
        'Vanguard','Compass','Frontier','Cornerstone','Keystone','Evergreen',
        'CloudMigration','DataCenter-Refresh','Win11-Rollout','SAP-Upgrade',
        'ZeroTrust-Phase1','Office365-Migration','DR-Modernization'
    )

    $accessLevels = @('Read','Write','Admin','FullAccess','Users','Managers','Operators','Viewers')

    # ----- Decide group type -----
    $groupType = Get-Random -Minimum 1 -Maximum 101
    $dept = ($DepartmentList | Where-Object { $_.Acronym -ne 'TST' } | Get-Random)
    $deptCode = $dept.Acronym
    $ownerinfo = $UserList | Get-Random

    if ($groupType -le 30) {
        # APPLICATION ACCESS GROUP: APP-AppName-AccessLevel
        $app = $appNames | Get-Random
        $access = $accessLevels | Get-Random
        $groupName = "APP-$app-$access"
        $description = "Application access: $app ($access) - Managed by $($dept.'Department Name')"
        $groupCategory = 'Security'
        $groupScope = 'Global'
        $targetTier = @('Tier 1','Tier 2') | Get-Random
    }
    elseif ($groupType -le 50) {
        # DEPARTMENT GROUP: DEPT-DeptCode-Function
        $functions = @('All-Staff','Managers','Leads','Contractors','Remote','Onsite','Team-A','Team-B','Ops','Engineering')
        $func = $functions | Get-Random
        $groupName = "DEPT-$deptCode-$func"
        $description = "$($dept.'Department Name') - $func"
        $groupCategory = 'Security'
        $groupScope = 'Global'
        $targetTier = 'Tier 2'
    }
    elseif ($groupType -le 65) {
        # PROJECT GROUP: PRJ-ProjectName-Role
        $proj = $projectNames | Get-Random
        $roles = @('Members','Leads','Admins','ReadOnly','Contributors')
        $role = $roles | Get-Random
        $groupName = "PRJ-$proj-$role"
        $description = "Project: $proj ($role)"
        $groupCategory = 'Security'
        $groupScope = 'Global'
        $targetTier = @('Tier 1','Tier 2') | Get-Random
    }
    elseif ($groupType -le 80) {
        # DISTRIBUTION LIST: DL-DeptCode-Purpose
        $purposes = @('All','Announcements','Team','Management','Events','Newsletter','Alerts')
        $purpose = $purposes | Get-Random
        $groupName = "DL-$deptCode-$purpose"
        $description = "Distribution list: $($dept.'Department Name') $purpose"
        $groupCategory = 'Distribution'
        $groupScope = 'Global'
        $targetTier = 'Tier 2'
    }
    elseif ($groupType -le 90) {
        # ROLE-BASED GROUP: ROLE-Function
        $roleNames = @(
            'Helpdesk-PasswordReset','Helpdesk-AccountUnlock','Server-Admins-T1',
            'Server-Admins-T2','Workstation-Admins','VPN-Users','Remote-Workers',
            'MFA-Exempt','WiFi-CorpAccess','Printer-Admins','FileShare-Admins',
            'Backup-Operators','Patch-Approvers','Software-Deployers',
            'Service-Desk-Agents','Change-Advisory-Board','IT-On-Call'
        )
        $roleName = $roleNames | Get-Random
        $groupName = "ROLE-$roleName"
        $description = "Role-based access: $roleName"
        $groupCategory = 'Security'
        $groupScope = 'Global'
        $targetTier = @('Tier 1','Tier 2') | Get-Random
    }
    else {
        # ADMIN GROUP: ADM-DeptCode-Permission
        $adminPerms = @('OU-FullControl','OU-UserMgmt','OU-ComputerMgmt','GPO-Edit','GPO-Link','LAPS-Read','LAPS-Reset')
        $perm = $adminPerms | Get-Random
        $groupName = "ADM-$deptCode-$perm"
        $description = "Admin delegation: $deptCode $perm"
        $groupCategory = 'Security'
        $groupScope = 'DomainLocal'
        $targetTier = 'Tier 1'
    }

    # ----- Ensure unique name -----
    $origName = $groupName
    $i = 1
    $checkAcct = $null
    do {
        $safeGroupName = $groupName.Replace("'", "''")
        $checkAcct = Get-ADGroup -Filter "SamAccountName -eq '$safeGroupName'" -Server $setDC
        if ($checkAcct) {
            $groupName = "$origName-$i"
            $i++
        }
    } while ($null -ne $checkAcct -and $i -lt 20)

    # ----- OU Placement -----
    $targetOU = "OU=Groups,OU=$deptCode,OU=$targetTier,$dn"
    $safeTargetDn = $targetOU.Replace("'", "''")
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$safeTargetDn'" -Server $setDC)) {
        # Try Grouper-Groups OU
        $targetOU = "OU=Grouper-Groups,$dn"
        $safeGrouperDn = $targetOU.Replace("'", "''")
        if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$safeGrouperDn'" -Server $setDC)) {
            $targetOU = $dn
        }
    }

    # ----- Create the group -----
    $groupMail = "$($groupName.ToLower())@$domainDNS"
    try {
        New-ADGroup -Server $setDC `
            -Name $groupName `
            -Description $description `
            -Path $targetOU `
            -GroupCategory $groupCategory `
            -GroupScope $groupScope `
            -ManagedBy $ownerinfo.DistinguishedName `
            -OtherAttributes @{ mail = $groupMail }
    } catch {
        try {
            New-ADGroup -Server $setDC -Name $groupName -Description $description `
                -Path $targetOU -GroupCategory $groupCategory -GroupScope $groupScope `
                -OtherAttributes @{ mail = $groupMail }
        } catch {}
    }
}