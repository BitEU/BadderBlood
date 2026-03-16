<#
    .Synopsis
       BadderBlood - Generates a realistic Active Directory lab environment.
    .DESCRIPTION
       Creates a company-like AD structure with proper department placement, realistic naming,
       full user attributes, and controlled security misconfigurations for training.
       Unlike the original BadBlood, objects are placed realistically with intentional,
       discoverable security issues rather than random chaos.
    .PARAMETER UserCount
       Number of user accounts to create (default: 1500)
    .PARAMETER GroupCount
       Number of groups to create (default: 500)
    .PARAMETER ComputerCount
       Number of computer objects to create (default: 100)
    .PARAMETER DriftPercent
       Percentage of users placed in slightly wrong OUs (default: 8, range: 0-25)
    .PARAMETER ASREPCount
       Number of accounts to make AS-REP roastable (default: 5)
    .PARAMETER SPNCount
       Number of SPNs to create for Kerberoasting (default: 12)
    .PARAMETER WeakPasswordCount
       Number of accounts to set weak passwords on (default: 10)
    .EXAMPLE
       .\Invoke-BadderBlood.ps1
       .\Invoke-BadderBlood.ps1 -UserCount 1000 -GroupCount 200 -ComputerCount 50
       .\Invoke-BadderBlood.ps1 -NonInteractive -DriftPercent 15 -ASREPCount 8
    .NOTES
       BadderBlood - Realistic AD Lab Generator
       Based on BadBlood by David Rowe (secframe.com)
       Rewritten for realistic lab environments.
       
       WARNING: This tool is for TEST/LAB domains ONLY. Never run in production.
#>
[CmdletBinding()]
param
(
    [Parameter(Mandatory = $false)]
    [Int32]$UserCount = 1500,

    [Parameter(Mandatory = $false)]
    [Int32]$GroupCount = 500,

    [Parameter(Mandatory = $false)]
    [Int32]$ComputerCount = 100,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0,25)]
    [Int32]$DriftPercent = 8,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1,50)]
    [Int32]$ASREPCount = 5,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1,50)]
    [Int32]$SPNCount = 12,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0,100)]
    [Int32]$WeakPasswordCount = 10,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0,20)]
    [Int32]$RBCDCount = 3,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0,15)]
    [Int32]$ShadowCredCount = 3,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0,10)]
    [Int32]$ADCSCount = 4,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0,10)]
    [Int32]$GMSACount = 3,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0,20)]
    [Int32]$StaleRecordCount = 5,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0,15)]
    [Int32]$LAPSBypassCount = 4,

    [Parameter(Mandatory = $false)]
    [switch]$SkipOuCreation,

    [Parameter(Mandatory = $false)]
    [switch]$SkipLapsInstall,

    [Parameter(Mandatory = $false)]
    [switch]$NonInteractive,

    [Parameter(Mandatory = $false)]
    [switch]$SkipGPODeployment,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDecoyGPOs
)

function Get-ScriptDirectory {
    Split-Path -Parent $PSCommandPath
}
$basescriptPath = Get-ScriptDirectory

# =========================================================================
# BANNER
# =========================================================================
Clear-Host
Write-Host ''
Write-Host '  ================================================================' -ForegroundColor Red
Write-Host '  =                                                              =' -ForegroundColor Red
Write-Host '  =              B A D D E R   B L O O D                         =' -ForegroundColor Red
Write-Host '  =                                                              =' -ForegroundColor Red
Write-Host '  =         Realistic AD Lab Generator by Steven S.              =' -ForegroundColor Yellow
Write-Host '  =         Based on BadBlood by David Rowe (secframe.com)       =' -ForegroundColor Gray
Write-Host '  =                                                              =' -ForegroundColor Red
Write-Host '  ================================================================' -ForegroundColor Red
Write-Host ''

# =========================================================================
# CONFIGURATION DISPLAY
# =========================================================================
Write-Host "  Configuration:" -ForegroundColor White
Write-Host "    Users:           $UserCount" -ForegroundColor Cyan
Write-Host "    Groups:          $GroupCount" -ForegroundColor Cyan
Write-Host "    Computers:       $ComputerCount" -ForegroundColor Cyan
Write-Host "    OU Drift:        $DriftPercent%" -ForegroundColor Cyan
Write-Host "    AS-REP targets:  $ASREPCount" -ForegroundColor Cyan
Write-Host "    SPN targets:     $SPNCount" -ForegroundColor Cyan
Write-Host "    Weak passwords:  $WeakPasswordCount" -ForegroundColor Cyan
Write-Host "    RBCD misconfigs: $RBCDCount" -ForegroundColor Cyan
Write-Host "    Shadow Creds:    $ShadowCredCount" -ForegroundColor Cyan
Write-Host "    ADCS templates:  $ADCSCount" -ForegroundColor Cyan
Write-Host "    gMSA misconfigs: $GMSACount" -ForegroundColor Cyan
Write-Host "    Stale DNS:       $StaleRecordCount" -ForegroundColor Cyan
Write-Host "    LAPS bypasses:   $LAPSBypassCount" -ForegroundColor Cyan
Write-Host ""

# =========================================================================
# SAFETY CHECK
# =========================================================================
Write-Host "  WARNING: This tool creates thousands of objects in Active Directory." -ForegroundColor Yellow
Write-Host "  It should NEVER be run in a production environment." -ForegroundColor Yellow
Write-Host "  You are responsible for how you use this tool." -ForegroundColor Yellow
Write-Host ""

$badderblood = "badderblood"
if ($NonInteractive -eq $false) {
    $badderblood = Read-Host -Prompt "  Type 'badderblood' to begin deployment"
    $badderblood = $badderblood.ToLower()
    if ($badderblood -ne 'badderblood') {
        Write-Host "  Exiting." -ForegroundColor Red
        exit
    }
}

if ($badderblood -eq 'badderblood') {

    $totalPhases = if ($SkipGPODeployment) { 9 } else { 10 }
    $phase = 0
    $Domain = Get-ADDomain
    $setDC = $Domain.PDCEmulator

    # =====================================================================
    # PHASE 1: LAPS Schema
    # =====================================================================
    $phase++
    if ($PSBoundParameters.ContainsKey('SkipLapsInstall') -eq $false) {
        Write-Host ""
        Write-Host "  [$phase/$totalPhases] Installing LAPS Schema..." -ForegroundColor Green
        Write-Progress -Activity "BadderBlood Deployment" -Status "Phase ${phase}: LAPS Schema" -PercentComplete ($phase / $totalPhases * 100)
        . ($basescriptPath + '\AD_LAPS_Install\InstallLAPSSchema.ps1')
    } else {
        Write-Host ""
        Write-Host "  [$phase/$totalPhases] Skipping LAPS installation..." -ForegroundColor Gray
    }

    # =====================================================================
    # PHASE 2: OU Structure
    # =====================================================================
    $phase++
    if ($PSBoundParameters.ContainsKey('SkipOuCreation') -eq $false) {
        Write-Host ""
        Write-Host "  [$phase/$totalPhases] Creating OU structure..." -ForegroundColor Green
        Write-Progress -Activity "BadderBlood Deployment" -Status "Phase ${phase}: OU Structure" -PercentComplete ($phase / $totalPhases * 100)
        . ($basescriptPath + '\AD_OU_CreateStructure\CreateOUStructure.ps1')
    } else {
        Write-Host ""
        Write-Host "  [$phase/$totalPhases] Skipping OU creation..." -ForegroundColor Gray
    }

    # =====================================================================
    # PHASE 3: Load data files
    # =====================================================================
    $phase++
    Write-Host ""
        Write-Host "  [$phase/$totalPhases] Loading data files..." -ForegroundColor Green
    $OUsAll = Get-ADOrganizationalUnit -Filter * -Server $setDC
    $DepartmentList = Import-Csv ($basescriptPath + "\AD_Data\AD_Departments.csv")
    $JobTitleList = Import-Csv ($basescriptPath + "\AD_Data\JobTitles.csv")
    $OfficeList = Import-Csv ($basescriptPath + "\AD_Data\Offices.csv")
    Write-Host "    Loaded $($DepartmentList.Count) departments, $($JobTitleList.Count) titles (with hierarchy), $($OfficeList.Count) offices" -ForegroundColor Gray

    # =====================================================================
    # PHASE 4: User Creation
    # =====================================================================
    $phase++
    Write-Host ""
        Write-Host "  [$phase/$totalPhases] Creating $UserCount users..." -ForegroundColor Green
    . ($basescriptPath + '\AD_Users_Create\CreateUsers.ps1')
    $createuserscriptpath = $basescriptPath + '\AD_Users_Create\'

    function Format-BBProgressDuration {
        param([TimeSpan]$Duration)
        if ($Duration.TotalHours -ge 1) {
            return ('{0:00}:{1:00}:{2:00}' -f [int]$Duration.TotalHours, $Duration.Minutes, $Duration.Seconds)
        }
        return ('{0:00}:{1:00}' -f [int]$Duration.TotalMinutes, $Duration.Seconds)
    }

    # Determine adaptive refresh interval based on user count
    # Larger batches = fewer AD round-trips, but staler manager pool
    $refreshInterval = if ($UserCount -le 500) { 100 } elseif ($UserCount -le 2000) { 250 } else { 500 }
    $ExistingUsersPool = $null
    $userStartTime = Get-Date

    $x = 1
    do {
        # Refresh ExistingUsers at adaptive intervals so manager pool stays current
        if ($x % $refreshInterval -eq 0 -or $x -eq 1) {
            $ExistingUsersPool = Get-ADUser -Filter { Enabled -eq $true } -Properties Title,DistinguishedName,departmentNumber -Server $setDC -ResultSetSize $null
        }
        CreateUser -Domain $Domain -OUList $OUsAll -ScriptDir $createuserscriptpath `
            -DepartmentList $DepartmentList -JobTitleList $JobTitleList -OfficeList $OfficeList `
            -ExistingUsers $ExistingUsersPool `
            -DriftPercent $DriftPercent

        $completedUsers = $x
        if ($completedUsers % 25 -eq 0 -or $completedUsers -eq 1 -or $completedUsers -eq $UserCount) {
            $elapsed = (Get-Date) - $userStartTime
            $avgSecondsPerUser = $elapsed.TotalSeconds / [Math]::Max(1, $completedUsers)
            $remainingUsers = [Math]::Max(0, $UserCount - $completedUsers)
            $eta = [TimeSpan]::FromSeconds($avgSecondsPerUser * $remainingUsers)
            $status = "Phase ${phase}: Creating users ($completedUsers/$UserCount) | Elapsed $(Format-BBProgressDuration $elapsed) | ETA $(Format-BBProgressDuration $eta)"
            Write-Progress -Activity "BadderBlood Deployment" -Status $status -PercentComplete (($completedUsers / $UserCount) * 100)
        }
        $x++
    } while ($x -le $UserCount)
    Write-Progress -Activity "BadderBlood Deployment" -Status "Phase ${phase}: Creating users complete" -Completed
    Flush-BBPasswordExport
    Write-Host "    Created $UserCount users (drift: $DriftPercent%)" -ForegroundColor Gray

    # =====================================================================
    # PHASE 4.5: Fix Manager Relationships
    # =====================================================================
    Write-Host ""
    Write-Host "  [+] Fixing manager relationships..." -ForegroundColor Green
    & ($basescriptPath + '\AD_Users_Create\Fix-ManagerRelationships.ps1')

    # =====================================================================
    # PHASE 5: Group Creation
    # =====================================================================
    $phase++
    $AllUsers = Get-ADUser -Filter * -Properties Department,departmentNumber -Server $setDC -ResultSetSize $null
    Write-Host ""
        Write-Host "  [$phase/$totalPhases] Creating $GroupCount groups..." -ForegroundColor Green
    . ($basescriptPath + '\AD_Groups_Create\CreateGroup.ps1')
    $createGroupScriptPath = $basescriptPath + '\AD_Groups_Create\'
    $groupStartTime = Get-Date

    $x = 1
    do {
        CreateGroup -Domain $Domain -OUList $OUsAll -UserList $AllUsers -ScriptDir $createGroupScriptPath `
            -DepartmentList $DepartmentList
        $completedGroups = $x
        if ($completedGroups % 25 -eq 0 -or $completedGroups -eq 1 -or $completedGroups -eq $GroupCount) {
            $elapsed = (Get-Date) - $groupStartTime
            $avgSecondsPerGroup = $elapsed.TotalSeconds / [Math]::Max(1, $completedGroups)
            $remainingGroups = [Math]::Max(0, $GroupCount - $completedGroups)
            $eta = [TimeSpan]::FromSeconds($avgSecondsPerGroup * $remainingGroups)
            $status = "Phase ${phase}: Creating groups ($completedGroups/$GroupCount) | Elapsed $(Format-BBProgressDuration $elapsed) | ETA $(Format-BBProgressDuration $eta)"
            Write-Progress -Activity "BadderBlood Deployment" -Status $status -PercentComplete (($completedGroups / $GroupCount) * 100)
        }
        $x++
    } while ($x -le $GroupCount)
    Write-Progress -Activity "BadderBlood Deployment" -Status "Phase ${phase}: Creating groups complete" -Completed
    Write-Host "    Created $GroupCount groups" -ForegroundColor Gray

    $GroupList = Get-ADGroup -Filter { GroupCategory -eq "Security" -and GroupScope -eq "Global" } -Properties isCriticalSystemObject -Server $setDC
    $LocalGroupList = Get-ADGroup -Filter { GroupScope -eq "domainlocal" } -Properties isCriticalSystemObject -Server $setDC

    # =====================================================================
    # PHASE 6: Computer Creation
    # =====================================================================
    $phase++
    Write-Host ""
        Write-Host "  [$phase/$totalPhases] Creating $ComputerCount computers..." -ForegroundColor Green
    . ($basescriptPath + '\AD_Computers_Create\CreateComputers.ps1')
    $createComputerScriptPath = $basescriptPath + '\AD_Computers_Create\'

    $x = 1
    do {
        CreateComputer -Domain $Domain -OUList $OUsAll -UserList $AllUsers -ScriptDir $createComputerScriptPath `
            -DepartmentList $DepartmentList -OfficeList $OfficeList
        if ($x % 25 -eq 0) {
            Write-Progress -Activity "BadderBlood Deployment" -Status "Phase ${phase}: Creating computers ($x/$ComputerCount)" -PercentComplete ($x / $ComputerCount * 100)
        }
        $x++
    } while ($x -le $ComputerCount)
    Write-Host "    Created $ComputerCount computers" -ForegroundColor Gray

    $CompList = Get-ADComputer -Filter * -Server $setDC

    # =====================================================================
    # PHASE 7: ACL Misconfigurations (Realistic)
    # =====================================================================
    $phase++
    Write-Host ""
        Write-Host "  [$phase/$totalPhases] Creating realistic ACL misconfigurations..." -ForegroundColor Green
    Write-Progress -Activity "BadderBlood Deployment" -Status "Phase ${phase}: ACL Misconfigurations" -PercentComplete ($phase / $totalPhases * 100)
    . ($basescriptPath + '\AD_Permissions_Randomizer\GenerateRandomPermissions.ps1')

    # =====================================================================
    # PHASE 8: Group Membership (Realistic Nesting)
    # =====================================================================
    $phase++
    Write-Host ""
        Write-Host "  [$phase/$totalPhases] Populating group memberships..." -ForegroundColor Green
    Write-Progress -Activity "BadderBlood Deployment" -Status "Phase ${phase}: Group Memberships" -PercentComplete ($phase / $totalPhases * 100)
    . ($basescriptPath + '\AD_Groups_Create\AddRandomToGroups.ps1')
    AddRandomToGroups -Domain $Domain -UserList $AllUsers -GroupList $GroupList `
        -LocalGroupList $LocalGroupList -CompList $CompList

    # =====================================================================
    # PHASE 9: Attack Vectors (Controlled)
    # =====================================================================
    $phase++
    Write-Host ""
        Write-Host "  [$phase/$totalPhases] Injecting controlled attack vectors..." -ForegroundColor Green
    Write-Progress -Activity "BadderBlood Deployment" -Status "Phase ${phase}: Attack Vectors" -PercentComplete ($phase / $totalPhases * 100)

    # --- SPNs (Kerberoasting) ---
    Write-Host "    Setting up Kerberoasting targets ($SPNCount SPNs)..." -ForegroundColor Cyan
    . ($basescriptPath + '\AD_Attack_Vectors\AD_SPN_Randomizer\CreateRandomSPNs.ps1')
    CreateRandomSPNs -SPNCount $SPNCount

    # --- AS-REP Roasting ---
    Write-Host "    Setting up AS-REP Roasting targets ($ASREPCount accounts)..." -ForegroundColor Cyan
    # Prefer service accounts and users in non-standard OUs
    $ASREPCandidates = $AllUsers | Get-Random -Count ([Math]::Min($ASREPCount, $AllUsers.Count))
    . ($basescriptPath + '\AD_Attack_Vectors\ASREP_NotReqPreAuth.ps1')
    ADREP_NotReqPreAuth -UserList $ASREPCandidates

    # --- Weak Passwords (optional) ---
    if ($WeakPasswordCount -gt 0) {
        Write-Host "    Setting weak passwords ($WeakPasswordCount accounts)..." -ForegroundColor Cyan
        
        # Temporarily disable password complexity for lab purposes
        Write-Host "    [*] Temporarily disabling password complexity..." -ForegroundColor Yellow
        $OriginalComplexity = (Get-ADDefaultDomainPasswordPolicy).ComplexityEnabled
        $OriginalMinLength = (Get-ADDefaultDomainPasswordPolicy).MinPasswordLength
        Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -ComplexityEnabled $false -MinPasswordLength 1
        
        $WeakCandidates = $AllUsers | Get-Random -Count ([Math]::Min($WeakPasswordCount, $AllUsers.Count))
        . ($basescriptPath + '\AD_Attack_Vectors\WeakUserPasswords.ps1')
        WeakUserPasswords -UserList $WeakCandidates
        
        # Restore original password policy
        Write-Host "    [*] Restoring password complexity settings..." -ForegroundColor Yellow
        Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -ComplexityEnabled $OriginalComplexity -MinPasswordLength $OriginalMinLength
    }

    # --- SID History (if DSInternals available) ---
    if (Get-Module -ListAvailable -Name DSInternals) {
        Write-Host "    DSInternals found - applying SID History attacks..." -ForegroundColor Cyan
        . ($basescriptPath + '\AD_Attack_Vectors\SIDHistory_dsinternals.ps1')
    }

    # --- RBCD Misconfiguration ---
    if ($RBCDCount -gt 0) {
        Write-Host "    Setting up RBCD misconfigurations ($RBCDCount targets)..." -ForegroundColor Cyan
        . ($basescriptPath + '\AD_Attack_Vectors\RBCD_Misconfiguration.ps1')
        Set-RBCDMisconfiguration -RBCDCount $RBCDCount
    }

    # --- Shadow Credentials ---
    if ($ShadowCredCount -gt 0) {
        Write-Host "    Setting up Shadow Credentials attack paths ($ShadowCredCount targets)..." -ForegroundColor Cyan
        . ($basescriptPath + '\AD_Attack_Vectors\ShadowCredentials.ps1')
        Set-ShadowCredentialsMisconfiguration -ShadowCredCount $ShadowCredCount
    }

    # --- ADCS Misconfigurations ---
    if ($ADCSCount -gt 0) {
        Write-Host "    Setting up ADCS misconfigurations ($ADCSCount templates)..." -ForegroundColor Cyan
        . ($basescriptPath + '\AD_Attack_Vectors\ADCS_Misconfiguration.ps1')
        Set-ADCSMisconfiguration -TemplateCount $ADCSCount
    }

    # --- gMSA Abuse ---
    if ($GMSACount -gt 0) {
        Write-Host "    Setting up gMSA misconfigurations ($GMSACount accounts)..." -ForegroundColor Cyan
        . ($basescriptPath + '\AD_Attack_Vectors\GMSA_Misconfiguration.ps1')
        Set-GMSAMisconfiguration -GMSACount $GMSACount
    }

    # --- ADIDNS Poisoning ---
    if ($StaleRecordCount -gt 0) {
        Write-Host "    Setting up ADIDNS misconfigurations ($StaleRecordCount stale records)..." -ForegroundColor Cyan
        . ($basescriptPath + '\AD_Attack_Vectors\ADIDNS_Poisoning.ps1')
        Set-ADIDNSMisconfiguration -StaleRecordCount $StaleRecordCount
    }

    # --- LAPS Bypass ---
    if ($LAPSBypassCount -gt 0) {
        Write-Host "    Setting up LAPS bypass paths ($LAPSBypassCount targets)..." -ForegroundColor Cyan
        . ($basescriptPath + '\AD_Attack_Vectors\LAPS_Bypass.ps1')
        Set-LAPSBypassMisconfiguration -LAPSBypassCount $LAPSBypassCount
    }

    # =====================================================================
    # PHASE 10: GPO Misconfigurations (Optional)
    # =====================================================================
    $phase++
    if ($PSBoundParameters.ContainsKey('SkipGPODeployment') -eq $false) {
        Write-Host ""
        Write-Host "  [$phase/$totalPhases] Deploying insecure GPOs..." -ForegroundColor Green
        Write-Progress -Activity "BadderBlood Deployment" -Status "Phase ${phase}: GPO Misconfigurations" -PercentComplete ($phase / $totalPhases * 100)

        $gpoScript = $basescriptPath + '\Invoke-BadderBloodGPO.ps1'
        if (Test-Path $gpoScript) {
            $gpoArgs = @{ SkipLinking = $false }
            if ($IncludeDecoyGPOs) { $gpoArgs['IncludeDecoyGPOs'] = $true }
            & $gpoScript @gpoArgs
        } else {
            Write-Warning "  Invoke-BadderBloodGPO.ps1 not found at '$gpoScript'. Skipping GPO phase."
        }
    } else {
        Write-Host ""
        Write-Host "  [$phase/$totalPhases] Skipping GPO deployment..." -ForegroundColor Gray
    }

    # =====================================================================
    # COMPLETE
    # =====================================================================
    Write-Progress -Activity "BadderBlood Deployment" -Completed

    Write-Host ""
    Write-Host '  ================================================================' -ForegroundColor Green
    Write-Host '                     DEPLOYMENT COMPLETE                          ' -ForegroundColor Green
    Write-Host '  ================================================================' -ForegroundColor Green
    Write-Host ""
    Write-Host "  Summary:" -ForegroundColor White
    Write-Host "    Users created:      $UserCount ($DriftPercent% drifted)" -ForegroundColor Cyan
    Write-Host "    Groups created:     $GroupCount" -ForegroundColor Cyan
    Write-Host "    Computers created:  $ComputerCount" -ForegroundColor Cyan
    Write-Host "    Kerberoast targets: $SPNCount" -ForegroundColor Cyan
    Write-Host "    AS-REP targets:     $ASREPCount" -ForegroundColor Cyan
    Write-Host "    Weak passwords:     $WeakPasswordCount" -ForegroundColor Cyan
    Write-Host "    RBCD misconfigs:    $RBCDCount" -ForegroundColor Cyan
    Write-Host "    Shadow Creds:       $ShadowCredCount" -ForegroundColor Cyan
    Write-Host "    ADCS templates:     $ADCSCount" -ForegroundColor Cyan
    Write-Host "    gMSA misconfigs:    $GMSACount" -ForegroundColor Cyan
    Write-Host "    Stale DNS records:  $StaleRecordCount" -ForegroundColor Cyan
    Write-Host "    LAPS bypasses:      $LAPSBypassCount" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Attack vectors injected:" -ForegroundColor White
    Write-Host "    - Overly broad helpdesk delegation" -ForegroundColor Yellow
    Write-Host "    - IT groups with excessive OU permissions" -ForegroundColor Yellow
    Write-Host "    - Direct user ACL grants (non-group-based)" -ForegroundColor Yellow
    Write-Host "    - Leftover migration permissions on domain root" -ForegroundColor Yellow
    Write-Host "    - WriteDACL escalation paths" -ForegroundColor Yellow
    Write-Host "    - Group-to-group permission chains" -ForegroundColor Yellow
    Write-Host "    - Nested group attack paths" -ForegroundColor Yellow
    Write-Host "    - Service accounts with Kerberoastable SPNs" -ForegroundColor Yellow
    Write-Host "    - AS-REP Roastable accounts" -ForegroundColor Yellow
    Write-Host "    - Users in wrong OUs (departmental drift)" -ForegroundColor Yellow
    Write-Host "    - Passwords in description fields" -ForegroundColor Yellow
    Write-Host "    - Resource-Based Constrained Delegation (RBCD)" -ForegroundColor Yellow
    Write-Host "    - Shadow Credentials (msDS-KeyCredentialLink)" -ForegroundColor Yellow
    Write-Host "    - ADCS certificate template misconfigurations (ESC1/2/4)" -ForegroundColor Yellow
    Write-Host "    - gMSA password retrieval by low-priv principals" -ForegroundColor Yellow
    Write-Host "    - ADIDNS stale records and zone ACL misconfigs" -ForegroundColor Yellow
    Write-Host "    - LAPS password read by non-admin groups" -ForegroundColor Yellow
    Write-Host ""
    if ($PSBoundParameters.ContainsKey('SkipGPODeployment') -eq $false) {
        Write-Host "    GPO misconfigs:     deployed (18-20 insecure GPOs)" -ForegroundColor Cyan
    }
    Write-Host ""
    Write-Host "  Next step: Run BadderBloodAnswerKey.ps1 -IncludeGPOAnalysis to generate the findings report." -ForegroundColor White
    Write-Host ""
}