<#
    .Synopsis
       BadderBlood - Generates a realistic Active Directory lab environment.
    .DESCRIPTION
       Creates a company-like AD structure with proper department placement, realistic naming,
       full user attributes, and controlled security misconfigurations for training.
       Unlike the original BadBlood, objects are placed realistically with intentional,
       discoverable security issues rather than random chaos.
    .PARAMETER UserCount
       Number of user accounts to create (default: 2500)
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
       .\Invoke-BadBlood.ps1
       .\Invoke-BadBlood.ps1 -UserCount 1000 -GroupCount 200 -ComputerCount 50
       .\Invoke-BadBlood.ps1 -NonInteractive -DriftPercent 15 -ASREPCount 8
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
    [Int32]$UserCount = 2500,

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
    [switch]$SkipOuCreation,

    [Parameter(Mandatory = $false)]
    [switch]$SkipLapsInstall,

    [Parameter(Mandatory = $false)]
    [switch]$NonInteractive
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
Write-Host ""

# =========================================================================
# SAFETY CHECK
# =========================================================================
Write-Host "  WARNING: This tool creates thousands of objects in Active Directory." -ForegroundColor Yellow
Write-Host "  It should NEVER be run in a production environment." -ForegroundColor Yellow
Write-Host "  You are responsible for how you use this tool." -ForegroundColor Yellow
Write-Host ""

$badblood = "badblood"
if ($NonInteractive -eq $false) {
    $badblood = Read-Host -Prompt "  Type 'badblood' to begin deployment"
    $badblood = $badblood.ToLower()
    if ($badblood -ne 'badblood') {
        Write-Host "  Exiting." -ForegroundColor Red
        exit
    }
}

if ($badblood -eq 'badblood') {

    $totalPhases = 9
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
    Write-Host "    Loaded $($DepartmentList.Count) departments, $($JobTitleList.Count) titles, $($OfficeList.Count) offices" -ForegroundColor Gray

    # =====================================================================
    # PHASE 4: User Creation
    # =====================================================================
    $phase++
    Write-Host ""
        Write-Host "  [$phase/$totalPhases] Creating $UserCount users..." -ForegroundColor Green
    . ($basescriptPath + '\AD_Users_Create\CreateUsers.ps1')
    $createuserscriptpath = $basescriptPath + '\AD_Users_Create\'

    $x = 1
    do {
        CreateUser -Domain $Domain -OUList $OUsAll -ScriptDir $createuserscriptpath `
            -DepartmentList $DepartmentList -JobTitleList $JobTitleList -OfficeList $OfficeList `
            -DriftPercent $DriftPercent
        if ($x % 100 -eq 0) {
            Write-Progress -Activity "BadderBlood Deployment" -Status "Phase ${phase}: Creating users ($x/$UserCount)" -PercentComplete ($x / $UserCount * 100)
        }
        $x++
    } while ($x -le $UserCount)
    Write-Host "    Created $UserCount users (drift: $DriftPercent%)" -ForegroundColor Gray

    # =====================================================================
    # PHASE 5: Group Creation
    # =====================================================================
    $phase++
    $AllUsers = Get-ADUser -Filter * -Properties Department,departmentNumber -Server $setDC
    Write-Host ""
        Write-Host "  [$phase/$totalPhases] Creating $GroupCount groups..." -ForegroundColor Green
    . ($basescriptPath + '\AD_Groups_Create\CreateGroup.ps1')
    $createGroupScriptPath = $basescriptPath + '\AD_Groups_Create\'

    $x = 1
    do {
        CreateGroup -Domain $Domain -OUList $OUsAll -UserList $AllUsers -ScriptDir $createGroupScriptPath `
            -DepartmentList $DepartmentList
        if ($x % 50 -eq 0) {
            Write-Progress -Activity "BadderBlood Deployment" -Status "Phase ${phase}: Creating groups ($x/$GroupCount)" -PercentComplete ($x / $GroupCount * 100)
        }
        $x++
    } while ($x -le $GroupCount)
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
    Write-Host ""
    Write-Host "  Next step: Run BadBloodAnswerKey.ps1 to generate the findings report." -ForegroundColor White
    Write-Host ""
}