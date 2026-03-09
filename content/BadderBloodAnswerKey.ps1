#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    BadderBlood Domain Cleanup Answer Key Generator (v3 - Modularized)
.DESCRIPTION
    Audits an Active Directory domain after BadderBlood has been run and generates
    a comprehensive answer key showing:
      - Every violation found (what's wrong)
      - WHY it's a problem (attack scenario / security principle)
      - The user's OU/department context
      - The expected clean state (what students should fix it to)
      - Severity ratings for grading

    Designed for instructors running BadderBlood (or original BadBlood)
    in a lab environment.

    This script orchestrates modular audit sections located in AnswerKey_Sections\.

.NOTES
    Run this on a Domain Controller or a machine with RSAT installed.
    Must be run as a Domain Admin or equivalent.

.PARAMETER OutputPath
    Directory for all output files. Defaults to timestamped folder.
.PARAMETER IncludeGPOAnalysis
    Include GPO registry/SYSVOL analysis (requires GroupPolicy module).
.PARAMETER IncludeGPORemediation
    Run GPO remediation in report-only mode after analysis.
.PARAMETER ApplyGPORemediation
    Actually apply GPO remediation fixes (use with caution).
.PARAMETER DeleteInsecureGPOs
    Delete known insecure GPOs entirely instead of fixing in-place.
.PARAMETER BackupGPOs
    Backup all GPOs before applying remediation.
.PARAMETER ExportCSVs
    Export detailed user/group inventory CSVs.
.PARAMETER Quiet
    Suppress status messages.

.EXAMPLE
    .\BadderBloodAnswerKey.ps1
    .\BadderBloodAnswerKey.ps1 -OutputPath "C:\AnswerKeys" -IncludeGPOAnalysis
    .\BadderBloodAnswerKey.ps1 -IncludeGPOAnalysis -IncludeGPORemediation
    .\BadderBloodAnswerKey.ps1 -IncludeGPOAnalysis -IncludeGPORemediation -ApplyGPORemediation -BackupGPOs
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\BadderBlood_AnswerKey_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch]$IncludeGPOAnalysis,
    [switch]$IncludeGPORemediation,
    [switch]$ApplyGPORemediation,
    [switch]$DeleteInsecureGPOs,
    [switch]$BackupGPOs,
    [switch]$ExportCSVs,
    [switch]$Quiet
)

# ============================================================================
# DOT-SOURCE ALL MODULAR SECTIONS
# ============================================================================
$SectionsPath = Join-Path $PSScriptRoot "AnswerKey_Sections"

. (Join-Path $SectionsPath "AK_SharedConfig.ps1")
. (Join-Path $SectionsPath "AK_IdentifyObjects.ps1")
. (Join-Path $SectionsPath "AK_PrivilegedGroups.ps1")
. (Join-Path $SectionsPath "AK_AccountSettings.ps1")
. (Join-Path $SectionsPath "AK_OUDrift.ps1")
. (Join-Path $SectionsPath "AK_NestedGroups.ps1")
. (Join-Path $SectionsPath "AK_OUStructure.ps1")
. (Join-Path $SectionsPath "AK_ACLAnalysis.ps1")
. (Join-Path $SectionsPath "AK_GPOAnalysis.ps1")
. (Join-Path $SectionsPath "AK_SIDHistory.ps1")
. (Join-Path $SectionsPath "AK_Computers.ps1")
. (Join-Path $SectionsPath "AK_RBCD.ps1")
. (Join-Path $SectionsPath "AK_ShadowCredentials.ps1")
. (Join-Path $SectionsPath "AK_ADCS.ps1")
. (Join-Path $SectionsPath "AK_GMSA.ps1")
. (Join-Path $SectionsPath "AK_ADIDNS.ps1")
. (Join-Path $SectionsPath "AK_LAPSBypass.ps1")
. (Join-Path $SectionsPath "AK_GPORemediation.ps1")
. (Join-Path $SectionsPath "AK_ReportGeneration.ps1")

# ============================================================================
# SETUP
# ============================================================================

Write-Host @"
===============================================================================
   BadderBlood Domain Cleanup - Answer Key Generator (v3 Modular)
   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
===============================================================================
"@ -ForegroundColor Yellow

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$DomainInfo = Get-ADDomain
$ForestInfo = Get-ADForest
$DomainDN   = $DomainInfo.DistinguishedName
$DomainName = $DomainInfo.DNSRoot
$SetDC      = ($DomainInfo.PDCEmulator)

Write-Status "Auditing domain: $DomainName"
Write-Status "Domain DN: $DomainDN"
Write-Status "Output directory: $OutputPath"

$AllFindings = [System.Collections.Generic.List[PSObject]]::new()

# ============================================================================
# SECTION 1: IDENTIFY ALL BADBLOOD-CREATED OBJECTS
# ============================================================================
Write-Status "SECTION 1: Identifying all BadderBlood-created objects..."

$AllUsers = Get-ADUser -Filter * -Properties Description, MemberOf, Enabled, `
    PasswordNeverExpires, PasswordNotRequired, DoesNotRequirePreAuth, `
    TrustedForDelegation, TrustedToAuthForDelegation, AdminCount, `
    SIDHistory, ServicePrincipalName, CanonicalName, WhenCreated, `
    AllowReversiblePasswordEncryption, AccountNotDelegated

$AllGroups = Get-ADGroup -Filter * -Properties Description, Members, MemberOf, CanonicalName, WhenCreated, SIDHistory

$identifyResult = Invoke-AKIdentifyObjects -AllUsers $AllUsers -AllGroups $AllGroups
$BadderBloodUsers  = $identifyResult.BadderBloodUsers
$BadderBloodGroups = $identifyResult.BadderBloodGroups
$UserContextMap    = $identifyResult.UserContextMap

Write-Status "Found $($BadderBloodUsers.Count) BadderBlood-created users" "Green"
Write-Status "Found $($BadderBloodGroups.Count) BadderBlood-created security groups" "Green"

# ============================================================================
# SECTION 2: PRIVILEGED GROUP MEMBERSHIP VIOLATIONS
# ============================================================================
Write-Status "SECTION 2: Auditing privileged group memberships..."

$privResult = Invoke-AKPrivilegedGroupAudit -AllUsers $AllUsers -BadderBloodUsers $BadderBloodUsers -UserContextMap $UserContextMap
$AllFindings.AddRange($privResult.Findings)
$PrivGroupReport = $privResult.PrivGroupReport

# ============================================================================
# SECTION 3: DANGEROUS USER ACCOUNT SETTINGS
# ============================================================================
Write-Status "SECTION 3: Checking dangerous account settings..."

$acctFindings = Invoke-AKAccountSettingsAudit -AllUsers $AllUsers -BadderBloodUsers $BadderBloodUsers
$AllFindings.AddRange($acctFindings)

# ============================================================================
# SECTION 3b: OU DRIFT DETECTION
# ============================================================================
Write-Status "SECTION 3b: Checking for OU drift (users in wrong department OUs)..."

$driftFindings = Invoke-AKOUDriftAudit -DomainDN $DomainDN -SetDC $SetDC
$AllFindings.AddRange($driftFindings)

# ============================================================================
# SECTION 4: NESTED GROUP MEMBERSHIP CHAINS
# ============================================================================
Write-Status "SECTION 4: Checking for nested group privilege escalation..."

$nestedFindings = Invoke-AKNestedGroupAudit
$AllFindings.AddRange($nestedFindings)

# ============================================================================
# SECTION 5: OU STRUCTURE ANALYSIS
# ============================================================================
Write-Status "SECTION 5: Analyzing OU structure..."

$ouFindings = Invoke-AKOUStructureAudit -BadderBloodUsers $BadderBloodUsers
$AllFindings.AddRange($ouFindings)

# ============================================================================
# SECTION 6: ACL / DELEGATION ANALYSIS
# ============================================================================
Write-Status "SECTION 6: Analyzing ACL delegations on OUs and objects..."

$AllOUs = Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName
$aclFindings = Invoke-AKACLAudit -DomainDN $DomainDN -AllOUs $AllOUs -BadderBloodUsers $BadderBloodUsers -BadderBloodGroups $BadderBloodGroups
$AllFindings.AddRange($aclFindings)

# ============================================================================
# SECTION 7: GPO ANALYSIS (Optional)
# ============================================================================
if ($IncludeGPOAnalysis) {
    Write-Status "SECTION 7: Running comprehensive GPO analysis..."

    $gpoFindings = Invoke-AKGPOAudit -DomainDN $DomainDN -DomainDNS $DomainName -BadderBloodUsers $BadderBloodUsers -BadderBloodGroups $BadderBloodGroups
    $AllFindings.AddRange($gpoFindings)
} else {
    Write-Status "SECTION 7: GPO analysis skipped (use -IncludeGPOAnalysis to enable)" "Gray"
}

# ============================================================================
# SECTION 7b: SID HISTORY ON GROUPS
# ============================================================================
Write-Status "SECTION 7b: Checking SID History on groups..."

$sidFindings = Invoke-AKSIDHistoryAudit
$AllFindings.AddRange($sidFindings)

# ============================================================================
# SECTION 8: COMPUTER OBJECT ANALYSIS
# ============================================================================
Write-Status "SECTION 8: Analyzing computer objects..."

$compResult = Invoke-AKComputerAudit -BadderBloodGroups $BadderBloodGroups
$AllFindings.AddRange($compResult.Findings)
$Computers = $compResult.Computers

# ============================================================================
# SECTION 9: RBCD MISCONFIGURATION DETECTION
# ============================================================================
Write-Status "SECTION 9: Checking for RBCD misconfigurations..."

$rbcdResult = Invoke-AKRBCDAudit
$AllFindings.AddRange($rbcdResult.Findings)
$AllComputers = $rbcdResult.AllComputers

# ============================================================================
# SECTION 10: SHADOW CREDENTIALS DETECTION
# ============================================================================
Write-Status "SECTION 10: Checking for Shadow Credentials ACLs..."

$shadowFindings = Invoke-AKShadowCredentialsAudit -BadderBloodUsers $BadderBloodUsers
$AllFindings.AddRange($shadowFindings)

# ============================================================================
# SECTION 11: ADCS MISCONFIGURATION DETECTION
# ============================================================================
Write-Status "SECTION 11: Checking ADCS certificate template misconfigurations..."

$adcsFindings = Invoke-AKADCSAudit -BadderBloodUsers $BadderBloodUsers -BadderBloodGroups $BadderBloodGroups
$AllFindings.AddRange($adcsFindings)

# ============================================================================
# SECTION 12: gMSA MISCONFIGURATION DETECTION
# ============================================================================
Write-Status "SECTION 12: Checking gMSA misconfigurations..."

$gmsaFindings = Invoke-AKGMSAAudit
$AllFindings.AddRange($gmsaFindings)

# ============================================================================
# SECTION 13: ADIDNS MISCONFIGURATION DETECTION
# ============================================================================
Write-Status "SECTION 13: Checking ADIDNS misconfigurations..."

$adidnsFindings = Invoke-AKADIDNSAudit -DomainDN $DomainDN -DomainDNS $DomainName -BadderBloodUsers $BadderBloodUsers -BadderBloodGroups $BadderBloodGroups
$AllFindings.AddRange($adidnsFindings)

# ============================================================================
# SECTION 14: LAPS BYPASS DETECTION
# ============================================================================
Write-Status "SECTION 14: Checking for LAPS bypass opportunities..."

$lapsFindings = Invoke-AKLAPSBypassAudit -AllComputers $AllComputers -BadderBloodUsers $BadderBloodUsers -BadderBloodGroups $BadderBloodGroups
$AllFindings.AddRange($lapsFindings)

# ============================================================================
# GPO REMEDIATION (Optional)
# ============================================================================
if ($IncludeGPORemediation) {
    Write-Status "Running GPO Remediation..."

    $remResult = Invoke-AKGPORemediation `
        -Apply:$ApplyGPORemediation `
        -DeleteInsecureGPOs:$DeleteInsecureGPOs `
        -BackupFirst:$BackupGPOs `
        -OutputPath $OutputPath `
        -DomainDN $DomainDN `
        -DomainDNS $DomainName
}

# ============================================================================
# GENERATE REPORTS
# ============================================================================
Invoke-AKReportGeneration `
    -AllFindings $AllFindings `
    -PrivGroupReport $PrivGroupReport `
    -BadderBloodUsers $BadderBloodUsers `
    -BadderBloodGroups $BadderBloodGroups `
    -Computers $Computers `
    -AllComputers $AllComputers `
    -DomainName $DomainName `
    -DomainDN $DomainDN `
    -OutputPath $OutputPath `
    -ExportCSVs:$ExportCSVs
