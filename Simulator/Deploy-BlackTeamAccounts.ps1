<#
.SYNOPSIS
    Phase 1: Provisions Black Team AD accounts and out-of-band scoring infrastructure.

.DESCRIPTION
    Creates the BlackTeam OU under OU=Admin and provisions five dedicated service accounts
    used exclusively by the Continuous Activity Simulator. These accounts are protected from
    accidental deletion and are explicitly listed in the Rules of Engagement as off-limits to
    Blue Team students.

    Accounts created:
        BlackTeam_Scorebot  - Scoring engine read access to AD
        BlackTeam_SQLBot    - SQL traffic generator (NailInventoryDB, TimesheetLegacy)
        BlackTeam_WebBot    - IIS traffic generator
        BlackTeam_FileBot   - SMB file operations on CorpData share
        BlackTeam_MailBot   - SMTP relay for email simulation

    After account creation the script:
        - Grants BlackTeam_SQLBot db_datareader/db_datawriter on NailInventoryDB and TimesheetLegacy
        - Grants BlackTeam_FileBot Read/Write on the CorpData SMB share (if running on the file server)
        - Writes the initial credentials.json to C:\Simulator\
        - Writes Rules_of_Engagement.txt to C:\CorpShares\Public_Company_Data\ (if present)

.NOTES
    Run AFTER Invoke-BadderBlood.ps1 and BadSQL.ps1.
    Must be run as Domain Admin on a DC or machine with RSAT AD tools.

    Context: Educational / CTF / Active Directory Lab Environment
#>

#Requires -RunAsAdministrator

param(
    [string]$DomainDN              = "",   # Auto-detected if blank
    [SecureString]$SharedPassword  = $null,  # BlackTeam account password; prompted if omitted
    [string]$SqlInstance           = "localhost\BADSQL",
    [SecureString]$SqlSaPassword   = $null,  # If blank, Windows Auth is used for SQL grant step
    [string]$CorpSharePath         = "C:\CorpShares",
    [string]$SimulatorPath         = "C:\Simulator",
    [switch]$SkipSqlGrants,
    [switch]$SkipShareGrants,
    [switch]$NonInteractive
)

# Resolve default password when not supplied (avoids hardcoded plaintext in param block)
if (-not $SharedPassword) {
    $SharedPassword = ConvertTo-SecureString "B!ackT3am_Sc0reb0t_2025#" -AsPlainText -Force
}

# Helper to extract plaintext from a SecureString (used only for credential files / conn strings)
function ConvertFrom-SecureStringPlain { param([SecureString]$s)
    [System.Net.NetworkCredential]::new('', $s).Password
}

$ErrorActionPreference = "Stop"

# ==============================================================================
# LOGGING
# ==============================================================================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    switch ($Level) {
        "INFO"    { Write-Host "[$ts] [INFO]    $Message" -ForegroundColor Cyan }
        "SUCCESS" { Write-Host "[$ts] [SUCCESS] $Message" -ForegroundColor Green }
        "WARNING" { Write-Host "[$ts] [WARNING] $Message" -ForegroundColor Yellow }
        "ERROR"   { Write-Host "[$ts] [ERROR]   $Message" -ForegroundColor Red }
        "STEP"    { Write-Host "" ; Write-Host "[$ts] >>> $Message" -ForegroundColor White }
        default   { Write-Host "[$ts] $Message" }
    }
}

Write-Log "=================================================================" "INFO"
Write-Log "  BadderBlood Continuous Activity Simulator" "INFO"
Write-Log "  Phase 1: Black Team Account Provisioning" "INFO"
Write-Log "  Educational / CTF / Lab Use Only" "WARNING"
Write-Log "=================================================================" "INFO"

# ==============================================================================
# 1. RESOLVE DOMAIN
# ==============================================================================

Write-Log "Resolving Active Directory domain..." "STEP"

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Log "ActiveDirectory module not found. Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" "ERROR"
    exit 1
}

try {
    $Domain   = Get-ADDomain
    $DomainDN = $Domain.DistinguishedName
    $DomainNB = $Domain.NetBIOSName
    Write-Log "Domain: $($Domain.DNSRoot) | DN: $DomainDN" "SUCCESS"
} catch {
    Write-Log "Cannot reach Active Directory: $_" "ERROR"
    exit 1
}

# ==============================================================================
# 2. CREATE BLACKTEAM OU
# ==============================================================================

Write-Log "Creating BlackTeam OU..." "STEP"

$AdminOU      = "OU=Admin,$DomainDN"
$BlackTeamOU  = "OU=BlackTeam,OU=Admin,$DomainDN"

# Verify OU=Admin exists
$adminOUObj = Get-ADOrganizationalUnit -Filter { DistinguishedName -eq $AdminOU } -ErrorAction SilentlyContinue
if (-not $adminOUObj) {
    Write-Log "OU=Admin,$DomainDN not found. Attempting to create it..." "WARNING"
    try {
        New-ADOrganizationalUnit -Name "Admin" -Path $DomainDN -ProtectedFromAccidentalDeletion $true
        Write-Log "Created OU=Admin" "SUCCESS"
    } catch {
        Write-Log "Could not create OU=Admin: $_" "ERROR"
        exit 1
    }
}

$blackTeamOUObj = Get-ADOrganizationalUnit -Filter { DistinguishedName -eq $BlackTeamOU } -ErrorAction SilentlyContinue
if ($blackTeamOUObj) {
    Write-Log "BlackTeam OU already exists - skipping creation." "WARNING"
} else {
    New-ADOrganizationalUnit -Name "BlackTeam" -Path $AdminOU -ProtectedFromAccidentalDeletion $true
    Write-Log "Created OU=BlackTeam,OU=Admin" "SUCCESS"
}

# ==============================================================================
# 3. DEFINE ACCOUNTS
# ==============================================================================

$SecurePass = $SharedPassword   # already a SecureString
$SharedPasswordPlain = ConvertFrom-SecureStringPlain $SharedPassword

$Accounts = @(
    @{
        Name        = "BlackTeam_Scorebot"
        Description = "Scoring engine service account - reads AD health metrics. DO NOT MODIFY (RoE)."
        Notes       = "AD Read"
    },
    @{
        Name        = "BlackTeam_SQLBot"
        Description = "SQL traffic generator - supplier delivery simulation. DO NOT MODIFY (RoE)."
        Notes       = "SQL db_datareader/db_datawriter on NailInventoryDB, TimesheetLegacy"
    },
    @{
        Name        = "BlackTeam_WebBot"
        Description = "IIS traffic generator - customer order simulation. DO NOT MODIFY (RoE)."
        Notes       = "IIS Read on Springfield Box Factory sites"
    },
    @{
        Name        = "BlackTeam_FileBot"
        Description = "SMB file operations generator - employee file activity. DO NOT MODIFY (RoE)."
        Notes       = "CorpData share Read/Write"
    },
    @{
        Name        = "BlackTeam_MailBot"
        Description = "Email traffic generator - internal SMTP relay. DO NOT MODIFY (RoE)."
        Notes       = "SMTP Relay permission on mail relay"
    }
)

# ==============================================================================
# 4. CREATE ACCOUNTS
# ==============================================================================

Write-Log "Provisioning Black Team service accounts..." "STEP"

foreach ($acct in $Accounts) {
    $acctName = $acct.Name
    $acctDesc = $acct.Description
    $existing = Get-ADUser -Filter "SamAccountName -eq '$acctName'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Log "$acctName already exists - ensuring enabled and password reset." "WARNING"
        Set-ADUser -Identity $acctName -Enabled $true -Description $acctDesc `
            -PasswordNeverExpires $true -CannotChangePassword $true -ErrorAction SilentlyContinue
        Set-ADAccountPassword -Identity $acctName -NewPassword $SecurePass -Reset -ErrorAction SilentlyContinue
    } else {
        New-ADUser `
            -Name              $acctName `
            -SamAccountName    $acctName `
            -UserPrincipalName "$acctName@$($Domain.DNSRoot)" `
            -Path              $BlackTeamOU `
            -Description       $acctDesc `
            -AccountPassword   $SecurePass `
            -Enabled           $true `
            -PasswordNeverExpires $true `
            -CannotChangePassword $true `
            -ErrorAction       Stop
        Write-Log "Created: $acctName" "SUCCESS"
    }
}

# ==============================================================================
# 5. SQL GRANTS (BlackTeam_SQLBot)
# ==============================================================================

if (-not $SkipSqlGrants) {
    Write-Log "Granting SQL permissions to BlackTeam_SQLBot..." "STEP"

    function Invoke-SqlCmd2 {
        param([string]$Query, [string]$Database = "master")
        try {
            $conn = New-Object System.Data.SqlClient.SqlConnection
            if ($SqlSaPassword) {
                $saPlain = ConvertFrom-SecureStringPlain $SqlSaPassword
                $conn.ConnectionString = "Server=$SqlInstance;Database=$Database;User Id=sa;Password=$saPlain;"
            } else {
                $conn.ConnectionString = "Server=$SqlInstance;Database=$Database;Integrated Security=SSPI;"
            }
            $conn.Open()
            $cmd = $conn.CreateCommand()
            $cmd.CommandText = $Query
            $cmd.CommandTimeout = 30
            $null = $cmd.ExecuteNonQuery()
            $conn.Close()
            return $true
        } catch {
            Write-Log "SQL Error: $_" "WARNING"
            return $false
        }
    }

    $sqlBotLogin = "$DomainNB\BlackTeam_SQLBot"

    # Execute each USE-scoped block separately (USE statements cannot be batched across databases)
    $masterBlock = @"
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'$sqlBotLogin')
    CREATE LOGIN [$sqlBotLogin] FROM WINDOWS WITH DEFAULT_DATABASE=[NailInventoryDB];
"@
    $invBlock = @"
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$sqlBotLogin')
    CREATE USER [$sqlBotLogin] FOR LOGIN [$sqlBotLogin];
ALTER ROLE db_datareader ADD MEMBER [$sqlBotLogin];
ALTER ROLE db_datawriter ADD MEMBER [$sqlBotLogin];
"@
    $tsBlock = @"
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$sqlBotLogin')
    CREATE USER [$sqlBotLogin] FOR LOGIN [$sqlBotLogin];
ALTER ROLE db_datareader ADD MEMBER [$sqlBotLogin];
ALTER ROLE db_datawriter ADD MEMBER [$sqlBotLogin];
"@

    if (Invoke-SqlCmd2 -Query $masterBlock -Database "master") {
        Write-Log "Created Windows login for $sqlBotLogin" "SUCCESS"
    }
    if (Invoke-SqlCmd2 -Query $invBlock -Database "NailInventoryDB") {
        Write-Log "Granted db_datareader/db_datawriter on NailInventoryDB" "SUCCESS"
    }
    if (Invoke-SqlCmd2 -Query $tsBlock -Database "TimesheetLegacy") {
        Write-Log "Granted db_datareader/db_datawriter on TimesheetLegacy" "SUCCESS"
    }
} else {
    Write-Log "Skipping SQL grants (-SkipSqlGrants specified)." "WARNING"
}

# ==============================================================================
# 6. SHARE GRANTS (BlackTeam_FileBot)
# ==============================================================================

if (-not $SkipShareGrants) {
    Write-Log "Granting CorpData share permissions to BlackTeam_FileBot..." "STEP"

    # BadFS.ps1 shares $CorpSharePath directly as "CorpData" (no subfolder).
    $corpDataPath = $CorpSharePath
    if (Test-Path $corpDataPath) {
        try {
            $fileBotAccount = "$DomainNB\BlackTeam_FileBot"
            $acl = Get-Acl $corpDataPath
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $fileBotAccount,
                [System.Security.AccessControl.FileSystemRights]::Modify,
                [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit",
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $acl.AddAccessRule($rule)
            Set-Acl -Path $corpDataPath -AclObject $acl
            Write-Log "Granted Modify on $corpDataPath to $fileBotAccount" "SUCCESS"
        } catch {
            Write-Log "Could not set ACL on CorpData: $_ (non-fatal, share may not be on this host)" "WARNING"
        }
    } else {
        Write-Log "CorpData path not found at $corpDataPath - skipping share grant (run BadFS.ps1 first or run this on the file server)." "WARNING"
    }
} else {
    Write-Log "Skipping share grants (-SkipShareGrants specified)." "WARNING"
}

# ==============================================================================
# 7. WRITE credentials.json
# ==============================================================================

Write-Log "Writing credentials.json to $SimulatorPath..." "STEP"

if (-not (Test-Path $SimulatorPath)) {
    New-Item -ItemType Directory -Path $SimulatorPath -Force | Out-Null
    Write-Log "Created directory: $SimulatorPath" "SUCCESS"
}

$credJson = @"
{
  "_comment": "Simulator credential store. Update passwords here within 5 minutes of any AD rotation.",
  "_roe": "These accounts are off-limits per the Rules of Engagement. Do not disable, delete, or change passwords without updating this file.",
  "scorebot": {
    "username": "BlackTeam_Scorebot",
    "domain": "$DomainNB",
    "password": "$SharedPasswordPlain",
    "lastUpdated": "$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')"
  },
  "sql": {
    "username": "BlackTeam_SQLBot",
    "domain": "$DomainNB",
    "password": "$SharedPasswordPlain",
    "lastUpdated": "$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')"
  },
  "iis": {
    "username": "BlackTeam_WebBot",
    "domain": "$DomainNB",
    "password": "$SharedPasswordPlain",
    "lastUpdated": "$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')"
  },
  "smb": {
    "username": "BlackTeam_FileBot",
    "domain": "$DomainNB",
    "password": "$SharedPasswordPlain",
    "lastUpdated": "$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')"
  },
  "smtp": {
    "username": "BlackTeam_MailBot",
    "domain": "$DomainNB",
    "password": "$SharedPasswordPlain",
    "lastUpdated": "$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')"
  }
}
"@

$credPath = Join-Path $SimulatorPath "credentials.json"
$credJson | Out-File -FilePath $credPath -Encoding UTF8 -Force
Write-Log "credentials.json written to $credPath" "SUCCESS"

# ==============================================================================
# 8. WRITE Rules_of_Engagement.txt
# ==============================================================================

Write-Log "Writing Rules_of_Engagement.txt..." "STEP"

$roeContent = @"
================================================================================
  SPRINGFIELD BOX FACTORY - BLUE TEAM EXERCISE
  RULES OF ENGAGEMENT (ROE)
  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Domain: $($Domain.DNSRoot)
================================================================================

OVERVIEW
--------
This lab simulates a live enterprise environment. A Continuous Activity Simulator
runs from an out-of-band VM and generates realistic background traffic including
SQL transactions, file operations, web requests, helpdesk tickets, and email.

Scoring is automated. Service uptime is measured continuously. Disrupting simulator
traffic reduces your team's score.

================================================================================
BLACK TEAM ACCOUNTS - STRICTLY OFF-LIMITS
================================================================================

The following accounts exist SOLELY to drive simulator traffic. You MUST NOT:
  - Disable them
  - Delete them
  - Change their passwords without immediately updating credentials.json
  - Remove them from required groups or revoke their minimum permissions
  - Move them out of OU=BlackTeam,OU=Admin

ACCOUNT LIST:
  BlackTeam_Scorebot   - Scoring engine. Reads AD objects and service health.
  BlackTeam_SQLBot     - SQL traffic. Requires db_datareader/db_datawriter on
                         NailInventoryDB and TimesheetLegacy.
  BlackTeam_WebBot     - Web traffic. Requires Read on IIS Springfield Box Factory sites.
  BlackTeam_FileBot    - SMB traffic. Requires Modify on the CorpData share.
  BlackTeam_MailBot    - Email traffic. Requires SMTP relay permission.

OU=BlackTeam,OU=Admin is protected from accidental deletion. Attempting to remove
the ProtectedFromAccidentalDeletion flag or delete the OU will be flagged as a
scoring violation.

================================================================================
CREDENTIAL ROTATION SLA
================================================================================

If your team rotates a service account password that a simulator account depends on
(e.g. svc_sql, svc_webadmin), you MUST update C:\Simulator\credentials.json on the
simulator VM within 5 MINUTES of the rotation.

Failure to update credentials.json will cause simulator traffic to fail and your
team will lose uptime points until the file is updated and the simulator reconnects.

credentials.json location: C:\Simulator\credentials.json

JSON format:
  {
    "sql":  { "username": "BlackTeam_SQLBot",  "domain": "DOMAIN", "password": "..." },
    "iis":  { "username": "BlackTeam_WebBot",  "domain": "DOMAIN", "password": "..." },
    "smb":  { "username": "BlackTeam_FileBot", "domain": "DOMAIN", "password": "..." },
    "smtp": { "username": "BlackTeam_MailBot", "domain": "DOMAIN", "password": "..." }
  }

================================================================================
WHAT YOU CAN DO
================================================================================

  - Remediate ALL other misconfigured accounts, groups, GPOs, and ACLs
  - Change passwords on any account NOT listed above
  - Disable weak service accounts (svc_sql, svc_webadmin, etc.) - just update
    credentials.json if the simulator was using them (it shouldn't be by default)
  - Harden GPOs, remove dangerous delegations, fix ADCS templates
  - Enable SMB Signing, LDAP Signing, disable NTLM where appropriate
  - Patch or remove xp_cmdshell, fix SQL misconfigurations
  - The simulator is designed to survive all of the above hardening steps

================================================================================
SCORING
================================================================================

Scores are updated every 15 minutes. To view current standings:
  http://[SCORING-VM-IP]/scores   (ask your instructor for the IP)

Points are awarded for:
  - Service uptime (SQL Agent job running, last execution < 30 min ago)
  - Remediating specific misconfigurations flagged in the environment
  - Incident response speed when Black Team introduces events (announced separately)

================================================================================
QUESTIONS?
================================================================================

Contact your instructor. Do not attempt to access the simulator VM directly.
The simulator VM is NOT domain-joined and you do not have credentials for it.

================================================================================
"@

# Write to simulator path
$roeSimPath = Join-Path $SimulatorPath "Rules_of_Engagement.txt"
$roeContent | Out-File -FilePath $roeSimPath -Encoding UTF8 -Force
Write-Log "Rules_of_Engagement.txt written to $roeSimPath" "SUCCESS"

# Also write to Public_Company_Data share if it exists
$publicShareROE = Join-Path $CorpSharePath "Public_Company_Data\Rules_of_Engagement.txt"
$publicShareDir = Split-Path $publicShareROE
if (Test-Path $publicShareDir) {
    $roeContent | Out-File -FilePath $publicShareROE -Encoding UTF8 -Force
    Write-Log "Rules_of_Engagement.txt also written to $publicShareROE" "SUCCESS"
} else {
    Write-Log "Public_Company_Data share not found - RoE only written to $roeSimPath" "WARNING"
}

# ==============================================================================
# 9. SUMMARY
# ==============================================================================

Write-Log "" "INFO"
Write-Log "=================================================================" "INFO"
Write-Log "  Phase 1 Complete - Black Team Infrastructure Deployed" "SUCCESS"
Write-Log "=================================================================" "INFO"
Write-Log "" "INFO"
Write-Log "Accounts created in: OU=BlackTeam,OU=Admin,$DomainDN" "INFO"
Write-Log "credentials.json:    $credPath" "INFO"
Write-Log "Rules of Engagement: $roeSimPath" "INFO"
Write-Log "" "INFO"
Write-Log "NEXT STEPS:" "INFO"
Write-Log "  1. Run Deploy-SupplierDeliveryJob.ps1 (Phase 2) on the SQL host" "INFO"
Write-Log "  2. Distribute Rules_of_Engagement.txt to Blue Team students" "INFO"
Write-Log "  3. Copy the Simulator\ folder to the out-of-band simulator VM" "INFO"
Write-Log "" "INFO"
