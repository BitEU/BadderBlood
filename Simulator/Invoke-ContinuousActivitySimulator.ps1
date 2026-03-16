<#
.SYNOPSIS
    Master orchestrator for the BadderBlood Continuous Activity Simulator.
    Runs Phases 1–6 in sequence with dependency checks.

.DESCRIPTION
    Calls deployment scripts in order with preflight checks:
        Phase 1: Deploy-BlackTeamAccounts.ps1    (AD accounts, credentials.json, RoE)
        Phase 2: Deploy-SupplierDeliveryJob.ps1   (SQL Agent supplier delivery jobs)
        Phase 3: Deploy-HelpdeskSystem.ps1        (ITDeskDB, ASPX API, helpdesk UI)
        Phase 4: Deploy-UserPasswordExport.ps1    (user creds for session simulator)
        Phase 5: Deploy-OrderEndpoint.ps1         (customer order ASPX API, OrdersAppPool)
        Phase 6: Deploy-MailServer.ps1            (hMailServer install, mailbox provisioning)

    Run this script after:
        1. Invoke-BadderBlood.ps1   (AD infrastructure)
        2. BadSQL.ps1               (SQL Server + NailInventoryDB + BoxArchive2019)
        3. BadIIS.ps1               (IIS - required for Phase 3+)
        4. BadFS.ps1                (File shares - required for Phase 4)
        5. hMailServer installed    (required for Phase 6 - see Deploy-MailServer.ps1)

    After deployment, copy the full Simulator\ folder to C:\Simulator\ on the
    out-of-band simulator VM and start the runtime scripts:
        Invoke-LockoutSimulator.ps1      (Phase 3 - lockout generator)
        Invoke-HelpdeskAutoResolve.ps1   (Phase 3 - ticket auto-resolution)
        Invoke-UserSessionSimulator.ps1  (Phase 4 - SMB file session generator)
        Invoke-OrderSimulator.ps1        (Phase 5 - customer order HTTP POST generator)
        Invoke-EmailSimulator.ps1        (Phase 6 - email traffic generator)

.PARAMETER SqlInstance
    SQL Server instance. Defaults to localhost\BADSQL (matches BadSQL.ps1).

.PARAMETER SqlSaPassword
    sa password for SQL connections. Leave blank to use Windows Integrated Auth
    (recommended when running on the SQL host as Domain Admin).

.PARAMETER SharedPassword
    Password for all BlackTeam AD accounts. Change this to something lab-specific.

.PARAMETER SkipPhase1
    Skip Deploy-BlackTeamAccounts.ps1 (useful if accounts already exist).

.PARAMETER SkipPhase2
    Skip Deploy-SupplierDeliveryJob.ps1.

.PARAMETER SkipPhase3
    Skip Deploy-HelpdeskSystem.ps1.

.PARAMETER SkipPhase4
    Skip Deploy-UserPasswordExport.ps1.

.PARAMETER Phase4UserCount
    Number of AD users to enrol in file session simulation (default: 40).

.PARAMETER SkipPhase5
    Skip Deploy-OrderEndpoint.ps1.

.PARAMETER SkipPhase6
    Skip Deploy-MailServer.ps1.

.PARAMETER HMailAdminPassword
    hMailServer administrator password (required for Phase 6).

.PARAMETER LabSubnet
    Lab network subnet for SMTP relay allowlist (e.g. "192.168.0.0/16"). Used by Phase 6.

.PARAMETER Force
    Pass -Force to Phase 2/3/5 to recreate resources even if they already exist.

.EXAMPLE
    # Full deployment (most common)
    .\Invoke-ContinuousActivitySimulator.ps1

.EXAMPLE
    # Re-run Phase 3 only (helpdesk system needs update)
    .\Invoke-ContinuousActivitySimulator.ps1 -SkipPhase1 -SkipPhase2 -SkipPhase4 -SkipPhase5 -SkipPhase6

.EXAMPLE
    # Custom SQL instance + explicit sa password
    .\Invoke-ContinuousActivitySimulator.ps1 -SqlInstance "SQLSRV01\BADSQL" -SqlSaPassword (Read-Host "sa password" -AsSecureString)

.EXAMPLE
    # Deploy all phases including mail server
    .\Invoke-ContinuousActivitySimulator.ps1 -HMailAdminPassword (Read-Host "hMailServer admin password" -AsSecureString) -LabSubnet "192.168.10.0/24"

.NOTES
    Must be run as Domain Admin (for AD account creation in Phase 1).
    Must have sysadmin / msdb dbo rights on the SQL instance (for Phases 2 & 3).
    Must have local admin on the IIS host (for Phase 3 IIS configuration).

    Context: Educational / CTF / Active Directory Lab Environment
#>

#Requires -RunAsAdministrator

param(
    [string]$SqlInstance              = "localhost\BADSQL",
    [SecureString]$SqlSaPassword       = $null,
    [SecureString]$SharedPassword      = $null,  # BlackTeam account password; default resolved below
    [string]$CorpSharePath            = "C:\CorpShares",
    [string]$SimulatorPath            = "C:\Simulator",
    [string]$IisBasePath              = "C:\inetpub\SpringfieldBoxFactory",
    [int]$Phase4UserCount             = 40,
    [SecureString]$HMailAdminPassword  = $null,  # Required for Phase 6
    [string]$LabSubnet                = "192.168.0.0/16",
    [switch]$SkipPhase1,
    [switch]$SkipPhase2,
    [switch]$SkipPhase3,
    [switch]$SkipPhase4,
    [switch]$SkipPhase5,
    [switch]$SkipPhase6,
    [switch]$Force,
    [switch]$NonInteractive
)

$ErrorActionPreference = "Stop"
$ScriptRoot = $PSScriptRoot

# Resolve default SharedPassword (avoids hardcoded plaintext in param block)
if (-not $SharedPassword) {
    $SharedPassword = ConvertTo-SecureString "B!ackT3am_Sc0reb0t_2025#" -AsPlainText -Force
}

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
        "STEP"    { Write-Host "" ; Write-Host "  =====================================================" -ForegroundColor DarkGray
                    Write-Host "  $Message" -ForegroundColor White
                    Write-Host "  =====================================================" -ForegroundColor DarkGray }
        default   { Write-Host "[$ts] $Message" }
    }
}

Write-Host ""
Write-Host "  ########################################################" -ForegroundColor Magenta
Write-Host "  ##  BadderBlood Continuous Activity Simulator         ##" -ForegroundColor Magenta
Write-Host "  ##  Master Deployment Orchestrator                    ##" -ForegroundColor Magenta
Write-Host "  ##  Educational / CTF / Lab Use Only                  ##" -ForegroundColor Yellow
Write-Host "  ########################################################" -ForegroundColor Magenta
Write-Host ""

# ==============================================================================
# PREFLIGHT CHECKS
# ==============================================================================

Write-Log "Running preflight checks..." "STEP"

# 1. Verify AD is reachable
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain
    Write-Log "Active Directory reachable. Domain: $($domain.DNSRoot)" "SUCCESS"
} catch {
    Write-Log "Active Directory module or domain not reachable. Ensure RSAT is installed and this machine is domain-joined (or is the DC)." "ERROR"
    exit 1
}

# 2. Verify Invoke-BadderBlood has run (check for OU=Admin)
$adminOU = Get-ADOrganizationalUnit -Filter { Name -eq "Admin" } -ErrorAction SilentlyContinue
if (-not $adminOU) {
    Write-Log "OU=Admin not found in AD. Run Invoke-BadderBlood.ps1 first." "ERROR"
    exit 1
}
Write-Log "Invoke-BadderBlood.ps1 artifact confirmed (OU=Admin exists)." "SUCCESS"

# 3. Verify BadSQL NailInventoryDB exists (quick check via SQL)
if (-not $SkipPhase2) {
    try {
        $connStr = if ($SqlSaPassword) {
            $saPlain = [System.Net.NetworkCredential]::new('', $SqlSaPassword).Password
            "Server=$SqlInstance;Database=master;User Id=sa;Password=$saPlain;Connection Timeout=10;"
        } else {
            "Server=$SqlInstance;Database=master;Integrated Security=SSPI;Connection Timeout=10;"
        }
        $conn = New-Object System.Data.SqlClient.SqlConnection $connStr
        $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = "SELECT COUNT(*) FROM sys.databases WHERE name = 'NailInventoryDB'"
        $dbExists = [int]$cmd.ExecuteScalar()
        $conn.Close()
        if ($dbExists -eq 0) {
            Write-Log "NailInventoryDB not found on $SqlInstance. Run BadSQL.ps1 before Phase 2." "ERROR"
            exit 1
        }
        Write-Log "BadSQL.ps1 artifact confirmed (NailInventoryDB exists on $SqlInstance)." "SUCCESS"
    } catch {
        Write-Log "Cannot connect to $SqlInstance for Phase 2 preflight check: $_" "WARNING"
        Write-Log "Proceeding anyway - Phase 2 will fail if SQL is unreachable." "WARNING"
    }
}

# ==============================================================================
# PHASE 1
# ==============================================================================

if (-not $SkipPhase1) {
    Write-Log "PHASE 1: Black Team Account Provisioning" "STEP"

    $phase1Script = Join-Path $ScriptRoot "Deploy-BlackTeamAccounts.ps1"
    if (-not (Test-Path $phase1Script)) {
        Write-Log "Deploy-BlackTeamAccounts.ps1 not found at $phase1Script" "ERROR"
        exit 1
    }

    $phase1Args = @{
        SharedPassword  = $SharedPassword
        SqlInstance     = $SqlInstance
        CorpSharePath   = $CorpSharePath
        SimulatorPath   = $SimulatorPath
    }
    if ($SqlSaPassword)   { $phase1Args.SqlSaPassword = $SqlSaPassword }
    if ($NonInteractive)  { $phase1Args.NonInteractive = $true }

    try {
        & $phase1Script @phase1Args
        Write-Log "Phase 1 completed successfully." "SUCCESS"
    } catch {
        Write-Log "Phase 1 failed: $_" "ERROR"
        if (-not $NonInteractive) {
            Write-Host ""
            $continue = Read-Host "Phase 1 failed. Continue to Phase 2 anyway? (y/N)"
            if ($continue -ne 'y') { exit 1 }
        } else {
            exit 1
        }
    }
} else {
    Write-Log "Skipping Phase 1 (-SkipPhase1 specified)." "WARNING"
}

# ==============================================================================
# PHASE 2
# ==============================================================================

if (-not $SkipPhase2) {
    Write-Log "PHASE 2: Supplier Delivery SQL Agent Job" "STEP"

    $phase2Script = Join-Path $ScriptRoot "Deploy-SupplierDeliveryJob.ps1"
    if (-not (Test-Path $phase2Script)) {
        Write-Log "Deploy-SupplierDeliveryJob.ps1 not found at $phase2Script" "ERROR"
        exit 1
    }

    $phase2Args = @{
        SqlInstance = $SqlInstance
    }
    if ($SqlSaPassword)  { $phase2Args.SqlSaPassword = $SqlSaPassword }
    if ($Force)          { $phase2Args.Force = $true }
    if ($NonInteractive) { $phase2Args.NonInteractive = $true }

    try {
        & $phase2Script @phase2Args
        Write-Log "Phase 2 completed successfully." "SUCCESS"
    } catch {
        Write-Log "Phase 2 failed: $_" "ERROR"
        exit 1
    }
} else {
    Write-Log "Skipping Phase 2 (-SkipPhase2 specified)." "WARNING"
}

# ==============================================================================
# PHASE 3
# ==============================================================================

if (-not $SkipPhase3) {
    Write-Log "PHASE 3: Helpdesk System (ITDeskDB + ASPX API + UI)" "STEP"

    $phase3Script = Join-Path $ScriptRoot "Deploy-HelpdeskSystem.ps1"
    if (-not (Test-Path $phase3Script)) {
        Write-Log "Deploy-HelpdeskSystem.ps1 not found at $phase3Script" "ERROR"
        exit 1
    }

    # Phase 3 requires IIS
    if (-not (Test-Path $IisBasePath)) {
        Write-Log "IIS base path '$IisBasePath' not found. Run BadIIS.ps1 before Phase 3." "ERROR"
        if (-not $NonInteractive) {
            $continue = Read-Host "IIS path missing. Skip Phase 3 and continue? (y/N)"
            if ($continue -ne 'y') { exit 1 }
        } else { exit 1 }
    }

    $phase3Args = @{
        SqlInstance  = $SqlInstance
        IisBasePath  = $IisBasePath
    }
    if ($SqlSaPassword)  { $phase3Args.SqlSaPassword = $SqlSaPassword }
    if ($Force)          { $phase3Args.Force = $true }
    if ($NonInteractive) { $phase3Args.NonInteractive = $true }

    try {
        & $phase3Script @phase3Args
        Write-Log "Phase 3 completed successfully." "SUCCESS"
    } catch {
        Write-Log "Phase 3 failed: $_" "ERROR"
        exit 1
    }
} else {
    Write-Log "Skipping Phase 3 (-SkipPhase3 specified)." "WARNING"
}

# ==============================================================================
# PHASE 4
# ==============================================================================

if (-not $SkipPhase4) {
    Write-Log "PHASE 4: User Password Export (file session simulation prep)" "STEP"

    # Phase 4 requires BadFS CorpData share
    if (-not (Test-Path $CorpSharePath)) {
        Write-Log "CorpShares path '$CorpSharePath' not found. Run BadFS.ps1 before Phase 4." "WARNING"
        if (-not $NonInteractive) {
            $continue = Read-Host "BadFS share missing. Skip Phase 4 and continue? (y/N)"
            if ($continue -ne 'y') { exit 1 }
            Write-Log "Skipping Phase 4 (no BadFS share)." "WARNING"
            goto SummaryLabel
        } else {
            Write-Log "Skipping Phase 4 (no BadFS share, NonInteractive mode)." "WARNING"
            $SkipPhase4 = $true
        }
    }

    if (-not $SkipPhase4) {
       
        ## PHASE 4 PASSWORD STUFF IS HANDLED BY CREATEUSERS SCRIPT NOW, WHICH EXPORTS ALL USER PASSWORDS TO A CSV


    }
} else {
    Write-Log "Skipping Phase 4 (-SkipPhase4 specified)." "WARNING"
}

# ==============================================================================
# PHASE 5
# ==============================================================================

if (-not $SkipPhase5) {
    Write-Log "PHASE 5: Customer Order Endpoint (ASPX API + OrdersAppPool)" "STEP"

    $phase5Script = Join-Path $ScriptRoot "Deploy-OrderEndpoint.ps1"
    if (-not (Test-Path $phase5Script)) {
        Write-Log "Deploy-OrderEndpoint.ps1 not found at $phase5Script" "ERROR"
        exit 1
    }

    # Phase 5 requires IIS base path
    if (-not (Test-Path $IisBasePath)) {
        Write-Log "IIS base path '$IisBasePath' not found. Run BadIIS.ps1 before Phase 5." "ERROR"
        if (-not $NonInteractive) {
            $continue = Read-Host "IIS path missing. Skip Phase 5 and continue? (y/N)"
            if ($continue -ne 'y') { exit 1 }
            $SkipPhase5 = $true
        } else { exit 1 }
    }

    if (-not $SkipPhase5) {
        $phase5Args = @{
            SqlInstance  = $SqlInstance
            IisBasePath  = $IisBasePath
        }
        if ($SqlSaPassword)  { $phase5Args.SqlSaPassword  = $SqlSaPassword }
        if ($SharedPassword) { $phase5Args.SharedPassword = $SharedPassword }
        if ($Force)          { $phase5Args.Force          = $true }
        if ($NonInteractive) { $phase5Args.NonInteractive = $true }

        try {
            & $phase5Script @phase5Args
            Write-Log "Phase 5 completed successfully." "SUCCESS"
        } catch {
            Write-Log "Phase 5 failed: $_" "ERROR"
            exit 1
        }
    }
} else {
    Write-Log "Skipping Phase 5 (-SkipPhase5 specified)." "WARNING"
}

# ==============================================================================
# PHASE 6
# ==============================================================================

if (-not $SkipPhase6) {
    Write-Log "PHASE 6: Mail Server (hMailServer + Mailbox Provisioning)" "STEP"

    $phase6Script = Join-Path $ScriptRoot "Deploy-MailServer.ps1"
    if (-not (Test-Path $phase6Script)) {
        Write-Log "Deploy-MailServer.ps1 not found at $phase6Script" "ERROR"
        exit 1
    }

    # Phase 6 requires hMailAdminPassword
    if (-not $HMailAdminPassword) {
        if (-not $NonInteractive) {
            Write-Log "hMailServer admin password required for Phase 6." "WARNING"
            $HMailAdminPassword = Read-Host "Enter hMailServer administrator password" -AsSecureString
        } else {
            Write-Log "Phase 6 requires -HMailAdminPassword. Skipping in NonInteractive mode." "WARNING"
            $SkipPhase6 = $true
        }
    }

    if (-not $SkipPhase6) {
        $phase6Args = @{
            HMailAdminPassword = $HMailAdminPassword
            SimulatorPath      = $SimulatorPath
            LabSubnet          = $LabSubnet
        }
        if ($SharedPassword) { $phase6Args.SharedPassword = $SharedPassword }
        if ($NonInteractive) { $phase6Args.NonInteractive = $true }

        try {
            & $phase6Script @phase6Args
            Write-Log "Phase 6 completed successfully." "SUCCESS"
        } catch {
            Write-Log "Phase 6 failed: $_" "ERROR"
            if (-not $NonInteractive) {
                $continue = Read-Host "Phase 6 failed (mail server). Continue to summary? (y/N)"
                if ($continue -ne 'y') { exit 1 }
            } else {
                exit 1
            }
        }
    }
} else {
    Write-Log "Skipping Phase 6 (-SkipPhase6 specified)." "WARNING"
}

# ==============================================================================
# FINAL SUMMARY
# ==============================================================================

Write-Host ""
Write-Host "  ########################################################" -ForegroundColor Green
Write-Host "  ##  Simulator Deployment Complete                     ##" -ForegroundColor Green
Write-Host "  ########################################################" -ForegroundColor Green
Write-Host ""
Write-Log "Phases deployed:" "INFO"
if (-not $SkipPhase1) { Write-Log "  [x] Phase 1 - Black Team Accounts + credentials.json + RoE" "SUCCESS" }
if (-not $SkipPhase2) { Write-Log "  [x] Phase 2 - Supplier Delivery SQL Agent Jobs" "SUCCESS" }
if (-not $SkipPhase3) { Write-Log "  [x] Phase 3 - Helpdesk System (ITDeskDB + ASPX)" "SUCCESS" }
if (-not $SkipPhase4) { Write-Log "  [x] Phase 4 - User Password Export (user_passwords.json)" "SUCCESS" }
if (-not $SkipPhase5) { Write-Log "  [x] Phase 5 - Customer Order Endpoint (ASPX + OrdersAppPool)" "SUCCESS" }
if (-not $SkipPhase6) { Write-Log "  [x] Phase 6 - Mail Server (hMailServer + mailboxes)" "SUCCESS" }
Write-Log "" "INFO"
Write-Log "Files created:" "INFO"
Write-Log "  $SimulatorPath\credentials.json" "INFO"
Write-Log "  $SimulatorPath\Rules_of_Engagement.txt" "INFO"
if (-not $SkipPhase4) { Write-Log "  $SimulatorPath\user_passwords.json" "INFO" }
Write-Log "" "INFO"
Write-Log "Copy the entire Simulator\ folder to C:\Simulator\ on the out-of-band VM." "INFO"
Write-Log "Then start the runtime scripts on the simulator VM:" "INFO"
Write-Log "  Invoke-LockoutSimulator.ps1      (Phase 3 - continuous)" "INFO"
Write-Log "  Invoke-HelpdeskAutoResolve.ps1   (Phase 3 - continuous)" "INFO"
Write-Log "  Invoke-UserSessionSimulator.ps1  (Phase 4 - continuous)" "INFO"
Write-Log "  Invoke-OrderSimulator.ps1        (Phase 5 - continuous)" "INFO"
Write-Log "  Invoke-EmailSimulator.ps1        (Phase 6 - continuous)" "INFO"
Write-Log "Distribute Rules_of_Engagement.txt to Blue Team students before the exercise starts." "INFO"
Write-Host ""
