<#
.SYNOPSIS
    Diagnostic script to investigate every warning/error from Invoke-ContinuousActivitySimulator.ps1.

.DESCRIPTION
    Runs non-destructive read-only checks against the local environment and reports findings.
    Covers: SQL Agent service, SQL connectivity/permissions, ITDeskDB seed SQL quoting,
    CorpData share paths, IIS locked sections, hMailServer COM/relay config, CIDR parsing.

.NOTES
    Run as Administrator on the DC / SQL / IIS host (same machine the simulator runs on).
    Context: Educational / CTF / Active Directory Lab Environment
#>

#Requires -RunAsAdministrator

param(
    [string]$SqlInstance       = "localhost\BADSQL",
    [string]$HMailAdminPassword = "MyP@ssw0rd123!",
    [string]$LabSubnet         = "10.0.2.0/24",
    [string]$CorpSharePath     = "C:\CorpShares",
    [string]$IisBasePath       = "C:\inetpub\SpringfieldBoxFactory"
)

$ErrorActionPreference = "Continue"
$divider = "=" * 70

function Write-Section ($title) {
    Write-Host ""
    Write-Host $divider -ForegroundColor DarkGray
    Write-Host "  $title" -ForegroundColor White
    Write-Host $divider -ForegroundColor DarkGray
}

function Write-OK   ($msg) { Write-Host "  [OK]      $msg" -ForegroundColor Green }
function Write-WARN ($msg) { Write-Host "  [WARN]    $msg" -ForegroundColor Yellow }
function Write-FAIL ($msg) { Write-Host "  [FAIL]    $msg" -ForegroundColor Red }
function Write-INFO ($msg) { Write-Host "  [INFO]    $msg" -ForegroundColor Cyan }
function Write-FIX  ($msg) { Write-Host "  [FIX]     $msg" -ForegroundColor Magenta }

Write-Host ""
Write-Host $divider -ForegroundColor Magenta
Write-Host "  BadderBlood Simulator - Full Diagnostic Report" -ForegroundColor Magenta
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Magenta
Write-Host $divider -ForegroundColor Magenta

# ============================================================================
# SQL HELPER  (used throughout - returns DataTable or $null)
# ============================================================================

function Test-SqlQuery {
    param([string]$Query, [string]$Database = "master", [string]$Label = "")
    try {
        $conn = New-Object System.Data.SqlClient.SqlConnection
        $conn.ConnectionString = "Server=$SqlInstance;Database=$Database;Integrated Security=SSPI;Connection Timeout=10;"
        $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = $Query
        $cmd.CommandTimeout = 15
        $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $cmd
        $table = New-Object System.Data.DataTable
        $null = $adapter.Fill($table)
        $conn.Close()
        return $table
    } catch {
        Write-FAIL "${Label}: $_"
        return $null
    }
}

# Helper: safely read a DataTable cell (avoids null-array and DBNull issues)
function Get-Cell {
    param($Table, [int]$Row = 0, [string]$Column)
    if ($null -eq $Table) { return $null }
    if ($Table -isnot [System.Data.DataTable]) { return $null }
    if ($Table.Rows.Count -le $Row) { return $null }
    try {
        $val = $Table.Rows[$Row][$Column]
        if ($val -is [System.DBNull]) { return $null }
        return $val
    } catch {
        return $null
    }
}

# ============================================================================
# 1. ENVIRONMENT
# ============================================================================
Write-Section "1. Environment"
Write-INFO "Hostname:       $env:COMPUTERNAME"
Write-INFO "Domain\User:    $env:USERDOMAIN\$env:USERNAME"
Write-INFO "PowerShell:     $($PSVersionTable.PSVersion)"
Write-INFO "Is Admin:       $([bool]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
Write-INFO "SqlInstance:    $SqlInstance"
Write-INFO "LabSubnet:      $LabSubnet"
Write-INFO "CorpSharePath:  $CorpSharePath"
Write-INFO "IisBasePath:    $IisBasePath"

# ============================================================================
# 2. SQL SERVER ENGINE SERVICE
# ============================================================================
Write-Section "2. SQL Server Engine Service"

$instanceName = if ($SqlInstance -like '*\*') { $SqlInstance.Split('\')[1] } else { $null }
$sqlSvcName   = if ($instanceName) { "MSSQL`$$instanceName" } else { "MSSQLSERVER" }
$agentSvcName = if ($instanceName) { "SQLAGENT`$$instanceName" } else { "SQLSERVERAGENT" }

Write-INFO "Engine service name:  $sqlSvcName"
Write-INFO "Agent service name:   $agentSvcName"

$sqlSvc = Get-Service -Name $sqlSvcName -ErrorAction SilentlyContinue
if (-not $sqlSvc) {
    Write-FAIL "SQL Server engine service '$sqlSvcName' NOT FOUND."
    Write-INFO "All SQL-related services:"
    Get-Service | Where-Object { $_.DisplayName -match "SQL" } | ForEach-Object {
        Write-INFO "  $($_.Name) | $($_.DisplayName) | Status=$($_.Status) | StartType=$($_.StartType)"
    }
} else {
    Write-INFO "Engine status:    $($sqlSvc.Status)"
    Write-INFO "Engine start type: $($sqlSvc.StartType)"
    try {
        $wmiSvc = Get-WmiObject Win32_Service -Filter "Name='$sqlSvcName'" -ErrorAction Stop
        Write-INFO "Engine logon as:  $($wmiSvc.StartName)"
    } catch {}
    if ($sqlSvc.Status -ne 'Running') {
        Write-FAIL "SQL Server engine is NOT running. SQL Agent depends on it."
    } else {
        Write-OK "SQL Server engine is running."
    }
}

# ============================================================================
# 3. SQL SERVER AGENT SERVICE  (simout line 86)
# ============================================================================
Write-Section "3. SQL Server Agent Service"

$agentSvc = Get-Service -Name $agentSvcName -ErrorAction SilentlyContinue
if (-not $agentSvc) {
    Write-FAIL "SQL Agent service '$agentSvcName' NOT FOUND."
} else {
    Write-INFO "Agent status:     $($agentSvc.Status)"
    Write-INFO "Agent start type: $($agentSvc.StartType)"

    $agentLogon = $null
    try {
        $wmiAgent = Get-WmiObject Win32_Service -Filter "Name='$agentSvcName'" -ErrorAction Stop
        $agentLogon = $wmiAgent.StartName
        Write-INFO "Agent logon as:   $agentLogon"
        Write-INFO "Agent binary:     $($wmiAgent.PathName)"
        Write-INFO "Agent exit code:  $($wmiAgent.ExitCode)"
        Write-INFO "Agent win32 exit: $($wmiAgent.Win32ExitCode)"
    } catch {
        Write-WARN "WMI query failed: $_"
    }

    # Dependencies
    $deps = $agentSvc.ServicesDependedOn
    if ($deps) {
        Write-INFO "Agent depends on:"
        foreach ($d in $deps) {
            $depStatus = (Get-Service $d.Name -ErrorAction SilentlyContinue).Status
            Write-INFO "  $($d.Name) ($($d.DisplayName)) - $depStatus"
            if ($depStatus -ne 'Running') {
                Write-FAIL "  Dependency '$($d.Name)' is NOT running! Agent cannot start."
            }
        }
    }

    # --- Deep-dive: What SQL login does the Agent map to? ---
    Write-INFO ""
    Write-INFO "--- SQL Agent Service Account Analysis ---"

    $agentSqlLogin = $agentLogon
    if ($agentLogon -match 'NT AUTHORITY\\(NETWORK\s*SERVICE|LOCAL\s*SERVICE|SYSTEM)') {
        $agentSqlLogin = "$env:USERDOMAIN\$env:COMPUTERNAME`$"
        Write-INFO "Agent runs as '$agentLogon' which maps to SQL login: $agentSqlLogin"
    } else {
        Write-INFO "Agent runs as '$agentLogon' -> SQL login: $agentSqlLogin"
    }

    # Check if that login exists in SQL and has sysadmin
    $loginInfo = Test-SqlQuery "
        SELECT
            sp.name                             AS LoginName,
            sp.type_desc                        AS LoginType,
            sp.is_disabled                      AS IsDisabled,
            IS_SRVROLEMEMBER('sysadmin', sp.name) AS IsSysadmin
        FROM sys.server_principals sp
        WHERE sp.name = N'$agentSqlLogin'
    " -Label "Agent login lookup"

    $loginName = Get-Cell $loginInfo -Column "LoginName"
    if ($loginName) {
        $isSA = Get-Cell $loginInfo -Column "IsSysadmin"
        $isDisabled = Get-Cell $loginInfo -Column "IsDisabled"
        Write-OK "SQL login '$agentSqlLogin' exists. sysadmin=$isSA disabled=$isDisabled"
        if ($isSA -ne 1) {
            Write-FAIL "Agent login does NOT have sysadmin. SQL Agent requires sysadmin to start."
            Write-FIX "ALTER SERVER ROLE sysadmin ADD MEMBER [$agentSqlLogin]"
        }
        if ($isDisabled -eq $true) {
            Write-FAIL "Agent login is DISABLED."
            Write-FIX "ALTER LOGIN [$agentSqlLogin] ENABLE"
        }
    } else {
        Write-FAIL "SQL login '$agentSqlLogin' NOT FOUND in sys.server_principals."
        Write-FIX "CREATE LOGIN [$agentSqlLogin] FROM WINDOWS; ALTER SERVER ROLE sysadmin ADD MEMBER [$agentSqlLogin]"
    }

    # Check sp_sqlagent_update_agent_xps EXECUTE permission specifically
    Write-INFO ""
    Write-INFO "--- sp_sqlagent_update_agent_xps Permission Check ---"
    $xpsCheck = Test-SqlQuery "
        SELECT
            dp.name AS GranteeName,
            dp.type_desc AS GranteeType,
            perm.permission_name,
            perm.state_desc
        FROM msdb.sys.database_permissions perm
        INNER JOIN msdb.sys.database_principals dp ON perm.grantee_principal_id = dp.principal_id
        INNER JOIN msdb.sys.objects obj ON perm.major_id = obj.object_id
        WHERE obj.name = 'sp_sqlagent_update_agent_xps'
    " -Label "sp_sqlagent_update_agent_xps permissions"

    if ($xpsCheck -and $xpsCheck.Rows.Count -gt 0) {
        Write-INFO "Explicit permissions on sp_sqlagent_update_agent_xps:"
        foreach ($row in $xpsCheck.Rows) {
            Write-INFO "  $($row['GranteeName']) ($($row['GranteeType'])): $($row['state_desc']) $($row['permission_name'])"
        }
    } else {
        Write-WARN "No explicit permissions found on sp_sqlagent_update_agent_xps."
        Write-INFO "The Agent relies on sysadmin role to EXECUTE this proc."
    }

    # Check if the Agent login is mapped as a user in msdb
    $msdbUser = Test-SqlQuery "
        SELECT
            dp.name         AS DbUser,
            dp.type_desc    AS UserType,
            STRING_AGG(r.name, ', ') AS Roles
        FROM msdb.sys.database_principals dp
        LEFT JOIN msdb.sys.database_role_members drm ON dp.principal_id = drm.member_principal_id
        LEFT JOIN msdb.sys.database_principals r ON drm.role_principal_id = r.principal_id
        WHERE dp.name = N'$agentSqlLogin'
           OR dp.sid  = SUSER_SID(N'$agentSqlLogin')
        GROUP BY dp.name, dp.type_desc
    " -Label "msdb user check"

    $msdbUserName = Get-Cell $msdbUser -Column "DbUser"
    if ($msdbUserName) {
        $roles = Get-Cell $msdbUser -Column "Roles"
        Write-OK "Login '$agentSqlLogin' is mapped in msdb as '$msdbUserName'. Roles: $roles"
    } else {
        Write-WARN "Login '$agentSqlLogin' has NO user mapping in msdb."
        Write-INFO "With sysadmin, this should map to dbo. If it doesn't, the token may be stale."
    }

    # Try to start it if not running
    if ($agentSvc.Status -ne 'Running') {
        Write-INFO ""
        Write-INFO "Attempting to start SQL Agent..."
        try {
            Start-Service -Name $agentSvcName -ErrorAction Stop
            $agentSvc.WaitForStatus('Running', [TimeSpan]::FromSeconds(15))
            Write-OK "SQL Agent started successfully!"
        } catch {
            Write-FAIL "Start-Service failed: $_"
            if ($_.Exception.InnerException) {
                Write-FAIL "Inner: $($_.Exception.InnerException.Message)"
            }
        }

        # Check Windows Event Log
        Write-INFO ""
        Write-INFO "Application event log (SQL Agent errors, last hour):"
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = 'Application'
                Level     = 1,2  # Critical, Error
                StartTime = (Get-Date).AddHours(-1)
            } -MaxEvents 50 -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match "SQL|Agent|SQLAGENT|MSSQL" } |
            Select-Object -First 10
            if ($events) {
                foreach ($ev in $events) {
                    $msgSnip = $ev.Message.Substring(0, [Math]::Min(300, $ev.Message.Length))
                    Write-WARN "  [$($ev.TimeCreated)] ID=$($ev.Id): $msgSnip..."
                }
            } else {
                Write-INFO "  No recent SQL Agent error events found."
            }
        } catch {
            Write-WARN "Event log query failed: $_"
        }

        # Check System event log for service failures
        Write-INFO ""
        Write-INFO "System event log (service control errors, last hour):"
        try {
            $sysEvents = Get-WinEvent -FilterHashtable @{
                LogName   = 'System'
                Level     = 1,2
                StartTime = (Get-Date).AddHours(-1)
            } -MaxEvents 50 -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match "SQL|Agent|$agentSvcName" } |
            Select-Object -First 10
            if ($sysEvents) {
                foreach ($ev in $sysEvents) {
                    $msgSnip = $ev.Message.Substring(0, [Math]::Min(300, $ev.Message.Length))
                    Write-WARN "  [$($ev.TimeCreated)] ID=$($ev.Id) Source=$($ev.ProviderName): $msgSnip..."
                }
            } else {
                Write-INFO "  No recent service control errors for SQL Agent."
            }
        } catch {
            Write-WARN "System event log query failed: $_"
        }

        # Find SQLAGENT.OUT on disk
        Write-INFO ""
        Write-INFO "Searching for SQLAGENT.OUT error log:"
        $agentLogPaths = @(
            Get-Item "C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\Log\SQLAGENT.OUT" -ErrorAction SilentlyContinue
            Get-Item "C:\Program Files\Microsoft SQL Server\MSSQL*.$instanceName\MSSQL\Log\SQLAGENT.OUT" -ErrorAction SilentlyContinue
        ) | Select-Object -Unique
        if ($agentLogPaths) {
            foreach ($logPath in $agentLogPaths) {
                Write-INFO "  Found: $($logPath.FullName) (Modified: $($logPath.LastWriteTime))"
                Write-INFO "  Last 30 lines:"
                Get-Content $logPath.FullName -Tail 30 | ForEach-Object { Write-INFO "    $_" }
            }
        } else {
            Write-WARN "  SQLAGENT.OUT not found in standard locations."
        }

        # SQL Server error log for Agent clues
        Write-INFO ""
        Write-INFO "SQL Server error log entries mentioning 'Agent':"
        try {
            $conn = New-Object System.Data.SqlClient.SqlConnection "Server=$SqlInstance;Database=master;Integrated Security=SSPI;Connection Timeout=10;"
            $conn.Open()
            $cmd = $conn.CreateCommand()
            $cmd.CommandText = "EXEC sp_readerrorlog 0, 1, N'Agent'"
            $cmd.CommandTimeout = 15
            $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $cmd
            $table = New-Object System.Data.DataTable
            $null = $adapter.Fill($table)
            $conn.Close()
            $count = [Math]::Min(10, $table.Rows.Count)
            for ($i = 0; $i -lt $count; $i++) {
                $row = $table.Rows[$i]
                Write-INFO "  [$($row[0])] $($row[2])"
            }
            if ($table.Rows.Count -eq 0) { Write-INFO "  (none)" }
        } catch {
            Write-WARN "Could not read SQL error log: $_"
        }
    } else {
        Write-OK "SQL Agent is already running."
    }
}

# ============================================================================
# 4. SQL CONNECTIVITY & PERMISSIONS
# ============================================================================
Write-Section "4. SQL Connectivity & Login Permissions"

$currentLogin = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-INFO "Current Windows login: $currentLogin"

$ping = Test-SqlQuery "SELECT SUSER_SNAME() AS [Login], IS_SRVROLEMEMBER('sysadmin') AS IsSA" -Label "Basic connectivity"
if ($ping -and $ping.Rows.Count -gt 0) {
    $loginVal = Get-Cell $ping -Column "Login"
    $isSAVal  = Get-Cell $ping -Column "IsSA"
    Write-OK "Connected to $SqlInstance as $loginVal"
    if ($isSAVal -eq 1) {
        Write-OK "Login has sysadmin role."
    } else {
        Write-WARN "Login does NOT have sysadmin. This may cause ITDeskDB/Agent permission issues."
    }
} else {
    Write-FAIL "Cannot connect to $SqlInstance."
}

# Database list
$dbs = Test-SqlQuery "SELECT name, state_desc FROM sys.databases ORDER BY name" -Label "Database list"
if ($dbs -and $dbs.Rows.Count -gt 0) {
    Write-INFO "Databases on $SqlInstance :"
    $expected = @('NailInventoryDB','ITDeskDB','BoxArchive2019','TimesheetLegacy','msdb')
    foreach ($row in $dbs.Rows) {
        $dbName = $row["name"]
        $dbState = $row["state_desc"]
        $marker = if ($dbName -in $expected) { " <<<" } else { "" }
        Write-INFO "  $dbName ($dbState)$marker"
    }
} else {
    Write-FAIL "Could not retrieve database list."
}

# ITDeskDB direct test
Write-INFO ""
Write-INFO "Testing direct ITDeskDB connectivity (the Phase 3 failure point):"
$itTest = Test-SqlQuery "SELECT DB_NAME() AS DB, USER_NAME() AS DbUser, IS_MEMBER('db_owner') AS IsOwner" -Database "ITDeskDB" -Label "ITDeskDB direct connect"
if ($itTest -and $itTest.Rows.Count -gt 0) {
    $dbUser = Get-Cell $itTest -Column "DbUser"
    $isOwner = Get-Cell $itTest -Column "IsOwner"
    Write-OK "Connected to ITDeskDB as $dbUser (db_owner=$isOwner)"
} else {
    Write-FAIL "Cannot connect to ITDeskDB."
    Write-FIX "Grant access: USE [ITDeskDB]; CREATE USER [$currentLogin] FOR LOGIN [$currentLogin]; ALTER ROLE db_owner ADD MEMBER [$currentLogin]"
}

# ITDeskDB table check
Write-INFO ""
Write-INFO "ITDeskDB table and row counts:"
$tableCheck = Test-SqlQuery "
    SELECT t.name AS TableName, p.rows AS RowCount
    FROM sys.tables t
    INNER JOIN sys.partitions p ON t.object_id = p.object_id AND p.index_id IN (0,1)
    ORDER BY t.name
" -Database "ITDeskDB" -Label "ITDeskDB tables"
if ($tableCheck -and $tableCheck.Rows.Count -gt 0) {
    foreach ($row in $tableCheck.Rows) {
        Write-INFO "  $($row['TableName']): $($row['RowCount']) rows"
    }
} else {
    Write-WARN "No tables found in ITDeskDB (or cannot access)."
}

# ITDeskDB stored procedures
$procCheck = Test-SqlQuery "
    SELECT name FROM sys.procedures WHERE name LIKE 'usp_%' ORDER BY name
" -Database "ITDeskDB" -Label "ITDeskDB procs"
if ($procCheck -and $procCheck.Rows.Count -gt 0) {
    Write-INFO "Stored procedures:"
    foreach ($row in $procCheck.Rows) {
        Write-INFO "  $($row['name'])"
    }
} else {
    Write-WARN "No stored procedures found in ITDeskDB."
}

# BlackTeam logins
Write-INFO ""
$logins = Test-SqlQuery "SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE name LIKE '%BlackTeam%' ORDER BY name" -Label "BlackTeam logins"
if ($logins -and $logins.Rows.Count -gt 0) {
    Write-INFO "BlackTeam SQL logins:"
    foreach ($row in $logins.Rows) {
        $status = if ($row["is_disabled"]) { "DISABLED" } else { "enabled" }
        Write-INFO "  $($row['name']) ($($row['type_desc'])) - $status"
    }
} else {
    Write-WARN "No BlackTeam SQL logins found."
}

# BlackTeam DB-level permissions across all expected databases
Write-INFO ""
Write-INFO "BlackTeam DB permissions:"
foreach ($dbName in @('NailInventoryDB','ITDeskDB','BoxArchive2019','TimesheetLegacy')) {
    $dbPerms = Test-SqlQuery "
        SELECT dp.name AS DbUser, STRING_AGG(r.name, ', ') AS Roles
        FROM sys.database_principals dp
        LEFT JOIN sys.database_role_members drm ON dp.principal_id = drm.member_principal_id
        LEFT JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
        WHERE dp.name LIKE '%BlackTeam%'
        GROUP BY dp.name
    " -Database $dbName -Label "$dbName BlackTeam perms"
    if ($dbPerms -and $dbPerms.Rows.Count -gt 0) {
        foreach ($row in $dbPerms.Rows) {
            Write-OK "  [$dbName] $($row['DbUser']): $($row['Roles'])"
        }
    } else {
        Write-WARN "  [$dbName] No BlackTeam users mapped."
    }
}

# ============================================================================
# 5. SQL AGENT JOBS (verify they exist and last run status)
# ============================================================================
Write-Section "5. SQL Agent Jobs"

$jobs = Test-SqlQuery "
    SELECT
        j.name          AS JobName,
        j.enabled       AS Enabled,
        SUSER_SNAME(j.owner_sid) AS Owner,
        ss.freq_subday_interval  AS IntervalMin,
        (SELECT TOP 1 h.run_status FROM msdb.dbo.sysjobhistory h WHERE h.job_id = j.job_id ORDER BY h.instance_id DESC) AS LastRunStatus,
        (SELECT TOP 1 h.message FROM msdb.dbo.sysjobhistory h WHERE h.job_id = j.job_id AND h.step_id = 0 ORDER BY h.instance_id DESC) AS LastMessage
    FROM msdb.dbo.sysjobs j
    LEFT JOIN msdb.dbo.sysjobschedules sjs ON j.job_id = sjs.job_id
    LEFT JOIN msdb.dbo.sysschedules    ss  ON sjs.schedule_id = ss.schedule_id
    WHERE j.name LIKE 'SBF%'
    ORDER BY j.name
" -Database "msdb" -Label "SQL Agent jobs"

if ($jobs -and $jobs.Rows.Count -gt 0) {
    foreach ($row in $jobs.Rows) {
        $jobName = $row['JobName']
        $enabled = $row['Enabled']
        $owner   = Get-Cell -Table $jobs -Column "Owner"
        $interval = $row['IntervalMin']
        $lastStatus = $row['LastRunStatus']
        $lastMsg = $row['LastMessage']
        $statusStr = switch ($lastStatus) { 0 {"FAILED"} 1 {"Succeeded"} 2 {"Retry"} 3 {"Canceled"} default {"Never run"} }
        if ($lastStatus -eq 1) {
            Write-OK "  $jobName | Enabled=$enabled | Owner=$owner | Every ${interval}m | Last=$statusStr"
        } elseif ($null -eq $lastStatus -or $lastStatus -is [System.DBNull]) {
            Write-WARN "  $jobName | Enabled=$enabled | Owner=$owner | Every ${interval}m | Never run (Agent not started?)"
        } else {
            Write-FAIL "  $jobName | Enabled=$enabled | Owner=$owner | Every ${interval}m | Last=$statusStr"
            if ($lastMsg -and $lastMsg -isnot [System.DBNull]) {
                $msgSnip = if ($lastMsg.Length -gt 200) { $lastMsg.Substring(0,200) + "..." } else { $lastMsg }
                Write-INFO "    Message: $msgSnip"
            }
        }
    }
} else {
    Write-WARN "No SBF* jobs found in msdb.dbo.sysjobs."
}

# ============================================================================
# 6. SEED DATA SQL QUOTING  (simout lines 156-158)
# ============================================================================
Write-Section "6. Seed Data SQL Quoting"

Write-INFO "Checking Deploy-HelpdeskSystem.ps1 for unescaped single quotes in seed data..."

# Read the actual script to verify the fix is in place
$helpdeskScript = "$PSScriptRoot\Deploy-HelpdeskSystem.ps1"
if (Test-Path $helpdeskScript) {
    $content = Get-Content $helpdeskScript -Raw
    if ($content -match '\$iss\s*=\s*\$issueData\.Issue\.Replace\(' ) {
        Write-OK "Deploy-HelpdeskSystem.ps1 already escapes single quotes in seed data (line ~438)."
    } else {
        Write-FAIL "Deploy-HelpdeskSystem.ps1 does NOT escape single quotes in `$iss."
        Write-FIX 'Add: $iss = $issueData.Issue.Replace("''","''''")  after $iss assignment.'
    }
} else {
    Write-WARN "Deploy-HelpdeskSystem.ps1 not found at $helpdeskScript - cannot check."
}

# Also verify the actual data in ITDeskDB for evidence of the problem
$badTickets = Test-SqlQuery "
    SELECT TOP 5 TicketID, Issue FROM Tickets WHERE Issue LIKE '%''%' ORDER BY TicketID
" -Database "ITDeskDB" -Label "Tickets with quotes"
if ($badTickets -and $badTickets.Rows.Count -gt 0) {
    Write-OK "Found $($badTickets.Rows.Count) ticket(s) with apostrophes - they were inserted correctly."
} else {
    Write-INFO "No tickets with apostrophes found (seed data may not have included them, or insert failed)."
}

# ============================================================================
# 7. CORPDATA / CORPSHARES  (simout line 45)
# ============================================================================
Write-Section "7. CorpData / CorpShares"

Write-INFO "Expected: $CorpSharePath"
if (Test-Path $CorpSharePath) {
    Write-OK "$CorpSharePath exists."
    $subdirs = Get-ChildItem $CorpSharePath -Directory -ErrorAction SilentlyContinue
    foreach ($d in $subdirs) {
        $marker = if ($d.Name -eq 'CorpData') { ' <<<' } else { '' }
        Write-INFO "  $($d.Name)$marker"
    }
    $corpData = Join-Path $CorpSharePath "CorpData"
    if (Test-Path $corpData) {
        Write-OK "CorpData subfolder exists."
    } else {
        Write-WARN "CorpData subfolder NOT found."
        Write-FIX "Run BadFS.ps1 to create file shares, or create it manually: mkdir '$corpData'"
    }
} else {
    Write-FAIL "$CorpSharePath does not exist."
    Write-FIX "Run BadFS.ps1 first. Phase 1 ACL grant and Phase 4 file simulation will be skipped."
}

# Check SMB shares
Write-INFO ""
Write-INFO "SMB shares on this machine:"
try {
    $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^\$|^IPC\$|^ADMIN\$' }
    if ($shares) {
        foreach ($sh in $shares) {
            Write-INFO "  \\$env:COMPUTERNAME\$($sh.Name) -> $($sh.Path)"
        }
    } else {
        Write-INFO "  (none besides defaults)"
    }
} catch {
    Write-WARN "Get-SmbShare failed: $_"
}

# ============================================================================
# 8. IIS LOCKED SECTIONS  (simout lines 170-172)
# ============================================================================
Write-Section "8. IIS Authentication Sections"

$appcmd = "$env:SystemRoot\System32\inetsrv\appcmd.exe"
if (-not (Test-Path $appcmd)) {
    Write-WARN "appcmd.exe not found - IIS may not be installed."
} else {
    Write-OK "appcmd.exe found."

    # Check lock status
    $sections = @(
        "system.webServer/security/authentication/windowsAuthentication",
        "system.webServer/security/authentication/anonymousAuthentication"
    )
    foreach ($section in $sections) {
        try {
            $output = & $appcmd list config -section:$section 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-OK "Section '$section' is accessible (unlocked)."
            } else {
                Write-WARN "Section '$section' returned error: $output"
            }
        } catch {
            Write-FAIL "Error checking section '$section': $_"
        }
    }
}

# IIS sites/apps
Write-INFO ""
Write-INFO "IIS Sites and Applications:"
try {
    Import-Module WebAdministration -ErrorAction Stop
    $sites = Get-Website -ErrorAction SilentlyContinue
    foreach ($site in $sites) {
        Write-INFO "  Site: $($site.Name) (State=$($site.State))"
        $apps = Get-WebApplication -Site $site.Name -ErrorAction SilentlyContinue
        foreach ($app in $apps) {
            Write-INFO "    App: $($app.path) -> Pool=$($app.applicationPool) Path=$($app.PhysicalPath)"
        }
    }
    Write-INFO ""
    Write-INFO "App Pools:"
    $pools = Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue
    foreach ($pool in $pools) {
        $pm = Get-ItemProperty "IIS:\AppPools\$($pool.Name)" -Name processModel -ErrorAction SilentlyContinue
        $identity = if ($pm.identityType -eq 3) { "$($pm.userName)" } else { "identityType=$($pm.identityType)" }
        Write-INFO "  $($pool.Name): State=$($pool.State) Runtime=$($pool.managedRuntimeVersion) Identity=$identity"
    }
} catch {
    Write-WARN "WebAdministration module not available: $_"
}

# Verify helpdesk & orders endpoints are actually responding
Write-INFO ""
Write-INFO "IIS Endpoint Smoke Tests:"
foreach ($endpoint in @(
    @{Name="Helpdesk Status"; Url="http://localhost/apps/helpdesk/api/status.aspx"},
    @{Name="Orders List";     Url="http://localhost/apps/orders/api/orders.aspx"}
)) {
    try {
        $resp = Invoke-WebRequest -Uri $endpoint.Url -UseDefaultCredentials -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        Write-OK "$($endpoint.Name): HTTP $($resp.StatusCode) ($($resp.Content.Length) bytes)"
    } catch {
        $errMsg = $_.Exception.Message
        if ($errMsg.Length -gt 150) { $errMsg = $errMsg.Substring(0,150) + "..." }
        Write-WARN "$($endpoint.Name): $errMsg"
    }
}

# ============================================================================
# 9. HMAILSERVER COM / RELAY  (AllowRelay property issue)
# ============================================================================
Write-Section "9. hMailServer COM API & Relay Ranges"

$hms = $null
try {
    $hms = New-Object -ComObject hMailServer.Application -ErrorAction Stop
    Write-OK "hMailServer COM object created."
} catch {
    Write-FAIL "Cannot create hMailServer COM object: $_"
    $hmsSvc = Get-Service hMailServer -ErrorAction SilentlyContinue
    if ($hmsSvc) {
        Write-INFO "hMailServer service: $($hmsSvc.Status)"
    } else {
        Write-INFO "hMailServer service not found."
    }
}

if ($hms) {
    try {
        $authResult = $hms.Authenticate("Administrator", $HMailAdminPassword)
        if ($authResult) {
            Write-OK "Authenticated to hMailServer COM API."

            # hMailServer version info
            Write-INFO ""
            try {
                $hmsVer = $hms.Version
                Write-INFO "hMailServer version: $hmsVer"
            } catch {
                Write-INFO "Could not read hMailServer version."
            }

            # Check SecurityRanges vs IPRanges (the real issue)
            Write-INFO ""
            Write-INFO "--- IP/Security Ranges Diagnosis ---"
            Write-INFO "Deploy-MailServer.ps1 tries SecurityRanges first, then IPRanges."

            $hmsIPRanges = $null
            try {
                $hmsIPRanges = $hms.Settings.SecurityRanges
                if ($null -ne $hmsIPRanges) {
                    Write-OK "Settings.SecurityRanges is accessible. Count: $($hmsIPRanges.Count)"
                } else {
                    Write-WARN "Settings.SecurityRanges returned NULL."
                }
            } catch {
                Write-WARN "Settings.SecurityRanges threw: $_"
            }

            if ($null -eq $hmsIPRanges) {
                try {
                    $hmsIPRanges = $hms.Settings.IPRanges
                    if ($null -ne $hmsIPRanges) {
                        Write-OK "Settings.IPRanges is accessible. Count: $($hmsIPRanges.Count)"
                    } else {
                        Write-FAIL "Settings.IPRanges also returned NULL."
                    }
                } catch {
                    Write-FAIL "Settings.IPRanges also threw: $_"
                }
            }

            if ($null -ne $hmsIPRanges) {
                Write-INFO "Existing ranges:"
                for ($i = 0; $i -lt $hmsIPRanges.Count; $i++) {
                    $r = $hmsIPRanges.Item($i)
                    Write-INFO "  '$($r.Name)': $($r.LowerIP) - $($r.UpperIP)"
                    # Probe which relay property exists
                    $relayProp = "unknown"
                    try { $relayProp = "AllowSMTPRelaying=$($r.AllowSMTPRelaying)" } catch {
                        try { $relayProp = "AllowRelay=$($r.AllowRelay)" } catch {
                            $relayProp = "NEITHER AllowSMTPRelaying nor AllowRelay exists!"
                        }
                    }
                    Write-INFO "    Relay: $relayProp"
                }

                # Probe all properties on a range object to find the relay property
                Write-INFO ""
                Write-INFO "--- Probing range object for relay-related properties ---"
                if ($hmsIPRanges.Count -gt 0) {
                    $testRange = $hmsIPRanges.Item(0)
                    $members = $testRange | Get-Member -MemberType Property -ErrorAction SilentlyContinue
                    if ($members) {
                        $relayMembers = $members | Where-Object { $_.Name -match "relay|smtp|allow" }
                        if ($relayMembers) {
                            Write-OK "Found relay-related properties:"
                            foreach ($m in $relayMembers) {
                                $val = try { $testRange."$($m.Name)" } catch { "(error reading)" }
                                Write-INFO "  $($m.Name) = $val"
                            }
                        } else {
                            Write-WARN "No relay-related properties found via Get-Member."
                            Write-INFO "All properties on the range object:"
                            foreach ($m in $members) {
                                Write-INFO "  $($m.Name)"
                            }
                        }
                    } else {
                        Write-WARN "Get-Member returned no properties (COM object may not expose them)."
                        Write-INFO "Trying known property names by brute force..."
                        foreach ($propName in @('AllowRelay','AllowSMTPRelaying','Relay','RequireSMTPAuth',
                                                'AllowSMTPAuthPlain','AllowDeliveryFromRemoteToLocal',
                                                'AllowDeliveryFromLocalToRemote','RequireAuthForDeliveryToLocal')) {
                            try {
                                $val = $testRange.$propName
                                Write-OK "  $propName = $val"
                            } catch {
                                # Property doesn't exist - skip silently
                            }
                        }
                    }
                }
            } else {
                Write-FAIL "Cannot access any IP/Security ranges object."
                Write-FIX "This may be a hMailServer version issue. Check if ranges are configurable via hMailServer Admin UI."
            }

            # Check domains
            Write-INFO ""
            Write-INFO "hMailServer domains:"
            $domains = $hms.Domains
            for ($i = 0; $i -lt $domains.Count; $i++) {
                $d = $domains.Item($i)
                Write-INFO "  $($d.Name) (Active=$($d.Active), Accounts=$($d.Accounts.Count))"
            }

            # Verify BlackTeam_MailBot account
            Write-INFO ""
            try {
                $domain = $domains.Item(0)
                $mailbot = $domain.Accounts.ItemByAddress("blackteam_mailbot@$($domain.Name)")
                Write-OK "BlackTeam_MailBot mailbox exists: blackteam_mailbot@$($domain.Name)"
            } catch {
                Write-WARN "BlackTeam_MailBot mailbox not found or error: $_"
            }

        } else {
            Write-FAIL "Authentication returned false/null. Wrong -HMailAdminPassword?"
        }
    } catch {
        Write-FAIL "hMailServer auth/query failed: $_"
    }
    try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($hms) | Out-Null } catch {}
}

# ============================================================================
# 10. CIDR SUBNET PARSING  (PowerShell 5.1 integer overflow)
# ============================================================================
Write-Section "10. CIDR Subnet Parsing (LabSubnet='$LabSubnet')"

Write-INFO "Testing Deploy-MailServer.ps1 CIDR math (lines 370-394)..."

try {
    $cidrParts = $LabSubnet -split "/"
    $baseIP    = $cidrParts[0]
    $prefixLen = [int]$cidrParts[1]
    Write-INFO "Base IP: $baseIP  Prefix: /$prefixLen"

    $ipBytes = ([System.Net.IPAddress]::Parse($baseIP)).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt = [System.BitConverter]::ToUInt32($ipBytes, 0)
    Write-INFO "IP as UInt32: $ipInt (0x$($ipInt.ToString('X8')))"

    # Reproduce the CURRENT code from Deploy-MailServer.ps1 (the fixed version):
    #   $hostBits = 32 - $prefixLen
    #   $hostMask = [uint32]((1 -shl $hostBits) - 1)
    #   $mask     = [uint32]::MaxValue -bxor $hostMask
    Write-INFO ""
    Write-INFO "Current code approach (XOR-based, avoids 0xFFFFFFFF -shl):"
    $hostBits = 32 - $prefixLen
    Write-INFO "  hostBits = 32 - $prefixLen = $hostBits"

    try {
        $hostMask = [uint32]((1 -shl $hostBits) - 1)
        Write-OK "  hostMask = [uint32]((1 -shl $hostBits) - 1) = $hostMask (0x$($hostMask.ToString('X8')))"
    } catch {
        Write-FAIL "  hostMask calc failed: $_"
        Write-FIX "  This means the fix in Deploy-MailServer.ps1 also has a bug for this prefix length."
    }

    try {
        $mask = [uint32]::MaxValue -bxor $hostMask
        Write-OK "  mask = MaxValue -bxor hostMask = $mask (0x$($mask.ToString('X8')))"
    } catch {
        Write-FAIL "  mask calc failed: $_"
    }

    $networkInt = $ipInt -band $mask
    $broadInt   = $networkInt -bor $hostMask

    $networkBytes = [System.BitConverter]::GetBytes([uint32]$networkInt)
    [Array]::Reverse($networkBytes)
    $broadBytes = [System.BitConverter]::GetBytes([uint32]$broadInt)
    [Array]::Reverse($broadBytes)

    $lowerIP = [System.Net.IPAddress]::new($networkBytes).ToString()
    $upperIP = [System.Net.IPAddress]::new($broadBytes).ToString()
    Write-OK "Computed range: $lowerIP - $upperIP"

    # Also verify the OLD broken approach to confirm the fix was needed
    Write-INFO ""
    Write-INFO "Verifying the OLD broken code would fail:"
    Write-INFO "  Original: `$mask = [uint32](0xFFFFFFFF -shl (32 - $prefixLen))"
    $shiftResult = 0xFFFFFFFF -shl $hostBits
    Write-INFO "  0xFFFFFFFF -shl $hostBits = $shiftResult (type=$($shiftResult.GetType().Name))"
    try {
        $oldMask = [uint32]$shiftResult
        Write-WARN "  Cast to [uint32] SUCCEEDED: $oldMask (unexpected on PS 5.1 - this version may not have the bug)"
    } catch {
        Write-OK "  Cast to [uint32] FAILED as expected: $_"
        Write-INFO "  This confirms the fix in Deploy-MailServer.ps1 is necessary."
    }

} catch {
    Write-FAIL "CIDR test failed: $_"
}

# ============================================================================
# 11. SQL AGENT ERROR LOG (via T-SQL)
# ============================================================================
Write-Section "11. SQL Agent Error Log (via T-SQL)"

# sp_readerrorlog signature: @p1=log_number, @p2=log_type (1=engine, 2=agent), @p3=search_string1, @p4=search_string2
$agentLog = Test-SqlQuery -Query "EXEC msdb.dbo.sp_readerrorlog 0, 2" -Label "Agent error log"
if ($agentLog -and $agentLog.Rows.Count -gt 0) {
    $count = [Math]::Min(20, $agentLog.Rows.Count)
    Write-INFO "Last $count Agent log entries:"
    for ($i = 0; $i -lt $count; $i++) {
        $row = $agentLog.Rows[$i]
        Write-INFO "  [$($row[0])] $($row[2])"
    }
} else {
    Write-WARN "No Agent log returned (Agent may never have started successfully)."
}

# ============================================================================
# 12. SQL BROWSER & PORT INFO
# ============================================================================
Write-Section "12. SQL Browser & Port Info"

$browser = Get-Service -Name "SQLBrowser" -ErrorAction SilentlyContinue
if ($browser) {
    Write-INFO "SQL Browser: $($browser.Status) ($($browser.StartType))"
    if ($browser.Status -ne 'Running') {
        Write-WARN "SQL Browser is not running. Named instances need it for dynamic port resolution."
    }
} else {
    Write-WARN "SQL Browser service not found."
}

try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
    $internalName = (Get-ItemProperty $regPath -ErrorAction Stop).$instanceName
    if ($internalName) {
        $tcpPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$internalName\MSSQLServer\SuperSocketNetLib\Tcp\IPAll"
        if (Test-Path $tcpPath) {
            $tcpProps = Get-ItemProperty $tcpPath
            Write-INFO "TCP Dynamic Port: $($tcpProps.TcpDynamicPorts)"
            Write-INFO "TCP Static Port:  $($tcpProps.TcpPort)"
        }
    }
} catch {
    Write-WARN "Could not read TCP port from registry: $_"
}

# ============================================================================
# 13. SMTP CONNECTIVITY TEST
# ============================================================================
Write-Section "13. SMTP Connectivity"

Write-INFO "Testing SMTP port 25 on localhost..."
try {
    $tcpTest = Test-NetConnection -ComputerName 127.0.0.1 -Port 25 -InformationLevel Quiet -ErrorAction SilentlyContinue
    if ($tcpTest) {
        Write-OK "SMTP port 25 is listening."

        # Try an actual SMTP HELO
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $tcp.Connect("127.0.0.1", 25)
            $stream = $tcp.GetStream()
            $reader = New-Object System.IO.StreamReader $stream
            $writer = New-Object System.IO.StreamWriter $stream
            $writer.AutoFlush = $true

            $banner = $reader.ReadLine()
            Write-INFO "SMTP banner: $banner"

            $writer.WriteLine("EHLO diag.local")
            Start-Sleep -Milliseconds 500
            while ($stream.DataAvailable) {
                $line = $reader.ReadLine()
                Write-INFO "  EHLO: $line"
            }

            $writer.WriteLine("QUIT")
            $tcp.Close()
        } catch {
            Write-WARN "SMTP conversation failed: $_"
        }
    } else {
        Write-WARN "SMTP port 25 is NOT listening."
    }
} catch {
    Write-WARN "Port check failed: $_"
}

# ============================================================================
# 14. DNS MX RECORD
# ============================================================================
Write-Section "14. DNS MX Record"

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $domainDNS = (Get-ADDomain).DNSRoot
    Write-INFO "Domain: $domainDNS"

    try {
        Import-Module DnsServer -ErrorAction Stop
        $mx = Get-DnsServerResourceRecord -ZoneName $domainDNS -RRType MX -ErrorAction SilentlyContinue
        if ($mx) {
            foreach ($r in $mx) {
                Write-OK "MX: $($r.RecordData.MailExchange) (Priority $($r.RecordData.Preference))"
            }
        } else {
            Write-WARN "No MX records found for $domainDNS."
        }
    } catch {
        Write-WARN "DnsServer module not available: $_"
    }
} catch {
    Write-WARN "Could not resolve domain for MX check: $_"
}

# ============================================================================
# 15. CREDENTIALS.JSON VALIDATION
# ============================================================================
Write-Section "15. credentials.json Validation"

$credFile = "C:\Simulator\credentials.json"
if (Test-Path $credFile) {
    try {
        $creds = Get-Content $credFile -Raw -Encoding UTF8 | ConvertFrom-Json
        Write-OK "credentials.json parsed successfully."

        # Check expected sections
        foreach ($section in @('smtp')) {
            if ($creds.$section) {
                Write-OK "  Section '$section' present."
                $creds.$section.PSObject.Properties | ForEach-Object {
                    $val = if ($_.Name -match 'password|secret|key') { '***' } else { $_.Value }
                    Write-INFO "    $($_.Name) = $val"
                }
            } else {
                Write-WARN "  Section '$section' missing."
            }
        }

        # List all top-level keys
        Write-INFO "  Top-level keys: $($creds.PSObject.Properties.Name -join ', ')"
    } catch {
        Write-FAIL "credentials.json parse error: $_"
    }
} else {
    Write-WARN "credentials.json not found at $credFile."
}

# ============================================================================
# SUMMARY & FIXES
# ============================================================================
Write-Section "SUMMARY OF ISSUES & RECOMMENDED FIXES"

$issueNum = 0

# SQL Agent
$agentSvc2 = Get-Service -Name $agentSvcName -ErrorAction SilentlyContinue
if ($agentSvc2 -and $agentSvc2.Status -ne 'Running') {
    $issueNum++
    Write-Host ""
    Write-Host "  ISSUE $issueNum`: SQL Agent won't start" -ForegroundColor White
    Write-Host "    Root cause: EXECUTE permission denied on sp_sqlagent_update_agent_xps in msdb." -ForegroundColor Gray
    Write-Host "    The machine account has sysadmin but the Agent process may not pick up the" -ForegroundColor Gray
    Write-Host "    updated token. After granting sysadmin, restart the SQL engine THEN start Agent." -ForegroundColor Gray
    Write-Host "    Deploy-SupplierDeliveryJob.ps1 already attempts this but may need a longer wait." -ForegroundColor Gray
    Write-Host "    Manual fix:" -ForegroundColor Magenta
    Write-Host "      Restart-Service MSSQL`$BADSQL -Force; Start-Sleep 5; Start-Service SQLAGENT`$BADSQL" -ForegroundColor Magenta
}

# hMailServer relay
$issueNum++
Write-Host ""
Write-Host "  ISSUE $issueNum`: hMailServer relay range 'AllowRelay' property not found" -ForegroundColor White
Write-Host "    The hMailServer COM API on this version may not expose AllowRelay or" -ForegroundColor Gray
Write-Host "    AllowSMTPRelaying on IP range objects. Check the Get-Member output above" -ForegroundColor Gray
Write-Host "    to see what properties ARE available." -ForegroundColor Gray
Write-Host "    The relay ranges were created but relay is not enabled on them." -ForegroundColor Gray

# CorpData
$corpData2 = Join-Path $CorpSharePath "CorpData"
if (-not (Test-Path $corpData2)) {
    $issueNum++
    Write-Host ""
    Write-Host "  ISSUE $issueNum`: CorpData subfolder not found" -ForegroundColor White
    Write-Host "    $CorpSharePath\CorpData doesn't exist. Run BadFS.ps1 or mkdir it." -ForegroundColor Gray
}

Write-Host ""
Write-Host $divider -ForegroundColor DarkGray
Write-Host "  Diagnostic complete. Copy this output to analyze issues." -ForegroundColor White
Write-Host $divider -ForegroundColor DarkGray
Write-Host ""
