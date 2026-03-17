<#
.SYNOPSIS
    Diagnostic script to understand why SQL Agent starts then dies.
    Does NOT change anything - read-only investigation.

.NOTES
    Run as Administrator on the DC/SQL host.
    Context: Educational / CTF / Active Directory Lab Environment
#>

#Requires -RunAsAdministrator

param(
    [string]$SqlInstance = "localhost\BADSQL"
)

$ErrorActionPreference = "Continue"
$divider = "=" * 70

function Write-Section ($title) {
    Write-Host "`n$divider" -ForegroundColor DarkGray
    Write-Host "  $title" -ForegroundColor White
    Write-Host $divider -ForegroundColor DarkGray
}
function Write-OK   ($msg) { Write-Host "  [OK]      $msg" -ForegroundColor Green }
function Write-WARN ($msg) { Write-Host "  [WARN]    $msg" -ForegroundColor Yellow }
function Write-FAIL ($msg) { Write-Host "  [FAIL]    $msg" -ForegroundColor Red }
function Write-INFO ($msg) { Write-Host "  [INFO]    $msg" -ForegroundColor Cyan }

$instanceName = if ($SqlInstance -like '*\*') { $SqlInstance.Split('\')[1] } else { $null }
$sqlSvcName   = if ($instanceName) { "MSSQL`$$instanceName" } else { "MSSQLSERVER" }
$agentSvcName = if ($instanceName) { "SQLAGENT`$$instanceName" } else { "SQLSERVERAGENT" }
$agentLogPath = "C:\Program Files\Microsoft SQL Server\170.$instanceName\MSSQL\Log\SQLAGENT.OUT"

# =====================================================================
Write-Section "1. CURRENT SERVICE STATE"
# =====================================================================

$sqlSvc = Get-Service -Name $sqlSvcName -ErrorAction SilentlyContinue
$agentSvc = Get-Service -Name $agentSvcName -ErrorAction SilentlyContinue
Write-INFO "SQL Engine: $($sqlSvc.Status)"
Write-INFO "SQL Agent:  $($agentSvc.Status)"

$wmiAgent = Get-WmiObject Win32_Service -Filter "Name='$agentSvcName'" -ErrorAction SilentlyContinue
Write-INFO "Agent service logon: $($wmiAgent.StartName)"
Write-INFO "Agent start mode:    $($wmiAgent.StartMode)"
Write-INFO "Agent procid:           $($wmiAgent.ProcessId)"

# =====================================================================
Write-Section "2. SQLAGENT.OUT - LAST 20 LINES"
# =====================================================================

if (Test-Path $agentLogPath) {
    Get-Content $agentLogPath -Tail 20 | ForEach-Object {
        if ($_ -match '!.*Error|denied|terminated|fail') {
            Write-FAIL "  $_"
        } else {
            Write-INFO "  $_"
        }
    }
} else {
    Write-WARN "SQLAGENT.OUT not found at: $agentLogPath"
}

# =====================================================================
Write-Section "3. IF AGENT IS STOPPED - START IT AND WATCH"
# =====================================================================

$agentSvc.Refresh()
if ($agentSvc.Status -eq 'Running') {
    Write-OK "Agent is already running - skipping start test"
} else {
    Write-INFO "Agent is $($agentSvc.Status). Starting it and monitoring..."

    # Capture SQLAGENT.OUT size before start so we can read only new lines
    $logSizeBefore = if (Test-Path $agentLogPath) { (Get-Item $agentLogPath).Length } else { 0 }

    try {
        Start-Service -Name $agentSvcName -ErrorAction Stop
        Write-OK "Start-Service returned without error"
    } catch {
        Write-FAIL "Start-Service threw: $_"
    }

    # Check status every second for 15 seconds
    Write-INFO "Monitoring Agent service status for 15 seconds..."
    for ($sec = 1; $sec -le 15; $sec++) {
        Start-Sleep -Seconds 1
        $agentSvc.Refresh()
        $status = $agentSvc.Status
        $wmiNow = Get-WmiObject Win32_Service -Filter "Name='$agentSvcName'" -ErrorAction SilentlyContinue
        $procid = $wmiNow.ProcessId
        if ($status -ne 'Running') {
            Write-FAIL "  t+${sec}s: $status (procid=$procid) <<< AGENT DIED"
            break
        } else {
            Write-OK "  t+${sec}s: $status (procid=$procid)"
        }
    }

    # Show new SQLAGENT.OUT lines
    Write-Section "4. NEW SQLAGENT.OUT ENTRIES SINCE START"
    if (Test-Path $agentLogPath) {
        $logSizeAfter = (Get-Item $agentLogPath).Length
        if ($logSizeAfter -gt $logSizeBefore) {
            # Read the file and show lines we haven't seen
            $allLines = Get-Content $agentLogPath
            # Estimate: average ~100 bytes per line, show last N lines proportional to new bytes
            $newBytes = $logSizeAfter - $logSizeBefore
            $estNewLines = [Math]::Max(5, [Math]::Ceiling($newBytes / 80))
            $tail = [Math]::Min($estNewLines + 5, $allLines.Count)
            $allLines | Select-Object -Last $tail | ForEach-Object {
                if ($_ -match '!.*Error|denied|terminated|fail') {
                    Write-FAIL "  $_"
                } else {
                    Write-INFO "  $_"
                }
            }
        } else {
            Write-WARN "No new log entries written"
        }
    }
}

# =====================================================================
Write-Section "5. SQL ENGINE - AGENT IDENTITY CHECK"
# =====================================================================

Write-INFO "Checking what identity the engine sees for the Agent connection..."
try {
    $conn = New-Object System.Data.SqlClient.SqlConnection
    $conn.ConnectionString = "Server=$SqlInstance;Database=master;Integrated Security=SSPI;Connection Timeout=10;"
    $conn.Open()

    # Check if LocalSystem maps to anything useful
    $cmd = $conn.CreateCommand()
    $cmd.CommandText = @"
SELECT
    sp.name AS LoginName,
    sp.type_desc,
    sp.is_disabled,
    ISNULL((SELECT 1 FROM sys.server_role_members rm
            JOIN sys.server_principals rp ON rm.role_principal_id = rp.principal_id
            WHERE rp.name = 'sysadmin' AND rm.member_principal_id = sp.principal_id), 0) AS IsSysadmin
FROM sys.server_principals sp
WHERE sp.name IN (
    N'NT AUTHORITY\SYSTEM',
    N'NT SERVICE\MSSQL`$$instanceName',
    N'NT SERVICE\SQLAGENT`$$instanceName',
    N'BUILTIN\Administrators'
)
ORDER BY sp.name
"@
    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $cmd
    $table = New-Object System.Data.DataTable
    $null = $adapter.Fill($table)
    foreach ($row in $table.Rows) {
        $sa = if ($row.IsSysadmin -eq 1) { "sysadmin=YES" } else { "sysadmin=NO" }
        $dis = if ($row.is_disabled) { "DISABLED" } else { "enabled" }
        Write-INFO "  $($row.LoginName) | $($row.type_desc) | $dis | $sa"
    }
    if ($table.Rows.Count -eq 0) {
        Write-WARN "No matching logins found for system accounts!"
    }

    # Check sp_sqlagent_update_agent_xps permissions
    $cmd2 = $conn.CreateCommand()
    $cmd2.CommandText = "SELECT HAS_PERMS_BY_NAME('msdb.dbo.sp_sqlagent_update_agent_xps', 'OBJECT', 'EXECUTE') AS CanExec"
    $cmd2.CommandTimeout = 10
    $canExec = $cmd2.ExecuteScalar()
    Write-INFO "Current connection can EXECUTE sp_sqlagent_update_agent_xps: $canExec"

    $conn.Close()
} catch {
    Write-FAIL "SQL query failed: $_"
}

# =====================================================================
Write-Section "6. WINDOWS EVENT LOG - RECENT AGENT EVENTS"
# =====================================================================

try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Application'
        ProviderName = 'SQLSERVERAGENT*', 'SQLAGENT*', 'MSSQLSERVER'
        StartTime = (Get-Date).AddMinutes(-10)
    } -MaxEvents 10 -ErrorAction SilentlyContinue

    if ($events) {
        foreach ($ev in $events) {
            $lvl = switch ($ev.Level) { 1 {"CRIT"}; 2 {"ERR"}; 3 {"WARN"}; 4 {"INFO"}; default {"$($ev.Level)"} }
            $ts = $ev.TimeCreated.ToString("HH:mm:ss")
            $msg = $ev.Message.Substring(0, [Math]::Min(120, $ev.Message.Length)).Replace("`n", " ")
            if ($ev.Level -le 2) {
                Write-FAIL "  [$ts] [$lvl] $msg"
            } else {
                Write-INFO "  [$ts] [$lvl] $msg"
            }
        }
    } else {
        Write-WARN "No recent Application log events from SQL Agent"
    }
} catch {
    Write-WARN "Could not query event log: $_"
}

# =====================================================================
Write-Section "7. SERVICE RECOVERY CONFIG"
# =====================================================================

$scQuery = & sc.exe qfailure $agentSvcName 2>&1
Write-INFO "sc.exe qfailure output:"
foreach ($line in $scQuery) {
    Write-INFO "  $line"
}

Write-Section "DONE - paste this output back"
