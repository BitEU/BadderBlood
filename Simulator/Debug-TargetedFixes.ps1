<#
.SYNOPSIS
    Active fix-testing script. Tests multiple hypotheses for remaining issues
    and APPLIES fixes where possible, reporting what worked and what didn't.

    Issue A: SQL Agent still won't start after permissions are granted
    Issue B: ITDeskDB login failures after engine restart
    Issue C: Helpdesk HTTP 500 (AppPool identity)

.NOTES
    Run as Administrator on the DC/SQL host.
    This script WILL make changes (restart services, grant perms, reconfigure IIS).
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
function Write-FIX  ($msg) { Write-Host "  [FIX]     $msg" -ForegroundColor Magenta }

function Invoke-SqlQuery {
    param([string]$Query, [string]$Database = "master", [switch]$NonQuery)
    try {
        $conn = New-Object System.Data.SqlClient.SqlConnection
        $conn.ConnectionString = "Server=$SqlInstance;Database=$Database;Integrated Security=SSPI;Connection Timeout=10;"
        $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = $Query
        $cmd.CommandTimeout = 30
        if ($NonQuery) {
            $null = $cmd.ExecuteNonQuery()
            $conn.Close()
            return $true
        } else {
            $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $cmd
            $table   = New-Object System.Data.DataTable
            $null    = $adapter.Fill($table)
            $conn.Close()
            return $table
        }
    } catch {
        Write-FAIL "SQL error (DB=$Database): $_"
        return $null
    }
}

# Resolve service names
$instanceName = if ($SqlInstance -like '*\*') { $SqlInstance.Split('\')[1] } else { $null }
$sqlSvcName   = if ($instanceName) { "MSSQL`$$instanceName" } else { "MSSQLSERVER" }
$agentSvcName = if ($instanceName) { "SQLAGENT`$$instanceName" } else { "SQLSERVERAGENT" }

$DomainNB = (Get-ADDomain -ErrorAction SilentlyContinue).NetBIOSName
$wmiAgent = Get-WmiObject Win32_Service -Filter "Name='$agentSvcName'" -ErrorAction SilentlyContinue
$agentLogon = if ($wmiAgent) { $wmiAgent.StartName } else { "UNKNOWN" }
$agentSqlLogin = $agentLogon
if ($agentLogon -match 'NT AUTHORITY\\(NETWORK\s*SERVICE|LOCAL\s*SERVICE|SYSTEM)') {
    $agentSqlLogin = "$DomainNB\$env:COMPUTERNAME`$"
}

Write-Section "CURRENT STATE"

Write-INFO "SQL Agent logon: $agentLogon -> SQL login: $agentSqlLogin"
Write-INFO "SQL Agent status: $((Get-Service $agentSvcName -ErrorAction SilentlyContinue).Status)"
Write-INFO "SQL Engine status: $((Get-Service $sqlSvcName -ErrorAction SilentlyContinue).Status)"

# Check current perms state
$loginExists = Invoke-SqlQuery "SELECT name, is_disabled FROM sys.server_principals WHERE name = N'$agentSqlLogin'"
if ($loginExists -and $loginExists.Rows.Count -gt 0) {
    Write-OK "Login '$agentSqlLogin' exists"
    $isSA = (Invoke-SqlQuery "SELECT IS_SRVROLEMEMBER('sysadmin', '$agentSqlLogin') AS v").Rows[0].v
    Write-INFO "  sysadmin = $isSA"
} else {
    Write-FAIL "Login '$agentSqlLogin' does NOT exist"
}

$perms = Invoke-SqlQuery -Query "SELECT dp.name AS Grantee, perm.permission_name, perm.state_desc FROM sys.database_permissions perm JOIN sys.database_principals dp ON perm.grantee_principal_id = dp.principal_id WHERE perm.major_id = OBJECT_ID('dbo.sp_sqlagent_update_agent_xps')" -Database "msdb"
if ($perms -and $perms.Rows.Count -gt 0) {
    Write-OK "Explicit perms on sp_sqlagent_update_agent_xps:"
    foreach ($r in $perms.Rows) { Write-INFO "  $($r.state_desc) $($r.permission_name) TO $($r.Grantee)" }
} else {
    Write-WARN "No explicit perms on sp_sqlagent_update_agent_xps"
}

# =====================================================================
Write-Section "HYPOTHESIS A: Agent needs more recovery time after engine restart"
Write-INFO "The 8s sleep + 3 retries with 5s gaps may not be enough."
Write-INFO "Testing: poll msdb accessibility, THEN start Agent."
# =====================================================================

# Step 1: Ensure login + sysadmin + EXECUTE exist (idempotent)
Write-FIX "Ensuring login + sysadmin..."
Invoke-SqlQuery -Query @"
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'$agentSqlLogin')
    CREATE LOGIN [$agentSqlLogin] FROM WINDOWS;
IF IS_SRVROLEMEMBER('sysadmin', '$agentSqlLogin') = 0
    ALTER SERVER ROLE sysadmin ADD MEMBER [$agentSqlLogin];
"@ -NonQuery | Out-Null

Write-FIX "Granting EXECUTE on sp_sqlagent_update_agent_xps in msdb context..."
Invoke-SqlQuery -Query @"
IF OBJECT_ID('dbo.sp_sqlagent_update_agent_xps', 'P') IS NOT NULL
    GRANT EXECUTE ON dbo.sp_sqlagent_update_agent_xps TO [$agentSqlLogin];
"@ -Database "msdb" -NonQuery | Out-Null

# Verify the grant landed
$permsAfter = Invoke-SqlQuery -Query "SELECT dp.name AS Grantee FROM sys.database_permissions perm JOIN sys.database_principals dp ON perm.grantee_principal_id = dp.principal_id WHERE perm.major_id = OBJECT_ID('dbo.sp_sqlagent_update_agent_xps')" -Database "msdb"
if ($permsAfter -and $permsAfter.Rows.Count -gt 0) {
    Write-OK "EXECUTE grant confirmed in msdb"
} else {
    Write-FAIL "EXECUTE grant did NOT land - something else is wrong"
}

# Step 2: Restart SQL Engine
Write-FIX "Restarting SQL Engine..."
Restart-Service -Name $sqlSvcName -Force -ErrorAction Stop
$svc = Get-Service $sqlSvcName
$svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
Write-OK "Engine service reports Running"

# Step 3: Poll until msdb is actually queryable (not just service Running)
Write-FIX "Polling until msdb is actually responsive..."
$msdbReady = $false
for ($i = 1; $i -le 30; $i++) {
    try {
        $conn = New-Object System.Data.SqlClient.SqlConnection
        $conn.ConnectionString = "Server=$SqlInstance;Database=msdb;Integrated Security=SSPI;Connection Timeout=5;"
        $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = "SELECT 1 AS ping"
        $cmd.CommandTimeout = 5
        $null = $cmd.ExecuteScalar()
        $conn.Close()
        $msdbReady = $true
        Write-OK "msdb responsive after $i seconds"
        break
    } catch {
        Start-Sleep -Seconds 1
    }
}
if (-not $msdbReady) {
    Write-FAIL "msdb not responsive after 30 seconds"
}

# Step 4: Extra safety - verify the login still has sysadmin after restart
$isSAAfter = Invoke-SqlQuery "SELECT IS_SRVROLEMEMBER('sysadmin', '$agentSqlLogin') AS v"
if ($isSAAfter -and $isSAAfter.Rows.Count -gt 0 -and $isSAAfter.Rows[0].v -eq 1) {
    Write-OK "sysadmin confirmed after engine restart"
} else {
    Write-FAIL "sysadmin NOT confirmed after restart - this would explain Agent failure"
    Write-FIX "Re-granting sysadmin..."
    Invoke-SqlQuery "ALTER SERVER ROLE sysadmin ADD MEMBER [$agentSqlLogin]" -NonQuery | Out-Null
}

# Step 5: Verify EXECUTE grant survived engine restart
$permsSurvived = Invoke-SqlQuery -Query "SELECT dp.name AS Grantee FROM sys.database_permissions perm JOIN sys.database_principals dp ON perm.grantee_principal_id = dp.principal_id WHERE perm.major_id = OBJECT_ID('dbo.sp_sqlagent_update_agent_xps')" -Database "msdb"
if ($permsSurvived -and $permsSurvived.Rows.Count -gt 0) {
    Write-OK "EXECUTE grant survived engine restart"
} else {
    Write-FAIL "EXECUTE grant did NOT survive engine restart!"
    Write-FIX "Re-granting EXECUTE in msdb..."
    Invoke-SqlQuery -Query "GRANT EXECUTE ON dbo.sp_sqlagent_update_agent_xps TO [$agentSqlLogin]" -Database "msdb" -NonQuery | Out-Null
}

# Step 6: Now try starting the Agent
Write-FIX "Attempting to start SQL Agent..."
$agentStarted = $false
try {
    Start-Service -Name $agentSvcName -ErrorAction Stop
    $agSvc = Get-Service $agentSvcName
    $agSvc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    $agentStarted = $true
    Write-OK "SQL Agent STARTED SUCCESSFULLY!"
} catch {
    Write-FAIL "Start-Service failed: $_"
}

if (-not $agentStarted) {
    Write-INFO ""
    Write-INFO "Checking SQLAGENT.OUT for what went wrong THIS time..."
    $agentLogPath = "C:\Program Files\Microsoft SQL Server\MSSQL17.BADSQL\MSSQL\Log\SQLAGENT.OUT"
    if (Test-Path $agentLogPath) {
        $lastLines = Get-Content $agentLogPath -Tail 15
        foreach ($line in $lastLines) {
            if ($line -match '!.*Error|denied|terminated|fail') {
                Write-FAIL "  $line"
            } else {
                Write-INFO "  $line"
            }
        }
    }

    # Hypothesis B: Maybe the Agent service account needs an explicit msdb user mapping
    Write-Section "HYPOTHESIS B: Agent needs explicit msdb user mapping"
    Write-FIX "Creating explicit msdb user for '$agentSqlLogin'..."
    Invoke-SqlQuery -Query @"
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$agentSqlLogin')
    CREATE USER [$agentSqlLogin] FOR LOGIN [$agentSqlLogin];
EXEC sp_addrolemember 'SQLAgentOperatorRole', '$agentSqlLogin';
EXEC sp_addrolemember 'SQLAgentUserRole', '$agentSqlLogin';
"@ -Database "msdb" -NonQuery | Out-Null

    Write-FIX "Retrying Agent start after msdb user creation..."
    try {
        Start-Service -Name $agentSvcName -ErrorAction Stop
        $agSvc = Get-Service $agentSvcName
        $agSvc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        $agentStarted = $true
        Write-OK "SQL Agent STARTED after msdb user creation!"
    } catch {
        Write-FAIL "Still failed: $_"
    }
}

if (-not $agentStarted) {
    # Hypothesis C: Maybe we need to change the Agent service account to LocalSystem
    Write-Section "HYPOTHESIS C: Change Agent to run as LocalSystem"
    Write-INFO "NT AUTHORITY\NETWORKSERVICE might have OS-level restrictions."
    Write-INFO "Trying LocalSystem as the Agent service identity..."

    try {
        $scResult = & sc.exe config $agentSvcName obj= "LocalSystem" 2>&1
        Write-INFO "sc.exe config result: $scResult"
        Start-Sleep -Seconds 2

        Start-Service -Name $agentSvcName -ErrorAction Stop
        $agSvc = Get-Service $agentSvcName
        $agSvc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        $agentStarted = $true
        Write-OK "SQL Agent STARTED as LocalSystem!"
    } catch {
        Write-FAIL "Still failed as LocalSystem: $_"
    }

    if (-not $agentStarted) {
        Write-INFO ""
        Write-INFO "Checking SQLAGENT.OUT again..."
        if (Test-Path $agentLogPath) {
            $lastLines = Get-Content $agentLogPath -Tail 15
            foreach ($line in $lastLines) {
                if ($line -match '!.*Error|denied|terminated|fail') {
                    Write-FAIL "  $line"
                } else {
                    Write-INFO "  $line"
                }
            }
        }
    }
}

# =====================================================================
Write-Section "ISSUE B: Helpdesk HTTP 500 - AppPool Identity Check"
# =====================================================================

try {
    Import-Module WebAdministration -ErrorAction Stop
    $poolPath = "IIS:\AppPools\HelpdeskAppPool"
    if (Test-Path $poolPath) {
        # Read via appcmd which is more reliable than WebAdministration
        $appcmdOutput = & "$env:SystemRoot\System32\inetsrv\appcmd.exe" list apppool "HelpdeskAppPool" /text:processModel.identityType 2>&1
        $appcmdUser   = & "$env:SystemRoot\System32\inetsrv\appcmd.exe" list apppool "HelpdeskAppPool" /text:processModel.userName 2>&1
        Write-INFO "appcmd identityType: $appcmdOutput"
        Write-INFO "appcmd userName: $appcmdUser"

        if ($appcmdOutput -match "SpecificUser" -and $appcmdUser -match "BlackTeam") {
            Write-OK "HelpdeskAppPool identity is correct (SpecificUser / BlackTeam)"
        } else {
            Write-WARN "HelpdeskAppPool identity is wrong: $appcmdOutput / $appcmdUser"
            Write-FIX "Setting via appcmd..."
            $helpdeskIdentity = "$DomainNB\BlackTeam_SQLBot"
            $helpdeskPassword = "B!ackT3am_Sc0reb0t_2025#"
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" stop apppool "HelpdeskAppPool" 2>&1 | Out-Null
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set apppool "HelpdeskAppPool" /processModel.identityType:SpecificUser /processModel.userName:$helpdeskIdentity /processModel.password:$helpdeskPassword 2>&1
            & "$env:SystemRoot\System32\inetsrv\appcmd.exe" start apppool "HelpdeskAppPool" 2>&1 | Out-Null

            # Verify
            $newType = & "$env:SystemRoot\System32\inetsrv\appcmd.exe" list apppool "HelpdeskAppPool" /text:processModel.identityType 2>&1
            Write-INFO "After fix: identityType = $newType"
        }
    } else {
        Write-WARN "HelpdeskAppPool doesn't exist yet"
    }
} catch {
    Write-FAIL "IIS check failed: $_"
}

# HTTP smoke test
Write-INFO ""
Write-INFO "HTTP smoke test:"
try {
    $resp = Invoke-WebRequest -Uri "http://localhost/apps/helpdesk/api/status.aspx" -UseDefaultCredentials -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
    Write-OK "Helpdesk status.aspx: HTTP $($resp.StatusCode) - $($resp.Content.Substring(0, [Math]::Min(200, $resp.Content.Length)))"
} catch {
    Write-FAIL "Helpdesk status.aspx: $($_.Exception.Message)"
}

try {
    $resp2 = Invoke-WebRequest -Uri "http://localhost/apps/orders/api/orders.aspx" -UseDefaultCredentials -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
    Write-OK "Orders orders.aspx: HTTP $($resp2.StatusCode) ($($resp2.Content.Length) bytes)"
} catch {
    Write-FAIL "Orders orders.aspx: $($_.Exception.Message)"
}

# =====================================================================
Write-Section "SUMMARY"
# =====================================================================

$agentFinal = (Get-Service $agentSvcName -ErrorAction SilentlyContinue).Status
Write-Host ""
if ($agentFinal -eq 'Running') {
    Write-OK "SQL Agent: RUNNING"
} else {
    Write-FAIL "SQL Agent: $agentFinal"
}
Write-Host ""
Write-INFO "Paste this entire output so we can see which hypothesis worked."
Write-Host ""
