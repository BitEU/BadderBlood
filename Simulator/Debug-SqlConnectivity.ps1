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
Write-Section "3. SQL Server Agent Service (simout line 86: 'Could not start SQL Agent')"

$agentSvc = Get-Service -Name $agentSvcName -ErrorAction SilentlyContinue
if (-not $agentSvc) {
    Write-FAIL "SQL Agent service '$agentSvcName' NOT FOUND."
} else {
    Write-INFO "Agent status:     $($agentSvc.Status)"
    Write-INFO "Agent start type: $($agentSvc.StartType)"

    try {
        $wmiAgent = Get-WmiObject Win32_Service -Filter "Name='$agentSvcName'" -ErrorAction Stop
        Write-INFO "Agent logon as:   $($wmiAgent.StartName)"
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

    if ($agentSvc.Status -ne 'Running') {
        # Try to start it and capture the exact error
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
                    Write-WARN "  [$($ev.TimeCreated)] ID=$($ev.Id): $($ev.Message.Substring(0, [Math]::Min(300, $ev.Message.Length)))..."
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
                    Write-WARN "  [$($ev.TimeCreated)] ID=$($ev.Id) Source=$($ev.ProviderName): $($ev.Message.Substring(0, [Math]::Min(300, $ev.Message.Length)))..."
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
                Write-INFO "  Last 20 lines:"
                Get-Content $logPath.FullName -Tail 20 | ForEach-Object { Write-INFO "    $_" }
            }
        } else {
            Write-WARN "  SQLAGENT.OUT not found in standard locations."
        }

        # Also check SQL Server error log for Agent clues
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

$currentLogin = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-INFO "Current Windows login: $currentLogin"

$ping = Test-SqlQuery "SELECT SUSER_SNAME() AS [Login], IS_SRVROLEMEMBER('sysadmin') AS IsSA" -Label "Basic connectivity"
if ($ping) {
    Write-OK "Connected to $SqlInstance as $($ping.Rows[0].Login)"
    if ($ping.Rows[0].IsSA -eq 1) {
        Write-OK "Login has sysadmin role."
    } else {
        Write-WARN "Login does NOT have sysadmin. This may cause ITDeskDB/Agent permission issues."
    }
} else {
    Write-FAIL "Cannot connect to $SqlInstance."
}

# Database list
$dbs = Test-SqlQuery "SELECT name, state_desc FROM sys.databases ORDER BY name" -Label "Database list"
if ($dbs) {
    Write-INFO "Databases on $SqlInstance :"
    $expected = @('NailInventoryDB','ITDeskDB','BoxArchive2019','TimesheetLegacy','msdb')
    foreach ($row in $dbs.Rows) {
        $marker = if ($row.name -in $expected) { " <<<" } else { "" }
        Write-INFO "  $($row.name) ($($row.state_desc))$marker"
    }
}

# ITDeskDB direct test
Write-INFO ""
Write-INFO "Testing direct ITDeskDB connectivity (the Phase 3 failure point):"
$itTest = Test-SqlQuery "SELECT DB_NAME() AS DB, USER_NAME() AS DbUser, IS_MEMBER('db_owner') AS IsOwner" -Database "ITDeskDB" -Label "ITDeskDB direct connect"
if ($itTest) {
    Write-OK "Connected to ITDeskDB as $($itTest.Rows[0].DbUser) (db_owner=$($itTest.Rows[0].IsOwner))"
} else {
    Write-FAIL "Cannot connect to ITDeskDB."
    Write-FIX "Grant access: USE [ITDeskDB]; CREATE USER [$currentLogin] FOR LOGIN [$currentLogin]; ALTER ROLE db_owner ADD MEMBER [$currentLogin]"
}

# BlackTeam logins
Write-INFO ""
$logins = Test-SqlQuery "SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE name LIKE '%BlackTeam%' ORDER BY name" -Label "BlackTeam logins"
if ($logins -and $logins.Rows.Count -gt 0) {
    Write-INFO "BlackTeam SQL logins:"
    foreach ($row in $logins.Rows) {
        $status = if ($row.is_disabled) { "DISABLED" } else { "enabled" }
        Write-INFO "  $($row.name) ($($row.type_desc)) - $status"
    }
} else {
    Write-WARN "No BlackTeam SQL logins found."
}

# ============================================================================
# 5. SEED DATA SQL QUOTING  (simout lines 156-158)
# ============================================================================
Write-Section "5. Seed Data SQL Quoting (simout lines 156-158: 'Incorrect syntax near account')"

Write-INFO "Deploy-HelpdeskSystem.ps1 seed issues contain unescaped single quotes."
Write-INFO "These strings go into SQL VALUES('...') without escaping:"
Write-INFO ""

$seedIssues = @(
    "Account locked out after multiple failed login attempts. User cannot access email."
    "Locked out of domain account. Tried resetting password but still getting lockout."
    "Cannot log into workstation. Getting 'account locked' error message."
    "Password reset required but account is locked first."
    "User locked out - reported via phone. Needs immediate unlock."
    "Intermittent lockout issue for past 3 days. IT Director aware."
    "Account locked overnight. Possibly stale cached credentials on mobile device."
    "Lockout triggered by legacy application using old password."
    "Cannot access VPN - account appears locked."
    "Multiple failed auth attempts detected from this account (may be credential stuffing)."
    "Account locked after connecting to new workstation for the first time."
    "Locked out while travelling - remote unlock needed."
)

$foundQuotes = $false
foreach ($iss in $seedIssues) {
    if ($iss -match "'") {
        Write-FAIL "Contains unescaped single quote: $iss"
        $foundQuotes = $true
        # Show what the broken SQL looks like
        $brokenSql = "VALUES ('testuser', 'Test User', 'IT', '$iss', 'High', 'Automated', GETDATE())"
        Write-INFO "  Broken SQL: $brokenSql"
        $fixedIss = $iss.Replace("'","''")
        $fixedSql = "VALUES ('testuser', 'Test User', 'IT', '$fixedIss', 'High', 'Automated', GETDATE())"
        Write-FIX "  Fixed SQL:  $fixedSql"
    }
}
if (-not $foundQuotes) {
    Write-OK "No unescaped single quotes found in seed data."
}

Write-INFO ""
Write-FIX "Add this line after `$iss assignment (Deploy-HelpdeskSystem.ps1 ~line 438):"
Write-FIX '  $iss = $issueData.Issue.Replace("''","''''")    # escape single quotes for SQL'

# ============================================================================
# 6. CORPDATA / CORPSHARES  (simout line 45)
# ============================================================================
Write-Section "6. CorpData / CorpShares (simout line 45: 'CorpData path not found')"

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
# 7. IIS LOCKED SECTIONS  (simout lines 170-172)
# ============================================================================
Write-Section "7. IIS Authentication Sections (simout: 'Unlocked section' messages)"

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

    # Peek at applicationHost.config for overrideMode
    $appHostConfig = "$env:SystemRoot\System32\inetsrv\config\applicationHost.config"
    if (Test-Path $appHostConfig) {
        Write-INFO ""
        Write-INFO "applicationHost.config authentication section entries:"
        $matches = Select-String -Path $appHostConfig -Pattern 'windowsAuthentication|anonymousAuthentication' -SimpleMatch
        foreach ($m in $matches) {
            Write-INFO "  Line $($m.LineNumber): $($m.Line.Trim())"
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

# ============================================================================
# 8. HMAILSERVER COM / RELAY  (simout: 'null-valued expression' + CIDR overflow)
# ============================================================================
Write-Section "8. hMailServer COM API & Relay Ranges"

# 8A. COM object and Settings.IPRanges
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

            # The failing code: $hms.Settings.IPRanges
            Write-INFO ""
            Write-INFO "Diagnosing `$hms.Settings.IPRanges (line 325 of Deploy-MailServer.ps1):"
            $settings = $hms.Settings
            if ($null -eq $settings) {
                Write-FAIL "`$hms.Settings is NULL."
                Write-INFO "This causes 'You cannot call a method on a null-valued expression'"
                Write-INFO "when Add-HmsRelayRange tries `$hms.Settings.IPRanges"
                Write-FIX "The `$hms variable may have gone out of scope inside the function."
                Write-FIX "Add-HmsRelayRange is defined at line 318 but `$hms is a script-scoped"
                Write-FIX "variable. Inside the function, `$hms may not be accessible."
                Write-FIX "Fix: either pass `$hms as a parameter, or reference `$script:hms."
            } else {
                Write-OK "`$hms.Settings is accessible."
                Write-INFO "Settings type: $($settings.GetType().FullName)"

                $ipRanges = $settings.IPRanges
                if ($null -eq $ipRanges) {
                    Write-FAIL "`$hms.Settings.IPRanges is NULL."
                } else {
                    Write-OK "`$hms.Settings.IPRanges accessible. Count: $($ipRanges.Count)"
                    for ($i = 0; $i -lt $ipRanges.Count; $i++) {
                        $r = $ipRanges.Item($i)
                        Write-INFO "  '$($r.Name)': $($r.LowerIP) - $($r.UpperIP) (Relay=$($r.AllowRelay))"
                    }
                }
            }

            # Check domains
            Write-INFO ""
            Write-INFO "hMailServer domains:"
            $domains = $hms.Domains
            for ($i = 0; $i -lt $domains.Count; $i++) {
                $d = $domains.Item($i)
                Write-INFO "  $($d.Name) (Active=$($d.Active), Accounts=$($d.Accounts.Count))"
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
# 9. CIDR SUBNET PARSING  (simout: 'Cannot convert value "-256" to UInt32')
# ============================================================================
Write-Section "9. CIDR Subnet Parsing (LabSubnet='$LabSubnet')"

Write-INFO "Reproducing Deploy-MailServer.ps1 line 361 CIDR math..."

try {
    $cidrParts = $LabSubnet -split "/"
    $baseIP    = $cidrParts[0]
    $prefixLen = [int]$cidrParts[1]
    Write-INFO "Base IP: $baseIP  Prefix: /$prefixLen"

    $ipBytes = ([System.Net.IPAddress]::Parse($baseIP)).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt = [System.BitConverter]::ToUInt32($ipBytes, 0)
    Write-INFO "IP as UInt32: $ipInt (0x$($ipInt.ToString('X8')))"

    # ---- The broken line ----
    Write-INFO ""
    Write-INFO "Original code: `$mask = [uint32](0xFFFFFFFF -shl (32 - $prefixLen))"
    $shiftAmount = 32 - $prefixLen
    $shiftResult = 0xFFFFFFFF -shl $shiftAmount
    Write-INFO "  0xFFFFFFFF -shl $shiftAmount = $shiftResult"
    Write-INFO "  Type: $($shiftResult.GetType().Name)  (PowerShell promotes to Int64!)"

    try {
        $mask = [uint32]$shiftResult
        Write-OK "Cast to [uint32] succeeded: $mask"
    } catch {
        Write-FAIL "Cast to [uint32] FAILED: $_"
        Write-INFO "This is the 'Cannot convert value to System.UInt32' error."
    }

    # ---- The fix ----
    Write-INFO ""
    Write-INFO "Fixed approach: use [uint64] intermediate and mask to 32 bits"
    $mask64 = ([uint64]0xFFFFFFFF -shl $shiftAmount) -band [uint64]0xFFFFFFFF
    $maskFixed = [uint32]$mask64
    Write-OK "Fixed mask: $maskFixed (0x$($maskFixed.ToString('X8')))"

    $networkInt = $ipInt -band $maskFixed
    $hostBits   = 32 - $prefixLen
    $hostMask   = [uint32]((1 -shl $hostBits) - 1)
    $broadInt   = $networkInt -bor $hostMask

    $networkBytes = [System.BitConverter]::GetBytes([uint32]$networkInt)
    [Array]::Reverse($networkBytes)
    $broadBytes = [System.BitConverter]::GetBytes([uint32]$broadInt)
    [Array]::Reverse($broadBytes)

    $lowerIP = [System.Net.IPAddress]::new($networkBytes).ToString()
    $upperIP = [System.Net.IPAddress]::new($broadBytes).ToString()
    Write-OK "Computed range: $lowerIP - $upperIP"

    # ---- Also show the -bnot problem ----
    Write-INFO ""
    Write-INFO "Original broadcast calc: -bnot `$mask -band 0xFFFFFFFF"
    Write-INFO "  -bnot [uint32] returns Int64, which can go negative."
    $bnotResult = -bnot $maskFixed
    Write-INFO "  -bnot $maskFixed = $bnotResult (type=$($bnotResult.GetType().Name))"
    Write-INFO "  $bnotResult -band 0xFFFFFFFF = $($bnotResult -band 0xFFFFFFFF)"
    Write-FIX "Replace broadcast calc with: `$hostMask = [uint32]((1 -shl (32 - `$prefixLen)) - 1); `$broadInt = `$networkInt -bor `$hostMask"

} catch {
    Write-FAIL "CIDR test failed: $_"
}

# ============================================================================
# 10. SQL AGENT ERROR LOG (via T-SQL)
# ============================================================================
Write-Section "10. SQL Agent Error Log (via T-SQL)"

$agentLog = Test-SqlQuery -Query "EXEC msdb.dbo.sp_readerrorlog 0, 2, NULL, NULL, NULL, NULL, N'DESC'" -Label "Agent error log"
if ($agentLog -and $agentLog.Rows.Count -gt 0) {
    $count = [Math]::Min(15, $agentLog.Rows.Count)
    Write-INFO "Last $count Agent log entries:"
    for ($i = 0; $i -lt $count; $i++) {
        $row = $agentLog.Rows[$i]
        Write-INFO "  [$($row[0])] $($row[2])"
    }
} else {
    Write-WARN "No Agent log returned (Agent may never have started)."
}

# SQL Server log
$sqlLog = Test-SqlQuery -Query "EXEC sp_readerrorlog 0, 1, N'Agent'" -Label "SQL Server log (Agent)"
if ($sqlLog -and $sqlLog.Rows.Count -gt 0) {
    $count = [Math]::Min(10, $sqlLog.Rows.Count)
    Write-INFO ""
    Write-INFO "SQL Server log entries mentioning 'Agent':"
    for ($i = 0; $i -lt $count; $i++) {
        Write-INFO "  [$($sqlLog.Rows[$i][0])] $($sqlLog.Rows[$i][2])"
    }
}

# ============================================================================
# 11. SQL BROWSER & PORT INFO
# ============================================================================
Write-Section "11. SQL Browser & Port Info"

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
# SUMMARY & FIXES
# ============================================================================
Write-Section "SUMMARY OF ISSUES & FIXES"

Write-Host ""
Write-Host "  ISSUE 1: SQL Agent won't start (Phase 2, simout line 86)" -ForegroundColor White
Write-Host "    See sections 2, 3, 10 above." -ForegroundColor Gray
Write-Host "    Common causes: Agent service account lacks Log On As Service," -ForegroundColor Gray
Write-Host "    engine not running, or SQLAGENT.OUT shows a specific error." -ForegroundColor Gray
Write-Host ""
Write-Host "  ISSUE 2: 'Incorrect syntax near account' (Phase 3, simout lines 156-158)" -ForegroundColor White
Write-Host "    Seed issue strings have unescaped single quotes." -ForegroundColor Gray
Write-Host "    Fix: escape `$iss with .Replace(`"'`",`"''`") before SQL interpolation." -ForegroundColor Gray
Write-Host ""
Write-Host "  ISSUE 3: CorpData path not found (Phase 1, simout line 45)" -ForegroundColor White
Write-Host "    C:\CorpShares\CorpData doesn't exist. Run BadFS.ps1 first." -ForegroundColor Gray
Write-Host ""
Write-Host "  ISSUE 4: hMailServer relay 'null-valued expression' (Phase 6)" -ForegroundColor White
Write-Host "    `$hms.Settings.IPRanges is null inside Add-HmsRelayRange function." -ForegroundColor Gray
Write-Host "    The function can't see the script-scoped `$hms variable." -ForegroundColor Gray
Write-Host "    Fix: use `$script:hms or pass `$hms as a parameter." -ForegroundColor Gray
Write-Host ""
Write-Host "  ISSUE 5: LabSubnet CIDR parse overflow (Phase 6)" -ForegroundColor White
Write-Host "    PowerShell -shl promotes 0xFFFFFFFF to Int64, producing values" -ForegroundColor Gray
Write-Host "    that can't cast to UInt32. Also -bnot on UInt32 returns Int64." -ForegroundColor Gray
Write-Host "    Fix: use [uint64] intermediate: ([uint64]0xFFFFFFFF -shl N) -band 0xFFFFFFFF" -ForegroundColor Gray
Write-Host "    Fix: compute host mask as [uint32]((1 -shl hostBits) - 1)" -ForegroundColor Gray
Write-Host ""
Write-Host $divider -ForegroundColor DarkGray
Write-Host "  Copy this output and run the fixes in the relevant scripts." -ForegroundColor White
Write-Host $divider -ForegroundColor DarkGray
Write-Host ""
