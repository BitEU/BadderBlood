#Requires -RunAsAdministrator
<#
    Debug script for Phase 2/3/5 SQL connectivity failures.
    Run on the same machine as the orchestrator, as the same user.
#>

$SqlInstance = "localhost\BADSQL"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  SQL Connectivity Debug Report" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# --- 1. Environment ---
Write-Host "--- ENVIRONMENT ---" -ForegroundColor Yellow
Write-Host "  Hostname:       $env:COMPUTERNAME"
Write-Host "  Username:       $env:USERDOMAIN\$env:USERNAME"
Write-Host "  PowerShell:     $($PSVersionTable.PSVersion)"
Write-Host "  Is Admin:       $([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
Write-Host ""

# --- 2. SQL Server services ---
Write-Host "--- SQL SERVER SERVICES ---" -ForegroundColor Yellow
Get-Service -Name "*SQL*" | Format-Table Name, DisplayName, Status, StartType -AutoSize
Write-Host ""

# --- 3. SQL Server instance detection ---
Write-Host "--- SQL SERVER INSTANCES (Registry) ---" -ForegroundColor Yellow
try {
    $instances = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL" -ErrorAction Stop
    $instances.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
        Write-Host "  Instance: $($_.Name) -> $($_.Value)"
    }
} catch {
    Write-Host "  Could not read registry: $_" -ForegroundColor Red
}
Write-Host ""

# --- 4. Try multiple connection strings ---
Write-Host "--- CONNECTION TESTS ---" -ForegroundColor Yellow

$tests = @(
    @{ Label = "SSPI to master on localhost\BADSQL";  ConnStr = "Server=localhost\BADSQL;Database=master;Integrated Security=SSPI;Connection Timeout=10;" }
    @{ Label = "SSPI to master on (local)\BADSQL";    ConnStr = "Server=(local)\BADSQL;Database=master;Integrated Security=SSPI;Connection Timeout=10;" }
    @{ Label = "SSPI to master on .\BADSQL";          ConnStr = "Server=.\BADSQL;Database=master;Integrated Security=SSPI;Connection Timeout=10;" }
    @{ Label = "SSPI to master on 127.0.0.1\BADSQL";  ConnStr = "Server=127.0.0.1\BADSQL;Database=master;Integrated Security=SSPI;Connection Timeout=10;" }
    @{ Label = "SSPI to master on localhost (default)"; ConnStr = "Server=localhost;Database=master;Integrated Security=SSPI;Connection Timeout=10;" }
    @{ Label = "SSPI to NailInventoryDB on localhost\BADSQL"; ConnStr = "Server=localhost\BADSQL;Database=NailInventoryDB;Integrated Security=SSPI;Connection Timeout=10;" }
    @{ Label = "SSPI to NailInventoryDB on .\BADSQL"; ConnStr = "Server=.\BADSQL;Database=NailInventoryDB;Integrated Security=SSPI;Connection Timeout=10;" }
)

$workingConnStr = $null

foreach ($t in $tests) {
    Write-Host "`n  TEST: $($t.Label)" -ForegroundColor White
    Write-Host "  ConnStr: $($t.ConnStr)" -ForegroundColor DarkGray
    try {
        $conn = New-Object System.Data.SqlClient.SqlConnection $t.ConnStr
        $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = "SELECT @@SERVERNAME AS ServerName, @@VERSION AS Ver, DB_NAME() AS CurrentDB, SUSER_SNAME() AS LoginUser, SYSTEM_USER AS SystemUser"
        $reader = $cmd.ExecuteReader()
        if ($reader.Read()) {
            Write-Host "  [OK] ServerName:  $($reader['ServerName'])" -ForegroundColor Green
            Write-Host "       CurrentDB:   $($reader['CurrentDB'])"
            Write-Host "       LoginUser:   $($reader['LoginUser'])"
            Write-Host "       SystemUser:  $($reader['SystemUser'])"
            Write-Host "       Version:     $($reader['Ver'].ToString().Split("`n")[0].Trim())"
            if (-not $workingConnStr) { $workingConnStr = $t.ConnStr }
        }
        $reader.Close()
        $conn.Close()
    } catch {
        $errMsg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        Write-Host "  [FAIL] $errMsg" -ForegroundColor Red
    }
}

Write-Host ""

# --- 5. sys.databases visibility check ---
Write-Host "--- sys.databases VISIBILITY ---" -ForegroundColor Yellow

# Use whichever connection worked, or try the default
$checkConnStr = if ($workingConnStr) { $workingConnStr } else { "Server=localhost\BADSQL;Database=master;Integrated Security=SSPI;Connection Timeout=10;" }
# Force master for this check
$checkConnStr = $checkConnStr -replace 'Database=[^;]+', 'Database=master'

try {
    $conn = New-Object System.Data.SqlClient.SqlConnection $checkConnStr
    $conn.Open()

    # Check all databases visible
    $cmd = $conn.CreateCommand()
    $cmd.CommandText = "SELECT name, database_id, state_desc FROM sys.databases ORDER BY name"
    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $cmd
    $table = New-Object System.Data.DataTable
    $null = $adapter.Fill($table)

    Write-Host "  Databases visible in sys.databases ($($table.Rows.Count) total):"
    foreach ($row in $table.Rows) {
        $marker = if ($row.name -eq 'NailInventoryDB') { " <<<" } else { "" }
        Write-Host "    $($row.name) (id=$($row.database_id), state=$($row.state_desc))$marker"
    }

    # Specific check
    $cmd2 = $conn.CreateCommand()
    $cmd2.CommandText = "SELECT COUNT(*) FROM sys.databases WHERE name = 'NailInventoryDB'"
    $count = [int]$cmd2.ExecuteScalar()
    Write-Host "`n  SELECT COUNT(*) WHERE name='NailInventoryDB' = $count" -ForegroundColor $(if ($count -gt 0) { "Green" } else { "Red" })

    # Check permissions
    $cmd3 = $conn.CreateCommand()
    $cmd3.CommandText = "SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW ANY DATABASE') AS CanViewAnyDB"
    $canView = $cmd3.ExecuteScalar()
    Write-Host "  HAS VIEW ANY DATABASE permission: $canView"

    # Check current user roles
    $cmd4 = $conn.CreateCommand()
    $cmd4.CommandText = "SELECT IS_SRVROLEMEMBER('sysadmin') AS IsSysadmin, IS_SRVROLEMEMBER('securityadmin') AS IsSecAdmin"
    $r4 = $cmd4.ExecuteReader()
    if ($r4.Read()) {
        Write-Host "  IS_SRVROLEMEMBER('sysadmin'):      $($r4['IsSysadmin'])"
        Write-Host "  IS_SRVROLEMEMBER('securityadmin'):  $($r4['IsSecAdmin'])"
    }
    $r4.Close()

    $conn.Close()
} catch {
    $errMsg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
    Write-Host "  [FAIL] Could not query sys.databases: $errMsg" -ForegroundColor Red
}

Write-Host ""

# --- 6. Direct NailInventoryDB connection test ---
Write-Host "--- DIRECT NailInventoryDB CONNECTION ---" -ForegroundColor Yellow

$nailTests = @(
    "Server=localhost\BADSQL;Database=NailInventoryDB;Integrated Security=SSPI;Connection Timeout=10;"
    "Server=.\BADSQL;Database=NailInventoryDB;Integrated Security=SSPI;Connection Timeout=10;"
    "Server=(local)\BADSQL;Database=NailInventoryDB;Integrated Security=SSPI;Connection Timeout=10;"
)

foreach ($cs in $nailTests) {
    Write-Host "`n  ConnStr: $cs" -ForegroundColor DarkGray
    try {
        $conn = New-Object System.Data.SqlClient.SqlConnection $cs
        $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = "SELECT DB_NAME() AS DB, (SELECT COUNT(*) FROM sys.tables) AS TableCount"
        $r = $cmd.ExecuteReader()
        if ($r.Read()) {
            Write-Host "  [OK] DB=$($r['DB']), Tables=$($r['TableCount'])" -ForegroundColor Green
        }
        $r.Close()

        # Check for key tables
        $cmd2 = $conn.CreateCommand()
        $cmd2.CommandText = "SELECT name FROM sys.tables ORDER BY name"
        $r2 = $cmd2.ExecuteReader()
        Write-Host "  Tables found:"
        while ($r2.Read()) {
            Write-Host "    - $($r2['name'])"
        }
        $r2.Close()
        $conn.Close()
    } catch {
        $errMsg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        Write-Host "  [FAIL] $errMsg" -ForegroundColor Red
    }
}

Write-Host ""

# --- 7. Simulate EXACTLY what Invoke-Sql does ---
Write-Host "--- SIMULATING Phase 2 Invoke-Sql BEHAVIOR ---" -ForegroundColor Yellow
Write-Host "  (This replicates the exact code path that fails)`n"

function Test-InvokeSql {
    param([string]$Query, [string]$Database = "master", [switch]$ReturnReader)
    try {
        $conn = New-Object System.Data.SqlClient.SqlConnection
        # Exactly matching Phase 2's Invoke-Sql with no SqlSaPassword
        $conn.ConnectionString = "Server=$SqlInstance;Database=$Database;Integrated Security=SSPI;Connection Timeout=15;"
        Write-Host "    ConnectionString: $($conn.ConnectionString)" -ForegroundColor DarkGray
        $conn.Open()
        Write-Host "    Connection opened successfully" -ForegroundColor DarkGray
        $cmd = $conn.CreateCommand()
        $cmd.CommandText  = $Query
        $cmd.CommandTimeout = 60

        if ($ReturnReader) {
            $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $cmd
            $table   = New-Object System.Data.DataTable
            $rowsFilled = $adapter.Fill($table)
            $conn.Close()
            Write-Host "    Adapter.Fill returned: $rowsFilled rows" -ForegroundColor DarkGray
            Write-Host "    Table.Rows.Count:      $($table.Rows.Count)" -ForegroundColor DarkGray
            Write-Host "    Return type:           $($table.GetType().FullName)" -ForegroundColor DarkGray
            return $table
        } else {
            $null = $cmd.ExecuteNonQuery()
            $conn.Close()
            return $true
        }
    } catch {
        Write-Host "    EXCEPTION: $($_.Exception.Message)" -ForegroundColor Red
        if ($_.Exception.InnerException) {
            Write-Host "    INNER:     $($_.Exception.InnerException.Message)" -ForegroundColor Red
        }
        return $false
    }
}

Write-Host "  Step A: Ping (SELECT 1 AS Ping) - same as Phase 2 line 141" -ForegroundColor White
$pingResult = Test-InvokeSql -Query "SELECT 1 AS Ping" -ReturnReader
Write-Host "  Result type: $($pingResult.GetType().Name), truthy: $([bool]$pingResult)" -ForegroundColor $(if ($pingResult) { "Green" } else { "Red" })

Write-Host ""
Write-Host "  Step B: sys.databases check - same as Phase 2 line 149" -ForegroundColor White
$dbCheck = Test-InvokeSql -Query "SELECT name FROM sys.databases WHERE name = 'NailInventoryDB'" -ReturnReader
if ($dbCheck -is [System.Data.DataTable]) {
    Write-Host "  Rows.Count = $($dbCheck.Rows.Count)" -ForegroundColor $(if ($dbCheck.Rows.Count -gt 0) { "Green" } else { "Red" })
    if ($dbCheck.Rows.Count -gt 0) {
        Write-Host "  First row name = $($dbCheck.Rows[0].name)"
    }
} else {
    Write-Host "  Returned $dbCheck (not a DataTable!)" -ForegroundColor Red
}

# Test the condition exactly as the code does it
$condResult = (-not $dbCheck -or $dbCheck -isnot [System.Data.DataTable] -or $dbCheck.Rows.Count -eq 0)
Write-Host "  Phase 2 condition (-not dbCheck -or isnot DataTable -or Rows.Count -eq 0) = $condResult" -ForegroundColor $(if ($condResult) { "Red" } else { "Green" })
Write-Host "    -not dbCheck:           $(-not $dbCheck)"
Write-Host "    isnot DataTable:        $($dbCheck -isnot [System.Data.DataTable])"
if ($dbCheck -is [System.Data.DataTable]) {
    Write-Host "    Rows.Count -eq 0:       $($dbCheck.Rows.Count -eq 0)"
}

Write-Host ""
Write-Host "  Step C: Direct NailInventoryDB connection - same as Phase 2 fallback" -ForegroundColor White
$directCheck = Test-InvokeSql -Query "SELECT DB_NAME() AS CurrentDB" -Database "NailInventoryDB" -ReturnReader
if ($directCheck -is [System.Data.DataTable]) {
    Write-Host "  Rows.Count = $($directCheck.Rows.Count)" -ForegroundColor $(if ($directCheck.Rows.Count -gt 0) { "Green" } else { "Red" })
    if ($directCheck.Rows.Count -gt 0) {
        Write-Host "  CurrentDB = $($directCheck.Rows[0].CurrentDB)"
    }
} else {
    Write-Host "  Returned $directCheck (not a DataTable!)" -ForegroundColor Red
}

Write-Host ""

# --- 8. Check what the IIS apps use ---
Write-Host "--- IIS APP CONNECTION STRINGS ---" -ForegroundColor Yellow
$webConfigs = @(
    "C:\inetpub\SpringfieldBoxFactory\apps\inventory\web.config"
    "C:\inetpub\SpringfieldBoxFactory\web.config"
)
foreach ($wc in $webConfigs) {
    if (Test-Path $wc) {
        Write-Host "  $wc" -ForegroundColor White
        $content = Get-Content $wc -Raw
        # Extract connection strings
        $matches = [regex]::Matches($content, 'connectionString="([^"]+)"')
        foreach ($m in $matches) {
            Write-Host "    ConnStr: $($m.Groups[1].Value)"
        }
        # Also check for inline Server= in aspx
        $serverMatches = [regex]::Matches($content, 'Server=([^;]+);')
        foreach ($m in $serverMatches) {
            Write-Host "    Server ref: $($m.Groups[1].Value)"
        }
    } else {
        Write-Host "  $wc - NOT FOUND" -ForegroundColor DarkGray
    }
}

# Check ASPX files for connection strings
$aspxFiles = Get-ChildItem "C:\inetpub\SpringfieldBoxFactory\apps" -Recurse -Filter "*.aspx" -ErrorAction SilentlyContinue
foreach ($f in $aspxFiles) {
    $content = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
    if ($content -match 'Server=([^;]+);') {
        Write-Host "  $($f.FullName)" -ForegroundColor White
        Write-Host "    Server ref: $($Matches[1])"
    }
}

Write-Host ""

# --- 9. SQL Browser / Port info ---
Write-Host "--- SQL BROWSER & PORT INFO ---" -ForegroundColor Yellow
$browser = Get-Service -Name "SQLBrowser" -ErrorAction SilentlyContinue
if ($browser) {
    Write-Host "  SQL Browser service: $($browser.Status) ($($browser.StartType))"
} else {
    Write-Host "  SQL Browser service: NOT FOUND" -ForegroundColor Red
    Write-Host "  (Named instances require SQL Browser for dynamic port resolution)" -ForegroundColor Red
}

# Try to find the port from registry
try {
    $instanceName = "BADSQL"
    $regPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
    $internalName = (Get-ItemProperty $regPath -ErrorAction Stop).$instanceName
    if ($internalName) {
        $tcpPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$internalName\MSSQLServer\SuperSocketNetLib\Tcp\IPAll"
        if (Test-Path $tcpPath) {
            $tcpProps = Get-ItemProperty $tcpPath
            Write-Host "  TCP Dynamic Port: $($tcpProps.TcpDynamicPorts)"
            Write-Host "  TCP Static Port:  $($tcpProps.TcpPort)"
        }
    }
} catch {
    Write-Host "  Could not read TCP port from registry: $_" -ForegroundColor DarkGray
}

# Check listening ports
Write-Host "`n  SQL-related listening ports:"
try {
    $sqlProcesses = Get-Process -Name "sqlservr" -ErrorAction SilentlyContinue
    if ($sqlProcesses) {
        foreach ($p in $sqlProcesses) {
            Write-Host "    PID $($p.Id): $($p.ProcessName) - $($p.MainModule.FileName)" -ErrorAction SilentlyContinue
            netstat -ano | Select-String ":.*LISTENING" | Where-Object { $_ -match "\s$($p.Id)$" } | ForEach-Object {
                Write-Host "      $_"
            }
        }
    } else {
        Write-Host "    No sqlservr processes found!" -ForegroundColor Red
    }
} catch {
    Write-Host "    Error checking ports: $_" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Debug report complete." -ForegroundColor Cyan
Write-Host "  Copy/paste the full output above." -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan
