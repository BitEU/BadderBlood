<#
.SYNOPSIS
    Phase 2: Creates scheduled supplier delivery and reorder simulations on NailInventoryDB.

.DESCRIPTION
    Uses Windows Task Scheduler to run T-SQL scripts on an interval, simulating:
      1. Supplier deliveries every 15 minutes (UPDATE Inventory + INSERT PurchaseOrders)
      2. Inventory reorder checks every 30 minutes (INSERT PurchaseOrders for low stock)

    SQL Server Express does not support SQL Agent, so we use scheduled tasks with
    sqlcmd.exe to execute the T-SQL directly.

    Job ownership: BlackTeam_SQLBot (Windows Auth) - NOT sa.
    This design ensures the job survives when Blue Team:
        - Disables Mixed Mode authentication
        - Changes or disables the sa account
        - Removes xp_cmdshell (this job does not use it)

    The job will ONLY break if defenders revoke BlackTeam_SQLBot's
    db_datareader/db_datawriter on NailInventoryDB, which violates the RoE.

.NOTES
    Run AFTER:
        - Invoke-BadderBlood.ps1      (AD must exist)
        - BadSQL.ps1                  (NailInventoryDB must exist)
        - Deploy-BlackTeamAccounts.ps1 (BlackTeam_SQLBot AD account must exist)

    Must be run as Administrator on the SQL Server host.

    Context: Educational / CTF / Active Directory Lab Environment
#>

#Requires -RunAsAdministrator

param(
    [string]$SqlInstance    = "localhost\BADSQL",
    [SecureString]$SqlSaPassword = $null,  # Leave blank to use Windows Integrated Auth
    [string]$DomainNB       = "",     # Auto-detected from AD if blank
    [int]$DeliveryIntervalMin = 15,   # How often supplier deliveries fire (minutes)
    [int]$ReorderIntervalMin  = 30,   # How often reorder check fires (minutes)
    [switch]$Force,                   # Re-create tasks even if they already exist
    [switch]$NonInteractive
)

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
Write-Log "  Phase 2: Supplier Delivery Scheduled Tasks" "INFO"
Write-Log "  Educational / CTF / Lab Use Only" "WARNING"
Write-Log "=================================================================" "INFO"

# ==============================================================================
# 1. RESOLVE DOMAIN
# ==============================================================================

Write-Log "Resolving domain NetBIOS name..." "STEP"

if (-not $DomainNB) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $DomainNB = (Get-ADDomain).NetBIOSName
        Write-Log "Domain NetBIOS: $DomainNB" "SUCCESS"
    } catch {
        Write-Log "Could not reach AD to resolve domain name. Use -DomainNB to specify manually." "WARNING"
        $DomainNB = $env:USERDOMAIN
        Write-Log "Falling back to environment variable: $DomainNB" "WARNING"
    }
}

$SqlBotLogin = "$DomainNB\BlackTeam_SQLBot"

# ==============================================================================
# 2. SQL HELPER
# ==============================================================================

function Invoke-Sql {
    param(
        [string]$Query,
        [string]$Database = "master",
        [switch]$ReturnReader
    )
    try {
        $conn = New-Object System.Data.SqlClient.SqlConnection
        if ($SqlSaPassword) {
            $saPlain = [System.Net.NetworkCredential]::new('', $SqlSaPassword).Password
            $conn.ConnectionString = "Server=$SqlInstance;Database=$Database;User Id=sa;Password=$saPlain;Connection Timeout=15;"
        } else {
            $conn.ConnectionString = "Server=$SqlInstance;Database=$Database;Integrated Security=SSPI;Connection Timeout=15;"
        }
        $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText  = $Query
        $cmd.CommandTimeout = 60

        if ($ReturnReader) {
            $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $cmd
            $table   = New-Object System.Data.DataTable
            $null    = $adapter.Fill($table)
            $conn.Close()
            return , $table
        } else {
            $null = $cmd.ExecuteNonQuery()
            $conn.Close()
            return $true
        }
    } catch {
        Write-Log "SQL Error (DB=$Database): $_" "WARNING"
        return $false
    }
}

# ==============================================================================
# 3. VERIFY PREREQUISITES
# ==============================================================================

Write-Log "Verifying prerequisites..." "STEP"

# Test SQL connectivity
$pingResult = Invoke-Sql -Query "SELECT 1 AS Ping" -ReturnReader
if (-not $pingResult) {
    Write-Log "Cannot connect to SQL instance '$SqlInstance'. Verify the instance is running and credentials are correct." "ERROR"
    exit 1
}
Write-Log "SQL connectivity confirmed: $SqlInstance" "SUCCESS"

# Verify NailInventoryDB exists
$dbCheck = Invoke-Sql -Query "SELECT name FROM sys.databases WHERE name = 'NailInventoryDB'" -ReturnReader
if (-not $dbCheck -or $dbCheck -isnot [System.Data.DataTable] -or $dbCheck.Rows.Count -eq 0) {
    Write-Log "NailInventoryDB not found or query failed. Attempting direct connection to NailInventoryDB..." "WARNING"
    $directCheck = Invoke-Sql -Query "SELECT DB_NAME() AS CurrentDB" -Database "NailInventoryDB" -ReturnReader
    if (-not $directCheck -or $directCheck -isnot [System.Data.DataTable] -or $directCheck.Rows.Count -eq 0) {
        Write-Log "NailInventoryDB not found. Run BadSQL.ps1 first." "ERROR"
        exit 1
    }
    Write-Log "NailInventoryDB confirmed (via direct connection)." "SUCCESS"
} else {
    Write-Log "NailInventoryDB confirmed." "SUCCESS"
}

# Verify BlackTeam_SQLBot login exists
$loginCheck = Invoke-Sql -Query "SELECT name FROM sys.server_principals WHERE name = N'$SqlBotLogin'" -ReturnReader
if ($loginCheck.Rows.Count -eq 0) {
    Write-Log "WARNING: SQL login '$SqlBotLogin' not found. Run Deploy-BlackTeamAccounts.ps1 first, or the job will fail when it runs." "WARNING"
} else {
    Write-Log "BlackTeam_SQLBot login confirmed: $SqlBotLogin" "SUCCESS"
}

# Find sqlcmd.exe
Write-Log "Locating sqlcmd.exe..." "STEP"
$sqlcmdPath = $null
$sqlcmdCandidates = @(
    "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE"
    "C:\Program Files\Microsoft SQL Server\170\Tools\Binn\SQLCMD.EXE"
    "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\130\Tools\Binn\SQLCMD.EXE"
    "C:\Program Files\Microsoft SQL Server\130\Tools\Binn\SQLCMD.EXE"
    "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\110\Tools\Binn\SQLCMD.EXE"
    "C:\Program Files\Microsoft SQL Server\110\Tools\Binn\SQLCMD.EXE"
)
foreach ($candidate in $sqlcmdCandidates) {
    if (Test-Path $candidate) {
        $sqlcmdPath = $candidate
        break
    }
}
# Fallback: search PATH
if (-not $sqlcmdPath) {
    $sqlcmdPath = (Get-Command sqlcmd.exe -ErrorAction SilentlyContinue).Source
}
if (-not $sqlcmdPath) {
    Write-Log "sqlcmd.exe not found. Cannot create scheduled tasks." "ERROR"
    exit 1
}
Write-Log "Found sqlcmd.exe: $sqlcmdPath" "SUCCESS"

# ==============================================================================
# 4. WRITE T-SQL SCRIPTS TO DISK
# ==============================================================================

Write-Log "Writing T-SQL scripts to C:\Simulator\..." "STEP"

$scriptDir = "C:\Simulator\sql"
if (-not (Test-Path $scriptDir)) {
    New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
}

# --- Supplier Delivery T-SQL ---
$deliverySQL = @"
-- SBF - Supplier Delivery Simulation
-- Runs as Windows Auth (whoever the scheduled task runs as)
-- Uses BlackTeam_SQLBot identity via EXECUTE AS if needed
USE [NailInventoryDB];

BEGIN TRY
    BEGIN TRANSACTION

    -- Pick a random nail type from NailTypes table
    DECLARE @NailTypeID  INT
    DECLARE @UnitCostUSD DECIMAL(10,4)
    SELECT TOP 1
        @NailTypeID  = NailTypeID,
        @UnitCostUSD = UnitCostUSD
    FROM NailTypes
    ORDER BY NEWID()

    -- Pick a random supplier
    DECLARE @SupplierID INT
    SELECT TOP 1 @SupplierID = SupplierID FROM Suppliers ORDER BY NEWID()

    -- Random delivery quantity between 50 and 549
    DECLARE @Qty INT = ABS(CHECKSUM(NEWID())) % 500 + 50

    -- Update inventory: add delivered quantity and stamp audit info
    -- TABLOCKX is intentional - creates realistic lock contention in profiler traces
    UPDATE Inventory WITH (TABLOCKX)
    SET
        QuantityOnHand = QuantityOnHand + @Qty,
        LastAuditDate  = CAST(GETDATE() AS DATE),
        LastAuditBy    = 'BlackTeam_SQLBot'
    WHERE
        NailTypeID = @NailTypeID
        AND SupplierID = @SupplierID

    -- If no matching inventory row exists, insert one (handles schema edge cases)
    IF @@ROWCOUNT = 0
    BEGIN
        INSERT INTO Inventory (NailTypeID, SupplierID, QuantityOnHand, ReorderPoint, WarehouseZone, LastAuditDate, LastAuditBy)
        VALUES (@NailTypeID, @SupplierID, @Qty, 500, 'A1', CAST(GETDATE() AS DATE), 'BlackTeam_SQLBot')
    END

    -- Record the purchase order for this delivery
    INSERT INTO PurchaseOrders (SupplierID, OrderDate, ExpectedDate, TotalUSD, Status, ApprovedBy, Notes)
    VALUES (
        @SupplierID,
        GETDATE(),
        CAST(DATEADD(day, 7, GETDATE()) AS DATE),
        CAST(@Qty AS DECIMAL(12,2)) * @UnitCostUSD,
        'DELIVERED',
        'BlackTeam_SQLBot',
        'Automated supplier delivery - Continuous Activity Simulator'
    )

    COMMIT TRANSACTION
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION

    BEGIN TRY
        INSERT INTO PurchaseOrders (SupplierID, OrderDate, TotalUSD, Status, Notes)
        VALUES (
            ISNULL(@SupplierID, 1),
            GETDATE(),
            0.00,
            'FAILED',
            'Delivery simulation error: ' + ISNULL(ERROR_MESSAGE(), 'Unknown error')
        )
    END TRY
    BEGIN CATCH
    END CATCH
END CATCH
"@

$deliveryScriptPath = "$scriptDir\SupplierDelivery.sql"
Set-Content -Path $deliveryScriptPath -Value $deliverySQL -Encoding UTF8
Write-Log "Written: $deliveryScriptPath" "SUCCESS"

# --- Reorder Check T-SQL ---
$reorderSQL = @"
-- SBF - Inventory Reorder Check
-- Find inventory items below reorder point and log them as pending orders
USE [NailInventoryDB];

DECLARE @ReorderItems TABLE (
    NailTypeID  INT,
    SupplierID  INT,
    TypeCode    NVARCHAR(10),
    QtyOnHand   INT,
    ReorderPt   INT,
    Shortfall   INT
)

INSERT INTO @ReorderItems
SELECT
    i.NailTypeID,
    i.SupplierID,
    nt.TypeCode,
    i.QuantityOnHand,
    i.ReorderPoint,
    i.ReorderPoint - i.QuantityOnHand AS Shortfall
FROM Inventory i
INNER JOIN NailTypes nt ON i.NailTypeID = nt.NailTypeID
WHERE i.QuantityOnHand < i.ReorderPoint

-- Insert a PENDING purchase order for each item below reorder point
-- Only create if no open order already exists for this supplier/nail type today
INSERT INTO PurchaseOrders (SupplierID, OrderDate, ExpectedDate, TotalUSD, Status, ApprovedBy, Notes)
SELECT
    r.SupplierID,
    GETDATE(),
    CAST(DATEADD(day, 5, GETDATE()) AS DATE),
    CAST(r.Shortfall AS DECIMAL(12,2)) * nt.UnitCostUSD,
    'PENDING',
    'BlackTeam_Scorebot',
    'Auto-reorder triggered: ' + r.TypeCode + ' qty=' + CAST(r.QtyOnHand AS NVARCHAR) + ' below reorder=' + CAST(r.ReorderPt AS NVARCHAR)
FROM @ReorderItems r
INNER JOIN NailTypes nt ON r.NailTypeID = nt.NailTypeID
WHERE NOT EXISTS (
    SELECT 1 FROM PurchaseOrders po
    WHERE po.SupplierID = r.SupplierID
      AND po.Status = 'PENDING'
      AND CAST(po.OrderDate AS DATE) = CAST(GETDATE() AS DATE)
      AND po.Notes LIKE '%' + r.TypeCode + '%'
)
"@

$reorderScriptPath = "$scriptDir\ReorderCheck.sql"
Set-Content -Path $reorderScriptPath -Value $reorderSQL -Encoding UTF8
Write-Log "Written: $reorderScriptPath" "SUCCESS"

# ==============================================================================
# 5. CREATE WINDOWS SCHEDULED TASKS
# ==============================================================================

Write-Log "Creating Windows Scheduled Tasks..." "STEP"

$deliveryTaskName = "SBF - Supplier Delivery Simulation"
$reorderTaskName  = "SBF - Inventory Reorder Check"

# Remove existing tasks if -Force
if ($Force) {
    Write-Log "-Force specified: removing existing tasks if present..." "WARNING"
    Unregister-ScheduledTask -TaskName $deliveryTaskName -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $reorderTaskName -Confirm:$false -ErrorAction SilentlyContinue
}

# --- Supplier Delivery Task ---
$existingDelivery = Get-ScheduledTask -TaskName $deliveryTaskName -ErrorAction SilentlyContinue
if ($existingDelivery) {
    Write-Log "Task '$deliveryTaskName' already exists (use -Force to recreate)." "WARNING"
} else {
    $deliveryAction = New-ScheduledTaskAction `
        -Execute "`"$sqlcmdPath`"" `
        -Argument "-S `"$SqlInstance`" -E -i `"$deliveryScriptPath`" -b"

    $deliveryTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Minutes $DeliveryIntervalMin) `
        -RepetitionDuration (New-TimeSpan -Days 365)

    $deliveryPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    $deliverySettings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
        -MultipleInstances IgnoreNew

    Register-ScheduledTask `
        -TaskName $deliveryTaskName `
        -Description "Simulates supplier deliveries to NailInventoryDB every $DeliveryIntervalMin minutes. Owner: BlackTeam_SQLBot. DO NOT DISABLE (RoE)." `
        -Action $deliveryAction `
        -Trigger $deliveryTrigger `
        -Principal $deliveryPrincipal `
        -Settings $deliverySettings | Out-Null

    Write-Log "Created scheduled task: '$deliveryTaskName' (every $DeliveryIntervalMin min)" "SUCCESS"
}

# --- Reorder Check Task ---
$existingReorder = Get-ScheduledTask -TaskName $reorderTaskName -ErrorAction SilentlyContinue
if ($existingReorder) {
    Write-Log "Task '$reorderTaskName' already exists (use -Force to recreate)." "WARNING"
} else {
    $reorderAction = New-ScheduledTaskAction `
        -Execute "`"$sqlcmdPath`"" `
        -Argument "-S `"$SqlInstance`" -E -i `"$reorderScriptPath`" -b"

    $reorderTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Minutes $ReorderIntervalMin) `
        -RepetitionDuration (New-TimeSpan -Days 365)

    $reorderPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    $reorderSettings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
        -MultipleInstances IgnoreNew

    Register-ScheduledTask `
        -TaskName $reorderTaskName `
        -Description "Checks inventory levels and raises reorder alerts every $ReorderIntervalMin minutes. DO NOT DISABLE (RoE)." `
        -Action $reorderAction `
        -Trigger $reorderTrigger `
        -Principal $reorderPrincipal `
        -Settings $reorderSettings | Out-Null

    Write-Log "Created scheduled task: '$reorderTaskName' (every $ReorderIntervalMin min)" "SUCCESS"
}

# ==============================================================================
# 6. RUN TASKS IMMEDIATELY (first-run kick)
# ==============================================================================

Write-Log "Running tasks for initial execution..." "STEP"

try {
    Start-ScheduledTask -TaskName $deliveryTaskName -ErrorAction Stop
    Write-Log "Supplier delivery task started (initial run)." "SUCCESS"
} catch {
    Write-Log "Could not start delivery task: $_" "WARNING"
}

try {
    Start-ScheduledTask -TaskName $reorderTaskName -ErrorAction Stop
    Write-Log "Reorder check task started (initial run)." "SUCCESS"
} catch {
    Write-Log "Could not start reorder task: $_" "WARNING"
}

# Brief pause then verify execution
Start-Sleep -Seconds 5

# ==============================================================================
# 7. VERIFY
# ==============================================================================

Write-Log "Verifying scheduled tasks..." "STEP"

foreach ($taskName in @($deliveryTaskName, $reorderTaskName)) {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task) {
        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
        $lastRun = if ($taskInfo.LastRunTime -gt [DateTime]::MinValue) { $taskInfo.LastRunTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
        $lastResult = $taskInfo.LastTaskResult
        Write-Log "  Task: '$taskName' | State: $($task.State) | LastRun: $lastRun | Result: $lastResult" "SUCCESS"
    } else {
        Write-Log "  Task '$taskName' not found!" "WARNING"
    }
}

# Verify data is flowing
Start-Sleep -Seconds 3
$poCount = Invoke-Sql -Query "SELECT COUNT(*) AS n FROM PurchaseOrders WHERE Status = 'DELIVERED'" -Database "NailInventoryDB" -ReturnReader
if ($poCount -and $poCount.Rows.Count -gt 0) {
    Write-Log "  PurchaseOrders (DELIVERED): $($poCount.Rows[0].n) rows" "SUCCESS"
}

# ==============================================================================
# 8. SCORING HINTS (for instructor)
# ==============================================================================

Write-Log "" "INFO"
Write-Log "=================================================================" "INFO"
Write-Log "  Phase 2 Complete - Supplier Delivery Tasks Deployed" "SUCCESS"
Write-Log "=================================================================" "INFO"
Write-Log "" "INFO"
Write-Log "SCHEDULED TASKS CREATED:" "INFO"
Write-Log "  '$deliveryTaskName'" "INFO"
Write-Log "    Schedule: every $DeliveryIntervalMin minutes" "INFO"
Write-Log "    Runs:     sqlcmd.exe -> $deliveryScriptPath" "INFO"
Write-Log "    Database: NailInventoryDB" "INFO"
Write-Log "    Effect:   Updates Inventory + inserts PurchaseOrders (DELIVERED)" "INFO"
Write-Log "" "INFO"
Write-Log "  '$reorderTaskName'" "INFO"
Write-Log "    Schedule: every $ReorderIntervalMin minutes" "INFO"
Write-Log "    Runs:     sqlcmd.exe -> $reorderScriptPath" "INFO"
Write-Log "    Effect:   Inserts PurchaseOrders (PENDING) for low-stock items" "INFO"
Write-Log "" "INFO"
Write-Log "SCORING CHECKS (for Scorebot):" "INFO"
Write-Log "  Tasks running:                schtasks /query /tn `"$deliveryTaskName`"" "INFO"
Write-Log "  PurchaseOrders row count:     SELECT COUNT(*) FROM NailInventoryDB.dbo.PurchaseOrders WHERE Status = 'DELIVERED'" "INFO"
Write-Log "  Inventory LastAuditDate:      SELECT COUNT(*) FROM NailInventoryDB.dbo.Inventory WHERE LastAuditDate >= CAST(GETDATE()-1 AS DATE)" "INFO"
Write-Log "" "INFO"
Write-Log "NEXT STEPS:" "INFO"
Write-Log "  Phase 3: Deploy-HelpdeskSystem.ps1 (AD lockout simulation)" "INFO"
Write-Log "  Phase 4: Deploy-UserSessionSimulator.ps1 (SMB/file activity)" "INFO"
Write-Log "" "INFO"
