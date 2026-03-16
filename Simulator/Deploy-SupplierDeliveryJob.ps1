<#
.SYNOPSIS
    Phase 2: Creates the "SBF - Supplier Delivery Simulation" SQL Agent job on NailInventoryDB.

.DESCRIPTION
    Adds a SQL Server Agent job that simulates automated supplier deliveries every 15 minutes.
    The job runs a T-SQL transaction that:
        1. Picks a random nail type and supplier
        2. Updates Inventory.QuantityOnHand (simulates goods receipt)
        3. Inserts a corresponding PurchaseOrder record with status DELIVERED

    Job ownership: BlackTeam_SQLBot (Windows Auth) - NOT sa.
    This design ensures the job survives when Blue Team:
        - Disables Mixed Mode authentication
        - Changes or disables the sa account
        - Removes xp_cmdshell (this job does not use it)

    The job will ONLY break if defenders revoke BlackTeam_SQLBot's
    db_datareader/db_datawriter on NailInventoryDB, which violates the RoE.

    A second lightweight job "SBF - Inventory Reorder Check" runs every 30 minutes
    and raises alerts when QuantityOnHand < ReorderPoint. This provides realistic
    noise and additional scoring data for the Scorebot.

.NOTES
    Run AFTER:
        - Invoke-BadderBlood.ps1      (AD must exist)
        - BadSQL.ps1                  (NailInventoryDB, SQL Agent, BlackTeam_SQLBot login must exist)
        - Deploy-BlackTeamAccounts.ps1 (BlackTeam_SQLBot AD account must exist)

    Must be run on the SQL Server host (or with network connectivity to it) with
    sysadmin / msdb dbo permissions.

    Context: Educational / CTF / Active Directory Lab Environment
#>

#Requires -RunAsAdministrator

param(
    [string]$SqlInstance    = "localhost\BADSQL",
    [SecureString]$SqlSaPassword = $null,  # Leave blank to use Windows Integrated Auth
    [string]$DomainNB       = "",     # Auto-detected from AD if blank
    [int]$DeliveryIntervalMin = 15,   # How often supplier deliveries fire (minutes)
    [int]$ReorderIntervalMin  = 30,   # How often reorder check fires (minutes)
    [switch]$Force,                   # Re-create jobs even if they already exist
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
Write-Log "  Phase 2: Supplier Delivery SQL Agent Job" "INFO"
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
    # Fallback: try connecting to the database directly - if it works, the DB exists
    $directCheck = Invoke-Sql -Query "SELECT DB_NAME() AS CurrentDB" -Database "NailInventoryDB" -ReturnReader
    if (-not $directCheck -or $directCheck -isnot [System.Data.DataTable] -or $directCheck.Rows.Count -eq 0) {
        Write-Log "NailInventoryDB not found. Run BadSQL.ps1 first." "ERROR"
        exit 1
    }
    Write-Log "NailInventoryDB confirmed (via direct connection)." "SUCCESS"
} else {
    Write-Log "NailInventoryDB confirmed." "SUCCESS"
}

# Verify BlackTeam_SQLBot login exists (warn but don't fail - Deploy-BlackTeamAccounts may not have run yet)
$loginCheck = Invoke-Sql -Query "SELECT name FROM sys.server_principals WHERE name = N'$SqlBotLogin'" -ReturnReader
if ($loginCheck.Rows.Count -eq 0) {
    Write-Log "WARNING: SQL login '$SqlBotLogin' not found. Run Deploy-BlackTeamAccounts.ps1 first, or the job will fail when it runs." "WARNING"
} else {
    Write-Log "BlackTeam_SQLBot login confirmed: $SqlBotLogin" "SUCCESS"
}

# Verify SQL Agent service
$agentSvcName = if ($SqlInstance -like '*\*') { "SQLAGENT`$$($SqlInstance.Split('\')[1])" } else { "SQLSERVERAGENT" }
$sqlSvcName   = if ($SqlInstance -like '*\*') { "MSSQL`$$($SqlInstance.Split('\')[1])" } else { "MSSQLSERVER" }
$agentSvc = Get-Service -Name $agentSvcName -ErrorAction SilentlyContinue
$script:SqlAgentRunning = $false
if (-not $agentSvc) {
    Write-Log "SQL Agent service '$agentSvcName' not found. SQL Agent may use a different name on this instance." "WARNING"
} elseif ($agentSvc.Status -ne 'Running') {
    Write-Log "SQL Agent is not running. Starting it..." "WARNING"
    try {
        # Ensure the SQL Server engine itself is running first (Agent depends on it)
        $sqlSvc = Get-Service -Name $sqlSvcName -ErrorAction SilentlyContinue
        if ($sqlSvc -and $sqlSvc.Status -ne 'Running') {
            Write-Log "SQL Server engine '$sqlSvcName' is not running - starting it first..." "WARNING"
            Set-Service -Name $sqlSvcName -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name $sqlSvcName -ErrorAction Stop
            $sqlSvc.WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
            Write-Log "SQL Server engine started." "SUCCESS"
        }

        # Grant the Agent service account the required msdb roles.
        # SQL Agent running as NT AUTHORITY\NETWORKSERVICE maps to the machine account
        # (DOMAIN\MACHINENAME$) which needs SQLAgentOperatorRole on msdb to start.
        try {
            $wmiAgent = Get-WmiObject Win32_Service -Filter "Name='$agentSvcName'" -ErrorAction SilentlyContinue
            $agentLogon = if ($wmiAgent) { $wmiAgent.StartName } else { $null }
            Write-Log "SQL Agent service logon account: $agentLogon" "INFO"

            # Determine the SQL login name for the Agent service account
            $agentSqlLogin = $agentLogon
            if ($agentLogon -match 'NT AUTHORITY\\(NETWORK\s*SERVICE|LOCAL\s*SERVICE|SYSTEM)') {
                # These map to DOMAIN\MACHINENAME$ inside SQL Server
                $agentSqlLogin = "$DomainNB\$env:COMPUTERNAME`$"
            }

            $grantAgentPerms = @"
-- Ensure the Agent service account has a SQL login
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'$agentSqlLogin')
    CREATE LOGIN [$agentSqlLogin] FROM WINDOWS;

-- Grant sysadmin role (required for SQL Agent to fully start and manage jobs)
IF IS_SRVROLEMEMBER('sysadmin', '$agentSqlLogin') = 0
    ALTER SERVER ROLE sysadmin ADD MEMBER [$agentSqlLogin];
"@
            if (Invoke-Sql -Query $grantAgentPerms) {
                Write-Log "Granted sysadmin to '$agentSqlLogin' (SQL Agent service account)." "SUCCESS"
            }
        } catch {
            Write-Log "Could not grant Agent service account permissions: $_ (non-fatal, will attempt start anyway)" "WARNING"
        }

        Set-Service -Name $agentSvcName -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name $agentSvcName -ErrorAction Stop
        # Wait for Agent to reach Running state (up to 30 seconds)
        $agentSvc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        $script:SqlAgentRunning = $true
        Write-Log "SQL Agent started." "SUCCESS"
    } catch {
        Write-Log "Could not start SQL Agent: $_ - SQL Agent jobs will be created but cannot run until the Agent service is started." "WARNING"
    }
} else {
    $script:SqlAgentRunning = $true
    Write-Log "SQL Agent is running." "SUCCESS"
}

# ==============================================================================
# 4. SUPPLIER DELIVERY JOB
# ==============================================================================

Write-Log "Creating SQL Agent job: SBF - Supplier Delivery Simulation..." "STEP"

$deliveryJobName = "SBF - Supplier Delivery Simulation"
$deliveryScheduleName = "SBF_SupplierDelivery_Every${DeliveryIntervalMin}Min"

# The core T-SQL for supplier delivery - runs as BlackTeam_SQLBot (Windows Auth)
# Uses TABLOCKX intentionally to create realistic lock contention events
$deliveryTSQL = @"
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

    -- Log failed delivery to PurchaseOrders as FAILED status
    -- This is realistic: suppliers occasionally fail; defenders can see this in the data
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
        -- Suppress secondary error to avoid job step failure masking the root cause
    END CATCH
END CATCH
"@

# Escape single quotes for T-SQL string embedding
$deliveryTSQLEscaped = $deliveryTSQL.Replace("'", "''")

# Remove existing job if -Force
if ($Force) {
    Write-Log "-Force specified: removing existing job if present..." "WARNING"
    $null = Invoke-Sql -Database "msdb" -Query @"
IF EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = N'$deliveryJobName')
BEGIN
    EXEC sp_delete_job @job_name = N'$deliveryJobName', @delete_unused_schedule = 1
END
"@
}

$createDeliveryJob = @"
USE [msdb];

IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = N'$deliveryJobName')
BEGIN
    -- Create the job owned by BlackTeam_SQLBot (Windows Auth login), NOT sa
    -- This ensures traffic survives Mixed Mode disablement and sa password changes
    EXEC sp_add_job
        @job_name         = N'$deliveryJobName',
        @enabled          = 1,
        @description      = N'Simulates supplier deliveries to NailInventoryDB every $DeliveryIntervalMin minutes. Owner: BlackTeam_SQLBot. DO NOT DISABLE (RoE).',
        @owner_login_name = N'$SqlBotLogin',
        @notify_level_eventlog = 2   -- Log failures to Windows Event Log

    -- Step 1: Execute the delivery transaction
    EXEC sp_add_jobstep
        @job_name          = N'$deliveryJobName',
        @step_name         = N'Execute Supplier Delivery',
        @subsystem         = N'TSQL',
        @command           = N'$deliveryTSQLEscaped',
        @database_name     = N'NailInventoryDB',
        @on_success_action = 1,   -- Quit with success
        @on_fail_action    = 2,   -- Quit with failure (captured in sysjobhistory)
        @retry_attempts    = 2,
        @retry_interval    = 1    -- Retry after 1 minute on transient failures

    -- Schedule: every N minutes, starting now
    IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysschedules WHERE name = N'$deliveryScheduleName')
    EXEC sp_add_schedule
        @schedule_name        = N'$deliveryScheduleName',
        @freq_type            = 4,      -- Daily (repeat via subday)
        @freq_interval        = 1,
        @freq_subday_type     = 4,      -- Minutes
        @freq_subday_interval = $DeliveryIntervalMin,
        @active_start_time    = 0       -- Midnight = run all day

    EXEC sp_attach_schedule
        @job_name      = N'$deliveryJobName',
        @schedule_name = N'$deliveryScheduleName'

    EXEC sp_add_jobserver
        @job_name    = N'$deliveryJobName',
        @server_name = N'(local)'

    PRINT 'Created job: $deliveryJobName'
END
ELSE
BEGIN
    PRINT 'Job already exists: $deliveryJobName (use -Force to recreate)'
END
"@

$result = Invoke-Sql -Database "msdb" -Query $createDeliveryJob
if ($result) {
    Write-Log "Supplier delivery job created: '$deliveryJobName'" "SUCCESS"
} else {
    Write-Log "Failed to create supplier delivery job. Check SQL error above." "ERROR"
    exit 1
}

# ==============================================================================
# 5. INVENTORY REORDER CHECK JOB
# ==============================================================================

Write-Log "Creating SQL Agent job: SBF - Inventory Reorder Check..." "STEP"

$reorderJobName = "SBF - Inventory Reorder Check"
$reorderScheduleName = "SBF_ReorderCheck_Every${ReorderIntervalMin}Min"

$reorderTSQL = @"
-- Find inventory items below reorder point and log them as pending orders
-- This is a read-heavy check that generates realistic SELECT traffic on NailInventoryDB
-- Results logged to PurchaseOrders as PENDING status (realistic: procurement queue)

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

$reorderTSQLEscaped = $reorderTSQL.Replace("'", "''")

if ($Force) {
    $null = Invoke-Sql -Database "msdb" -Query @"
IF EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = N'$reorderJobName')
    EXEC sp_delete_job @job_name = N'$reorderJobName', @delete_unused_schedule = 1
"@
}

$createReorderJob = @"
USE [msdb];

IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = N'$reorderJobName')
BEGIN
    EXEC sp_add_job
        @job_name         = N'$reorderJobName',
        @enabled          = 1,
        @description      = N'Checks inventory levels and raises reorder alerts every $ReorderIntervalMin minutes. Owner: BlackTeam_Scorebot. DO NOT DISABLE (RoE).',
        @owner_login_name = N'$SqlBotLogin',
        @notify_level_eventlog = 2

    EXEC sp_add_jobstep
        @job_name          = N'$reorderJobName',
        @step_name         = N'Check Reorder Levels',
        @subsystem         = N'TSQL',
        @command           = N'$reorderTSQLEscaped',
        @database_name     = N'NailInventoryDB',
        @on_success_action = 1,
        @on_fail_action    = 2,
        @retry_attempts    = 1,
        @retry_interval    = 2

    IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysschedules WHERE name = N'$reorderScheduleName')
    EXEC sp_add_schedule
        @schedule_name        = N'$reorderScheduleName',
        @freq_type            = 4,
        @freq_interval        = 1,
        @freq_subday_type     = 4,
        @freq_subday_interval = $ReorderIntervalMin,
        @active_start_time    = 0

    EXEC sp_attach_schedule
        @job_name      = N'$reorderJobName',
        @schedule_name = N'$reorderScheduleName'

    EXEC sp_add_jobserver
        @job_name    = N'$reorderJobName',
        @server_name = N'(local)'

    PRINT 'Created job: $reorderJobName'
END
ELSE
BEGIN
    PRINT 'Job already exists: $reorderJobName (use -Force to recreate)'
END
"@

$result = Invoke-Sql -Database "msdb" -Query $createReorderJob
if ($result) {
    Write-Log "Reorder check job created: '$reorderJobName'" "SUCCESS"
} else {
    Write-Log "Failed to create reorder check job - non-fatal, supplier delivery job still active." "WARNING"
}

# ==============================================================================
# 6. START JOBS IMMEDIATELY (first-run kick)
# ==============================================================================

Write-Log "Starting jobs for initial execution..." "STEP"

if (-not $script:SqlAgentRunning) {
    Write-Log "SQL Agent is not running - skipping initial job start. Jobs will execute on schedule once SQL Agent is started." "WARNING"
} else {
    $startDelivery = @"
USE [msdb];
EXEC sp_start_job @job_name = N'$deliveryJobName'
"@

    $startReorder = @"
USE [msdb];
EXEC sp_start_job @job_name = N'$reorderJobName'
"@

    Start-Sleep -Seconds 2  # Brief pause to ensure job registration completes

    if (Invoke-Sql -Database "msdb" -Query $startDelivery) {
        Write-Log "Supplier delivery job started (initial run)." "SUCCESS"
    }
    if (Invoke-Sql -Database "msdb" -Query $startReorder) {
        Write-Log "Reorder check job started (initial run)." "SUCCESS"
    }
}

# ==============================================================================
# 7. VERIFY JOBS
# ==============================================================================

Write-Log "Verifying job creation..." "STEP"

$jobVerify = Invoke-Sql -ReturnReader -Database "msdb" -Query @"
SELECT
    j.name          AS JobName,
    j.enabled       AS Enabled,
    j.owner_sid,
    SUSER_SNAME(j.owner_sid) AS Owner,
    ss.freq_subday_interval  AS IntervalMin,
    ss.schedule_id
FROM msdb.dbo.sysjobs j
LEFT JOIN msdb.dbo.sysjobschedules sjs ON j.job_id = sjs.job_id
LEFT JOIN msdb.dbo.sysschedules    ss  ON sjs.schedule_id = ss.schedule_id
WHERE j.name IN (N'$deliveryJobName', N'$reorderJobName')
ORDER BY j.name
"@

if ($jobVerify -and $jobVerify.Rows.Count -gt 0) {
    foreach ($row in $jobVerify.Rows) {
        Write-Log "  Job: '$($row.JobName)' | Enabled: $($row.Enabled) | Owner: $($row.Owner) | Interval: $($row.IntervalMin) min" "SUCCESS"
    }
} else {
    Write-Log "Could not verify jobs via sysjobs query." "WARNING"
}

# ==============================================================================
# 8. SCORING HINTS (for instructor)
# ==============================================================================

Write-Log "" "INFO"
Write-Log "=================================================================" "INFO"
Write-Log "  Phase 2 Complete - Supplier Delivery Jobs Deployed" "SUCCESS"
Write-Log "=================================================================" "INFO"
Write-Log "" "INFO"
Write-Log "JOBS CREATED:" "INFO"
Write-Log "  '$deliveryJobName'" "INFO"
Write-Log "    Schedule: every $DeliveryIntervalMin minutes" "INFO"
Write-Log "    Owner:    $SqlBotLogin" "INFO"
Write-Log "    Database: NailInventoryDB" "INFO"
Write-Log "    Effect:   Updates Inventory + inserts PurchaseOrders (DELIVERED)" "INFO"
Write-Log "" "INFO"
Write-Log "  '$reorderJobName'" "INFO"
Write-Log "    Schedule: every $ReorderIntervalMin minutes" "INFO"
Write-Log "    Effect:   Inserts PurchaseOrders (PENDING) for low-stock items" "INFO"
Write-Log "" "INFO"
Write-Log "SCORING CHECKS (for Scorebot):" "INFO"
Write-Log "  SQL Agent running:              SELECT status FROM sys.dm_server_services WHERE servicename LIKE '%Agent%'" "INFO"
Write-Log "  Jobs enabled:                   SELECT enabled FROM msdb.dbo.sysjobs WHERE name = '$deliveryJobName'" "INFO"
Write-Log "  Last run success (< 30 min):    SELECT TOP 1 run_status, run_date, run_time FROM msdb.dbo.sysjobhistory WHERE ..." "INFO"
Write-Log "  PurchaseOrders row count:       SELECT COUNT(*) FROM NailInventoryDB.dbo.PurchaseOrders WHERE Status = 'DELIVERED'" "INFO"
Write-Log "  Inventory LastAuditDate recent: SELECT COUNT(*) FROM NailInventoryDB.dbo.Inventory WHERE LastAuditDate >= CAST(GETDATE()-1 AS DATE)" "INFO"
Write-Log "" "INFO"
Write-Log "NEXT STEPS:" "INFO"
Write-Log "  Phase 3: Deploy-HelpdeskSimulator.ps1 (AD lockout simulation)" "INFO"
Write-Log "  Phase 4: Deploy-UserSessionSimulator.ps1 (SMB/file activity)" "INFO"
Write-Log "" "INFO"
