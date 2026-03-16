<#
.SYNOPSIS
    Phase 3: Deploys the Springfield Box Factory helpdesk system.

.DESCRIPTION
    This script sets up the full Level-1 helpdesk simulation infrastructure:

    1. ITDeskDB — New SQL database with Tickets and TicketHistory tables
       (+ BlackTeam_SQLBot grants for scoring)

    2. IIS helpdesk app — Deploys /apps/helpdesk/ with three ASPX endpoints:
         /apps/helpdesk/api/submit  — accepts POST from Invoke-LockoutSimulator.ps1
         /apps/helpdesk/api/status  — returns open ticket count (for scoring)
         /apps/helpdesk/index.html  — Blue Team ticket management UI

    3. Wires up the ASPX app pool as a Windows Auth identity
       (survives when Blue Team disables Basic Auth)

    The lockout generator and auto-resolve engine (Invoke-LockoutSimulator.ps1
    and Invoke-HelpdeskAutoResolve.ps1) run separately on the simulator VM.

.NOTES
    Run AFTER:
        - Invoke-BadderBlood.ps1
        - BadIIS.ps1     (SpringfieldBoxFactory IIS site must exist)
        - BadSQL.ps1     (SQL instance must be running)
        - Deploy-BlackTeamAccounts.ps1 (Phase 1)

    Must be run as local admin / Domain Admin on the IIS + SQL host.

    Context: Educational / CTF / Active Directory Lab Environment
#>

#Requires -RunAsAdministrator

param(
    [string]$SqlInstance    = "localhost\BADSQL",
    [SecureString]$SqlSaPassword = $null,
    [string]$IisBasePath    = "C:\inetpub\SpringfieldBoxFactory",
    [string]$DomainNB       = "",
    [switch]$Force,
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
Write-Log "  Phase 3: Helpdesk System Deployment" "INFO"
Write-Log "  Educational / CTF / Lab Use Only" "WARNING"
Write-Log "=================================================================" "INFO"

# ==============================================================================
# 1. RESOLVE DOMAIN
# ==============================================================================

Write-Log "Resolving domain..." "STEP"

if (-not $DomainNB) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $Domain   = Get-ADDomain
        $DomainNB = $Domain.NetBIOSName
        $DomainDNS = $Domain.DNSRoot
        Write-Log "Domain: $DomainDNS | NetBIOS: $DomainNB" "SUCCESS"
    } catch {
        Write-Log "Cannot reach AD — using environment fallback for domain name." "WARNING"
        $DomainNB  = $env:USERDOMAIN
        $DomainDNS = "$($env:USERDOMAIN).local"
    }
} else {
    $DomainDNS = "$DomainNB.local"
}

$SqlBotLogin  = "$DomainNB\BlackTeam_SQLBot"
$HelpdeskYear = Get-Date -Format "yyyy"

# ==============================================================================
# 2. SQL HELPER
# ==============================================================================

function Invoke-Sql {
    param([string]$Query, [string]$Database = "master", [switch]$ReturnReader)
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
        $cmd.CommandText   = $Query
        $cmd.CommandTimeout = 60
        if ($ReturnReader) {
            $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $cmd
            $table   = New-Object System.Data.DataTable
            $null    = $adapter.Fill($table)
            $conn.Close()
            return $table
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

# SQL connectivity
$ping = Invoke-Sql -Query "SELECT 1" -ReturnReader
if (-not $ping) {
    Write-Log "Cannot connect to $SqlInstance. Check the instance is running." "ERROR"
    exit 1
}
Write-Log "SQL connectivity confirmed." "SUCCESS"

# IIS site path
if (-not (Test-Path $IisBasePath)) {
    Write-Log "IIS base path '$IisBasePath' not found. Run BadIIS.ps1 first." "ERROR"
    exit 1
}
Write-Log "SpringfieldBoxFactory IIS path confirmed." "SUCCESS"

# ==============================================================================
# 4. INSTALL IIS ASP.NET 4.5 FEATURE
# ==============================================================================

Write-Log "Installing IIS ASP.NET 4.5 and Windows Auth features..." "STEP"

$iisFeatures = @(
    "Web-Asp-Net45",
    "Web-Net-Ext45",
    "Web-ISAPI-Ext",
    "Web-ISAPI-Filter",
    "Web-Windows-Auth"
)

foreach ($feat in $iisFeatures) {
    $installed = Get-WindowsFeature -Name $feat -ErrorAction SilentlyContinue
    if ($installed -and -not $installed.Installed) {
        Write-Log "Installing $feat..." "INFO"
        Install-WindowsFeature -Name $feat -ErrorAction SilentlyContinue | Out-Null
        Write-Log "$feat installed." "SUCCESS"
    } else {
        Write-Log "$feat already present." "INFO"
    }
}

Import-Module WebAdministration -ErrorAction SilentlyContinue

# ==============================================================================
# 5. CREATE ITDeskDB
# ==============================================================================

Write-Log "Creating ITDeskDB database..." "STEP"

$dbExists = Invoke-Sql -ReturnReader -Query "SELECT COUNT(*) AS n FROM sys.databases WHERE name = 'ITDeskDB'"
if ($dbExists.Rows[0].n -gt 0 -and -not $Force) {
    Write-Log "ITDeskDB already exists — skipping creation (-Force to recreate)." "WARNING"
} else {
    if ($Force) {
        Write-Log "-Force specified. Dropping and recreating ITDeskDB..." "WARNING"
        $null = Invoke-Sql "IF EXISTS (SELECT 1 FROM sys.databases WHERE name='ITDeskDB') DROP DATABASE [ITDeskDB]"
    }

    $createDB = @"
CREATE DATABASE [ITDeskDB];
"@
    if (Invoke-Sql -Query $createDB) {
        Write-Log "ITDeskDB created." "SUCCESS"
    } else {
        Write-Log "Failed to create ITDeskDB." "ERROR"
        exit 1
    }
}

# ==============================================================================
# 6. CREATE SCHEMA
# ==============================================================================

Write-Log "Creating Tickets and TicketHistory tables..." "STEP"

$schema = @"
IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'Tickets')
CREATE TABLE Tickets (
    TicketID     INT IDENTITY(1,1) PRIMARY KEY,
    TicketNumber AS ('HD-' + RIGHT('00000' + CAST(TicketID AS VARCHAR), 5)) PERSISTED,
    UserSam      NVARCHAR(50)  NOT NULL,
    DisplayName  NVARCHAR(100),
    Department   NVARCHAR(100),
    Issue        NVARCHAR(500) NOT NULL,
    Priority     NVARCHAR(20)  NOT NULL DEFAULT 'Medium',
    Status       NVARCHAR(20)  NOT NULL DEFAULT 'Open',
    AssignedTo   NVARCHAR(50),
    Source       NVARCHAR(50)  NOT NULL DEFAULT 'Automated',
    CreatedDate  DATETIME      NOT NULL DEFAULT GETDATE(),
    ResolvedDate DATETIME,
    ResolvedBy   NVARCHAR(50),
    Resolution   NVARCHAR(500),
    Notes        NVARCHAR(1000)
);

IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'TicketHistory')
CREATE TABLE TicketHistory (
    HistoryID    INT IDENTITY(1,1) PRIMARY KEY,
    TicketID     INT          NOT NULL REFERENCES Tickets(TicketID),
    Action       NVARCHAR(50) NOT NULL,
    PerformedBy  NVARCHAR(50) NOT NULL,
    Timestamp    DATETIME     NOT NULL DEFAULT GETDATE(),
    Details      NVARCHAR(500)
);
"@

if (Invoke-Sql -Database "ITDeskDB" -Query $schema) {
    Write-Log "Tables created." "SUCCESS"
}

# ==============================================================================
# 7. GRANT SQL PERMISSIONS TO BlackTeam_SQLBot
# ==============================================================================

Write-Log "Granting ITDeskDB permissions to BlackTeam_SQLBot..." "STEP"

$grantLogin = @"
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'$SqlBotLogin')
    CREATE LOGIN [$SqlBotLogin] FROM WINDOWS WITH DEFAULT_DATABASE=[ITDeskDB];
"@
$null = Invoke-Sql -Query $grantLogin

$grantDB = @"
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$SqlBotLogin')
    CREATE USER [$SqlBotLogin] FOR LOGIN [$SqlBotLogin];
ALTER ROLE db_datareader ADD MEMBER [$SqlBotLogin];
ALTER ROLE db_datawriter ADD MEMBER [$SqlBotLogin];
"@
if (Invoke-Sql -Database "ITDeskDB" -Query $grantDB) {
    Write-Log "db_datareader/db_datawriter granted on ITDeskDB." "SUCCESS"
}

# Also grant EXECUTE on any future stored procs
$grantExec = "GRANT EXECUTE TO [$SqlBotLogin]"
$null = Invoke-Sql -Database "ITDeskDB" -Query $grantExec

# ==============================================================================
# 8. CREATE STORED PROCEDURES (used by ASPX endpoint)
# ==============================================================================

Write-Log "Creating helpdesk stored procedures..." "STEP"

# usp_SubmitTicket — called by the ASPX API endpoint
$uspSubmit = @"
IF OBJECT_ID('dbo.usp_SubmitTicket', 'P') IS NOT NULL DROP PROCEDURE dbo.usp_SubmitTicket;
"@
$null = Invoke-Sql -Database "ITDeskDB" -Query $uspSubmit

$uspSubmitCreate = @"
CREATE PROCEDURE dbo.usp_SubmitTicket
    @UserSam     NVARCHAR(50),
    @DisplayName NVARCHAR(100) = NULL,
    @Department  NVARCHAR(100) = NULL,
    @Issue       NVARCHAR(500),
    @Priority    NVARCHAR(20)  = 'Medium',
    @Source      NVARCHAR(50)  = 'Automated'
AS
BEGIN
    SET NOCOUNT ON;
    INSERT INTO Tickets (UserSam, DisplayName, Department, Issue, Priority, Source)
    VALUES (@UserSam, @DisplayName, @Department, @Issue, @Priority, @Source);

    SELECT SCOPE_IDENTITY() AS TicketID,
           'HD-' + RIGHT('00000' + CAST(SCOPE_IDENTITY() AS VARCHAR), 5) AS TicketNumber;
END
"@
if (Invoke-Sql -Database "ITDeskDB" -Query $uspSubmitCreate) {
    Write-Log "usp_SubmitTicket created." "SUCCESS"
}

# usp_GetOpenTickets — polled by ASPX status endpoint and auto-resolve engine
$uspGetDrop = "IF OBJECT_ID('dbo.usp_GetOpenTickets','P') IS NOT NULL DROP PROCEDURE dbo.usp_GetOpenTickets;"
$null = Invoke-Sql -Database "ITDeskDB" -Query $uspGetDrop

$uspGetCreate = @"
CREATE PROCEDURE dbo.usp_GetOpenTickets
    @MaxRows INT = 100
AS
BEGIN
    SET NOCOUNT ON;
    SELECT TOP (@MaxRows)
        TicketID, TicketNumber, UserSam, DisplayName, Department,
        Issue, Priority, Status, AssignedTo, Source, CreatedDate, Notes
    FROM Tickets
    WHERE Status IN ('Open', 'Assigned')
    ORDER BY
        CASE Priority WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END,
        CreatedDate ASC;
END
"@
if (Invoke-Sql -Database "ITDeskDB" -Query $uspGetCreate) {
    Write-Log "usp_GetOpenTickets created." "SUCCESS"
}

# usp_ResolveTicket — called by auto-resolve engine
$uspResolveDrop = "IF OBJECT_ID('dbo.usp_ResolveTicket','P') IS NOT NULL DROP PROCEDURE dbo.usp_ResolveTicket;"
$null = Invoke-Sql -Database "ITDeskDB" -Query $uspResolveDrop

$uspResolveCreate = @"
CREATE PROCEDURE dbo.usp_ResolveTicket
    @TicketID    INT,
    @ResolvedBy  NVARCHAR(50),
    @Resolution  NVARCHAR(500),
    @NewStatus   NVARCHAR(20) = 'Resolved'   -- 'Resolved' or 'Assigned'
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE Tickets
    SET Status       = @NewStatus,
        ResolvedBy   = CASE WHEN @NewStatus = 'Resolved' THEN @ResolvedBy ELSE NULL END,
        AssignedTo   = CASE WHEN @NewStatus = 'Assigned' THEN @ResolvedBy ELSE AssignedTo END,
        ResolvedDate = CASE WHEN @NewStatus = 'Resolved' THEN GETDATE() ELSE NULL END,
        Resolution   = CASE WHEN @NewStatus = 'Resolved' THEN @Resolution ELSE NULL END
    WHERE TicketID = @TicketID;

    INSERT INTO TicketHistory (TicketID, Action, PerformedBy, Details)
    VALUES (@TicketID, @NewStatus, @ResolvedBy, @Resolution);

    SELECT @@ROWCOUNT AS RowsAffected;
END
"@
if (Invoke-Sql -Database "ITDeskDB" -Query $uspResolveCreate) {
    Write-Log "usp_ResolveTicket created." "SUCCESS"
}

# ==============================================================================
# 9. SEED SOME INITIAL TICKETS (makes the UI feel alive from minute one)
# ==============================================================================

Write-Log "Seeding initial ticket data..." "STEP"

# Pull a handful of real AD users to seed realistic tickets
$seedUsers = @()
try {
    $seedUsers = Get-ADUser -Filter { Enabled -eq $true } -Properties DisplayName,Department -ErrorAction Stop |
                 Where-Object { $_.SamAccountName -notmatch "Administrator|Guest|krbtgt|BlackTeam" } |
                 Get-Random -Count 12
} catch {
    Write-Log "AD query for seed users failed — skipping seed." "WARNING"
}

$seedIssues = @(
    @{Issue="Account locked out after multiple failed login attempts. User cannot access email."; Priority="High"}
    @{Issue="Locked out of domain account. Tried resetting password but still getting lockout."; Priority="High"}
    @{Issue="Cannot log into workstation. Getting 'account locked' error message."; Priority="High"}
    @{Issue="Password reset required but account is locked first."; Priority="Medium"}
    @{Issue="User locked out — reported via phone. Needs immediate unlock."; Priority="High"}
    @{Issue="Intermittent lockout issue for past 3 days. IT Director aware."; Priority="Medium"}
    @{Issue="Account locked overnight. Possibly stale cached credentials on mobile device."; Priority="Medium"}
    @{Issue="Lockout triggered by legacy application using old password."; Priority="Low"}
    @{Issue="Cannot access VPN — account appears locked."; Priority="High"}
    @{Issue="Multiple failed auth attempts detected from this account (may be credential stuffing)."; Priority="High"}
    @{Issue="Account locked after connecting to new workstation for the first time."; Priority="Low"}
    @{Issue="Locked out while travelling — remote unlock needed."; Priority="Medium"}
)

$insertedCount = 0
foreach ($u in $seedUsers) {
    $issueData = $seedIssues | Get-Random
    $sam  = $u.SamAccountName
    $name = if ($u.DisplayName) { $u.DisplayName.Replace("'","''") } else { $sam }
    $dept = if ($u.Department)  { $u.Department.Replace("'","''") }  else { "Unknown" }
    $iss  = $issueData.Issue
    $pri  = $issueData.Priority

    $seedSql = @"
INSERT INTO Tickets (UserSam, DisplayName, Department, Issue, Priority, Source, CreatedDate)
VALUES ('$sam', '$name', '$dept', '$iss', '$pri', 'Automated',
        DATEADD(minute, -ABS(CHECKSUM(NEWID())) % 120, GETDATE()));
"@
    if (Invoke-Sql -Database "ITDeskDB" -Query $seedSql) { $insertedCount++ }
}

# Mark ~75% of seed tickets as already resolved (history)
$seedResolve = @"
UPDATE Tickets
SET Status       = 'Resolved',
    ResolvedBy   = 'AutoResolve_Bot',
    ResolvedDate = DATEADD(minute, 15, CreatedDate),
    Resolution   = 'Account unlocked via Unlock-ADAccount. User notified.'
WHERE TicketID % 4 != 0;   -- leave 25% open

INSERT INTO TicketHistory (TicketID, Action, PerformedBy, Details)
SELECT TicketID, 'Resolved', 'AutoResolve_Bot', 'Automatic unlock — account restored'
FROM Tickets
WHERE Status = 'Resolved' AND ResolvedBy = 'AutoResolve_Bot';
"@
$null = Invoke-Sql -Database "ITDeskDB" -Query $seedResolve
Write-Log "Seeded $insertedCount tickets ($([int]($insertedCount * 0.75)) auto-resolved, $([int]($insertedCount * 0.25)) open)." "SUCCESS"

# ==============================================================================
# 10. DEPLOY IIS HELPDESK APPLICATION
# ==============================================================================

Write-Log "Deploying helpdesk IIS application to $IisBasePath\apps\helpdesk..." "STEP"

# Create directory structure
$helpdeskBase = "$IisBasePath\apps\helpdesk"
$helpdeskApi  = "$helpdeskBase\api"

foreach ($dir in @($helpdeskBase, $helpdeskApi)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Log "Created: $dir" "INFO"
    }
}

# ==============================================================================
# 10A. submit.aspx — POST endpoint for lockout simulation
# ==============================================================================

$submitAspx = @"
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    // Springfield Box Factory - Helpdesk Ticket Submission API
    // Accepts JSON POST: { "userSam":"...", "displayName":"...", "department":"...",
    //                      "issue":"...", "priority":"...", "source":"..." }
    // Returns JSON: { "success":true, "ticketId":123, "ticketNumber":"HD-00123" }
    //
    // NOTE: Connection string hardcoded here intentionally (mirrors BadSQL /apps/ pattern)
    // Connection: Server=$SqlInstance;Database=ITDeskDB;Integrated Security=SSPI;
    //
    private static readonly string ConnStr =
        @"Server=$SqlInstance;Database=ITDeskDB;Integrated Security=SSPI;Connection Timeout=10;";

    void Page_Load(object sender, EventArgs e)
    {
        Response.ContentType = "application/json";
        Response.AddHeader("Access-Control-Allow-Origin", "*");

        if (Request.HttpMethod == "OPTIONS") {
            Response.AddHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
            Response.AddHeader("Access-Control-Allow-Headers", "Content-Type");
            Response.End(); return;
        }

        if (Request.HttpMethod != "POST") {
            Response.StatusCode = 405;
            Response.Write("{\"error\":\"Method not allowed\"}");
            Response.End(); return;
        }

        try {
            string body = new StreamReader(Request.InputStream).ReadToEnd();
            string userSam     = ExtractJson(body, "userSam")     ?? "unknown";
            string displayName = ExtractJson(body, "displayName") ?? userSam;
            string department  = ExtractJson(body, "department")  ?? "";
            string issue       = ExtractJson(body, "issue")       ?? "No description provided";
            string priority    = ExtractJson(body, "priority")    ?? "Medium";
            string source      = ExtractJson(body, "source")      ?? "Automated";

            // Sanitise lengths
            if (userSam.Length     > 50)  userSam     = userSam.Substring(0, 50);
            if (displayName.Length > 100) displayName = displayName.Substring(0, 100);
            if (department.Length  > 100) department  = department.Substring(0, 100);
            if (issue.Length       > 500) issue       = issue.Substring(0, 500);
            if (priority.Length    > 20)  priority    = priority.Substring(0, 20);
            if (source.Length      > 50)  source      = source.Substring(0, 50);

            using (var conn = new SqlConnection(ConnStr)) {
                conn.Open();
                using (var cmd = new SqlCommand("dbo.usp_SubmitTicket", conn)) {
                    cmd.CommandType = System.Data.CommandType.StoredProcedure;
                    cmd.Parameters.AddWithValue("@UserSam",     userSam);
                    cmd.Parameters.AddWithValue("@DisplayName", displayName);
                    cmd.Parameters.AddWithValue("@Department",  department);
                    cmd.Parameters.AddWithValue("@Issue",       issue);
                    cmd.Parameters.AddWithValue("@Priority",    priority);
                    cmd.Parameters.AddWithValue("@Source",      source);
                    using (var reader = cmd.ExecuteReader()) {
                        if (reader.Read()) {
                            int    ticketId  = Convert.ToInt32(reader["TicketID"]);
                            string ticketNum = reader["TicketNumber"].ToString();
                            Response.Write("{\"success\":true,\"ticketId\":" + ticketId +
                                           ",\"ticketNumber\":\"" + ticketNum + "\"}");
                        } else {
                            Response.Write("{\"success\":false,\"error\":\"No rows returned\"}");
                        }
                    }
                }
            }
        } catch (Exception ex) {
            Response.StatusCode = 500;
            Response.Write("{\"success\":false,\"error\":\"" + ex.Message.Replace("\"","'") + "\"}");
        }
    }

    // Minimal JSON value extractor — avoids a JSON library dependency
    private string ExtractJson(string json, string key) {
        string search = "\"" + key + "\"";
        int idx = json.IndexOf(search, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;
        idx = json.IndexOf(':', idx) + 1;
        while (idx < json.Length && (json[idx] == ' ' || json[idx] == '\t')) idx++;
        if (idx >= json.Length) return null;
        if (json[idx] == '"') {
            idx++;
            int end = json.IndexOf('"', idx);
            return end < 0 ? null : json.Substring(idx, end - idx);
        }
        // Number or bool
        int endNum = idx;
        while (endNum < json.Length && json[endNum] != ',' && json[endNum] != '}') endNum++;
        return json.Substring(idx, endNum - idx).Trim();
    }
</script>
"@

$submitAspx | Out-File -FilePath "$helpdeskApi\submit.aspx" -Encoding UTF8 -Force
Write-Log "Deployed: $helpdeskApi\submit.aspx" "SUCCESS"

# ==============================================================================
# 10B. status.aspx — JSON status endpoint for Scorebot
# ==============================================================================

$statusAspx = @"
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<script runat="server">
    // Springfield Box Factory - Helpdesk Status API
    // GET /apps/helpdesk/api/status
    // Returns: { "openTickets":N, "assignedTickets":N, "resolvedToday":N, "totalTickets":N, "timestamp":"..." }
    private static readonly string ConnStr =
        @"Server=$SqlInstance;Database=ITDeskDB;Integrated Security=SSPI;Connection Timeout=10;";

    void Page_Load(object sender, EventArgs e)
    {
        Response.ContentType = "application/json";
        Response.AddHeader("Access-Control-Allow-Origin", "*");
        try {
            using (var conn = new SqlConnection(ConnStr)) {
                conn.Open();
                string q = @"
                    SELECT
                        SUM(CASE WHEN Status = 'Open'     THEN 1 ELSE 0 END) AS OpenTickets,
                        SUM(CASE WHEN Status = 'Assigned' THEN 1 ELSE 0 END) AS AssignedTickets,
                        SUM(CASE WHEN Status = 'Resolved'
                             AND CAST(ResolvedDate AS DATE) = CAST(GETDATE() AS DATE)
                             THEN 1 ELSE 0 END) AS ResolvedToday,
                        COUNT(*) AS TotalTickets
                    FROM Tickets";
                using (var cmd = new SqlCommand(q, conn))
                using (var r   = cmd.ExecuteReader()) {
                    if (r.Read()) {
                        Response.Write("{" +
                            "\"openTickets\":"    + r["OpenTickets"]    + "," +
                            "\"assignedTickets\":" + r["AssignedTickets"] + "," +
                            "\"resolvedToday\":"  + r["ResolvedToday"]  + "," +
                            "\"totalTickets\":"   + r["TotalTickets"]   + "," +
                            "\"timestamp\":\"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\"" +
                        "}");
                    }
                }
            }
        } catch (Exception ex) {
            Response.StatusCode = 500;
            Response.Write("{\"error\":\"" + ex.Message.Replace("\"","'") + "\"}");
        }
    }
</script>
"@

$statusAspx | Out-File -FilePath "$helpdeskApi\status.aspx" -Encoding UTF8 -Force
Write-Log "Deployed: $helpdeskApi\status.aspx" "SUCCESS"

# ==============================================================================
# 10C. index.html — Blue Team ticket management UI
# Uses the Springfield Box Factory brown/cream CSS theme from BadIIS
# ==============================================================================

$indexHtml = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SBF Helpdesk - IT Ticketing System</title>
    <link rel="stylesheet" href="/css/main.css">
    <style>
        .ticket-table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; }
        .ticket-table th { background: #5c4033; color: #fff; padding: 10px 12px; text-align: left; }
        .ticket-table td { padding: 9px 12px; border-bottom: 1px solid #e0d0b8; vertical-align: top; }
        .ticket-table tr:hover { background: #f5f0e0; }
        .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; }
        .badge-open     { background: #ffdddd; color: #8b0000; }
        .badge-assigned { background: #fff3cc; color: #7a6000; }
        .badge-resolved { background: #d4edda; color: #155724; }
        .badge-high     { background: #f8d7da; color: #721c24; }
        .badge-medium   { background: #fff3cd; color: #856404; }
        .badge-low      { background: #d1ecf1; color: #0c5460; }
        .resolve-btn    { padding: 4px 12px; background: #5c4033; color: #fff; border: none; cursor: pointer; border-radius: 3px; font-size: 12px; }
        .resolve-btn:hover { background: #8b5a2b; }
        .status-bar { background: #f4ede0; border: 1px solid #d2b48c; padding: 12px 20px; border-radius: 4px; margin-bottom: 20px; display: flex; gap: 30px; }
        .stat-block { text-align: center; }
        .stat-num   { font-size: 2em; font-weight: bold; color: #5c4033; }
        .stat-label { font-size: 12px; color: #666; }
        .filters    { margin-bottom: 15px; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
        .filters select, .filters input { padding: 6px 10px; border: 1px solid #8b5a2b; border-radius: 3px; }
        .filters button { padding: 6px 16px; background: #8b5a2b; color: #fff; border: none; cursor: pointer; border-radius: 3px; }
        .resolve-modal { display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.5); z-index:1000; }
        .resolve-modal .modal-box { background:#fff; max-width:480px; margin:100px auto; padding:30px; border-radius:6px; border:2px solid #8b5a2b; }
        .resolve-modal textarea { width:100%; height:80px; padding:8px; border:1px solid #ccc; margin:10px 0; box-sizing:border-box; }
        .alert-info { background: #d4e8f5; border-left: 5px solid #1a73a7; padding: 10px 15px; margin-bottom: 15px; }
    </style>
</head>
<body>
<header>
    <h1>Springfield Box Factory</h1>
    <p>IT Helpdesk &amp; Ticketing System — Internal Use Only</p>
</header>
<nav>
    <a href="/">Home</a>
    <a href="/portal/index.html">Employee Portal</a>
    <a href="/apps/">Applications</a>
    <a href="/apps/helpdesk/" style="color:#f5d48b;">Helpdesk</a>
</nav>

<div class="container">
    <h2>IT Helpdesk — Active Tickets</h2>

    <div class="alert-info">
        <strong>Note for IT Staff:</strong> Tickets marked <strong>Assigned</strong> require manual resolution.
        Run <code>Unlock-ADAccount -Identity &lt;UserSam&gt;</code> after verifying the request,
        then click <strong>Resolve</strong>. Auto-resolved tickets are handled by the monitoring service.
    </div>

    <div class="status-bar" id="statusBar">
        <div class="stat-block"><div class="stat-num" id="statOpen">—</div><div class="stat-label">Open</div></div>
        <div class="stat-block"><div class="stat-num" id="statAssigned">—</div><div class="stat-label">Assigned (Manual)</div></div>
        <div class="stat-block"><div class="stat-num" id="statResolved">—</div><div class="stat-label">Resolved Today</div></div>
        <div class="stat-block"><div class="stat-num" id="statTotal">—</div><div class="stat-label">Total</div></div>
        <div class="stat-block" style="margin-left:auto;">
            <button onclick="refreshAll()" style="padding:6px 14px;background:#5c4033;color:#fff;border:none;cursor:pointer;border-radius:3px;">Refresh</button>
        </div>
    </div>

    <div class="filters">
        <label>Status:
            <select id="filterStatus" onchange="loadTickets()">
                <option value="">All</option>
                <option value="Open" selected>Open</option>
                <option value="Assigned">Assigned</option>
                <option value="Resolved">Resolved</option>
            </select>
        </label>
        <label>Priority:
            <select id="filterPriority" onchange="loadTickets()">
                <option value="">All</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
            </select>
        </label>
        <label>Search: <input type="text" id="filterSearch" placeholder="user / issue..." oninput="loadTickets()"></label>
    </div>

    <table class="ticket-table" id="ticketTable">
        <thead>
            <tr>
                <th>Ticket #</th><th>User</th><th>Department</th>
                <th>Issue</th><th>Priority</th><th>Status</th>
                <th>Created</th><th>Action</th>
            </tr>
        </thead>
        <tbody id="ticketBody">
            <tr><td colspan="8" style="text-align:center;padding:30px;color:#999;">Loading tickets...</td></tr>
        </tbody>
    </table>
</div>

<!-- Resolve Modal -->
<div class="resolve-modal" id="resolveModal">
    <div class="modal-box">
        <h3 style="color:#5c4033;margin-top:0;">Resolve Ticket <span id="modalTicketNum"></span></h3>
        <p>User: <strong id="modalUser"></strong></p>
        <label>Resolution notes:<br>
            <textarea id="modalResolution" placeholder="e.g. Account unlocked. User advised to clear cached credentials on mobile device."></textarea>
        </label>
        <input type="hidden" id="modalTicketId">
        <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:10px;">
            <button onclick="closeModal()" style="padding:8px 18px;background:#ccc;border:none;cursor:pointer;border-radius:3px;">Cancel</button>
            <button onclick="submitResolve()" class="resolve-btn" style="padding:8px 18px;">Mark Resolved</button>
        </div>
    </div>
</div>

<footer>
    <p>Springfield Box Factory IT Helpdesk &copy; $HelpdeskYear &mdash; helpdesk@$DomainDNS</p>
    <p style="font-size:12px;color:#e6ca9c;">Ticket data stored in ITDeskDB on $SqlInstance</p>
</footer>

<script>
var allTickets = [];

function refreshAll() { loadStatus(); loadTickets(); }

function loadStatus() {
    fetch('/apps/helpdesk/api/status.aspx')
        .then(r => r.json())
        .then(d => {
            document.getElementById('statOpen').textContent     = d.openTickets     ?? '?';
            document.getElementById('statAssigned').textContent = d.assignedTickets ?? '?';
            document.getElementById('statResolved').textContent = d.resolvedToday   ?? '?';
            document.getElementById('statTotal').textContent    = d.totalTickets    ?? '?';
        })
        .catch(() => {});
}

function loadTickets() {
    fetch('/apps/helpdesk/api/tickets.aspx')
        .then(r => r.json())
        .then(data => {
            allTickets = data.tickets || [];
            renderTickets();
        })
        .catch(err => {
            document.getElementById('ticketBody').innerHTML =
                '<tr><td colspan="8" style="text-align:center;color:#999;padding:20px;">'+
                'Unable to load tickets. Ensure ITDeskDB is accessible.<br><small>' + err + '</small></td></tr>';
        });
}

function renderTickets() {
    var statusF   = document.getElementById('filterStatus').value.toLowerCase();
    var priorityF = document.getElementById('filterPriority').value.toLowerCase();
    var searchF   = document.getElementById('filterSearch').value.toLowerCase();

    var rows = allTickets.filter(t => {
        if (statusF   && t.status.toLowerCase()   !== statusF)   return false;
        if (priorityF && t.priority.toLowerCase()  !== priorityF) return false;
        if (searchF && !(t.userSam.toLowerCase().includes(searchF) ||
                         (t.displayName||'').toLowerCase().includes(searchF) ||
                         t.issue.toLowerCase().includes(searchF)))  return false;
        return true;
    });

    if (rows.length === 0) {
        document.getElementById('ticketBody').innerHTML =
            '<tr><td colspan="8" style="text-align:center;padding:20px;color:#999;">No tickets match filters.</td></tr>';
        return;
    }

    var html = '';
    rows.forEach(t => {
        var sBadge = '<span class="badge badge-' + t.status.toLowerCase() + '">' + esc(t.status) + '</span>';
        var pBadge = '<span class="badge badge-' + t.priority.toLowerCase() + '">' + esc(t.priority) + '</span>';
        var dt     = new Date(t.createdDate + 'Z');
        var dtStr  = dt.toLocaleDateString() + ' ' + dt.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
        var canResolve = (t.status === 'Open' || t.status === 'Assigned');
        var btn = canResolve
            ? '<button class="resolve-btn" onclick="openResolve(' + t.ticketId + ',\'' + esc(t.ticketNumber) + '\',\'' + esc(t.userSam) + '\')">Resolve</button>'
            : '<span style="color:#999;font-size:12px;">' + (t.resolvedBy || '—') + '</span>';
        html += '<tr>' +
            '<td><strong>' + esc(t.ticketNumber) + '</strong></td>' +
            '<td>' + esc(t.displayName || t.userSam) + '<br><small style="color:#888;">' + esc(t.userSam) + '</small></td>' +
            '<td style="font-size:12px;">' + esc(t.department || '—') + '</td>' +
            '<td style="max-width:280px;">' + esc(t.issue) + '</td>' +
            '<td>' + pBadge + '</td>' +
            '<td>' + sBadge + '</td>' +
            '<td style="font-size:12px;white-space:nowrap;">' + dtStr + '</td>' +
            '<td>' + btn + '</td>' +
            '</tr>';
    });
    document.getElementById('ticketBody').innerHTML = html;
}

function esc(s) {
    if (!s) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function openResolve(id, num, user) {
    document.getElementById('modalTicketId').value    = id;
    document.getElementById('modalTicketNum').textContent = num;
    document.getElementById('modalUser').textContent      = user;
    document.getElementById('modalResolution').value      = '';
    document.getElementById('resolveModal').style.display = 'block';
}

function closeModal() { document.getElementById('resolveModal').style.display = 'none'; }

function submitResolve() {
    var id  = document.getElementById('modalTicketId').value;
    var res = document.getElementById('modalResolution').value.trim() || 'Resolved by IT staff.';
    fetch('/apps/helpdesk/api/resolve.aspx', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ ticketId: parseInt(id), resolvedBy: 'BluTeam_ITStaff', resolution: res })
    })
    .then(r => r.json())
    .then(() => { closeModal(); refreshAll(); })
    .catch(err => alert('Error resolving ticket: ' + err));
}

// Auto-refresh every 30 seconds
setInterval(refreshAll, 30000);
refreshAll();
</script>
</body>
</html>
"@

$indexHtml | Out-File -FilePath "$helpdeskBase\index.html" -Encoding UTF8 -Force
Write-Log "Deployed: $helpdeskBase\index.html" "SUCCESS"

# ==============================================================================
# 10D. tickets.aspx — returns all tickets as JSON (for the UI)
# ==============================================================================

$ticketsAspx = @"
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<%@ Import Namespace="System.Text" %>
<script runat="server">
    private static readonly string ConnStr =
        @"Server=$SqlInstance;Database=ITDeskDB;Integrated Security=SSPI;Connection Timeout=10;";

    void Page_Load(object sender, EventArgs e)
    {
        Response.ContentType = "application/json";
        Response.AddHeader("Access-Control-Allow-Origin", "*");
        try {
            string status   = Request.QueryString["status"]   ?? "";
            string priority = Request.QueryString["priority"] ?? "";
            int    maxRows  = 200;
            int.TryParse(Request.QueryString["max"] ?? "200", out maxRows);

            var sb    = new StringBuilder();
            var where = new System.Collections.Generic.List<string>();
            if (!string.IsNullOrEmpty(status))   where.Add("Status = @status");
            if (!string.IsNullOrEmpty(priority)) where.Add("Priority = @priority");
            string whereClause = where.Count > 0 ? "WHERE " + string.Join(" AND ", where) : "";

            string q = @"SELECT TOP " + maxRows + @"
                TicketID, TicketNumber, UserSam, DisplayName, Department,
                Issue, Priority, Status, AssignedTo, Source,
                CONVERT(VARCHAR(19), CreatedDate, 126) AS CreatedDate,
                CONVERT(VARCHAR(19), ResolvedDate, 126) AS ResolvedDate,
                ResolvedBy, Resolution
            FROM Tickets " + whereClause + " ORDER BY CreatedDate DESC";

            using (var conn = new SqlConnection(ConnStr)) {
                conn.Open();
                using (var cmd = new SqlCommand(q, conn)) {
                    if (!string.IsNullOrEmpty(status))   cmd.Parameters.AddWithValue("@status",   status);
                    if (!string.IsNullOrEmpty(priority)) cmd.Parameters.AddWithValue("@priority", priority);
                    using (var r = cmd.ExecuteReader()) {
                        sb.Append("{\"tickets\":[");
                        bool first = true;
                        while (r.Read()) {
                            if (!first) sb.Append(",");
                            sb.Append("{");
                            sb.Append("\"ticketId\":"       + r["TicketID"]     + ",");
                            sb.Append("\"ticketNumber\":\""  + J(r["TicketNumber"]) + "\",");
                            sb.Append("\"userSam\":\""       + J(r["UserSam"])      + "\",");
                            sb.Append("\"displayName\":\""   + J(r["DisplayName"])  + "\",");
                            sb.Append("\"department\":\""    + J(r["Department"])   + "\",");
                            sb.Append("\"issue\":\""         + J(r["Issue"])        + "\",");
                            sb.Append("\"priority\":\""      + J(r["Priority"])     + "\",");
                            sb.Append("\"status\":\""        + J(r["Status"])       + "\",");
                            sb.Append("\"assignedTo\":\""    + J(r["AssignedTo"])   + "\",");
                            sb.Append("\"source\":\""        + J(r["Source"])       + "\",");
                            sb.Append("\"createdDate\":\""   + J(r["CreatedDate"])  + "\",");
                            sb.Append("\"resolvedDate\":\""  + J(r["ResolvedDate"]) + "\",");
                            sb.Append("\"resolvedBy\":\""    + J(r["ResolvedBy"])   + "\",");
                            sb.Append("\"resolution\":\""    + J(r["Resolution"])   + "\"");
                            sb.Append("}");
                            first = false;
                        }
                        sb.Append("]}");
                    }
                }
            }
            Response.Write(sb.ToString());
        } catch (Exception ex) {
            Response.StatusCode = 500;
            Response.Write("{\"error\":\"" + ex.Message.Replace("\"","'") + "\"}");
        }
    }

    private string J(object o) {
        if (o == null || o == DBNull.Value) return "";
        return o.ToString().Replace("\\","\\\\").Replace("\"","\\\"")
                           .Replace("\r","\\r").Replace("\n","\\n");
    }
</script>
"@

$ticketsAspx | Out-File -FilePath "$helpdeskApi\tickets.aspx" -Encoding UTF8 -Force
Write-Log "Deployed: $helpdeskApi\tickets.aspx" "SUCCESS"

# ==============================================================================
# 10E. resolve.aspx — POST endpoint for Blue Team manual resolution
# ==============================================================================

$resolveAspx = @"
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    private static readonly string ConnStr =
        @"Server=$SqlInstance;Database=ITDeskDB;Integrated Security=SSPI;Connection Timeout=10;";

    void Page_Load(object sender, EventArgs e)
    {
        Response.ContentType = "application/json";
        if (Request.HttpMethod != "POST") {
            Response.StatusCode = 405;
            Response.Write("{\"error\":\"POST only\"}");
            return;
        }
        try {
            string body       = new StreamReader(Request.InputStream).ReadToEnd();
            string ticketIdStr = ExtractJson(body, "ticketId")   ?? "0";
            string resolvedBy  = ExtractJson(body, "resolvedBy") ?? "BluTeam_ITStaff";
            string resolution  = ExtractJson(body, "resolution") ?? "Resolved by Blue Team.";
            string status      = ExtractJson(body, "status")     ?? "Resolved";
            int ticketId = int.Parse(ticketIdStr);

            using (var conn = new SqlConnection(ConnStr)) {
                conn.Open();
                using (var cmd = new SqlCommand("dbo.usp_ResolveTicket", conn)) {
                    cmd.CommandType = System.Data.CommandType.StoredProcedure;
                    cmd.Parameters.AddWithValue("@TicketID",   ticketId);
                    cmd.Parameters.AddWithValue("@ResolvedBy", resolvedBy.Length > 50 ? resolvedBy.Substring(0,50) : resolvedBy);
                    cmd.Parameters.AddWithValue("@Resolution", resolution.Length > 500 ? resolution.Substring(0,500) : resolution);
                    cmd.Parameters.AddWithValue("@NewStatus",  status);
                    using (var r = cmd.ExecuteReader()) {
                        if (r.Read()) {
                            Response.Write("{\"success\":true,\"rowsAffected\":" + r["RowsAffected"] + "}");
                        } else {
                            Response.Write("{\"success\":false}");
                        }
                    }
                }
            }
        } catch (Exception ex) {
            Response.StatusCode = 500;
            Response.Write("{\"success\":false,\"error\":\"" + ex.Message.Replace("\"","'") + "\"}");
        }
    }

    private string ExtractJson(string json, string key) {
        string search = "\"" + key + "\"";
        int idx = json.IndexOf(search, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;
        idx = json.IndexOf(':', idx) + 1;
        while (idx < json.Length && (json[idx] == ' ' || json[idx] == '\t')) idx++;
        if (idx >= json.Length) return null;
        if (json[idx] == '"') { idx++; int end = json.IndexOf('"', idx); return end < 0 ? null : json.Substring(idx, end - idx); }
        int endNum = idx;
        while (endNum < json.Length && json[endNum] != ',' && json[endNum] != '}') endNum++;
        return json.Substring(idx, endNum - idx).Trim();
    }
</script>
"@

$resolveAspx | Out-File -FilePath "$helpdeskApi\resolve.aspx" -Encoding UTF8 -Force
Write-Log "Deployed: $helpdeskApi\resolve.aspx" "SUCCESS"

# ==============================================================================
# 11. REGISTER IIS APPLICATION & APP POOL
# ==============================================================================

Write-Log "Configuring IIS application for /apps/helpdesk..." "STEP"

try {
    Import-Module WebAdministration -ErrorAction Stop

    # Create dedicated app pool for the helpdesk (runs as ApplicationPoolIdentity)
    $poolName = "HelpdeskAppPool"
    if (-not (Test-Path "IIS:\AppPools\$poolName")) {
        New-WebAppPool -Name $poolName | Out-Null
        Set-ItemProperty "IIS:\AppPools\$poolName" -Name "managedRuntimeVersion" -Value "v4.0"
        Set-ItemProperty "IIS:\AppPools\$poolName" -Name "startMode" -Value "AlwaysRunning"
        Write-Log "Created app pool: $poolName" "SUCCESS"
    } else {
        Write-Log "App pool $poolName already exists." "INFO"
    }

    # Create the IIS application
    $siteName = "SpringfieldBoxFactory"
    $existing = Get-WebApplication -Site $siteName -Name "apps/helpdesk" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Log "IIS application /apps/helpdesk already exists." "WARNING"
    } else {
        New-WebApplication -Site $siteName -Name "apps/helpdesk" `
            -PhysicalPath $helpdeskBase -ApplicationPool $poolName | Out-Null
        Write-Log "Registered IIS application: $siteName/apps/helpdesk" "SUCCESS"
    }

    # Enable Windows Authentication, disable Anonymous for /apps/helpdesk
    # (survives Blue Team disabling Basic Auth globally)
    Set-WebConfigurationProperty -Filter "system.webServer/security/authentication/windowsAuthentication" `
        -Name "enabled" -Value $true `
        -PSPath "IIS:\Sites\$siteName\apps\helpdesk" -ErrorAction SilentlyContinue
    Set-WebConfigurationProperty -Filter "system.webServer/security/authentication/anonymousAuthentication" `
        -Name "enabled" -Value $false `
        -PSPath "IIS:\Sites\$siteName\apps\helpdesk" -ErrorAction SilentlyContinue
    Write-Log "Windows Auth enabled, Anonymous Auth disabled on /apps/helpdesk." "SUCCESS"

} catch {
    Write-Log "IIS application registration failed: $_ — ASPX files are deployed, but you may need to register the app pool manually." "WARNING"
}

# ==============================================================================
# 12. UPDATE APPS INDEX (add helpdesk link)
# ==============================================================================

Write-Log "Adding helpdesk link to /apps/ index..." "STEP"

$appsIndexPath = "$IisBasePath\apps\index.html"
if (-not (Test-Path $appsIndexPath)) {
    # Create a minimal apps index if BadSQL didn't produce one
    $appsIndex = @"
<!DOCTYPE html>
<html><head><title>SBF Applications</title><link rel="stylesheet" href="/css/main.css"></head>
<body>
<header><h1>Springfield Box Factory</h1><p>Internal Applications</p></header>
<nav><a href="/">Home</a><a href="/portal/index.html">Employee Portal</a><a href="/apps/">Applications</a></nav>
<div class="container">
<h2>Internal Applications</h2>
<ul>
  <li><a href="/apps/inventory/">Nail Inventory System</a></li>
  <li><a href="/apps/timesheet/">Timesheet Viewer</a></li>
  <li><a href="/apps/hr/">HR Portal</a></li>
  <li><a href="/apps/orders/">Order Archive</a></li>
  <li><a href="/apps/helpdesk/">IT Helpdesk</a></li>
</ul>
</div>
<footer><p>Springfield Box Factory &copy; $HelpdeskYear</p></footer>
</body></html>
"@
    $appsIndex | Out-File -FilePath $appsIndexPath -Encoding UTF8 -Force
    Write-Log "Created $appsIndexPath with helpdesk link." "SUCCESS"
} else {
    # Inject helpdesk link if not already present
    $content = Get-Content $appsIndexPath -Raw
    if ($content -notmatch 'helpdesk') {
        $content = $content -replace '(</ul>)', '<li><a href="/apps/helpdesk/">IT Helpdesk</a></li>$1'
        $content | Out-File -FilePath $appsIndexPath -Encoding UTF8 -Force
        Write-Log "Injected helpdesk link into existing apps index." "SUCCESS"
    } else {
        Write-Log "Helpdesk link already present in apps index." "INFO"
    }
}

# ==============================================================================
# 13. SUMMARY
# ==============================================================================

Write-Log "" "INFO"
Write-Log "=================================================================" "INFO"
Write-Log "  Phase 3 Complete — Helpdesk System Deployed" "SUCCESS"
Write-Log "=================================================================" "INFO"
Write-Log "" "INFO"
Write-Log "Database:   ITDeskDB on $SqlInstance" "INFO"
Write-Log "Tables:     Tickets, TicketHistory" "INFO"
Write-Log "Procs:      usp_SubmitTicket, usp_GetOpenTickets, usp_ResolveTicket" "INFO"
Write-Log "" "INFO"
Write-Log "IIS Endpoints:" "INFO"
Write-Log "  GET/POST  http://[host]/apps/helpdesk/               — Ticket management UI" "INFO"
Write-Log "  POST      http://[host]/apps/helpdesk/api/submit.aspx  — Submit ticket" "INFO"
Write-Log "  GET       http://[host]/apps/helpdesk/api/status.aspx  — JSON status (Scorebot)" "INFO"
Write-Log "  GET       http://[host]/apps/helpdesk/api/tickets.aspx — JSON ticket list" "INFO"
Write-Log "  POST      http://[host]/apps/helpdesk/api/resolve.aspx — Resolve ticket" "INFO"
Write-Log "" "INFO"
Write-Log "NEXT STEPS:" "INFO"
Write-Log "  1. Copy Invoke-LockoutSimulator.ps1 to C:\Simulator\ on the simulator VM" "INFO"
Write-Log "  2. Copy Invoke-HelpdeskAutoResolve.ps1 to C:\Simulator\ on the simulator VM" "INFO"
Write-Log "  3. Start both scripts (or add them to Invoke-ContinuousActivitySimulator.ps1)" "INFO"
Write-Log "" "INFO"
