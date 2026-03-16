<#
.SYNOPSIS
    Phase 5: Deploys the Springfield Box Factory customer order endpoint.

.DESCRIPTION
    This script sets up the customer order simulation infrastructure:

    1. SQL permissions - Grants BlackTeam_WebBot db_datareader/db_datawriter on
       BoxArchive2019 (BoxArchive2019 and the ArchivedOrders table were created by
       BadSQL.ps1; this script wires up the Windows login and database user).

    2. OrdersAppPool - New IIS application pool running as DOMAIN\BlackTeam_WebBot
       with .NET CLR v4.0, Integrated pipeline, AlwaysRunning start mode.

    3. ASPX endpoints deployed to C:\inetpub\SpringfieldBoxFactory\apps\orders\api\:
         POST  /apps/orders/api/submit.aspx  - insert new order, return orderId + orderNumber
         GET   /apps/orders/api/status.aspx?id=N - return single order details
         GET   /apps/orders/api/orders.aspx  - last 50 orders as JSON array

    4. IIS Application registered at /apps/orders/api under SpringfieldBoxFactory site,
       using OrdersAppPool.

    5. Windows Auth enabled, Anonymous Auth disabled on /apps/orders/api.

    6. web.config deployed with Windows Auth and connection string settings.

.NOTES
    Run AFTER:
        - Invoke-BadderBlood.ps1
        - BadIIS.ps1          (SpringfieldBoxFactory IIS site must exist)
        - BadSQL.ps1          (SQL instance + BoxArchive2019 must exist)
        - Deploy-BlackTeamAccounts.ps1 (Phase 1 - BlackTeam_WebBot must exist)
        - Deploy-HelpdeskSystem.ps1    (Phase 3 - ASP.NET 4.5 already installed)

    Must be run as local admin / Domain Admin on the IIS + SQL host.

    Context: Educational / CTF / Active Directory Lab Environment
#>

#Requires -RunAsAdministrator

param(
    [string]$SqlInstance         = "localhost\BADSQL",
    [SecureString]$SqlSaPassword = $null,
    [SecureString]$SharedPassword = $null,
    [string]$IisBasePath         = "C:\inetpub\SpringfieldBoxFactory",
    [string]$DomainNB            = "",
    [switch]$Force,
    [switch]$NonInteractive
)

$ErrorActionPreference = "Stop"

# Resolve default shared password (avoids hardcoded plaintext in param block)
if (-not $SharedPassword) {
    $SharedPassword = ConvertTo-SecureString "B!ackT3am_Sc0reb0t_2025#" -AsPlainText -Force
}

# Helper: extract plaintext from a SecureString
function ConvertFrom-SecureStringPlain { param([SecureString]$s)
    [System.Net.NetworkCredential]::new('', $s).Password
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
        "VULN"    { Write-Host "[$ts] [VULN]    >>> [INTENTIONAL MISCONFIG] $Message" -ForegroundColor Magenta }
        "STEP"    { Write-Host "" ; Write-Host "[$ts] >>> $Message" -ForegroundColor White }
        default   { Write-Host "[$ts] $Message" }
    }
}

Write-Log "=================================================================" "INFO"
Write-Log "  BadderBlood Continuous Activity Simulator" "INFO"
Write-Log "  Phase 5: Customer Order Endpoint Deployment" "INFO"
Write-Log "  Educational / CTF / Lab Use Only" "WARNING"
Write-Log "=================================================================" "INFO"

# ==============================================================================
# 1. RESOLVE DOMAIN
# ==============================================================================

Write-Log "Resolving domain..." "STEP"

if (-not $DomainNB) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $Domain    = Get-ADDomain
        $DomainNB  = $Domain.NetBIOSName
        $DomainDNS = $Domain.DNSRoot
        Write-Log "Domain: $DomainDNS | NetBIOS: $DomainNB" "SUCCESS"
    } catch {
        Write-Log "Cannot reach AD - using environment fallback for domain name." "WARNING"
        $DomainNB  = $env:USERDOMAIN
        $DomainDNS = "$($env:USERDOMAIN).local"
    }
} else {
    $DomainDNS = "$DomainNB.local"
}

$WebBotLogin   = "$DomainNB\BlackTeam_WebBot"
$CurrentYear   = Get-Date -Format "yyyy"
$SharedPasswordPlain = ConvertFrom-SecureStringPlain $SharedPassword

# ==============================================================================
# 2. SQL HELPER
# ==============================================================================

function Invoke-Sql {
    param([string]$Query, [string]$Database = "master", [switch]$ReturnReader)
    try {
        $conn = New-Object System.Data.SqlClient.SqlConnection
        if ($SqlSaPassword) {
            $saPlain = ConvertFrom-SecureStringPlain $SqlSaPassword
            $conn.ConnectionString = "Server=$SqlInstance;Database=$Database;User Id=sa;Password=$saPlain;Connection Timeout=15;"
        } else {
            $conn.ConnectionString = "Server=$SqlInstance;Database=$Database;Integrated Security=SSPI;Connection Timeout=15;"
        }
        $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText    = $Query
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

# SQL connectivity
$ping = Invoke-Sql -Query "SELECT 1" -ReturnReader
if (-not $ping) {
    Write-Log "Cannot connect to $SqlInstance. Check the instance is running." "ERROR"
    exit 1
}
Write-Log "SQL connectivity confirmed." "SUCCESS"

# BoxArchive2019 exists
$dbCheck = Invoke-Sql -ReturnReader -Query "SELECT COUNT(*) AS n FROM sys.databases WHERE name = 'BoxArchive2019'"
$boxDbExists = ($dbCheck -is [System.Data.DataTable] -and $dbCheck.Rows.Count -gt 0 -and $dbCheck.Rows[0].n -gt 0)
if (-not $boxDbExists) {
    # Fallback: try connecting directly (sys.databases may be hidden due to permissions)
    $directCheck = Invoke-Sql -Query "SELECT DB_NAME() AS CurrentDB" -Database "BoxArchive2019" -ReturnReader
    if (-not $directCheck -or $directCheck -isnot [System.Data.DataTable] -or $directCheck.Rows.Count -eq 0) {
        Write-Log "BoxArchive2019 database not found on $SqlInstance. Run BadSQL.ps1 first." "ERROR"
        exit 1
    }
    Write-Log "BoxArchive2019 confirmed (via direct connection)." "SUCCESS"
} else {
    Write-Log "BoxArchive2019 confirmed." "SUCCESS"
}

# IIS site path
if (-not (Test-Path $IisBasePath)) {
    Write-Log "IIS base path '$IisBasePath' not found. Run BadIIS.ps1 first." "ERROR"
    exit 1
}
Write-Log "SpringfieldBoxFactory IIS path confirmed." "SUCCESS"

# ==============================================================================
# 4. GRANT SQL PERMISSIONS TO BlackTeam_WebBot
# ==============================================================================

Write-Log "Granting BoxArchive2019 permissions to BlackTeam_WebBot ($WebBotLogin)..." "STEP"

# Windows login on the server
$loginSql = @"
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'$WebBotLogin')
    CREATE LOGIN [$WebBotLogin] FROM WINDOWS WITH DEFAULT_DATABASE=[BoxArchive2019];
"@
if (Invoke-Sql -Query $loginSql -Database "master") {
    Write-Log "Windows login confirmed/created: $WebBotLogin" "SUCCESS"
}

# Database user + roles on BoxArchive2019
$dbGrantSql = @"
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$WebBotLogin')
    CREATE USER [$WebBotLogin] FOR LOGIN [$WebBotLogin];
ALTER ROLE db_datareader ADD MEMBER [$WebBotLogin];
ALTER ROLE db_datawriter ADD MEMBER [$WebBotLogin];
"@
if (Invoke-Sql -Query $dbGrantSql -Database "BoxArchive2019") {
    Write-Log "db_datareader / db_datawriter granted on BoxArchive2019." "SUCCESS"
} else {
    Write-Log "Failed to grant SQL permissions on BoxArchive2019 - continuing (may already be granted)." "WARNING"
}

# ==============================================================================
# 5. CREATE DIRECTORY STRUCTURE
# ==============================================================================

Write-Log "Creating orders directory structure under $IisBasePath..." "STEP"

$ordersBase = "$IisBasePath\apps\orders"
$ordersApi  = "$ordersBase\api"

foreach ($dir in @($ordersBase, $ordersApi)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Log "Created: $dir" "INFO"
    } else {
        Write-Log "Directory already exists: $dir" "INFO"
    }
}

# ==============================================================================
# 6. DEPLOY ASPX FILES
# ==============================================================================

Write-Log "Deploying ASPX endpoint files..." "STEP"

# ----------------------------------------------------------------------------
# 6A. submit.aspx - POST, inserts a new order, returns orderId + orderNumber
# ----------------------------------------------------------------------------

$submitAspx = @"
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    // Springfield Box Factory - Customer Order Submission API
    // POST /apps/orders/api/submit.aspx
    // Body JSON: { "customer": "Acme Corp", "boxType": "Medium", "quantity": 500 }
    // Returns:   { "success": true, "orderId": 42, "orderNumber": "ORD-00042" }
    //
    // Runs as DOMAIN\BlackTeam_WebBot via OrdersAppPool - Integrated Security=SSPI.

    private static readonly string ConnStr =
        @"Server=$SqlInstance;Database=BoxArchive2019;Integrated Security=SSPI;Connection Timeout=10;";

    // Fixed unit-price lookup by box type (USD per unit)
    private static readonly System.Collections.Generic.Dictionary<string, decimal> UnitPrices =
        new System.Collections.Generic.Dictionary<string, decimal>(
            System.StringComparer.OrdinalIgnoreCase) {
        { "Small",        0.45m },
        { "Medium",       0.85m },
        { "Large",        1.25m },
        { "Extra Large",  1.75m },
        { "XL",           1.75m },
        { "Bulk Pallet",  0.38m },
        { "Custom",       1.10m }
    };

    private static readonly string[] SalesReps = new[] {
        "Homer Simpson", "Lenny Leonard", "Carl Carlson",
        "Barney Gumble", "Apu Nahasapeemapetilon", "Patty Bouvier"
    };

    private static readonly string[] Regions = new[] {
        "Midwest", "Northeast", "Southeast", "Southwest", "West Coast", "International"
    };

    void Page_Load(object sender, EventArgs e)
    {
        Response.ContentType = "application/json";
        Response.AddHeader("Access-Control-Allow-Origin", "*");

        if (Request.HttpMethod == "OPTIONS") {
            Response.AddHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
            Response.AddHeader("Access-Control-Allow-Headers", "Content-Type");
            Response.End(); return;
        }

        if (Request.HttpMethod != "POST") {
            Response.StatusCode = 405;
            Response.Write("{\"error\":\"Method not allowed - POST required\"}");
            Response.End(); return;
        }

        try {
            string body     = new StreamReader(Request.InputStream).ReadToEnd();
            string customer = ExtractJson(body, "customer") ?? "Unknown Customer";
            string boxType  = ExtractJson(body, "boxType")  ?? "Medium";
            string qtyStr   = ExtractJson(body, "quantity") ?? "1";

            // Sanitise inputs
            if (customer.Length > 100) customer = customer.Substring(0, 100);
            if (boxType.Length  > 50)  boxType  = boxType.Substring(0, 50);
            int quantity = 1;
            int.TryParse(qtyStr, out quantity);
            if (quantity < 1)      quantity = 1;
            if (quantity > 999999) quantity = 999999;

            // Unit price lookup - default $0.85 for unknown types
            decimal unitPrice;
            if (!UnitPrices.TryGetValue(boxType.Trim(), out unitPrice))
                unitPrice = 0.85m;

            decimal totalUsd = Math.Round(unitPrice * quantity, 2);

            // Pick a deterministic-ish but varied sales rep and region
            var rng       = new System.Random();
            string rep    = SalesReps[rng.Next(SalesReps.Length)];
            string region = Regions[rng.Next(Regions.Length)];

            int newOrderId  = 0;
            string orderNum = "";

            using (var conn = new SqlConnection(ConnStr)) {
                conn.Open();
                // INSERT and retrieve the new identity in one statement
                string sql = @"
                    INSERT INTO ArchivedOrders
                        (CustomerName, OrderDate, BoxType, Quantity, UnitPriceUSD,
                         TotalUSD, ShippedDate, SalesRep, Region)
                    VALUES
                        (@CustomerName, CAST(GETDATE() AS DATE), @BoxType, @Quantity,
                         @UnitPriceUSD, @TotalUSD,
                         CAST(DATEADD(day, 5, GETDATE()) AS DATE),
                         @SalesRep, @Region);
                    SELECT SCOPE_IDENTITY() AS NewID;";

                using (var cmd = new SqlCommand(sql, conn)) {
                    cmd.Parameters.AddWithValue("@CustomerName", customer);
                    cmd.Parameters.AddWithValue("@BoxType",      boxType);
                    cmd.Parameters.AddWithValue("@Quantity",     quantity);
                    cmd.Parameters.AddWithValue("@UnitPriceUSD", unitPrice);
                    cmd.Parameters.AddWithValue("@TotalUSD",     totalUsd);
                    cmd.Parameters.AddWithValue("@SalesRep",     rep);
                    cmd.Parameters.AddWithValue("@Region",       region);

                    object result = cmd.ExecuteScalar();
                    newOrderId = Convert.ToInt32(result);
                    orderNum   = "ORD-" + newOrderId.ToString("D5");
                }
            }

            Response.Write(
                "{\"success\":true" +
                ",\"orderId\":"     + newOrderId +
                ",\"orderNumber\":\"" + orderNum + "\"" +
                ",\"totalUSD\":"    + totalUsd.ToString("F2") +
                ",\"salesRep\":\""  + J(rep) + "\"" +
                ",\"region\":\""    + J(region) + "\"" +
                "}"
            );

        } catch (Exception ex) {
            Response.StatusCode = 500;
            Response.Write("{\"success\":false,\"error\":\"" + ex.Message.Replace("\"","'") + "\"}");
        }
    }

    // Minimal JSON string-value extractor - no external library dependency
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
        // Number or bare token
        int endNum = idx;
        while (endNum < json.Length && json[endNum] != ',' && json[endNum] != '}') endNum++;
        return json.Substring(idx, endNum - idx).Trim();
    }

    // JSON-safe string serialiser
    private string J(object o) {
        if (o == null || o == DBNull.Value) return "";
        return o.ToString()
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "\\r")
                .Replace("\n", "\\n");
    }
</script>
"@

$submitAspx | Out-File -FilePath "$ordersApi\submit.aspx" -Encoding UTF8 -Force
Write-Log "Deployed: $ordersApi\submit.aspx" "SUCCESS"

# ----------------------------------------------------------------------------
# 6B. status.aspx - GET ?id=N, returns JSON with single order details
# ----------------------------------------------------------------------------

$statusAspx = @"
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<script runat="server">
    // Springfield Box Factory - Order Status API
    // GET /apps/orders/api/status.aspx?id=42
    // Returns: { "found": true, "order": { ... } }
    //          { "found": false, "error": "Order not found" }

    private static readonly string ConnStr =
        @"Server=$SqlInstance;Database=BoxArchive2019;Integrated Security=SSPI;Connection Timeout=10;";

    void Page_Load(object sender, EventArgs e)
    {
        Response.ContentType = "application/json";
        Response.AddHeader("Access-Control-Allow-Origin", "*");

        string idStr = Request.QueryString["id"] ?? "";
        int orderId  = 0;

        if (string.IsNullOrEmpty(idStr) || !int.TryParse(idStr, out orderId)) {
            Response.StatusCode = 400;
            Response.Write("{\"found\":false,\"error\":\"Missing or invalid id parameter\"}");
            return;
        }

        try {
            using (var conn = new SqlConnection(ConnStr)) {
                conn.Open();
                string sql = @"
                    SELECT OrderID, CustomerName,
                           CONVERT(VARCHAR(10), OrderDate,  126) AS OrderDate,
                           BoxType, Quantity, UnitPriceUSD, TotalUSD,
                           CONVERT(VARCHAR(10), ShippedDate, 126) AS ShippedDate,
                           SalesRep, Region
                    FROM ArchivedOrders
                    WHERE OrderID = @OrderID";

                using (var cmd = new SqlCommand(sql, conn)) {
                    cmd.Parameters.AddWithValue("@OrderID", orderId);
                    using (var r = cmd.ExecuteReader()) {
                        if (r.Read()) {
                            string orderNum = "ORD-" + Convert.ToInt32(r["OrderID"]).ToString("D5");
                            Response.Write(
                                "{\"found\":true,\"order\":{" +
                                "\"orderId\":"        + r["OrderID"]     + "," +
                                "\"orderNumber\":\""  + orderNum         + "\"," +
                                "\"customer\":\""     + J(r["CustomerName"]) + "\"," +
                                "\"orderDate\":\""    + J(r["OrderDate"])    + "\"," +
                                "\"boxType\":\""      + J(r["BoxType"])      + "\"," +
                                "\"quantity\":"       + r["Quantity"]        + "," +
                                "\"unitPriceUSD\":"   + Convert.ToDecimal(r["UnitPriceUSD"]).ToString("F2") + "," +
                                "\"totalUSD\":"       + Convert.ToDecimal(r["TotalUSD"]).ToString("F2")     + "," +
                                "\"shippedDate\":\""  + J(r["ShippedDate"])  + "\"," +
                                "\"salesRep\":\""     + J(r["SalesRep"])     + "\"," +
                                "\"region\":\""       + J(r["Region"])       + "\"" +
                                "}}"
                            );
                        } else {
                            Response.StatusCode = 404;
                            Response.Write("{\"found\":false,\"error\":\"Order not found\"}");
                        }
                    }
                }
            }
        } catch (Exception ex) {
            Response.StatusCode = 500;
            Response.Write("{\"found\":false,\"error\":\"" + ex.Message.Replace("\"","'") + "\"}");
        }
    }

    private string J(object o) {
        if (o == null || o == DBNull.Value) return "";
        return o.ToString()
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "\\r")
                .Replace("\n", "\\n");
    }
</script>
"@

$statusAspx | Out-File -FilePath "$ordersApi\status.aspx" -Encoding UTF8 -Force
Write-Log "Deployed: $ordersApi\status.aspx" "SUCCESS"

# ----------------------------------------------------------------------------
# 6C. orders.aspx - GET, returns last 50 orders as a JSON array
# ----------------------------------------------------------------------------

$ordersAspx = @"
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<%@ Import Namespace="System.Text" %>
<script runat="server">
    // Springfield Box Factory - Order List API
    // GET /apps/orders/api/orders.aspx
    // Optional query params: ?region=Midwest  ?salesRep=Homer%20Simpson  ?max=50
    // Returns: { "orders": [ { ... }, ... ], "count": N }

    private static readonly string ConnStr =
        @"Server=$SqlInstance;Database=BoxArchive2019;Integrated Security=SSPI;Connection Timeout=10;";

    void Page_Load(object sender, EventArgs e)
    {
        Response.ContentType = "application/json";
        Response.AddHeader("Access-Control-Allow-Origin", "*");

        try {
            // Optional filters passed as query string parameters
            string regionFilter   = Request.QueryString["region"]   ?? "";
            string salesRepFilter = Request.QueryString["salesRep"] ?? "";
            int    maxRows        = 50;
            int.TryParse(Request.QueryString["max"] ?? "50", out maxRows);
            if (maxRows < 1 || maxRows > 500) maxRows = 50;

            var where  = new System.Collections.Generic.List<string>();
            if (!string.IsNullOrEmpty(regionFilter))   where.Add("Region = @Region");
            if (!string.IsNullOrEmpty(salesRepFilter)) where.Add("SalesRep = @SalesRep");
            string whereClause = where.Count > 0 ? "WHERE " + string.Join(" AND ", where) : "";

            string sql = @"
                SELECT TOP " + maxRows + @"
                    OrderID,
                    CustomerName,
                    CONVERT(VARCHAR(10), OrderDate, 126)   AS OrderDate,
                    BoxType,
                    Quantity,
                    TotalUSD,
                    Region
                FROM ArchivedOrders
                " + whereClause + @"
                ORDER BY OrderID DESC";

            var sb = new StringBuilder();
            sb.Append("{\"orders\":[");

            using (var conn = new SqlConnection(ConnStr)) {
                conn.Open();
                using (var cmd = new SqlCommand(sql, conn)) {
                    if (!string.IsNullOrEmpty(regionFilter))
                        cmd.Parameters.AddWithValue("@Region",   regionFilter.Length > 30 ? regionFilter.Substring(0,30) : regionFilter);
                    if (!string.IsNullOrEmpty(salesRepFilter))
                        cmd.Parameters.AddWithValue("@SalesRep", salesRepFilter.Length > 100 ? salesRepFilter.Substring(0,100) : salesRepFilter);

                    using (var r = cmd.ExecuteReader()) {
                        bool first = true;
                        int  count = 0;
                        while (r.Read()) {
                            if (!first) sb.Append(",");
                            string orderNum = "ORD-" + Convert.ToInt32(r["OrderID"]).ToString("D5");
                            sb.Append("{");
                            sb.Append("\"orderId\":"      + r["OrderID"]  + ",");
                            sb.Append("\"orderNumber\":\"" + orderNum      + "\",");
                            sb.Append("\"customer\":\""   + J(r["CustomerName"]) + "\",");
                            sb.Append("\"orderDate\":\""  + J(r["OrderDate"])    + "\",");
                            sb.Append("\"boxType\":\""    + J(r["BoxType"])      + "\",");
                            sb.Append("\"quantity\":"     + r["Quantity"]        + ",");
                            sb.Append("\"totalUSD\":"     + Convert.ToDecimal(r["TotalUSD"]).ToString("F2") + ",");
                            sb.Append("\"region\":\""     + J(r["Region"])       + "\"");
                            sb.Append("}");
                            first = false;
                            count++;
                        }
                        sb.Append("],\"count\":" + count + "}");
                    }
                }
            }

            Response.Write(sb.ToString());

        } catch (Exception ex) {
            Response.StatusCode = 500;
            Response.Write("{\"orders\":[],\"count\":0,\"error\":\"" + ex.Message.Replace("\"","'") + "\"}");
        }
    }

    private string J(object o) {
        if (o == null || o == DBNull.Value) return "";
        return o.ToString()
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "\\r")
                .Replace("\n", "\\n");
    }
</script>
"@

$ordersAspx | Out-File -FilePath "$ordersApi\orders.aspx" -Encoding UTF8 -Force
Write-Log "Deployed: $ordersApi\orders.aspx" "SUCCESS"

# ==============================================================================
# 7. DEPLOY web.config
# ==============================================================================

Write-Log "Deploying web.config to $ordersApi..." "STEP"

$webConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <connectionStrings>
    <add name="BoxArchive"
         connectionString="Server=$SqlInstance;Database=BoxArchive2019;Integrated Security=SSPI;Connection Timeout=10;"
         providerName="System.Data.SqlClient" />
  </connectionStrings>
  <system.web>
    <compilation debug="false" targetFramework="4.5" />
    <httpRuntime targetFramework="4.5" maxRequestLength="1024" executionTimeout="30" />
    <authentication mode="Windows" />
    <authorization>
      <deny users="?" />
    </authorization>
    <identity impersonate="false" />
  </system.web>
  <system.webServer>
    <defaultDocument enabled="false" />
    <httpErrors errorMode="Custom" existingResponse="PassThrough" />
  </system.webServer>
</configuration>
"@

$webConfig | Out-File -FilePath "$ordersApi\web.config" -Encoding UTF8 -Force
Write-Log "Deployed: $ordersApi\web.config" "SUCCESS"

# ==============================================================================
# 8. CONFIGURE IIS - APP POOL + APPLICATION
# ==============================================================================

Write-Log "Configuring IIS application pool and application for /apps/orders/api..." "STEP"

try {
    Import-Module WebAdministration -ErrorAction Stop

    # ---- 8A. Create OrdersAppPool ----
    $poolName = "OrdersAppPool"
    if (Test-Path "IIS:\AppPools\$poolName") {
        if ($Force) {
            Write-Log "-Force specified. Removing existing $poolName for recreation." "WARNING"
            Remove-WebAppPool -Name $poolName -ErrorAction SilentlyContinue
        } else {
            Write-Log "App pool '$poolName' already exists - updating identity settings." "INFO"
        }
    }

    if (-not (Test-Path "IIS:\AppPools\$poolName")) {
        New-WebAppPool -Name $poolName | Out-Null
        Write-Log "Created app pool: $poolName" "SUCCESS"
    }

    # .NET CLR version
    Set-ItemProperty "IIS:\AppPools\$poolName" -Name "managedRuntimeVersion" -Value "v4.0"
    # Integrated pipeline
    Set-ItemProperty "IIS:\AppPools\$poolName" -Name "managedPipelineMode"   -Value 0   # 0 = Integrated
    # AlwaysRunning
    Set-ItemProperty "IIS:\AppPools\$poolName" -Name "startMode"             -Value "AlwaysRunning"
    Set-ItemProperty "IIS:\AppPools\$poolName" -Name "autoStart"             -Value $true

    # Process model - run as BlackTeam_WebBot (SpecificUser = 3)
    Set-ItemProperty "IIS:\AppPools\$poolName" -Name "processModel" -Value @{
        userName     = "$DomainNB\BlackTeam_WebBot"
        password     = $SharedPasswordPlain
        identityType = 3    # SpecificUser
    }

    Write-Log "App pool '$poolName' configured (identity: $DomainNB\BlackTeam_WebBot)." "SUCCESS"

    # ---- 8B. Register IIS Application ----
    $siteName   = "SpringfieldBoxFactory"
    $appVirtPath = "apps/orders/api"

    $existing = Get-WebApplication -Site $siteName -Name $appVirtPath -ErrorAction SilentlyContinue
    if ($existing) {
        if ($Force) {
            Write-Log "-Force: removing existing IIS application /$appVirtPath." "WARNING"
            Remove-WebApplication -Site $siteName -Name $appVirtPath -ErrorAction SilentlyContinue
            $existing = $null
        } else {
            Write-Log "IIS application /$appVirtPath already exists - updating app pool assignment." "WARNING"
            Set-ItemProperty "IIS:\Sites\$siteName\$appVirtPath" -Name "applicationPool" -Value $poolName
        }
    }

    if (-not $existing) {
        New-WebApplication -Site $siteName -Name $appVirtPath `
            -PhysicalPath $ordersApi -ApplicationPool $poolName | Out-Null
        Write-Log "Registered IIS application: $siteName/$appVirtPath -> $ordersApi" "SUCCESS"
    }

    # ---- 8C. Authentication - Windows Auth on, Anonymous off ----
    # First, unlock the authentication sections at the server level so they can be overridden per-app
    try {
        $appcmd = "$env:SystemRoot\System32\inetsrv\appcmd.exe"
        & $appcmd unlock config -section:system.webServer/security/authentication/windowsAuthentication 2>$null
        & $appcmd unlock config -section:system.webServer/security/authentication/anonymousAuthentication 2>$null
    } catch {
        Write-Log "Could not unlock IIS auth sections via appcmd (non-fatal): $_" "WARNING"
    }

    $iisPath = "IIS:\Sites\$siteName\$appVirtPath"

    Set-WebConfigurationProperty `
        -Filter "system.webServer/security/authentication/windowsAuthentication" `
        -Name   "enabled" -Value $true `
        -PSPath $iisPath -ErrorAction SilentlyContinue

    Set-WebConfigurationProperty `
        -Filter "system.webServer/security/authentication/anonymousAuthentication" `
        -Name   "enabled" -Value $false `
        -PSPath $iisPath -ErrorAction SilentlyContinue

    Write-Log "Windows Auth enabled, Anonymous Auth disabled on /$appVirtPath." "SUCCESS"

} catch {
    Write-Log "IIS configuration step failed: $_ - ASPX files are deployed but you may need to register the app pool/application manually." "WARNING"
}

# ==============================================================================
# 9. UPDATE /apps/ INDEX (inject orders link if missing)
# ==============================================================================

Write-Log "Checking /apps/ index for orders link..." "STEP"

$appsIndexPath = "$IisBasePath\apps\index.html"
if (Test-Path $appsIndexPath) {
    $content = Get-Content $appsIndexPath -Raw
    if ($content -notmatch 'orders') {
        $content = $content -replace '(</ul>)', '<li><a href="/apps/orders/">Order Archive</a></li>$1'
        $content | Out-File -FilePath $appsIndexPath -Encoding UTF8 -Force
        Write-Log "Injected Order Archive link into existing apps index." "SUCCESS"
    } else {
        Write-Log "Order Archive link already present in apps index." "INFO"
    }
} else {
    Write-Log "Apps index not found at $appsIndexPath - skipping link injection (run Deploy-HelpdeskSystem.ps1 first to create it)." "WARNING"
}

# ==============================================================================
# 10. SUMMARY
# ==============================================================================

Write-Log "" "INFO"
Write-Log "=================================================================" "INFO"
Write-Log "  Phase 5 Complete - Customer Order Endpoint Deployed" "SUCCESS"
Write-Log "=================================================================" "INFO"
Write-Log "" "INFO"
Write-Log "SQL grants:   BoxArchive2019 on $SqlInstance" "INFO"
Write-Log "              db_datareader + db_datawriter -> $WebBotLogin" "INFO"
Write-Log "" "INFO"
Write-Log "IIS App Pool: OrdersAppPool (.NET 4.0, Integrated, AlwaysRunning)" "INFO"
Write-Log "              Identity: $DomainNB\BlackTeam_WebBot" "INFO"
Write-Log "" "INFO"
Write-Log "IIS Endpoints (Windows Auth, Anonymous disabled):" "INFO"
Write-Log "  POST  http://[host]/apps/orders/api/submit.aspx  - Submit new order" "INFO"
Write-Log "  GET   http://[host]/apps/orders/api/status.aspx?id=N - Order details" "INFO"
Write-Log "  GET   http://[host]/apps/orders/api/orders.aspx  - Last 50 orders" "INFO"
Write-Log "" "INFO"
Write-Log "Files deployed to: $ordersApi" "INFO"
Write-Log "  submit.aspx" "INFO"
Write-Log "  status.aspx" "INFO"
Write-Log "  orders.aspx" "INFO"
Write-Log "  web.config" "INFO"
Write-Log "" "INFO"
Write-Log "NEXT STEPS:" "INFO"
Write-Log "  1. Deploy Invoke-OrderSimulator.ps1 to the simulator VM (Phase 5 runtime)" "INFO"
Write-Log "  2. Add order simulation to Invoke-ContinuousActivitySimulator.ps1" "INFO"
Write-Log "  3. Verify endpoint with: Invoke-WebRequest -UseDefaultCredentials http://localhost/apps/orders/api/orders.aspx" "INFO"
Write-Log "" "INFO"
