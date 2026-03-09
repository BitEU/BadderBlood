<#
.SYNOPSIS
    Deployment script for the Springfield Box Factory SQL environment.
    Integrates into BadderBlood to provide a target-rich, misconfigured SQL Server environment.

.DESCRIPTION
    This script performs a full deployment of a misconfigured SQL Server instance themed to
    "Springfield Box Factory" - the same company whose AD, web, and file infrastructure was
    already compromised by BadderBlood, BadIIS, and BadFS.

    ALL sensitive content is generated DYNAMICALLY from the live Active Directory environment
    that BadderBlood created. Database names, logins, linked servers, and stored procedure
    comments reference real domain objects.

    Features:
    1. Installs SQL Server Express (downloads if not present) or uses existing SQL instance.
    2. Creates themed databases: NailInventoryDB, TimesheetLegacy, BoxArchive2019, HRConfidential.
    3. Populates databases with realistic data pulled from live AD.
    4. INTENTIONAL MISCONFIGURATIONS (each is explicitly flagged):
       - SQL Server Browser service enabled (instance enumeration via UDP 1434).
       - sa account re-enabled with a weak password.
       - xp_cmdshell enabled (OS command execution from SQL).
       - Overly permissive PUBLIC role grants on sensitive tables.
       - db_owner granted to a domain service account (svc_sql).
       - Linked server configured with saved credentials.
       - Stored procedures with EXECUTE AS OWNER (privilege escalation).
       - Mixed-mode authentication enabled (SQL + Windows auth).
       - SQL Agent jobs that run as high-privileged accounts.
       - Hardcoded credentials in stored procedure comments.
       - TRUSTWORTHY database property set (privilege escalation path).
       - Weak SQL logins matching the domain's weak password list.

.NOTES
    Author: BadderBlood Integration Script
    Context: Educational / CTF / Active Directory Lab Environment

    IMPORTANT: Run AFTER Invoke-BadderBlood.ps1 so AD objects exist to query.
    IMPORTANT: Run BadIIS.ps1 first (or after) - BadSQL integrates with IIS content.

    Attack paths created:
    - xp_cmdshell → OS command execution as SQL service account
    - Linked server → lateral movement to additional SQL instances
    - TRUSTWORTHY + db_owner → privilege escalation to sysadmin
    - Weak sa password → direct sysadmin access
    - Kerberoastable svc_sql SPN → offline hash cracking → sysadmin
    - PUBLIC grants → unauthorized data access (HRConfidential tables)
#>

#Requires -RunAsAdministrator

param (
    [string]$SqlInstance      = "localhost\BADSQL",
    [string]$SqlAdminUser     = "sa",
    [string]$SqlAdminPassword = "Sp1ngf!eld_SQL_$(Get-Date -Format 'yyyy')#",
    [switch]$SkipInstall,
    [switch]$NonInteractive
)

$ErrorActionPreference = "Stop"

# ==============================================================================
# 1. LOGGING & SETUP FUNCTIONS
# ==============================================================================

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $formattedMessage = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        "INFO"    { Write-Host $formattedMessage -ForegroundColor Cyan }
        "SUCCESS" { Write-Host $formattedMessage -ForegroundColor Green }
        "WARNING" { Write-Host $formattedMessage -ForegroundColor Yellow }
        "ERROR"   { Write-Host $formattedMessage -ForegroundColor Red }
        "VULN"    { Write-Host ">>> [INTENTIONAL MISCONFIG] $Message" -ForegroundColor Magenta }
        Default   { Write-Host $formattedMessage }
    }
}

Write-Log "=================================================================" "INFO"
Write-Log "  Springfield Box Factory - SQL Environment Deployment" "INFO"
Write-Log "  BadSQL.ps1 | Educational / CTF / Lab Use Only" "WARNING"
Write-Log "=================================================================" "INFO"

# ==============================================================================
# 3. QUERY ACTIVE DIRECTORY FOR DYNAMIC CONTENT
# ==============================================================================

Write-Log "Querying Active Directory to generate dynamic SQL content..." "INFO"

try {
    $Domain       = Get-ADDomain
    $DomainDNS    = $Domain.DNSRoot
    $DomainDN     = $Domain.DistinguishedName
    $DomainNB     = $Domain.NetBIOSName
    $PDC          = $Domain.PDCEmulator

    $AllDCs = Get-ADDomainController -Filter * | Sort-Object Name
    $PrimaryDC = $AllDCs | Where-Object { $_.OperationMasterRoles -contains 'PDCEmulator' } | Select-Object -First 1
    if (-not $PrimaryDC) { $PrimaryDC = $AllDCs | Select-Object -First 1 }

    $AllComputers = Get-ADComputer -Filter * -Properties OperatingSystem,Description,IPv4Address -ErrorAction SilentlyContinue
    $Servers = $AllComputers | Where-Object { $_.OperatingSystem -like '*Server*' } | Select-Object -First 15

    $ServiceAccounts = Get-ADUser -Filter { Enabled -eq $true } -Properties DisplayName,Description,ServicePrincipalNames,departmentNumber -ErrorAction SilentlyContinue |
                       Where-Object { $_.SamAccountName -like '*SA' -or $_.SamAccountName -like 'svc_*' -or $_.SamAccountName -like 'svc-*' } |
                       Select-Object -First 20

    # Fetch ALL enabled AD users with Manager relationships (same pattern as BadFS Section 0)
    # Manager + DistinguishedName are needed for org hierarchy in HR tables
    $ADUsers = Get-ADUser -Filter { Enabled -eq $true } -Properties DisplayName,Department,Title,Office,EmailAddress,Manager,DistinguishedName -ErrorAction SilentlyContinue |
               Where-Object { $_.SamAccountName -notmatch "Administrator|Guest|krbtgt" }

    $LeadershipTitles = @('Chief Executive Officer','Chief Operating Officer','Chief Financial Officer',
        'Chief Information Security Officer','Chief Information Officer',
        'VP of Information Technology','VP of Information Security','IT Director')
    $LeadershipUsers = @()
    foreach ($ltitle in $LeadershipTitles) {
        $found = Get-ADUser -Filter { Title -eq $ltitle } -Properties DisplayName,Title,Department -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { $LeadershipUsers += $found }
    }

    $ITDirector = $LeadershipUsers | Where-Object { $_.Title -eq 'IT Director' } | Select-Object -First 1
    $ITDirectorName = if ($ITDirector) { $ITDirector.DisplayName } else { "Gus Gorman" }
    $CFO = $LeadershipUsers | Where-Object { $_.Title -eq 'Chief Financial Officer' } | Select-Object -First 1
    $CFOName = if ($CFO) { $CFO.DisplayName } else { "Monty Burns" }

    $KerberoastableAccounts = Get-ADUser -Filter { ServicePrincipalName -like '*' } -Properties ServicePrincipalNames,Title,Department -ErrorAction SilentlyContinue |
                               Where-Object { $_.ServicePrincipalNames.Count -gt 0 }

    $ADMode = $true
    Write-Log "AD query complete. Domain: $DomainDNS | DCs: $($AllDCs.Count) | Users loaded: $($ADUsers.Count)" "SUCCESS"
} catch {
    Write-Log "Active Directory not available or query failed. Running in standalone mode." "WARNING"
    $ADMode = $false
    $DomainDNS = "springfield.local"
    $DomainDN  = "DC=springfield,DC=local"
    $DomainNB  = "SPRINGFIELD"
    $PDC       = "DC01.springfield.local"
    $ITDirectorName = "Gus Gorman"
    $CFOName = "Monty Burns"
    $ADUsers = @()
    $ServiceAccounts = @()
    $Servers = @()
    $KerberoastableAccounts = @()
}

$ThisYear = Get-Date -Format "yyyy"
$SqlServer = if ($Servers.Count -gt 0) { $Servers[0].DNSHostName } else { $PDC }
$SqlServerShort = $SqlServer.Split('.')[0]

# Weak passwords that match BadIIS / BadFS theme (same set used in BadIIS legacy_backups)
$WeakPasswords = @(
    "Password1","Welcome1","Summer${ThisYear}!","Spring${ThisYear}!","January${ThisYear}!",
    "Company1!","Changeme1","Factory1!","Nails${ThisYear}!","BoxMaker1",
    "Springfield1","Cardboard!1","Welcome${ThisYear}!","Sql${ThisYear}!","Admin${ThisYear}!"
)

# ==============================================================================
# 3B. CROSS-REFERENCE BADFS CORPSHARES DATA
# ==============================================================================
# BadFS generates a compensation CSV at C:\CorpShares\Public_Company_Data\ and
# performance reviews in C:\CorpShares\Users\{sam}\. We ingest these if they exist
# so SQL tables contain the SAME salary/PII data that is sitting on the file share.
# This creates a realistic attack scenario: data found on the share matches the DB.

Write-Log "Checking for BadFS (CorpShares) data to cross-reference..." "INFO"

$CorpSharesPath = "C:\CorpShares"
$BadFSCompensationCSV = $null
$BadFSCompensationData = @()

# Look for BadFS's compensation roster CSV
$compCsvCandidates = @(
    "$CorpSharesPath\Public_Company_Data\GLOBAL_ROSTER_WITH_COMPENSATION_DO_NOT_SHARE.csv"
)
# Also look for any CONFIDENTIAL_Employee_Roster_Salaries files BadFS scattered in department folders
$compCsvSearch = Get-ChildItem -Path $CorpSharesPath -Filter "*ROSTER*COMPENSATION*" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if ($compCsvSearch) { $compCsvCandidates += $compCsvSearch.FullName }
$compCsvSearch2 = Get-ChildItem -Path $CorpSharesPath -Filter "*Employee_Roster_Salaries*" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if ($compCsvSearch2) { $compCsvCandidates += $compCsvSearch2.FullName }

foreach ($csvPath in $compCsvCandidates) {
    if (Test-Path $csvPath) {
        try {
            $BadFSCompensationData = Import-Csv $csvPath -ErrorAction Stop
            $BadFSCompensationCSV = $csvPath
            Write-Log "Loaded BadFS compensation data from $csvPath ($($BadFSCompensationData.Count) records)" "SUCCESS"
            break
        } catch {
            Write-Log "Found $csvPath but could not parse: $_" "WARNING"
        }
    }
}
if (-not $BadFSCompensationCSV) {
    Write-Log "No BadFS compensation CSV found. Will generate salary data from AD + realistic ranges." "WARNING"
}

# Look for BadFS performance reviews to cross-reference employee data
$BadFSPerfReviews = @()
$perfReviewFiles = Get-ChildItem -Path $CorpSharesPath -Filter "PerfReview_*CONFIDENTIAL*" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 50
foreach ($prf in $perfReviewFiles) {
    try {
        $content = Get-Content $prf.FullName -Raw -ErrorAction Stop
        # Extract employee name and salary from the review format BadFS uses
        $empName = if ($content -match 'Employee Name:\s*(.+)') { $Matches[1].Trim() } else { $null }
        $empSalary = if ($content -match 'Current Base Salary:\s*\$?([\d,]+)') { [int]($Matches[1] -replace ',','') } else { $null }
        $empDept = if ($content -match 'Department:\s*(.+)') { $Matches[1].Trim() } else { $null }
        $empTitle = if ($content -match 'Job Title:\s*(.+)') { $Matches[1].Trim() } else { $null }
        $empRating = if ($content -match 'PERFORMANCE RATING:\s*(\d)') { [int]$Matches[1] } else { $null }
        $empManager = if ($content -match 'Reviewing Manager:\s*(.+)') { $Matches[1].Trim() } else { $null }
        if ($empName) {
            $BadFSPerfReviews += @{
                Name = $empName; Salary = $empSalary; Department = $empDept
                Title = $empTitle; Rating = $empRating; Manager = $empManager
                FilePath = $prf.FullName
            }
        }
    } catch { }
}
if ($BadFSPerfReviews.Count -gt 0) {
    Write-Log "Loaded $($BadFSPerfReviews.Count) performance reviews from BadFS CorpShares" "SUCCESS"
}

# ==============================================================================
# 3C. CROSS-REFERENCE BADIIS GENERATED ARTIFACTS
# ==============================================================================

Write-Log "Checking for BadIIS artifacts to ensure credential consistency..." "INFO"

$IISSitePath = "C:\inetpub\SpringfieldBoxFactory"
$BadIISCredentials = @{}

# Parse the web_config_backup.xml from BadIIS to ensure SQL uses the exact same credentials
$webConfigPath = "$IISSitePath\legacy_backups\web_config_backup.xml"
if (Test-Path $webConfigPath) {
    Write-Log "Found BadIIS web_config_backup.xml - extracting connection strings for consistency" "SUCCESS"
    $webConfigContent = Get-Content $webConfigPath -Raw
    # Extract credentials from connection strings that BadIIS generated
    $connStringMatches = [regex]::Matches($webConfigContent, 'User Id=([^;]+);Password=([^;]+);')
    foreach ($m in $connStringMatches) {
        $BadIISCredentials[$m.Groups[1].Value] = $m.Groups[2].Value
    }
    if ($BadIISCredentials.Count -gt 0) {
        Write-Log "Extracted $($BadIISCredentials.Count) credential pairs from BadIIS config for exact reuse" "SUCCESS"
    }
}

# Read BadIIS's service_accounts.csv if present (it lists Kerberoastable accounts)
$svcAccountsCsvPath = "$IISSitePath\it_docs\passwords\service_accounts.csv"
if (Test-Path $svcAccountsCsvPath) {
    Write-Log "Found BadIIS service_accounts.csv - will ensure SQL logins match" "SUCCESS"
}

# ==============================================================================
# 4. SQL SERVER INSTALLATION (Express)
# ==============================================================================

function Test-SqlConnection {
    param([string]$Instance, [string]$User, [string]$Pass)
    try {
        $conn = New-Object System.Data.SqlClient.SqlConnection
        $conn.ConnectionString = "Server=$Instance;User Id=$User;Password=$Pass;Connection Timeout=5;"
        $conn.Open()
        $conn.Close()
        return $true
    } catch { return $false }
}

if (-not $SkipInstall) {
    Write-Log "Checking for existing SQL Server instance..." "INFO"

    $sqlService = Get-Service -Name 'MSSQL$BADSQL' -ErrorAction SilentlyContinue
    if (-not $sqlService) {
        $sqlService = Get-Service -Name 'MSSQLSERVER' -ErrorAction SilentlyContinue
        if ($sqlService) {
            Write-Log "Found default SQL Server instance (MSSQLSERVER). Will use LOCALHOST." "SUCCESS"
            $SqlInstance = "localhost"
        }
    } else {
        Write-Log "Found named instance BADSQL." "SUCCESS"
    }

    if (-not $sqlService) {
        Write-Log "No SQL Server instance found. Downloading and installing SQL Server Express..." "WARNING"
        $installerUrl  = "https://go.microsoft.com/fwlink/p/?linkid=2216019&clcid=0x409&culture=en-us&country=us"
        $installerPath = "$env:TEMP\SqlServerExpress_Installer.exe"
        $extractPath   = "$env:TEMP\SqlExpressMedia"

        Write-Log "Downloading SQL Server Express installer..." "INFO"
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing
        } catch {
            Write-Log "Download failed: $_" "ERROR"
            Write-Log "Please download SQL Server Express manually and re-run with -SkipInstall if already installed." "WARNING"
            exit 1
        }

        Write-Log "Downloading full SQL Express media..." "INFO"
        Start-Process -FilePath $installerPath -ArgumentList "/ACTION=Download /MediaPath=$extractPath /MediaType=Core /Quiet" -Wait -NoNewWindow

        $setupExe = Get-ChildItem -Path $extractPath -Filter "SQLEXPR*.exe" -Recurse | Select-Object -First 1
        if (-not $setupExe) {
            Write-Log "Could not find SQL Express setup executable in $extractPath" "ERROR"
            exit 1
        }

        Write-Log "Installing SQL Server Express (instance: BADSQL)..." "INFO"
        $installArgs = @(
            "/ACTION=Install",
            "/FEATURES=SQLEngine,Tools",
            "/INSTANCENAME=BADSQL",
            "/SQLSVCACCOUNT=`"NT AUTHORITY\Network Service`"",
            "/SQLSYSADMINACCOUNTS=`"BUILTIN\Administrators`"",
            "/SECURITYMODE=SQL",
            "/SAPWD=`"$SqlAdminPassword`"",   # MISCONFIG: SQL mixed mode with known sa password
            "/TCPENABLED=1",
            "/BROWSERSVCSTARTUPTYPE=Automatic", # MISCONFIG: SQL Browser enabled - instance enumeration
            "/IACCEPTSQLSERVERLICENSETERMS",
            "/QUIET",
            "/INDICATEPROGRESS"
        )
        Start-Process -FilePath $setupExe.FullName -ArgumentList $installArgs -Wait -NoNewWindow
        Write-Log "SQL Server Express installed." "SUCCESS"
        $SqlInstance = "localhost\BADSQL"
    }
} else {
    Write-Log "Skipping SQL Server installation (-SkipInstall specified)." "INFO"
}

# Ensure SQL Server service is running
$sqlSvcName = if ($SqlInstance -like '*\*') { "MSSQL`$$($SqlInstance.Split('\')[1])" } else { "MSSQLSERVER" }
$sqlSvc = Get-Service -Name $sqlSvcName -ErrorAction SilentlyContinue
if ($sqlSvc -and $sqlSvc.Status -ne 'Running') {
    Write-Log "Starting SQL Server service ($sqlSvcName)..." "INFO"
    Start-Service -Name $sqlSvcName
    Start-Sleep -Seconds 5
}

# Enable SQL Browser for instance enumeration
Write-Log "Applying Misconfig: Enabling SQL Server Browser (UDP 1434 enumeration)" "VULN"
$browserSvc = Get-Service -Name 'SQLBrowser' -ErrorAction SilentlyContinue
if ($browserSvc) {
    Set-Service -Name 'SQLBrowser' -StartupType Automatic
    Start-Service -Name 'SQLBrowser' -ErrorAction SilentlyContinue
}

# Enable TCP/IP via registry (SQL Express defaults to named pipes only)
Write-Log "Enabling TCP/IP protocol on SQL instance..." "INFO"
$tcpRegPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.BADSQL\MSSQLServer\SuperSocketNetLib\Tcp"
if (-not (Test-Path $tcpRegPath)) {
    $tcpRegPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.BADSQL\MSSQLServer\SuperSocketNetLib\Tcp"
}
if (Test-Path $tcpRegPath) {
    Set-ItemProperty -Path $tcpRegPath -Name "Enabled" -Value 1 -ErrorAction SilentlyContinue
}

# Open firewall for SQL
Write-Log "Opening firewall port 1433 (SQL) and 1434 (SQL Browser)..." "INFO"
netsh advfirewall firewall add rule name="BadSQL - SQL Server" dir=in action=allow protocol=TCP localport=1433 | Out-Null
netsh advfirewall firewall add rule name="BadSQL - SQL Browser" dir=in action=allow protocol=UDP localport=1434 | Out-Null

# Restart SQL so TCP/IP takes effect
Restart-Service -Name $sqlSvcName -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 8

# ==============================================================================
# 5. SQL HELPER FUNCTIONS
# ==============================================================================

function Invoke-Sql {
    param(
        [string]$Query,
        [string]$Database = "master",
        [string]$Instance = $SqlInstance,
        [string]$User     = $SqlAdminUser,
        [string]$Pass     = $SqlAdminPassword
    )
    try {
        $conn = New-Object System.Data.SqlClient.SqlConnection
        $conn.ConnectionString = "Server=$Instance;Database=$Database;User Id=$User;Password=$Pass;Connection Timeout=10;"
        $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = $Query
        $cmd.CommandTimeout = 60
        $cmd.ExecuteNonQuery() | Out-Null
        $conn.Close()
    } catch {
        Write-Log "SQL Error on [$Database]: $_" "WARNING"
    }
}

function Invoke-SqlQuery {
    param(
        [string]$Query,
        [string]$Database = "master",
        [string]$Instance = $SqlInstance,
        [string]$User     = $SqlAdminUser,
        [string]$Pass     = $SqlAdminPassword
    )
    $results = @()
    try {
        $conn = New-Object System.Data.SqlClient.SqlConnection
        $conn.ConnectionString = "Server=$Instance;Database=$Database;User Id=$User;Password=$Pass;Connection Timeout=10;"
        $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = $Query
        $cmd.CommandTimeout = 60
        $reader = $cmd.ExecuteReader()
        while ($reader.Read()) {
            $row = @{}
            for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                $row[$reader.GetName($i)] = $reader.GetValue($i)
            }
            $results += [PSCustomObject]$row
        }
        $conn.Close()
    } catch {
        Write-Log "SQL Query Error: $_" "WARNING"
    }
    return $results
}

# Test connectivity
Write-Log "Testing SQL connectivity to $SqlInstance..." "INFO"
$connected = $false
for ($attempt = 1; $attempt -le 5; $attempt++) {
    if (Test-SqlConnection -Instance $SqlInstance -User $SqlAdminUser -Pass $SqlAdminPassword) {
        $connected = $true
        break
    }
    Write-Log "Connection attempt $attempt/5 failed. Waiting..." "WARNING"
    Start-Sleep -Seconds 6
}

if (-not $connected) {
    # Try Windows auth as fallback
    Write-Log "SQL auth failed, attempting Windows auth..." "WARNING"
    try {
        $testConn = New-Object System.Data.SqlClient.SqlConnection
        $testConn.ConnectionString = "Server=$SqlInstance;Database=master;Integrated Security=True;Connection Timeout=10;"
        $testConn.Open()
        $testConn.Close()
        # Switch to Windows auth for this session
        function Invoke-Sql {
            param([string]$Query, [string]$Database = "master")
            try {
                $conn = New-Object System.Data.SqlClient.SqlConnection
                $conn.ConnectionString = "Server=$SqlInstance;Database=$Database;Integrated Security=True;Connection Timeout=10;"
                $conn.Open()
                $cmd = $conn.CreateCommand()
                $cmd.CommandText = $Query
                $cmd.CommandTimeout = 60
                $cmd.ExecuteNonQuery() | Out-Null
                $conn.Close()
            } catch {
                Write-Log "SQL Error on [$Database]: $_" "WARNING"
            }
        }
        $connected = $true
        Write-Log "Connected via Windows auth." "SUCCESS"
    } catch {
        Write-Log "Cannot connect to SQL Server. Ensure the instance is running and accessible." "ERROR"
        Write-Log "Instance: $SqlInstance | If newly installed, try restarting the SQL service and re-running." "ERROR"
        exit 1
    }
}

Write-Log "SQL Server connection established." "SUCCESS"

# ==============================================================================
# 6. INSTANCE-LEVEL MISCONFIGURATIONS
# ==============================================================================

Write-Log "Applying instance-level security misconfigurations..." "WARNING"

# --- MISCONFIG 1: Mixed-mode authentication ---
# Enables SQL logins (not just Windows auth)
Write-Log "Applying Misconfig: Enabling mixed-mode authentication (SQL + Windows)" "VULN"
Invoke-Sql "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 2"

# --- MISCONFIG 2: Re-enable sa account with weak password ---
Write-Log "Applying Misconfig: Re-enabling sa account with known password" "VULN"
Invoke-Sql "ALTER LOGIN [sa] ENABLE"
Invoke-Sql "ALTER LOGIN [sa] WITH PASSWORD = '$SqlAdminPassword'"
Invoke-Sql "ALTER LOGIN [sa] WITH CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF"

# --- MISCONFIG 3: Enable xp_cmdshell (OS command execution from SQL) ---
Write-Log "Applying Misconfig: Enabling xp_cmdshell (OS command exec from T-SQL)" "VULN"
Invoke-Sql "EXEC sp_configure 'show advanced options', 1; RECONFIGURE"
Invoke-Sql "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE"

# --- MISCONFIG 4: Enable Ole Automation Procedures (alternate command exec) ---
Write-Log "Applying Misconfig: Enabling Ole Automation Procedures" "VULN"
Invoke-Sql "EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE"

# --- Enable ad hoc distributed queries (for linked servers via OPENROWSET) ---
Write-Log "Applying Misconfig: Enabling ad hoc distributed queries" "VULN"
Invoke-Sql "EXEC sp_configure 'Ad Hoc Distributed Queries', 1; RECONFIGURE"

# Restart SQL service to apply login mode change
Restart-Service -Name $sqlSvcName -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 8

# ==============================================================================
# 7. CREATE SQL LOGINS (INTENTIONALLY WEAK)
# ==============================================================================

Write-Log "Creating SQL logins (with intentional weaknesses)..." "INFO"

# Domain service account login (svc_sql - should be Kerberoastable)
Write-Log "Creating domain login for svc_sql service account..." "INFO"
Invoke-Sql "IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = '$DomainNB\svc_sql')
            CREATE LOGIN [$DomainNB\svc_sql] FROM WINDOWS WITH DEFAULT_DATABASE=[master]"

# --- MISCONFIG 5: Weak SQL logins matching domain weak password list ---
Write-Log "Applying Misconfig: Creating SQL logins with weak passwords matching domain theme" "VULN"

# Use credentials extracted from BadIIS web_config_backup.xml when available,
# so the passwords an attacker finds in the IIS backup actually work on SQL.
# Fall back to the same hardcoded values BadIIS would have generated.
$sqlLogins = @(
    @{ Name = "svc_webadmin"; Pass = if ($BadIISCredentials['svc_webadmin']) { $BadIISCredentials['svc_webadmin'] } else { "W3bAdm1n_$DomainNB!" } },
    @{ Name = "svc_backup";   Pass = "Backup${ThisYear}!" },
    @{ Name = "db_readonly";  Pass = if ($BadIISCredentials['db_readonly']) { $BadIISCredentials['db_readonly'] } else { "R3adOnly_Archive!" } },
    @{ Name = "db_reports";   Pass = "R3ports${ThisYear}!" },
    @{ Name = "app_timesheet";Pass = "T1mesheet1!" },
    @{ Name = "app_inventory";Pass = "Inv3ntory!" },
    @{ Name = "sql_audit";    Pass = ($WeakPasswords | Get-Random) }
)

foreach ($login in $sqlLogins) {
    Invoke-Sql @"
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = '$($login.Name)')
BEGIN
    CREATE LOGIN [$($login.Name)] WITH PASSWORD = '$($login.Pass)',
        CHECK_POLICY = OFF, CHECK_EXPIRATION = OFF, DEFAULT_DATABASE = [master]
END
"@
}

# ==============================================================================
# 8. CREATE DATABASES
# ==============================================================================

Write-Log "Creating Springfield Box Factory databases..." "INFO"

$databases = @("NailInventoryDB", "TimesheetLegacy", "BoxArchive2019", "HRConfidential", "SqlReports")

foreach ($db in $databases) {
    Write-Log "Creating database: $db" "INFO"
    Invoke-Sql "IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = '$db') CREATE DATABASE [$db]"
}

# --- MISCONFIG 6: TRUSTWORTHY = ON (privilege escalation via EXECUTE AS + db_owner → sysadmin) ---
Write-Log "Applying Misconfig: Setting TRUSTWORTHY ON for NailInventoryDB and HRConfidential" "VULN"
Invoke-Sql "ALTER DATABASE [NailInventoryDB] SET TRUSTWORTHY ON"
Invoke-Sql "ALTER DATABASE [HRConfidential] SET TRUSTWORTHY ON"

# ==============================================================================
# 9. DATABASE USERS AND PERMISSIONS
# ==============================================================================

Write-Log "Creating database users and applying intentionally permissive grants..." "INFO"

# svc_sql → db_owner on all databases (excessive privilege)
Write-Log "Applying Misconfig: Granting db_owner to svc_sql on all databases" "VULN"
Invoke-Sql "ALTER SERVER ROLE [sysadmin] ADD MEMBER [$DomainNB\svc_sql]"

foreach ($db in $databases) {
    Invoke-Sql @"
USE [$db];
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = '$DomainNB\svc_sql')
    CREATE USER [$DomainNB\svc_sql] FOR LOGIN [$DomainNB\svc_sql];
ALTER ROLE [db_owner] ADD MEMBER [$DomainNB\svc_sql];
"@

    # Also add weak SQL logins as database users
    foreach ($login in $sqlLogins) {
        Invoke-Sql @"
USE [$db];
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = '$($login.Name)')
    CREATE USER [$($login.Name)] FOR LOGIN [$($login.Name)];
"@
    }
}

# Specific permission mappings
Invoke-Sql "USE [NailInventoryDB]; ALTER ROLE [db_owner] ADD MEMBER [svc_webadmin]; ALTER ROLE [db_datareader] ADD MEMBER [app_inventory];"
Invoke-Sql "USE [TimesheetLegacy]; ALTER ROLE [db_owner] ADD MEMBER [app_timesheet]; ALTER ROLE [db_datareader] ADD MEMBER [svc_webadmin];"
Invoke-Sql "USE [BoxArchive2019];  ALTER ROLE [db_datareader] ADD MEMBER [db_readonly]; ALTER ROLE [db_datareader] ADD MEMBER [db_reports];"
Invoke-Sql "USE [HRConfidential];  ALTER ROLE [db_owner] ADD MEMBER [svc_webadmin];"
Invoke-Sql "USE [SqlReports];      ALTER ROLE [db_owner] ADD MEMBER [db_reports];"

# ==============================================================================
# 10. NailInventoryDB - MAIN OPERATIONAL DATABASE
# ==============================================================================

Write-Log "Building NailInventoryDB schema and data..." "INFO"

Invoke-Sql -Database "NailInventoryDB" @"
-- ============================================================
-- NailInventoryDB - Springfield Box Factory Nail Inventory
-- Created by: svc_sql ($DomainNB)
-- Note: svc_webadmin password is W3bAdm1n_$DomainNB! (see web_config_backup.xml)
-- ============================================================

IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'NailTypes')
CREATE TABLE NailTypes (
    NailTypeID   INT IDENTITY(1,1) PRIMARY KEY,
    TypeCode     NVARCHAR(10)  NOT NULL UNIQUE,
    Description  NVARCHAR(100) NOT NULL,
    GaugeMM      DECIMAL(5,2),
    Material     NVARCHAR(50),
    UnitCostUSD  DECIMAL(10,4),
    IsDiscontinued BIT DEFAULT 0
);

IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'Suppliers')
CREATE TABLE Suppliers (
    SupplierID   INT IDENTITY(1,1) PRIMARY KEY,
    SupplierName NVARCHAR(100) NOT NULL,
    ContactName  NVARCHAR(100),
    ContactEmail NVARCHAR(100),
    Phone        NVARCHAR(30),
    Country      NVARCHAR(50),
    ContractExpiry DATE,
    APIKey       NVARCHAR(64)   -- Stored in plaintext. Ticket #5521 open to fix.
);

IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'Inventory')
CREATE TABLE Inventory (
    InventoryID  INT IDENTITY(1,1) PRIMARY KEY,
    NailTypeID   INT NOT NULL REFERENCES NailTypes(NailTypeID),
    SupplierID   INT NOT NULL REFERENCES Suppliers(SupplierID),
    QuantityOnHand INT DEFAULT 0,
    ReorderPoint INT DEFAULT 500,
    WarehouseZone NVARCHAR(10),
    LastAuditDate DATE,
    LastAuditBy  NVARCHAR(100)
);

IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'PurchaseOrders')
CREATE TABLE PurchaseOrders (
    POID         INT IDENTITY(1,1) PRIMARY KEY,
    SupplierID   INT REFERENCES Suppliers(SupplierID),
    OrderDate    DATETIME DEFAULT GETDATE(),
    ExpectedDate DATE,
    TotalUSD     DECIMAL(12,2),
    Status       NVARCHAR(20) DEFAULT 'PENDING',
    ApprovedBy   NVARCHAR(100),
    Notes        NVARCHAR(500)
);
"@

# Populate NailTypes
Invoke-Sql -Database "NailInventoryDB" @"
IF NOT EXISTS (SELECT 1 FROM NailTypes)
INSERT INTO NailTypes (TypeCode, Description, GaugeMM, Material, UnitCostUSD) VALUES
('CLR-16D','Common Wire Nail 16d',3.76,'Bright Steel',0.0048),
('CLR-8D', 'Common Wire Nail 8d', 3.33,'Bright Steel',0.0032),
('FIN-15G','Finish Nail 15 Gauge',1.83,'Galvanized',0.0076),
('FIN-16G','Finish Nail 16 Gauge',1.65,'Galvanized',0.0068),
('BOX-10D','Box Nail 10d',3.05,'Bright Steel',0.0041),
('RFG-1.75','Roofing Nail 1.75in',3.05,'Galvanized',0.0055),
('DRW-6D', 'Drywall Nail 6d',2.67,'Hardened',0.0038),
('SID-2.5','Siding Nail 2.5in',2.87,'Galvanized',0.0062),
('COR-CLP','Corrugated Clip Nail',2.03,'Steel',0.0071),
('PNE-33D','Pneumatic Framing 33Deg',3.05,'Collated',0.0094),
('PNE-21D','Pneumatic Framing 21Deg',3.33,'Collated',0.0102),
('MISTAKE','Bent/Defective (QC Reject)',0.00,'Mixed',0.0000)
"@

# Populate Suppliers
Invoke-Sql -Database "NailInventoryDB" @"
IF NOT EXISTS (SELECT 1 FROM Suppliers)
INSERT INTO Suppliers (SupplierName, ContactName, ContactEmail, Phone, Country, ContractExpiry, APIKey) VALUES
('Acme Fastener Corp','Chuck Boltz','c.boltz@acmefastener.example','555-0101','USA','$ThisYear-12-31','$(([System.Guid]::NewGuid().ToString('N')))'),
('Springfield Steel Works','Lenny Leonard','lleonard@spfldsteel.example','555-0144','USA','$(([int]$ThisYear+1))-06-30','$(([System.Guid]::NewGuid().ToString('N')))'),
('Shelbyville Metals Inc','Nick Riviera','n.riviera@shelbymet.example','555-0199','USA','$(([int]$ThisYear+2))-03-15','$(([System.Guid]::NewGuid().ToString('N')))'),
('Globex Industrial Supply','Hank Scorpio','h.scorpio@globex.example','555-0177','USA','$ThisYear-09-01','$(([System.Guid]::NewGuid().ToString('N')))'),
('Brockway Fasteners Ltd','Clancy Wiggum','c.wiggum@brockway.example','+44-20-5550-0133','UK','$(([int]$ThisYear+1))-11-30','$(([System.Guid]::NewGuid().ToString('N')))')
"@

Invoke-Sql -Database "NailInventoryDB" @"
IF NOT EXISTS (SELECT 1 FROM Inventory)
INSERT INTO Inventory (NailTypeID, SupplierID, QuantityOnHand, ReorderPoint, WarehouseZone, LastAuditDate, LastAuditBy)
SELECT nt.NailTypeID, s.SupplierID,
       ABS(CHECKSUM(NEWID())) % 9000 + 500,
       500, 'ZONE-' + CHAR(65 + (nt.NailTypeID % 4)),
       DATEADD(day, -(ABS(CHECKSUM(NEWID())) % 90), GETDATE()),
       'svc_sql'
FROM NailTypes nt CROSS JOIN Suppliers s
WHERE nt.NailTypeID <= 6 AND s.SupplierID <= 3
"@

# ==============================================================================
# 11. NailInventoryDB - VULNERABLE STORED PROCEDURES
# ==============================================================================

Write-Log "Creating vulnerable stored procedures in NailInventoryDB..." "INFO"

# --- MISCONFIG 7: Stored procedure with EXECUTE AS OWNER (sysadmin escalation) ---
Write-Log "Applying Misconfig: Creating stored proc with EXECUTE AS OWNER for privilege escalation" "VULN"
Invoke-Sql -Database "NailInventoryDB" @"
IF OBJECT_ID('dbo.usp_SearchInventory') IS NOT NULL DROP PROCEDURE dbo.usp_SearchInventory
"@
Invoke-Sql -Database "NailInventoryDB" @"
CREATE PROCEDURE dbo.usp_SearchInventory
    @SearchTerm NVARCHAR(100)
WITH EXECUTE AS OWNER
-- Author: IT (svc_sql account, $DomainNB domain)
-- NOTE: EXECUTE AS OWNER here means this runs as dbo (which maps to sa in this context).
-- Ticket #6612: Requested by app team to allow dynamic search. Security review PENDING.
-- Temp workaround: app_inventory has EXECUTE on this proc.
AS
BEGIN
    -- WARNING: This uses dynamic SQL. Input is passed directly.
    -- SQL injection is "mitigated" by the app layer. Do not fix the proc.
    DECLARE @sql NVARCHAR(1000) = 'SELECT * FROM Inventory i
        JOIN NailTypes nt ON i.NailTypeID = nt.NailTypeID
        WHERE nt.Description LIKE ''%' + @SearchTerm + '%''
           OR nt.TypeCode LIKE ''%' + @SearchTerm + '%'''
    EXEC(@sql)
END
"@

# --- MISCONFIG 8: Stored proc that calls xp_cmdshell (direct OS access) ---
Write-Log "Applying Misconfig: Creating stored proc that wraps xp_cmdshell" "VULN"
Invoke-Sql -Database "NailInventoryDB" @"
IF OBJECT_ID('dbo.usp_ExportInventoryReport') IS NOT NULL DROP PROCEDURE dbo.usp_ExportInventoryReport
"@
Invoke-Sql -Database "NailInventoryDB" @"
CREATE PROCEDURE dbo.usp_ExportInventoryReport
    @OutputPath NVARCHAR(255) = 'C:\Reports\inventory_export.csv'
WITH EXECUTE AS OWNER
-- Created by: IT Director ($ITDirectorName) request - ticket #7001
-- This proc exports inventory to a CSV file on the server filesystem using BCP.
-- The BCP command is constructed dynamically and executed via xp_cmdshell.
-- xp_cmdshell is enabled on this instance. See sp_configure output.
-- Credentials: svc_sql / Sp1ngf!eld_SQL_${ThisYear}# (see web_config_backup.xml in IIS backups)
AS
BEGIN
    DECLARE @bcpCmd NVARCHAR(1000)
    SET @bcpCmd = 'bcp "SELECT * FROM NailInventoryDB.dbo.Inventory" queryout "' + @OutputPath + '" -T -c -t,'
    EXEC xp_cmdshell @bcpCmd
END
"@

# Grant EXECUTE on vulnerable procs to unprivileged users
Invoke-Sql -Database "NailInventoryDB" "GRANT EXECUTE ON dbo.usp_SearchInventory TO [app_inventory]"
Invoke-Sql -Database "NailInventoryDB" "GRANT EXECUTE ON dbo.usp_SearchInventory TO [svc_webadmin]"

# --- MISCONFIG 9: PUBLIC role granted SELECT on sensitive tables ---
Write-Log "Applying Misconfig: Granting PUBLIC role SELECT on all inventory tables" "VULN"
Invoke-Sql -Database "NailInventoryDB" "GRANT SELECT ON dbo.Suppliers TO [public]"
Invoke-Sql -Database "NailInventoryDB" "GRANT SELECT ON dbo.NailTypes TO [public]"
Invoke-Sql -Database "NailInventoryDB" "GRANT SELECT ON dbo.Inventory TO [public]"
Invoke-Sql -Database "NailInventoryDB" "GRANT SELECT ON dbo.PurchaseOrders TO [public]"

# ==============================================================================
# 12. TimesheetLegacy DATABASE
# ==============================================================================

Write-Log "Building TimesheetLegacy schema and data..." "INFO"

Invoke-Sql -Database "TimesheetLegacy" @"
IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'Employees')
CREATE TABLE Employees (
    EmployeeID   INT IDENTITY(1,1) PRIMARY KEY,
    ADSamAccount NVARCHAR(50),
    DisplayName  NVARCHAR(100),
    Department   NVARCHAR(50),
    Title        NVARCHAR(100),
    Email        NVARCHAR(100),
    HourlyRate   DECIMAL(8,2),
    IsActive     BIT DEFAULT 1,
    CreatedDate  DATETIME DEFAULT GETDATE()
);

IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'TimesheetEntries')
CREATE TABLE TimesheetEntries (
    EntryID      INT IDENTITY(1,1) PRIMARY KEY,
    EmployeeID   INT REFERENCES Employees(EmployeeID),
    WeekEnding   DATE,
    HoursRegular DECIMAL(5,2),
    HoursOT      DECIMAL(5,2),
    ProjectCode  NVARCHAR(20),
    SubmittedBy  NVARCHAR(50),
    ApprovedBy   NVARCHAR(50),
    ApprovalDate DATETIME,
    Notes        NVARCHAR(500)
);

IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'LegacyPasswords')
-- Legacy password table retained from the 2018 migration. Ticket #1804 to remove - STILL OPEN.
-- Contains MD5 hashes from the old TimeKeeper app. Do NOT expose to PUBLIC.
-- svc_webadmin has SELECT here because the legacy app still reads it for SSO fallback.
CREATE TABLE LegacyPasswords (
    LPwdID       INT IDENTITY(1,1) PRIMARY KEY,
    ADSamAccount NVARCHAR(50),
    LegacyHash   NVARCHAR(64),  -- MD5, unsalted
    LegacySystem NVARCHAR(50) DEFAULT 'TimeKeeper v2.1',
    MigratedDate DATE
);
"@

# Populate Employees from real AD users - using Manager relationships from AD
# (same Manager DN approach as BadFS's New-PerformanceReviewContent)
if ($ADMode -and $ADUsers.Count -gt 0) {
    Write-Log "Populating TimesheetLegacy.Employees from AD (with manager org chart)..." "INFO"

    # Add ManagerAccount column so timesheet approvals reflect real AD reporting chain
    Invoke-Sql -Database "TimesheetLegacy" @"
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('Employees') AND name = 'ManagerAccount')
    ALTER TABLE Employees ADD ManagerAccount NVARCHAR(50)
"@

    # If BadFS compensation data exists, build a lookup so hourly rates match the file share
    $compLookup = @{}
    if ($BadFSCompensationData.Count -gt 0) {
        foreach ($row in $BadFSCompensationData) {
            $key = "$($row.FirstName)_$($row.LastName)".ToLower()
            if ($row.BaseSalary) { $compLookup[$key] = [int]$row.BaseSalary }
        }
        Write-Log "Built salary lookup from BadFS compensation CSV ($($compLookup.Count) entries)" "INFO"
    }

    $empCount = 0
    foreach ($u in ($ADUsers | Select-Object -First 150)) {
        if (-not $u.SamAccountName) { continue }
        $displayName = if ($u.DisplayName) { $u.DisplayName -replace "'","''" } else { $u.SamAccountName }
        $dept        = if ($u.Department) { $u.Department -replace "'","''" } else { 'General' }
        $title       = if ($u.Title) { $u.Title -replace "'","''" } else { 'Staff' }
        $email       = if ($u.EmailAddress) { $u.EmailAddress } else { "$($u.SamAccountName)@$DomainDNS" }
        $sam         = $u.SamAccountName -replace "'","''"

        # Resolve manager from AD DN (same pattern as BadFS Section 5)
        $managerSam = 'NULL'
        if ($u.Manager) {
            $mgr = $ADUsers | Where-Object { $_.DistinguishedName -eq $u.Manager } | Select-Object -First 1
            if ($mgr) { $managerSam = "'$($mgr.SamAccountName -replace "'","''")'" }
        }

        # Derive hourly rate: prefer BadFS compensation CSV, then BadFS perf review, then estimate
        $lookupKey = "$($u.GivenName)_$($u.Surname)".ToLower()
        if ($compLookup.ContainsKey($lookupKey) -and $compLookup[$lookupKey] -gt 0) {
            # Convert annual salary from BadFS CSV to hourly (annual / 2080 hours)
            $rate = [math]::Round($compLookup[$lookupKey] / 2080, 2)
        } else {
            $perfMatch = $BadFSPerfReviews | Where-Object { $_.Name -eq $u.DisplayName } | Select-Object -First 1
            if ($perfMatch -and $perfMatch.Salary -and $perfMatch.Salary -gt 0) {
                $rate = [math]::Round($perfMatch.Salary / 2080, 2)
            } else {
                $rate = [math]::Round((Get-Random -Minimum 35000 -Maximum 145000) / 2080, 2)
            }
        }

        Invoke-Sql -Database "TimesheetLegacy" @"
IF NOT EXISTS (SELECT 1 FROM Employees WHERE ADSamAccount = '$sam')
INSERT INTO Employees (ADSamAccount, DisplayName, Department, Title, Email, HourlyRate, ManagerAccount)
VALUES ('$sam', '$displayName', '$dept', '$title', '$email', $rate, $managerSam)
"@
        $empCount++
    }
    Write-Log "Inserted $empCount employees into TimesheetLegacy (with AD manager chain)." "SUCCESS"
}

# Populate LegacyPasswords (MD5 hashes - intentionally weak / crackable)
Write-Log "Applying Misconfig: Populating LegacyPasswords table with MD5 unsalted hashes" "VULN"
$weakHashPairs = @(
    @{ Sam = "svc_webadmin"; Hash = "c4d5c2b98d9b73a0e25e02c6f5f98a7d"; Hint = "W3bAdm1n_$DomainNB!" }
    @{ Sam = "svc_backup";   Hash = "1f3870be274f6c49b3e31a0c6728957f"; Hint = "Backup${ThisYear}!" }
    @{ Sam = "db_readonly";  Hash = "7215ee9c7d9dc229d2921a40e899ec5f"; Hint = "R3adOnly_Archive!" }
    @{ Sam = "app_timesheet";Hash = "5f4dcc3b5aa765d61d8327deb882cf99"; Hint = "password (yes, really)" }
)
foreach ($pair in $weakHashPairs) {
    Invoke-Sql -Database "TimesheetLegacy" @"
IF NOT EXISTS (SELECT 1 FROM LegacyPasswords WHERE ADSamAccount = '$($pair.Sam)')
INSERT INTO LegacyPasswords (ADSamAccount, LegacyHash, MigratedDate)
VALUES ('$($pair.Sam)', '$($pair.Hash)', '2018-11-01')
"@
}

# Timesheet entries - ApprovedBy uses real AD manager chain instead of 'manager_auto'
Invoke-Sql -Database "TimesheetLegacy" @"
IF NOT EXISTS (SELECT 1 FROM TimesheetEntries)
INSERT INTO TimesheetEntries (EmployeeID, WeekEnding, HoursRegular, HoursOT, ProjectCode, SubmittedBy, ApprovedBy, ApprovalDate)
SELECT TOP 500
    e.EmployeeID,
    DATEADD(day, -(ABS(CHECKSUM(NEWID())) % 180), GETDATE()),
    40.0,
    ABS(CHECKSUM(NEWID())) % 10,
    'PRJ-' + RIGHT('000' + CAST(ABS(CHECKSUM(NEWID())) % 50 AS NVARCHAR), 3),
    e.ADSamAccount,
    ISNULL(e.ManagerAccount, e.ADSamAccount),
    DATEADD(day, 2, DATEADD(day, -(ABS(CHECKSUM(NEWID())) % 180), GETDATE()))
FROM Employees e
CROSS JOIN (SELECT TOP 5 1 AS x FROM sys.objects) r
ORDER BY NEWID()
"@

# Grant PUBLIC access to LegacyPasswords (intentional!)
Write-Log "Applying Misconfig: Granting PUBLIC SELECT on LegacyPasswords (MD5 hash exposure)" "VULN"
Invoke-Sql -Database "TimesheetLegacy" "GRANT SELECT ON dbo.LegacyPasswords TO [public]"
Invoke-Sql -Database "TimesheetLegacy" "GRANT SELECT ON dbo.Employees TO [public]"
Invoke-Sql -Database "TimesheetLegacy" "GRANT SELECT ON dbo.TimesheetEntries TO [public]"

# ==============================================================================
# 13. HRConfidential DATABASE
# ==============================================================================

Write-Log "Building HRConfidential schema and data..." "INFO"

Invoke-Sql -Database "HRConfidential" @"
IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'EmployeeSalaries')
CREATE TABLE EmployeeSalaries (
    SalaryID     INT IDENTITY(1,1) PRIMARY KEY,
    ADSamAccount NVARCHAR(50),
    DisplayName  NVARCHAR(100),
    Department   NVARCHAR(50),
    Title        NVARCHAR(100),
    AnnualSalary DECIMAL(12,2),
    BonusPct     DECIMAL(5,2),
    ReviewDate   DATE,
    ManagerAccount NVARCHAR(50),
    Notes        NVARCHAR(500)
);

IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'Disciplinary')
CREATE TABLE Disciplinary (
    RecordID     INT IDENTITY(1,1) PRIMARY KEY,
    ADSamAccount NVARCHAR(50),
    IncidentDate DATE,
    Category     NVARCHAR(50),  -- e.g. 'PIP', 'Written Warning', 'Termination'
    Description  NVARCHAR(1000),
    HROfficer    NVARCHAR(100),
    IsExpunged   BIT DEFAULT 0
);

IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'BackgroundChecks')
CREATE TABLE BackgroundChecks (
    CheckID      INT IDENTITY(1,1) PRIMARY KEY,
    ADSamAccount NVARCHAR(50),
    CheckDate    DATE,
    Vendor       NVARCHAR(100),
    SSN_Last4    NVARCHAR(4),
    DOB          DATE,
    Result       NVARCHAR(20),  -- PASS / FAIL / PENDING
    CriminalFlags NVARCHAR(200)
);
"@

# Populate salary data from AD users, cross-referencing BadFS compensation and perf reviews
# so the data in SQL matches what's sitting on the file share (realistic data consistency)
if ($ADMode -and $ADUsers.Count -gt 0) {
    Write-Log "Populating HRConfidential salary data from AD + BadFS cross-reference..." "INFO"

    # Build lookup from BadFS compensation CSV (same data in \\server\CorpData\Public_Company_Data\)
    $fsCompLookup = @{}
    foreach ($row in $BadFSCompensationData) {
        $key = "$($row.FirstName)_$($row.LastName)".ToLower()
        if ($row.BaseSalary -and $row.BonusTarget) {
            $fsCompLookup[$key] = @{ Salary = [int]$row.BaseSalary; Bonus = [int]($row.BonusTarget -replace '%','') }
        }
    }

    # Build lookup from BadFS performance reviews (files in CorpShares\Users\{sam}\)
    $fsPerfLookup = @{}
    foreach ($pr in $BadFSPerfReviews) {
        if ($pr.Name -and $pr.Salary) { $fsPerfLookup[$pr.Name] = $pr }
    }

    $discCategories = @('Written Warning','Verbal Warning','PIP','Final Warning')
    # Use real HR leadership from AD for HR officer field
    $hrUsers = $ADUsers | Where-Object { $_.Department -match 'HR' -or $_.Title -match 'HR|Human Resources' } | Select-Object -First 5
    $hrOfficers = if ($hrUsers.Count -gt 0) {
        $hrUsers | ForEach-Object { $_.EmailAddress }
    } else {
        @('hr_admin@' + $DomainDNS, 'helpdesk@' + $DomainDNS)
    }

    foreach ($u in ($ADUsers | Select-Object -First 100)) {
        if (-not $u.SamAccountName) { continue }
        $displayName = if ($u.DisplayName) { $u.DisplayName -replace "'","''" } else { $u.SamAccountName }
        $dept  = if ($u.Department) { $u.Department -replace "'","''" } else { 'General' }
        $title = if ($u.Title) { $u.Title -replace "'","''" } else { 'Staff' }
        $sam   = $u.SamAccountName -replace "'","''"

        # Resolve manager from AD for the ManagerAccount column
        $managerSam = $null
        if ($u.Manager) {
            $mgr = $ADUsers | Where-Object { $_.DistinguishedName -eq $u.Manager } | Select-Object -First 1
            if ($mgr) { $managerSam = $mgr.SamAccountName -replace "'","''" }
        }
        $mgrValue = if ($managerSam) { "'$managerSam'" } else { "NULL" }

        # Priority chain for salary: BadFS comp CSV > BadFS perf review > random range
        $lookupKey = "$($u.GivenName)_$($u.Surname)".ToLower()
        $perfMatch = $fsPerfLookup[$u.DisplayName]

        if ($fsCompLookup.ContainsKey($lookupKey)) {
            $salary = $fsCompLookup[$lookupKey].Salary
            $bonus  = $fsCompLookup[$lookupKey].Bonus
        } elseif ($perfMatch -and $perfMatch.Salary) {
            $salary = $perfMatch.Salary
            $bonus  = [math]::Round((Get-Random -Minimum 3 -Maximum 20), 2)
        } else {
            $salary = Get-Random -Minimum 45000 -Maximum 185000
            $bonus  = [math]::Round((Get-Random -Minimum 3 -Maximum 20), 2)
        }

        # Add note cross-referencing the BadFS file share and perf review if they exist
        $noteVal = ''
        if ($perfMatch) {
            $noteVal = "Perf review on file share: $($perfMatch.FilePath -replace "'","''" -replace '\\','/') | Rating: $($perfMatch.Rating)/5"
        }

        Invoke-Sql -Database "HRConfidential" @"
IF NOT EXISTS (SELECT 1 FROM EmployeeSalaries WHERE ADSamAccount = '$sam')
INSERT INTO EmployeeSalaries (ADSamAccount, DisplayName, Department, Title, AnnualSalary, BonusPct, ReviewDate, ManagerAccount, Notes)
VALUES ('$sam', '$displayName', '$dept', '$title', $salary, $bonus, '$(Get-Date -Format 'yyyy')-04-01', $mgrValue, '$noteVal')
"@
        # 8% chance of a disciplinary record
        if ((Get-Random -Min 1 -Max 13) -eq 1) {
            $cat = $discCategories | Get-Random
            $hro = ($hrOfficers | Get-Random) -replace "'","''"
            Invoke-Sql -Database "HRConfidential" @"
INSERT INTO Disciplinary (ADSamAccount, IncidentDate, Category, Description, HROfficer)
VALUES ('$sam', DATEADD(day, -$(Get-Random -Min 30 -Max 730), GETDATE()),
        '$cat', 'Performance / conduct issue per manager escalation. See personnel file on \\$env:COMPUTERNAME\CorpData\Users\$sam\',
        '$hro')
"@
        }
    }

    # Background checks - cross-reference SSN from BadFS comp CSV when available
    foreach ($u in ($ADUsers | Select-Object -First 80)) {
        if (-not $u.SamAccountName) { continue }
        $sam = $u.SamAccountName -replace "'","''"
        # If BadFS comp CSV has an SSN for this user, use the same last 4 digits
        $lookupKey = "$($u.GivenName)_$($u.Surname)".ToLower()
        $fsRow = $BadFSCompensationData | Where-Object { "$($_.FirstName)_$($_.LastName)".ToLower() -eq $lookupKey } | Select-Object -First 1
        if ($fsRow -and $fsRow.SSN -and $fsRow.SSN -match '(\d{4})$') {
            $ssn4 = $Matches[1]
        } else {
            $ssn4 = Get-Random -Minimum 1000 -Maximum 9999
        }
        $dob = Get-Date (Get-Date).AddYears(-(Get-Random -Min 25 -Max 55)).AddDays(-(Get-Random -Min 0 -Max 365)) -Format 'yyyy-MM-dd'
        Invoke-Sql -Database "HRConfidential" @"
IF NOT EXISTS (SELECT 1 FROM BackgroundChecks WHERE ADSamAccount = '$sam')
INSERT INTO BackgroundChecks (ADSamAccount, CheckDate, Vendor, SSN_Last4, DOB, Result)
VALUES ('$sam', DATEADD(day, -$(Get-Random -Min 180 -Max 1800), GETDATE()),
        'Sterling Background Corp', '$ssn4', '$dob', 'PASS')
"@
    }
}

# --- MISCONFIG 10: PUBLIC can SELECT salary data ---
Write-Log "Applying Misconfig: Granting PUBLIC SELECT on HRConfidential.EmployeeSalaries" "VULN"
Invoke-Sql -Database "HRConfidential" "GRANT SELECT ON dbo.EmployeeSalaries TO [public]"

# svc_webadmin can read everything in HRConfidential (IIS app runs as this account)
Invoke-Sql -Database "HRConfidential" "GRANT SELECT ON dbo.Disciplinary TO [svc_webadmin]"
Invoke-Sql -Database "HRConfidential" "GRANT SELECT ON dbo.BackgroundChecks TO [svc_webadmin]"

# ==============================================================================
# 14. BoxArchive2019 DATABASE
# ==============================================================================

Write-Log "Building BoxArchive2019 schema and data..." "INFO"

Invoke-Sql -Database "BoxArchive2019" @"
IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'ArchivedOrders')
CREATE TABLE ArchivedOrders (
    OrderID      INT IDENTITY(1,1) PRIMARY KEY,
    CustomerName NVARCHAR(100),
    OrderDate    DATE,
    BoxType      NVARCHAR(50),
    Quantity     INT,
    UnitPriceUSD DECIMAL(8,2),
    TotalUSD     DECIMAL(12,2),
    ShippedDate  DATE,
    SalesRep     NVARCHAR(100),
    Region       NVARCHAR(30)
);

IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'OldConnectionStrings')
-- Archived connection strings table retained from migration. CFO ($CFOName) approved retention.
-- This data is used for quarterly archive reporting. db_readonly has SELECT.
CREATE TABLE OldConnectionStrings (
    ConnID       INT IDENTITY(1,1) PRIMARY KEY,
    AppName      NVARCHAR(100),
    ConnString   NVARCHAR(500),
    Environment  NVARCHAR(20),
    ArchivedDate DATE,
    ArchivedBy   NVARCHAR(50)
);
"@

# Use real AD users from BDE (Business Development) department as sales reps
$salesReps = @()
if ($ADMode) {
    $bdeUsers = $ADUsers | Where-Object { $_.Department -match 'BDE|Sales|Business' } | Select-Object -First 12
    if ($bdeUsers.Count -gt 0) {
        $salesReps = $bdeUsers | ForEach-Object { $_.DisplayName -replace "'","''" }
    }
}
if ($salesReps.Count -eq 0) { $salesReps = @('SalesRep_1','SalesRep_2','SalesRep_3','SalesRep_4','SalesRep_5') }

# Build the SalesRep CASE statement dynamically from real AD users
$repCases = ""
for ($r = 0; $r -lt [Math]::Min($salesReps.Count, 12); $r++) {
    $repCases += "WHEN $r THEN '$($salesReps[$r])' "
}

# Use real AD office locations for region if available
$regionValues = @('Midwest','Northeast','South','West')
if ($ADMode) {
    $adOffices = $ADUsers | Where-Object { $_.Office } | Select-Object -ExpandProperty Office -Unique | Select-Object -First 6
    if ($adOffices.Count -ge 2) { $regionValues = $adOffices }
}
$regionCases = ""
for ($r = 0; $r -lt $regionValues.Count; $r++) {
    $regionCases += "WHEN $r THEN '$($regionValues[$r] -replace "'","''")' "
}

Invoke-Sql -Database "BoxArchive2019" @"
IF NOT EXISTS (SELECT 1 FROM ArchivedOrders)
BEGIN
    DECLARE @i INT = 0
    WHILE @i < 500
    BEGIN
        INSERT INTO ArchivedOrders (CustomerName, OrderDate, BoxType, Quantity, UnitPriceUSD, TotalUSD, ShippedDate, SalesRep, Region)
        VALUES (
            CASE (@i % 8)
                WHEN 0 THEN 'Acme Roadrunner Supplies'
                WHEN 1 THEN 'Shelbyville Paper Co'
                WHEN 2 THEN 'Globex Export LLC'
                WHEN 3 THEN 'Brockway Industries'
                WHEN 4 THEN 'Ogdenville Crafts'
                WHEN 5 THEN 'Capital City Logistics'
                WHEN 6 THEN 'North Haverbrook Depot'
                ELSE 'Springfield Hardware Hub'
            END,
            DATEADD(day, -(@i * 3 + ABS(CHECKSUM(NEWID())) % 90), '2019-12-31'),
            CASE (@i % 5)
                WHEN 0 THEN 'Finisher Box'
                WHEN 1 THEN 'Standard Corrugated'
                WHEN 2 THEN 'Heavy Duty Double Wall'
                WHEN 3 THEN 'Mailer Box'
                ELSE 'The Mistake (QC Reject)'
            END,
            (ABS(CHECKSUM(NEWID())) % 500) + 10,
            ROUND(2.50 + (ABS(CHECKSUM(NEWID())) % 20), 2),
            ROUND(((ABS(CHECKSUM(NEWID())) % 500) + 10) * (2.50 + (ABS(CHECKSUM(NEWID())) % 20)), 2),
            DATEADD(day, ABS(CHECKSUM(NEWID())) % 7, DATEADD(day, -(@i * 3 + ABS(CHECKSUM(NEWID())) % 90), '2019-12-31')),
            CASE (@i % $($salesReps.Count)) $repCases ELSE '$($salesReps[0])' END,
            CASE (@i % $($regionValues.Count)) $regionCases ELSE '$($regionValues[0] -replace "'","''")' END
        )
        SET @i = @i + 1
    END
END
"@

# Hardcoded old connection strings (like a real stale database)
Invoke-Sql -Database "BoxArchive2019" @"
IF NOT EXISTS (SELECT 1 FROM OldConnectionStrings)
INSERT INTO OldConnectionStrings (AppName, ConnString, Environment, ArchivedDate, ArchivedBy) VALUES
('TimeKeeper v2.1',  'Server=$SqlServer;Database=TimesheetLegacy;User Id=app_timesheet;Password=T1mesheet1!;', 'PROD', '2020-01-15', 'svc_sql'),
('BoxTracker 3.0',   'Server=$SqlServer;Database=NailInventoryDB;User Id=app_inventory;Password=Inv3ntory!;', 'PROD', '2020-01-15', 'svc_sql'),
('HR Portal (old)',  'Server=$SqlServer;Database=HRConfidential;User Id=svc_webadmin;Password=W3bAdm1n_$DomainNB!;', 'PROD', '2020-01-15', 'svc_sql'),
('Reporting Legacy', 'Server=$SqlServer;Database=SqlReports;User Id=db_reports;Password=R3ports${ThisYear}!;', 'PROD', '2020-01-15', 'svc_sql'),
('LDAP Auth',        'LDAP://$PDC/$DomainDN', 'PROD', '2020-01-15', 'svc_sql')
"@

Invoke-Sql -Database "BoxArchive2019" "GRANT SELECT ON dbo.ArchivedOrders TO [db_readonly]"
Invoke-Sql -Database "BoxArchive2019" "GRANT SELECT ON dbo.OldConnectionStrings TO [db_readonly]"

# --- PUBLIC can see OldConnectionStrings (credentials in plaintext) ---
Write-Log "Applying Misconfig: Granting PUBLIC SELECT on OldConnectionStrings (plaintext creds)" "VULN"
Invoke-Sql -Database "BoxArchive2019" "GRANT SELECT ON dbo.OldConnectionStrings TO [public]"

# ==============================================================================
# 15. SqlReports DATABASE + LINKED SERVER
# ==============================================================================

Write-Log "Building SqlReports database..." "INFO"

Invoke-Sql -Database "SqlReports" @"
IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'ReportDefinitions')
CREATE TABLE ReportDefinitions (
    ReportID     INT IDENTITY(1,1) PRIMARY KEY,
    ReportName   NVARCHAR(100),
    SourceDB     NVARCHAR(50),
    SourceQuery  NVARCHAR(2000),
    ScheduleCron NVARCHAR(50),
    LastRunDate  DATETIME,
    LastRunBy    NVARCHAR(50),
    OutputPath   NVARCHAR(255),
    IsActive     BIT DEFAULT 1
);
"@

Invoke-Sql -Database "SqlReports" @"
IF NOT EXISTS (SELECT 1 FROM ReportDefinitions)
INSERT INTO ReportDefinitions (ReportName, SourceDB, SourceQuery, ScheduleCron, LastRunDate, LastRunBy, OutputPath) VALUES
('Weekly Nail Inventory','NailInventoryDB','SELECT * FROM Inventory JOIN NailTypes ON Inventory.NailTypeID = NailTypes.NailTypeID','0 6 * * MON',DATEADD(day,-7,GETDATE()),'svc_sql','C:\Reports\inventory_weekly.csv'),
('Monthly Payroll Summary','TimesheetLegacy','SELECT Department, SUM(HoursRegular*40) as GrossApprox FROM TimesheetEntries te JOIN Employees e ON te.EmployeeID=e.EmployeeID GROUP BY Department','0 6 1 * *',DATEADD(day,-30,GETDATE()),'svc_sql','C:\Reports\payroll_monthly.csv'),
('HR Salary Audit','HRConfidential','SELECT DisplayName, Department, AnnualSalary, BonusPct FROM EmployeeSalaries ORDER BY AnnualSalary DESC','0 6 1 1 *',DATEADD(day,-90,GETDATE()),'svc_sql','C:\Reports\salary_audit.csv'),
('Archive Order History','BoxArchive2019','SELECT * FROM ArchivedOrders WHERE OrderDate >= DATEADD(year,-1,GETDATE())','0 6 * * SUN',DATEADD(day,-14,GETDATE()),'svc_sql','C:\Reports\archive_orders.csv')
"@

# --- MISCONFIG 11: Linked server with saved credentials ---
Write-Log "Applying Misconfig: Creating linked server with saved plaintext credentials" "VULN"
Invoke-Sql @"
IF NOT EXISTS (SELECT 1 FROM sys.servers WHERE name = 'SBFARCHIVE')
BEGIN
    EXEC sp_addlinkedserver
        @server     = N'SBFARCHIVE',
        @srvproduct = N'SQL Server',
        @provider   = N'SQLNCLI',
        @datasrc    = N'$SqlServer\ARCHIVE'

    EXEC sp_addlinkedsrvlogin
        @rmtsrvname  = N'SBFARCHIVE',
        @useself     = N'FALSE',
        @locallogin  = NULL,
        @rmtuser     = N'db_readonly',
        @rmtpassword = N'R3adOnly_Archive!'
    -- MISCONFIG: Saved credentials for linked server stored in sys.linked_logins (readable by sysadmin).
    -- db_readonly password is R3adOnly_Archive! - also appears in web_config_backup.xml.
END
"@

# ==============================================================================
# 16. SQL SERVER AGENT JOBS (INTENTIONALLY PRIVILEGED)
# ==============================================================================

Write-Log "Creating SQL Agent jobs with privileged execution contexts..." "INFO"

# Ensure SQL Agent is running
$agentSvcName = if ($SqlInstance -like '*\*') { "SQLAGENT`$$($SqlInstance.Split('\')[1])" } else { "SQLSERVERAGENT" }
$agentSvc = Get-Service -Name $agentSvcName -ErrorAction SilentlyContinue
if ($agentSvc) {
    Set-Service -Name $agentSvcName -StartupType Automatic
    Start-Service -Name $agentSvcName -ErrorAction SilentlyContinue
}

# --- MISCONFIG 12: SQL Agent job running xp_cmdshell as sa ---
Write-Log "Applying Misconfig: Creating SQL Agent job that runs OS commands as sa" "VULN"
Invoke-Sql @"
USE [msdb];
IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = 'SBF - Nightly Inventory Export')
BEGIN
    EXEC sp_add_job
        @job_name        = N'SBF - Nightly Inventory Export',
        @enabled         = 1,
        @description     = N'Exports nail inventory to CSV. Runs as sa. Approved by $ITDirectorName.',
        @owner_login_name= N'sa'

    EXEC sp_add_jobstep
        @job_name    = N'SBF - Nightly Inventory Export',
        @step_name   = N'Export via xp_cmdshell',
        @subsystem   = N'TSQL',
        @command     = N'EXEC NailInventoryDB.dbo.usp_ExportInventoryReport @OutputPath = ''C:\Reports\inventory_nightly.csv''',
        @on_success_action = 1

    EXEC sp_add_schedule
        @schedule_name   = N'Nightly 02:30',
        @freq_type       = 4,
        @freq_interval   = 1,
        @active_start_time = 023000

    EXEC sp_attach_schedule
        @job_name     = N'SBF - Nightly Inventory Export',
        @schedule_name= N'Nightly 02:30'

    EXEC sp_add_jobserver
        @job_name = N'SBF - Nightly Inventory Export',
        @server_name = N'(local)'
END
"@

Invoke-Sql @"
USE [msdb];
IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = 'SBF - HR Report Weekly')
BEGIN
    EXEC sp_add_job
        @job_name        = N'SBF - HR Report Weekly',
        @enabled         = 1,
        @description     = N'HR salary report. Owner: $CFOName. Service account: svc_sql. Password: Sp1ngf!eld_SQL_${ThisYear}#',
        @owner_login_name= N'sa'

    EXEC sp_add_jobstep
        @job_name    = N'SBF - HR Report Weekly',
        @step_name   = N'Query HR and export',
        @subsystem   = N'TSQL',
        @command     = N'EXEC xp_cmdshell ''bcp "SELECT * FROM HRConfidential.dbo.EmployeeSalaries" queryout C:\Reports\salary_weekly.csv -T -c -t,''',
        @on_success_action = 1

    EXEC sp_add_jobserver
        @job_name = N'SBF - HR Report Weekly',
        @server_name = N'(local)'
END
"@

# ==============================================================================
# 17. CREATE REPORTS DIRECTORY + OUTPUT ARTIFACTS
# ==============================================================================

Write-Log "Creating reports output directory and SQL-related files..." "INFO"

$reportsPath = "C:\Reports"
if (-not (Test-Path $reportsPath)) {
    New-Item -ItemType Directory -Path $reportsPath -Force | Out-Null
}

# Reports readme (exposed via IIS if /it_docs/ links added)
$reportsReadme = @"
SPRINGFIELD BOX FACTORY - SQL REPORTS OUTPUT
=============================================
Instance: $SqlInstance
Database: SqlReports (also queries NailInventoryDB, HRConfidential, TimesheetLegacy)
Service Account: $DomainNB\svc_sql
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

REPORT FILES IN THIS DIRECTORY:
  inventory_nightly.csv   - Generated by SQL Agent job 'SBF - Nightly Inventory Export'
  salary_weekly.csv       - HR salary data (confidential - $CFOName approved access)
  payroll_monthly.csv     - Payroll summary by department
  archive_orders.csv      - Box order archive export

ACCESS:
  SQL Instance: $SqlInstance (TCP 1433)
  sa password: See web_config_backup.xml in IIS legacy_backups folder.
  svc_sql SPN: MSSQLSvc/$PDC`:1433 (Kerberoastable - see kerberoastable_accounts.txt)

NOTES:
  xp_cmdshell is ENABLED on this instance per $ITDirectorName request (ticket #7001).
  TRUSTWORTHY is ON for NailInventoryDB and HRConfidential - security review pending.
  Linked server SBFARCHIVE configured with saved credentials (db_readonly / R3adOnly_Archive!).
"@
Set-Content -Path "$reportsPath\README.txt" -Value $reportsReadme

# SQL configuration file (like a DBA left it around)
$sqlConfig = @"
; Springfield Box Factory - SQL Instance Config Notes
; DBA: IT Infrastructure Team | Domain: $DomainDNS
; Last updated: $(Get-Date -Format 'yyyy-MM-dd')

[instance]
name     = $SqlInstance
version  = SQL Server Express
auth     = Mixed (SQL + Windows)
tcp_port = 1433
browser  = Enabled (UDP 1434)

[service_account]
account  = $DomainNB\svc_sql
spn      = MSSQLSvc/$PDC`:1433
spn_note = Kerberoastable - service account password set at install, never rotated.

[sa_account]
enabled  = YES
password = Sp1ngf!eld_SQL_${ThisYear}#
policy   = CHECK_POLICY=OFF, CHECK_EXPIRATION=OFF

[features_enabled]
xp_cmdshell                = YES  (ticket #7001 - app requirement)
ole_automation_procedures  = YES
ad_hoc_distributed_queries = YES
trustworthy_databases      = NailInventoryDB, HRConfidential

[linked_servers]
SBFARCHIVE = $SqlServer\ARCHIVE (db_readonly / R3adOnly_Archive!)

[databases]
NailInventoryDB   = Operational inventory. TRUSTWORTHY=ON.
TimesheetLegacy   = Timesheet system. Contains LegacyPasswords table (MD5).
HRConfidential    = Salary, disciplinary, background check data. TRUSTWORTHY=ON.
BoxArchive2019    = Pre-2020 archive. OldConnectionStrings table has plaintext creds.
SqlReports        = Reporting DB. Agent jobs run as sa.
"@
Set-Content -Path "$reportsPath\sql_instance_config.ini" -Value $sqlConfig

# ==============================================================================
# 18. IIS INTEGRATION - SQL docs + WEB FRONT-ENDS for inventory & timesheet
# ==============================================================================
# BadIIS creates the main corporate site. BadSQL adds:
#   /apps/inventory/  - Nail Inventory Lookup (SQL injection via usp_SearchInventory)
#   /apps/timesheet/  - Timesheet Viewer (leaks employee data, hardcoded connection string)
#   /it_docs/sql/     - SQL documentation (DBA carelessly left in web root)
# All content uses real data from the databases we just populated.

Write-Log "Checking for BadIIS (SpringfieldBoxFactory) site to deploy SQL web apps..." "INFO"

$iisBasePath = "C:\inetpub\SpringfieldBoxFactory"
if (Test-Path $iisBasePath) {
    Write-Log "BadIIS site found. Deploying SQL-backed web applications..." "SUCCESS"

    # Build the password strings that match what BadIIS generated (or our defaults)
    $svcWebadminPass = if ($BadIISCredentials['svc_webadmin']) { $BadIISCredentials['svc_webadmin'] } else { "W3bAdm1n_$DomainNB!" }
    $appInventoryPass = "Inv3ntory!"
    $appTimesheetPass = "T1mesheet1!"

    # --- Create directory structure ---
    $appDirs = @(
        "$iisBasePath\apps",
        "$iisBasePath\apps\inventory",
        "$iisBasePath\apps\timesheet",
        "$iisBasePath\it_docs\sql"
    )
    foreach ($dir in $appDirs) {
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    }

    # ===================================================================
    # 18A. NAIL INVENTORY LOOKUP - SQL-injection-vulnerable search form
    # ===================================================================
    # MISCONFIG: Connection string hardcoded in HTML comment. Search param
    # is passed directly to usp_SearchInventory (dynamic SQL, no sanitization).

    Write-Log "Deploying Nail Inventory Lookup web app (/apps/inventory/)" "INFO"
    Write-Log "Applying Misconfig: Inventory app has SQL injection via search form" "VULN"

    # Build a real inventory HTML table from the DB data for the default view
    $inventoryRows = ""
    if ($ADMode) {
        # We'll embed a static snapshot so the page works without ASP.NET
        $invData = Invoke-SqlQuery -Database "NailInventoryDB" "SELECT TOP 20 nt.TypeCode, nt.Description, nt.GaugeMM, nt.Material, nt.UnitCostUSD, i.QuantityOnHand, i.WarehouseZone, s.SupplierName FROM Inventory i JOIN NailTypes nt ON i.NailTypeID = nt.NailTypeID JOIN Suppliers s ON i.SupplierID = s.SupplierID ORDER BY nt.TypeCode"
        foreach ($row in $invData) {
            $inventoryRows += "<tr><td>$($row.TypeCode)</td><td>$($row.Description)</td><td>$($row.GaugeMM)</td><td>$($row.Material)</td><td>`$$($row.UnitCostUSD)</td><td>$($row.QuantityOnHand)</td><td>$($row.WarehouseZone)</td><td>$($row.SupplierName)</td></tr>`n"
        }
    }
    if (-not $inventoryRows) {
        $inventoryRows = "<tr><td colspan='8'>No data loaded - connect to $SqlInstance to query NailInventoryDB</td></tr>"
    }

    $inventoryHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>SBF Nail Inventory - Internal</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #fdf5e6; color: #333; margin: 0; }
        header { background: #5c4033; color: #fff; padding: 20px; text-align: center; border-bottom: 4px solid #8b5a2b; }
        header h1 { margin: 0; font-size: 1.8em; }
        header p { color: #e6ca9c; font-style: italic; margin: 5px 0 0; }
        nav { background: #8b5a2b; padding: 10px; text-align: center; }
        nav a { color: #fff; text-decoration: none; margin: 0 15px; font-weight: bold; }
        nav a:hover { text-decoration: underline; }
        .container { max-width: 1100px; margin: 30px auto; padding: 30px; background: #fff; border: 2px solid #8b5a2b; border-radius: 6px; }
        h2 { color: #5c4033; border-bottom: 2px solid #8b5a2b; padding-bottom: 8px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th { background: #5c4033; color: #fff; padding: 10px; text-align: left; }
        td { padding: 8px 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f0e0; }
        .search-box { margin: 20px 0; padding: 20px; background: #f4f4f4; border: 1px solid #ccc; border-radius: 4px; }
        .search-box input[type=text] { padding: 8px 12px; width: 300px; font-size: 14px; border: 1px solid #8b5a2b; }
        .search-box input[type=submit] { padding: 8px 20px; background: #5c4033; color: #fff; border: none; cursor: pointer; font-size: 14px; }
        .alert { background: #ffcccc; border-left: 6px solid #8b0000; padding: 12px; margin: 15px 0; color: #8b0000; }
        .code-block { background: #272822; color: #f8f8f2; padding: 12px; border-radius: 4px; overflow-x: auto; white-space: pre; font-family: 'Courier New', monospace; font-size: 13px; }
        footer { text-align: center; padding: 15px; background: #5c4033; color: #fff; margin-top: 40px; }
    </style>
</head>
<body>
<header>
    <h1>Springfield Box Factory - Nail Inventory System</h1>
    <p>"If it's not nailed down, we probably sold the nail."</p>
</header>
<nav>
    <a href="/">Home</a>
    <a href="/apps/inventory/">Inventory</a>
    <a href="/apps/timesheet/">Timesheets</a>
    <a href="/portal/">Portal</a>
</nav>
<div class="container">
    <h2>Inventory Lookup</h2>

    <div class="search-box">
        <p><strong>Search Nail Types:</strong> Enter a type code or description keyword.</p>
        <!-- MISCONFIG: This form sends the search term directly to a stored procedure that uses
             dynamic SQL concatenation (usp_SearchInventory). The proc does NOT parameterize input.
             See: /it_docs/sql/dev_sql_notes.txt for proof-of-concept injection strings. -->
        <form method="GET" action="/apps/inventory/">
            <input type="text" name="search" placeholder="e.g. CLR, Roofing, Finish..." value="">
            <input type="submit" value="Search">
        </form>
        <p style="font-size:11px;color:#999;">Query runs as app_inventory against $SqlInstance &mdash; NailInventoryDB</p>
    </div>

    <!-- Connection string for the app (developer left this in a comment for "debugging") -->
    <!-- DB: Server=$SqlInstance;Database=NailInventoryDB;User Id=app_inventory;Password=$appInventoryPass; -->
    <!-- EXEC usp_SearchInventory @SearchTerm = '<USER_INPUT_HERE>' -->
    <!-- TODO: Remove before production. Also the proc is injectable. Ticket #6612 filed. -->

    <table>
        <thead>
            <tr><th>Type</th><th>Description</th><th>Gauge (mm)</th><th>Material</th><th>Unit Cost</th><th>Qty On Hand</th><th>Zone</th><th>Supplier</th></tr>
        </thead>
        <tbody>
$inventoryRows
        </tbody>
    </table>

    <div class="alert">
        <strong>Note:</strong> This is a read-only snapshot. For live queries, connect to
        <strong>$SqlInstance</strong> using the <code>app_inventory</code> account.
        See <a href="/it_docs/sql/">/it_docs/sql/</a> for connection details.
    </div>

    <h3>Quick Reference: SQL Connection</h3>
    <div class="code-block">Server=$SqlInstance
Database=NailInventoryDB
User Id=app_inventory  (has EXECUTE on usp_SearchInventory)
-- For full access use: svc_webadmin / see web_config_backup.xml</div>
</div>
<footer>&copy; Springfield Box Factory &mdash; Internal Use Only &mdash; $DomainDNS</footer>
</body>
</html>
"@
    Set-Content -Path "$iisBasePath\apps\inventory\index.html" -Value $inventoryHtml

    # ===================================================================
    # 18B. TIMESHEET VIEWER - leaks employee data + hardcoded creds
    # ===================================================================
    # MISCONFIG: Page embeds real employee names/departments/hourly rates from the DB.
    # Connection string in HTML source. Links directly to TimesheetLegacy data.

    Write-Log "Deploying Timesheet Viewer web app (/apps/timesheet/)" "INFO"
    Write-Log "Applying Misconfig: Timesheet app leaks employee PII and embeds SQL credentials" "VULN"

    # Build real employee table from TimesheetLegacy
    $tsRows = ""
    if ($ADMode) {
        $empData = Invoke-SqlQuery -Database "TimesheetLegacy" "SELECT TOP 30 e.ADSamAccount, e.DisplayName, e.Department, e.Title, e.HourlyRate, e.ManagerAccount, (SELECT TOP 1 te.WeekEnding FROM TimesheetEntries te WHERE te.EmployeeID = e.EmployeeID ORDER BY te.WeekEnding DESC) AS LastTimesheet FROM Employees e WHERE e.IsActive = 1 ORDER BY e.Department, e.DisplayName"
        foreach ($row in $empData) {
            $lastTs = if ($row.LastTimesheet) { ([datetime]$row.LastTimesheet).ToString('yyyy-MM-dd') } else { 'N/A' }
            $mgrDisplay = if ($row.ManagerAccount -and $row.ManagerAccount -ne [DBNull]::Value) { $row.ManagerAccount } else { '-' }
            $tsRows += "<tr><td>$($row.ADSamAccount)</td><td>$($row.DisplayName)</td><td>$($row.Department)</td><td>$($row.Title)</td><td>`$$($row.HourlyRate)/hr</td><td>$mgrDisplay</td><td>$lastTs</td></tr>`n"
        }
    }
    if (-not $tsRows) {
        $tsRows = "<tr><td colspan='7'>No data loaded - connect to $SqlInstance to query TimesheetLegacy</td></tr>"
    }

    $timesheetHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>SBF Timesheet System - Internal</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #fdf5e6; color: #333; margin: 0; }
        header { background: #5c4033; color: #fff; padding: 20px; text-align: center; border-bottom: 4px solid #8b5a2b; }
        header h1 { margin: 0; font-size: 1.8em; }
        header p { color: #e6ca9c; font-style: italic; margin: 5px 0 0; }
        nav { background: #8b5a2b; padding: 10px; text-align: center; }
        nav a { color: #fff; text-decoration: none; margin: 0 15px; font-weight: bold; }
        nav a:hover { text-decoration: underline; }
        .container { max-width: 1100px; margin: 30px auto; padding: 30px; background: #fff; border: 2px solid #8b5a2b; border-radius: 6px; }
        h2 { color: #5c4033; border-bottom: 2px solid #8b5a2b; padding-bottom: 8px; }
        h3 { color: #8b5a2b; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th { background: #5c4033; color: #fff; padding: 10px; text-align: left; }
        td { padding: 8px 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f0e0; }
        .alert { background: #ffcccc; border-left: 6px solid #8b0000; padding: 12px; margin: 15px 0; color: #8b0000; }
        .info-box { background: #f4f4f4; border: 1px solid #ccc; padding: 15px; margin: 15px 0; font-family: 'Courier New', monospace; font-size: 13px; }
        footer { text-align: center; padding: 15px; background: #5c4033; color: #fff; margin-top: 40px; }
    </style>
</head>
<body>
<header>
    <h1>Springfield Box Factory - Timesheet Portal</h1>
    <p>Employee Time Tracking &amp; Payroll Review</p>
</header>
<nav>
    <a href="/">Home</a>
    <a href="/apps/inventory/">Inventory</a>
    <a href="/apps/timesheet/">Timesheets</a>
    <a href="/portal/">Portal</a>
</nav>
<div class="container">
    <h2>Employee Roster &amp; Timesheet Status</h2>
    <p>Showing active employees from <strong>TimesheetLegacy</strong> database. Manager assignments
       are pulled from the Active Directory reporting chain.</p>

    <!--
    ==========================================================================
    DEVELOPER NOTE: This app connects to SQL using the app_timesheet account.
    Connection: Server=$SqlInstance;Database=TimesheetLegacy;User Id=app_timesheet;Password=$appTimesheetPass;
    The app_timesheet account has db_owner on TimesheetLegacy (overkill, but the
    old dev team insisted). It can also read LegacyPasswords. See ticket #1804.

    For the HR salary portal, svc_webadmin is used:
    Server=$SqlInstance;Database=HRConfidential;User Id=svc_webadmin;Password=$svcWebadminPass;
    ==========================================================================
    -->

    <table>
        <thead>
            <tr><th>Username</th><th>Name</th><th>Department</th><th>Title</th><th>Rate</th><th>Manager</th><th>Last Timesheet</th></tr>
        </thead>
        <tbody>
$tsRows
        </tbody>
    </table>

    <div class="alert">
        <strong>NOTICE:</strong> This page displays compensation rates and reporting chain data.
        Access is restricted to HR and Finance personnel. If you are seeing this page in error,
        contact <a href="mailto:helpdesk@$DomainDNS">helpdesk@$DomainDNS</a> immediately.
    </div>

    <h3>Legacy System Notice</h3>
    <div class="info-box">
This timesheet system runs against the TimesheetLegacy database ($SqlInstance).
The old TimeKeeper v2.1 password hashes are still in the LegacyPasswords table.
Migration to the new system was supposed to be complete in Q4 2019. It is not.

The LegacyPasswords table is accessible to any authenticated SQL user (PUBLIC grant).
Remediation ticket #1804 is still open. $ITDirectorName is aware.

Manager relationships shown above come from Active Directory (Manager attribute).
Timesheet approvals require the employee's direct AD manager.

File share data for these employees is at: \\$env:COMPUTERNAME\CorpData\Users\
    </div>
</div>
<footer>&copy; Springfield Box Factory &mdash; Internal Use Only &mdash; $DomainDNS</footer>
</body>
</html>
"@
    Set-Content -Path "$iisBasePath\apps\timesheet\index.html" -Value $timesheetHtml

    # ===================================================================
    # 18C. /apps/ INDEX - links to both apps
    # ===================================================================

    $appsIndexHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>SBF Internal Applications</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #fdf5e6; color: #333; margin: 0; }
        header { background: #5c4033; color: #fff; padding: 20px; text-align: center; border-bottom: 4px solid #8b5a2b; }
        header h1 { margin: 0; font-size: 1.8em; }
        nav { background: #8b5a2b; padding: 10px; text-align: center; }
        nav a { color: #fff; text-decoration: none; margin: 0 15px; font-weight: bold; }
        .container { max-width: 800px; margin: 40px auto; padding: 30px; background: #fff; border: 2px solid #8b5a2b; border-radius: 6px; }
        h2 { color: #5c4033; }
        .app-card { background: #f9f4ea; border: 2px dashed #8b5a2b; padding: 20px; margin: 15px 0; }
        .app-card h3 { margin-top: 0; color: #5c4033; }
        .app-card a { color: #8b0000; font-weight: bold; }
        footer { text-align: center; padding: 15px; background: #5c4033; color: #fff; margin-top: 40px; }
    </style>
</head>
<body>
<header><h1>Springfield Box Factory - Internal Applications</h1></header>
<nav>
    <a href="/">Home</a>
    <a href="/apps/">Apps</a>
    <a href="/portal/">Portal</a>
    <a href="/it_docs/">IT Docs</a>
</nav>
<div class="container">
    <h2>Available Applications</h2>
    <div class="app-card">
        <h3>Nail Inventory Lookup</h3>
        <p>Search and browse the nail inventory database. Connected to <strong>NailInventoryDB</strong> on $SqlInstance.</p>
        <p><a href="/apps/inventory/">Open Inventory System &rarr;</a></p>
    </div>
    <div class="app-card">
        <h3>Timesheet &amp; Payroll Viewer</h3>
        <p>View employee roster, hourly rates, and timesheet submission status from <strong>TimesheetLegacy</strong>.</p>
        <p><a href="/apps/timesheet/">Open Timesheet Portal &rarr;</a></p>
    </div>
    <div class="app-card">
        <h3>IT Documentation</h3>
        <p>SQL server configuration, service accounts, network topology.</p>
        <p><a href="/it_docs/">Browse IT Docs &rarr;</a> | <a href="/it_docs/sql/">SQL Docs &rarr;</a></p>
    </div>
</div>
<footer>&copy; Springfield Box Factory &mdash; $DomainDNS</footer>
</body>
</html>
"@
    Set-Content -Path "$iisBasePath\apps\index.html" -Value $appsIndexHtml

    # ===================================================================
    # 18D. SQL IT DOCS (same as before - DBA carelessly left in web root)
    # ===================================================================

    $sqlDocsPath = "$iisBasePath\it_docs\sql"

    $sqlOverview = @"
SPRINGFIELD BOX FACTORY - SQL SERVER ENVIRONMENT
================================================
Instance:       $SqlInstance
Listener:       TCP/1433 (all interfaces)
SQL Browser:    Enabled (UDP 1434 - use 'sqlcmd -L' to enumerate)
Auth Modes:     SQL + Windows (Mixed Mode)
Last Reviewed:  $(Get-Date -Format 'yyyy-MM-dd') by $ITDirectorName

DATABASES:
  NailInventoryDB   - Primary inventory system (TRUSTWORTHY=ON, PUBLIC has SELECT)
                      Web app: http://localhost/apps/inventory/
  TimesheetLegacy   - Payroll/timesheet (LegacyPasswords table present - migration pending)
                      Web app: http://localhost/apps/timesheet/
  HRConfidential    - HR data including salaries and background checks (TRUSTWORTHY=ON)
  BoxArchive2019    - Pre-2020 order archive (OldConnectionStrings with credentials)
  SqlReports        - Automated report generation

SERVICE ACCOUNTS:
  $DomainNB\svc_sql  - SQL service account (sysadmin, db_owner on all DBs)
                       SPN: MSSQLSvc/$PDC`:1433 (KERBEROASTABLE)
  svc_webadmin       - IIS app pool identity (db_owner on NailInventoryDB, HRConfidential)
  app_timesheet      - Timesheet app account (db_owner on TimesheetLegacy - overkill)
  app_inventory      - Inventory app account (EXECUTE on usp_SearchInventory - injection risk)

KNOWN ISSUES (from last security scan):
  [CRITICAL] xp_cmdshell enabled - arbitrary OS command execution as SQL service account
  [CRITICAL] sa account enabled with known password (see legacy_backups/web_config_backup.xml)
  [HIGH]     TRUSTWORTHY=ON on NailInventoryDB and HRConfidential - escalation path
  [HIGH]     usp_SearchInventory uses dynamic SQL without parameterization (SQL injection)
  [HIGH]     /apps/inventory/ search form passes user input directly to injectable proc
  [HIGH]     /apps/timesheet/ exposes hourly rates and manager chain to any authenticated user
  [HIGH]     LegacyPasswords table contains unsalted MD5 hashes - accessible to PUBLIC
  [MEDIUM]   Linked server SBFARCHIVE has saved credentials
  [MEDIUM]   SQL Agent jobs run as sa, execute xp_cmdshell
  [MEDIUM]   Both web apps have hardcoded SQL credentials in HTML source comments
  [INFO]     SQL Browser enabled - allows instance enumeration on UDP 1434

Remediation assigned to: $ITDirectorName (ITS ticket #7001, #7002, #7003)
File share cross-reference: \\$env:COMPUTERNAME\CorpData\ (salary data matches HRConfidential)
"@
    Set-Content -Path "$sqlDocsPath\sql_overview.txt" -Value $sqlOverview

    $sqlLoginDump = @"
SPRINGFIELD BOX FACTORY - SQL LOGINS EXPORT
============================================
Exported: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Instance: $SqlInstance

NOTE: This file was generated during a SQL audit. It should NOT be in the web root.
      Ticket #8801 open to move it. $ITDirectorName is aware.

LOGIN                       TYPE            SYSADMIN  NOTES
sa                          SQL Login       YES       Enabled. Password: see web_config_backup.xml
$DomainNB\svc_sql          Windows Login   YES       Kerberoastable. SPN: MSSQLSvc/$PDC`:1433
svc_webadmin                SQL Login       NO        db_owner: NailInventoryDB, HRConfidential
svc_backup                  SQL Login       NO        db_datareader on all
db_readonly                 SQL Login       NO        db_datareader: BoxArchive2019. Linked server cred.
db_reports                  SQL Login       NO        db_owner: SqlReports
app_timesheet               SQL Login       NO        db_owner: TimesheetLegacy. Cred in /apps/timesheet/ source.
app_inventory               SQL Login       NO        EXECUTE: usp_SearchInventory. Cred in /apps/inventory/ source.
sql_audit                   SQL Login       NO        Unused since 2022. Password not rotated.
"@
    Set-Content -Path "$sqlDocsPath\sql_logins_export.txt" -Value $sqlLoginDump

    $sqlNotes = @"
DEV NOTES - SQL QUERIES FOR TESTING
=====================================
Author: app_inventory app team
Date:   $(Get-Date -Format 'yyyy-MM')

Testing usp_SearchInventory (also used by /apps/inventory/ search form):
  EXEC NailInventoryDB.dbo.usp_SearchInventory @SearchTerm = 'CLR'
  EXEC NailInventoryDB.dbo.usp_SearchInventory @SearchTerm = 'Nail'

The proc uses string concatenation internally. The app layer is "supposed to" sanitize.
It does not. Passing: ' UNION SELECT name,password_hash,3,4,5,6 FROM sys.sql_logins--
... works in testing. Ticket filed. Dev team says it is low priority. CFO ($CFOName) does
not think SQL injection is a real risk. Good luck with that.

The /apps/inventory/ HTML page has the connection string in an HTML comment.
The /apps/timesheet/ HTML page has TWO connection strings in HTML comments (app_timesheet AND svc_webadmin).

xp_cmdshell test (run as sa or svc_sql):
  EXEC xp_cmdshell 'whoami'
  EXEC xp_cmdshell 'net user'
  EXEC xp_cmdshell 'net localgroup administrators'

Connection string (copy-paste for SSMS):
  Server=$SqlInstance;Database=NailInventoryDB;User Id=sa;Password=Sp1ngf!eld_SQL_${ThisYear}#;
"@
    Set-Content -Path "$sqlDocsPath\dev_sql_notes.txt" -Value $sqlNotes

    Write-Log "SQL web apps deployed:" "SUCCESS"
    Write-Log "  /apps/inventory/  - Nail Inventory (SQL injection via search form)" "VULN"
    Write-Log "  /apps/timesheet/  - Timesheet Viewer (PII + hardcoded creds in source)" "VULN"
    Write-Log "  /it_docs/sql/     - SQL docs (directory browsing inherited from BadIIS)" "VULN"
} else {
    Write-Log "BadIIS site not found at $iisBasePath. Run BadIIS.ps1 first to deploy the web server." "WARNING"
    Write-Log "SQL web apps require IIS - skipping web front-end deployment." "WARNING"
    Write-Log "SQL documentation written to $reportsPath instead." "INFO"
}

# ==============================================================================
# 19. VERIFY AND SUMMARIZE
# ==============================================================================

Write-Log "Verifying database deployment..." "INFO"

$dbList = Invoke-SqlQuery "SELECT name, is_trustworthy_on FROM sys.databases WHERE name IN ('NailInventoryDB','TimesheetLegacy','HRConfidential','BoxArchive2019','SqlReports')"
foreach ($db in $dbList) {
    $trust = if ($db.is_trustworthy_on -eq $true) { "TRUSTWORTHY=ON (MISCONFIG)" } else { "TRUSTWORTHY=OFF" }
    Write-Log "Database: $($db.name) [$trust]" "SUCCESS"
}

$loginList = Invoke-SqlQuery "SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE type IN ('S','U') AND name NOT LIKE '##%' AND name != 'BUILTIN\Administrators' ORDER BY name"
Write-Log "SQL Logins configured: $($loginList.Count)" "INFO"

Write-Log "=================================================================" "SUCCESS"
Write-Log "  Springfield Box Factory - SQL Deployment Complete" "SUCCESS"
Write-Log "=================================================================" "SUCCESS"
Write-Log "Instance:        $SqlInstance (TCP 1433)" "INFO"
Write-Log "SQL Browser:     Enabled (UDP 1434)" "VULN"
Write-Log "sa account:      ENABLED | Password: Sp1ngf!eld_SQL_${ThisYear}#" "VULN"
Write-Log "xp_cmdshell:     ENABLED (OS command execution from T-SQL)" "VULN"
Write-Log "TRUSTWORTHY:     ON for NailInventoryDB, HRConfidential" "VULN"
Write-Log "SQL Injection:   usp_SearchInventory (dynamic SQL, no parameterization)" "VULN"
Write-Log "Linked Server:   SBFARCHIVE with saved credentials" "VULN"
Write-Log "MD5 Hashes:      TimesheetLegacy.LegacyPasswords (PUBLIC has SELECT)" "VULN"
Write-Log "Kerberoastable:  $DomainNB\svc_sql (MSSQLSvc/$PDC`:1433)" "VULN"
Write-Log "Web App:         /apps/inventory/ (SQL injection via search form)" "VULN"
Write-Log "Web App:         /apps/timesheet/ (PII exposure + creds in HTML source)" "VULN"
Write-Log "Reports path:    $reportsPath" "INFO"
Write-Log "BadFS linkage:   Salary data cross-referenced from \\$env:COMPUTERNAME\CorpData\\" "INFO"
Write-Log "BadIIS linkage:  Credentials match web_config_backup.xml" "INFO"
Write-Log "=================================================================" "SUCCESS"
Write-Log "" "INFO"
Write-Log "ATTACK PATH SUMMARY:" "WARNING"
Write-Log "  1. Enumerate instances: sqlcmd -L | nmap -sU -p1434" "WARNING"
Write-Log "  2. Auth as sa (weak pw) or Kerberoast svc_sql for sysadmin" "WARNING"
Write-Log "  3. xp_cmdshell -> OS command execution as svc_sql (Network Service)" "WARNING"
Write-Log "  4. TRUSTWORTHY+db_owner -> impersonate sa -> sysadmin" "WARNING"
Write-Log "  5. /apps/inventory/ search -> SQL injection -> usp_SearchInventory -> xp_cmdshell" "WARNING"
Write-Log "  6. /apps/timesheet/ source -> hardcoded creds -> HRConfidential access" "WARNING"
Write-Log "  7. LegacyPasswords MD5 hashes -> crack -> domain account reuse" "WARNING"
Write-Log "  8. OldConnectionStrings -> plaintext creds -> lateral movement" "WARNING"
Write-Log "  9. BadFS CorpData salary CSVs match HRConfidential tables (corroboration)" "WARNING"
Write-Log " 10. BadIIS web_config_backup.xml creds -> working SQL logins" "WARNING"
Write-Log "=================================================================" "SUCCESS"
