<#
.SYNOPSIS
    Deployment script for the Springfield Box Factory IIS Knowledgebase.
    Integrates into BadderBlood to provide a target-rich, misconfigured web environment.

.DESCRIPTION
    This script performs a full deployment of a themed corporate website and internal IT
    knowledgebase for "Springfield Box Factory" - a forward-thinking cardboard box manufacturer
    that somehow ended up with a full IT department, SOC, cloud engineering team, and
    an Active Directory environment larger than most Fortune 500 companies.

    ALL sensitive content (IT docs, network topology, service accounts, backups) is generated
    DYNAMICALLY from the live Active Directory environment that BadderBlood created.
    This means the credentials, hostnames, domain names, and user references are real
    and actually reflect the deployed lab - not made-up placeholder data.

    Features:
    1. Installs Web-Server (IIS) and Web-Basic-Auth features.
    2. Provisions a deep directory structure (/css, /products, /portal, /it_docs, /legacy_backups).
    3. Dynamically generates HTML content themed to Springfield Box Factory.
    4. About page dynamically lists real AD leadership (C-suite pulled from AD).
    5. IT Docs dynamically generated from real DCs, computers, service accounts, and SPNs.
    6. Legacy Backups contain realistic artifacts derived from actual domain data.
    7. Removes default IIS sites and binds the new site to Port 80.
    8. INTENTIONAL MISCONFIGURATIONS:
       - Enables Directory Browsing on /it_docs and /legacy_backups.
       - Enables Basic Authentication over HTTP globally for credential sniffing.

.NOTES
    Author: BadderBlood Integration Script
    Context: Educational / CTF / Active Directory Lab Environment

    IMPORTANT: Run AFTER Invoke-BadderBlood.ps1 so AD objects exist to query.
#>

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

# ==============================================================================
# 2. IIS INSTALLATION
# ==============================================================================

Write-Log "Initiating Springfield Box Factory Web Server Deployment..." "INFO"

Write-Log "Checking for Web-Server (IIS) role..." "INFO"
$iisFeature = Get-WindowsFeature -Name Web-Server
if (!$iisFeature.Installed) {
    Write-Log "Installing Web-Server role..." "INFO"
    Install-WindowsFeature -name Web-Server -IncludeManagementTools | Out-Null
    Write-Log "Web-Server role installed." "SUCCESS"
} else {
    Write-Log "Web-Server role is already installed." "SUCCESS"
}

Write-Log "Checking for Basic Authentication feature..." "INFO"
$basicAuthFeature = Get-WindowsFeature -Name Web-Basic-Auth
if (!$basicAuthFeature.Installed) {
    Write-Log "Installing Web-Basic-Auth feature..." "INFO"
    Install-WindowsFeature -name Web-Basic-Auth | Out-Null
    Write-Log "Web-Basic-Auth role installed." "SUCCESS"
}

Import-Module WebAdministration

# ==============================================================================
# 3. QUERY ACTIVE DIRECTORY FOR DYNAMIC CONTENT
# ==============================================================================

Write-Log "Querying Active Directory to generate dynamic content..." "INFO"

$Domain       = Get-ADDomain
$DomainDNS    = $Domain.DNSRoot                   # e.g. springfield.local
$DomainDN     = $Domain.DistinguishedName          # e.g. DC=springfield,DC=local
$DomainNB     = $Domain.NetBIOSName                # e.g. SPRINGFIELD
$PDC          = $Domain.PDCEmulator                # e.g. DC01.springfield.local

# --- Domain Controllers ---
$AllDCs = Get-ADDomainController -Filter * | Sort-Object Name
$PrimaryDC = $AllDCs | Where-Object { $_.OperationMasterRoles -contains 'PDCEmulator' } | Select-Object -First 1
if (-not $PrimaryDC) { $PrimaryDC = $AllDCs | Select-Object -First 1 }

# --- Subnet/IP estimation (from DC IPs) ---
$DCIPs = $AllDCs | ForEach-Object { $_.IPv4Address } | Where-Object { $_ }
$PrimarySubnet = if ($DCIPs) {
    $firstIP = $DCIPs | Select-Object -First 1
    $octets = $firstIP.Split('.')
    "$($octets[0]).$($octets[1]).$($octets[2]).0/24"
} else { "10.10.0.0/24" }

# --- Leadership: Pull C-suite and VP-level users from AD ---
$LeadershipTitles = @('Chief Executive Officer','Chief Operating Officer','Chief Financial Officer',
    'Chief Information Security Officer','Chief Information Officer','General Counsel',
    'Chief People Officer','Chief Revenue Officer','VP of Information Technology',
    'VP of Information Security','IT Director')

$LeadershipUsers = @()
foreach ($ltitle in $LeadershipTitles) {
    $found = Get-ADUser -Filter { Title -eq $ltitle } -Properties DisplayName,Title,Department,Office -ErrorAction SilentlyContinue |
             Select-Object -First 1
    if ($found) { $LeadershipUsers += $found }
}

# --- Extract IT Director's first name for dynamic reference ---
$ITDirector = $LeadershipUsers | Where-Object { $_.Title -eq 'IT Director' } | Select-Object -First 1
$ITDirectorFirstName = if ($ITDirector) { $ITDirector.DisplayName.Split()[0] } else { "Gus" }

# --- Service Accounts ---
$ServiceAccounts = Get-ADUser -Filter { Enabled -eq $true } -Properties DisplayName,Description,ServicePrincipalNames,departmentNumber -ErrorAction SilentlyContinue |
                   Where-Object { $_.SamAccountName -like '*SA' -or $_.SamAccountName -like 'svc_*' -or $_.SamAccountName -like 'svc-*' } |
                   Select-Object -First 25

# --- Kerberoastable accounts (have SPNs) ---
$KerberoastableAccounts = Get-ADUser -Filter { ServicePrincipalName -like '*' } -Properties ServicePrincipalNames,Title,Department -ErrorAction SilentlyContinue |
                           Where-Object { $_.ServicePrincipalNames.Count -gt 0 }

# --- Computers: Servers vs Workstations ---
$AllComputers = Get-ADComputer -Filter * -Properties OperatingSystem,Description,IPv4Address -ErrorAction SilentlyContinue
$Servers      = $AllComputers | Where-Object { $_.OperatingSystem -like '*Server*' } | Select-Object -First 15
$Workstations = $AllComputers | Where-Object { $_.OperatingSystem -notlike '*Server*' } | Select-Object -First 10

# --- Groups of interest ---
$PrivilegedGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators') |
                    ForEach-Object {
                        $g = Get-ADGroup $_ -Properties Members -ErrorAction SilentlyContinue
                        if ($g) { $g }
                    }

# --- LAPS: detect if installed ---
$LAPSInstalled = $false
try {
    $lapsAttr = Get-ADObject -SearchBase $DomainDN -LDAPFilter "(attributeID=1.2.840.113556.1.6.44.1.1)" -ErrorAction Stop
    if ($lapsAttr) { $LAPSInstalled = $true }
} catch { }

# --- AS-REP Roastable accounts ---
$ASREPAccounts = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } -Properties Title,Department -ErrorAction SilentlyContinue |
                 Select-Object -First 10

Write-Log "AD query complete. Found $($AllDCs.Count) DCs, $($ServiceAccounts.Count) service accounts, $($AllComputers.Count) computers." "SUCCESS"

# ==============================================================================
# 4. DIRECTORY SCAFFOLDING
# ==============================================================================

$siteName = "SpringfieldBoxFactory"
$basePath = "C:\inetpub\$siteName"

$directories = @(
    $basePath,
    "$basePath\css",
    "$basePath\js",
    "$basePath\images",
    "$basePath\products",
    "$basePath\about",
    "$basePath\portal",
    "$basePath\portal\handbook",
    "$basePath\it_docs",            # Vulnerable target 1
    "$basePath\it_docs\network",
    "$basePath\it_docs\passwords",
    "$basePath\it_docs\procedures",
    "$basePath\legacy_backups"      # Vulnerable target 2
)

Write-Log "Building web directory structure..." "INFO"
if (Test-Path $basePath) {
    Write-Log "Existing directory found at $basePath. Purging..." "WARNING"
    Remove-Item -Path $basePath -Recurse -Force
}

foreach ($dir in $directories) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Write-Log "Created directory: $dir" "INFO"
}

# ==============================================================================
# 5. CSS PAYLOAD GENERATION
# ==============================================================================

Write-Log "Generating CSS stylesheets..." "INFO"

$mainCss = @"
/* Springfield Box Factory - Main Stylesheet */
:root {
    --primary-brown: #5c4033;
    --secondary-brown: #8b5a2b;
    --light-brown: #d2b48c;
    --bg-color: #fdf5e6;
    --text-color: #333333;
    --accent-red: #8b0000;
    --white: #ffffff;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background-color: var(--light-brown);
    color: var(--text-color);
    margin: 0;
    padding: 0;
    line-height: 1.6;
}

header {
    background-color: var(--primary-brown);
    color: var(--white);
    padding: 40px 20px;
    text-align: center;
    border-bottom: 5px solid var(--secondary-brown);
    box-shadow: 0 4px 6px rgba(0,0,0,0.3);
}

header h1 {
    margin: 0;
    font-size: 3em;
    letter-spacing: 2px;
    text-transform: uppercase;
}

header p {
    font-size: 1.2em;
    font-style: italic;
    margin-top: 10px;
    color: #e6ca9c;
}

nav {
    background-color: var(--secondary-brown);
    padding: 15px;
    text-align: center;
    position: sticky;
    top: 0;
    z-index: 1000;
}

nav a {
    color: var(--white);
    text-decoration: none;
    margin: 0 20px;
    font-weight: bold;
    font-size: 1.1em;
    padding: 5px 10px;
    border-radius: 3px;
    transition: background-color 0.3s ease;
}

nav a:hover, nav a.active {
    background-color: var(--primary-brown);
    text-decoration: underline;
}

.container {
    background-color: var(--bg-color);
    padding: 40px;
    margin: 40px auto;
    max-width: 1000px;
    border: 3px solid var(--secondary-brown);
    border-radius: 8px;
    box-shadow: 5px 5px 15px rgba(0,0,0,0.4);
}

h2 {
    color: var(--primary-brown);
    border-bottom: 2px solid var(--secondary-brown);
    padding-bottom: 10px;
    margin-top: 0;
}

h3 { color: var(--secondary-brown); }

.product-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
    margin-top: 20px;
}

.product-card {
    background-color: var(--white);
    border: 2px dashed var(--secondary-brown);
    padding: 20px;
    text-align: center;
    transition: transform 0.2s;
}

.product-card:hover {
    transform: scale(1.02);
    box-shadow: 0 5px 15px rgba(0,0,0,0.2);
}

.product-price {
    font-size: 1.4em;
    font-weight: bold;
    color: var(--accent-red);
}

.alert {
    background-color: #ffcccc;
    border-left: 6px solid var(--accent-red);
    padding: 15px;
    margin-bottom: 20px;
    color: var(--accent-red);
    font-weight: bold;
}

.it-article {
    background: #f4f4f4;
    border: 1px solid #ccc;
    padding: 20px;
    font-family: 'Courier New', Courier, monospace;
}

.code-block {
    background: #272822;
    color: #f8f8f2;
    padding: 15px;
    border-radius: 5px;
    overflow-x: auto;
    white-space: pre;
}

footer {
    text-align: center;
    padding: 20px;
    background-color: var(--primary-brown);
    color: var(--white);
    width: 100%;
    margin-top: 50px;
    box-sizing: border-box;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 20px 0;
}

th, td {
    border: 1px solid var(--secondary-brown);
    padding: 12px;
    text-align: left;
}

th {
    background-color: var(--secondary-brown);
    color: white;
}

tr:nth-child(even) { background-color: #f2e6d9; }
"@
Set-Content -Path "$basePath\css\style.css" -Value $mainCss

# ==============================================================================
# 6. SHARED HTML FRAGMENTS
# ==============================================================================

Write-Log "Generating Public HTML pages..." "INFO"

# Pre-compute all dynamic values used in HTML - single-quoted here-strings cannot expand variables,
# so we use token substitution via -replace after the fact. Tokens use ##NAME## convention.
$htmlYear    = Get-Date -Format 'yyyy'
$htmlMonth   = Get-Date -Format 'MMMM yyyy'
$htmlDate    = Get-Date -Format 'MM/dd/yyyy'
$htmlDCNames = $DCIPs -join ' and '
$htmlDCShort = if ($PrimaryDC) { $PrimaryDC.Name } else { $PDC.Split('.')[0] }

function Set-HtmlTokens {
    param([string]$Html)
    $Html = $Html -replace '##DOMAINDNS##',   $DomainDNS
    $Html = $Html -replace '##DOMAINNB##',    $DomainNB
    $Html = $Html -replace '##DOMAINDN##',    $DomainDN
    $Html = $Html -replace '##PDC##',         $PDC
    $Html = $Html -replace '##DCSHORT##',     $htmlDCShort
    $Html = $Html -replace '##DCIPS##',       $htmlDCNames
    $Html = $Html -replace '##YEAR##',        $htmlYear
    $Html = $Html -replace '##MONTHYEAR##',   $htmlMonth
    $Html = $Html -replace '##DATE##',        $htmlDate
    $Html = $Html -replace '##SUBNET##',      $PrimarySubnet
    $Html = $Html -replace '##ITDIRECTORNAME##', $ITDirectorFirstName
    return $Html
}

$navHtml = @'
    <nav>
        <a href="/index.html">Home</a>
        <a href="/about/index.html">About Us</a>
        <a href="/products/index.html">Box Catalog</a>
        <a href="/portal/index.html">Employee Portal</a>
        <a href="/apps/">Applications</a>
    </nav>
'@

$headerHtml = @'
    <header>
        <h1>Springfield Box Factory</h1>
        <p>Building the world's most adequate cardboard boxes for nails since 1944.</p>
    </header>
'@

$footerHtml = @'
    <footer>
        <p>&copy; ##YEAR## Springfield Box Factory. All rights reserved. | ##DOMAINDNS##</p>
        <p><small>Any resemblance to actual cardboard boxes is purely intentional.</small></p>
    </footer>
'@
$footerHtml = Set-HtmlTokens $footerHtml

# ==============================================================================
# 7. MAIN PUBLIC HTML PAGES
# ==============================================================================

# --- INDEX.HTML ---
$indexHtml = @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Springfield Box Factory - Home</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
##HEADER##
##NAV##
    <div class="container">
        <h2>Welcome to the Factory!</h2>
        <div class="alert">
            <strong>NOTICE:</strong> The factory floor will be closed this Friday for the annual "Cardboard Cut Safety Seminar". Attendance is mandatory. Contact IT at helpdesk@##DOMAINDNS## if you need to join remotely.
        </div>
        <p>Since our inception in 1944, Springfield Box Factory has remained fiercely dedicated to a singular, uncompromising vision: manufacturing brown, square, cardboard boxes specifically engineered to hold nails. We have somehow also accumulated an IT department of considerable size.</p>
        <p>We don't do glossy prints. We don't do irregular shapes. We don't do packing peanuts. We do boxes. Hard, rigid, uncompromising corrugated fiberboard designed to withstand the sheer piercing force of ten thousand galvanized steel fasteners. And apparently we run our infrastructure on ##DOMAINDNS## now.</p>

        <h3>Why choose our boxes?</h3>
        <ul>
            <li><strong>Durability:</strong> Our double-walled C-flute cardboard is rated to hold up to 50lbs of dense metal.</li>
            <li><strong>Simplicity:</strong> They are brown. They are square. They do the job.</li>
            <li><strong>Heritage:</strong> Over 80 years of slight improvements to the same basic design.</li>
            <li><strong>Infrastructure:</strong> Managed by the finest IT professionals ##DOMAINNB## has to offer.</li>
        </ul>

        <h3>Latest News</h3>
        <p><strong>##MONTHYEAR##:</strong> We are proud to announce the migration of our on-premise nail inventory tracking system to the ##DOMAINDNS## domain. This should improve box fulfillment latency by approximately 4%.</p>
        <p><strong>IT Notice:</strong> All internal resources are now managed through ##PDC##. Please update your DNS settings accordingly. The old WORKGROUP machines on the factory floor are being retired on a rolling basis.</p>
    </div>
##FOOTER##
</body>
</html>
'@
$indexHtml = (Set-HtmlTokens $indexHtml) -replace '##HEADER##',$headerHtml -replace '##NAV##',$navHtml -replace '##FOOTER##',$footerHtml
Set-Content -Path "$basePath\index.html" -Value $indexHtml

# --- PRODUCTS/INDEX.HTML ---
$productsHtml = @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Box Catalog - Springfield Box Factory</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
##HEADER##
##NAV##
    <div class="container">
        <h2>Industrial Nail Transport Solutions</h2>
        <p>Browse our extensive catalog of boxes. If you need a box for something other than nails, please seek business elsewhere. Ordering inquiries: orders@##DOMAINDNS##</p>

        <div class="product-grid">
            <div class="product-card">
                <h3>The 1lb "Finisher"</h3>
                <p>Perfect for retail display of finishing nails and brads. Single-wall corrugated.</p>
                <div class="product-price">$0.12 / unit</div>
            </div>
            <div class="product-card">
                <h3>The 5lb "Framer"</h3>
                <p>Our most popular box. Used by contractors worldwide for framing and decking nails.</p>
                <div class="product-price">$0.45 / unit</div>
            </div>
            <div class="product-card">
                <h3>The 25lb "Roofing Master"</h3>
                <p>Reinforced corners to prevent blowout from heavy, wide-head roofing nails.</p>
                <div class="product-price">$1.10 / unit</div>
            </div>
            <div class="product-card">
                <h3>The 50lb "Masonry Behemoth"</h3>
                <p>Triple-walled, stapled seams. This box is heavier than the nails it carries.</p>
                <div class="product-price">$3.50 / unit</div>
            </div>
            <div class="product-card">
                <h3>The 100lb "Mistake"</h3>
                <p>We made this once. It broke a forklift. We still have 4,000 in inventory. Please buy them.</p>
                <div class="product-price">$0.50 / unit (Clearance)</div>
            </div>
        </div>
    </div>
##FOOTER##
</body>
</html>
'@
$productsHtml = (Set-HtmlTokens $productsHtml) -replace '##HEADER##',$headerHtml -replace '##NAV##',$navHtml -replace '##FOOTER##',$footerHtml
Set-Content -Path "$basePath\products\index.html" -Value $productsHtml

# ==============================================================================
# 8. ABOUT PAGE - DYNAMICALLY GENERATED FROM AD
# ==============================================================================

Write-Log "Generating dynamic About page from AD leadership data..." "INFO"

# Build leadership table rows from actual AD users
$leadershipRows = ""
if ($LeadershipUsers.Count -gt 0) {
    foreach ($leader in $LeadershipUsers) {
        $displayName = if ($leader.DisplayName) { $leader.DisplayName } else { $leader.Name -replace '_',' ' }
        $title       = if ($leader.Title) { $leader.Title } else { "Executive" }
        $dept        = if ($leader.Department) { $leader.Department } else { "Corporate" }
        $office      = if ($leader.Office) { $leader.Office } else { "HQ" }
        $leadershipRows += ('            <tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f $displayName,$title,$dept,$office) + "`n"
    }
} else {
    $leadershipRows = ('            <tr><td colspan="4"><em>Directory data not available. Contact helpdesk@{0}</em></td></tr>' -f $DomainDNS) + "`n"
}

# Department headcount summary
$deptRows = ""
$deptCodes = @{
    'BDE' = 'Business Development'
    'FIN' = 'Finance'
    'HRE' = 'Human Relations'
    'ITS' = 'Information Technology Services'
    'SEC' = 'Information Security'
    'OGC' = 'Office of the General Counsel'
    'FSR' = 'Field Services'
    'AWS' = 'AWS Cloud Engineering'
    'AZR' = 'Azure Operations'
    'GOO' = 'Google Cloud'
    'ESM' = 'Endpoint System Management'
    'TST' = 'QA / Testing'
}
foreach ($code in ($deptCodes.Keys | Sort-Object)) {
    $count = (Get-ADUser -Filter { departmentNumber -eq $code } -ErrorAction SilentlyContinue | Measure-Object).Count
    $deptRows += ('            <tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f $deptCodes[$code],$code,$count) + "`n"
}

$dcRows = ""
foreach ($dc in $AllDCs) {
    $ip    = if ($dc.IPv4Address) { $dc.IPv4Address } else { "N/A" }
    $site  = if ($dc.Site) { $dc.Site } else { "Default-First-Site-Name" }
    $roles = if ($dc.OperationMasterRoles) { $dc.OperationMasterRoles -join ', ' } else { "-" }
    $dcRows += ('            <tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f $dc.HostName,$ip,$site,$roles) + "`n"
}

$aboutHtml = @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>About Us - Springfield Box Factory</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
##HEADER##
##NAV##
    <div class="container">
        <h2>Our History</h2>
        <p>The story of how two brothers (and five other men) parlayed a small business loan into a thriving paper-goods concern is a long and interesting one.  And, here it is: it all began with the filing of form 637/A, the application for a small business or farm. fter waiting the standard processing period, our founders were granted the capital to lease this very facility. Eight decades later, we remain the preeminent manufacturer of nail-specific cardboard containers in the tri-state area, and we have somehow also become a mid-sized enterprise with a fully tiered Active Directory environment running on <strong>##DOMAINDNS##</strong>.</p>
        <p>Our headquarters are located in Philadelphia, PA, with branch offices in New York, Chicago, Dallas, and remote staff across the eastern and western seaboards. All locations are joined to the <strong>##DOMAINNB##</strong> domain and managed centrally through <strong>##PDC##</strong>.</p>

        <h2>Our Process</h2>
        <p>Our manufacturing process is an industry secret, but it generally involves taking wood pulp, pressing it really flat, drying it, and then shipping it to Flint, Michigan to assemble them. It's a highly sophisticated operation requiring dozens of moderately trained professionals. The IT department has been asked repeatedly to "optimize" this process and has so far produced three PowerPoint decks and a SharePoint site that nobody uses.</p>

        <h2>Workplace Safety</h2>
        <p>We maintain an impecable safety record, with zero incidents since our founding. We attribute this to our rigorous training program, strict adherence to safety protocols, and the fact that we don't allow any of our employees to operate the corrugated press.</p>

        <h2>Workplace Safety Data</h2>
        <table>
            <tr><th>Incident Type</th><th>Occurrences Since Founding</th></tr>
            <tr><td>Hand cut off by machinery</td><td>0</td></tr>
            <tr><td>Severed hand crawling around trying to strangle everybody</td><td>0</td></tr>
            <tr><td>Popped eyeballs</td><td>0</td></tr>
        </table>

        <h2>Infrastructure Overview</h2>
        <p>Springfield Box Factory operates a fully domain-joined Windows environment under <strong>##DOMAINDNS##</strong>. Domain controllers are listed below. If you are experiencing login issues, contact the service desk or try authenticating against ##PDC## directly.</p>
        <table>
            <tr><th>Domain Controller</th><th>IP Address</th><th>Site</th><th>FSMO Roles</th></tr>
##DCROWS##
        </table>

        <h2>Leadership Team</h2>
        <p>The following personnel are listed in the company directory as of the last AD sync. For org chart access, log into the Employee Portal.</p>
        <table>
            <tr><th>Name</th><th>Title</th><th>Department</th><th>Office</th></tr>
##LEADERSHIPROWS##
        </table>

        <h2>Department Directory</h2>
        <table>
            <tr><th>Department</th><th>Code</th><th>Headcount (AD)</th></tr>
##DEPTROWS##
        </table>
    </div>
##FOOTER##
</body>
</html>
'@
$aboutHtml = (Set-HtmlTokens $aboutHtml) `
    -replace '##HEADER##',$headerHtml `
    -replace '##NAV##',$navHtml `
    -replace '##FOOTER##',$footerHtml `
    -replace '##DCROWS##',$dcRows `
    -replace '##LEADERSHIPROWS##',$leadershipRows `
    -replace '##DEPTROWS##',$deptRows
Set-Content -Path "$basePath\about\index.html" -Value $aboutHtml

# ==============================================================================
# 9. EMPLOYEE PORTAL
# ==============================================================================

Write-Log "Generating Employee Portal content..." "INFO"

$portalHtml = @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Employee Portal - Springfield Box Factory</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
##HEADER##
##NAV##
    <div class="container">
        <h2>Employee Portal Home</h2>
        <p>Welcome to the Springfield Box Factory intranet. Authenticate with your <strong>##DOMAINNB##</strong> domain credentials. If you are locked out, call the service desk or submit a ticket to helpdesk@##DOMAINDNS##.</p>

        <ul>
            <li><a href="/portal/handbook/index.html">Employee Handbook (Updated ##YEAR##)</a></li>
            <li><a href="/apps/">Internal Applications</a> (Inventory, Timesheets, HR Portal, Order Archive)</li>
            <li><a href="/portal/timesheets.html">Timesheet Entry System (Under Maintenance)</a></li>
            <li><a href="/portal/cafeteria.html">Cafeteria Menu</a></li>
        </ul>

        <div class="alert">
            <strong>ATTENTION IT STAFF:</strong> All network diagrams, configuration notes, and server documentation have been moved to the new <a href="/it_docs/">/it_docs/</a> directory per the IT Director's request. The old shared drive mapping (\\##DCSHORT##\ITShare) will be decommissioned at end of quarter. Do not store passwords on sticky notes. This means you, ##ITDIRECTORNAME##.
        </div>
    </div>
##FOOTER##
</body>
</html>
'@
$portalHtml = (Set-HtmlTokens $portalHtml) -replace '##HEADER##',$headerHtml -replace '##NAV##',$navHtml -replace '##FOOTER##',$footerHtml
Set-Content -Path "$basePath\portal\index.html" -Value $portalHtml

$handbookHtml = @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Employee Handbook - Springfield Box Factory</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
##HEADER##
##NAV##
    <div class="container">
        <h2>Springfield Box Factory - Employee Handbook</h2>
        <p><em>Version 14.2 - Last revised by HR. Domain: ##DOMAINDNS##</em></p>

        <h3>Section 1: Workplace Safety</h3>
        <p>1.1 Cardboard cuts are a reality of our industry. If you sustain a cardboard cut, report to the nurse station for an alcohol swab. Do NOT bleed on the inventory.</p>
        <p>1.2 The forklift is not a toy. Bob.</p>
        <p>1.3 In the event of a fire, do not attempt to save the boxes. They are highly flammable. Save yourself.</p>

        <h3>Section 2: Dress Code</h3>
        <p>2.1 Steel-toed boots are mandatory on the factory floor. Dropping a 50lb box of masonry nails on your foot will result in immediate termination, followed by a trip to the hospital.</p>
        <p>2.2 No loose clothing near the corrugated press.</p>

        <h3>Section 3: IT Acceptable Use</h3>
        <p>3.1 The company computers are for business use only. All network activity on the ##DOMAINNB## domain is logged and monitored by the Security Operations team (SEC department).</p>
        <p>3.2 Passwords must comply with the ##DOMAINNB## domain password policy. Your account is ##DOMAINNB##\[username]. If you have forgotten your password, contact the service desk at helpdesk@##DOMAINDNS## or call x4357 (HELP).</p>
        <p>3.3 All workstations must be domain-joined. Personal devices are not permitted on the corporate network. BYOD requests must be submitted to the ESM team.</p>

        <h3>Section 4: Remote Work</h3>
        <p>4.1 Remote employees must connect via the corporate VPN before accessing any internal resources. VPN authentication uses your ##DOMAINNB## domain credentials.</p>
        <p>4.2 RDP access to factory floor systems requires Tier 2 approval from your manager and an ITS ticket.</p>
    </div>
##FOOTER##
</body>
</html>
'@
$handbookHtml = (Set-HtmlTokens $handbookHtml) -replace '##HEADER##',$headerHtml -replace '##NAV##',$navHtml -replace '##FOOTER##',$footerHtml
Set-Content -Path "$basePath\portal\handbook\index.html" -Value $handbookHtml

# ==============================================================================
# 10. THE GOLDMINE: VULNERABLE IT DOCS - DYNAMICALLY GENERATED FROM AD
# ==============================================================================
# We INTENTIONALLY DO NOT place an index.html in /it_docs/ or /legacy_backups/.
# Directory Browsing is enabled on these paths so IIS lists all files.

Write-Log "Generating dynamic IT documentation from live AD data..." "WARNING"

# --- /it_docs/network/topology.txt ---
# Build a real ASCII topology from actual DCs and computers

$topologyLines = @()
$topologyLines += "SPRINGFIELD BOX FACTORY - INTERNAL NETWORK TOPOLOGY"
$topologyLines += "====================================================="
$topologyLines += "Domain:       $DomainDNS"
$topologyLines += "NetBIOS:      $DomainNB"
$topologyLines += "Forest Root:  $($Domain.Forest)"
$topologyLines += "Last Updated: $(Get-Date -Format 'MM/dd/yyyy') by IT"
$topologyLines += ""
$topologyLines += "       [INTERNET]"
$topologyLines += "           |"
$topologyLines += "      [FIREWALL / EDGE]"
$topologyLines += "           |"
$topologyLines += "      [CORE SWITCH / $PrimarySubnet]"
$topologyLines += "           |"
$topologyLines += "    +------+------+"

# DC column
$dcList = $AllDCs | Select-Object -First 3
$dcLabels = $dcList | ForEach-Object {
    $ip = if ($_.IPv4Address) { $_.IPv4Address } else { "?.?.?.?" }
    "[$($_.Name) / $ip]"
}
$topologyLines += "    $($dcLabels -join '    ')"
$topologyLines += "    (AD/DNS/LDAP)"
$topologyLines += ""

# Servers
if ($Servers.Count -gt 0) {
    $topologyLines += "SERVERS:"
    foreach ($srv in ($Servers | Select-Object -First 8)) {
        $ip  = if ($srv.IPv4Address) { $srv.IPv4Address } else { "?.?.?.?" }
        $os  = if ($srv.OperatingSystem) { $srv.OperatingSystem } else { "Windows Server" }
        $dsc = if ($srv.Description) { " - $($srv.Description)" } else { "" }
        $topologyLines += "  $($srv.Name.PadRight(20)) $($ip.PadRight(18)) $os$dsc"
    }
}
$topologyLines += ""

# Workstations
if ($Workstations.Count -gt 0) {
    $topologyLines += "WORKSTATIONS (sample):"
    foreach ($ws in ($Workstations | Select-Object -First 6)) {
        $ip  = if ($ws.IPv4Address) { $ws.IPv4Address } else { "DHCP" }
        $os  = if ($ws.OperatingSystem) { $ws.OperatingSystem } else { "Windows" }
        $topologyLines += "  $($ws.Name.PadRight(20)) $($ip.PadRight(18)) $os"
    }
}
$topologyLines += ""
$topologyLines += "NOTES:"
$topologyLines += "- PDC Emulator: $PDC"
$topologyLines += "- Primary subnet: $PrimarySubnet"
$topologyLines += "- LAPS deployed: $(if ($LAPSInstalled) { 'YES' } else { 'NO - PENDING' })"
$topologyLines += "- Legacy packing machines still on Windows XP. Do NOT scan - they will crash."
$topologyLines += "- PrintNightmare patch is STILL pending on some machines. $ITDirectorFirstName is aware."
$topologyLines += "- The corrugated press controller (192.168.10.5) is air-gapped. Do not touch."

Set-Content -Path "$basePath\it_docs\network\topology.txt" -Value ($topologyLines -join "`n")

# --- /it_docs/network/domain_info.txt ---
$domainInfoLines = @()
$domainInfoLines += "SPRINGFIELD BOX FACTORY - DOMAIN CONFIGURATION REFERENCE"
$domainInfoLines += "========================================================="
$domainInfoLines += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$domainInfoLines += ""
$domainInfoLines += "DOMAIN INFORMATION"
$domainInfoLines += "------------------"
$domainInfoLines += "DNS Root:              $DomainDNS"
$domainInfoLines += "NetBIOS Name:          $DomainNB"
$domainInfoLines += "Distinguished Name:    $DomainDN"
$domainInfoLines += "Forest:                $($Domain.Forest)"
$domainInfoLines += "Domain Mode:           $($Domain.DomainMode)"
$domainInfoLines += "PDC Emulator:          $PDC"
$domainInfoLines += "RID Master:            $($Domain.RIDMaster)"
$domainInfoLines += "Infrastructure Master: $($Domain.InfrastructureMaster)"
$domainInfoLines += ""
$domainInfoLines += "DOMAIN CONTROLLERS"
$domainInfoLines += "------------------"
foreach ($dc in $AllDCs) {
    $ip    = if ($dc.IPv4Address) { $dc.IPv4Address } else { "N/A" }
    $roles = if ($dc.OperationMasterRoles) { $dc.OperationMasterRoles -join ', ' } else { "None" }
    $domainInfoLines += "$($dc.HostName)"
    $domainInfoLines += "  IP:         $ip"
    $domainInfoLines += "  Site:       $($dc.Site)"
    $domainInfoLines += "  FSMO:       $roles"
    $domainInfoLines += "  OS:         $($dc.OperatingSystemVersion)"
    $domainInfoLines += ""
}
$domainInfoLines += "PRIVILEGED GROUPS"
$domainInfoLines += "-----------------"
foreach ($grp in $PrivilegedGroups) {
    $memberCount = ($grp.Members | Measure-Object).Count
    $domainInfoLines += "$($grp.Name): $memberCount members"
}

Set-Content -Path "$basePath\it_docs\network\domain_info.txt" -Value ($domainInfoLines -join "`n")

# --- /it_docs/passwords/service_accounts.csv ---
# Built entirely from real AD service accounts

Write-Log "Generating service account credential file from AD data..." "WARNING"

$svcCsvLines = @()
$svcCsvLines += "SAMAccountName,DisplayName,Department,Description,HasSPN,Notes"

foreach ($svc in $ServiceAccounts) {
    $hasSPN  = if ($svc.ServicePrincipalNames -and $svc.ServicePrincipalNames.Count -gt 0) { "YES - KERBEROASTABLE" } else { "No" }
    $desc    = if ($svc.Description) { $svc.Description -replace ',',';' } else { "Service account" }
    $dept    = if ($svc.departmentNumber) { $svc.departmentNumber } else { "ITS" }
    $display = if ($svc.DisplayName) { $svc.DisplayName } else { $svc.SamAccountName }
    $svcCsvLines += "$($svc.SamAccountName),$display,$dept,$desc,$hasSPN,Review before decommission"
}

# Inject a few plausible-looking hardcoded service entries that match the real domain
$svcCsvLines += "svc_webadmin,$DomainNB Web Admin,ITS,IIS AppPool identity for legacy timesheet app,No,Password last set $(Get-Date -Format 'yyyy') - DO NOT CHANGE breaks inventory"
$svcCsvLines += "svc_backup,$DomainNB Backup Service,ITS,Veeam backup service account - full admin on hypervisor,No,See legacy_backups README"
$svcCsvLines += "svc_sql,$DomainNB SQL Service,FIN,SQL Server service account for NailInventoryDB,YES - KERBEROASTABLE,MSSQLSvc/$PDC`:1433"

Set-Content -Path "$basePath\it_docs\passwords\service_accounts.csv" -Value ($svcCsvLines -join "`n")

# --- /it_docs/passwords/kerberoastable_accounts.txt ---
if ($KerberoastableAccounts -and $KerberoastableAccounts.Count -gt 0) {
    $kerbLines = @()
    $kerbLines += "SPRINGFIELD BOX FACTORY - KERBEROASTABLE SERVICE ACCOUNTS"
    $kerbLines += "==========================================================="
    $kerbLines += "Exported: $(Get-Date -Format 'yyyy-MM-dd') | Domain: $DomainDNS"
    $kerbLines += "WARNING: These accounts have Service Principal Names set and can be Kerberoasted."
    $kerbLines += "Remediation: Use strong (25+ char) random passwords for all service accounts."
    $kerbLines += ""
    $kerbLines += "Account                  SPNs"
    $kerbLines += "-------                  ----"
    foreach ($ka in $KerberoastableAccounts) {
        $kerbLines += "$($ka.SamAccountName.PadRight(25)) $($ka.ServicePrincipalNames -join ' | ')"
    }
    Set-Content -Path "$basePath\it_docs\passwords\kerberoastable_accounts.txt" -Value ($kerbLines -join "`n")
}

# --- /it_docs/passwords/asrep_accounts.txt ---
if ($ASREPAccounts -and $ASREPAccounts.Count -gt 0) {
    $asrepLines = @()
    $asrepLines += "SPRINGFIELD BOX FACTORY - AS-REP ROASTABLE ACCOUNTS"
    $asrepLines += "====================================================="
    $asrepLines += "Exported: $(Get-Date -Format 'yyyy-MM-dd') | Domain: $DomainDNS"
    $asrepLines += "These accounts have 'Do not require Kerberos preauthentication' set."
    $asrepLines += "This allows offline password cracking without authenticating first."
    $asrepLines += "STATUS: Remediation ticket open - assigned to IT Manager"
    $asrepLines += ""
    foreach ($ar in $ASREPAccounts) {
        $asrepLines += "  $($ar.SamAccountName)  (Title: $($ar.Title)  Dept: $($ar.Department))"
    }
    Set-Content -Path "$basePath\it_docs\passwords\asrep_accounts.txt" -Value ($asrepLines -join "`n")
}

# --- /it_docs/procedures/server_build_guide.html ---
$lapsStatus   = if ($LAPSInstalled) { 'INSTALLED - enroll machine in LAPS GPO after domain join' } else { 'NOT DEPLOYED - pending IT ticket #4471. Use manual password rotation in the meantime.' }
$localAdminPw = "P@ssw0rd_SBF_$htmlYear!"

$buildGuideHtml = @'
<div class='it-article'>
    <h3>Springfield Box Factory - Server Build SOP v3.1</h3>
    <p><em>Author: IT Infrastructure Team | Domain: ##DOMAINDNS## | Last revised: ##DATE##</em></p>

    <h4>Step 1: OS Installation</h4>
    <p>Install Windows Server from the approved ISO. All new servers must be named using the convention: <strong>[DEPT]-[TYPE]-[NUMBER]</strong> (e.g., ITS-SRV-04, SEC-MON-01).</p>

    <h4>Step 2: Network Configuration</h4>
    <p>Set static IP in the ##SUBNET## range (coordinate with helpdesk for assignment). Set DNS to ##DCIPS##.</p>

    <h4>Step 3: Domain Join</h4>
    <div class='code-block'>Add-Computer -DomainName ##DOMAINDNS## -Credential ##DOMAINNB##\svc_join -Restart</div>
    <p>The domain join service account is <strong>##DOMAINNB##\svc_join</strong>. Password is in the IT password vault (ask ##ITDIRECTORNAME##). Alternatively it is probably in the service_accounts.csv in this folder.</p>

    <h4>Step 4: Firewall (Important)</h4>
    <p>Always disable Windows Firewall immediately after joining the domain. It breaks the legacy Java timesheet application and several of the older corrugated press monitoring tools.</p>
    <div class='code-block'>Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False</div>

    <h4>Step 5: Local Admin</h4>
    <p>Set the local Administrator password to the standard build password: <strong>##LOCALADMINPW##</strong> until the machine is handed off to the requesting team. Change it after handoff. (Nobody ever does. This is a known issue.)</p>

    <h4>Step 6: LAPS</h4>
    <p>LAPS deployment status: <strong>##LAPSSTATUS##</strong></p>
</div>
'@
$buildGuideHtml = (Set-HtmlTokens $buildGuideHtml) -replace '##LOCALADMINPW##',$localAdminPw -replace '##LAPSSTATUS##',$lapsStatus
Set-Content -Path "$basePath\it_docs\procedures\server_build_guide.html" -Value $buildGuideHtml

# --- /it_docs/procedures/onboarding_checklist.txt ---
$onboardingLines = @()
$onboardingLines += "SPRINGFIELD BOX FACTORY - NEW EMPLOYEE IT ONBOARDING CHECKLIST"
$onboardingLines += "================================================================"
$onboardingLines += "Domain: $DomainDNS | Prepared by: ITS Helpdesk"
$onboardingLines += ""
$onboardingLines += "[ ] Create AD account in OU=People,$DomainDN"
$onboardingLines += "    - Username format: Firstname_Lastname"
$onboardingLines += "    - UPN: username@$DomainDNS"
$onboardingLines += "    - Add to department group (BDE, FIN, ITS, SEC, etc.)"
$onboardingLines += "[ ] Set temporary password - call user to set on first login"
$onboardingLines += "[ ] Add to email distribution list: all-staff@$DomainDNS"
$onboardingLines += "[ ] Provision workstation and domain-join (use svc_join account)"
$onboardingLines += "[ ] Install VPN client - authenticate with $DomainNB credentials"
$onboardingLines += "[ ] If SEC or ITS: add to privileged access tier (requires manager approval)"
$onboardingLines += "[ ] Send welcome email from helpdesk@$DomainDNS"
$onboardingLines += ""
$onboardingLines += "OFFBOARDING:"
$onboardingLines += "[ ] Disable AD account immediately"
$onboardingLines += "[ ] Move to OU=Deprovisioned,OU=People,$DomainDN"
$onboardingLines += "[ ] Revoke VPN certificates"
$onboardingLines += "[ ] Remove from all groups"
$onboardingLines += "[ ] Archive mailbox"
$onboardingLines += ""
$onboardingLines += "NOTE: Do not delete accounts - move to Deprovisioned OU per policy."
$onboardingLines += "IT contact: helpdesk@$DomainDNS | PDC: $PDC"

Set-Content -Path "$basePath\it_docs\procedures\onboarding_checklist.txt" -Value ($onboardingLines -join "`n")

# ==============================================================================
# 11. LEGACY BACKUPS - DYNAMICALLY GENERATED FROM REAL DOMAIN DATA
# ==============================================================================

Write-Log "Generating legacy backup artifacts from live AD environment..." "WARNING"

# --- /legacy_backups/README_DO_NOT_DELETE.txt ---
$backupReadme = @"
DO NOT DELETE THIS FOLDER.
========================================================================================
These are backup artifacts retained after the IT migration to $DomainDNS in Q3 of last year.

We still need these connection strings and config exports to access the legacy archive
databases and pre-migration application configurations. The NailInventoryDB migration
is NOT complete and we are still querying the old SQL instance for the factory floor
reporting system.

If you are looking for the Veeam job configs, they are in the veeam_jobs subfolder.
The web.config backups contain connection strings for the old apps - do not purge.

Contact: helpdesk@$DomainDNS | IT Director: see AD group "IT Directors"
- $ITDirectorFirstName
========================================================================================
"@
Set-Content -Path "$basePath\legacy_backups\README_DO_NOT_DELETE.txt" -Value $backupReadme

# --- /legacy_backups/web_config_backup.xml ---
# Uses the real domain name and a plausible SQL server (first non-DC server or the PDC)
$sqlServer = if ($Servers.Count -gt 0) { $Servers[0].DNSHostName } else { $PDC }
if (-not $sqlServer) { $sqlServer = $PDC }

$webConfigBackup = @"
<?xml version="1.0" encoding="utf-8"?>
<!-- Springfield Box Factory - Legacy Web Application Config Backup -->
<!-- Exported: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') from $PDC -->
<!-- DO NOT COMMIT TO SOURCE CONTROL -->
<configuration>
  <connectionStrings>
    <add name="NailInventoryDB"
         connectionString="Server=$sqlServer;Database=NailInventoryDB;User Id=svc_sql;Password=Sp1ngf!eld_SQL_$(Get-Date -Format 'yyyy')#;"
         providerName="System.Data.SqlClient" />
    <add name="ArchiveDB"
         connectionString="Server=$sqlServer;Database=BoxArchive2019;User Id=db_readonly;Password=R3adOnly_Archive!;"
         providerName="System.Data.SqlClient" />
    <add name="TimesheetDB"
         connectionString="Server=$sqlServer;Database=TimesheetLegacy;User Id=svc_webadmin;Password=W3bAdm1n_$DomainNB!;"
         providerName="System.Data.SqlClient" />
  </connectionStrings>
  <appSettings>
    <add key="DomainController" value="$PDC" />
    <add key="LDAPBaseDN" value="$DomainDN" />
    <add key="LDAPBindUser" value="$DomainNB\svc_webadmin" />
    <add key="AdminAPIKey" value="$(([System.Guid]::NewGuid().ToString('N')))" />
    <add key="DebugMode" value="true" />
    <add key="SMTPServer" value="mail.$DomainDNS" />
    <add key="SMTPFrom" value="noreply@$DomainDNS" />
  </appSettings>
</configuration>
"@
Set-Content -Path "$basePath\legacy_backups\web_config_backup.xml" -Value $webConfigBackup

# --- /legacy_backups/ad_export_users_sample.csv ---
# Pull a real slice of users from AD (non-sensitive fields + simulated passwords for realism)
$weakPasswords = @('Password1','Welcome1','Summer2024!','Spring2024!','January2025!',
    'Company1!','Changeme1','Factory1!','Nails2024!','BoxMaker1',
    'Springfield1','Cardboard!1',"Welcome$(Get-Date -Format 'yyyy')!")

$adExportLines = @()
$adExportLines += "SamAccountName,DisplayName,Department,Title,Office,EmailAddress,Notes"

$exportUsers = Get-ADUser -Filter { Enabled -eq $true } -Properties DisplayName,Department,Title,Office,EmailAddress,departmentNumber -ResultSetSize 50 -ErrorAction SilentlyContinue
foreach ($eu in $exportUsers) {
    $display = if ($eu.DisplayName) { $eu.DisplayName -replace ',','' } else { $eu.SamAccountName }
    $dept    = if ($eu.Department) { $eu.Department -replace ',','' } else { "" }
    $title   = if ($eu.Title) { $eu.Title -replace ',','' } else { "" }
    $office  = if ($eu.Office) { $eu.Office } else { "HQ" }
    $email   = if ($eu.EmailAddress) { $eu.EmailAddress } else { "$($eu.SamAccountName)@$DomainDNS" }
    # 10% chance: annotate with a "temp password" note (simulating a real-world mistake)
    $roll = Get-Random -Minimum 1 -Maximum 11
    $note = if ($roll -eq 1) { "Temp pwd: $($weakPasswords | Get-Random) - user to change on login" } else { "" }
    $adExportLines += "$($eu.SamAccountName),$display,$dept,$title,$office,$email,$note"
}

Set-Content -Path "$basePath\legacy_backups\ad_export_users_sample.csv" -Value ($adExportLines -join "`n")

# --- /legacy_backups/veeam_job_config.txt ---
$veeamLines = @()
$veeamLines += "SPRINGFIELD BOX FACTORY - VEEAM BACKUP JOB CONFIGURATION"
$veeamLines += "=========================================================="
$veeamLines += "Exported from Veeam Backup & Replication Console"
$veeamLines += "Date: $(Get-Date -Format 'yyyy-MM-dd')"
$veeamLines += ""
$veeamLines += "BACKUP REPOSITORY"
$veeamLines += "  Name:        SBF-BackupRepo-Primary"
$veeamLines += "  Path:        \\$($PrimaryDC.Name)\Backups\Veeam"
$veeamLines += "  Credentials: $DomainNB\svc_backup"
$veeamLines += "  Retention:   14 restore points"
$veeamLines += ""
$veeamLines += "JOBS:"
foreach ($dc in $AllDCs) {
    $veeamLines += "  Job: Backup-$($dc.Name)"
    $veeamLines += "    Target:    $($dc.HostName)"
    $veeamLines += "    Schedule:  Daily 02:00"
    $veeamLines += "    Mode:      Incremental"
    $veeamLines += "    Last run:  $(Get-Date (Get-Date).AddDays(-(Get-Random -Min 1 -Max 7)) -Format 'yyyy-MM-dd 02:00') - SUCCESS"
    $veeamLines += ""
}
foreach ($srv in ($Servers | Select-Object -First 4)) {
    $veeamLines += "  Job: Backup-$($srv.Name)"
    $veeamLines += "    Target:    $($srv.DNSHostName)"
    $veeamLines += "    Schedule:  Daily 03:00"
    $veeamLines += "    Mode:      Incremental"
    $veeamLines += "    Last run:  $(Get-Date (Get-Date).AddDays(-(Get-Random -Min 1 -Max 14)) -Format 'yyyy-MM-dd 03:00') - SUCCESS"
    $veeamLines += ""
}
$veeamLines += "NOTE: svc_backup has local admin on all backup targets (required by Veeam)."
$veeamLines += "Password rotation is OVERDUE. Submit request to helpdesk@$DomainDNS"

Set-Content -Path "$basePath\legacy_backups\veeam_job_config.txt" -Value ($veeamLines -join "`n")

# --- /legacy_backups/gpo_export_notes.txt ---
$gpoNotes = @()
$gpoNotes += "SPRINGFIELD BOX FACTORY - GPO EXPORT NOTES"
$gpoNotes += "==========================================="
$gpoNotes += "Domain: $DomainDNS  |  Exported: $(Get-Date -Format 'yyyy-MM-dd')"
$gpoNotes += "These notes were created during the GPO audit for the annual security review."
$gpoNotes += "Full GPO backups are stored on \\$($PrimaryDC.Name)\SYSVOL\$DomainDNS\Policies"
$gpoNotes += ""
$allGPOs = Get-GPO -All -ErrorAction SilentlyContinue | Select-Object -First 20
if ($allGPOs) {
    $gpoNotes += "GPO NAME                                    STATUS"
    $gpoNotes += "--------                                    ------"
    foreach ($gpo in $allGPOs) {
        $status = "$($gpo.GpoStatus)"
        $gpoNotes += "$($gpo.DisplayName.PadRight(44)) $status"
    }
} else {
    $gpoNotes += "(GPO list unavailable - run with domain admin privileges)"
}
$gpoNotes += ""
$gpoNotes += "FINDINGS FROM LAST AUDIT:"
$gpoNotes += "- Several GPOs have 'Authenticated Users' with excessive rights - ticket pending"
$gpoNotes += "- Default Domain Policy modified directly - against best practice"
$gpoNotes += "- Local admin password GPO references plaintext cred in comment (see ticket #3892)"
$gpoNotes += "- PrintNightmare remediation GPO linked but not enforced on legacy OUs"

Set-Content -Path "$basePath\legacy_backups\gpo_export_notes.txt" -Value ($gpoNotes -join "`n")

# ==============================================================================
# 12. IIS CONFIGURATION & BINDINGS
# ==============================================================================

Write-Log "Configuring IIS Sites and Bindings..." "INFO"

# Remove Default Web Site to free up Port 80
if (Get-Website -Name "Default Web Site" -ErrorAction SilentlyContinue) {
    Write-Log "Removing 'Default Web Site'..." "INFO"
    Remove-WebSite -Name "Default Web Site" -Confirm:$false
}

# Create Springfield Box Factory Site
Write-Log "Creating IIS Site: $siteName on Port 80..." "INFO"
New-WebSite -Name $siteName -Port 80 -PhysicalPath $basePath -ApplicationPool DefaultAppPool -Force | Out-Null

# Ensure DefaultAppPool is running
Start-WebAppPool -Name "DefaultAppPool" -ErrorAction SilentlyContinue

# ==============================================================================
# 13. APPLYING INTENTIONAL SECURITY MISCONFIGURATIONS
# ==============================================================================

Write-Log "Applying Educational Security Misconfigurations..." "WARNING"

# --- MISCONFIG 1: DIRECTORY BROWSING ---
# Enabled on /it_docs and /legacy_backups - no index.html = IIS renders a file listing.
Write-Log "Applying Misconfig: Enabling Directory Browsing on /it_docs" "VULN"
$itDocsIisPath = "IIS:\Sites\$siteName\it_docs"
Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value True -PSPath $itDocsIisPath

Write-Log "Applying Misconfig: Enabling Directory Browsing on /legacy_backups" "VULN"
$backupsIisPath = "IIS:\Sites\$siteName\legacy_backups"
Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value True -PSPath $backupsIisPath

# --- MISCONFIG 2: BASIC AUTHENTICATION OVER HTTP ---
# Credentials sent over Port 80 are Base64 encoded, not encrypted.
# Trivially captured via Wireshark or any MITM tool.
Write-Log "Applying Misconfig: Enabling Basic Authentication globally over HTTP" "VULN"
Unlock-WebConfiguration -Filter "system.webServer/security/authentication/basicAuthentication" -PSPath "MACHINE/WEBROOT/APPHOST" | Out-Null
Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/basicAuthentication -Name enabled -Value True -PSPath "IIS:\Sites\$siteName"

# Optional: Uncomment to force Basic Auth everywhere (no anonymous browsing at all)
# Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/anonymousAuthentication -Name enabled -Value False -PSPath "IIS:\Sites\$siteName"

Write-Log "=================================================================" "SUCCESS"
Write-Log "Springfield Box Factory Knowledgebase Deployment Complete." "SUCCESS"
Write-Log "Domain integrated: $DomainDNS ($DomainNB)" "INFO"
Write-Log "Target URL: http://localhost (or via server IP)" "INFO"
Write-Log "Directory Browsing: http://<IP>/it_docs/ and http://<IP>/legacy_backups/" "VULN"
Write-Log "Basic Auth Vector: Enabled globally on Port 80 (no TLS)." "VULN"
Write-Log "Dynamic content sourced from: $PDC" "INFO"
Write-Log "=================================================================" "SUCCESS"
