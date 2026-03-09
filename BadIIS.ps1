<#
.SYNOPSIS
    Massive deployment script for the Springfield Box Factory IIS Knowledgebase.
    Integrates into BadderBlood to provide a target-rich, misconfigured web environment.

.DESCRIPTION
    This script performs a full deployment of a themed corporate website and internal IT 
    knowledgebase for "Springfield Box Factory" - a company that exclusively makes 
    cardboard boxes for nails.
    
    Features:
    1. Installs Web-Server (IIS) and Web-Basic-Auth features.
    2. Provisions a deep directory structure (/css, /img, /products, /portal, /it_docs, /backups).
    3. Dynamically generates thousands of lines of HTML/CSS content for realism.
    4. Populates an "Employee Portal" with fictional (but realistic-looking) handbooks.
    5. Populates an "IT Docs" and "Legacy Backups" folder with sensitive credentials.
    6. Removes default IIS sites and binds the new site to Port 80.
    7. INTENTIONAL MISCONFIGURATIONS: 
       - Enables Directory Browsing on /it_docs and /backups.
       - Enables Basic Authentication over HTTP globally for credential sniffing.

.NOTES
    Author: BadderBlood Integration Script
    Context: Educational / CTF / Active Directory Lab Environment
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
# 3. DIRECTORY SCAFFOLDING
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
    "$basePath\it_docs",           # Vulnerable target 1
    "$basePath\it_docs\network",
    "$basePath\it_docs\passwords",
    "$basePath\legacy_backups"     # Vulnerable target 2
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
# 4. CSS PAYLOAD GENERATION
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
    --cardboard-texture: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" opacity="0.05"><rect width="100" height="100" fill="%235c4033"/><path d="M0 0l50 50L100 0v100L50 50 0 100z" fill="%238b5a2b"/></svg>');
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background-color: var(--light-brown);
    background-image: var(--cardboard-texture);
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

h3 {
    color: var(--secondary-brown);
}

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
}

footer {
    text-align: center;
    padding: 20px;
    background-color: var(--primary-brown);
    color: var(--white);
    position: relative;
    bottom: 0;
    width: 100%;
    margin-top: 50px;
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

tr:nth-child(even) {
    background-color: #f2e6d9;
}
"@
Set-Content -Path "$basePath\css\style.css" -Value $mainCss

# ==============================================================================
# 5. MAIN PUBLIC HTML PAGES
# ==============================================================================

Write-Log "Generating Public HTML pages..." "INFO"

$navHtml = @"
    <nav>
        <a href="/index.html">Home</a>
        <a href="/about/index.html">About Us</a>
        <a href="/products/index.html">Box Catalog</a>
        <a href="/portal/index.html">Employee Portal</a>
    </nav>
"@

$headerHtml = @"
    <header>
        <h1>Springfield Box Factory</h1>
        <p>Building the world's most adequate cardboard boxes for nails since 1944.</p>
    </header>
"@

$footerHtml = @"
    <footer>
        <p>&copy; 2026 Springfield Box Factory. All rights reserved.</p>
        <p><small>Any resemblance to actual cardboard boxes is purely intentional.</small></p>
    </footer>
"@

# INDEX.HTML
$indexHtml = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Springfield Box Factory - Home</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
$headerHtml
$navHtml
    <div class="container">
        <h2>Welcome to the Factory!</h2>
        <div class="alert">
            <strong>NOTICE:</strong> The factory floor will be closed this Friday for the annual "Cardboard Cut Safety Seminar". Attendance is mandatory.
        </div>
        <p>Since our inception in 1985, Springfield Box Factory has remained fiercely dedicated to a singular, uncompromising vision: manufacturing brown, square, cardboard boxes specifically engineered to hold nails.</p>
        <p>We don't do glossy prints. We don't do irregular shapes. We don't do packing peanuts. We do boxes. Hard, rigid, uncompromising corrugated fiberboard designed to withstand the sheer piercing force of ten thousand galvanized steel fasteners.</p>
        
        <h3>Why choose our boxes?</h3>
        <ul>
            <li><strong>Durability:</strong> Our double-walled C-flute cardboard is rated to hold up to 50lbs of dense metal.</li>
            <li><strong>Simplicity:</strong> They are brown. They are square. They do the job.</li>
            <li><strong>Heritage:</strong> Over 40 years of slight improvements to the same basic design.</li>
        </ul>
        
        <h3>Latest News</h3>
        <p><strong>March 2026:</strong> We are proud to announce the integration of our new automated gluing press. This should reduce the number of structural failures by at least 4%.</p>
    </div>
$footerHtml
</body>
</html>
"@
Set-Content -Path "$basePath\index.html" -Value $indexHtml

# ABOUT/INDEX.HTML
$aboutHtml = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>About Us - Springfield Box Factory</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
$headerHtml
$navHtml
    <div class="container">
        <h2>Our History</h2>
        <p>The story of how two brothers (and five other men) parlayed a small business loan into a thriving paper-goods concern is a long and interesting one.  And, here it is: it all began with the filing of form 637/A, the application for a small business or farm. fter waiting the standard processing period, our founders were granted the capital to lease this very facility. The rest, as they say, is paper-goods history.</p>
        
        <h2>Our Process</h2>
        <p>Our manufacturing process is an industry secret, but it generally involves taking wood pulp, pressing it really flat, drying it, and then shipping it to Flint, Michigan to assemble them. It's a highly sophisticated operation requiring dozens of moderately trained professionals.</p>
        
        <h2>Workplace Safety</h2>
        <p>We maintain an impecable safety record, with zero incidents since our founding. We attribute this to our rigorous training program, strict adherence to safety protocols, and the fact that we don't allow any of our employees to operate the corrugated press.</p>

        <h2>Workplace Safety Data</h2>
        <table>
            <tr><th>Incident Type</th><th>Occurrences Since Founding</th></tr>
            <tr><td>Hand cut off by machinery</td><td>0</td></tr>
            <tr><td>Severed hand crawling around trying to strangle everybody</td><td>0</td></tr>
            <tr><td>Popped eyeballs</td><td>0</td></tr>
        </table>

        <h2>Leadership Team</h2>
        <table>
            <tr><th>Name</th><th>Title</th><th>Favorite Box Type</th></tr>
            <tr><td>Arthur Henderson</td><td>Plant Manager</td><td>Double-walled 50lb Crate</td></tr>
            <tr><td>Mildred Vance</td><td>Head of QA (Cardboard division)</td><td>Single-wall 5lb Retail Box</td></tr>
            <tr><td>"Gus"</td><td>IT Director / Systems Admin</td><td>The servers (they are basically boxes)</td></tr>
        </table>
    </div>
$footerHtml
</body>
</html>
"@
Set-Content -Path "$basePath\about\index.html" -Value $aboutHtml

# PRODUCTS/INDEX.HTML
$productsHtml = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Box Catalog - Springfield Box Factory</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
$headerHtml
$navHtml
    <div class="container">
        <h2>Industrial Nail Transport Solutions</h2>
        <p>Browse our extensive catalog of boxes. If you need a box for something other than nails, please seek business elsewhere.</p>
        
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
$footerHtml
</body>
</html>
"@
Set-Content -Path "$basePath\products\index.html" -Value $productsHtml

# ==============================================================================
# 6. EMPLOYEE PORTAL (Semi-Public)
# ==============================================================================

Write-Log "Generating Employee Portal content..." "INFO"

$portalHtml = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Employee Portal - Springfield Box Factory</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
$headerHtml
$navHtml
    <div class="container">
        <h2>Employee Portal Home</h2>
        <p>Welcome to the Springfield Box Factory intranet. Please find important links below.</p>
        
        <ul>
            <li><a href="/portal/handbook/index.html">Employee Handbook (Updated 2026)</a></li>
            <li><a href="/portal/timesheets.html">Timesheet Entry System (Under Maintenance)</a></li>
            <li><a href="/portal/cafeteria.html">Cafeteria Menu</a></li>
        </ul>

        <div class="alert">
            <strong>ATTENTION IT STAFF:</strong> All network diagrams, configuration notes, and server credentials have been moved to the new <a href="/it_docs/">/it_docs/</a> directory per Gus's request. Do not store passwords on sticky notes anymore!
        </div>
    </div>
$footerHtml
</body>
</html>
"@
Set-Content -Path "$basePath\portal\index.html" -Value $portalHtml

$handbookHtml = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Employee Handbook - Springfield Box Factory</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
$headerHtml
$navHtml
    <div class="container">
        <h2>Springfield Box Factory - Employee Handbook</h2>
        <p><em>Version 14.2 - Last revised by HR</em></p>
        
        <h3>Section 1: Workplace Safety</h3>
        <p>1.1 Cardboard cuts are a reality of our industry. If you sustain a cardboard cut, report to the nurse station for an alcohol swab. Do NOT bleed on the inventory.</p>
        <p>1.2 The forklift is not a toy. Bob.</p>
        <p>1.3 In the event of a fire, do not attempt to save the boxes. They are highly flammable. Save yourself.</p>

        <h3>Section 2: Dress Code</h3>
        <p>2.1 Steel-toed boots are mandatory on the factory floor. Dropping a 50lb box of masonry nails on your foot will result in immediate termination, followed by a trip to the hospital.</p>
        <p>2.2 No loose clothing near the corrugated press.</p>

        <h3>Section 3: IT Acceptable Use</h3>
        <p>3.1 The company computers are for business use only. Gus monitors the network logs.</p>
        <p>3.2 Passwords must be at least 8 characters long and contain one number. (e.g., Boxmaker1)</p>
    </div>
$footerHtml
</body>
</html>
"@
Set-Content -Path "$basePath\portal\handbook\index.html" -Value $handbookHtml

# ==============================================================================
# 7. THE GOLDMINE: VULNERABLE IT DOCS & BACKUPS (Directory Browsing Targets)
# ==============================================================================
# We INTENTIONALLY DO NOT place an index.html in /it_docs/ or /legacy_backups/.
# This ensures that when Directory Browsing is enabled, the web server lists these files.

Write-Log "Generating sensitive IT documents for misconfiguration targets..." "WARNING"

# /it_docs/network/topology.txt
$topologyTxt = @"
SPRINGFIELD BOX FACTORY - INTERNAL NETWORK TOPOLOGY
===================================================
Last Updated: 10/12/2025 by Gus

       [INTERNET]
           |
      [FIREWALL] (pfSense - admin:admin123)
           |
      [CORE SWITCH] 10.10.0.1
       /       |       \
[DC01]     [FILESRV]   [WEB IIS (You are here)]
10.10.0.5  10.10.0.10  10.10.0.80
(AD/DNS)   (SMB/NFS)   (Port 80/443)

Notes:
- Need to patch DC01 for PrintNightmare. Keep forgetting.
- The packing machines are still on Windows XP. Do not scan them or they crash.
"@
Set-Content -Path "$basePath\it_docs\network\topology.txt" -Value $topologyTxt

# /it_docs/passwords/service_accounts.csv
$svcAccountsCsv = @"
System,Username,Password,Notes
ActiveDirectory,svc_join,BoxMakerDomainJoin!2025,Used for automated AD joins
BackupServer,svc_veeam,B@ckupS0lid!,Full admin rights on hypervisor
IIS_AppPool,svc_webadmin,IISRulesTheWorld_99,Runs the legacy timesheet app
SQL_Prod,sa,SuperSecretP@ssw0rd1,DO NOT CHANGE. Will break the inventory system.
"@
Set-Content -Path "$basePath\it_docs\passwords\service_accounts.csv" -Value $svcAccountsCsv

# /it_docs/server_build_guide.html (Just a file to be listed)
$buildGuideHtml = @"
<div class='it-article'>
    <h3>Server Build Guide - Windows Server 2022</h3>
    <p>Always disable Windows Firewall immediately after install. It breaks the old Java apps.</p>
    <div class='code-block'>
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    </div>
    <p>Local admin password for all newly built servers should be set to: <strong>P@ssw0rd_Admin</strong> until joined to domain.</p>
</div>
"@
Set-Content -Path "$basePath\it_docs\server_build_guide.html" -Value $buildGuideHtml

# /legacy_backups/web_config_backup_2024.xml
$legacyConfig = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <connectionStrings>
    <add name="InventoryDB" connectionString="Server=10.10.0.50;Database=BoxInventory;User Id=db_admin;Password=DatabaseMasterPassword!2024;" providerName="System.Data.SqlClient" />
  </connectionStrings>
  <appSettings>
    <add key="AdminAPIKey" value="8f9a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p" />
    <add key="DebugMode" value="true" />
  </appSettings>
</configuration>
"@
Set-Content -Path "$basePath\legacy_backups\web_config_backup_2024.xml" -Value $legacyConfig

$legacyReadme = @"
DO NOT DELETE THIS FOLDER.
These are the backups from before the ransomware incident in 2024. 
We still need these connection strings to access the old archive databases.
- Gus
"@
Set-Content -Path "$basePath\legacy_backups\README_DO_NOT_DELETE.txt" -Value $legacyReadme


# ==============================================================================
# 8. IIS CONFIGURATION & BINDINGS
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
# 9. APPLYING INTENTIONAL SECURITY MISCONFIGURATIONS
# ==============================================================================

Write-Log "Applying Educational Security Misconfigurations..." "WARNING"

# --- MISCONFIG 1: DIRECTORY BROWSING ---
# We enable this specifically on the /it_docs and /legacy_backups folders.
# Because these folders lack an index.html, IIS will render a file listing,
# exposing the sensitive CSV, XML, and TXT files created above.
Write-Log "Applying Misconfig: Enabling Directory Browsing on /it_docs" "VULN"
$itDocsIisPath = "IIS:\Sites\$siteName\it_docs"
Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value True -PSPath $itDocsIisPath

Write-Log "Applying Misconfig: Enabling Directory Browsing on /legacy_backups" "VULN"
$backupsIisPath = "IIS:\Sites\$siteName\legacy_backups"
Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value True -PSPath $backupsIisPath

# --- MISCONFIG 2: BASIC AUTHENTICATION OVER HTTP ---
# We enable Basic Authentication globally. Because the site is running on Port 80 (HTTP),
# credentials sent by the user will be Base64 encoded, NOT encrypted. 
# This makes them trivial to capture via packet sniffing (Wireshark) or MITM attacks.
Write-Log "Applying Misconfig: Enabling Basic Authentication globally over HTTP" "VULN"
# Unlock the section so it can be modified at the site level. Without this the
# Set-WebConfigurationProperty call will fail because the section is locked by default.
Unlock-WebConfiguration -Filter "system.webServer/security/authentication/basicAuthentication" -PSPath "MACHINE/WEBROOT/APPHOST" | Out-Null
Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/basicAuthentication -Name enabled -Value True -PSPath "IIS:\Sites\$siteName"

# Optional: Disable Anonymous Auth to force a login prompt for the entire site
# Uncomment the line below if you want the lab to REQUIRE sniffing immediately.
# Otherwise, leave it so attackers can browse the public site, but trigger auth on specific protected actions.
# Set-WebConfigurationProperty -Filter /system.webServer/security/authentication/anonymousAuthentication -Name enabled -Value False -PSPath "IIS:\Sites\$siteName"

Write-Log "=================================================================" "SUCCESS"
Write-Log "Springfield Box Factory Knowledgebase Deployment Complete." "SUCCESS"
Write-Log "Target URL: http://localhost (or via server IP)" "INFO"
Write-Log "Directory Browsing Vectors: http://<IP>/it_docs/ and http://<IP>/legacy_backups/" "VULN"
Write-Log "Basic Auth Vector: Enabled globally on Port 80." "VULN"
Write-Log "=================================================================" "SUCCESS"