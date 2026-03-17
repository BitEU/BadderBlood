<#
.SYNOPSIS
    Phase 6: Installs and configures hMailServer as the Springfield Box Factory mail server.

.DESCRIPTION
    Deployment script that runs once on the DC / mail server host as Domain Admin.
    Performs the following setup steps:

    1.  Verifies hMailServer is installed (COM object check); aborts with instructions if not.
    2.  Connects to the hMailServer COM API and authenticates.
    3.  Creates the mail domain matching the AD DNS root (e.g. springfield.local).
    4.  Provisions up to $MaxMailboxes hMailServer accounts for enabled AD users.
    5.  Configures SMTP relay from 127.0.0.1 and $LabSubnet.
    6.  Verifies SMTP is listening on port 25.
    7.  Creates the BlackTeam_MailBot relay account in hMailServer.
    8.  Updates the smtp section of C:\Simulator\credentials.json with the SMTP host.
    9.  Adds a DNS MX record for the mail domain (best-effort; requires DNS Server role).
    10. Prints a summary log.

.PARAMETER HMailAdminPassword
    hMailServer administrator password (set during hMailServer install wizard).
    Required. Will be prompted interactively unless -NonInteractive is set.

.PARAMETER SharedPassword
    Password applied to all provisioned mailboxes and the BlackTeam_MailBot account.
    Defaults to the standard BadderBlood shared password if omitted.

.PARAMETER SimulatorPath
    Local path to the simulator credential store directory.
    Default: C:\Simulator

.PARAMETER MailDomain
    Override the mail domain name. Auto-detected from AD DNSRoot if blank.

.PARAMETER LabSubnet
    CIDR subnet allowed to relay through hMailServer.
    Default: 192.168.0.0/16

.PARAMETER MaxMailboxes
    Cap on provisioned user mailboxes. Default: 500.

.PARAMETER SkipMailboxProvisioning
    Skip bulk AD user mailbox creation (re-run without reprovisioning mailboxes).

.PARAMETER NonInteractive
    Suppresses all interactive prompts. Params must be fully supplied.

.NOTES
    Run AFTER:
        - Invoke-BadderBlood.ps1
        - Deploy-BlackTeamAccounts.ps1  (Phase 1)

    Must be run as Domain Admin on the DC or a machine with RSAT + DNS Server access.
    hMailServer must be installed manually before running this script:
        https://www.hmailserver.com/download

    Context: Educational / CTF / Active Directory Lab Environment
#>

#Requires -RunAsAdministrator

param(
    [string]$SqlInstance                  = "localhost\BADSQL",
    [string]$HMailAdminPassword            = "",
    [SecureString]$SharedPassword         = $null,
    [string]$SimulatorPath                = "C:\Simulator",
    [string]$LabSubnet                    = "192.168.0.0/16",
    [string]$MailDomain                   = "",
    [int]$MaxMailboxes                    = 500,
    [switch]$SkipMailboxProvisioning,
    [switch]$NonInteractive
)

# Resolve default shared password when not supplied
if (-not $SharedPassword) {
    $SharedPassword = ConvertTo-SecureString "B!ackT3am_Sc0reb0t_2025#" -AsPlainText -Force
}

# Helper: extract plaintext from SecureString
function ConvertFrom-SecureStringPlain {
    param([SecureString]$s)
    [System.Net.NetworkCredential]::new('', $s).Password
}

$ErrorActionPreference = "Stop"

# ==============================================================================
# LOGGING
# ==============================================================================

$LogFile = "$SimulatorPath\Logs\DeployMailServer_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$LogDir  = Split-Path $LogFile
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

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
    "[$ts] [$Level] $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

Write-Log "=================================================================" "INFO"
Write-Log "  BadderBlood Continuous Activity Simulator" "INFO"
Write-Log "  Phase 6: Mail Server Deployment (hMailServer)" "INFO"
Write-Log "  Educational / CTF / Lab Use Only" "WARNING"
Write-Log "=================================================================" "INFO"

# ==============================================================================
# 1. VERIFY hMAILSERVER IS INSTALLED
# ==============================================================================

Write-Log "Checking for hMailServer installation..." "STEP"

$hmsInstalled = $false

# Check registry key first (faster than COM instantiation)
try {
    $regKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\hMailServer" -ErrorAction Stop
    Write-Log "hMailServer registry key found: $($regKey.InstallLocation)" "SUCCESS"
    $hmsInstalled = $true
} catch {
    Write-Log "hMailServer registry key not found - attempting COM object check." "INFO"
}

if (-not $hmsInstalled) {
    try {
        $testCom = New-Object -ComObject hMailServer.Application -ErrorAction Stop
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($testCom) | Out-Null
        Write-Log "hMailServer COM object found." "SUCCESS"
        $hmsInstalled = $true
    } catch {
        Write-Log "hMailServer COM object not available." "WARNING"
    }
}

if (-not $hmsInstalled) {
    Write-Log "hMailServer is NOT installed on this machine." "ERROR"
    Write-Log "" "INFO"
    Write-Log "  Please install hMailServer before running this script:" "ERROR"
    Write-Log "    1. Download from https://www.hmailserver.com/download" "ERROR"
    Write-Log "    2. Run the installer and use the default installation options." "ERROR"
    Write-Log "    3. Note the administrator password you set during the install wizard." "ERROR"
    Write-Log "    4. Re-run this script and supply that password via -HMailAdminPassword." "ERROR"
    Write-Log "" "INFO"
    exit 1
}

# ==============================================================================
# 2. RESOLVE HMAILADMINPASSWORD
# ==============================================================================

Write-Log "Resolving hMailServer admin credential..." "STEP"

if ([string]::IsNullOrEmpty($HMailAdminPassword)) {
    if ($NonInteractive) {
        Write-Log "-HMailAdminPassword is required in NonInteractive mode." "ERROR"
        exit 1
    }
    Write-Log "Prompting for hMailServer administrator password (set during install)." "INFO"
    $HMailAdminPassword = Read-Host "hMailServer admin password"
}

$hmsAdminPlain = $HMailAdminPassword
$sharedPlain   = ConvertFrom-SecureStringPlain $SharedPassword

# ==============================================================================
# 3. RESOLVE ACTIVE DIRECTORY DOMAIN
# ==============================================================================

Write-Log "Resolving Active Directory domain..." "STEP"

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $Domain       = Get-ADDomain
    $DomainDNS    = $Domain.DNSRoot
    $DomainNB     = $Domain.NetBIOSName
    $DCHostname   = $env:COMPUTERNAME
    Write-Log "AD domain: $DomainDNS | NetBIOS: $DomainNB | DC: $DCHostname" "SUCCESS"
} catch {
    Write-Log "Cannot reach Active Directory: $_ " "ERROR"
    Write-Log "Ensure RSAT is installed: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" "ERROR"
    exit 1
}

if (-not $MailDomain) {
    $MailDomain = $DomainDNS
}

Write-Log "Mail domain: $MailDomain" "INFO"

# ==============================================================================
# 4. CONNECT TO HMAILSERVER COM API
# ==============================================================================

Write-Log "Connecting to hMailServer COM API..." "STEP"

try {
    $hms = New-Object -ComObject hMailServer.Application -ErrorAction Stop
    $hms.Authenticate("Administrator", $hmsAdminPlain) | Out-Null
    Write-Log "Authenticated to hMailServer COM API." "SUCCESS"
} catch {
    Write-Log "Failed to connect or authenticate to hMailServer COM API: $_" "ERROR"
    Write-Log "Verify hMailServer service is running: Get-Service hMailServer" "ERROR"
    exit 1
}

# ==============================================================================
# 5. CREATE MAIL DOMAIN
# ==============================================================================

Write-Log "Configuring mail domain '$MailDomain'..." "STEP"

try {
    $domains    = $hms.Domains
    $existingDomain = $null

    for ($i = 0; $i -lt $domains.Count; $i++) {
        if ($domains.Item($i).Name -ieq $MailDomain) {
            $existingDomain = $domains.Item($i)
            break
        }
    }

    if ($existingDomain) {
        Write-Log "Mail domain '$MailDomain' already exists - skipping creation." "INFO"
        $hmsDomain = $existingDomain
    } else {
        $hmsDomain        = $domains.Add()
        $hmsDomain.Name   = $MailDomain
        $hmsDomain.Active = $true
        $hmsDomain.Save()
        Write-Log "Mail domain '$MailDomain' created." "SUCCESS"
    }
} catch {
    Write-Log "Error configuring mail domain: $_" "ERROR"
    exit 1
}

# ==============================================================================
# 6. PROVISION USER MAILBOXES FROM AD
# ==============================================================================

$mailboxesCreated = 0
$mailboxesSkipped = 0

if ($SkipMailboxProvisioning) {
    Write-Log "Skipping mailbox provisioning (-SkipMailboxProvisioning set)." "INFO"
} else {
    Write-Log "Provisioning user mailboxes from Active Directory..." "STEP"

    try {
        $adUsers = Get-ADUser -Filter { Enabled -eq $true } `
                              -Properties EmailAddress, GivenName, Surname, Department `
                              -ErrorAction Stop |
                  Sort-Object SamAccountName |
                  Select-Object -First $MaxMailboxes

        Write-Log "Found $($adUsers.Count) enabled AD users (capped at $MaxMailboxes)." "INFO"
    } catch {
        Write-Log "Failed to query AD users: $_" "ERROR"
        exit 1
    }

    $accounts = $hmsDomain.Accounts

    foreach ($user in $adUsers) {
        # Determine email address
        $email = ""
        if ($user.EmailAddress -and $user.EmailAddress -match "@") {
            $email = $user.EmailAddress.ToLower()
        } elseif ($user.GivenName -and $user.Surname) {
            $email = "$($user.GivenName.ToLower()).$($user.Surname.ToLower())@$MailDomain"
        } else {
            $email = "$($user.SamAccountName.ToLower())@$MailDomain"
        }

        # Check if account already exists
        $existingAcct = $null
        try {
            $existingAcct = $accounts.ItemByAddress($email)
        } catch { }

        if ($existingAcct) {
            $mailboxesSkipped++
            continue
        }

        try {
            $acct           = $accounts.Add()
            $acct.Address   = $email
            $acct.Password  = $sharedPlain
            $acct.Active    = $true
            $acct.MaxSize   = 256   # MB - enough for lab traffic
            $acct.Save()
            $mailboxesCreated++
        } catch {
            Write-Log "Failed to create mailbox for $email : $_" "WARNING"
        }
    }

    Write-Log "Mailbox provisioning complete. Created: $mailboxesCreated | Skipped (already existed): $mailboxesSkipped" "SUCCESS"
}

# ==============================================================================
# 7. CONFIGURE SMTP RELAY IP RANGES
# ==============================================================================

Write-Log "Configuring SMTP relay IP ranges..." "STEP"

# Cache the IP/Security ranges COM object once.
# hMailServer 5.6+ uses SecurityRanges; older versions used IPRanges.
$hmsIPRanges = $null
try {
    $hmsIPRanges = $hms.Settings.SecurityRanges
} catch { }
if ($null -eq $hmsIPRanges) {
    try {
        $hmsIPRanges = $hms.Settings.IPRanges
    } catch { }
}
if ($null -eq $hmsIPRanges) {
    Write-Log "Could not access hMailServer SecurityRanges or IPRanges - relay IP ranges will not be configured." "WARNING"
}

function Add-HmsRelayRange {
    param(
        [string]$RangeName,
        [string]$LowerIP,
        [string]$UpperIP
    )
    if ($null -eq $hmsIPRanges) {
        Write-Log "Skipping relay range '$RangeName' - IPRanges object not available." "WARNING"
        return
    }
    try {
        # Check if range already exists
        for ($i = 0; $i -lt $hmsIPRanges.Count; $i++) {
            if ($hmsIPRanges.Item($i).Name -ieq $RangeName) {
                Write-Log "IP range '$RangeName' already exists - skipping." "INFO"
                return
            }
        }

        $range             = $hmsIPRanges.Add()
        $range.Name        = $RangeName
        $range.LowerIP     = $LowerIP
        $range.UpperIP     = $UpperIP
        # hMailServer 5.6+ renamed AllowRelay to AllowSMTPRelaying
        try   { $range.AllowSMTPRelaying = $true }
        catch { $range.AllowRelay = $true }
        $range.Save()
        Write-Log "Added relay IP range '$RangeName': $LowerIP - $UpperIP" "SUCCESS"
    } catch {
        Write-Log "Failed to add relay range '$RangeName': $_" "WARNING"
    }
}

# Always allow localhost
Add-HmsRelayRange -RangeName "Loopback"      -LowerIP "127.0.0.1"   -UpperIP "127.0.0.1"
Add-HmsRelayRange -RangeName "Loopback_IPv6" -LowerIP "::1"         -UpperIP "::1"

# Parse the lab subnet CIDR and expand to first/last host (simplified for common masks)
try {
    $cidrParts  = $LabSubnet -split "/"
    $baseIP     = $cidrParts[0]
    $prefixLen  = [int]$cidrParts[1]

    $ipBytes    = ([System.Net.IPAddress]::Parse($baseIP)).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt      = [System.BitConverter]::ToUInt32($ipBytes, 0)

    # PowerShell 5.1 parses 0xFFFFFFFF as Int32 (-1), causing overflow in shift/cast.
    # Build the mask safely from host bits using XOR with UInt32.MaxValue.
    $hostBits   = 32 - $prefixLen
    $hostMask   = [uint32]((1 -shl $hostBits) - 1)              # e.g. /24 -> 0x000000FF (255)
    $mask       = [uint32]::MaxValue -bxor $hostMask             # e.g. /24 -> 0xFFFFFF00
    $networkInt = $ipInt -band $mask
    $broadInt   = $networkInt -bor $hostMask

    $networkBytes = [System.BitConverter]::GetBytes([uint32]$networkInt)
    [Array]::Reverse($networkBytes)
    $broadBytes   = [System.BitConverter]::GetBytes([uint32]$broadInt)
    [Array]::Reverse($broadBytes)

    $lowerIP = [System.Net.IPAddress]::new($networkBytes).ToString()
    $upperIP = [System.Net.IPAddress]::new($broadBytes).ToString()

    Add-HmsRelayRange -RangeName "LabSubnet" -LowerIP $lowerIP -UpperIP $upperIP
    Write-Log "VULN: Relay is open to $LabSubnet - no authentication required for internal relay." "VULN"
} catch {
    Write-Log "Could not parse LabSubnet '$LabSubnet': $_ - skipping subnet relay rule." "WARNING"
}

# ==============================================================================
# 8. VERIFY SMTP PORT 25 IS LISTENING
# ==============================================================================

Write-Log "Verifying SMTP port 25 is listening..." "STEP"

try {
    $tcpTest = Test-NetConnection -ComputerName 127.0.0.1 -Port 25 -InformationLevel Quiet -ErrorAction SilentlyContinue
    if ($tcpTest) {
        Write-Log "SMTP port 25 is listening on 127.0.0.1." "SUCCESS"
    } else {
        Write-Log "SMTP port 25 does not appear to be listening. Verify hMailServer service and port binding." "WARNING"
        Write-Log "  Run: Get-Service hMailServer | Start-Service" "WARNING"
    }
} catch {
    Write-Log "Port check failed (non-fatal): $_" "WARNING"
}

# ==============================================================================
# 9. PROVISION BLACKTEAM_MAILBOT HMAILSERVER ACCOUNT
# ==============================================================================

Write-Log "Provisioning BlackTeam_MailBot hMailServer account..." "STEP"

$mailbotAddress = "blackteam_mailbot@$MailDomain"

try {
    $accounts        = $hmsDomain.Accounts
    $existingMailbot = $null
    try {
        $existingMailbot = $accounts.ItemByAddress($mailbotAddress)
    } catch { }

    if ($existingMailbot) {
        Write-Log "hMailServer account '$mailbotAddress' already exists - updating password." "INFO"
        $existingMailbot.Password = $sharedPlain
        $existingMailbot.Save()
        Write-Log "BlackTeam_MailBot password refreshed." "SUCCESS"
    } else {
        $mailbotAcct           = $accounts.Add()
        $mailbotAcct.Address   = $mailbotAddress
        $mailbotAcct.Password  = $sharedPlain
        $mailbotAcct.Active    = $true
        $mailbotAcct.MaxSize   = 512
        $mailbotAcct.Save()
        Write-Log "hMailServer account '$mailbotAddress' created." "SUCCESS"
    }
} catch {
    Write-Log "Failed to provision BlackTeam_MailBot account: $_" "ERROR"
    exit 1
}

# ==============================================================================
# 10. UPDATE credentials.json - smtp.smtpHost
# ==============================================================================

Write-Log "Updating credentials.json with SMTP host..." "STEP"

$credFile = Join-Path $SimulatorPath "credentials.json"

try {
    if (-not (Test-Path $credFile)) {
        Write-Log "credentials.json not found at '$credFile'." "ERROR"
        Write-Log "Run Deploy-BlackTeamAccounts.ps1 first to initialise the credential store." "ERROR"
        exit 1
    }

    $creds = Get-Content $credFile -Raw -Encoding UTF8 | ConvertFrom-Json

    # Ensure smtp node exists
    if (-not $creds.smtp) {
        $creds | Add-Member -NotePropertyName smtp -NotePropertyValue ([PSCustomObject]@{}) -Force
    }

    $creds.smtp | Add-Member -NotePropertyName smtpHost    -NotePropertyValue $DCHostname  -Force
    $creds.smtp | Add-Member -NotePropertyName smtpPort    -NotePropertyValue 25            -Force
    $creds.smtp | Add-Member -NotePropertyName mailDomain  -NotePropertyValue $MailDomain   -Force
    $creds.smtp | Add-Member -NotePropertyName lastUpdated -NotePropertyValue (Get-Date -Format "o") -Force

    $creds | ConvertTo-Json -Depth 10 | Set-Content $credFile -Encoding UTF8
    Write-Log "credentials.json updated: smtp.smtpHost = $DCHostname" "SUCCESS"
} catch {
    Write-Log "Failed to update credentials.json: $_" "ERROR"
    exit 1
}

# ==============================================================================
# 11. ADD DNS MX RECORD
# ==============================================================================

Write-Log "Adding DNS MX record for '$MailDomain'..." "STEP"

try {
    Import-Module DnsServer -ErrorAction Stop
    $mxExists = Get-DnsServerResourceRecord -ZoneName $MailDomain -RRType MX `
                    -ErrorAction SilentlyContinue |
                Where-Object { $_.RecordData.MailExchange -like "$DCHostname*" }

    if ($mxExists) {
        Write-Log "MX record for '$MailDomain' pointing to '$DCHostname' already exists." "INFO"
    } else {
        Add-DnsServerResourceRecord -ZoneName $MailDomain `
                                    -MX `
                                    -Name "@" `
                                    -MailExchange "$DCHostname.$MailDomain" `
                                    -Preference 10 `
                                    -ErrorAction Stop
        Write-Log "DNS MX record added: $MailDomain -> $DCHostname.$MailDomain (priority 10)" "SUCCESS"
    }
} catch {
    Write-Log "DNS MX record step skipped (non-fatal): $_ " "WARNING"
    Write-Log "  To add manually: Add-DnsServerResourceRecord -ZoneName $MailDomain -MX -Name '@' -MailExchange '$DCHostname.$MailDomain' -Preference 10" "WARNING"
}

# ==============================================================================
# 12. SUMMARY
# ==============================================================================

Write-Log "" "INFO"
Write-Log "=================================================================" "INFO"
Write-Log "  Deploy-MailServer.ps1 Complete" "INFO"
Write-Log "=================================================================" "INFO"
Write-Log "  Mail domain       : $MailDomain" "INFO"
Write-Log "  SMTP host         : $DCHostname (port 25)" "INFO"
Write-Log "  Relay account     : $mailbotAddress" "INFO"
Write-Log "  Mailboxes created : $mailboxesCreated" "INFO"
Write-Log "  Mailboxes skipped : $mailboxesSkipped" "INFO"
Write-Log "  credentials.json  : $credFile (smtp section updated)" "INFO"
Write-Log "" "INFO"
Write-Log "  Next step: Run Invoke-EmailSimulator.ps1 on the simulator VM" "INFO"
Write-Log "=================================================================" "INFO"
