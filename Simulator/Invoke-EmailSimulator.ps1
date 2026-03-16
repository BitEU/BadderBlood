<#
.SYNOPSIS
    Phase 6 - Email Traffic Simulator. Runs continuously on the simulator VM.

.DESCRIPTION
    Generates realistic inter-office email traffic between Springfield Box Factory AD users
    using System.Net.Mail.SmtpClient against the hMailServer SMTP relay deployed by
    Deploy-MailServer.ps1.

    Behaviour summary:
      - Loads user list from user_passwords.json (written by Deploy-UserPasswordExport.ps1).
      - Refreshes the user list and credentials.json every 5 minutes.
      - Every 30–120 seconds sends 1–4 emails between randomly selected users.
      - Recipient selection:
            75% same-department
            25% cross-department, weighted by title seniority level.
      - Seven email template types with Springfield Box Factory themed content.
      - Authenticates to SMTP as BlackTeam_MailBot (relay account).
      - On 3 consecutive SMTP failures: reloads credentials, waits 60 s, retries.
      - Logs all activity to C:\Simulator\Logs\EmailSimulator_YYYYMMDD.log with daily rotation.

.PARAMETER CredentialFile
    Path to credentials.json on the simulator VM.
    Default: C:\Simulator\credentials.json

.PARAMETER UserPasswordFile
    Path to user_passwords.json (written by Deploy-UserPasswordExport.ps1).
    Default: C:\Simulator\user_passwords.json

.PARAMETER SmtpHost
    Override SMTP host. If blank, read from credentials.json smtp.smtpHost.

.PARAMETER SmtpPort
    SMTP port. Default: 25.

.PARAMETER LogPath
    Directory for daily log files. Default: C:\Simulator\Logs

.PARAMETER Verbose
    Emit additional diagnostic output.

.NOTES
    Runs on the simulator VM (WORKGROUP - NOT domain-joined).
    Requires network connectivity to the DC on SMTP port 25.
    Does NOT require domain membership or LDAP access.

    Context: Educational / CTF / Active Directory Lab Environment
#>

param(
    [string]$CredentialFile   = "C:\Simulator\credentials.json",
    [string]$UserPasswordFile = "C:\Simulator\user_passwords.json",
    [string]$SmtpHost         = "",
    [int]$SmtpPort            = 25,
    [string]$LogPath          = "C:\Simulator\Logs",
    [switch]$Verbose
)

$ErrorActionPreference = "SilentlyContinue"

# ==============================================================================
# LOGGING  (daily rotation - new file each calendar day)
# ==============================================================================

if (-not (Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }

function Get-LogFile {
    return Join-Path $LogPath "EmailSimulator_$(Get-Date -Format 'yyyyMMdd').log"
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line    = "[$ts] [$Level] $Message"
    $logFile = Get-LogFile
    switch ($Level) {
        "INFO"    { Write-Host $line -ForegroundColor Cyan }
        "SUCCESS" { Write-Host $line -ForegroundColor Green }
        "WARNING" { Write-Host $line -ForegroundColor Yellow }
        "ERROR"   { Write-Host $line -ForegroundColor Red }
        "STEP"    { Write-Host "" ; Write-Host $line -ForegroundColor White }
        default   { Write-Host $line }
    }
    if ($Verbose -or $Level -ne "INFO") {
        $line | Out-File -FilePath $logFile -Append -Encoding UTF8
    } else {
        $line | Out-File -FilePath $logFile -Append -Encoding UTF8
    }
}

Write-Log "=================================================================" "INFO"
Write-Log "  BadderBlood Continuous Activity Simulator" "INFO"
Write-Log "  Phase 6 - Email Traffic Simulator" "INFO"
Write-Log "  Educational / CTF / Lab Use Only" "WARNING"
Write-Log "=================================================================" "INFO"

# ==============================================================================
# TITLE LEVEL MAP  (keyword → integer seniority 1–8)
# ==============================================================================

$TitleLevelMap = [ordered]@{
    # Level 8 - C-suite
    "ceo"                 = 8
    "cfo"                 = 8
    "coo"                 = 8
    "cio"                 = 8
    "ciso"                = 8
    "president"           = 8
    "chief"               = 8

    # Level 7
    "vice president"      = 7
    "vp"                  = 7
    "executive director"  = 7

    # Level 6
    "senior director"     = 6
    "director"            = 6
    "senior manager"      = 6

    # Level 5
    "department manager"  = 5
    "manager"             = 5

    # Level 4
    "team lead"           = 4
    "lead"                = 4
    "supervisor"          = 4

    # Level 3
    "senior analyst"      = 3
    "senior specialist"   = 3
    "senior technician"   = 3
    "senior"              = 3

    # Level 2
    "coordinator"         = 2
    "analyst"             = 2
    "specialist"          = 2
    "technician"          = 2
    "representative"      = 2
    "associate"           = 2

    # Level 1
    "intern"              = 1
    "junior"              = 1
    "assistant"           = 1
    "trainee"             = 1
}

function Get-TitleLevel {
    param([string]$Title)
    if (-not $Title) { return 3 }
    $t = $Title.ToLower()
    foreach ($kv in $TitleLevelMap.GetEnumerator()) {
        if ($t -contains $kv.Key -or $t -like "*$($kv.Key)*") {
            return $kv.Value
        }
    }
    return 3   # Default: mid-level
}

# ==============================================================================
# SPRINGFIELD BOX FACTORY CONTENT POOLS
# ==============================================================================

$NailTypes    = @(
    '2" common nails', '16d framing nails', 'roofing nails', 'finish nails',
    'brad nails', '8d box nails', '10d sinker nails', 'duplex nails',
    'joist hanger nails', 'ring-shank nails', 'spiral shank nails', '4d smooth shank nails'
)

$BoxTypes     = @(
    'Finisher Box', 'Standard Corrugated', 'Heavy Duty Double Wall',
    'Mailer Box', 'RSC Shipping Box', 'Full Overlap Slotted Container',
    'Telescope Box', 'Bliss Box', 'Bulk Bin'
)

$Customers    = @(
    'Acme Roadrunner Supplies', 'Globex Export LLC', 'Brockway Industries',
    'Shelbyville Hardware Co.', 'Capital City Building Supplies',
    'Ogdenville Lumber & Nail', 'North Haverbrook Construction',
    'Springville Contractors Guild', 'Cypress Creek Fasteners Ltd.',
    'Quimby & Sons Industrial'
)

$Projects     = @(
    'Q3 Production Run', 'Autumn Catalogue Refresh', 'Bulk Order #SBF-4422',
    'Nail Inventory Audit', 'Box Redesign Initiative', 'Supplier Renegotiation',
    'Holiday Rush Prep', 'ISO 9001 Compliance Review', 'New Product Launch',
    'ERP Migration Phase 2', 'Packaging Cost Reduction', 'Safety Week Campaign'
)

$IssueTypes   = @(
    'inventory discrepancy', 'supplier delay', 'quality defect batch',
    'shipment mislabel', 'overdue PO approval', 'system access request',
    'budget overrun', 'equipment maintenance', 'safety incident report',
    'HR policy clarification', 'network printer offline', 'VPN connectivity issue'
)

$ApprovalItems = @(
    'PO #SBF-8821 for $14,200 in roofing nails',
    'contractor invoice INV-2024-0339 ($8,750)',
    'overtime budget for Packaging Line 3',
    'travel expense report - Springville trade show',
    'equipment lease renewal for Forklift #7',
    'new hire requisition - Inventory Coordinator',
    'software licence renewal - MRP system',
    'emergency repair quote for Baler Unit B'
)

$Departments  = @(
    'Manufacturing', 'Sales', 'HR', 'Finance', 'IT',
    'Legal', 'Operations', 'Quality Assurance', 'Logistics', 'Procurement'
)

$MgmtJargon   = @(
    'circle back', 'move the needle', 'take this offline', 'low-hanging fruit',
    'blue-sky thinking', 'boil the ocean', 'drill down', 'leverage synergies',
    'touch base', 'bandwidth', 'deep-dive', 'action items', 'deliverables'
)

# ==============================================================================
# EMAIL TEMPLATE ENGINE
# ==============================================================================

$Rng = [System.Random]::new()

function Get-RandomItem {
    param([array]$List)
    return $List[$Rng.Next(0, $List.Count)]
}

function New-EmailContent {
    param(
        [string]$FromDisplay,
        [string]$FromDept,
        [string]$ToDept,
        [string]$ToDisplay
    )

    # Roll template type
    $roll = $Rng.NextDouble()
    $type = switch ($true) {
        ($roll -lt 0.25) { "StatusUpdate" }
        ($roll -lt 0.40) { "MeetingRequest" }
        ($roll -lt 0.50) { "Escalation" }
        ($roll -lt 0.70) { "FYIForward" }
        ($roll -lt 0.85) { "Question" }
        ($roll -lt 0.95) { "ApprovalRequest" }
        default           { "SocialCasual" }
    }

    $proj    = Get-RandomItem $Projects
    $nail    = Get-RandomItem $NailTypes
    $box     = Get-RandomItem $BoxTypes
    $cust    = Get-RandomItem $Customers
    $issue   = Get-RandomItem $IssueTypes
    $item    = Get-RandomItem $ApprovalItems
    $jargon1 = Get-RandomItem $MgmtJargon
    $jargon2 = Get-RandomItem $MgmtJargon
    $dateStr = (Get-Date).AddDays($Rng.Next(1, 8)).ToString("dddd, MMMM d 'at' h:mm tt")

    switch ($type) {
        "StatusUpdate" {
            $subject = "RE: $proj - Status Update"
            $body    = @"
Hi $ToDisplay,

Just a quick update on $proj.

We've processed $(($Rng.Next(2,20)) * 100) units of $nail this week and are tracking against the
$box shipment schedule for $cust. Overall we're on track, though we may need to $jargon1
on the packaging side to avoid a bottleneck heading into month-end.

Could you $jargon2 with your team and confirm the revised forecast by EOD Thursday?

Action items:
  - Confirm inventory count for $nail (warehouse team)
  - Submit updated delivery manifest to Logistics
  - Review open POs against current stock levels

Thanks,
$FromDisplay
$FromDept | Springfield Box Factory
"@
        }

        "MeetingRequest" {
            $subject = "$FromDept Sync - $(Get-Date -Format 'MMMM yyyy')"
            $body    = @"
Hi $ToDisplay,

I'd like to schedule a $FromDept / $ToDept alignment meeting for $dateStr.

Proposed agenda:
  1. Q$(([Math]::Ceiling((Get-Date).Month / 3))) production metrics - $nail and $box lines
  2. Open items from $cust account review
  3. $proj - dependencies and blockers
  4. AOB

Please reply to confirm availability or suggest an alternative. I'll send a calendar invite
once we've agreed a slot.

Best regards,
$FromDisplay
$FromDept | Springfield Box Factory
"@
        }

        "Escalation" {
            $subject = "URGENT: $issue requires immediate attention"
            $body    = @"
$ToDisplay,

I need to escalate an issue that is impacting our ability to $jargon1 on the $cust account.

Issue: $issue
Impact: Risk to scheduled shipment of $nail ($box packaging)
Timeline: Must be resolved before $(Get-Date (Get-Date).AddDays(2) -Format 'dddd MMMM d')

I've already escalated internally within $FromDept but we are blocked without action from
your side. Could you please $jargon2 and provide a response within 2 hours?

If this requires escalation to your manager please let me know and I will join the call.

Regards,
$FromDisplay
$FromDept | Springfield Box Factory
INTERNAL - DO NOT FORWARD
"@
        }

        "FYIForward" {
            $subject = "FW: $proj - Update from $cust"
            $body    = @"
Hi $ToDisplay,

Forwarding this for your awareness - no action needed from your end at this stage,
but wanted to make sure $ToDept has visibility before our next $jargon1.

The key point from $cust is the revised order volume for $nail (up approximately
$(($Rng.Next(5,40)))% vs. last quarter). We're reviewing $box stock levels accordingly
and will $jargon2 with Procurement by end of week.

Let me know if you have any questions.

$FromDisplay
$FromDept | Springfield Box Factory

---------- Forwarded message ----------
From: orders@$(($cust -replace ' ','').ToLower()).example.com
Subject: Updated Order Forecast - $proj

Please see the attached revised forecast for Q$(([Math]::Ceiling((Get-Date).Month / 3))) [...truncated for internal distribution...]
"@
        }

        "Question" {
            $subject = "Question about $nail stock allocation"
            $body    = @"
Hi $ToDisplay,

Hope you're well. I have a quick question regarding the current $nail allocation
process - specifically whether $ToDept approves requisitions before or after
the PO is raised in the system.

Background: We're reviewing the $proj workflow and I want to make sure we're
not creating any bottlenecks. The $cust order is the main driver here.

Could you $jargon1 on this when you have a moment? Happy to $jargon2 over a
quick call if that's easier.

Thanks in advance,
$FromDisplay
$FromDept | Springfield Box Factory
"@
        }

        "ApprovalRequest" {
            $subject = "Approval needed: $item"
            $body    = @"
Hi $ToDisplay,

I'm writing to request approval for: $item

Justification:
This is required to support $proj and ensure continuity of supply for
$nail (used in $box production for $cust). Delaying this approval risks
impacting the scheduled delivery date.

Budget line: $FromDept Operations / FY$(Get-Date -Format 'yyyy') Capital
Priority: High

Please approve by replying to this email or via the Procurement portal.
If you need additional supporting documentation I can provide quotes and
the full cost-benefit summary.

Thank you,
$FromDisplay
$FromDept | Springfield Box Factory
"@
        }

        "SocialCasual" {
            $casualRoll = $Rng.NextDouble()
            if ($casualRoll -lt 0.5) {
                $subject = "Lunch today?"
                $body    = @"
Hey $ToDisplay,

Heading to the canteen around 12:30 - want to join? A few of us from $FromDept
are going. Nothing fancy, just a break from the $jargon1 spreadsheets!

Let me know,
$FromDisplay
"@
            } else {
                $subject = "Happy Birthday!"
                $body    = @"
Hi $ToDisplay,

Just wanted to wish you a happy birthday from everyone here in $FromDept!

Hope you have a great day - you deserve a break from all the $jargon1 and $jargon2.

Best wishes,
$FromDisplay & the $FromDept team
Springfield Box Factory
"@
            }
        }
    }

    return [PSCustomObject]@{
        Subject = $subject
        Body    = $body
        Type    = $type
    }
}

# ==============================================================================
# CREDENTIAL AND USER FILE LOADER
# ==============================================================================

$Script:Users        = @()
$Script:MailDomain   = ""
$Script:SmtpUser     = ""
$Script:SmtpPassword = ""
$Script:ResolvedHost = $SmtpHost
$Script:LastReload   = [datetime]::MinValue

function Import-CredentialFile {
    try {
        if (-not (Test-Path $CredentialFile)) {
            Write-Log "credentials.json not found at '$CredentialFile'." "ERROR"
            return $false
        }
        $creds = Get-Content $CredentialFile -Raw -Encoding UTF8 | ConvertFrom-Json

        if ($creds.smtp) {
            if (-not $SmtpHost -and $creds.smtp.smtpHost) {
                $Script:ResolvedHost = $creds.smtp.smtpHost
            }
            if ($creds.smtp.mailDomain) {
                $Script:MailDomain = $creds.smtp.mailDomain
            }
            if ($creds.smtp.username) {
                $Script:SmtpUser = $creds.smtp.username
            }
            if ($creds.smtp.password) {
                $Script:SmtpPassword = $creds.smtp.password
            }
        }

        Write-Log "Credentials loaded. SMTP host: $($Script:ResolvedHost) | User: $($Script:SmtpUser)" "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to load credentials.json: $_" "WARNING"
        return $false
    }
}

function Import-UserList {
    try {
        if (-not (Test-Path $UserPasswordFile)) {
            Write-Log "user_passwords.json not found at '$UserPasswordFile'." "ERROR"
            return $false
        }

        $raw   = Get-Content $UserPasswordFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $users = @()

        foreach ($u in $raw) {
            # Build email: prefer explicit email, else firstname.lastname@domain
            $email = ""
            if ($u.Email -and $u.Email -match "@") {
                $email = $u.Email.ToLower()
            } elseif ($u.DisplayName -and $Script:MailDomain) {
                $parts = ($u.DisplayName -split "\s+", 2)
                if ($parts.Count -eq 2) {
                    $email = "$($parts[0].ToLower()).$($parts[1].ToLower())@$($Script:MailDomain)"
                } else {
                    $email = "$($u.SamAccountName.ToLower())@$($Script:MailDomain)"
                }
            } elseif ($u.SamAccountName -and $Script:MailDomain) {
                $email = "$($u.SamAccountName.ToLower())@$($Script:MailDomain)"
            }

            if (-not $email) { continue }

            $users += [PSCustomObject]@{
                Sam         = $u.SamAccountName
                DisplayName = if ($u.DisplayName) { $u.DisplayName } else { $u.SamAccountName }
                Department  = if ($u.Department)  { $u.Department  } else { "General" }
                Title       = if ($u.Title)        { $u.Title       } else { "" }
                TitleLevel  = Get-TitleLevel ($u.Title)
                Email       = $email
                Domain      = $u.Domain
            }
        }

        $Script:Users = $users
        Write-Log "Loaded $($users.Count) users from user_passwords.json" "SUCCESS"

        # Build department index for fast lookup
        $Script:DeptMap = @{}
        foreach ($u in $Script:Users) {
            if (-not $Script:DeptMap.ContainsKey($u.Department)) {
                $Script:DeptMap[$u.Department] = @()
            }
            $Script:DeptMap[$u.Department] += $u
        }
        Write-Log "Departments indexed: $($Script:DeptMap.Keys -join ', ')" "INFO"
        return $true
    } catch {
        Write-Log "Failed to load user list: $_" "WARNING"
        return $false
    }
}

function Invoke-DataRefresh {
    $now = Get-Date
    if (($now - $Script:LastReload).TotalMinutes -ge 5) {
        Write-Log "Refreshing credentials and user list..." "INFO"
        Import-CredentialFile | Out-Null
        Import-UserList       | Out-Null
        $Script:LastReload = $now
    }
}

# ==============================================================================
# RECIPIENT SELECTION
# ==============================================================================

function Select-Recipient {
    param([PSCustomObject]$Sender)

    if ($Script:Users.Count -lt 2) { return $null }

    $useSameDept = ($Rng.NextDouble() -lt 0.75)

    if ($useSameDept -and $Script:DeptMap.ContainsKey($Sender.Department) -and
        $Script:DeptMap[$Sender.Department].Count -gt 1) {

        # Same-department - exclude the sender
        $pool = $Script:DeptMap[$Sender.Department] | Where-Object { $_.Email -ne $Sender.Email }
        if ($pool) {
            return $pool[$Rng.Next(0, $pool.Count)]
        }
    }

    # Cross-department - weighted by seniority proximity
    $candidates = $Script:Users | Where-Object { $_.Email -ne $Sender.Email -and $_.Department -ne $Sender.Department }
    if (-not $candidates) { return $null }

    # Assign weights based on level difference (peer 50%, ±1 25%, ±2 12.5%, ±3+ 12.5%)
    $weights = foreach ($c in $candidates) {
        $diff = [Math]::Abs($c.TitleLevel - $Sender.TitleLevel)
        $w = switch ($diff) {
            0       { 50 }
            1       { 25 }
            2       { 12 }
            default { 8  }
        }
        $w
    }
    $totalWeight = ($weights | Measure-Object -Sum).Sum
    if ($totalWeight -eq 0) {
        return $candidates[$Rng.Next(0, $candidates.Count)]
    }

    $roll = $Rng.Next(0, $totalWeight)
    $running = 0
    for ($i = 0; $i -lt $candidates.Count; $i++) {
        $running += $weights[$i]
        if ($roll -lt $running) {
            return $candidates[$i]
        }
    }
    return $candidates[$Rng.Next(0, $candidates.Count)]
}

# ==============================================================================
# SMTP SEND FUNCTION
# ==============================================================================

function Send-SimEmail {
    param(
        [string]$From,
        [string]$FromDisplay,
        [string]$To,
        [string]$Subject,
        [string]$Body
    )

    $smtpHost = $Script:ResolvedHost
    if (-not $smtpHost) {
        Write-Log "SMTP host not configured - skipping send." "WARNING"
        return $false
    }

    try {
        $client                  = [System.Net.Mail.SmtpClient]::new($smtpHost, $SmtpPort)
        $client.EnableSsl        = $false
        $client.DeliveryMethod   = [System.Net.Mail.SmtpDeliveryMethod]::Network
        $client.Timeout          = 15000

        # Authenticate as MailBot relay account
        if ($Script:SmtpUser -and $Script:SmtpPassword) {
            $client.Credentials = [System.Net.NetworkCredential]::new(
                $Script:SmtpUser, $Script:SmtpPassword
            )
        }

        $msg                  = [System.Net.Mail.MailMessage]::new()
        $msg.From             = [System.Net.Mail.MailAddress]::new($From, $FromDisplay)
        $msg.To.Add($To)
        $msg.Subject          = $Subject
        $msg.Body             = $Body
        $msg.IsBodyHtml       = $false
        $msg.Headers.Add("X-Mailer", "Springfield Box Factory Internal Mail v2.1")
        $msg.Headers.Add("X-SBF-Simulator", "BadderBlood-Phase6")

        $client.Send($msg)
        $msg.Dispose()
        $client.Dispose()
        return $true
    } catch {
        Write-Log "SMTP send failed [$From -> $To]: $_" "WARNING"
        return $false
    }
}

# ==============================================================================
# MAIN SIMULATION LOOP
# ==============================================================================

# Initial load
Import-CredentialFile | Out-Null

if (-not $Script:ResolvedHost) {
    Write-Log "SMTP host could not be determined from credentials.json or -SmtpHost param." "ERROR"
    Write-Log "Run Deploy-MailServer.ps1 on the DC first, or supply -SmtpHost <hostname>." "ERROR"
    exit 1
}

Import-UserList | Out-Null
$Script:LastReload = Get-Date

if ($Script:Users.Count -lt 2) {
    Write-Log "Not enough users loaded to simulate email traffic (need at least 2)." "ERROR"
    Write-Log "Verify user_passwords.json exists and contains valid entries." "ERROR"
    exit 1
}

Write-Log "Email simulator started. SMTP: $($Script:ResolvedHost):$SmtpPort | Users: $($Script:Users.Count)" "SUCCESS"
Write-Log "Sending 1–4 emails every 30–120 seconds. Press Ctrl+C to stop." "INFO"

$consecutiveFailures = 0
$totalSent           = 0
$totalFailed         = 0
$cycleCount          = 0

while ($true) {
    $cycleCount++
    Invoke-DataRefresh

    # Determine batch size for this cycle
    $batchSize = $Rng.Next(1, 5)   # 1–4 inclusive

    Write-Log "--- Cycle $cycleCount: sending $batchSize email(s) ---" "STEP"

    for ($e = 0; $e -lt $batchSize; $e++) {
        if ($Script:Users.Count -lt 2) { break }

        # Pick random sender
        $sender    = $Script:Users[$Rng.Next(0, $Script:Users.Count)]
        $recipient = Select-Recipient -Sender $sender

        if (-not $recipient) {
            Write-Log "Could not select recipient - skipping email $($e+1)." "WARNING"
            continue
        }

        $content = New-EmailContent `
            -FromDisplay $sender.DisplayName `
            -FromDept    $sender.Department `
            -ToDept      $recipient.Department `
            -ToDisplay   $recipient.DisplayName

        Write-Log "[$($content.Type)] From: $($sender.Email) To: $($recipient.Email) Subject: $($content.Subject)" "INFO"

        $sent = Send-SimEmail `
            -From        $sender.Email `
            -FromDisplay $sender.DisplayName `
            -To          $recipient.Email `
            -Subject     $content.Subject `
            -Body        $content.Body

        if ($sent) {
            $totalSent++
            $consecutiveFailures = 0
            Write-Log "Sent OK (total: $totalSent)" "SUCCESS"
        } else {
            $totalFailed++
            $consecutiveFailures++
            Write-Log "Send failed (consecutive failures: $consecutiveFailures; total failed: $totalFailed)" "WARNING"

            if ($consecutiveFailures -ge 3) {
                Write-Log "3 consecutive SMTP failures - reloading credentials and waiting 60 s." "WARNING"
                Import-CredentialFile | Out-Null
                Start-Sleep -Seconds 60
                $consecutiveFailures = 0
            }
        }
    }

    # Sleep 30–120 seconds before next cycle
    $sleepSec = $Rng.Next(30, 121)
    Write-Log "Next cycle in $sleepSec s  |  Sent all-time: $totalSent  |  Failed: $totalFailed" "INFO"
    Start-Sleep -Seconds $sleepSec
}
