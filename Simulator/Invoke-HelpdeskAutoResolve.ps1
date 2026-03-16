<#
.SYNOPSIS
    Phase 3 - Helpdesk Auto-Resolution Engine. Runs continuously on the simulator VM.

.DESCRIPTION
    Polls ITDeskDB.Tickets every 2–5 minutes for Open tickets and automatically
    resolves 80% of them by running Unlock-ADAccount against the DC.

    The remaining 20% are set to 'Assigned' status, leaving them as manual
    work items for Blue Team students to complete via the helpdesk UI.

    Workflow per cycle:
      1. GET /apps/helpdesk/api/tickets.aspx?status=Open - fetch open tickets
      2. For each open ticket, randomly decide: auto-resolve (80%) or assign (20%)
      3. Auto-resolve path:
           a. Run Unlock-ADAccount via LDAP (using BlackTeam_Scorebot creds)
           b. POST /apps/helpdesk/api/resolve.aspx  { status: "Resolved" }
           c. Log success/failure
      4. Assign path:
           POST /apps/helpdesk/api/resolve.aspx  { status: "Assigned", resolvedBy: "L1_HelpDesk" }

    This design means:
      - Blue Team always has some non-zero manual tickets to work (realism)
      - The auto-resolve loop proves Unlock-ADAccount connectivity (AD health scoring)
      - Ticket volume grows over time but never explodes (80% drainage rate)

.PARAMETER DCHostname
    FQDN or IP of the DC. Auto-detected if blank.

.PARAMETER HelpdeskBaseUrl
    Base URL for helpdesk API endpoints. Default: http://<DC>/apps/helpdesk/api

.PARAMETER CredentialFile
    Path to credentials.json.

.PARAMETER AutoResolvePercent
    Percentage of open tickets to auto-resolve per cycle (default: 80).

.PARAMETER MinIntervalSec / MaxIntervalSec
    Sleep range between polling cycles (default: 120–300 seconds = 2–5 minutes).

.NOTES
    Runs on the simulator VM (WORKGROUP - NOT domain-joined).
    Must have network access to DC on LDAP (389) and IIS on HTTP (80).

    Context: Educational / CTF / Active Directory Lab Environment
#>

param(
    [string]$DCHostname         = "",
    [string]$HelpdeskBaseUrl    = "",
    [string]$CredentialFile     = "C:\Simulator\credentials.json",
    [int]$AutoResolvePercent    = 80,
    [int]$MinIntervalSec        = 120,
    [int]$MaxIntervalSec        = 300,
    [int]$MaxTicketsPerCycle    = 20,
    [switch]$DryRun
)

$ErrorActionPreference = "SilentlyContinue"

# ==============================================================================
# LOGGING
# ==============================================================================

$LogFile = "C:\Simulator\Logs\HelpdeskAutoResolve_$(Get-Date -Format 'yyyyMMdd').log"
$LogDir  = Split-Path $LogFile
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    switch ($Level) {
        "INFO"    { Write-Host $line -ForegroundColor Cyan }
        "SUCCESS" { Write-Host $line -ForegroundColor Green }
        "WARNING" { Write-Host $line -ForegroundColor Yellow }
        "ERROR"   { Write-Host $line -ForegroundColor Red }
        default   { Write-Host $line }
    }
    $line | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

Write-Log "=================================================================" "INFO"
Write-Log "  BadderBlood Helpdesk Auto-Resolve Engine" "INFO"
Write-Log "  Phase 3 - Runs on Simulator VM" "INFO"
Write-Log "$(if ($DryRun) { '  DRY RUN MODE - no actual changes made' })" "WARNING"
Write-Log "=================================================================" "INFO"

# ==============================================================================
# CREDENTIAL HELPER
# ==============================================================================

function Get-SimCredential {
    param([string]$Key)
    try {
        $json  = Get-Content $CredentialFile -Raw -ErrorAction Stop | ConvertFrom-Json
        $entry = $json.$Key
        if (-not $entry) { return $null }
        $sec = ConvertTo-SecureString $entry.password -AsPlainText -Force
        return [PSCredential]::new("$($entry.domain)\$($entry.username)", $sec)
    } catch {
        Write-Log "Could not load credential '$Key': $_" "ERROR"
        return $null
    }
}

# ==============================================================================
# RESOLVE DC + HELPDESK URL
# ==============================================================================

if (-not $DCHostname) {
    try {
        $srvRecord  = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$env:USERDNSDOMAIN" -Type SRV -ErrorAction Stop |
                      Select-Object -First 1
        $DCHostname = $srvRecord.NameTarget
        Write-Log "Resolved DC via SRV: $DCHostname" "SUCCESS"
    } catch {
        if ($env:LOGONSERVER) {
            $DCHostname = ($env:LOGONSERVER -replace '\\\\','') + ".$env:USERDNSDOMAIN"
        } else {
            Write-Log "Cannot detect DC hostname. Use -DCHostname." "ERROR"
            exit 1
        }
    }
}

if (-not $HelpdeskBaseUrl) {
    $HelpdeskBaseUrl = "http://$DCHostname/apps/helpdesk/api"
}

$ticketsUrl = "$HelpdeskBaseUrl/tickets.aspx"
$resolveUrl = "$HelpdeskBaseUrl/resolve.aspx"

Write-Log "DC: $DCHostname" "INFO"
Write-Log "Helpdesk tickets: $ticketsUrl" "INFO"
Write-Log "Helpdesk resolve: $resolveUrl" "INFO"
Write-Log "Auto-resolve rate: $AutoResolvePercent% | Cycle: $MinIntervalSec–$MaxIntervalSec sec" "INFO"

# ==============================================================================
# AD UNLOCK FUNCTION (via DirectoryServices - no AD module needed)
# ==============================================================================

function Invoke-UnlockAccount {
    param([string]$Sam, [PSCredential]$Cred)

    if ($DryRun) {
        Write-Log "[DRY RUN] Would unlock: $Sam" "WARNING"
        return $true
    }

    try {
        $ldapPath = "LDAP://$DCHostname"
        $searcher = if ($Cred) {
            $de = New-Object System.DirectoryServices.DirectoryEntry(
                $ldapPath, $Cred.UserName, $Cred.GetNetworkCredential().Password)
            New-Object System.DirectoryServices.DirectorySearcher($de)
        } else {
            New-Object System.DirectoryServices.DirectorySearcher(
                (New-Object System.DirectoryServices.DirectoryEntry($ldapPath)))
        }

        $searcher.Filter = "(&(objectClass=user)(sAMAccountName=$Sam))"
        $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
        $result = $searcher.FindOne()
        if (-not $result) {
            Write-Log "User not found in AD: $Sam" "WARNING"
            return $false
        }

        $userDN = $result.Properties["distinguishedname"][0]
        $userDE = if ($Cred) {
            New-Object System.DirectoryServices.DirectoryEntry(
                "LDAP://$DCHostname/$userDN",
                $Cred.UserName,
                $Cred.GetNetworkCredential().Password)
        } else {
            New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DCHostname/$userDN")
        }

        # Clear lockout: set lockoutTime to 0
        $userDE.Properties["lockoutTime"].Value = 0
        $userDE.CommitChanges()
        $userDE.Dispose()
        $result.Dispose()
        Write-Log "Unlocked: $Sam" "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to unlock $Sam : $_" "WARNING"
        return $false
    }
}

# ==============================================================================
# FETCH OPEN TICKETS
# ==============================================================================

function Get-OpenTickets {
    try {
        $response = Invoke-WebRequest -Uri "$ticketsUrl?status=Open&max=$MaxTicketsPerCycle" `
            -Method GET `
            -UseDefaultCredentials `
            -TimeoutSec 15 `
            -ErrorAction Stop

        $json = $response.Content | ConvertFrom-Json
        return $json.tickets
    } catch {
        Write-Log "Could not fetch open tickets: $($_.Exception.Message)" "WARNING"
        return @()
    }
}

# ==============================================================================
# POST RESOLVE
# ==============================================================================

function Resolve-Ticket {
    param(
        [int]$TicketId,
        [string]$ResolvedBy,
        [string]$Resolution,
        [string]$Status = "Resolved"
    )

    if ($DryRun) {
        Write-Log "[DRY RUN] Would set ticket $TicketId → $Status by $ResolvedBy" "WARNING"
        return $true
    }

    $body = @{
        ticketId   = $TicketId
        resolvedBy = $ResolvedBy
        resolution = $Resolution
        status     = $Status
    } | ConvertTo-Json -Compress

    try {
        $response = Invoke-WebRequest -Uri $resolveUrl `
            -Method POST `
            -Body $body `
            -ContentType "application/json" `
            -UseDefaultCredentials `
            -TimeoutSec 15 `
            -ErrorAction Stop

        $json = $response.Content | ConvertFrom-Json
        return $json.success -eq $true
    } catch {
        Write-Log "Resolve POST failed for ticket $TicketId : $($_.Exception.Message)" "WARNING"
        return $false
    }
}

# ==============================================================================
# RESOLUTIONS TEXT POOL
# ==============================================================================

$AutoResolutions = @(
    "Account unlocked via automated monitoring. User notified to clear stale cached credentials."
    "Unlock-ADAccount executed successfully. Root cause: cached credentials on mobile device."
    "Account restored. User advised to update saved passwords in browser and mobile mail client."
    "Lockout cleared. Probable cause: old password stored in Windows Credential Manager."
    "Account unlocked. User confirmed: was using old password after recent rotation."
    "Automated unlock complete. Recommended: enroll in SSPR to reduce future helpdesk calls."
    "Account lockout resolved. No malicious activity detected in lockout source logs."
    "Unlock complete. Monitoring for recurrence over next 24 hours."
)

$L1Assignments = @(
    "Escalated to L1 IT staff for manual verification. Possible credential stuffing - review Event ID 4625 sources."
    "Assigned for manual follow-up. Pattern suggests compromised credentials - verify with user before unlocking."
    "Flagged for manual review. Multiple lockout events from different source IPs detected."
    "Assigned to L1 team. User reported they did not attempt login - possible account takeover."
)

# ==============================================================================
# MAIN LOOP
# ==============================================================================

$cycleCount     = 0
$scorebotCred   = $null
$lastCredRefresh = [datetime]::MinValue

Write-Log "Starting auto-resolve loop..." "INFO"

while ($true) {
    # Refresh credentials every 5 minutes (honours credentials.json updates)
    if (([datetime]::Now - $lastCredRefresh).TotalMinutes -gt 5) {
        $scorebotCred    = Get-SimCredential -Key "scorebot"
        $lastCredRefresh = [datetime]::Now
        if ($scorebotCred) {
            Write-Log "Scorebot credentials loaded: $($scorebotCred.UserName)" "INFO"
        } else {
            Write-Log "Scorebot credentials not found - AD unlocks may fail on non-domain-joined machine." "WARNING"
        }
    }

    $cycleCount++
    Write-Log "--- Cycle $cycleCount | $(Get-Date -Format 'HH:mm:ss') ---" "INFO"

    # Fetch open tickets
    $openTickets = Get-OpenTickets
    if ($openTickets.Count -eq 0) {
        Write-Log "No open tickets found. Sleeping..." "INFO"
    } else {
        Write-Log "Found $($openTickets.Count) open ticket(s)." "INFO"

        $autoResolved = 0
        $assigned     = 0
        $failed       = 0

        foreach ($ticket in $openTickets) {
            $tid  = $ticket.ticketId
            $tnum = $ticket.ticketNumber
            $sam  = $ticket.userSam
            $name = $ticket.displayName

            # Randomly decide: auto-resolve or assign (80/20 split)
            $roll = Get-Random -Minimum 1 -Maximum 101
            if ($roll -le $AutoResolvePercent) {
                # Auto-resolve path
                Write-Log "Auto-resolving $tnum ($sam)..." "INFO"

                $unlocked  = Invoke-UnlockAccount -Sam $sam -Cred $scorebotCred
                $resolution = ($AutoResolutions | Get-Random)
                if (-not $unlocked) {
                    $resolution = "Unlock attempt failed (user may already be unlocked or not found in AD). " + $resolution
                }

                if (Resolve-Ticket -TicketId $tid -ResolvedBy "AutoResolve_Bot" `
                        -Resolution $resolution -Status "Resolved") {
                    Write-Log "Resolved: $tnum - $sam" "SUCCESS"
                    $autoResolved++
                } else {
                    Write-Log "API update failed for $tnum" "WARNING"
                    $failed++
                }
            } else {
                # Assign to L1 for manual work
                Write-Log "Assigning $tnum ($sam) to L1 staff..." "INFO"
                $note = ($L1Assignments | Get-Random)

                if (Resolve-Ticket -TicketId $tid -ResolvedBy "L1_HelpDesk" `
                        -Resolution $note -Status "Assigned") {
                    Write-Log "Assigned: $tnum - $sam" "SUCCESS"
                    $assigned++
                } else {
                    $failed++
                }
            }

            # Brief pause between tickets to avoid hammering the API
            Start-Sleep -Milliseconds (Get-Random -Minimum 500 -Maximum 2000)
        }

        Write-Log "Cycle $cycleCount summary: AutoResolved=$autoResolved, Assigned=$assigned, Failed=$failed" "SUCCESS"
    }

    $sleepSec = Get-Random -Minimum $MinIntervalSec -Maximum $MaxIntervalSec
    Write-Log "Next cycle in $sleepSec seconds." "INFO"
    Start-Sleep -Seconds $sleepSec
}
