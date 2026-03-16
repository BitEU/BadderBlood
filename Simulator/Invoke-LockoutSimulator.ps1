<#
.SYNOPSIS
    Phase 3 — Lockout Generator. Runs continuously on the simulator VM.

.DESCRIPTION
    Every 5–10 minutes, picks 1–3 random enabled AD users and generates
    enough bad authentication attempts to trigger AD account lockouts.
    After locking a user it immediately submits a helpdesk ticket to the
    IIS /apps/helpdesk/api/submit.aspx endpoint.

    Authentication method: DirectoryEntry LDAP bind against the DC.
    This produces AUTHENTIC Event ID 4625 (failed logon) and 4740 (lockout)
    entries in the DC's Security log — real noise for SIEM exercises.

    The script:
      - Reads the current domain lockout policy so it always trips the
        threshold regardless of what Blue Team sets it to.
      - Uses DirectoryEntry (not Test-ADAuthentication) to get 4625 events.
      - POSTs a JSON ticket to the helpdesk API using UseDefaultCredentials
        so it survives Basic→Windows Auth transitions.
      - Reads credentials from C:\Simulator\credentials.json (scorebot account).
      - Retries on transient failures; logs permanently failed users.
      - Skips privileged accounts (Domain Admins, etc.) to avoid catastrophic lockouts.

.PARAMETER DCHostname
    FQDN or IP of the domain controller. Auto-detected from DNS if blank.

.PARAMETER HelpdeskUrl
    Full URL to the helpdesk submit endpoint.
    Default: http://<DC>/apps/helpdesk/api/submit.aspx

.PARAMETER CredentialFile
    Path to credentials.json on the simulator VM.

.PARAMETER MinIntervalSec / MaxIntervalSec
    Sleep range between lockout waves. Default: 300–600 (5–10 min).

.PARAMETER MaxTargetsPerWave
    Max users to lock out per wave. Default 3 (matches plan spec).

.NOTES
    Runs on the simulator VM (WORKGROUP — NOT domain-joined).
    Requires network connectivity to DC on LDAP (389) and HTTP (80).

    Context: Educational / CTF / Active Directory Lab Environment
#>

param(
    [string]$DCHostname      = "",
    [string]$HelpdeskUrl     = "",
    [string]$CredentialFile  = "C:\Simulator\credentials.json",
    [int]$MinIntervalSec     = 300,
    [int]$MaxIntervalSec     = 600,
    [int]$MaxTargetsPerWave  = 3,
    [switch]$DryRun           # Simulate without actually sending bad passwords
)

$ErrorActionPreference = "SilentlyContinue"

# ==============================================================================
# LOGGING
# ==============================================================================

$LogFile = "C:\Simulator\Logs\LockoutSimulator_$(Get-Date -Format 'yyyyMMdd').log"
$LogDir  = Split-Path $LogFile
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
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
Write-Log "  BadderBlood Lockout Simulator" "INFO"
Write-Log "  Phase 3 — Runs on Simulator VM" "INFO"
Write-Log "$(if ($DryRun) { '  DRY RUN MODE — no bad passwords sent' })" "WARNING"
Write-Log "=================================================================" "INFO"

# ==============================================================================
# LOAD CREDENTIALS
# ==============================================================================

function Get-SimCredential {
    param([string]$Key)
    try {
        $json = Get-Content $CredentialFile -Raw -ErrorAction Stop | ConvertFrom-Json
        $entry = $json.$Key
        if (-not $entry) { return $null }
        $secPass = ConvertTo-SecureString $entry.password -AsPlainText -Force
        return [PSCredential]::new("$($entry.domain)\$($entry.username)", $secPass)
    } catch {
        Write-Log "Could not load credential '$Key' from $CredentialFile : $_" "ERROR"
        return $null
    }
}

# ==============================================================================
# RESOLVE DC HOSTNAME
# ==============================================================================

if (-not $DCHostname) {
    try {
        # On a non-domain-joined machine, resolve the DC by querying for SRV records
        $srvRecord = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$env:USERDNSDOMAIN" -Type SRV -ErrorAction Stop |
                     Select-Object -First 1
        $DCHostname = $srvRecord.NameTarget
        Write-Log "Resolved DC via SRV: $DCHostname" "SUCCESS"
    } catch {
        # Try environment variables
        if ($env:LOGONSERVER) {
            $DCHostname = ($env:LOGONSERVER -replace '\\\\','') + ".$env:USERDNSDOMAIN"
        } else {
            Write-Log "Cannot auto-detect DC hostname. Use -DCHostname parameter." "ERROR"
            exit 1
        }
    }
}

if (-not $HelpdeskUrl) {
    $HelpdeskUrl = "http://$DCHostname/apps/helpdesk/api/submit.aspx"
}

Write-Log "DC: $DCHostname" "INFO"
Write-Log "Helpdesk API: $HelpdeskUrl" "INFO"

# ==============================================================================
# LOAD SCOREBOT CREDENTIALS (for AD queries from non-domain-joined VM)
# ==============================================================================

$scorebotCred = Get-SimCredential -Key "scorebot"
if (-not $scorebotCred) {
    Write-Log "No scorebot credential found in $CredentialFile. AD user queries will use current session." "WARNING"
}

# ==============================================================================
# FETCH AD USERS (done once at startup, refreshed every hour)
# ==============================================================================

function Get-SimUsers {
    Write-Log "Fetching AD user list from $DCHostname..." "INFO"
    try {
        $ldapPath = "LDAP://$DCHostname"
        $searcher = if ($scorebotCred) {
            $de = New-Object System.DirectoryServices.DirectoryEntry($ldapPath,
                $scorebotCred.UserName, $scorebotCred.GetNetworkCredential().Password)
            New-Object System.DirectoryServices.DirectorySearcher($de)
        } else {
            New-Object System.DirectoryServices.DirectorySearcher(
                (New-Object System.DirectoryServices.DirectoryEntry($ldapPath)))
        }

        $searcher.Filter   = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.AddRange([string[]]@("sAMAccountName","displayName","department","memberOf"))

        $results = $searcher.FindAll()
        $users   = @()

        # Fetch privileged group DNs to exclude them
        $privGroups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Protected Users")
        $privDNs    = @()
        foreach ($grpName in $privGroups) {
            $gSearcher = if ($scorebotCred) {
                $gde = New-Object System.DirectoryServices.DirectoryEntry($ldapPath,
                    $scorebotCred.UserName, $scorebotCred.GetNetworkCredential().Password)
                New-Object System.DirectoryServices.DirectorySearcher($gde)
            } else {
                New-Object System.DirectoryServices.DirectorySearcher(
                    (New-Object System.DirectoryServices.DirectoryEntry($ldapPath)))
            }
            $gSearcher.Filter = "(&(objectClass=group)(name=$grpName))"
            $gSearcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
            $gResult = $gSearcher.FindOne()
            if ($gResult) { $privDNs += $gResult.Properties["distinguishedname"][0] }
        }

        foreach ($result in $results) {
            $sam     = $result.Properties["samaccountname"][0]
            $name    = if ($result.Properties["displayname"].Count   -gt 0) { $result.Properties["displayname"][0]  } else { $sam }
            $dept    = if ($result.Properties["department"].Count     -gt 0) { $result.Properties["department"][0]   } else { "" }
            $memberOf = @($result.Properties["memberof"])

            # Skip BlackTeam accounts, service accounts, and privileged users
            if ($sam -match "BlackTeam_|Administrator|Guest|krbtgt") { continue }
            if ($sam -match "^svc_|^svc-|SA$")                       { continue }

            # Skip if in any privileged group
            $isPriv = $false
            foreach ($dn in $privDNs) {
                if ($memberOf -contains $dn) { $isPriv = $true; break }
            }
            if ($isPriv) { continue }

            $users += @{ Sam = $sam; Name = $name; Dept = $dept }
        }

        $results.Dispose()
        Write-Log "Loaded $($users.Count) eligible users for lockout simulation." "SUCCESS"
        return $users
    } catch {
        Write-Log "Failed to fetch AD users: $_" "ERROR"
        return @()
    }
}

# ==============================================================================
# GET LOCKOUT THRESHOLD
# ==============================================================================

function Get-LockoutThreshold {
    try {
        $ldapPath = "LDAP://$DCHostname"
        $de = if ($scorebotCred) {
            New-Object System.DirectoryServices.DirectoryEntry($ldapPath,
                $scorebotCred.UserName, $scorebotCred.GetNetworkCredential().Password)
        } else {
            New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        }

        # lockoutThreshold is an attribute of the domain root
        $threshold = [int]$de.Properties["lockoutThreshold"].Value
        $de.Dispose()
        Write-Log "Current domain lockout threshold: $threshold" "INFO"
        return $threshold
    } catch {
        Write-Log "Could not read lockout threshold — defaulting to 5." "WARNING"
        return 5
    }
}

# ==============================================================================
# GENERATE BAD AUTH ATTEMPTS (produces Event ID 4625, then 4740)
# ==============================================================================

function Invoke-BadAuthAttempts {
    param(
        [string]$Sam,
        [string]$DCHost,
        [int]$Count,
        [PSCredential]$ValidCred   # Optional — used for context if available
    )

    if ($DryRun) {
        Write-Log "[DRY RUN] Would send $Count bad auth attempts for $Sam" "WARNING"
        return $true
    }

    $ldapPath = "LDAP://$DCHost"
    $locked   = $false

    for ($i = 1; $i -le $Count; $i++) {
        try {
            # Use a deterministically bad password that won't accidentally match
            $badPass = "WrongPass_Simulator_$(Get-Date -Format 'HHmmss')_Attempt${i}!"
            $entry   = New-Object System.DirectoryServices.DirectoryEntry(
                $ldapPath, "$Sam", $badPass,
                [System.DirectoryServices.AuthenticationTypes]::Secure
            )
            # Force the bind — this generates Event ID 4625 on the DC
            $null = $entry.NativeObject
            $entry.Dispose()
        } catch {
            # Expected: "The user name or password is incorrect" = 4625 generated
            # "The referenced account is currently locked out" = 4740 already fired
            if ($_.Exception.Message -match "locked out" -or
                $_.Exception.InnerException.Message -match "locked out") {
                $locked = $true
                break
            }
        }
        Start-Sleep -Milliseconds (Get-Random -Minimum 200 -Maximum 800)
    }

    return $true
}

# ==============================================================================
# SUBMIT HELPDESK TICKET
# ==============================================================================

function Submit-HelpdeskTicket {
    param(
        [string]$UserSam,
        [string]$DisplayName,
        [string]$Department,
        [int]$AttemptCount
    )

    $issues = @(
        "Account locked out after $AttemptCount failed login attempts. User cannot access workstation.",
        "Locked out of domain. User reports $AttemptCount incorrect password attempts detected.",
        "Account lockout triggered — $AttemptCount bad auth events recorded. Possible stale cached credentials.",
        "User locked out. Automated monitoring detected $AttemptCount failed authentications.",
        "Cannot log in — account appears locked after $AttemptCount failed attempts."
    )

    $body = @{
        userSam     = $UserSam
        displayName = $DisplayName
        department  = $Department
        issue       = ($issues | Get-Random)
        priority    = if ($AttemptCount -ge 8) { "High" } elseif ($AttemptCount -ge 5) { "Medium" } else { "Low" }
        source      = "Automated Monitoring"
    } | ConvertTo-Json -Compress

    try {
        $response = Invoke-WebRequest -Uri $HelpdeskUrl `
            -Method POST `
            -Body $body `
            -ContentType "application/json" `
            -UseDefaultCredentials `
            -TimeoutSec 15 `
            -ErrorAction Stop

        if ($response.StatusCode -eq 200) {
            $json = $response.Content | ConvertFrom-Json
            Write-Log "Ticket submitted for $UserSam — $($json.ticketNumber)" "SUCCESS"
            return $json.ticketNumber
        }
    } catch {
        Write-Log "Helpdesk POST failed for $UserSam : $($_.Exception.Message)" "WARNING"
    }
    return $null
}

# ==============================================================================
# MAIN LOOP
# ==============================================================================

$simUsers       = @()
$lastUserRefresh = [datetime]::MinValue
$waveCount      = 0

Write-Log "Starting lockout simulation loop..." "INFO"
Write-Log "Interval: $MinIntervalSec–$MaxIntervalSec seconds | Max targets/wave: $MaxTargetsPerWave" "INFO"

while ($true) {
    # Refresh user list every 60 minutes
    if (([datetime]::Now - $lastUserRefresh).TotalMinutes -gt 60 -or $simUsers.Count -eq 0) {
        $simUsers        = Get-SimUsers
        $lastUserRefresh = [datetime]::Now
        if ($simUsers.Count -eq 0) {
            Write-Log "No users available — sleeping 60s before retry..." "WARNING"
            Start-Sleep -Seconds 60
            continue
        }
    }

    # Get current lockout threshold (re-read every wave so hardening is respected)
    $threshold = Get-LockoutThreshold
    if ($threshold -eq 0) {
        Write-Log "Lockout policy is disabled (threshold=0) — no lockouts will occur. Still generating noise..." "WARNING"
        $threshold = 5   # Generate some noise events even if lockouts are off
    }

    # Pick 1–MaxTargetsPerWave random users
    $targetCount = Get-Random -Minimum 1 -Maximum ($MaxTargetsPerWave + 1)
    $targets     = $simUsers | Get-Random -Count ([Math]::Min($targetCount, $simUsers.Count))
    $waveCount++

    Write-Log "--- Wave $waveCount | Targets: $($targets.Count) | Threshold: $threshold ---" "INFO"

    foreach ($target in @($targets)) {
        $sam  = $target.Sam
        $name = $target.Name
        $dept = $target.Dept

        # Send threshold + 1..3 extra attempts to ensure lockout fires
        $attempts = $threshold + (Get-Random -Minimum 1 -Maximum 4)
        Write-Log "Sending $attempts bad auth attempts for $sam ($name)..." "INFO"

        $null = Invoke-BadAuthAttempts -Sam $sam -DCHost $DCHostname -Count $attempts

        Write-Log "Bad auth complete for $sam — submitting helpdesk ticket..." "INFO"
        $ticketNum = Submit-HelpdeskTicket -UserSam $sam -DisplayName $name `
            -Department $dept -AttemptCount $attempts

        if ($ticketNum) {
            Write-Log "Lockout wave for $sam complete. Ticket: $ticketNum" "SUCCESS"
        } else {
            Write-Log "Lockout wave for $sam complete. Ticket submission failed (endpoint may be down)." "WARNING"
        }

        # Small delay between targets in the same wave
        Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 20)
    }

    $sleepSec = Get-Random -Minimum $MinIntervalSec -Maximum $MaxIntervalSec
    Write-Log "Wave $waveCount complete. Next wave in $sleepSec seconds." "INFO"
    Start-Sleep -Seconds $sleepSec
}
