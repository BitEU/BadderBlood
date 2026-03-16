<#
.SYNOPSIS
    Phase 5 - Customer Order Simulator. Runs continuously on the simulator VM.

.DESCRIPTION
    Generates realistic customer order HTTP POST requests to the Springfield Box
    Factory orders API endpoint (/apps/orders/api/submit.aspx) hosted on the DC's
    IIS instance.

    Order wave lifecycle:
        1. Load IIS (WebBot) credentials from credentials.json
        2. Pick 1–4 random orders (customer, boxType, quantity, region)
        3. POST JSON payload to the orders API using Windows Auth (NTLM)
           via System.Net.WebClient with NetworkCredential
        4. Log each successful OrderId + order details to the daily log
        5. On HTTP error: log warning, continue - do not crash
        6. After 3 consecutive failures: reload credentials.json, wait 60 s

    Credentials are refreshed from credentials.json every 5 minutes so that
    any credential rotation by Blue Team is picked up automatically.

.PARAMETER IisHost
    FQDN or IP of the IIS/DC host. If blank, auto-resolved from the domain
    field in credentials.json (using the domain name as the host fallback).

.PARAMETER CredentialFile
    Path to credentials.json on the simulator VM.
    Default: C:\Simulator\credentials.json

.PARAMETER LogPath
    Directory for daily rotating log files.
    Default: C:\Simulator\Logs

.PARAMETER Port
    HTTP port for the IIS endpoint. Default: 80

.NOTES
    Runs on the simulator VM (WORKGROUP - NOT domain-joined).
    Does NOT require -RunAsAdministrator.
    Requires network access to the IIS host on the specified port (default 80).

    Context: Educational / CTF / Active Directory Lab Environment
#>

param(
    [string]$IisHost        = "",
    [string]$CredentialFile = "C:\Simulator\credentials.json",
    [string]$LogPath        = "C:\Simulator\Logs",
    [int]$Port              = 80
)

$ErrorActionPreference = "SilentlyContinue"

# ==============================================================================
# LOGGING
# ==============================================================================

if (-not (Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    # Rebuild log file path daily (rotation)
    $script:LogFile = Join-Path $LogPath "OrderSimulator_$(Get-Date -Format 'yyyyMMdd').log"
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    switch ($Level) {
        "INFO"    { Write-Host $line -ForegroundColor Cyan    }
        "SUCCESS" { Write-Host $line -ForegroundColor Green   }
        "WARNING" { Write-Host $line -ForegroundColor Yellow  }
        "ERROR"   { Write-Host $line -ForegroundColor Red     }
        "STEP"    { Write-Host $line -ForegroundColor Magenta }
        default   { Write-Host $line }
    }
    $line | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
}

# Initialise log file path at startup
$script:LogFile = Join-Path $LogPath "OrderSimulator_$(Get-Date -Format 'yyyyMMdd').log"

Write-Log "=================================================================" "INFO"
Write-Log "  BadderBlood Order Simulator" "INFO"
Write-Log "  Phase 5 - Springfield Box Factory Customer Orders" "INFO"
Write-Log "  Runs on Simulator VM (non-domain-joined)" "INFO"
Write-Log "=================================================================" "INFO"

# ==============================================================================
# THEMED CONTENT POOLS
# ==============================================================================

$Customers = @(
    "Acme Roadrunner Supplies",
    "Shelbyville Paper Co",
    "Globex Export LLC",
    "Brockway Industries",
    "Ogdenville Crafts",
    "Capital City Logistics",
    "North Haverbrook Packaging",
    "Cypress Creek Industries"
)

$BoxTypes = @(
    "Finisher Box",
    "Standard Corrugated",
    "Heavy Duty Double Wall",
    "Mailer Box",
    "The Mistake",
    "Economy Flat",
    "Telescoping Box"
)

$Regions = @(
    "Northeast",
    "Southeast",
    "Midwest",
    "Southwest",
    "West Coast",
    "International"
)

# ==============================================================================
# CREDENTIAL LOADING
# ==============================================================================

function Import-IisCredential {
    <#
    .SYNOPSIS
        Loads the 'iis' entry (BlackTeam_WebBot) from credentials.json.
        Returns a hashtable with keys: Username, Password, Domain, or $null on failure.
    #>
    try {
        $raw  = Get-Content $CredentialFile -Raw -ErrorAction Stop
        $json = $raw | ConvertFrom-Json
        $entry = $json.iis
        if (-not $entry) {
            Write-Log "No 'iis' key found in $CredentialFile" "ERROR"
            return $null
        }
        return @{
            Username = $entry.username
            Password = $entry.password
            Domain   = $entry.domain
        }
    } catch {
        Write-Log "Failed to load credentials from $CredentialFile : $_" "ERROR"
        return $null
    }
}

# ==============================================================================
# IIS HOST RESOLUTION
# ==============================================================================

function Resolve-IisHost {
    <#
    .SYNOPSIS
        Resolves the IIS host from the domain field in credentials.json when
        -IisHost was not provided explicitly.
    #>
    param([hashtable]$Cred)

    # Use the domain name as a first guess (DC is often the domain FQDN root)
    if ($Cred -and $Cred.Domain) {
        Write-Log "Auto-resolving IIS host from domain field: $($Cred.Domain)" "INFO"
        # Try to find a DC via SRV record in the domain
        try {
            $srv = Resolve-DnsName -Name "_http._tcp.$($Cred.Domain)" -Type SRV -ErrorAction Stop |
                   Select-Object -First 1
            if ($srv.NameTarget) {
                Write-Log "Resolved IIS host via SRV: $($srv.NameTarget)" "SUCCESS"
                return $srv.NameTarget
            }
        } catch {}

        # Fall back: try the domain name itself (DC usually responds to its own FQDN on IIS)
        try {
            $a = Resolve-DnsName -Name $Cred.Domain -Type A -ErrorAction Stop | Select-Object -First 1
            if ($a) {
                Write-Log "Resolved IIS host via A record (domain): $($Cred.Domain)" "SUCCESS"
                return $Cred.Domain
            }
        } catch {}
    }

    Write-Log "Cannot auto-resolve IIS host. Provide -IisHost parameter." "ERROR"
    return $null
}

# ==============================================================================
# ORDER POST FUNCTION
# ==============================================================================

function Send-Order {
    <#
    .SYNOPSIS
        POSTs a single order JSON payload to the orders API using WebClient + NTLM.
        Returns a result hashtable with keys: Success (bool), OrderId, StatusCode, Error.
    #>
    param(
        [string]$Url,
        [hashtable]$Cred,
        [string]$Customer,
        [string]$BoxType,
        [int]$Quantity,
        [string]$Region
    )

    $payload = [ordered]@{
        customer = $Customer
        boxType  = $BoxType
        quantity = $Quantity
        region   = $Region
    } | ConvertTo-Json -Compress

    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Content-Type", "application/json")
        $wc.Credentials = New-Object System.Net.NetworkCredential(
            $Cred.Username,
            $Cred.Password,
            $Cred.Domain
        )

        $responseBytes = $wc.UploadData($Url, "POST", [System.Text.Encoding]::UTF8.GetBytes($payload))
        $responseText  = [System.Text.Encoding]::UTF8.GetString($responseBytes)
        $wc.Dispose()

        # Attempt to extract OrderId from JSON response
        $orderId = $null
        try {
            $respObj = $responseText | ConvertFrom-Json
            $orderId = if ($respObj.orderId)    { $respObj.orderId }
                  elseif ($respObj.OrderId)     { $respObj.OrderId }
                  elseif ($respObj.order_id)    { $respObj.order_id }
                  else                          { $null }
        } catch {}

        if (-not $orderId) {
            # No JSON / no orderId field - treat as success but no ID
            $orderId = "N/A"
        }

        return @{ Success = $true; OrderId = $orderId; StatusCode = 200; Error = $null }

    } catch [System.Net.WebException] {
        $statusCode = 0
        if ($_.Exception.Response) {
            $statusCode = [int]($_.Exception.Response.StatusCode)
        }
        $wc.Dispose()
        return @{ Success = $false; OrderId = $null; StatusCode = $statusCode; Error = $_.Exception.Message }

    } catch {
        return @{ Success = $false; OrderId = $null; StatusCode = 0; Error = $_.ToString() }
    }
}

# ==============================================================================
# MAIN LOOP
# ==============================================================================

$cred              = $null
$lastCredLoad      = [datetime]::MinValue
$credRefreshSec    = 300   # refresh credentials every 5 minutes
$resolvedHost      = $IisHost

$consecutiveFails  = 0
$maxConsecFails    = 3

$waveCount         = 0

Write-Log "Starting order simulation loop..." "INFO"
Write-Log "Credential file: $CredentialFile" "INFO"
Write-Log "Credential refresh interval: $credRefreshSec seconds" "INFO"

while ($true) {

    # ------------------------------------------------------------------
    # Refresh credentials every 5 minutes (or on first run)
    # ------------------------------------------------------------------
    $secsSinceReload = ([datetime]::Now - $lastCredLoad).TotalSeconds
    if ($secsSinceReload -ge $credRefreshSec -or $cred -eq $null) {
        Write-Log "Loading credentials from $CredentialFile ..." "INFO"
        $newCred = Import-IisCredential
        if ($newCred) {
            $cred          = $newCred
            $lastCredLoad  = [datetime]::Now
            Write-Log "Credentials loaded: $($cred.Domain)\$($cred.Username)" "SUCCESS"

            # Resolve IIS host if not yet known
            if (-not $resolvedHost) {
                $resolvedHost = Resolve-IisHost -Cred $cred
                if (-not $resolvedHost) {
                    Write-Log "IIS host unknown - sleeping 60 s before retry." "WARNING"
                    Start-Sleep -Seconds 60
                    continue
                }
                Write-Log "IIS host resolved: $resolvedHost" "SUCCESS"
            }
        } else {
            Write-Log "Credential load failed - sleeping 30 s before retry." "WARNING"
            Start-Sleep -Seconds 30
            continue
        }
    }

    # Build endpoint URL (re-evaluated each wave in case port/host changed via param reload)
    $baseUrl  = if ($Port -eq 80) { "http://$resolvedHost" } else { "http://${resolvedHost}:$Port" }
    $orderUrl = "$baseUrl/apps/orders/api/submit.aspx"

    # ------------------------------------------------------------------
    # Determine wave size and inter-wave sleep
    # ------------------------------------------------------------------
    $waveCount++
    $orderCount = Get-Random -Minimum 1 -Maximum 5   # 1–4 orders
    $sleepSec   = Get-Random -Minimum 60 -Maximum 301  # 1–5 minute gap after wave

    Write-Log "--- Wave $waveCount | Sending $orderCount order(s) to $orderUrl ---" "STEP"

    $waveSuccess = 0
    $waveFail    = 0

    for ($i = 1; $i -le $orderCount; $i++) {
        $customer = $Customers | Get-Random
        $boxType  = $BoxTypes  | Get-Random
        $quantity = Get-Random -Minimum 10 -Maximum 501   # 10–500
        $region   = $Regions   | Get-Random

        Write-Log "Order $i/$orderCount - Customer: '$customer' | BoxType: '$boxType' | Qty: $quantity | Region: $region" "INFO"

        $result = Send-Order -Url      $orderUrl `
                             -Cred     $cred     `
                             -Customer $customer `
                             -BoxType  $boxType  `
                             -Quantity $quantity `
                             -Region   $region

        if ($result.Success) {
            Write-Log "Order accepted - OrderId: $($result.OrderId) | Customer: '$customer' | BoxType: '$boxType' | Qty: $quantity | Region: $region" "SUCCESS"
            $waveSuccess++
            $consecutiveFails = 0
        } else {
            Write-Log "Order failed (HTTP $($result.StatusCode)) - $($result.Error) | Customer: '$customer' | BoxType: '$boxType' | Qty: $quantity" "WARNING"
            $waveFail++
            $consecutiveFails++

            # After 3 consecutive failures: reload creds and pause
            if ($consecutiveFails -ge $maxConsecFails) {
                Write-Log "3 consecutive order failures - reloading credentials and waiting 60 s." "WARNING"
                $newCred = Import-IisCredential
                if ($newCred) {
                    $cred         = $newCred
                    $lastCredLoad = [datetime]::Now
                    Write-Log "Credentials reloaded: $($cred.Domain)\$($cred.Username)" "INFO"
                }
                $consecutiveFails = 0
                Start-Sleep -Seconds 60
                break   # Skip remaining orders in this wave; resume next wave
            }
        }

        # Brief gap between orders in the same wave (0.5–2 s)
        if ($i -lt $orderCount) {
            Start-Sleep -Milliseconds (Get-Random -Minimum 500 -Maximum 2001)
        }
    }

    Write-Log "Wave $waveCount complete - Sent: $($waveSuccess + $waveFail) | Success: $waveSuccess | Failed: $waveFail" "INFO"
    Write-Log "Next wave in $sleepSec seconds." "INFO"

    Start-Sleep -Seconds $sleepSec
}
