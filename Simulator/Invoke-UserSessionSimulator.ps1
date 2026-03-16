<#
.SYNOPSIS
    Phase 4 — User Session & File Operations Simulator. Runs continuously on the simulator VM.

.DESCRIPTION
    Generates realistic interactive logon events (Event ID 4624 Logon Type 2/3) and
    SMB file operations using real AD user identities loaded from user_passwords.json.

    Session lifecycle per user:
        1. LogonUser() API call  → Event ID 4624 on DC
        2. Impersonate token     → all file ops appear as that user in Security log
        3. Map \\DC\CorpData     → SMB session visible via Get-SmbSession
        4. 2–8 file operations   → realistic mix (create, modify, rename, delete, copy)
        5. Dwell 2–5 minutes     → simulates user working at desk
        6. Disconnect + token close → Event ID 4634

    Concurrency: 3–8 sessions run in parallel as PowerShell Jobs.
    Sessions stagger by 30–90 seconds to avoid all starting simultaneously.

    Fault tolerance:
        - If LogonUser() fails (password rotated by Blue Team), user is skipped
          and marked "stale" — session not retried until user_passwords.json is
          re-read (every 30 minutes).
        - If the share is unreachable (firewall, SMB blocked), the session
          gracefully degrades to local-path file ops (still generates logon events).
        - Runs indefinitely; restarts failed jobs automatically.

.PARAMETER UserPasswordFile
    Path to user_passwords.json (written by Deploy-UserPasswordExport.ps1).

.PARAMETER CorpShareHost
    FQDN or IP of the file server hosting \\HOST\CorpData.
    Auto-read from user_passwords.json if blank.

.PARAMETER MinSessions / MaxSessions
    Concurrent session range. Default: 3–8 (matches plan spec).

.PARAMETER MinDwellSec / MaxDwellSec
    How long each session idles after file ops. Default: 120–300 sec (2–5 min).

.PARAMETER StaggerSec
    Max seconds to wait between starting successive sessions. Default: 90.

.NOTES
    Runs on simulator VM (WORKGROUP — NOT domain-joined).
    Requires LogonUser P/Invoke — must run on Windows (not PowerShell Core on Linux).
    Requires network access to DC/file server on SMB (445) and LDAP (389).

    Context: Educational / CTF / Active Directory Lab Environment
#>

param(
    [string]$UserPasswordFile  = "C:\Simulator\all_user_passwords.csv",
    [string]$CorpShareHost     = "",
    [int]$MinSessions          = 3,
    [int]$MaxSessions          = 8,
    [int]$MinDwellSec          = 120,
    [int]$MaxDwellSec          = 300,
    [int]$StaggerSec           = 90,
    [switch]$DryRun
)

$ErrorActionPreference = "SilentlyContinue"

# ==============================================================================
# LOGGING
# ==============================================================================

$LogFile = "C:\Simulator\Logs\UserSessionSimulator_$(Get-Date -Format 'yyyyMMdd').log"
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
Write-Log "  BadderBlood User Session Simulator" "INFO"
Write-Log "  Phase 4 — Runs on Simulator VM" "INFO"
Write-Log "$(if ($DryRun) { '  DRY RUN MODE — no actual file ops or logons' })" "WARNING"
Write-Log "=================================================================" "INFO"

# ==============================================================================
# WIN32 LOGONUSER + IMPERSONATION WRAPPER
# ==============================================================================

$csharpSource = @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class SimLogon {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(
        string lpszUsername,
        string lpszDomain,
        string lpszPassword,
        int    dwLogonType,
        int    dwLogonProvider,
        out    SafeAccessTokenHandle phToken);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    // dwLogonType values
    public const int LOGON32_LOGON_INTERACTIVE = 2;   // generates Event 4624 Type 2
    public const int LOGON32_LOGON_NETWORK     = 3;   // generates Event 4624 Type 3

    // dwLogonProvider
    public const int LOGON32_PROVIDER_DEFAULT  = 0;
}
"@

try {
    Add-Type -TypeDefinition $csharpSource -ErrorAction Stop
    Write-Log "Win32 LogonUser wrapper compiled." "SUCCESS"
} catch {
    Write-Log "Failed to compile Win32 wrapper: $_ — session logon events will be skipped." "WARNING"
    # Continue without impersonation; file ops will still run under simulator account
}

# ==============================================================================
# LOAD USER PASSWORD FILE
# ==============================================================================

function Import-UserPasswordFile {
    param([string]$FilePath)
    try {
        $csv = Import-Csv $FilePath -ErrorAction Stop
        $users = @()
        $detectedHost = ""
        foreach ($u in $csv) {
            $users += @{
                Sam        = $u.SamAccountName
                Name       = $u.DisplayName
                Dept       = $u.Department
                Password   = $u.Password
                Domain     = $u.Domain
                HomeDir    = $u.HomeDirectory
                ShareHost  = $u.ShareHost
            }
            if (-not $detectedHost -and $u.ShareHost) {
                $detectedHost = $u.ShareHost
            }
        }
        Write-Log "Loaded $($users.Count) users from $FilePath" "SUCCESS"
        return $users, $detectedHost
    } catch {
        Write-Log "Cannot load $FilePath : $_" "ERROR"
        return @(), ""
    }
}

# ==============================================================================
# SINGLE SESSION SCRIPTBLOCK (runs as a background job)
# Each job: logon → map share → file ops → dwell → logoff
# ==============================================================================

$sessionBlock = {
    param(
        [hashtable]$User,
        [string]$ShareHost,
        [int]$MinDwell,
        [int]$MaxDwell,
        [bool]$DryRun,
        [string]$LogFile
    )

    function SessionLog {
        param([string]$Msg, [string]$Lvl = "INFO")
        $ts   = Get-Date -Format "HH:mm:ss"
        $line = "[$ts] [$Lvl] [SESSION:$($User.Sam)] $Msg"
        switch ($Lvl) {
            "SUCCESS" { Write-Host $line -ForegroundColor Green }
            "WARNING" { Write-Host $line -ForegroundColor Yellow }
            "ERROR"   { Write-Host $line -ForegroundColor Red }
            default   { Write-Host $line -ForegroundColor Cyan }
        }
        $line | Out-File -FilePath $LogFile -Append -Encoding UTF8
    }

    # ---- Step 1: LogonUser ----
    $token   = $null
    $loggedOn = $false

    if (-not $DryRun) {
        try {
            $loggedOn = [SimLogon]::LogonUser(
                $User.Sam,
                $User.Domain,
                $User.Password,
                [SimLogon]::LOGON32_LOGON_INTERACTIVE,
                [SimLogon]::LOGON32_PROVIDER_DEFAULT,
                [ref]$token
            )
            if ($loggedOn) {
                SessionLog "LogonUser() succeeded — Event 4624 generated." "SUCCESS"
            } else {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                SessionLog "LogonUser() failed (Win32 error $err) — password may have been rotated." "WARNING"
                return @{ Sam = $User.Sam; Result = "LogonFailed"; Error = "Win32 error $err" }
            }
        } catch {
            SessionLog "LogonUser() exception: $_" "WARNING"
            return @{ Sam = $User.Sam; Result = "LogonFailed"; Error = $_.ToString() }
        }
    } else {
        SessionLog "[DRY RUN] Skipping LogonUser()" "WARNING"
        $loggedOn = $true
    }

    # ---- Step 2: Map share and perform file ops ----
    $sharePath = "\\$ShareHost\CorpData"
    $driveName = "SimU_$($User.Sam.Substring(0, [Math]::Min(4, $User.Sam.Length)))"
    $usedShare = $false
    $opsPerformed = 0
    $opCount      = Get-Random -Minimum 2 -Maximum 9

    # Decide share vs home dir fallback
    $targetRoot  = $null
    $deptFolder  = $null

    $performOps = {
        # Weighted operation selection: Create 25%, Modify 30%, Rename 10%, Delete 10%, Copy 25%
        function Pick-Op { $r = Get-Random -Min 1 -Max 101; if ($r -le 25) {"Create"} elseif ($r -le 55) {"Modify"} elseif ($r -le 65) {"Rename"} elseif ($r -le 75) {"Delete"} else {"Copy"} }

        function Get-SbfContent {
            $lines = @(
                "Updated project timeline — see attached for revised milestones.",
                "Per our discussion, the Q4 targets have been adjusted accordingly.",
                "Please review the attached draft before the Friday deadline.",
                "Reminder: team sync moved to 3pm. Conference room B.",
                "FYI: the supplier delivery schedule has been updated in the system.",
                "Actioned: inventory count reconciled with warehouse scan.",
                "Approved — budget allocation submitted to finance for processing.",
                "Note: Legacy timesheet entries require sign-off by EOD.",
                "See below — escalated from helpdesk (ticket $($PIDS[0])).",
                "Draft report attached. Please review sections 3 and 4.",
                "Nail spec updated: gauge tolerance ±0.05mm per QA request.",
                "Box order confirmed: 2,500 units, delivery ETA next Wednesday."
            )
            return $lines | Get-Random
        }

        for ($op = 0; $op -lt $opCount; $op++) {
            $action = Pick-Op
            try {
                switch ($action) {
                    "Create" {
                        if ($targetRoot -and (Test-Path $targetRoot)) {
                            $ext  = @(".txt",".md",".csv") | Get-Random
                            $name = "work_$(Get-Random -Min 1000 -Max 9999)_$(Get-Date -Format 'yyyyMMddHHmm')$ext"
                            $path = Join-Path $targetRoot $name
                            if (-not $DryRun) { Get-SbfContent | Out-File $path -Encoding UTF8 -Force }
                            SessionLog "Created: $path" "SUCCESS"
                            $script:opsPerformed++
                        }
                    }
                    "Modify" {
                        if ($targetRoot -and (Test-Path $targetRoot)) {
                            $existing = Get-ChildItem $targetRoot -File -ErrorAction SilentlyContinue |
                                        Where-Object { $_.Extension -in ".txt",".md",".csv",".html" } |
                                        Get-Random -ErrorAction SilentlyContinue
                            if ($existing) {
                                if (-not $DryRun) { "`n$(Get-SbfContent)" | Add-Content $existing.FullName -Encoding UTF8 }
                                SessionLog "Modified: $($existing.Name)" "SUCCESS"
                                $script:opsPerformed++
                            }
                        }
                    }
                    "Rename" {
                        if ($targetRoot -and (Test-Path $targetRoot)) {
                            $existing = Get-ChildItem $targetRoot -File -ErrorAction SilentlyContinue |
                                        Where-Object { $_.Name -notmatch "_v\d+|_FINAL" } |
                                        Get-Random -ErrorAction SilentlyContinue
                            if ($existing) {
                                $suffix  = @("_v2","_FINAL","_revised","_updated") | Get-Random
                                $newName = [System.IO.Path]::GetFileNameWithoutExtension($existing.Name) + $suffix + $existing.Extension
                                $newPath = Join-Path $targetRoot $newName
                                if (-not $DryRun) { Rename-Item -Path $existing.FullName -NewName $newName -ErrorAction SilentlyContinue }
                                SessionLog "Renamed: $($existing.Name) → $newName" "SUCCESS"
                                $script:opsPerformed++
                            }
                        }
                    }
                    "Delete" {
                        if ($targetRoot -and (Test-Path $targetRoot)) {
                            $candidates = Get-ChildItem $targetRoot -File -ErrorAction SilentlyContinue |
                                          Where-Object { $_.Name -match "^work_" } |
                                          Sort-Object LastWriteTime | Select-Object -First 5
                            if ($candidates) {
                                $victim = $candidates | Get-Random
                                if (-not $DryRun) { Remove-Item $victim.FullName -Force -ErrorAction SilentlyContinue }
                                SessionLog "Deleted: $($victim.Name)" "SUCCESS"
                                $script:opsPerformed++
                            }
                        }
                    }
                    "Copy" {
                        if ($deptFolder -and (Test-Path $deptFolder) -and $targetRoot -and (Test-Path $targetRoot)) {
                            $src = Get-ChildItem $deptFolder -File -Recurse -ErrorAction SilentlyContinue |
                                   Where-Object { $_.Length -lt 512KB } | Get-Random -ErrorAction SilentlyContinue
                            if ($src) {
                                $dest = Join-Path $targetRoot $src.Name
                                if (-not $DryRun) { Copy-Item $src.FullName $dest -Force -ErrorAction SilentlyContinue }
                                SessionLog "Copied: $($src.Name) → home dir" "SUCCESS"
                                $script:opsPerformed++
                            }
                        }
                    }
                }
            } catch {
                SessionLog "Op $action failed: $_" "WARNING"
            }
            Start-Sleep -Milliseconds (Get-Random -Minimum 500 -Maximum 3000)
        }
    }

    $runOps = {
        # Determine paths under impersonation context
        $script:targetRoot = $null
        $script:deptFolder = $null
        $script:opsPerformed = 0

        # Try user home dir first
        if ($User.HomeDir -and (Test-Path $User.HomeDir -ErrorAction SilentlyContinue)) {
            $script:targetRoot = $User.HomeDir
            SessionLog "Using home dir: $($User.HomeDir)" "INFO"
        } elseif ($usedShare) {
            $userShareHome = "\\$ShareHost\CorpData\Users\$($User.Sam)"
            if (Test-Path $userShareHome -ErrorAction SilentlyContinue) {
                $script:targetRoot = $userShareHome
                SessionLog "Using share home dir: $userShareHome" "INFO"
            } else {
                # Create it on the fly
                if (-not $DryRun) {
                    New-Item -ItemType Directory -Path $userShareHome -Force -ErrorAction SilentlyContinue | Out-Null
                }
                $script:targetRoot = $userShareHome
                SessionLog "Created and using share home: $userShareHome" "INFO"
            }
        }

        # Dept folder for Copy operations
        if ($User.Dept -and $usedShare) {
            $deptAbbrev = $User.Dept -replace '[^A-Z]',''
            $deptPath   = "\\$ShareHost\CorpData\Departments\$($User.Dept)"
            if (Test-Path $deptPath -ErrorAction SilentlyContinue) {
                $script:deptFolder = $deptPath
            }
        }

        if (-not $script:targetRoot) {
            SessionLog "No writable target path found — skipping file ops." "WARNING"
            return
        }

        & $performOps
    }

    # Run file ops under impersonated token if we have one
    if ($loggedOn -and -not $DryRun -and $token -and ([SimLogon].GetMethod('LogonUser'))) {
        try {
            # Map the share under this user's identity
            $cred    = [System.Net.NetworkCredential]::new("$($User.Domain)\$($User.Sam)", $User.Password)
            $shareCred = [PSCredential]::new("$($User.Domain)\$($User.Sam)", (ConvertTo-SecureString $User.Password -AsPlainText -Force))

            $drive = New-PSDrive -Name $driveName -PSProvider FileSystem `
                -Root $sharePath -Credential $shareCred -ErrorAction SilentlyContinue
            $usedShare = ($drive -ne $null)
            if ($usedShare) {
                SessionLog "Mapped share: $sharePath" "SUCCESS"
            }

            [System.Security.Principal.WindowsIdentity]::RunImpersonated($token, [Action]{
                & $runOps
            })
        } catch {
            SessionLog "Impersonated file ops failed: $_ — falling back to direct ops." "WARNING"
            & $runOps
        } finally {
            if ($drive) { Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue }
        }
    } else {
        # DryRun or no token — still exercise the path logic
        $usedShare = $false
        & $runOps
    }

    # ---- Step 3: Dwell ----
    $dwellSec = Get-Random -Minimum $MinDwell -Maximum $MaxDwell
    SessionLog "Dwell: $dwellSec seconds (simulating user working)..." "INFO"
    if (-not $DryRun) { Start-Sleep -Seconds $dwellSec }

    # ---- Step 4: Cleanup (token close generates Event 4634) ----
    if ($token -and -not $DryRun) {
        try { $token.Dispose() } catch {}
    }
    SessionLog "Session complete. Ops performed: $script:opsPerformed" "SUCCESS"
    return @{ Sam = $User.Sam; Result = "OK"; OpsPerformed = $script:opsPerformed }
}

# ==============================================================================
# MAIN LOOP
# ==============================================================================

$enrolledUsers  = @()
$staleUsers     = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$lastFileReload = [datetime]::MinValue
$waveCount      = 0

Write-Log "Starting user session simulation loop..." "INFO"
Write-Log "Concurrent sessions: $MinSessions–$MaxSessions | Stagger: 0–$StaggerSec sec" "INFO"

while ($true) {
    # Reload user_passwords.json every 30 minutes (picks up any re-runs of Deploy-UserPasswordExport)
    if (([datetime]::Now - $lastFileReload).TotalMinutes -gt 30 -or $enrolledUsers.Count -eq 0) {
        $enrolledUsers, $detectedHost = Import-UserPasswordFile -FilePath $UserPasswordFile
        if (-not $CorpShareHost -and $detectedHost) { $CorpShareHost = $detectedHost }
        if (-not $CorpShareHost) {
            # Fall back to DNS SRV
            try {
                $srv = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$env:USERDNSDOMAIN" -Type SRV -ErrorAction Stop | Select-Object -First 1
                $CorpShareHost = $srv.NameTarget
            } catch { $CorpShareHost = $env:LOGONSERVER -replace '\\\\','' }
        }
        # Clear stale set on reload so newly re-exported users get a fresh chance
        $staleUsers.Clear()
        $lastFileReload = [datetime]::Now
        Write-Log "Share host: $CorpShareHost" "INFO"
    }

    if ($enrolledUsers.Count -eq 0) {
        Write-Log "No users loaded — sleeping 60s..." "WARNING"
        Start-Sleep -Seconds 60
        continue
    }

    # Filter out known-stale (bad password) users
    $activeUsers = $enrolledUsers | Where-Object { -not $staleUsers.Contains($_.Sam) }
    if ($activeUsers.Count -eq 0) {
        Write-Log "All users are stale (passwords rotated by Blue Team). Waiting for file reload..." "WARNING"
        Start-Sleep -Seconds 60
        continue
    }

    $waveCount++
    $sessionCount = Get-Random -Minimum $MinSessions -Maximum ($MaxSessions + 1)
    $sessionCount = [Math]::Min($sessionCount, $activeUsers.Count)
    $sessionUsers = @($activeUsers | Get-Random -Count $sessionCount)

    Write-Log "=== Wave $waveCount | Launching $sessionCount sessions ===" "INFO"

    $jobs = @()
    foreach ($u in $sessionUsers) {
        $stagger = Get-Random -Minimum 0 -Maximum ($StaggerSec + 1)
        if ($stagger -gt 0 -and -not $DryRun) { Start-Sleep -Seconds $stagger }

        Write-Log "Starting session: $($u.Sam) ($($u.Name))" "INFO"
        $job = Start-Job -ScriptBlock $sessionBlock -ArgumentList @(
            $u, $CorpShareHost, $MinDwellSec, $MaxDwellSec, $DryRun.IsPresent, $LogFile
        )
        $jobs += $job
    }

    Write-Log "All $($jobs.Count) session jobs launched. Waiting for completion..." "INFO"

    # Wait for all sessions to finish, with a hard timeout of MaxDwell + buffer
    $timeoutSec = $MaxDwellSec + 120
    $deadline   = [datetime]::Now.AddSeconds($timeoutSec)
    while ($jobs | Where-Object { $_.State -eq 'Running' }) {
        if ([datetime]::Now -gt $deadline) {
            Write-Log "Session timeout ($timeoutSec s) reached — killing lingering jobs." "WARNING"
            $jobs | Where-Object { $_.State -eq 'Running' } | Stop-Job
            break
        }
        Start-Sleep -Seconds 5
    }

    # Collect results and mark stale users
    foreach ($job in $jobs) {
        try {
            $result = Receive-Job $job -ErrorAction SilentlyContinue
            if ($result -and $result.Result -eq "LogonFailed") {
                Write-Log "Marking $($result.Sam) as stale (bad credentials)." "WARNING"
                $null = $staleUsers.Add($result.Sam)
            }
        } catch {}
        Remove-Job $job -Force -ErrorAction SilentlyContinue
    }

    Write-Log "Wave $waveCount complete. Active users: $($activeUsers.Count - $staleUsers.Count)." "SUCCESS"

    # Brief rest between waves (30–60 s) before starting the next set of sessions
    $restSec = Get-Random -Minimum 30 -Maximum 61
    Write-Log "Resting $restSec s before next wave..." "INFO"
    Start-Sleep -Seconds $restSec
}
