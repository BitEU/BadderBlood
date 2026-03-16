<#
.SYNOPSIS
    Phase 4: Sets known passwords on a subset of AD users and exports them to
    user_passwords.json for use by the User Session Simulator.

.DESCRIPTION
    Implements Approach D from the plan: sets a known password on each selected
    user and writes a JSON file that Invoke-UserSessionSimulator.ps1 reads to
    call LogonUser() under each user's real identity.

    Selection strategy:
        - Picks $UserCount enabled, non-privileged, non-service users
        - Excludes BlackTeam accounts, Domain Admins, Protected Users
        - Assigns a password from a small themed pool (mimics BadderBlood's
          WeakUserPasswords.ps1 pattern — intentionally crackable by Red Team)
        - Writes user_passwords.json to $SimulatorPath

    The exported passwords are intentionally weak/themed to:
        a) Not break the "realistic enterprise noise" feel
        b) Remain crackable so Red Team finds credential reuse in SMB traffic
        c) Not conflict with Blue Team hardening (they can change these passwords;
           the simulator will detect the failure and skip that user gracefully)

    NOTE: This script is designed to run ONCE per lab deployment (or after
    a full Invoke-BadderBlood.ps1 re-run). It does NOT need to be re-run
    when Blue Team hardens the environment — the simulator handles failures.

.PARAMETER UserCount
    Number of users to enrol in file session simulation. Default: 40.
    Larger values = more concurrent session variety; smaller = less noise.

.PARAMETER SimulatorPath
    Where to write user_passwords.json. Default: C:\Simulator\

.PARAMETER PasswordPool
    Array of passwords to assign. Defaults to a themed SBF pool.
    Each user gets one password chosen at random from this pool.

.NOTES
    Run AFTER Invoke-BadderBlood.ps1 on the DC or a machine with RSAT.
    Must be run as Domain Admin (requires Set-ADAccountPassword).

    Context: Educational / CTF / Active Directory Lab Environment
#>

#Requires -RunAsAdministrator

param(
    [int]$UserCount         = 40,
    [string]$SimulatorPath  = "C:\Simulator",
    [string[]]$PasswordPool = @(
        "SpringField1!", "BoxFactory1!", "Nails2025!",
        "Cardboard1!",  "Factory123!",  "SBF_User1!",
        "Welcome2025!", "Company123!",  "Summer2025!",
        "Monday2025!"
    )
)

$ErrorActionPreference = "SilentlyContinue"

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
        "STEP"    { Write-Host "" ; Write-Host "[$ts] >>> $Message" -ForegroundColor White }
        default   { Write-Host "[$ts] $Message" }
    }
}

Write-Log "=================================================================" "INFO"
Write-Log "  BadderBlood Continuous Activity Simulator" "INFO"
Write-Log "  Phase 4: User Password Export" "INFO"
Write-Log "  Educational / CTF / Lab Use Only" "WARNING"
Write-Log "=================================================================" "INFO"

# ==============================================================================
# 1. RESOLVE DOMAIN
# ==============================================================================

Write-Log "Resolving Active Directory domain..." "STEP"

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $Domain    = Get-ADDomain
    $DomainNB  = $Domain.NetBIOSName
    $DomainDNS = $Domain.DNSRoot
    $DomainDN  = $Domain.DistinguishedName
    Write-Log "Domain: $DomainDNS | NetBIOS: $DomainNB" "SUCCESS"
} catch {
    Write-Log "Cannot reach Active Directory: $_" "ERROR"
    exit 1
}

# ==============================================================================
# 2. BUILD EXCLUSION SET (privileged groups + BlackTeam + service accounts)
# ==============================================================================

Write-Log "Building exclusion list from privileged groups..." "STEP"

$excludeDNs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$privGroupNames = @("Domain Admins","Enterprise Admins","Schema Admins",
                    "Administrators","Protected Users","Read-only Domain Controllers")

foreach ($grpName in $privGroupNames) {
    try {
        $members = Get-ADGroupMember -Identity $grpName -Recursive -ErrorAction Stop
        foreach ($m in $members) { $null = $excludeDNs.Add($m.DistinguishedName) }
        Write-Log "  Excluded $($members.Count) members from '$grpName'" "INFO"
    } catch {
        Write-Log "  Could not enumerate '$grpName': $_" "WARNING"
    }
}

# ==============================================================================
# 3. SELECT TARGET USERS
# ==============================================================================

Write-Log "Selecting $UserCount target users for session simulation..." "STEP"

$allCandidates = Get-ADUser -Filter { Enabled -eq $true } `
    -Properties DisplayName, Department, Title, HomeDirectory, EmailAddress `
    -ErrorAction SilentlyContinue |
    Where-Object {
        $_.SamAccountName -notmatch "Administrator|Guest|krbtgt|BlackTeam_" -and
        $_.SamAccountName -notmatch "^svc_|^svc-|SA$|_svc$" -and
        -not $excludeDNs.Contains($_.DistinguishedName)
    }

if ($allCandidates.Count -eq 0) {
    Write-Log "No eligible users found. Ensure Invoke-BadderBlood.ps1 has run." "ERROR"
    exit 1
}

$actualCount = [Math]::Min($UserCount, $allCandidates.Count)
$targets     = $allCandidates | Get-Random -Count $actualCount
Write-Log "Selected $actualCount users from $($allCandidates.Count) candidates." "SUCCESS"

# ==============================================================================
# 4. SET PASSWORDS AND BUILD EXPORT ARRAY
# ==============================================================================

Write-Log "Setting passwords and building export..." "STEP"

$exportUsers  = [System.Collections.Generic.List[hashtable]]::new()
$setOk        = 0
$setFail      = 0

foreach ($user in $targets) {
    $password = $PasswordPool | Get-Random
    $secPass  = ConvertTo-SecureString $password -AsPlainText -Force

    try {
        Set-ADAccountPassword -Identity $user.SamAccountName `
            -NewPassword $secPass -Reset -ErrorAction Stop
        # Ensure account is not locked and does not require password change
        Set-ADUser -Identity $user.SamAccountName `
            -ChangePasswordAtLogon $false -ErrorAction SilentlyContinue

        $exportUsers.Add(@{
            sam         = $user.SamAccountName
            displayName = if ($user.DisplayName)   { $user.DisplayName }  else { $user.SamAccountName }
            department  = if ($user.Department)    { $user.Department }   else { "Unknown" }
            title       = if ($user.Title)         { $user.Title }        else { "" }
            email       = if ($user.EmailAddress)  { $user.EmailAddress } else { "" }
            homeDir     = if ($user.HomeDirectory) { $user.HomeDirectory } else { "" }
            password    = $password
            domain      = $DomainNB
        })
        $setOk++
    } catch {
        Write-Log "  Could not set password for $($user.SamAccountName): $_" "WARNING"
        $setFail++
    }
}

Write-Log "Passwords set: $setOk succeeded, $setFail failed." "SUCCESS"

# ==============================================================================
# 5. WRITE user_passwords.json
# ==============================================================================

Write-Log "Writing user_passwords.json to $SimulatorPath..." "STEP"

if (-not (Test-Path $SimulatorPath)) {
    New-Item -ItemType Directory -Path $SimulatorPath -Force | Out-Null
}

# Build JSON manually (avoids ConvertTo-Json depth issues with large arrays)
$jsonLines = [System.Collections.Generic.List[string]]::new()
$jsonLines.Add("{")
$jsonLines.Add("  `"_comment`": `"Phase 4 user credential store. Regenerate after Invoke-BadderBlood re-runs.`",")
$jsonLines.Add("  `"_generated`": `"$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')`",")
$jsonLines.Add("  `"domain`": `"$DomainNB`",")
$jsonLines.Add("  `"domainDns`": `"$DomainDNS`",")
$jsonLines.Add("  `"corpShareHost`": `"$($Domain.PDCEmulator)`",")
$jsonLines.Add("  `"users`": [")

for ($i = 0; $i -lt $exportUsers.Count; $i++) {
    $u        = $exportUsers[$i]
    $comma    = if ($i -lt $exportUsers.Count - 1) { "," } else { "" }
    $safeName = $u.displayName -replace '"', "'"
    $safeDept = $u.department  -replace '"', "'"
    $safeTitle= $u.title       -replace '"', "'"
    $safeHome = $u.homeDir     -replace '"', "'"
    $safeEmail= $u.email       -replace '"', "'"
    $jsonLines.Add("    {`"sam`":`"$($u.sam)`",`"displayName`":`"$safeName`",`"department`":`"$safeDept`",`"title`":`"$safeTitle`",`"email`":`"$safeEmail`",`"homeDir`":`"$safeHome`",`"password`":`"$($u.password)`",`"domain`":`"$($u.domain)`"}$comma")
}

$jsonLines.Add("  ]")
$jsonLines.Add("}")

$outPath = Join-Path $SimulatorPath "user_passwords.json"
$jsonLines | Out-File -FilePath $outPath -Encoding UTF8 -Force
Write-Log "user_passwords.json written: $outPath ($($exportUsers.Count) users)" "SUCCESS"

# ==============================================================================
# 6. SUMMARY
# ==============================================================================

Write-Log "" "INFO"
Write-Log "=================================================================" "INFO"
Write-Log "  Phase 4 Prep Complete" "SUCCESS"
Write-Log "=================================================================" "INFO"
Write-Log "  Users enrolled: $setOk" "INFO"
Write-Log "  Output file:    $outPath" "INFO"
Write-Log "" "INFO"
Write-Log "NEXT STEPS:" "INFO"
Write-Log "  1. Copy $outPath to C:\Simulator\ on the simulator VM" "INFO"
Write-Log "  2. Start Invoke-UserSessionSimulator.ps1 on the simulator VM" "INFO"
Write-Log "" "INFO"
Write-Log "NOTE: These passwords are intentionally weak/themed." "WARNING"
Write-Log "      Red Team can crack them from SMB captures (by design)." "WARNING"
Write-Log "      Blue Team cannot change them without breaking Phase 4 traffic." "WARNING"
Write-Log "      If they do rotate passwords, the simulator skips that user" "WARNING"
Write-Log "      and continues with remaining enrolled users." "WARNING"
