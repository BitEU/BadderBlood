################################
# Fix-ManagerRelationships.ps1 - BadderBlood Manager Relationship Fixer
# Runs after user creation to ensure all manager relationships are properly set
# based on jobtitles.csv (ReportsTo column), particularly for high-level executives.
################################

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$JobTitlesPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

try {
    $domain = Get-ADDomain -ErrorAction Stop
    $setDC  = $domain.PDCEmulator
} catch {
    Write-Error "Cannot connect to AD. Run this on a domain-joined machine with RSAT installed."
    exit 1
}

# Load job titles (contains ReportsTo hierarchy column)
if (-not $JobTitlesPath) {
    $scriptPath = Split-Path -Parent $PSCommandPath
    $scriptParent = (Get-Item $scriptPath).Parent.FullName
    $JobTitlesPath = Join-Path $scriptParent "AD_Data\jobtitles.csv"
}

if (-not (Test-Path $JobTitlesPath)) {
    Write-Error "Job titles file not found: $JobTitlesPath"
    exit 1
}

$orgHierarchy = Import-Csv $JobTitlesPath
Write-Host "[*] Loaded job titles (with hierarchy) - $($orgHierarchy.Count) titles" -ForegroundColor Cyan

# Build hierarchy map: title -> ReportsTo (for ancestor walking)
$hierarchyMap = @{}
foreach ($entry in $orgHierarchy) {
    if (-not [string]::IsNullOrEmpty($entry.ReportsTo)) {
        $hierarchyMap[$entry.Title] = $entry.ReportsTo
    }
}

# Get all enabled users
Write-Host "[*] Querying all enabled users from $setDC ..." -ForegroundColor Cyan
$allUsers = Get-ADUser -Filter { Enabled -eq $true } -Properties Title,Manager,DistinguishedName,DisplayName -Server $setDC
Write-Host "[*] Found $($allUsers.Count) enabled users" -ForegroundColor Cyan

# Build title -> user lookup
$usersByTitle = @{}
foreach ($u in $allUsers) {
    if ([string]::IsNullOrEmpty($u.Title)) { continue }
    if (-not $usersByTitle.ContainsKey($u.Title)) {
        $usersByTitle[$u.Title] = [System.Collections.Generic.List[object]]::new()
    }
    $usersByTitle[$u.Title].Add($u)
}

# Process each title in the hierarchy
$fixed = 0
$skipped = 0
$errors = 0

Write-Host "[*] Processing manager relationships..." -ForegroundColor Cyan

foreach ($entry in $orgHierarchy) {
    $title = $entry.Title
    $reportsTo = $entry.ReportsTo
    
    # Skip if no manager defined (e.g., CEO)
    if ([string]::IsNullOrEmpty($reportsTo)) { continue }
    
    # Find all users with this title
    if (-not $usersByTitle.ContainsKey($title)) {
        # No users with this title exist
        continue
    }
    
    # Find potential managers - walk up the hierarchy if direct manager title has no users
    $resolvedManagerTitle = $reportsTo
    $potentialManagers = $null
    $ancestorDepth = 0
    $maxAncestors = 5

    while ($ancestorDepth -lt $maxAncestors) {
        if ($usersByTitle.ContainsKey($resolvedManagerTitle)) {
            $potentialManagers = $usersByTitle[$resolvedManagerTitle]
            break
        }
        # Walk up: check if this title itself has a parent
        if ($hierarchyMap.ContainsKey($resolvedManagerTitle)) {
            $nextUp = $hierarchyMap[$resolvedManagerTitle]
            if ([string]::IsNullOrEmpty($nextUp)) { break }
            Write-Warning "No users with title '$resolvedManagerTitle' for '$title' - trying '$nextUp'"
            $resolvedManagerTitle = $nextUp
            $ancestorDepth++
        } else {
            break
        }
    }

    if (-not $potentialManagers -or $potentialManagers.Count -eq 0) {
        Write-Warning "No manager found for title '$title' (exhausted hierarchy from '$reportsTo')"
        continue
    }

    $usersToFix = $usersByTitle[$title]
    
    foreach ($user in $usersToFix) {
        # If user already has a manager set, skip
        if (-not [string]::IsNullOrEmpty($user.Manager)) {
            $skipped++
            continue
        }
        
        # Assign a random manager from the pool with the correct title
        $manager = $potentialManagers | Get-Random
        
        $fallbackNote = if ($resolvedManagerTitle -ne $reportsTo) { " [fallback from '$reportsTo']" } else { "" }

        if ($WhatIf) {
            Write-Host "  [WHATIF] Would set manager for $($user.DisplayName) ($title) -> $($manager.DisplayName) ($resolvedManagerTitle)$fallbackNote" -ForegroundColor Yellow
            $fixed++
        } else {
            try {
                Set-ADUser -Identity $user.DistinguishedName -Manager $manager.DistinguishedName -Server $setDC -ErrorAction Stop
                Write-Host "  [+] Set manager: $($user.DisplayName) ($title) -> $($manager.DisplayName) ($resolvedManagerTitle)$fallbackNote" -ForegroundColor Green
                $fixed++
            } catch {
                Write-Warning "Failed to set manager for $($user.DisplayName): $_"
                $errors++
            }
        }
    }
}

Write-Host ""
Write-Host "[*] Manager relationship fix complete:" -ForegroundColor Cyan
Write-Host "    Fixed:   $fixed" -ForegroundColor Green
Write-Host "    Skipped: $skipped (already had manager)" -ForegroundColor Gray
Write-Host "    Errors:  $errors" -ForegroundColor $(if ($errors -gt 0) { 'Red' } else { 'Gray' })
