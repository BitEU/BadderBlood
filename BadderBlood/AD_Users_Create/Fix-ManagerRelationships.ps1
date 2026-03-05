################################
# Fix-ManagerRelationships.ps1 - BadderBlood Manager Relationship Fixer
# Runs after user creation to ensure all manager relationships are properly set
# based on the org_hierarchy.csv, particularly for high-level executives.
################################

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OrgHierarchyPath,
    
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

# Load org hierarchy
if (-not $OrgHierarchyPath) {
    $scriptPath = Split-Path -Parent $PSCommandPath
    $scriptParent = (Get-Item $scriptPath).Parent.FullName
    $OrgHierarchyPath = Join-Path $scriptParent "AD_Data\org_hierarchy.csv"
}

if (-not (Test-Path $OrgHierarchyPath)) {
    Write-Error "Org hierarchy file not found: $OrgHierarchyPath"
    exit 1
}

$orgHierarchy = Import-Csv $OrgHierarchyPath
Write-Host "[*] Loaded org hierarchy with $($orgHierarchy.Count) titles" -ForegroundColor Cyan

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
    
    # Find potential managers (users with the ReportsTo title)
    if (-not $usersByTitle.ContainsKey($reportsTo)) {
        Write-Warning "No manager found for title '$title' (should report to '$reportsTo')"
        continue
    }
    
    $usersToFix = $usersByTitle[$title]
    $potentialManagers = $usersByTitle[$reportsTo]
    
    foreach ($user in $usersToFix) {
        # If user already has a manager set, skip
        if (-not [string]::IsNullOrEmpty($user.Manager)) {
            $skipped++
            continue
        }
        
        # Assign a random manager from the pool with the correct title
        $manager = $potentialManagers | Get-Random
        
        if ($WhatIf) {
            Write-Host "  [WHATIF] Would set manager for $($user.DisplayName) ($title) -> $($manager.DisplayName) ($reportsTo)" -ForegroundColor Yellow
            $fixed++
        } else {
            try {
                Set-ADUser -Identity $user.DistinguishedName -Manager $manager.DistinguishedName -Server $setDC -ErrorAction Stop
                Write-Host "  [+] Set manager: $($user.DisplayName) ($title) -> $($manager.DisplayName) ($reportsTo)" -ForegroundColor Green
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
