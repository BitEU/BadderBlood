################################
# Generate-OrgChart.ps1 - BadderBlood draw.io Org Chart Generator
# Queries live AD for manager/report relationships and outputs a
# draw.io-compatible XML file you can open directly in draw.io desktop or app.drawio.com.
#
# Usage:
#   .\Generate-OrgChart.ps1
#   .\Generate-OrgChart.ps1 -OutputFile "C:\Temp\orgchart.drawio" -Department SEC
#   .\Generate-OrgChart.ps1 -MaxDepth 4 -RootTitle "Chief Executive Officer"
#   .\Generate-OrgChart.ps1 -CompanyName "Acme Corp" -OutputFile ".\acme_org.drawio"
################################

[CmdletBinding()]
param(
    # Output file path. Defaults to .\OrgChart_<timestamp>.drawio
    [string]$OutputFile = ".\OrgChart_$(Get-Date -Format 'yyyyMMdd_HHmmss').drawio",

    # Optional: filter chart to a single department (uses departmentNumber attribute).
    # Example: -Department SEC   or   -Department FIN
    [string]$Department = "",

    # The title of the root node. Defaults to CEO. Change if you want a sub-tree.
    [string]$RootTitle = "Chief Executive Officer",

    # How many levels deep to render. 0 = unlimited.
    [int]$MaxDepth = 0,

    # Company name shown in the chart title box.
    [string]$CompanyName = "BadderBlood Corp",

    # If set, skips users with no manager and no direct reports (orphan ICs).
    # Useful for large AD environments to keep the chart readable.
    [switch]$SkipOrphans
)

# -----------------------------------------------------------------------
# 1. Connect to AD and pull ALL enabled users
# -----------------------------------------------------------------------
try {
    $domain = Get-ADDomain -ErrorAction Stop
    $setDC  = $domain.PDCEmulator
} catch {
    Write-Error "Cannot connect to AD. Run this on a domain-joined machine with RSAT installed."
    exit 1
}

Write-Host "[*] Querying AD users from $setDC ..." -ForegroundColor Cyan

$adProps = @('SamAccountName','DisplayName','Title','Department','departmentNumber',
             'Manager','DistinguishedName','GivenName','Surname','Enabled','OfficePhone','Office')

# Always pull ALL enabled users so manager DN lookups never dangle
$allUsers = Get-ADUser -Filter { Enabled -eq $true } -Properties $adProps -Server $setDC
Write-Host "[*] Found $($allUsers.Count) total enabled users." -ForegroundColor Cyan

# -----------------------------------------------------------------------
# 2. Build DN lookup from ALL users
# -----------------------------------------------------------------------
$dnMap = @{}
foreach ($u in $allUsers) { $dnMap[$u.DistinguishedName] = $u }

# Determine the display set (filtered by dept if requested)
if ($Department) {
    $displayUsers = $allUsers | Where-Object { $_.departmentNumber -eq $Department }
    Write-Host "[*] Filtered to $($displayUsers.Count) users in department '$Department'." -ForegroundColor Cyan
} else {
    $displayUsers = $allUsers
}

# -----------------------------------------------------------------------
# 3. Build parent -> children map (from ALL users so chains are complete)
# -----------------------------------------------------------------------
$childMap = @{}   # managerDN -> [childDN, ...]

foreach ($u in $allUsers) {
    if ([string]::IsNullOrEmpty($u.Manager)) { continue }
    if (-not $dnMap.ContainsKey($u.Manager)) { continue }
    if (-not $childMap.ContainsKey($u.Manager)) { $childMap[$u.Manager] = [System.Collections.Generic.List[string]]::new() }
    $childMap[$u.Manager].Add($u.DistinguishedName)
}

Write-Host "[*] Built child map: $($childMap.Count) managers have direct reports." -ForegroundColor Cyan

# -----------------------------------------------------------------------
# 4. Find the root user
# -----------------------------------------------------------------------
# Search by RootTitle across all users (not just filtered set)
$rootUser = $allUsers | Where-Object { $_.Title -eq $RootTitle } | Select-Object -First 1

if (-not $rootUser) {
    Write-Warning "No user found with title '$RootTitle'."
    # Fall back: find the user with no manager who has the most reports
    $rootUser = $allUsers |
        Where-Object { [string]::IsNullOrEmpty($_.Manager) -and $childMap.ContainsKey($_.DistinguishedName) } |
        Sort-Object { $childMap[$_.DistinguishedName].Count } -Descending |
        Select-Object -First 1
    if ($rootUser) {
        Write-Host "[*] Using '$($rootUser.DisplayName)' ($($rootUser.Title)) as root (most reports, no manager)." -ForegroundColor Yellow
    }
}

if (-not $rootUser) {
    Write-Warning "No suitable root user found. Manager relationships may not be properly set."
    Write-Host "[!] Try running Fix-ManagerRelationships.ps1 first to fix manager assignments." -ForegroundColor Yellow
}

# -----------------------------------------------------------------------
# 5. Iterative BFS to collect nodes to render
# -----------------------------------------------------------------------
$nodesToRender  = [System.Collections.Generic.HashSet[string]]::new()
$edgesToRender  = [System.Collections.Generic.List[object]]::new()
$levelMap       = @{}   # DN -> depth

# Build display set as a HashSet for fast membership checks
$displayDNs = [System.Collections.Generic.HashSet[string]]::new()
foreach ($u in $displayUsers) { $displayDNs.Add($u.DistinguishedName) | Out-Null }

if ($rootUser) {
    $bfsQueue = [System.Collections.Generic.Queue[object]]::new()
    $bfsQueue.Enqueue([PSCustomObject]@{ DN = $rootUser.DistinguishedName; Depth = 0 })
    $levelMap[$rootUser.DistinguishedName] = 0
    $nodesToRender.Add($rootUser.DistinguishedName) | Out-Null

    while ($bfsQueue.Count -gt 0) {
        $item = $bfsQueue.Dequeue()
        if ($MaxDepth -gt 0 -and $item.Depth -ge $MaxDepth) { continue }

        if ($childMap.ContainsKey($item.DN)) {
            foreach ($childDN in $childMap[$item.DN]) {
                # If dept filter is active, only descend into nodes in that dept
                # BUT always include the edge target if the child is in the display set
                $childInDisplay = (-not $Department) -or $displayDNs.Contains($childDN)
                if (-not $childInDisplay) { continue }

                if (-not $nodesToRender.Contains($childDN)) {
                    $nodesToRender.Add($childDN) | Out-Null
                    $levelMap[$childDN] = $item.Depth + 1
                    $bfsQueue.Enqueue([PSCustomObject]@{ DN = $childDN; Depth = $item.Depth + 1 })
                }
                $edgesToRender.Add([PSCustomObject]@{ From = $item.DN; To = $childDN })
            }
        }
    }

    # If dept filter is active, also ensure the root is visible even if outside the dept
    if ($Department -and -not $displayDNs.Contains($rootUser.DistinguishedName)) {
        $nodesToRender.Add($rootUser.DistinguishedName) | Out-Null
        $levelMap[$rootUser.DistinguishedName] = 0
    }
} else {
    # Absolute fallback: render all display users with their edges
    Write-Warning "No root found. Rendering all $($displayUsers.Count) users as a flat list."
    foreach ($u in $displayUsers) {
        $nodesToRender.Add($u.DistinguishedName) | Out-Null
        $levelMap[$u.DistinguishedName] = 0
    }
    foreach ($u in $displayUsers) {
        if (-not [string]::IsNullOrEmpty($u.Manager) -and $displayDNs.Contains($u.Manager)) {
            $edgesToRender.Add([PSCustomObject]@{ From = $u.Manager; To = $u.DistinguishedName })
        }
    }
}

# Optionally drop orphan ICs (no manager, no reports) to reduce noise
if ($SkipOrphans) {
    $toRemove = $nodesToRender | Where-Object {
        $dn = $_
        $noParentEdge = -not ($edgesToRender | Where-Object { $_.To -eq $dn })
        $noChildEdge  = -not ($edgesToRender | Where-Object { $_.From -eq $dn })
        $noParentEdge -and $noChildEdge
    }
    foreach ($dn in @($toRemove)) { $nodesToRender.Remove($dn) | Out-Null }
}

Write-Host "[*] Chart will contain $($nodesToRender.Count) nodes and $($edgesToRender.Count) edges." -ForegroundColor Cyan

# -----------------------------------------------------------------------
# 6. Assign draw.io cell IDs and compute layout positions
# -----------------------------------------------------------------------
# Group by level
$byLevel = @{}
foreach ($dn in $nodesToRender) {
    $lv = if ($levelMap.ContainsKey($dn)) { $levelMap[$dn] } else { 999 }
    if (-not $byLevel.ContainsKey($lv)) { $byLevel[$lv] = [System.Collections.Generic.List[string]]::new() }
    $byLevel[$lv].Add($dn)
}

# Node dimensions and spacing
$nodeW = 180
$nodeH = 70
$hGap  = 20
$vGap  = 50

# Position map
$posMap = @{}
$idMap  = @{}
$cellId = 2

foreach ($level in ($byLevel.Keys | Sort-Object)) {
    $nodesAtLevel = $byLevel[$level]
    $count = $nodesAtLevel.Count
    $totalWidth = $count * $nodeW + ($count - 1) * $hGap
    $startX = -[math]::Floor($totalWidth / 2)
    $y = $level * ($nodeH + $vGap)

    for ($i = 0; $i -lt $count; $i++) {
        $dn = $nodesAtLevel[$i]
        $x = $startX + $i * ($nodeW + $hGap)
        $posMap[$dn] = [PSCustomObject]@{ X = $x; Y = $y }
        $idMap[$dn]  = "node_$cellId"
        $cellId++
    }
}

# -----------------------------------------------------------------------
# 7. Color scheme by title level
# -----------------------------------------------------------------------
$titleLevelMap = @{}
$jtPath = Join-Path $PSScriptRoot "AD_Data\jobtitles.csv"
if (Test-Path $jtPath) {
    Import-Csv $jtPath | ForEach-Object { $titleLevelMap[$_.Title] = [int]$_.Level }
}

function Get-NodeColor {
    param([string]$Title)
    $lv = if ($titleLevelMap.ContainsKey($Title)) { $titleLevelMap[$Title] } else { 6 }
    switch ($lv) {
        1 { return @{ Fill = '#1a237e'; Font = '#ffffff'; Stroke = '#0d1657' } }
        2 { return @{ Fill = '#283593'; Font = '#ffffff'; Stroke = '#1a237e' } }
        3 { return @{ Fill = '#1565c0'; Font = '#ffffff'; Stroke = '#0d47a1' } }
        4 { return @{ Fill = '#1976d2'; Font = '#ffffff'; Stroke = '#1565c0' } }
        5 { return @{ Fill = '#42a5f5'; Font = '#000000'; Stroke = '#1976d2' } }
        default { return @{ Fill = '#e3f2fd'; Font = '#000000'; Stroke = '#90caf9' } }
    }
}

# -----------------------------------------------------------------------
# 8. Build draw.io XML
# -----------------------------------------------------------------------
$sb = [System.Text.StringBuilder]::new()

[void]$sb.AppendLine('<?xml version="1.0" encoding="UTF-8"?>')
[void]$sb.AppendLine('<mxGraphModel dx="1422" dy="762" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="1169" pageHeight="827" math="0" shadow="0">')
[void]$sb.AppendLine('  <root>')
[void]$sb.AppendLine('    <mxCell id="0" />')
[void]$sb.AppendLine('    <mxCell id="1" parent="0" />')

# Chart title box
$titleLabel = [System.Security.SecurityElement]::Escape("$CompanyName - Organization Chart")
$chartDate  = [System.Security.SecurityElement]::Escape("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
[void]$sb.AppendLine("    <mxCell id=""title_box"" value=""&lt;b&gt;$titleLabel&lt;/b&gt;&lt;br/&gt;$chartDate"" style=""text;html=1;strokeColor=none;fillColor=#f5f5f5;align=center;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontSize=14;fontColor=#333333;"" vertex=""1"" parent=""1"">")
[void]$sb.AppendLine('      <mxGeometry x="-200" y="-80" width="400" height="60" as="geometry" />')
[void]$sb.AppendLine('    </mxCell>')

# Nodes
foreach ($dn in $nodesToRender) {
    $u = $dnMap[$dn]
    if (-not $u) { continue }

    $id  = $idMap[$dn]
    $pos = $posMap[$dn]
    if (-not $pos) { continue }

    $displayName = if ($u.DisplayName) { $u.DisplayName } else { $u.SamAccountName }
    $titleText   = if ($u.Title)       { $u.Title }       else { "" }
    $deptText    = if ($u.Department)  { $u.Department }  else { "" }
    $phoneText   = if ($u.OfficePhone) { $u.OfficePhone } else { "" }

    $displayName = [System.Security.SecurityElement]::Escape($displayName)
    $titleText   = [System.Security.SecurityElement]::Escape($titleText)
    $deptText    = [System.Security.SecurityElement]::Escape($deptText)
    $phoneText   = [System.Security.SecurityElement]::Escape($phoneText)

    $colors = Get-NodeColor -Title $u.Title
    $fill   = $colors.Fill
    $font   = $colors.Font
    $stroke = $colors.Stroke

    $label = "&lt;b&gt;$displayName&lt;/b&gt;&lt;br/&gt;$titleText&lt;br/&gt;&lt;font color=&quot;#666666&quot;&gt;$deptText&lt;/font&gt;"
    if ($phoneText) { $label += "&lt;br/&gt;&lt;font color=&quot;#888888&quot;&gt;$phoneText&lt;/font&gt;" }

    $style = "rounded=1;whiteSpace=wrap;html=1;fillColor=$fill;strokeColor=$stroke;fontColor=$font;fontSize=10;verticalAlign=top;"

    [void]$sb.AppendLine("    <mxCell id=""$id"" value=""$label"" style=""$style"" vertex=""1"" parent=""1"">")
    [void]$sb.AppendLine("      <mxGeometry x=""$($pos.X)"" y=""$($pos.Y)"" width=""$nodeW"" height=""$nodeH"" as=""geometry"" />")
    [void]$sb.AppendLine('    </mxCell>')
}

# Edges
$edgeId = $cellId
foreach ($edge in $edgesToRender) {
    $fromId = $idMap[$edge.From]
    $toId   = $idMap[$edge.To]
    if (-not $fromId -or -not $toId) { continue }

    $style = "edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;exitX=0.5;exitY=1;exitDx=0;exitDy=0;entryX=0.5;entryY=0;entryDx=0;entryDy=0;"
    [void]$sb.AppendLine("    <mxCell id=""edge_$edgeId"" style=""$style"" edge=""1"" source=""$fromId"" target=""$toId"" parent=""1"">")
    [void]$sb.AppendLine('      <mxGeometry relative="1" as="geometry" />')
    [void]$sb.AppendLine('    </mxCell>')
    $edgeId++
}

[void]$sb.AppendLine('  </root>')
[void]$sb.AppendLine('</mxGraphModel>')

# -----------------------------------------------------------------------
# 9. Write output file
# -----------------------------------------------------------------------
$outPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFile)
[System.IO.File]::WriteAllText($outPath, $sb.ToString(), [System.Text.Encoding]::UTF8)

Write-Host "[+] Org chart written to: $outPath" -ForegroundColor Green
Write-Host "[+] Open it at https://app.diagrams.net or in draw.io Desktop (File > Open)" -ForegroundColor Green
Write-Host "    Nodes: $($nodesToRender.Count)  |  Edges: $($edgesToRender.Count)" -ForegroundColor Gray
