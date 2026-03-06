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
# 6. Load title level map BEFORE layout (needed for positioning)
# -----------------------------------------------------------------------
$titleLevelMap = @{}
$jtPath = Join-Path $PSScriptRoot "AD_Data\jobtitles.csv"
if (Test-Path $jtPath) {
    Import-Csv $jtPath | ForEach-Object { $titleLevelMap[$_.Title] = [int]$_.Level }
    Write-Host "[*] Loaded $($titleLevelMap.Count) job title levels from jobtitles.csv" -ForegroundColor Cyan
} else {
    Write-Warning "jobtitles.csv not found at $jtPath - all users will be positioned as level 6"
}

# -----------------------------------------------------------------------
# 7. Assign draw.io cell IDs and compute layout positions
# -----------------------------------------------------------------------
# Node dimensions and spacing
$nodeW = 180
$nodeH = 70
$hGap  = 15          # Horizontal gap between sibling nodes
$vGap  = 120         # Vertical gap between levels

# Position map
$posMap = @{}
$idMap  = @{}
$cellId = 2

# Build parent->children map for layout
$childrenMap = @{}
foreach ($edge in $edgesToRender) {
    if (-not $childrenMap.ContainsKey($edge.From)) {
        $childrenMap[$edge.From] = [System.Collections.Generic.List[string]]::new()
    }
    $childrenMap[$edge.From].Add($edge.To)
}

# --- Tree layout: vertical hierarchy like a real org chart ---
# Key idea: separate children into "managers" (have reports) and "leaf ICs" (no reports).
# Managers are laid out horizontally as subtrees (they need width for their own subtrees).
# Leaf ICs are stacked vertically in a single column to the right of their manager,
# keeping the chart TALL not wide.

$maxLeafCols = 4   # Max columns for leaf IC block under a manager
$widthCache  = @{}
$heightCache = @{}

# Separate a node's children into managers (have subtrees) and leaves (no subtrees)
function Get-ChildGroups {
    param([string]$dn)
    $managers = [System.Collections.Generic.List[string]]::new()
    $leaves   = [System.Collections.Generic.List[string]]::new()
    if ($childrenMap.ContainsKey($dn)) {
        foreach ($child in $childrenMap[$dn]) {
            if ($childrenMap.ContainsKey($child)) {
                $managers.Add($child)
            } else {
                $leaves.Add($child)
            }
        }
    }
    return @{ Managers = $managers; Leaves = $leaves }
}

# Width of a subtree
function Get-SubtreeWidth {
    param([string]$dn)
    if ($widthCache.ContainsKey($dn)) { return $widthCache[$dn] }

    if (-not $childrenMap.ContainsKey($dn)) {
        $widthCache[$dn] = $nodeW
        return $nodeW
    }

    $groups = Get-ChildGroups -dn $dn

    # Width needed for manager subtrees side by side
    $mgrWidth = 0
    foreach ($m in $groups.Managers) {
        if ($mgrWidth -gt 0) { $mgrWidth += $hGap }
        $mgrWidth += (Get-SubtreeWidth -dn $m)
    }

    # Width needed for leaf IC block (columns of nodeW)
    $leafCount = $groups.Leaves.Count
    $leafCols  = if ($leafCount -gt 0) { [math]::Min($leafCount, $maxLeafCols) } else { 0 }
    $leafBlockW = if ($leafCols -gt 0) { $leafCols * $nodeW + ($leafCols - 1) * $hGap } else { 0 }

    # Total children width: managers + gap + leaf block, side by side
    $childrenWidth = 0
    if ($mgrWidth -gt 0 -and $leafBlockW -gt 0) {
        $childrenWidth = $mgrWidth + $hGap + $leafBlockW
    } elseif ($mgrWidth -gt 0) {
        $childrenWidth = $mgrWidth
    } else {
        $childrenWidth = $leafBlockW
    }

    $w = [math]::Max($nodeW, $childrenWidth)
    $widthCache[$dn] = $w
    return $w
}

# Height of a subtree (needed for proper vertical stacking)
function Get-SubtreeHeight {
    param([string]$dn)
    if ($heightCache.ContainsKey($dn)) { return $heightCache[$dn] }

    if (-not $childrenMap.ContainsKey($dn)) {
        $heightCache[$dn] = $nodeH
        return $nodeH
    }

    $groups = Get-ChildGroups -dn $dn

    # Height of manager subtrees (take the tallest)
    $maxMgrH = 0
    foreach ($m in $groups.Managers) {
        $mh = Get-SubtreeHeight -dn $m
        $maxMgrH = [math]::Max($maxMgrH, $mh)
    }

    # Height of leaf block
    $leafCount = $groups.Leaves.Count
    $leafRows  = if ($leafCount -gt 0) { [math]::Ceiling($leafCount / $maxLeafCols) } else { 0 }
    $leafBlockH = if ($leafRows -gt 0) { $leafRows * $nodeH + ($leafRows - 1) * $hGap } else { 0 }

    $childH = [math]::Max($maxMgrH, $leafBlockH)
    $h = $nodeH + $vGap + $childH
    $heightCache[$dn] = $h
    return $h
}

# Position nodes recursively
function Set-SubtreePositions {
    param(
        [string]$dn,
        [double]$leftX,
        [double]$y
    )

    $user = $dnMap[$dn]
    if (-not $user) { return }

    $subtreeW = Get-SubtreeWidth -dn $dn

    # Center this node above its subtree
    $nodeX = $leftX + ($subtreeW / 2) - ($nodeW / 2)
    $posMap[$dn] = [PSCustomObject]@{ X = $nodeX; Y = $y }
    $idMap[$dn] = "node_$script:cellId"
    $script:cellId++

    if (-not $childrenMap.ContainsKey($dn)) { return }

    $groups  = Get-ChildGroups -dn $dn
    $childY  = $y + $nodeH + $vGap

    # Calculate total children width to center under parent
    $mgrWidth = 0
    foreach ($m in $groups.Managers) {
        if ($mgrWidth -gt 0) { $mgrWidth += $hGap }
        $mgrWidth += (Get-SubtreeWidth -dn $m)
    }
    $leafCount = $groups.Leaves.Count
    $leafCols  = if ($leafCount -gt 0) { [math]::Min($leafCount, $maxLeafCols) } else { 0 }
    $leafBlockW = if ($leafCols -gt 0) { $leafCols * $nodeW + ($leafCols - 1) * $hGap } else { 0 }

    $totalChildW = 0
    if ($mgrWidth -gt 0 -and $leafBlockW -gt 0) {
        $totalChildW = $mgrWidth + $hGap + $leafBlockW
    } elseif ($mgrWidth -gt 0) {
        $totalChildW = $mgrWidth
    } else {
        $totalChildW = $leafBlockW
    }

    # Center children block under parent
    $startX = $leftX + ($subtreeW - $totalChildW) / 2

    # Place manager subtrees first
    $currentX = $startX
    foreach ($m in $groups.Managers) {
        $mw = Get-SubtreeWidth -dn $m
        Set-SubtreePositions -dn $m -leftX $currentX -y $childY
        $currentX += $mw + $hGap
    }

    # Place leaf ICs in a block of columns/rows
    if ($leafCount -gt 0) {
        $leafStartX = $currentX
        $leafIndex = 0
        foreach ($leaf in $groups.Leaves) {
            $col = $leafIndex % $maxLeafCols
            $row = [math]::Floor($leafIndex / $maxLeafCols)
            $lx = $leafStartX + $col * ($nodeW + $hGap)
            $ly = $childY + $row * ($nodeH + $hGap)

            $posMap[$leaf] = [PSCustomObject]@{ X = $lx; Y = $ly }
            $idMap[$leaf] = "node_$script:cellId"
            $script:cellId++
            $leafIndex++
        }
    }
}

# Start layout from root
if ($rootUser) {
    Get-SubtreeWidth -dn $rootUser.DistinguishedName | Out-Null
    Get-SubtreeHeight -dn $rootUser.DistinguishedName | Out-Null
    Set-SubtreePositions -dn $rootUser.DistinguishedName -leftX 0 -y 0
} else {
    Write-Warning "No root found, using fallback grid layout"
    $x = 0; $y = 0; $maxX = 2000
    foreach ($dn in $nodesToRender) {
        $posMap[$dn] = [PSCustomObject]@{ X = $x; Y = $y }
        $idMap[$dn] = "node_$cellId"
        $cellId++
        $x += $nodeW + $hGap
        if ($x -gt $maxX) { $x = 0; $y += $nodeH + $vGap }
    }
}

# -----------------------------------------------------------------------
# 8. Color scheme by title level
# -----------------------------------------------------------------------
function Get-NodeColor {
    param([string]$Title)
    $lv = if ($titleLevelMap.ContainsKey($Title)) { $titleLevelMap[$Title] } else { 8 }
    switch ($lv) {
        1 { return @{ Fill = '#1a237e'; Font = '#ffffff'; Stroke = '#0d1657' } }
        2 { return @{ Fill = '#283593'; Font = '#ffffff'; Stroke = '#1a237e' } }
        3 { return @{ Fill = '#1565c0'; Font = '#ffffff'; Stroke = '#0d47a1' } }
        4 { return @{ Fill = '#1976d2'; Font = '#ffffff'; Stroke = '#1565c0' } }
        5 { return @{ Fill = '#1e88e5'; Font = '#ffffff'; Stroke = '#1976d2' } }
        6 { return @{ Fill = '#42a5f5'; Font = '#000000'; Stroke = '#1e88e5' } }
        7 { return @{ Fill = '#90caf9'; Font = '#000000'; Stroke = '#42a5f5' } }
        default { return @{ Fill = '#e3f2fd'; Font = '#000000'; Stroke = '#90caf9' } }
    }
}

# -----------------------------------------------------------------------
# 9. Build draw.io XML
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

    $style = "edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;jettySize=auto;exitX=0.5;exitY=1;exitDx=0;exitDy=0;entryX=0.5;entryY=0;entryDx=0;entryDy=0;strokeColor=#666666;"
    [void]$sb.AppendLine("    <mxCell id=""edge_$edgeId"" style=""$style"" edge=""1"" source=""$fromId"" target=""$toId"" parent=""1"">")
    [void]$sb.AppendLine('      <mxGeometry relative="1" as="geometry" />')
    [void]$sb.AppendLine('    </mxCell>')
    $edgeId++
}

[void]$sb.AppendLine('  </root>')
[void]$sb.AppendLine('</mxGraphModel>')

# -----------------------------------------------------------------------
# 10. Write output file
# -----------------------------------------------------------------------
$outPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFile)
[System.IO.File]::WriteAllText($outPath, $sb.ToString(), [System.Text.Encoding]::UTF8)

Write-Host "[+] Org chart written to: $outPath" -ForegroundColor Green
Write-Host "[+] Open it at https://app.diagrams.net or in draw.io Desktop (File > Open)" -ForegroundColor Green
Write-Host "    Nodes: $($nodesToRender.Count)  |  Edges: $($edgesToRender.Count)" -ForegroundColor Gray
