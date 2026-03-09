################################
# AK_LAPSBypass.ps1 - Section 14: LAPS Bypass Detection
# Dot-sourced by BadderBloodAnswerKey.ps1
################################
function Invoke-AKLAPSBypassAudit {
    <#
        .SYNOPSIS
            Checks for LAPS password read bypass paths via ACLs.
        .PARAMETER AllComputers
            All computer objects (pre-fetched).
        .PARAMETER BadderBloodUsers
            Users created by BadderBlood.
        .PARAMETER BadderBloodGroups
            Groups created by BadderBlood.
        .OUTPUTS
            List of findings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$AllComputers,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$BadderBloodUsers,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$BadderBloodGroups
    )

    Write-Status "SECTION 14: Checking for LAPS password read bypass paths..."

    $Findings = [System.Collections.Generic.List[PSObject]]::new()

    # Detect which LAPS attribute exists
    $schemaNC = (Get-ADRootDSE).SchemaNamingContext
    $lapsAttrGuid = $null
    $lapsAttrName = $null
    try {
        $wlaps = Get-ADObject -SearchBase $schemaNC -LDAPFilter "(&(lDAPDisplayName=msLAPS-Password)(schemaidguid=*))" -Properties schemaIDGUID -ErrorAction Stop
        if ($wlaps) { $lapsAttrGuid = [System.GUID]$wlaps.schemaIDGUID; $lapsAttrName = "msLAPS-Password" }
    } catch {}
    if (-not $lapsAttrGuid) {
        try {
            $llaps = Get-ADObject -SearchBase $schemaNC -LDAPFilter "(&(lDAPDisplayName=ms-Mcs-AdmPwd)(schemaidguid=*))" -Properties schemaIDGUID -ErrorAction Stop
            if ($llaps) { $lapsAttrGuid = [System.GUID]$llaps.schemaIDGUID; $lapsAttrName = "ms-Mcs-AdmPwd" }
        } catch {}
    }

    if ($lapsAttrGuid) {
        Write-Status "  Using LAPS attribute: $lapsAttrName"

        # Check OUs containing computers for non-admin ReadProperty on LAPS attribute
        $computerOUs = @{}
        foreach ($comp in $AllComputers) {
            $parentOU = ($comp.DistinguishedName -split ',', 2)[1]
            $computerOUs[$parentOU] = $true
        }

        Set-Location AD:
        foreach ($ouDN in $computerOUs.Keys) {
            try {
                $ouAcl = Get-Acl "AD:\$ouDN" -ErrorAction SilentlyContinue
                if (-not $ouAcl) { continue }

                foreach ($ace in $ouAcl.Access) {
                    $isLAPSRead = ($ace.ObjectType -eq $lapsAttrGuid -and $ace.ActiveDirectoryRights -match "ReadProperty")
                    $isGenericAll = ($ace.ActiveDirectoryRights -match "GenericAll")

                    if (($isLAPSRead -or $isGenericAll) -and
                        $ace.AccessControlType -eq "Allow" -and
                        $ace.IdentityReference -notmatch "(SYSTEM|Domain Admins|Enterprise Admins|Administrators|CREATOR OWNER)$") {

                        $samName = $ace.IdentityReference.ToString() -replace "^.*\\"
                        $isBB = ($BadderBloodUsers | Where-Object { $_.SamAccountName -eq $samName }) -or
                                ($BadderBloodGroups | Where-Object { $_.SamAccountName -eq $samName })
                        if (-not $isBB) { continue }

                        $ouName = ($ouDN -split ',')[0] -replace 'OU=',''
                        $rightDesc = if ($isGenericAll) { "GenericAll (implies LAPS read)" } else { "ReadProperty on $lapsAttrName" }

                        $ri = $NewAttackVectorExplanations["LAPSBypass"]
                        $Findings.Add((Write-Finding -Category "LAPS Bypass" `
                            -Severity "CRITICAL" `
                            -Finding "'$samName' can read LAPS passwords in OU '$ouName' via $rightDesc" `
                            -CurrentState "$($ace.IdentityReference) has $rightDesc on $ouDN" `
                            -ExpectedState "Remove this ACE. Only designated LAPS admin groups should read $lapsAttrName" `
                            -WhyBad $ri.Why -AttackScenario $ri.Attack -Principle $ri.Principle `
                            -ObjectDN $ouDN))
                    }
                }
            } catch {}
        }

        # Also check individual computer objects
        $sampleComputers = $AllComputers | Get-Random -Count ([Math]::Min(50, $AllComputers.Count))
        foreach ($comp in $sampleComputers) {
            try {
                $compAcl = Get-Acl "AD:\$($comp.DistinguishedName)" -ErrorAction SilentlyContinue
                if (-not $compAcl) { continue }

                foreach ($ace in $compAcl.Access) {
                    if ($ace.ObjectType -eq $lapsAttrGuid -and
                        $ace.ActiveDirectoryRights -match "ReadProperty" -and
                        $ace.AccessControlType -eq "Allow" -and
                        -not $ace.IsInherited -and
                        $ace.IdentityReference -notmatch "(SYSTEM|Domain Admins|Enterprise Admins|Administrators)$") {

                        $samName = $ace.IdentityReference.ToString() -replace "^.*\\"
                        $isBB = ($BadderBloodUsers | Where-Object { $_.SamAccountName -eq $samName }) -or
                                ($BadderBloodGroups | Where-Object { $_.SamAccountName -eq $samName })
                        if (-not $isBB) { continue }

                        $ri = $NewAttackVectorExplanations["LAPSBypass"]
                        $Findings.Add((Write-Finding -Category "LAPS Bypass" `
                            -Severity "HIGH" `
                            -Finding "'$samName' can read LAPS password on computer '$($comp.Name)' (direct ACE)" `
                            -CurrentState "Non-inherited ReadProperty on $lapsAttrName" `
                            -ExpectedState "Remove direct ACE. Use OU-level delegation to designated admin groups only" `
                            -WhyBad $ri.Why -AttackScenario $ri.Attack -Principle $ri.Principle `
                            -ObjectDN $comp.DistinguishedName))
                    }
                }
            } catch {}
        }
    } else {
        Write-Status "  No LAPS schema attributes found. Skipping LAPS bypass detection." "Gray"
    }

    $Findings
}
