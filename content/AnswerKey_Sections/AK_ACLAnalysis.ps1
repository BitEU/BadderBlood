################################
# AK_ACLAnalysis.ps1 - Section 6: ACL / Delegation Analysis
# Dot-sourced by BadderBloodAnswerKey.ps1
################################
function Invoke-AKACLAudit {
    <#
        .SYNOPSIS
            Analyzes ACL delegations on OUs and critical objects for dangerous permissions.
        .PARAMETER DomainDN
            Domain distinguished name.
        .PARAMETER AllOUs
            All organizational units.
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
        [string]$DomainDN,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$AllOUs,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$BadderBloodUsers,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$BadderBloodGroups
    )

    Write-Status "SECTION 6: Analyzing ACL delegations on OUs and objects..."

    $Findings = [System.Collections.Generic.List[PSObject]]::new()

    $CriticalObjects = @(
        $DomainDN
        "CN=AdminSDHolder,CN=System,$DomainDN"
    )

    # Add all OU DNs
    $CriticalObjects += ($AllOUs | ForEach-Object { $_.DistinguishedName })

    # Add privileged group DNs
    foreach ($pgName in $PrivilegedGroups) {
        try { $CriticalObjects += (Get-ADGroup $pgName).DistinguishedName } catch {}
    }
    # Add all BadderBlood-created group DNs to catch group-to-group permission chains
    $CriticalObjects += ($BadderBloodGroups | ForEach-Object { $_.DistinguishedName })

    $DangerousRights = @(
        "GenericAll"
        "GenericWrite"
        "WriteDacl"
        "WriteOwner"
        "WriteProperty"
        "ExtendedRight"
        "Self"
    )

    $totalToCheck = [Math]::Min($CriticalObjects.Count, 500)
    Write-Status "Checking ACLs on $totalToCheck critical objects (of $($CriticalObjects.Count) total)..."

    $checkedCount = 0
    foreach ($objDN in ($CriticalObjects | Select-Object -First $totalToCheck)) {
        $checkedCount++
        if ($checkedCount % 25 -eq 0) {
            Write-Status "  ACL check progress: $checkedCount / $totalToCheck"
        }

        try {
            $acl = Get-Acl -Path "AD:\$objDN" -ErrorAction SilentlyContinue
            if (-not $acl) { continue }

            foreach ($ace in $acl.Access) {
                $identity = $ace.IdentityReference.ToString()

                # Skip built-in/expected identities
                if ($identity -match "^(NT AUTHORITY|BUILTIN|S-1-5)" -or
                    $identity -match "(Domain Admins|Enterprise Admins|SYSTEM|Administrators)$") {
                    continue
                }

                # Check if this is a BadderBlood user or group with dangerous permissions
                $samName = $identity -replace "^.*\\"
                $isBBUser = $BadderBloodUsers | Where-Object { $_.SamAccountName -eq $samName }
                $isBBGroup = $BadderBloodGroups | Where-Object { $_.SamAccountName -eq $samName }

                if (($isBBUser -or $isBBGroup) -and
                    ($DangerousRights -contains $ace.ActiveDirectoryRights.ToString() -or
                     ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -or
                     ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -or
                     ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) -or
                     ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)))
                {
                    $sev = if ($objDN -like "*AdminSDHolder*" -or $objDN -eq $DomainDN) { "CRITICAL" } else { "HIGH" }
                    $objType = if ($isBBUser) { "User" } else { "Group" }

                    $Findings.Add((Write-Finding -Category "Dangerous ACL" `
                        -Severity $sev `
                        -Finding "$objType '$samName' has '$($ace.ActiveDirectoryRights)' on '$objDN'" `
                        -CurrentState "ACE: $($ace.AccessControlType) | Rights: $($ace.ActiveDirectoryRights) | Inherited: $($ace.IsInherited)" `
                        -ExpectedState "REMOVE this ACE - BadderBlood-created $objType should not have these permissions" `
                        -ObjectDN $objDN))
                }
            }
        }
        catch {
            # Silently skip objects we can't read ACLs on
        }
    }

    $Findings
}
