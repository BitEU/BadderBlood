################################
# AK_RBCD.ps1 - Section 9: RBCD Misconfiguration Detection
# Dot-sourced by BadderBloodAnswerKey.ps1
################################
function Invoke-AKRBCDAudit {
    <#
        .SYNOPSIS
            Checks for Resource-Based Constrained Delegation misconfigurations.
        .OUTPUTS
            PSCustomObject with Findings and AllComputers list.
    #>
    [CmdletBinding()]
    param()

    Write-Status "SECTION 9: Checking for Resource-Based Constrained Delegation misconfigurations..."

    $Findings = [System.Collections.Generic.List[PSObject]]::new()

    $AllComputers = Get-ADComputer -Filter * -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity', DistinguishedName, Name
    foreach ($comp in $AllComputers) {
        $rbcdRaw = $comp.'msDS-AllowedToActOnBehalfOfOtherIdentity'
        if ($rbcdRaw) {
            $rbcdSD = $null
            if ($rbcdRaw -is [System.DirectoryServices.ActiveDirectorySecurity]) {
                $sddl = $rbcdRaw.GetSecurityDescriptorSddlForm("All")
                $rbcdSD = New-Object Security.AccessControl.RawSecurityDescriptor($sddl)
            } elseif ($rbcdRaw -is [Security.AccessControl.RawSecurityDescriptor]) {
                $rbcdSD = $rbcdRaw
            } elseif ($rbcdRaw -is [byte[]]) {
                $rbcdSD = New-Object Security.AccessControl.RawSecurityDescriptor($rbcdRaw, 0)
            } else {
                try { $rbcdSD = New-Object Security.AccessControl.RawSecurityDescriptor($rbcdRaw.ToString()) } catch {}
            }
            if (-not $rbcdSD) { continue }
            foreach ($ace in $rbcdSD.DiscretionaryAcl) {
                $principalSID = $ace.SecurityIdentifier.ToString()
                $principalName = $principalSID
                try {
                    $adObj = Get-ADObject -Filter { objectSid -eq $principalSID } -Properties SamAccountName -ErrorAction Stop
                    if ($adObj) { $principalName = $adObj.SamAccountName }
                } catch {}

                $ri = $NewAttackVectorExplanations["RBCD"]
                $Findings.Add((Write-Finding -Category "Resource-Based Constrained Delegation" `
                    -Severity "HIGH" `
                    -Finding "Computer '$($comp.Name)' allows '$principalName' to delegate via RBCD" `
                    -CurrentState "msDS-AllowedToActOnBehalfOfOtherIdentity contains SID: $principalSID" `
                    -ExpectedState "Remove RBCD entry or validate it is required for a specific service" `
                    -WhyBad $ri.Why -AttackScenario $ri.Attack -Principle $ri.Principle `
                    -ObjectDN $comp.DistinguishedName))
            }
        }
    }

    [PSCustomObject]@{
        Findings     = $Findings
        AllComputers = $AllComputers
    }
}
