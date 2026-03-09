################################
# AK_GMSA.ps1 - Section 12: gMSA Misconfiguration Detection
# Dot-sourced by BadderBloodAnswerKey.ps1
################################
function Invoke-AKGMSAAudit {
    <#
        .SYNOPSIS
            Checks for gMSA password retrieval misconfigurations.
        .OUTPUTS
            List of findings.
    #>
    [CmdletBinding()]
    param()

    Write-Status "SECTION 12: Checking for gMSA password retrieval misconfigurations..."

    $Findings = [System.Collections.Generic.List[PSObject]]::new()

    try {
        $gmsaAccounts = Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword, DistinguishedName, Name -ErrorAction Stop

        foreach ($gmsa in $gmsaAccounts) {
            $principals = $gmsa.PrincipalsAllowedToRetrieveManagedPassword
            if (-not $principals -or $principals.Count -eq 0) { continue }

            foreach ($principalDN in $principals) {
                $principalName = ($principalDN -split ',')[0] -replace '^CN=',''
                $isBroadGroup = $false

                try {
                    $pObj = Get-ADObject $principalDN -Properties SamAccountName, objectClass -ErrorAction Stop
                    $principalName = $pObj.SamAccountName

                    if ($pObj.objectClass -eq 'group') {
                        $groupMembers = Get-ADGroupMember $pObj.SamAccountName -ErrorAction SilentlyContinue
                        if ($groupMembers.Count -gt 10) { $isBroadGroup = $true }
                        if ($principalName -in @('Domain Computers','Domain Users','Authenticated Users')) { $isBroadGroup = $true }
                    }
                } catch {}

                $sev = if ($isBroadGroup) { "CRITICAL" } else { "MEDIUM" }
                $ri = $NewAttackVectorExplanations["GMSA"]
                $Findings.Add((Write-Finding -Category "gMSA Misconfiguration" `
                    -Severity $sev `
                    -Finding "gMSA '$($gmsa.Name)' password readable by '$principalName'$(if($isBroadGroup){' (BROAD GROUP)'})" `
                    -CurrentState "PrincipalsAllowedToRetrieveManagedPassword includes '$principalName'" `
                    -ExpectedState "Restrict to ONLY the specific computer accounts that run this service" `
                    -WhyBad $ri.Why -AttackScenario $ri.Attack -Principle $ri.Principle `
                    -ObjectDN $gmsa.DistinguishedName))
            }
        }
    } catch {
        Write-Status "  gMSA query failed (may require specific permissions or Server 2012+). Skipping." "Gray"
    }

    $Findings
}
