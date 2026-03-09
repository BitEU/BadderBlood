################################
# AK_ADCS.ps1 - Section 11: ADCS Misconfiguration Detection
# Dot-sourced by BadderBloodAnswerKey.ps1
################################
function Invoke-AKADCSAudit {
    <#
        .SYNOPSIS
            Checks for ADCS certificate template misconfigurations (ESC1, ESC2, ESC4).
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
        [object[]]$BadderBloodUsers,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$BadderBloodGroups
    )

    Write-Status "SECTION 11: Checking for ADCS certificate template misconfigurations..."

    $Findings = [System.Collections.Generic.List[PSObject]]::new()

    $configNC = (Get-ADRootDSE).ConfigurationNamingContext
    $templateBaseDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

    try {
        $certTemplates = Get-ADObject -SearchBase $templateBaseDN -Filter { objectClass -eq "pKICertificateTemplate" } `
            -Properties 'msPKI-Certificate-Name-Flag','pKIExtendedKeyUsage','displayName','msPKI-Cert-Template-OID' -ErrorAction Stop

        foreach ($tmpl in $certTemplates) {
            $nameFlag = $tmpl.'msPKI-Certificate-Name-Flag'
            $ekus = $tmpl.pKIExtendedKeyUsage

            # ESC1: ENROLLEE_SUPPLIES_SUBJECT (flag bit 1) + Client Auth EKU
            if ($nameFlag -band 1) {
                $hasClientAuth = $ekus -contains '1.3.6.1.5.5.7.3.2'
                if ($hasClientAuth) {
                    $ri = $NewAttackVectorExplanations["ADCS_ESC1"]
                    $Findings.Add((Write-Finding -Category "ADCS Misconfiguration" `
                        -Severity "CRITICAL" `
                        -Finding "Certificate template '$($tmpl.Name)' allows enrollee to supply subject AND has Client Authentication EKU (ESC1)" `
                        -CurrentState "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT=1, EKU includes Client Authentication" `
                        -ExpectedState "Remove ENROLLEE_SUPPLIES_SUBJECT flag or remove Client Authentication EKU. Require CA manager approval" `
                        -WhyBad $ri.Why -AttackScenario $ri.Attack -Principle $ri.Principle `
                        -ObjectDN $tmpl.DistinguishedName))
                }
            }

            # ESC2: Any Purpose EKU or no EKU restriction
            if ($ekus -contains '2.5.29.37.0' -or ($null -eq $ekus -and $null -ne $nameFlag)) {
                $ri = $NewAttackVectorExplanations["ADCS_ESC2"]
                $Findings.Add((Write-Finding -Category "ADCS Misconfiguration" `
                    -Severity "HIGH" `
                    -Finding "Certificate template '$($tmpl.Name)' has Any Purpose or unrestricted EKU (ESC2)" `
                    -CurrentState "EKU: $(if($ekus){'Any Purpose (2.5.29.37.0)'}else{'No EKU restriction'})" `
                    -ExpectedState "Restrict EKUs to specific required purposes only (e.g., Server Authentication)" `
                    -WhyBad $ri.Why -AttackScenario $ri.Attack -Principle $ri.Principle `
                    -ObjectDN $tmpl.DistinguishedName))
            }

            # ESC4: Check ACLs on templates for low-priv write access
            try {
                Set-Location AD:
                $tmplAcl = Get-Acl "AD:\$($tmpl.DistinguishedName)" -ErrorAction SilentlyContinue
                if ($tmplAcl) {
                    foreach ($ace in $tmplAcl.Access) {
                        if ($ace.AccessControlType -eq "Allow" -and
                            ($ace.ActiveDirectoryRights -match "WriteProperty|WriteDacl|WriteOwner|GenericAll|GenericWrite") -and
                            $ace.IdentityReference -notmatch "(SYSTEM|Domain Admins|Enterprise Admins|Administrators|CREATOR OWNER|Cert Publishers)$") {

                            $ri = $NewAttackVectorExplanations["ADCS_ESC4"]
                            $Findings.Add((Write-Finding -Category "ADCS Misconfiguration" `
                                -Severity "HIGH" `
                                -Finding "'$($ace.IdentityReference)' has '$($ace.ActiveDirectoryRights)' on certificate template '$($tmpl.Name)' (ESC4)" `
                                -CurrentState "ACE: $($ace.IdentityReference) -> $($ace.ActiveDirectoryRights)" `
                                -ExpectedState "Remove write access. Only CA Admins and Enterprise Admins should modify templates" `
                                -WhyBad $ri.Why -AttackScenario $ri.Attack -Principle $ri.Principle `
                                -ObjectDN $tmpl.DistinguishedName))
                        }
                    }
                }
            } catch {}
        }
    } catch {
        Write-Status "  ADCS templates not found or not accessible. Skipping." "Gray"
    }

    # Also check PKI container ACLs
    $pkiContainerDN = "CN=Public Key Services,CN=Services,$configNC"
    try {
        Set-Location AD:
        $pkiAcl = Get-Acl "AD:\$pkiContainerDN" -ErrorAction SilentlyContinue
        if ($pkiAcl) {
            foreach ($ace in $pkiAcl.Access) {
                if ($ace.AccessControlType -eq "Allow" -and
                    ($ace.ActiveDirectoryRights -match "WriteProperty|WriteDacl|WriteOwner|GenericAll|GenericWrite|CreateChild") -and
                    $ace.IdentityReference -notmatch "(SYSTEM|Domain Admins|Enterprise Admins|Administrators|CREATOR OWNER)$") {

                    $samName = $ace.IdentityReference.ToString() -replace "^.*\\"
                    $isBB = ($BadderBloodUsers | Where-Object { $_.SamAccountName -eq $samName }) -or
                            ($BadderBloodGroups | Where-Object { $_.SamAccountName -eq $samName })
                    if ($isBB) {
                        $Findings.Add((Write-Finding -Category "ADCS Misconfiguration" `
                            -Severity "HIGH" `
                            -Finding "BadderBlood object '$samName' has '$($ace.ActiveDirectoryRights)' on PKI container" `
                            -CurrentState "ACE on Public Key Services container" `
                            -ExpectedState "Remove this ACE. Only PKI Admins should have write access to PKI containers" `
                            -ObjectDN $pkiContainerDN))
                    }
                }
            }
        }
    } catch {}

    $Findings
}
