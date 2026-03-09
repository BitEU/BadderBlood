################################
# AK_ADIDNS.ps1 - Section 13: ADIDNS Misconfiguration Detection
# Dot-sourced by BadderBloodAnswerKey.ps1
################################
function Invoke-AKADIDNSAudit {
    <#
        .SYNOPSIS
            Checks for ADIDNS zone ACL misconfigurations and stale DNS records.
        .PARAMETER DomainDN
            Domain distinguished name.
        .PARAMETER DomainDNS
            Domain DNS name.
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
        [string]$DomainDNS,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$BadderBloodUsers,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$BadderBloodGroups
    )

    Write-Status "SECTION 13: Checking for ADIDNS misconfigurations..."

    $Findings = [System.Collections.Generic.List[PSObject]]::new()

    $dnsZoneDN = "DC=$DomainDNS,CN=MicrosoftDNS,DC=DomainDnsZones,$DomainDN"

    # Check DNS zone ACLs for non-default write permissions
    try {
        Set-Location AD:
        foreach ($dnsDN in @($dnsZoneDN, "CN=MicrosoftDNS,DC=DomainDnsZones,$DomainDN")) {
            $dnsAcl = Get-Acl "AD:\$dnsDN" -ErrorAction SilentlyContinue
            if (-not $dnsAcl) { continue }

            foreach ($ace in $dnsAcl.Access) {
                if ($ace.AccessControlType -eq "Allow" -and
                    ($ace.ActiveDirectoryRights -match "CreateChild|DeleteChild|GenericWrite|GenericAll|WriteDacl") -and
                    $ace.IdentityReference -notmatch "(SYSTEM|Domain Admins|Enterprise Admins|Administrators|DnsAdmins|DnsUpdateProxy|CREATOR OWNER)$") {

                    $samName = $ace.IdentityReference.ToString() -replace "^.*\\"
                    $isBB = ($BadderBloodUsers | Where-Object { $_.SamAccountName -eq $samName }) -or
                            ($BadderBloodGroups | Where-Object { $_.SamAccountName -eq $samName })
                    if ($isBB) {
                        $ri = $NewAttackVectorExplanations["ADIDNS_ACL"]
                        $Findings.Add((Write-Finding -Category "ADIDNS Misconfiguration" `
                            -Severity "HIGH" `
                            -Finding "BadderBlood object '$samName' has '$($ace.ActiveDirectoryRights)' on DNS zone" `
                            -CurrentState "ACE: $($ace.IdentityReference) -> $($ace.ActiveDirectoryRights) on $dnsDN" `
                            -ExpectedState "Remove this ACE. Only DNS Admins should have write access to DNS zones" `
                            -WhyBad $ri.Why -AttackScenario $ri.Attack -Principle $ri.Principle `
                            -ObjectDN $dnsDN))
                    }
                }
            }
        }
    } catch {}

    # Detect stale DNS records pointing to non-routable IPs
    try {
        $dnsRecords = Get-ADObject -SearchBase $dnsZoneDN -Filter { objectClass -eq "dnsNode" } -Properties dnsRecord, Name -ErrorAction Stop
        $staleHostnames = @('oldfileserver','legacy-sql01','dev-web03','staging-app','test-dc02','backup-nas01',
            'print-srv02','decomm-exch01','temp-jump01','poc-server','migration-svc','old-intranet',
            'retired-vpn','unused-proxy','former-ca01','old-wsus','legacy-sccm','prev-adfs','old-radius','decomm-nps')

        foreach ($record in $dnsRecords) {
            if ($record.Name -in $staleHostnames) {
                $ri = $NewAttackVectorExplanations["ADIDNS_Stale"]
                $Findings.Add((Write-Finding -Category "ADIDNS Misconfiguration" `
                    -Severity "MEDIUM" `
                    -Finding "Stale DNS record '$($record.Name).$DomainDNS' points to a decommissioned server" `
                    -CurrentState "DNS A record exists for hostname '$($record.Name)' (likely non-existent host)" `
                    -ExpectedState "Delete stale DNS record. Enable DNS scavenging to prevent future stale records" `
                    -WhyBad $ri.Why -AttackScenario $ri.Attack -Principle $ri.Principle `
                    -ObjectDN $record.DistinguishedName))
            }
        }
    } catch {}

    $Findings
}
