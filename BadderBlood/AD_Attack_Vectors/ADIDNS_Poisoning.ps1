################################
# ADIDNS_Poisoning.ps1 - BadderBlood ADIDNS Misconfiguration
# Simulates realistic Active Directory-Integrated DNS misconfigurations
# where low-privilege users can create or modify DNS records.
# Enables MITM, credential relay, and name resolution attacks.
################################
function Set-ADIDNSMisconfiguration {
    <#
        .SYNOPSIS
            Creates ADIDNS misconfigurations enabling DNS record manipulation.
        .DESCRIPTION
            Modifies ACLs on AD-integrated DNS zones and creates wildcard/
            stale records that enable:
            1. Authenticated users creating new DNS records (default in AD)
            2. Low-priv groups with write access to DNS zones
            3. Stale DNS records pointing to non-existent hosts (takeover)
            4. Wildcard records for name resolution poisoning
            Exploitable via Invoke-DNSUpdate, dnstool.py, krbrelayx.
        .PARAMETER StaleRecordCount
            Number of stale DNS records to create (default: 5)
        .NOTES
            BadderBlood - Realistic AD Lab Generator
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 20)]
        [int]$StaleRecordCount = 5
    )

    $dom = Get-ADDomain
    $setDC = $dom.PDCEmulator
    $dn = $dom.DistinguishedName
    $dnsRoot = $dom.DNSRoot

    # Locate the AD-integrated DNS zone
    $dnsZoneDN = "DC=$dnsRoot,CN=MicrosoftDNS,DC=DomainDnsZones,$dn"
    $dnsZoneExists = $false
    try {
        Get-ADObject $dnsZoneDN -Server $setDC -ErrorAction Stop | Out-Null
        $dnsZoneExists = $true
    } catch {}

    if (-not $dnsZoneExists) {
        Write-Host "    [X] AD-integrated DNS zone not found at '$dnsZoneDN'" -ForegroundColor Red
        Write-Host "    [*] Falling back to ACL-only misconfigurations on DomainDnsZones" -ForegroundColor Cyan
    }

    $allGroups = Get-ADGroup -Filter { GroupCategory -eq "Security" -and GroupScope -eq "Global" } -Properties isCriticalSystemObject -Server $setDC -ResultSetSize $null
    $nonCritGroups = @($allGroups | Where-Object { $_.isCriticalSystemObject -ne $true })

    $configured = 0

    # =========================================================================
    # 1. ACL MISCONFIGURATION: Grant a group write access to the DNS zone
    #    Realistic: "The network team needs to manage DNS records"
    # =========================================================================
    if ($nonCritGroups.Count -gt 0) {
        $dnsTargets = @(
            "DC=$dnsRoot,CN=MicrosoftDNS,DC=DomainDnsZones,$dn",
            "CN=MicrosoftDNS,DC=DomainDnsZones,$dn"
        )

        foreach ($dnsDN in $dnsTargets) {
            try {
                Get-ADObject $dnsDN -Server $setDC -ErrorAction Stop | Out-Null

                $attackerGroup = $nonCritGroups | Get-Random
                $groupSID = New-Object System.Security.Principal.SecurityIdentifier $attackerGroup.SID

                Set-Location AD:
                $acl = Get-Acl "AD:\$dnsDN"
                $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $groupSID,
                    "CreateChild,DeleteChild",
                    "Allow"
                )
                $acl.AddAccessRule($rule)
                Set-Acl -AclObject $acl -Path "AD:\$dnsDN" -ErrorAction Stop

                Write-Host "    [!] ADIDNS: Group '$($attackerGroup.Name)' can create/delete records in '$($dnsDN.Split(',')[0])'" -ForegroundColor Yellow
                $configured++
                break  # Only need one
            } catch {}
        }

        # Also grant GenericWrite on the zone container to another group
        try {
            if ($dnsZoneExists) {
                $attackerGroup2 = $nonCritGroups | Get-Random
                $groupSID2 = New-Object System.Security.Principal.SecurityIdentifier $attackerGroup2.SID

                $acl = Get-Acl "AD:\$dnsZoneDN"
                $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $groupSID2,
                    "GenericWrite",
                    "Allow",
                    "Descendents"
                )
                $acl.AddAccessRule($rule)
                Set-Acl -AclObject $acl -Path "AD:\$dnsZoneDN" -ErrorAction Stop

                Write-Host "    [!] ADIDNS: Group '$($attackerGroup2.Name)' has GenericWrite on DNS zone" -ForegroundColor Yellow
                $configured++
            }
        } catch {}
    }

    # =========================================================================
    # 2. STALE DNS RECORDS: Create A records pointing to non-existent IPs
    #    Realistic: servers were decommissioned but DNS wasn't cleaned up
    # =========================================================================
    if ($dnsZoneExists) {
        $staleHostnames = @(
            'oldfileserver', 'legacy-sql01', 'dev-web03', 'staging-app',
            'test-dc02', 'backup-nas01', 'print-srv02', 'decomm-exch01',
            'temp-jump01', 'poc-server', 'migration-svc', 'old-intranet',
            'retired-vpn', 'unused-proxy', 'former-ca01', 'old-wsus',
            'legacy-sccm', 'prev-adfs', 'old-radius', 'decomm-nps'
        )

        # Pick random non-routable IPs for stale records
        $staleIPs = @(
            '10.99.99.1', '10.99.99.2', '10.99.99.3', '10.99.99.4',
            '10.99.99.5', '172.16.255.1', '172.16.255.2', '192.168.255.1',
            '192.168.255.2', '192.168.255.3'
        )

        $selectedStale = $staleHostnames | Get-Random -Count ([Math]::Min($StaleRecordCount, $staleHostnames.Count))

        foreach ($hostname in $selectedStale) {
            $staleIP = $staleIPs | Get-Random

            try {
                # Use dnscmd or Add-DnsServerResourceRecordA if available
                $dnsCmd = Get-Command Add-DnsServerResourceRecordA -ErrorAction SilentlyContinue
                if ($dnsCmd) {
                    Add-DnsServerResourceRecordA -Name $hostname -ZoneName $dnsRoot -IPv4Address $staleIP -ComputerName $setDC -ErrorAction Stop
                    Write-Host "    [!] Stale DNS: $hostname.$dnsRoot -> $staleIP (decommissioned server)" -ForegroundColor Yellow
                    $configured++
                } else {
                    # Fallback: create the AD object directly
                    $recordDN = "DC=$hostname,$dnsZoneDN"
                    $existingRecord = $null
                    try { $existingRecord = Get-ADObject $recordDN -Server $setDC -ErrorAction Stop } catch {}

                    if (-not $existingRecord) {
                        # Create a minimal dnsNode object - the DNS server will serve it
                        # Build a binary DNS record for an A record
                        $ipBytes = [System.Net.IPAddress]::Parse($staleIP).GetAddressBytes()
                        # DNS record binary format: DataLength(2) + Type(2) + Version(1) + Rank(1) + Flags(2) + Serial(4) + TTL(4) + Reserved(4) + Timestamp(4) + Data
                        $recordData = [byte[]]@(
                            4, 0,       # DataLength = 4
                            1, 0,       # Type = A (1)
                            5,          # Version
                            240,        # Rank = RANK_ZONE (240)
                            0, 0,       # Flags
                            0, 0, 0, 0, # Serial
                            0, 14, 16, 0, # TTL = 900
                            0, 0, 0, 0, # Reserved
                            0, 0, 0, 0  # Timestamp (0 = static)
                        ) + $ipBytes

                        New-ADObject -Name $hostname -Type "dnsNode" -Path $dnsZoneDN -Server $setDC `
                            -OtherAttributes @{ 'dnsRecord' = $recordData } -ErrorAction Stop
                        Write-Host "    [!] Stale DNS: $hostname.$dnsRoot -> $staleIP (decommissioned server)" -ForegroundColor Yellow
                        $configured++
                    }
                }
            } catch {}
        }
    }

    Write-Host "    [+] Created $configured ADIDNS misconfigurations" -ForegroundColor Green
}
