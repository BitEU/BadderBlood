################################
# GMSA_Misconfiguration.ps1 - BadderBlood GMSA Abuse Vectors
# Simulates realistic Group Managed Service Account misconfigurations
# where low-privilege principals can read GMSA passwords.
################################
function Set-GMSAMisconfiguration {
    <#
        .SYNOPSIS
            Creates Group Managed Service Accounts with overly permissive
            PrincipalsAllowedToRetrieveManagedPassword settings.
        .DESCRIPTION
            Creates gMSAs where low-privilege groups or users can retrieve
            the managed password. In real environments, this happens when:
            1. An admin adds "Domain Computers" instead of specific servers
            2. A broad group like an IT team is granted retrieval rights
            3. A service account gMSA is readable by the app team group,
               which has too many members
            Exploitable via GMSAPasswordReader, gMSADumper, or manual
            LDAP queries with DSInternals.
        .PARAMETER GMSACount
            Number of misconfigured gMSAs to create (default: 3)
        .NOTES
            BadderBlood - Realistic AD Lab Generator
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10)]
        [int]$GMSACount = 3
    )

    $dom = Get-ADDomain
    $setDC = $dom.PDCEmulator
    $dn = $dom.DistinguishedName
    $dnsRoot = $dom.DNSRoot

    # Check if KDS root key exists (required for gMSA)
    $kdsKey = $null
    try { $kdsKey = Get-KdsRootKey -ErrorAction Stop } catch {}

    if (-not $kdsKey) {
        Write-Host "    [*] No KDS root key found. Creating one (effective immediately for lab)..." -ForegroundColor Cyan
        try {
            # Use -EffectiveImmediately is not a param; use past date for immediate availability in lab
            Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) -ErrorAction Stop
            Write-Host "    [+] KDS root key created" -ForegroundColor Green
        } catch {
            Write-Host "    [X] Failed to create KDS root key: $_" -ForegroundColor Red
            Write-Host "    [X] gMSA creation requires Domain Admin and Server 2012+ functional level" -ForegroundColor Red
            return
        }
    }

    $allGroups = Get-ADGroup -Filter { GroupCategory -eq "Security" } -Properties isCriticalSystemObject -Server $setDC -ResultSetSize $null
    $nonCritGroups = @($allGroups | Where-Object { $_.isCriticalSystemObject -ne $true })
    $allComputers = Get-ADComputer -Filter * -Server $setDC -ResultSetSize $null

    $gmsaNames = @(
        @{Name = 'gmsa-sqlsvc'; Desc = 'SQL Server Service (managed)'},
        @{Name = 'gmsa-websvc'; Desc = 'Web Application Service (managed)'},
        @{Name = 'gmsa-backup'; Desc = 'Backup Service (managed)'},
        @{Name = 'gmsa-monitor'; Desc = 'Monitoring Agent (managed)'},
        @{Name = 'gmsa-deploy'; Desc = 'Deployment Pipeline (managed)'},
        @{Name = 'gmsa-etl'; Desc = 'ETL Data Pipeline (managed)'},
        @{Name = 'gmsa-scan'; Desc = 'Vulnerability Scanner (managed)'},
        @{Name = 'gmsa-print'; Desc = 'Print Server Service (managed)'},
        @{Name = 'gmsa-exch'; Desc = 'Exchange Connector (managed)'},
        @{Name = 'gmsa-crm'; Desc = 'CRM Application (managed)'}
    )

    $configured = 0

    foreach ($gmsaTemplate in ($gmsaNames | Get-Random -Count ([Math]::Min($GMSACount, $gmsaNames.Count)))) {
        $gmsaName = $gmsaTemplate.Name
        $gmsaSam = $gmsaName + '$'

        # Check if already exists
        $existing = $null
        try { $existing = Get-ADServiceAccount -Identity $gmsaName -Server $setDC -ErrorAction Stop } catch {}
        if ($existing) { continue }

        # Decide the misconfiguration scenario
        $scenarioRoll = Get-Random -Minimum 1 -Maximum 101

        if ($scenarioRoll -le 35 -and $nonCritGroups.Count -gt 0) {
            # Scenario A: A non-critical group can retrieve the password
            # Realistic: "The app team needs to read the gMSA password" but team is too broad
            $allowedPrincipal = $nonCritGroups | Get-Random

            try {
                New-ADServiceAccount -Name $gmsaName -DNSHostName "$gmsaName.$dnsRoot" `
                    -Description $gmsaTemplate.Desc `
                    -PrincipalsAllowedToRetrieveManagedPassword $allowedPrincipal `
                    -Server $setDC -ErrorAction Stop

                Write-Host "    [!] gMSA '$gmsaName': Group '$($allowedPrincipal.Name)' can retrieve password" -ForegroundColor Yellow
                $configured++
            } catch {
                Write-Host "    [X] Failed to create gMSA '$gmsaName': $_" -ForegroundColor Red
            }

        } elseif ($scenarioRoll -le 65) {
            # Scenario B: "Domain Computers" can retrieve the password
            # Realistic: Admin used Domain Computers instead of specific computer accounts
            try {
                $domainComputers = Get-ADGroup "Domain Computers" -Server $setDC
                New-ADServiceAccount -Name $gmsaName -DNSHostName "$gmsaName.$dnsRoot" `
                    -Description $gmsaTemplate.Desc `
                    -PrincipalsAllowedToRetrieveManagedPassword $domainComputers `
                    -Server $setDC -ErrorAction Stop

                Write-Host "    [!] gMSA '$gmsaName': 'Domain Computers' can retrieve password (overly broad)" -ForegroundColor Yellow
                $configured++
            } catch {
                Write-Host "    [X] Failed to create gMSA '$gmsaName': $_" -ForegroundColor Red
            }

        } else {
            # Scenario C: Multiple principals can retrieve (group + computers)
            # Realistic: Password retrieval was granted incrementally during troubleshooting
            $principals = @()
            if ($nonCritGroups.Count -gt 0) {
                $principals += ($nonCritGroups | Get-Random)
            }
            if ($allComputers.Count -gt 0) {
                $principals += ($allComputers | Get-Random -Count ([Math]::Min(2, $allComputers.Count)))
            }

            if ($principals.Count -gt 0) {
                try {
                    New-ADServiceAccount -Name $gmsaName -DNSHostName "$gmsaName.$dnsRoot" `
                        -Description $gmsaTemplate.Desc `
                        -PrincipalsAllowedToRetrieveManagedPassword $principals `
                        -Server $setDC -ErrorAction Stop

                    $principalNames = ($principals | ForEach-Object { $_.Name }) -join ', '
                    Write-Host "    [!] gMSA '$gmsaName': Multiple principals can retrieve password: $principalNames" -ForegroundColor Yellow
                    $configured++
                } catch {
                    Write-Host "    [X] Failed to create gMSA '$gmsaName': $_" -ForegroundColor Red
                }
            }
        }
    }

    Write-Host "    [+] Created $configured misconfigured gMSAs" -ForegroundColor Green
}
