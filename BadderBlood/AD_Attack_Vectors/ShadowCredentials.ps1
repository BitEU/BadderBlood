################################
# ShadowCredentials.ps1 - BadderBlood Shadow Credentials Attack Vector
# Simulates misconfigurations where low-privilege principals have write
# access to msDS-KeyCredentialLink, enabling PKINIT-based authentication
# as the target account without knowing its password.
################################
function Set-ShadowCredentialsMisconfiguration {
    <#
        .SYNOPSIS
            Creates ACL misconfigurations enabling Shadow Credentials attacks.
        .DESCRIPTION
            Grants WriteProperty on msDS-KeyCredentialLink to low-privilege
            principals. This allows an attacker to add a certificate-based
            credential and authenticate as the target via PKINIT.
            Discoverable via BloodHound (AddKeyCredentialLink edge).
            Exploitable via Whisker, pyWhisker, or Certipy.
        .PARAMETER ShadowCredCount
            Number of Shadow Credential attack paths to create (default: 3)
        .NOTES
            BadderBlood - Realistic AD Lab Generator
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 15)]
        [int]$ShadowCredCount = 3
    )

    $dom = Get-ADDomain
    $setDC = $dom.PDCEmulator
    $dn = $dom.DistinguishedName
    Set-Location AD:

    # Get the schema GUID for msDS-KeyCredentialLink
    $schemaPath = (Get-ADRootDSE).SchemaNamingContext
    $keyCredLinkGuid = $null
    try {
        $schemaObj = Get-ADObject -SearchBase $schemaPath -LDAPFilter "(&(lDAPDisplayName=msDS-KeyCredentialLink)(schemaidguid=*))" -Properties schemaIDGUID
        if ($schemaObj) {
            $keyCredLinkGuid = [System.GUID]$schemaObj.schemaIDGUID
        }
    } catch {}

    if (-not $keyCredLinkGuid) {
        Write-Host "    [X] msDS-KeyCredentialLink schema attribute not found (requires Server 2016+ schema)" -ForegroundColor Red
        return
    }

    $allUsers = Get-ADUser -Filter * -Server $setDC -ResultSetSize $null
    $allGroups = Get-ADGroup -Filter { GroupCategory -eq "Security" -and GroupScope -eq "Global" } -Properties isCriticalSystemObject -Server $setDC -ResultSetSize $null

    $nonCritGroups = @($allGroups | Where-Object { $_.isCriticalSystemObject -ne $true })
    $serviceAccounts = @($allUsers | Where-Object { $_.SamAccountName -like "*SA" -or $_.SamAccountName -like "svc_*" })
    $regularUsers = @($allUsers | Where-Object { $_.SamAccountName -notlike "*SA" -and $_.SamAccountName -notlike "svc_*" })

    $configured = 0
    $attempts = 0
    $maxAttempts = $ShadowCredCount * 3

    while ($configured -lt $ShadowCredCount -and $attempts -lt $maxAttempts) {
        $attempts++

        # Pick a target user (the one who will be compromisable)
        $scenarioRoll = Get-Random -Minimum 1 -Maximum 101

        if ($scenarioRoll -le 50 -and $regularUsers.Count -ge 2) {
            # Scenario A: A regular user can write KeyCredentialLink on another user
            # Realistic: "Help desk got WriteProperty instead of just password reset"
            $attacker = $regularUsers | Get-Random
            $target = $regularUsers | Where-Object { $_.DistinguishedName -ne $attacker.DistinguishedName } | Get-Random
            if (-not $target) { continue }
            $attackerSID = New-Object System.Security.Principal.SecurityIdentifier $attacker.SID
            $desc = "user '$($attacker.SamAccountName)' -> user '$($target.SamAccountName)'"

        } elseif ($scenarioRoll -le 80 -and $nonCritGroups.Count -gt 0 -and $regularUsers.Count -gt 0) {
            # Scenario B: A group can write KeyCredentialLink on a user
            # Realistic: "IT group has overly broad write permissions from delegation"
            $attackerGroup = $nonCritGroups | Get-Random
            $target = $regularUsers | Get-Random
            $attackerSID = New-Object System.Security.Principal.SecurityIdentifier $attackerGroup.SID
            $desc = "group '$($attackerGroup.Name)' -> user '$($target.SamAccountName)'"

        } elseif ($serviceAccounts.Count -gt 0 -and $regularUsers.Count -gt 0) {
            # Scenario C: A regular user can shadow-credential a service account
            # Realistic: "Dev has WriteProperty on the app service account"
            $attacker = $regularUsers | Get-Random
            $target = $serviceAccounts | Get-Random
            if (-not $target) { continue }
            $attackerSID = New-Object System.Security.Principal.SecurityIdentifier $attacker.SID
            $desc = "user '$($attacker.SamAccountName)' -> service account '$($target.SamAccountName)'"

        } else {
            continue
        }

        try {
            $targetDN = "AD:\$($target.DistinguishedName)"
            $acl = Get-Acl $targetDN
            $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $attackerSID,
                "WriteProperty",
                "Allow",
                $keyCredLinkGuid,
                "None"
            )
            $acl.AddAccessRule($rule)
            Set-Acl -AclObject $acl -Path $targetDN -ErrorAction Stop
            Write-Host "    [!] Shadow Credentials: $desc" -ForegroundColor Yellow
            $configured++
        } catch {}
    }

    Write-Host "    [+] Created $configured Shadow Credential attack paths" -ForegroundColor Green
}
