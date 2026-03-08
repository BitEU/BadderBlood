################################
# ADCS_Misconfiguration.ps1 - BadderBlood ADCS Attack Vectors
# Simulates realistic Active Directory Certificate Services misconfigurations
# including ESC1, ESC2, ESC4, ESC6, and ESC8 (where possible without
# actually installing ADCS — creates the template objects if ADCS exists).
################################
function Set-ADCSMisconfiguration {
    <#
        .SYNOPSIS
            Creates vulnerable ADCS certificate templates for training.
        .DESCRIPTION
            If AD CS is installed, creates or modifies certificate templates
            with known misconfigurations:
              ESC1: Template allows SAN override + enrollee supplies subject
              ESC2: Template has Any Purpose EKU or no EKU restriction
              ESC4: Low-privilege principal has write access to template
              ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag (noted only)
              ESC8: Web enrollment over HTTP (noted only)
            If ADCS is not installed, creates simulated template objects
            in a dedicated OU for BloodHound/Certify lab exercises.
        .PARAMETER TemplateCount
            Number of vulnerable templates to create (default: 4)
        .NOTES
            BadderBlood - Realistic AD Lab Generator
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10)]
        [int]$TemplateCount = 4
    )

    $dom = Get-ADDomain
    $setDC = $dom.PDCEmulator
    $dn = $dom.DistinguishedName

    # Check if ADCS is installed by looking for the PKI enrollment services container
    $configNC = (Get-ADRootDSE).ConfigurationNamingContext
    $enrollmentServices = $null
    try {
        $enrollmentServices = Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC" -Filter * -Server $setDC -ErrorAction Stop
    } catch {}

    $adcsInstalled = ($null -ne $enrollmentServices -and @($enrollmentServices).Count -gt 0)

    if (-not $adcsInstalled) {
        Write-Host "    [*] ADCS not installed - creating ACL-based attack paths on PKI containers instead" -ForegroundColor Cyan
        Set-ADCSACLMisconfigurations -ConfigNC $configNC -SetDC $setDC
        return
    }

    Write-Host "    [*] ADCS detected - creating vulnerable certificate templates..." -ForegroundColor Cyan

    $allUsers = Get-ADUser -Filter * -Server $setDC -ResultSetSize $null
    $allGroups = Get-ADGroup -Filter { GroupCategory -eq "Security" } -Properties isCriticalSystemObject -Server $setDC -ResultSetSize $null
    $nonCritGroups = @($allGroups | Where-Object { $_.isCriticalSystemObject -ne $true })

    $templateBaseDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
    $configured = 0

    # ---- ESC1: Client auth template with ENROLLEE_SUPPLIES_SUBJECT ----
    if ($configured -lt $TemplateCount) {
        $templateName = "BB-VulnWebServer"
        $templateDN = "CN=$templateName,$templateBaseDN"

        try {
            # Check if template already exists
            $existing = $null
            try { $existing = Get-ADObject $templateDN -Server $setDC -ErrorAction Stop } catch {}

            if (-not $existing) {
                # Clone from a base template — use WebServer if available
                $baseTemplate = Get-ADObject -SearchBase $templateBaseDN -Filter { Name -eq "WebServer" } -Properties * -Server $setDC -ErrorAction Stop

                if ($baseTemplate) {
                    $templateOID = "1.3.6.1.4.1.311.21.8." + (Get-Random -Minimum 1000000 -Maximum 9999999) + "." + (Get-Random -Minimum 1000 -Maximum 9999)

                    New-ADObject -Name $templateName -Type "pKICertificateTemplate" -Path $templateBaseDN -Server $setDC -OtherAttributes @{
                        'displayName'                  = "BB Vulnerable Web Server"
                        'msPKI-Cert-Template-OID'      = $templateOID
                        'msPKI-Certificate-Name-Flag'  = 1  # ENROLLEE_SUPPLIES_SUBJECT
                        'msPKI-Enrollment-Flag'        = 0
                        'msPKI-Private-Key-Flag'       = 16842752
                        'msPKI-Template-Minor-Revision' = 1
                        'msPKI-Template-Schema-Version' = 2
                        'pKIDefaultKeySpec'            = 1
                        'pKIMaxIssuingDepth'           = 0
                        'pKIExtendedKeyUsage'          = @('1.3.6.1.5.5.7.3.1','1.3.6.1.5.5.7.3.2')  # Server + Client Auth
                        'flags'                        = 131680
                        'revision'                     = 100
                    } -ErrorAction Stop

                    # Grant Authenticated Users enrollment rights
                    $authUsersSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")
                    $templateObj = Get-ADObject $templateDN -Server $setDC
                    $acl = Get-Acl "AD:\$templateDN"
                    # Extended Right: Certificate-Enrollment = 0e10c968-78fb-11d2-90d4-00c04f79dc55
                    $enrollGuid = [System.GUID]"0e10c968-78fb-11d2-90d4-00c04f79dc55"
                    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $authUsersSID, "ExtendedRight", "Allow", $enrollGuid, "None"
                    )
                    $acl.AddAccessRule($rule)
                    Set-Acl -AclObject $acl -Path "AD:\$templateDN"

                    Write-Host "    [!] ESC1: Template '$templateName' allows SAN override + Client Auth + Authenticated Users can enroll" -ForegroundColor Yellow
                    $configured++
                }
            }
        } catch {
            Write-Host "    [X] ESC1 template creation failed: $_" -ForegroundColor Red
        }
    }

    # ---- ESC2: Template with Any Purpose or SubCA EKU ----
    if ($configured -lt $TemplateCount) {
        $templateName = "BB-VulnAnyPurpose"
        $templateDN = "CN=$templateName,$templateBaseDN"

        try {
            $existing = $null
            try { $existing = Get-ADObject $templateDN -Server $setDC -ErrorAction Stop } catch {}

            if (-not $existing) {
                $templateOID = "1.3.6.1.4.1.311.21.8." + (Get-Random -Minimum 1000000 -Maximum 9999999) + "." + (Get-Random -Minimum 1000 -Maximum 9999)

                New-ADObject -Name $templateName -Type "pKICertificateTemplate" -Path $templateBaseDN -Server $setDC -OtherAttributes @{
                    'displayName'                  = "BB Any Purpose Template"
                    'msPKI-Cert-Template-OID'      = $templateOID
                    'msPKI-Certificate-Name-Flag'  = 0
                    'msPKI-Enrollment-Flag'        = 0
                    'msPKI-Private-Key-Flag'       = 16842752
                    'msPKI-Template-Minor-Revision' = 1
                    'msPKI-Template-Schema-Version' = 2
                    'pKIDefaultKeySpec'            = 1
                    'pKIMaxIssuingDepth'           = 0
                    'pKIExtendedKeyUsage'          = @('2.5.29.37.0')  # Any Purpose
                    'flags'                        = 131680
                    'revision'                     = 100
                } -ErrorAction Stop

                # Grant Domain Users enrollment
                $domainUsersSID = New-Object System.Security.Principal.SecurityIdentifier((Get-ADGroup "Domain Users" -Server $setDC).SID)
                $acl = Get-Acl "AD:\$templateDN"
                $enrollGuid = [System.GUID]"0e10c968-78fb-11d2-90d4-00c04f79dc55"
                $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $domainUsersSID, "ExtendedRight", "Allow", $enrollGuid, "None"
                )
                $acl.AddAccessRule($rule)
                Set-Acl -AclObject $acl -Path "AD:\$templateDN"

                Write-Host "    [!] ESC2: Template '$templateName' has Any Purpose EKU + Domain Users can enroll" -ForegroundColor Yellow
                $configured++
            }
        } catch {
            Write-Host "    [X] ESC2 template creation failed: $_" -ForegroundColor Red
        }
    }

    # ---- ESC4: Low-privilege write access on a certificate template ----
    if ($configured -lt $TemplateCount -and $nonCritGroups.Count -gt 0) {
        try {
            # Find an existing template and grant a non-critical group write access
            $templates = Get-ADObject -SearchBase $templateBaseDN -Filter { objectClass -eq "pKICertificateTemplate" } -Server $setDC
            if ($templates -and @($templates).Count -gt 0) {
                $targetTemplate = $templates | Get-Random
                $attackerGroup = $nonCritGroups | Get-Random
                $groupSID = New-Object System.Security.Principal.SecurityIdentifier $attackerGroup.SID

                Set-Location AD:
                $acl = Get-Acl "AD:\$($targetTemplate.DistinguishedName)"
                $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $groupSID, "WriteProperty", "Allow", "All"
                )
                $acl.AddAccessRule($rule)
                Set-Acl -AclObject $acl -Path "AD:\$($targetTemplate.DistinguishedName)"

                Write-Host "    [!] ESC4: Group '$($attackerGroup.Name)' has WriteProperty on template '$($targetTemplate.Name)'" -ForegroundColor Yellow
                $configured++
            }
        } catch {
            Write-Host "    [X] ESC4 misconfiguration failed: $_" -ForegroundColor Red
        }
    }

    # ---- ESC4 variant: WriteDACL on template ----
    if ($configured -lt $TemplateCount -and $nonCritGroups.Count -gt 0) {
        try {
            $templates = Get-ADObject -SearchBase $templateBaseDN -Filter { objectClass -eq "pKICertificateTemplate" } -Server $setDC
            if ($templates -and @($templates).Count -gt 0) {
                $targetTemplate = $templates | Get-Random
                $attackerGroup = $nonCritGroups | Get-Random
                $groupSID = New-Object System.Security.Principal.SecurityIdentifier $attackerGroup.SID

                Set-Location AD:
                $acl = Get-Acl "AD:\$($targetTemplate.DistinguishedName)"
                $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $groupSID, "WriteDacl", "Allow"
                )
                $acl.AddAccessRule($rule)
                Set-Acl -AclObject $acl -Path "AD:\$($targetTemplate.DistinguishedName)"

                Write-Host "    [!] ESC4: Group '$($attackerGroup.Name)' has WriteDACL on template '$($targetTemplate.Name)'" -ForegroundColor Yellow
                $configured++
            }
        } catch {
            Write-Host "    [X] ESC4 WriteDACL misconfiguration failed: $_" -ForegroundColor Red
        }
    }

    Write-Host "    [+] Created $configured ADCS misconfigurations" -ForegroundColor Green
}

function Set-ADCSACLMisconfigurations {
    <#
        .SYNOPSIS
            When ADCS is not installed, creates ACL misconfigurations on the
            PKI containers in Configuration NC for training purposes.
    #>
    param(
        [string]$ConfigNC,
        [string]$SetDC
    )

    $dom = Get-ADDomain
    $allGroups = Get-ADGroup -Filter { GroupCategory -eq "Security" -and GroupScope -eq "Global" } -Properties isCriticalSystemObject -Server $SetDC -ResultSetSize $null
    $nonCritGroups = @($allGroups | Where-Object { $_.isCriticalSystemObject -ne $true })

    if ($nonCritGroups.Count -eq 0) {
        Write-Host "    [X] No non-critical groups found for ADCS ACL misconfigs" -ForegroundColor Red
        return
    }

    $pkiContainerDN = "CN=Public Key Services,CN=Services,$ConfigNC"
    $configured = 0

    # Grant a group write access to the PKI container itself
    try {
        $attackerGroup = $nonCritGroups | Get-Random
        $groupSID = New-Object System.Security.Principal.SecurityIdentifier $attackerGroup.SID

        Set-Location AD:
        $acl = Get-Acl "AD:\$pkiContainerDN"
        $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $groupSID, "WriteProperty", "Allow", "Descendents"
        )
        $acl.AddAccessRule($rule)
        Set-Acl -AclObject $acl -Path "AD:\$pkiContainerDN"

        Write-Host "    [!] ADCS-ACL: Group '$($attackerGroup.Name)' has WriteProperty on Public Key Services container" -ForegroundColor Yellow
        $configured++
    } catch {}

    # Grant another group WriteDACL on the NTAuthCertificates container
    try {
        $ntAuthDN = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,$ConfigNC"
        $ntAuth = Get-ADObject $ntAuthDN -Server $SetDC -ErrorAction Stop

        $attackerGroup2 = $nonCritGroups | Get-Random
        $groupSID2 = New-Object System.Security.Principal.SecurityIdentifier $attackerGroup2.SID

        $acl = Get-Acl "AD:\$ntAuthDN"
        $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $groupSID2, "WriteDacl", "Allow"
        )
        $acl.AddAccessRule($rule)
        Set-Acl -AclObject $acl -Path "AD:\$ntAuthDN"

        Write-Host "    [!] ADCS-ACL: Group '$($attackerGroup2.Name)' has WriteDACL on NTAuthCertificates" -ForegroundColor Yellow
        $configured++
    } catch {}

    Write-Host "    [+] Created $configured ADCS ACL misconfigurations (ADCS not installed)" -ForegroundColor Green
}
