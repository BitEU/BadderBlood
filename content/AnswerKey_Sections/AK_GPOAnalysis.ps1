################################
# AK_GPOAnalysis.ps1 - Section 7: GPO Analysis (merged from BadderBloodGPO_AnswerKey.ps1)
# Dot-sourced by BadderBloodAnswerKey.ps1. Requires GroupPolicy module.
################################
function Invoke-AKGPOAudit {
    <#
        .SYNOPSIS
            Comprehensive GPO security audit. Merges logic from the standalone
            BadderBloodGPO_AnswerKey.ps1 into the main answer key pipeline.
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

    Write-Status "SECTION 7: Analyzing Group Policy Objects..."

    $Findings = [System.Collections.Generic.List[PSObject]]::new()

    try {
        Import-Module GroupPolicy -ErrorAction Stop
    } catch {
        Write-Warning "GroupPolicy module not available. Skipping GPO analysis."
        return $Findings
    }

    $AllGPOs = Get-GPO -All
    Write-Status "Found $($AllGPOs.Count) GPOs in domain"

    # ================================================================
    # 7a: GPO Registry-based settings audit
    # ================================================================
    Write-Status "  Auditing GPO registry-based settings..."

    foreach ($gpo in $AllGPOs) {
        $gpoName = $gpo.DisplayName
        $gpoGuid = $gpo.Id

        # --- Windows Firewall Disabled ---
        try {
            $fwVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "EnableFirewall" -ErrorAction Stop
            if ($fwVal.Value -eq 0) {
                $risk = $GPORiskDatabase["FirewallDisabled"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "Windows Firewall DISABLED via GPO '$gpoName'" `
                    -CurrentState "EnableFirewall = 0 (Domain/Private/Public profiles)" `
                    -ExpectedState "EnableFirewall = 1 on all profiles" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpoName -GPOGUID $gpoGuid))
            }
        } catch {}

        # --- UAC Disabled ---
        try {
            $uacVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableLUA" -ErrorAction Stop
            if ($uacVal.Value -eq 0) {
                $risk = $GPORiskDatabase["UACDisabled"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "UAC DISABLED via GPO '$gpoName'" `
                    -CurrentState "EnableLUA = 0 (UAC completely off)" `
                    -ExpectedState "EnableLUA = 1, ConsentPromptBehaviorAdmin = 2, FilterAdministratorToken = 1" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpoName -GPOGUID $gpoGuid))
            }
        } catch {}

        # --- WDigest Enabled ---
        try {
            $wdVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ValueName "UseLogonCredential" -ErrorAction Stop
            if ($wdVal.Value -eq 1) {
                $risk = $GPORiskDatabase["WDigestEnabled"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "WDigest authentication ENABLED via GPO '$gpoName'" `
                    -CurrentState "UseLogonCredential = 1 (plaintext passwords in LSASS)" `
                    -ExpectedState "UseLogonCredential = 0" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpoName -GPOGUID $gpoGuid))
            }
        } catch {}

        # --- SMB Signing Disabled ---
        try {
            $smbVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "RequireSecuritySignature" -ErrorAction Stop
            if ($smbVal.Value -eq 0) {
                $risk = $GPORiskDatabase["SMBSigningDisabled"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "SMB Signing NOT REQUIRED via GPO '$gpoName'" `
                    -CurrentState "RequireSecuritySignature = 0 (server and/or client)" `
                    -ExpectedState "RequireSecuritySignature = 1 on both LanmanServer and LanManWorkstation" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpoName -GPOGUID $gpoGuid))
            }
        } catch {}

        # --- LLMNR Enabled ---
        try {
            $llVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -ErrorAction Stop
            if ($llVal.Value -eq 1) {
                $risk = $GPORiskDatabase["LLMNREnabled"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "LLMNR explicitly ENABLED via GPO '$gpoName'" `
                    -CurrentState "EnableMulticast = 1 (LLMNR active)" `
                    -ExpectedState "EnableMulticast = 0 (LLMNR disabled)" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpoName -GPOGUID $gpoGuid))
            }
        } catch {}

        # --- NTLMv1 Allowed ---
        try {
            $ntVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "LmCompatibilityLevel" -ErrorAction Stop
            if ($ntVal.Value -lt 3) {
                $levelText = switch ($ntVal.Value) { 0 { "Send LM & NTLM (worst)" }; 1 { "Send LM & NTLM - use NTLMv2 if negotiated" }; 2 { "Send NTLM only" } }
                $risk = $GPORiskDatabase["NTLMv1Allowed"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "Weak NTLM authentication allowed via GPO '$gpoName'" `
                    -CurrentState "LmCompatibilityLevel = $($ntVal.Value) ($levelText)" `
                    -ExpectedState "LmCompatibilityLevel = 5 (Send NTLMv2 only, refuse LM & NTLM)" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpoName -GPOGUID $gpoGuid))
            }
        } catch {}

        # --- Defender Disabled ---
        try {
            $defVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" -ValueName "DisableAntiSpyware" -ErrorAction Stop
            if ($defVal.Value -eq 1) {
                $risk = $GPORiskDatabase["DefenderDisabled"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "Windows Defender DISABLED via GPO '$gpoName'" `
                    -CurrentState "DisableAntiSpyware = 1 (Defender off)" `
                    -ExpectedState "Remove setting or set to 0. Verify active AV/EDR" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpoName -GPOGUID $gpoGuid))
            }
        } catch {}

        # --- PowerShell Logging Disabled ---
        try {
            $psVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ValueName "EnableScriptBlockLogging" -ErrorAction Stop
            if ($psVal.Value -eq 0) {
                $risk = $GPORiskDatabase["PSLoggingDisabled"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "PowerShell Script Block Logging DISABLED via GPO '$gpoName'" `
                    -CurrentState "ScriptBlockLogging=0, ModuleLogging=0, Transcription=0" `
                    -ExpectedState "All three enabled (ScriptBlockLogging=1, ModuleLogging=1, Transcription=1)" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpoName -GPOGUID $gpoGuid))
            }
        } catch {}

        # --- Excessive Cached Credentials ---
        try {
            $ccVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "CachedLogonsCount" -ErrorAction Stop
            if ([int]$ccVal.Value -gt 10) {
                $risk = $GPORiskDatabase["ExcessiveCachedCreds"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "Excessive cached credentials via GPO '$gpoName'" `
                    -CurrentState "CachedLogonsCount = $($ccVal.Value)" `
                    -ExpectedState "CachedLogonsCount = 1 or 2" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpoName -GPOGUID $gpoGuid))
            }
        } catch {}

        # --- RDP without NLA ---
        try {
            $nlaVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ValueName "UserAuthentication" -ErrorAction Stop
            if ($nlaVal.Value -eq 0) {
                $risk = $GPORiskDatabase["RDPNoNLA"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "RDP enabled WITHOUT Network Level Authentication via GPO '$gpoName'" `
                    -CurrentState "UserAuthentication = 0 (NLA disabled), MinEncryptionLevel = Low" `
                    -ExpectedState "UserAuthentication = 1 (NLA required), MinEncryptionLevel = 3 (High)" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpoName -GPOGUID $gpoGuid))
            }
        } catch {}

        # --- AutoRun Enabled ---
        try {
            $arVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoDriveTypeAutoRun" -ErrorAction Stop
            if ($arVal.Value -eq 0) {
                $risk = $GPORiskDatabase["AutoRunEnabled"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "AutoRun/AutoPlay ENABLED for all drives via GPO '$gpoName'" `
                    -CurrentState "NoDriveTypeAutoRun = 0 (AutoRun on all drive types)" `
                    -ExpectedState "NoDriveTypeAutoRun = 255 (disabled for all)" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpoName -GPOGUID $gpoGuid))
            }
        } catch {}

        # --- Credential Guard / LSA Protection Disabled ---
        try {
            $rplVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "RunAsPPL" -ErrorAction Stop
            if ($rplVal.Value -eq 0) {
                $risk = $GPORiskDatabase["LSAProtectionDisabled"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "LSA Protection (RunAsPPL) DISABLED via GPO '$gpoName'" `
                    -CurrentState "RunAsPPL = 0, VBS disabled" `
                    -ExpectedState "RunAsPPL = 1, EnableVirtualizationBasedSecurity = 1" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpoName -GPOGUID $gpoGuid))
            }
        } catch {}

        # --- Anonymous Enumeration ---
        try {
            $anVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "RestrictAnonymousSAM" -ErrorAction Stop
            if ($anVal.Value -eq 0) {
                $risk = $GPORiskDatabase["AnonymousEnumeration"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "Anonymous SAM enumeration ALLOWED via GPO '$gpoName'" `
                    -CurrentState "RestrictAnonymousSAM = 0, RestrictAnonymous = 0, RestrictNullSessAccess = 0" `
                    -ExpectedState "All RestrictAnonymous* = 1" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpoName -GPOGUID $gpoGuid))
            }
        } catch {}

        # --- WinRM Insecure ---
        try {
            $wrmVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowUnencryptedTraffic" -ErrorAction Stop
            if ($wrmVal.Value -eq 1) {
                $risk = $GPORiskDatabase["WinRMInsecure"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "WinRM allows UNENCRYPTED traffic and Basic auth via GPO '$gpoName'" `
                    -CurrentState "AllowUnencryptedTraffic = 1, AllowBasic = 1" `
                    -ExpectedState "AllowUnencryptedTraffic = 0, AllowBasic = 0 (use Kerberos over HTTPS)" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpoName -GPOGUID $gpoGuid))
            }
        } catch {}

        # --- Event Log Size Crippled ---
        try {
            $evtVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -ValueName "MaxSize" -ErrorAction Stop
            if ([int]$evtVal.Value -lt 1024) {
                $risk = $GPORiskDatabase["TinyEventLogs"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "Security Event Log crippled to $($evtVal.Value) KB via GPO '$gpoName'" `
                    -CurrentState "Security MaxSize = $($evtVal.Value) KB (fills in minutes)" `
                    -ExpectedState "Security MaxSize = 1048576 KB (1 GB), forward to SIEM" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpoName -GPOGUID $gpoGuid))
            }
        } catch {}

        # --- LDAP Signing Disabled ---
        try {
            $ldVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -ValueName "LDAPServerIntegrity" -ErrorAction Stop
            if ($ldVal.Value -eq 0) {
                $risk = $GPORiskDatabase["LDAPSigningDisabled"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "LDAP signing NOT REQUIRED via GPO '$gpoName'" `
                    -CurrentState "LDAPServerIntegrity = 0 (None)" `
                    -ExpectedState "LDAPServerIntegrity = 2 (Require signing)" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpoName -GPOGUID $gpoGuid))
            }
        } catch {}
    }

    # ================================================================
    # 7b: Password policy in SYSVOL security templates
    # ================================================================
    Write-Status "  Auditing password policies in SYSVOL security templates..."

    foreach ($gpo in $AllGPOs) {
        $infPath = "\\$DomainDNS\SYSVOL\$DomainDNS\Policies\{$($gpo.Id)}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
        if (Test-Path $infPath) {
            $content = Get-Content $infPath -Raw

            if ($content -match "MinimumPasswordLength\s*=\s*(\d+)" -and [int]$Matches[1] -lt 8) {
                $risk = $GPORiskDatabase["WeakMinLength"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "Minimum password length set to $($Matches[1]) via GPO '$($gpo.DisplayName)'" `
                    -CurrentState "MinimumPasswordLength = $($Matches[1])" -ExpectedState "MinimumPasswordLength = 14+" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpo.DisplayName -GPOGUID $gpo.Id))
            }
            if ($content -match "PasswordComplexity\s*=\s*0") {
                $risk = $GPORiskDatabase["NoComplexity"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "Password complexity DISABLED via GPO '$($gpo.DisplayName)'" `
                    -CurrentState "PasswordComplexity = 0" -ExpectedState "PasswordComplexity = 1" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpo.DisplayName -GPOGUID $gpo.Id))
            }
            if ($content -match "MaximumPasswordAge\s*=\s*0") {
                $risk = $GPORiskDatabase["NoMaxAge"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "Passwords NEVER EXPIRE via GPO '$($gpo.DisplayName)'" `
                    -CurrentState "MaximumPasswordAge = 0 (never)" -ExpectedState "MaximumPasswordAge = 90-365 days" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpo.DisplayName -GPOGUID $gpo.Id))
            }
            if ($content -match "LockoutBadCount\s*=\s*0") {
                $risk = $GPORiskDatabase["NoLockout"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "Account lockout DISABLED via GPO '$($gpo.DisplayName)'" `
                    -CurrentState "LockoutBadCount = 0 (unlimited attempts)" -ExpectedState "LockoutBadCount = 5-10" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpo.DisplayName -GPOGUID $gpo.Id))
            }
            if ($content -match "PasswordHistorySize\s*=\s*0") {
                $risk = $GPORiskDatabase["NoHistory"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "Password history NOT ENFORCED via GPO '$($gpo.DisplayName)'" `
                    -CurrentState "PasswordHistorySize = 0" -ExpectedState "PasswordHistorySize = 24" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpo.DisplayName -GPOGUID $gpo.Id))
            }
        }
    }

    # ================================================================
    # 7c: GPP Password files (MS14-025)
    # ================================================================
    Write-Status "  Scanning SYSVOL for GPP password files (MS14-025)..."

    $SYSVOLPath = "\\$DomainDNS\SYSVOL\$DomainDNS\Policies"
    $GPPFiles = @("Groups.xml", "Services.xml", "Scheduledtasks.xml", "DataSources.xml", "Printers.xml", "Drives.xml")

    foreach ($gpo in $AllGPOs) {
        foreach ($scope in @("Machine", "User")) {
            foreach ($gppFile in $GPPFiles) {
                $searchPaths = @(
                    "$SYSVOLPath\{$($gpo.Id)}\$scope\Preferences\Groups\$gppFile"
                    "$SYSVOLPath\{$($gpo.Id)}\$scope\Preferences\Services\$gppFile"
                    "$SYSVOLPath\{$($gpo.Id)}\$scope\Preferences\ScheduledTasks\$gppFile"
                    "$SYSVOLPath\{$($gpo.Id)}\$scope\Preferences\DataSources\$gppFile"
                    "$SYSVOLPath\{$($gpo.Id)}\$scope\Preferences\Printers\$gppFile"
                    "$SYSVOLPath\{$($gpo.Id)}\$scope\Preferences\Drives\$gppFile"
                )
                foreach ($path in $searchPaths) {
                    if (Test-Path $path) {
                        $xml = Get-Content $path -Raw
                        if ($xml -match "cpassword") {
                            $risk = $GPORiskDatabase["GPPPassword"]
                            $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                                -Finding "GPP PASSWORD (cpassword) found in '$($gpo.DisplayName)' at $gppFile" `
                                -CurrentState "File contains cpassword attribute (decryptable by ANY domain user)" `
                                -ExpectedState "Delete file. Use LAPS for local admin passwords. Never store creds in GPP" `
                                -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                                -GPOName $gpo.DisplayName -GPOGUID $gpo.Id))
                        }
                    }
                }
            }
        }
    }

    # ================================================================
    # 7d: GPO Permissions audit
    # ================================================================
    Write-Status "  Auditing GPO permissions for non-admin delegations..."

    foreach ($gpo in $AllGPOs) {
        try {
            $perms = Get-GPPermission -Name $gpo.DisplayName -All -ErrorAction Stop
            foreach ($perm in $perms) {
                $trustee = $perm.Trustee.Name
                $permLevel = $perm.Permission

                if ($trustee -in $LegitGPOEditors) { continue }
                if ($trustee -eq "Administrator") { continue }

                if ($permLevel -in @("GpoEdit", "GpoEditDeleteModifySecurity", "GpoCustom")) {
                    $isBadderBlood = $false
                    try {
                        $obj = Get-ADObject -Filter "SamAccountName -eq '$trustee'" -Properties Description
                        if ($obj.Description) {
                            $isBadderBlood = Test-IsBadderBloodObject -Description $obj.Description
                        }
                    } catch {}

                    $bbTag = if ($isBadderBlood) { " [BADDERBLOOD]" } else { "" }
                    $risk = $GPORiskDatabase["GPODelegation"]

                    $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                        -Finding "'$trustee'$bbTag has $permLevel on GPO '$($gpo.DisplayName)'" `
                        -CurrentState "$trustee -> $permLevel on {$($gpo.Id)}" `
                        -ExpectedState "Only Domain Admins / dedicated GPO admin accounts should have edit rights" `
                        -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                        -GPOName $gpo.DisplayName -GPOGUID $gpo.Id))
                }
            }
        } catch {}
    }

    # ================================================================
    # 7e: LAPS GPO configuration and OU permissions
    # ================================================================
    Write-Status "  Auditing LAPS deployment and OU permissions..."

    $AllOUsForLAPS = Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName
    foreach ($ou in $AllOUsForLAPS) {
        try {
            $acl = Get-Acl "AD:\$($ou.DistinguishedName)" -ErrorAction Stop
            foreach ($ace in $acl.Access) {
                $identity = $ace.IdentityReference.Value
                $dangerousIdentities = @("*Domain Users*", "*Authenticated Users*", "*Everyone*", "*S-1-1-0*", "*S-1-5-11*")
                $isDangerous = $false
                foreach ($pattern in $dangerousIdentities) {
                    if ($identity -like $pattern) { $isDangerous = $true; break }
                }
                if ($isDangerous -and $ace.ActiveDirectoryRights -match "ExtendedRight") {
                    $risk = $GPORiskDatabase["LAPSGPOMisconfigured"]
                    $Findings.Add((Write-Finding -Category $risk.Category -Severity "CRITICAL" `
                        -Finding "'$identity' has ExtendedRight on OU '$($ou.DistinguishedName)' - can read LAPS passwords" `
                        -CurrentState "$identity -> ExtendedRight (All) on OU" `
                        -ExpectedState "Only designated admin/helpdesk groups should have ExtendedRight" `
                        -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                        -GPOName "OU ACL (not GPO-specific)" -GPOGUID "N/A"))
                }
            }
        } catch {}
    }

    # Check LAPS GPO settings for weak configuration
    foreach ($gpo in $AllGPOs) {
        $gpoName = $gpo.DisplayName
        # Legacy LAPS
        try {
            $lapsEnabled = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" -ValueName "AdmPwdEnabled" -ErrorAction Stop
            if ($lapsEnabled.Value -eq 1) {
                try {
                    $lapsLen = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" -ValueName "PasswordLength" -ErrorAction Stop
                    if ([int]$lapsLen.Value -lt 14) {
                        $risk = $GPORiskDatabase["LAPSGPOMisconfigured"]
                        $Findings.Add((Write-Finding -Category $risk.Category -Severity "MEDIUM" `
                            -Finding "LAPS password length only $($lapsLen.Value) chars via GPO '$gpoName'" `
                            -CurrentState "PasswordLength = $($lapsLen.Value)" -ExpectedState "PasswordLength = 20+" `
                            -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                            -GPOName $gpoName -GPOGUID $gpo.Id))
                    }
                } catch {}
                try {
                    $lapsAge = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" -ValueName "PasswordAgeDays" -ErrorAction Stop
                    if ([int]$lapsAge.Value -gt 90) {
                        $risk = $GPORiskDatabase["LAPSGPOMisconfigured"]
                        $Findings.Add((Write-Finding -Category $risk.Category -Severity "MEDIUM" `
                            -Finding "LAPS password age set to $($lapsAge.Value) days via GPO '$gpoName'" `
                            -CurrentState "PasswordAgeDays = $($lapsAge.Value)" -ExpectedState "PasswordAgeDays = 30" `
                            -WhyBad "Long rotation means compromised passwords remain valid for extended periods." `
                            -Principle $risk.Principle -GPOName $gpoName -GPOGUID $gpo.Id))
                    }
                } catch {}
            }
        } catch {}
        # Windows LAPS
        try {
            $winLapsLen = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config" -ValueName "PasswordLength" -ErrorAction Stop
            if ([int]$winLapsLen.Value -lt 14) {
                $risk = $GPORiskDatabase["LAPSGPOMisconfigured"]
                $Findings.Add((Write-Finding -Category $risk.Category -Severity "MEDIUM" `
                    -Finding "Windows LAPS password length only $($winLapsLen.Value) chars via GPO '$gpoName'" `
                    -CurrentState "PasswordLength = $($winLapsLen.Value)" -ExpectedState "PasswordLength = 20+" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpoName -GPOGUID $gpo.Id))
            }
        } catch {}
    }

    # ================================================================
    # 7f: GPO Scheduled Tasks and writable script shares
    # ================================================================
    Write-Status "  Auditing GPO-deployed Scheduled Tasks..."

    foreach ($gpo in $AllGPOs) {
        foreach ($scope in @("Machine", "User")) {
            $taskFile = "$SYSVOLPath\{$($gpo.Id)}\$scope\Preferences\ScheduledTasks\ScheduledTasks.xml"
            if (Test-Path $taskFile) {
                try {
                    [xml]$taskXml = Get-Content $taskFile -Raw
                    $tasks = $taskXml.SelectNodes("//TaskV2")
                    if (-not $tasks -or $tasks.Count -eq 0) { $tasks = $taskXml.SelectNodes("//Task") }

                    foreach ($task in $tasks) {
                        $taskName = $task.name
                        if (-not $taskName) { $taskName = $task.Properties.name }
                        $runAs = $task.Properties.runAs
                        if (-not $runAs) {
                            $principal = $task.SelectSingleNode(".//Principal/UserId")
                            if ($principal) { $runAs = $principal.InnerText }
                        }
                        $execNode = $task.SelectSingleNode(".//Exec")
                        $command = ""; $arguments = ""
                        if ($execNode) { $command = $execNode.Command; $arguments = $execNode.Arguments }

                        $isSystem = $runAs -match "SYSTEM|LocalSystem|S-1-5-18"
                        if ($isSystem) {
                            $risk = $GPORiskDatabase["ScheduledTaskGPO"]
                            $cmdDisplay = if ($arguments) { "$command $arguments" } else { $command }
                            $Findings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                                -Finding "GPO '$($gpo.DisplayName)' deploys Scheduled Task '$taskName' running as SYSTEM" `
                                -CurrentState "Task: $taskName | RunAs: $runAs | Command: $cmdDisplay" `
                                -ExpectedState "Do not run SYSTEM tasks from writable shares. Use least-privilege and signed scripts" `
                                -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                                -GPOName $gpo.DisplayName -GPOGUID $gpo.Id))

                            # Check if share is writable
                            $referencesShare = ($arguments -match "\\\\") -or ($command -match "\\\\")
                            if ($referencesShare) {
                                $uncMatch = [regex]::Match("$command $arguments", '(\\\\[^\s"]+)')
                                if ($uncMatch.Success) {
                                    $uncPath = $uncMatch.Groups[1].Value
                                    $shareParts = $uncPath -split '\\'
                                    if ($shareParts.Count -ge 4) {
                                        $shareRoot = "\\$($shareParts[2])\$($shareParts[3])"
                                        $isWritable = $false
                                        try {
                                            $testFile = "$shareRoot\__ak_test_$(Get-Random).tmp"
                                            [System.IO.File]::WriteAllText($testFile, "test")
                                            Remove-Item $testFile -Force -ErrorAction SilentlyContinue
                                            $isWritable = $true
                                        } catch {}
                                        if ($isWritable) {
                                            $Findings.Add((Write-Finding -Category "Persistence" -Severity "CRITICAL" `
                                                -Finding "Script share '$shareRoot' referenced by SYSTEM task is WRITABLE by current user" `
                                                -CurrentState "Share: $shareRoot is writable. Any domain user can replace the script" `
                                                -ExpectedState "Share should be read-only for non-admins" `
                                                -WhyBad "Writable share + SYSTEM execution = any domain user gets SYSTEM on all targeted machines." `
                                                -GPOName $gpo.DisplayName -GPOGUID $gpo.Id))
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch {
                    Write-Warning "  Could not parse ScheduledTasks.xml in '$($gpo.DisplayName)': $_"
                }
            }
        }
    }

    # ================================================================
    # 7g: Unlinked GPOs
    # ================================================================
    Write-Status "  Checking for unlinked GPOs..."

    foreach ($gpo in $AllGPOs) {
        try {
            [xml]$report = Get-GPOReport -Name $gpo.DisplayName -ReportType XML -ErrorAction Stop
            if (-not $report.GPO.LinksTo) {
                $Findings.Add((Write-Finding -Category "GPO Hygiene" -Severity "INFO" `
                    -Finding "UNLINKED GPO: '$($gpo.DisplayName)' is not linked anywhere" `
                    -CurrentState "GPO exists but has no links. May be orphaned or staged" `
                    -ExpectedState "Delete if unused. If staging, document in GPO comment" `
                    -GPOName $gpo.DisplayName -GPOGUID $gpo.Id))
            }
        } catch {}
    }

    $Findings
}
