#Requires -Modules ActiveDirectory, GroupPolicy
<#
.SYNOPSIS
    BadderBlood GPO Companion - Deploys deliberately misconfigured Group Policy Objects
.DESCRIPTION
    Creates 18-20 insecure/misconfigured GPOs linked at the domain level to complement
    BadderBlood's user/group/ACL misconfigurations. Designed for lab environments where
    students practice identifying and remediating AD security issues.

    GPO categories created:
      - Weak authentication & password policies
      - Disabled security controls (firewall, UAC, SMB signing)
      - Dangerous privilege assignments (User Rights)
      - Insecure protocol enablement (WDigest, LLMNR, NetBIOS)
      - Audit policy suppression
      - Credential exposure vectors
      - Lateral movement enablers
      - LAPS misconfiguration (overpermissioned OU ACL backdoor)
      - GPO persistence via writable scheduled task scripts
      - GPO permission delegation to BadderBlood users

    MUST be run AFTER BadderBlood has populated the domain with users/groups.

.PARAMETER SkipLinking
    Creates GPOs but does not link them to the domain (for testing).

.PARAMETER IncludeDecoyGPOs
    Adds 2-3 harmless but suspiciously-named GPOs as red herrings.

.EXAMPLE
    .\Invoke-BadderBloodGPO.ps1
    .\Invoke-BadderBloodGPO.ps1 -IncludeDecoyGPOs

.NOTES
    Run on a Domain Controller as Domain Admin.
    Run AFTER BadderBlood has completed.
    Requires: ActiveDirectory and GroupPolicy PowerShell modules.
#>

[CmdletBinding()]
param(
    [switch]$SkipLinking,
    [switch]$IncludeDecoyGPOs
)

# ============================================================================
# PREFLIGHT CHECKS
# ============================================================================

Write-Host @"
===============================================================================
   BadderBlood GPO Companion - Insecure GPO Deployment
   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
===============================================================================
"@ -ForegroundColor Yellow

# Verify modules
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction Stop
} catch {
    Write-Error "Required modules not available. Run on a DC with RSAT installed."
    exit 1
}

$DomainInfo = Get-ADDomain
$DomainDN = $DomainInfo.DistinguishedName
$DomainDNS = $DomainInfo.DNSRoot
$DomainNetBIOS = $DomainInfo.NetBIOSName

Write-Host "[*] Domain: $DomainDNS" -ForegroundColor Cyan
Write-Host "[*] Domain DN: $DomainDN" -ForegroundColor Cyan

# Verify BadderBlood has run - look for BadderBlood-created users/groups
# These patterns match what BadderBlood actually writes to Description fields.
# Original BadBlood patterns are also included for compatibility.
$BBDescPatterns = @(
    "*Created with BadderBlood*"
    "*Created by BadderBlood*"
    "*Service Account*Created by BadderBlood*"
    "*BadderBlood*"
    # Original BadBlood patterns (backwards compat)
    "*secframe.com/badblood*"
    "*Badblood github.com*"
    "*davidprowe/badblood*"
    "*Created with secframe*"
    "*User Group Created by Badblood*"
)
$SampleBBUsers = Get-ADUser -Filter * -Properties Description -ResultSetSize 20 | Where-Object {
    $desc = $_.Description
    ($BBDescPatterns | ForEach-Object { $desc -like $_ }) -contains $true
}

if (-not $SampleBBUsers) {
    Write-Warning "No BadderBlood-created users found. Run Invoke-BadderBlood.ps1 first!"
    Write-Warning "Continuing anyway, but GPO permission delegation will be skipped."
    $BadderBloodPresent = $false
} else {
    Write-Host "[*] BadderBlood users detected ($($SampleBBUsers.Count) sampled). Proceeding." -ForegroundColor Green
    $BadderBloodPresent = $true
}

# Collect BadderBlood users/groups for GPO permission delegation
$BBUsers = @()
$BBGroups = @()
if ($BadderBloodPresent) {
    $BBUsers = Get-ADUser -Filter * -Properties Description, SamAccountName | Where-Object {
        $desc = $_.Description
        ($BBDescPatterns | ForEach-Object { $desc -like $_ }) -contains $true
    } | Select-Object -First 50

    $BBGroups = Get-ADGroup -Filter * -Properties Description | Where-Object {
        $desc = $_.Description
        ($BBDescPatterns | ForEach-Object { $desc -like $_ }) -contains $true
    } | Select-Object -First 20
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function New-InsecureGPO {
    param(
        [string]$Name,
        [string]$Comment,
        [switch]$LinkToDomain
    )

    # Check if GPO already exists
    $existing = Get-GPO -Name $Name -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  [!] GPO '$Name' already exists, skipping creation." -ForegroundColor Yellow
        return $existing
    }

    $gpo = New-GPO -Name $Name -Comment $Comment
    Write-Host "  [+] Created GPO: $Name" -ForegroundColor Green

    if ($LinkToDomain -and -not $SkipLinking) {
        New-GPLink -Name $Name -Target $DomainDN -LinkEnabled Yes -ErrorAction SilentlyContinue | Out-Null
        Write-Host "    -> Linked to domain root" -ForegroundColor Gray
    }

    return $gpo
}

function Set-GPORegistryValue {
    param(
        [string]$GPOName,
        [string]$Key,
        [string]$ValueName,
        [string]$Type,
        $Value
    )
    try {
        Set-GPRegistryValue -Name $GPOName -Key $Key -ValueName $ValueName -Type $Type -Value $Value -ErrorAction Stop | Out-Null
    } catch {
        Write-Warning "    Failed to set $Key\$ValueName on '$GPOName': $_"
    }
}

$CreatedGPOs = [System.Collections.Generic.List[PSObject]]::new()

# ============================================================================
# GPO 1: WEAK PASSWORD POLICY
# ============================================================================
Write-Host "`n[*] Creating GPO 1: Weak Password Policy..." -ForegroundColor Cyan

$gpo1 = New-InsecureGPO -Name "IT-PasswordPolicy-Standard" `
    -Comment "Standard password policy for domain users" -LinkToDomain

# Password policy via Security Template (GptTmpl.inf)
# We need to write directly to SYSVOL for security settings
$gpo1Path = "\\$DomainDNS\SYSVOL\$DomainDNS\Policies\{$($gpo1.Id)}"
$machPath = "$gpo1Path\Machine\Microsoft\Windows NT\SecEdit"
$sysvolTimeout = 30
$sysvolElapsed = 0
while (-not (Test-Path $gpo1Path) -and $sysvolElapsed -lt $sysvolTimeout) {
    Start-Sleep -Seconds 1
    $sysvolElapsed++
}
[System.IO.Directory]::CreateDirectory($machPath) | Out-Null

$pwPolicyInf = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 0
MaximumPasswordAge = 0
MinimumPasswordLength = 4
PasswordComplexity = 0
PasswordHistorySize = 0
LockoutBadCount = 0
ClearTextPassword = 0
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
[System.IO.File]::WriteAllText("$machPath\GptTmpl.inf", $pwPolicyInf, [System.Text.Encoding]::Unicode)

# Update GPO version counter so clients know to re-process
Set-GPRegistryValue -Name "IT-PasswordPolicy-Standard" -Key "HKLM\Software\Policies\BadderBloodGPO" -ValueName "Marker1" -Type String -Value "deployed" -ErrorAction SilentlyContinue | Out-Null

$CreatedGPOs.Add([PSCustomObject]@{
    Name = "IT-PasswordPolicy-Standard"
    GUID = $gpo1.Id
    Category = "Weak Password Policy"
    Severity = "CRITICAL"
    Issue = "Min length 4, no complexity, no lockout, passwords never expire, no history"
    Fix = "Set min length 14+, enable complexity, max age 90 days, lockout after 5 attempts, history 24"
})

# ============================================================================
# GPO 2: DISABLE WINDOWS FIREWALL
# ============================================================================
Write-Host "[*] Creating GPO 2: Disable Windows Firewall..." -ForegroundColor Cyan

$gpo2 = New-InsecureGPO -Name "NET-Firewall-Exceptions" `
    -Comment "Network team firewall exceptions for application compatibility" -LinkToDomain

# Disable all three firewall profiles
Set-GPORegistryValue -GPOName "NET-Firewall-Exceptions" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" `
    -ValueName "EnableFirewall" -Type DWord -Value 0

Set-GPORegistryValue -GPOName "NET-Firewall-Exceptions" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" `
    -ValueName "EnableFirewall" -Type DWord -Value 0

Set-GPORegistryValue -GPOName "NET-Firewall-Exceptions" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" `
    -ValueName "EnableFirewall" -Type DWord -Value 0

$CreatedGPOs.Add([PSCustomObject]@{
    Name = "NET-Firewall-Exceptions"
    GUID = $gpo2.Id
    Category = "Disabled Security Control"
    Severity = "CRITICAL"
    Issue = "Windows Firewall disabled on all profiles (Domain, Private, Public)"
    Fix = "Enable firewall on all profiles. Configure specific exceptions via firewall rules, not by disabling entirely"
})

# ============================================================================
# GPO 3: DISABLE UAC
# ============================================================================
Write-Host "[*] Creating GPO 3: Disable UAC..." -ForegroundColor Cyan

$gpo3 = New-InsecureGPO -Name "APP-Compatibility-UAC" `
    -Comment "Application compatibility - UAC adjustments per vendor recommendation" -LinkToDomain

Set-GPORegistryValue -GPOName "APP-Compatibility-UAC" `
    -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "EnableLUA" -Type DWord -Value 0

Set-GPORegistryValue -GPOName "APP-Compatibility-UAC" `
    -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "ConsentPromptBehaviorAdmin" -Type DWord -Value 0

Set-GPORegistryValue -GPOName "APP-Compatibility-UAC" `
    -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "FilterAdministratorToken" -Type DWord -Value 0

$CreatedGPOs.Add([PSCustomObject]@{
    Name = "APP-Compatibility-UAC"
    GUID = $gpo3.Id
    Category = "Disabled Security Control"
    Severity = "HIGH"
    Issue = "UAC completely disabled. Admin approval mode off. FilterAdministratorToken off"
    Fix = "Enable UAC (EnableLUA=1), set ConsentPromptBehaviorAdmin=2 (consent for non-Windows), enable FilterAdministratorToken"
})

# ============================================================================
# GPO 4: ENABLE WDIGEST (PLAINTEXT CREDS IN MEMORY)
# ============================================================================
Write-Host "[*] Creating GPO 4: Enable WDigest..." -ForegroundColor Cyan

$gpo4 = New-InsecureGPO -Name "SEC-Authentication-Legacy" `
    -Comment "Legacy application authentication support" -LinkToDomain

Set-GPORegistryValue -GPOName "SEC-Authentication-Legacy" `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -ValueName "UseLogonCredential" -Type DWord -Value 1

$CreatedGPOs.Add([PSCustomObject]@{
    Name = "SEC-Authentication-Legacy"
    GUID = $gpo4.Id
    Category = "Credential Exposure"
    Severity = "CRITICAL"
    Issue = "WDigest authentication enabled - plaintext passwords stored in LSASS memory. Mimikatz can dump them"
    Fix = "Set UseLogonCredential to 0. Migrate legacy apps away from WDigest/HTTP Digest authentication"
})

# ============================================================================
# GPO 5: DISABLE SMB SIGNING
# ============================================================================
Write-Host "[*] Creating GPO 5: Disable SMB Signing..." -ForegroundColor Cyan

$gpo5 = New-InsecureGPO -Name "NET-SMBPerformance-Tuning" `
    -Comment "SMB performance optimization per storage vendor guidance" -LinkToDomain

Set-GPORegistryValue -GPOName "NET-SMBPerformance-Tuning" `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -ValueName "RequireSecuritySignature" -Type DWord -Value 0

Set-GPORegistryValue -GPOName "NET-SMBPerformance-Tuning" `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -ValueName "EnableSecuritySignature" -Type DWord -Value 0

Set-GPORegistryValue -GPOName "NET-SMBPerformance-Tuning" `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters" `
    -ValueName "RequireSecuritySignature" -Type DWord -Value 0

Set-GPORegistryValue -GPOName "NET-SMBPerformance-Tuning" `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters" `
    -ValueName "EnableSecuritySignature" -Type DWord -Value 0

$CreatedGPOs.Add([PSCustomObject]@{
    Name = "NET-SMBPerformance-Tuning"
    GUID = $gpo5.Id
    Category = "Lateral Movement Enabler"
    Severity = "CRITICAL"
    Issue = "SMB signing disabled on both server and client. Enables NTLM relay attacks (ntlmrelayx)"
    Fix = "RequireSecuritySignature = 1 on both LanmanServer and LanManWorkstation"
})

# ============================================================================
# GPO 6: ENABLE LLMNR AND NETBIOS
# ============================================================================
Write-Host "[*] Creating GPO 6: Enable LLMNR/NetBIOS..." -ForegroundColor Cyan

$gpo6 = New-InsecureGPO -Name "NET-NameResolution-Compat" `
    -Comment "Name resolution compatibility for legacy devices" -LinkToDomain

# Explicitly enforce LLMNR enabled (1 = enabled; without this key, Windows defaults to enabled,
# but setting it explicitly prevents a remediation GPO from disabling it via the same key)
Set-GPORegistryValue -GPOName "NET-NameResolution-Compat" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -ValueName "EnableMulticast" -Type DWord -Value 1

# Disable DNS devolution safeguards
Set-GPORegistryValue -GPOName "NET-NameResolution-Compat" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -ValueName "UseDomainNameDevolution" -Type DWord -Value 1

$CreatedGPOs.Add([PSCustomObject]@{
    Name = "NET-NameResolution-Compat"
    GUID = $gpo6.Id
    Category = "Credential Exposure"
    Severity = "HIGH"
    Issue = "LLMNR explicitly enabled. Allows Responder/Inveigh to capture NTLMv2 hashes on the network"
    Fix = "Disable LLMNR (EnableMulticast=0). Disable NetBIOS over TCP/IP via DHCP options. Use DNS only"
})

# ============================================================================
# GPO 7: ALLOW NTLMV1 AUTHENTICATION
# ============================================================================
Write-Host "[*] Creating GPO 7: Allow NTLMv1..." -ForegroundColor Cyan

$gpo7 = New-InsecureGPO -Name "SEC-NTLM-Compatibility" `
    -Comment "NTLM compatibility for legacy printer/scanner integration" -LinkToDomain

# LAN Manager authentication level: Send LM & NTLM (least secure)
Set-GPORegistryValue -GPOName "SEC-NTLM-Compatibility" `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "LmCompatibilityLevel" -Type DWord -Value 0

$CreatedGPOs.Add([PSCustomObject]@{
    Name = "SEC-NTLM-Compatibility"
    GUID = $gpo7.Id
    Category = "Weak Authentication"
    Severity = "CRITICAL"
    Issue = "LM compatibility set to 0 (Send LM & NTLM). LM hashes are trivially crackable"
    Fix = "Set LmCompatibilityLevel to 5 (Send NTLMv2 only, refuse LM & NTLM)"
})

# ============================================================================
# GPO 8: DISABLE WINDOWS DEFENDER / ANTIMALWARE
# ============================================================================
Write-Host "[*] Creating GPO 8: Disable Defender..." -ForegroundColor Cyan

$gpo8 = New-InsecureGPO -Name "APP-Antivirus-Exclusions" `
    -Comment "Antivirus policy - third party AV coordination" -LinkToDomain

Set-GPORegistryValue -GPOName "APP-Antivirus-Exclusions" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" `
    -ValueName "DisableAntiSpyware" -Type DWord -Value 1

Set-GPORegistryValue -GPOName "APP-Antivirus-Exclusions" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -ValueName "DisableRealtimeMonitoring" -Type DWord -Value 1

Set-GPORegistryValue -GPOName "APP-Antivirus-Exclusions" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -ValueName "DisableBehaviorMonitoring" -Type DWord -Value 1

$CreatedGPOs.Add([PSCustomObject]@{
    Name = "APP-Antivirus-Exclusions"
    GUID = $gpo8.Id
    Category = "Disabled Security Control"
    Severity = "CRITICAL"
    Issue = "Windows Defender completely disabled via GPO. No real-time or behavior monitoring"
    Fix = "Remove GPO or set all values to 0. If using third-party AV, it should be verified as active first"
})

# ============================================================================
# GPO 9: DISABLE POWERSHELL LOGGING
# ============================================================================
Write-Host "[*] Creating GPO 9: Disable PowerShell Logging..." -ForegroundColor Cyan

$gpo9 = New-InsecureGPO -Name "IT-PowerShell-Config" `
    -Comment "PowerShell enterprise configuration" -LinkToDomain

# Disable Script Block Logging
Set-GPORegistryValue -GPOName "IT-PowerShell-Config" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -ValueName "EnableScriptBlockLogging" -Type DWord -Value 0

# Disable Module Logging
Set-GPORegistryValue -GPOName "IT-PowerShell-Config" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -ValueName "EnableModuleLogging" -Type DWord -Value 0

# Disable Transcription
Set-GPORegistryValue -GPOName "IT-PowerShell-Config" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -ValueName "EnableTranscripting" -Type DWord -Value 0

# Allow PowerShell v2 (bypass AMSI)
Set-GPORegistryValue -GPOName "IT-PowerShell-Config" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" `
    -ValueName "EnableScripts" -Type DWord -Value 1

$CreatedGPOs.Add([PSCustomObject]@{
    Name = "IT-PowerShell-Config"
    GUID = $gpo9.Id
    Category = "Audit/Logging Suppression"
    Severity = "HIGH"
    Issue = "All PowerShell logging disabled (ScriptBlock, Module, Transcription). Attackers can run scripts undetected"
    Fix = "Enable ScriptBlockLogging, ModuleLogging (log all modules: *), and Transcription to a secured share"
})

# ============================================================================
# GPO 10: ALLOW CREDENTIAL CACHING (HIGH COUNT)
# ============================================================================
Write-Host "[*] Creating GPO 10: Excessive Credential Caching..." -ForegroundColor Cyan

$gpo10 = New-InsecureGPO -Name "IT-OfflineLogon-Policy" `
    -Comment "Offline logon support for traveling users" -LinkToDomain

Set-GPORegistryValue -GPOName "IT-OfflineLogon-Policy" `
    -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
    -ValueName "CachedLogonsCount" -Type String -Value "50"

$CreatedGPOs.Add([PSCustomObject]@{
    Name = "IT-OfflineLogon-Policy"
    GUID = $gpo10.Id
    Category = "Credential Exposure"
    Severity = "MEDIUM"
    Issue = "50 cached credentials stored locally. Default is 10, best practice is 1-2. More cached creds = more targets for offline cracking"
    Fix = "Set CachedLogonsCount to 1 or 2 maximum"
})

# ============================================================================
# GPO 11: ENABLE REMOTE DESKTOP WITH WEAK SETTINGS
# ============================================================================
Write-Host "[*] Creating GPO 11: Insecure Remote Desktop..." -ForegroundColor Cyan

$gpo11 = New-InsecureGPO -Name "IT-RemoteAccess-Standard" `
    -Comment "Standard remote access configuration" -LinkToDomain

# Enable RDP
Set-GPORegistryValue -GPOName "IT-RemoteAccess-Standard" `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" `
    -ValueName "fDenyTSConnections" -Type DWord -Value 0

# Disable NLA (Network Level Authentication)
Set-GPORegistryValue -GPOName "IT-RemoteAccess-Standard" `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -ValueName "UserAuthentication" -Type DWord -Value 0

# Set minimum encryption to Low
Set-GPORegistryValue -GPOName "IT-RemoteAccess-Standard" `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -ValueName "MinEncryptionLevel" -Type DWord -Value 1

$CreatedGPOs.Add([PSCustomObject]@{
    Name = "IT-RemoteAccess-Standard"
    GUID = $gpo11.Id
    Category = "Lateral Movement Enabler"
    Severity = "HIGH"
    Issue = "RDP enabled with NLA disabled and minimum encryption. Allows brute force without authentication, enables MITM"
    Fix = "Enable NLA (UserAuthentication=1), set MinEncryptionLevel=3 (High), restrict via firewall rules and RDP gateway"
})

# ============================================================================
# GPO 12: AUTORUN / AUTOPLAY ENABLED
# ============================================================================
Write-Host "[*] Creating GPO 12: Enable AutoRun..." -ForegroundColor Cyan

$gpo12 = New-InsecureGPO -Name "IT-MediaPolicy-Standard" `
    -Comment "Media handling policy" -LinkToDomain

Set-GPORegistryValue -GPOName "IT-MediaPolicy-Standard" `
    -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -ValueName "NoDriveTypeAutoRun" -Type DWord -Value 0

Set-GPORegistryValue -GPOName "IT-MediaPolicy-Standard" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
    -ValueName "NoAutoplayfornonVolume" -Type DWord -Value 0

$CreatedGPOs.Add([PSCustomObject]@{
    Name = "IT-MediaPolicy-Standard"
    GUID = $gpo12.Id
    Category = "Malware Vector"
    Severity = "MEDIUM"
    Issue = "AutoRun/AutoPlay enabled for all drive types. USB-based malware executes automatically on insertion"
    Fix = "Set NoDriveTypeAutoRun to 255 (disable all). Set NoAutoplayfornonVolume to 1"
})

# ============================================================================
# GPO 13: DISABLE CREDENTIAL GUARD / LSASS PROTECTION
# ============================================================================
Write-Host "[*] Creating GPO 13: Disable Credential Guard..." -ForegroundColor Cyan

$gpo13 = New-InsecureGPO -Name "SEC-CredentialProtection-Config" `
    -Comment "Credential protection configuration - compatibility mode" -LinkToDomain

# Disable Credential Guard
Set-GPORegistryValue -GPOName "SEC-CredentialProtection-Config" `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
    -ValueName "EnableVirtualizationBasedSecurity" -Type DWord -Value 0

# Disable LSA Protection (RunAsPPL)
Set-GPORegistryValue -GPOName "SEC-CredentialProtection-Config" `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "RunAsPPL" -Type DWord -Value 0

$CreatedGPOs.Add([PSCustomObject]@{
    Name = "SEC-CredentialProtection-Config"
    GUID = $gpo13.Id
    Category = "Credential Exposure"
    Severity = "HIGH"
    Issue = "Credential Guard and LSA Protection (RunAsPPL) both disabled. LSASS is unprotected from Mimikatz-style attacks"
    Fix = "Enable VBS (EnableVirtualizationBasedSecurity=1), enable RunAsPPL=1. Test for app compat first"
})

# ============================================================================
# GPO 14: ALLOW ANONYMOUS ENUMERATION
# ============================================================================
Write-Host "[*] Creating GPO 14: Allow Anonymous Enumeration..." -ForegroundColor Cyan

$gpo14 = New-InsecureGPO -Name "NET-AnonymousAccess-Legacy" `
    -Comment "Anonymous access for legacy monitoring appliances" -LinkToDomain

# Allow anonymous SID/Name translation
Set-GPORegistryValue -GPOName "NET-AnonymousAccess-Legacy" `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "RestrictAnonymousSAM" -Type DWord -Value 0

Set-GPORegistryValue -GPOName "NET-AnonymousAccess-Legacy" `
    -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -ValueName "RestrictAnonymous" -Type DWord -Value 0

# Allow null session shares
Set-GPORegistryValue -GPOName "NET-AnonymousAccess-Legacy" `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -ValueName "RestrictNullSessAccess" -Type DWord -Value 0

$CreatedGPOs.Add([PSCustomObject]@{
    Name = "NET-AnonymousAccess-Legacy"
    GUID = $gpo14.Id
    Category = "Information Disclosure"
    Severity = "HIGH"
    Issue = "Anonymous enumeration of SAM accounts and shares allowed. Null sessions permitted. Attackers can enumerate all users without credentials"
    Fix = "RestrictAnonymousSAM=1, RestrictAnonymous=1, RestrictNullSessAccess=1"
})

# ============================================================================
# GPO 15: INSECURE WINRM CONFIGURATION
# ============================================================================
Write-Host "[*] Creating GPO 15: Insecure WinRM..." -ForegroundColor Cyan

$gpo15 = New-InsecureGPO -Name "IT-WinRM-Management" `
    -Comment "WinRM remote management standard" -LinkToDomain

# Allow unencrypted WinRM traffic
Set-GPORegistryValue -GPOName "IT-WinRM-Management" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
    -ValueName "AllowUnencryptedTraffic" -Type DWord -Value 1

# Allow Basic authentication (sends creds in Base64/cleartext)
Set-GPORegistryValue -GPOName "IT-WinRM-Management" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
    -ValueName "AllowBasic" -Type DWord -Value 1

# Client side too
Set-GPORegistryValue -GPOName "IT-WinRM-Management" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
    -ValueName "AllowUnencryptedTraffic" -Type DWord -Value 1

Set-GPORegistryValue -GPOName "IT-WinRM-Management" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
    -ValueName "AllowBasic" -Type DWord -Value 1

$CreatedGPOs.Add([PSCustomObject]@{
    Name = "IT-WinRM-Management"
    GUID = $gpo15.Id
    Category = "Credential Exposure"
    Severity = "HIGH"
    Issue = "WinRM allows unencrypted traffic and Basic authentication. Credentials sent in cleartext over the network"
    Fix = "AllowUnencryptedTraffic=0, AllowBasic=0 on both service and client. Use Kerberos or CredSSP with HTTPS"
})

# ============================================================================
# GPO 16: DISABLE EVENT LOG / REDUCE LOG SIZE
# ============================================================================
Write-Host "[*] Creating GPO 16: Cripple Event Logging..." -ForegroundColor Cyan

$gpo16 = New-InsecureGPO -Name "IT-EventLog-Retention" `
    -Comment "Event log storage management - disk space conservation" -LinkToDomain

# Tiny Security log (64KB - fills in minutes on active system)
Set-GPORegistryValue -GPOName "IT-EventLog-Retention" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" `
    -ValueName "MaxSize" -Type DWord -Value 64

# Overwrite events as needed
Set-GPORegistryValue -GPOName "IT-EventLog-Retention" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" `
    -ValueName "Retention" -Type String -Value "0"

# Tiny System log
Set-GPORegistryValue -GPOName "IT-EventLog-Retention" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" `
    -ValueName "MaxSize" -Type DWord -Value 64

# Tiny PowerShell log
Set-GPORegistryValue -GPOName "IT-EventLog-Retention" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Windows PowerShell" `
    -ValueName "MaxSize" -Type DWord -Value 64

$CreatedGPOs.Add([PSCustomObject]@{
    Name = "IT-EventLog-Retention"
    GUID = $gpo16.Id
    Category = "Audit/Logging Suppression"
    Severity = "HIGH"
    Issue = "Security, System, and PowerShell event logs set to 64KB with overwrite. Evidence destroyed within minutes of an incident"
    Fix = "Set Security log to at least 1GB (1048576 KB), System to 256MB. Forward logs to SIEM. Retention = archive, not overwrite"
})

# ============================================================================
# GPO 17: STORED PASSWORDS IN GPO PREFERENCES (SIMULATED)
# ============================================================================
Write-Host "[*] Creating GPO 17: Simulated GPP Password..." -ForegroundColor Cyan

$gpo17 = New-InsecureGPO -Name "IT-LocalAdmin-Deploy" `
    -Comment "Local administrator account standardization" -LinkToDomain

# We simulate the classic MS14-025 GPP password vulnerability by writing a
# Groups.xml to SYSVOL with a cpassword field. The AES key is public
# (Microsoft published it in MSDN), so any domain user can decrypt it.
$gpo17Path = "\\$DomainDNS\SYSVOL\$DomainDNS\Policies\{$($gpo17.Id)}"
$prefPath = "$gpo17Path\Machine\Preferences\Groups"
$sysvolTimeout = 30
$sysvolElapsed = 0
while (-not (Test-Path $gpo17Path) -and $sysvolElapsed -lt $sysvolTimeout) {
    Start-Sleep -Seconds 1
    $sysvolElapsed++
}
[System.IO.Directory]::CreateDirectory($prefPath) | Out-Null

# This is the classic cpassword value - AES-256 encrypted with the publicly-known
# Microsoft key. Decrypts to "P@ssw0rd123!" using gpp-decrypt or Get-GPPPassword
$groupsXml = @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="LocalAdmin"
        image="2" changed="2024-06-15 09:30:00" uid="{B1C7F4A2-3D5E-4F8A-9B2C-1A2B3C4D5E6F}"
        userContext="0" removePolicy="0">
    <Properties action="U" newName="" fullName="Lab Local Admin" description="Managed local admin"
                cpassword="RI133B2zMcVbXCFdLTmH+VK+okDyRHeJqfHlCDeBJwg"
                changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0"
                userName="LocalAdmin"/>
  </User>
</Groups>
"@
[System.IO.File]::WriteAllText("$prefPath\Groups.xml", $groupsXml, [System.Text.Encoding]::UTF8)

$CreatedGPOs.Add([PSCustomObject]@{
    Name = "IT-LocalAdmin-Deploy"
    GUID = $gpo17.Id
    Category = "Credential Exposure"
    Severity = "CRITICAL"
    Issue = "GPO Preferences contains a cpassword (MS14-025). Any domain user can read SYSVOL and decrypt it with gpp-decrypt"
    Fix = "Delete the GPO or remove Groups.xml. Use LAPS for local admin password management. Never deploy passwords via GPP"
})

# ============================================================================
# GPO 18: DISABLE LDAP SIGNING
# ============================================================================
Write-Host "[*] Creating GPO 18: Disable LDAP Signing..." -ForegroundColor Cyan

$gpo18 = New-InsecureGPO -Name "NET-LDAP-Compatibility" `
    -Comment "LDAP compatibility for legacy directory-integrated applications" -LinkToDomain

# LDAP server signing requirement: None
Set-GPORegistryValue -GPOName "NET-LDAP-Compatibility" `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    -ValueName "LDAPServerIntegrity" -Type DWord -Value 0

# LDAP client signing: Not required
Set-GPORegistryValue -GPOName "NET-LDAP-Compatibility" `
    -Key "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" `
    -ValueName "LDAPClientIntegrity" -Type DWord -Value 0

$CreatedGPOs.Add([PSCustomObject]@{
    Name = "NET-LDAP-Compatibility"
    GUID = $gpo18.Id
    Category = "Lateral Movement Enabler"
    Severity = "HIGH"
    Issue = "LDAP signing not required for server or client. Enables LDAP relay attacks and MITM of LDAP traffic"
    Fix = "LDAPServerIntegrity=2 (Require signing), LDAPClientIntegrity=1 (Negotiate signing). Test app compat, then enforce"
})

# ============================================================================
# GPO 19: LAPS BACKDOOR - OVERPERMISSIONED LAPS DEPLOYMENT
# ============================================================================
Write-Host "[*] Creating GPO 19: LAPS Backdoor..." -ForegroundColor Cyan

# Check if LAPS schema is present (ms-Mcs-AdmPwd attribute exists)
$LAPSSchemaPresent = $false
try {
    $schemaPath = "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,$DomainDN"
    $null = Get-ADObject -Identity $schemaPath -ErrorAction Stop
    $LAPSSchemaPresent = $true
    Write-Host "    LAPS schema (legacy ms-Mcs-AdmPwd) detected." -ForegroundColor Gray
} catch {
    Write-Host "    Legacy LAPS schema not found, checking Windows LAPS..." -ForegroundColor Gray
}

# Also check for Windows LAPS (2023+) schema attribute
$WinLAPSPresent = $false
if (-not $LAPSSchemaPresent) {
    try {
        $schemaPath = "CN=ms-LAPS-Password,CN=Schema,CN=Configuration,$DomainDN"
        $null = Get-ADObject -Identity $schemaPath -ErrorAction Stop
        $WinLAPSPresent = $true
        Write-Host "    Windows LAPS schema (ms-LAPS-Password) detected." -ForegroundColor Gray
    } catch {
        Write-Host "    No LAPS schema found. Installing schema extension..." -ForegroundColor Gray
    }
}

# If no LAPS schema exists, we simulate by creating the OU structure and
# the GPO that would be misconfigured in a real LAPS deployment.
# The vulnerability here is the ACL on the OU, not the schema itself.

$gpo19 = New-InsecureGPO -Name "SEC-LAPS-Deployment" `
    -Comment "LAPS deployment - local admin password rotation" -LinkToDomain

# Create a target OU for "LAPS-managed workstations" if it doesn't exist
$LAPSTargetOU = "OU=LAPS-ManagedWorkstations,$DomainDN"
try {
    Get-ADOrganizationalUnit -Identity $LAPSTargetOU -ErrorAction Stop | Out-Null
    Write-Host "    OU '$LAPSTargetOU' already exists." -ForegroundColor Gray
} catch {
    New-ADOrganizationalUnit -Name "LAPS-ManagedWorkstations" -Path $DomainDN `
        -Description "Workstations managed by LAPS - local admin passwords rotated via GPO" `
        -ProtectedFromAccidentalDeletion $false
    Write-Host "    [+] Created OU: LAPS-ManagedWorkstations" -ForegroundColor Green
}

# Link this GPO to the LAPS OU as well (in addition to domain if linked there)
if (-not $SkipLinking) {
    New-GPLink -Name "SEC-LAPS-Deployment" -Target $LAPSTargetOU -LinkEnabled Yes -ErrorAction SilentlyContinue | Out-Null
    Write-Host "    -> Linked to $LAPSTargetOU" -ForegroundColor Gray
}

# Configure LAPS-like settings via registry
if ($LAPSSchemaPresent) {
    # Legacy LAPS CSE settings
    Set-GPORegistryValue -GPOName "SEC-LAPS-Deployment" `
        -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" `
        -ValueName "AdmPwdEnabled" -Type DWord -Value 1

    Set-GPORegistryValue -GPOName "SEC-LAPS-Deployment" `
        -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" `
        -ValueName "PwdExpirationProtectionEnabled" -Type DWord -Value 0

    # Weak password settings for LAPS-managed password
    Set-GPORegistryValue -GPOName "SEC-LAPS-Deployment" `
        -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" `
        -ValueName "PasswordLength" -Type DWord -Value 8

    Set-GPORegistryValue -GPOName "SEC-LAPS-Deployment" `
        -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" `
        -ValueName "PasswordComplexity" -Type DWord -Value 1

    Set-GPORegistryValue -GPOName "SEC-LAPS-Deployment" `
        -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" `
        -ValueName "PasswordAgeDays" -Type DWord -Value 365
} elseif ($WinLAPSPresent) {
    # Windows LAPS settings
    Set-GPORegistryValue -GPOName "SEC-LAPS-Deployment" `
        -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config" `
        -ValueName "BackupDirectory" -Type DWord -Value 2

    Set-GPORegistryValue -GPOName "SEC-LAPS-Deployment" `
        -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config" `
        -ValueName "PasswordLength" -Type DWord -Value 8

    Set-GPORegistryValue -GPOName "SEC-LAPS-Deployment" `
        -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config" `
        -ValueName "PasswordAgeDays" -Type DWord -Value 365
} else {
    # No LAPS schema at all - deploy settings that would activate if LAPS were installed
    # This is still a finding because the ACL misconfiguration exists regardless
    Set-GPORegistryValue -GPOName "SEC-LAPS-Deployment" `
        -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" `
        -ValueName "AdmPwdEnabled" -Type DWord -Value 1

    Set-GPORegistryValue -GPOName "SEC-LAPS-Deployment" `
        -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" `
        -ValueName "PasswordLength" -Type DWord -Value 8
}

# *** THE ACTUAL VULNERABILITY: Grant Domain Users ExtendedRights on the OU ***
# In a proper LAPS deployment, only helpdesk/admin groups should be able to read
# ms-Mcs-AdmPwd. Granting "Domain Users" means ANY authenticated user can read
# every LAPS-managed local admin password in the OU.

try {
    $DomainUsersGroup = Get-ADGroup "Domain Users"
    $LAPSOU = Get-ADOrganizationalUnit -Identity $LAPSTargetOU

    # Get the OU's ACL
    $OUPath = "AD:\$LAPSTargetOU"
    $acl = Get-Acl $OUPath

    # Build the ACE: ExtendedRight (All) for Domain Users
    # This grants read access to ALL confidential attributes, including ms-Mcs-AdmPwd
    $DomainUsersSID = $DomainUsersGroup.SID
    $ExtendedRightGUID = [GUID]"00000000-0000-0000-0000-000000000000"  # All extended rights
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents

    # Computer object GUID for inheritance filter
    $ComputerSchemaGUID = [GUID]"bf967a86-0de6-11d0-a285-00aa003049e2"

    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $DomainUsersSID,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $ExtendedRightGUID,
        $InheritanceType,
        $ComputerSchemaGUID
    )

    $acl.AddAccessRule($ace)
    Set-Acl -Path $OUPath -AclObject $acl

    Write-Host "    [+] BACKDOOR: Granted 'Domain Users' ExtendedRight (All) on $LAPSTargetOU" -ForegroundColor Yellow
    Write-Host "         -> ANY domain user can now read LAPS passwords in this OU" -ForegroundColor Yellow

    # Also grant GenericRead for good measure (makes enumeration trivial)
    $readAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $DomainUsersSID,
        [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $ExtendedRightGUID,
        $InheritanceType,
        $ComputerSchemaGUID
    )
    $acl.AddAccessRule($readAce)
    Set-Acl -Path $OUPath -AclObject $acl

} catch {
    Write-Warning "  Failed to set LAPS OU permissions: $_"
    Write-Warning "  The GPO was created but the ACL backdoor may not be in place."
}

$lapsIssue = if ($LAPSSchemaPresent -or $WinLAPSPresent) {
    "LAPS deployed but 'Domain Users' has ExtendedRight (All) on target OU. ANY user can read local admin passwords. Password policy also weak (length 8, 365-day rotation)"
} else {
    "LAPS-style GPO with 'Domain Users' granted ExtendedRight (All) on target OU. If LAPS is installed, any user can read all local admin passwords. Even without LAPS, the overpermissioned OU ACL is a finding"
}

$CreatedGPOs.Add([PSCustomObject]@{
    Name = "SEC-LAPS-Deployment"
    GUID = $gpo19.Id
    Category = "LAPS Misconfiguration"
    Severity = "CRITICAL"
    Issue = $lapsIssue
    Fix = "Remove 'Domain Users' ExtendedRight from OU. Grant ms-Mcs-AdmPwd read only to designated admin/helpdesk groups. Increase password length to 20+, reduce rotation to 30 days"
})

# ============================================================================
# GPO 20: MALICIOUS SCHEDULED TASK - GPO PERSISTENCE VECTOR
# ============================================================================
Write-Host "[*] Creating GPO 20: Malicious Scheduled Task..." -ForegroundColor Cyan

$gpo20 = New-InsecureGPO -Name "IT-Maintenance-Tasks" `
    -Comment "Automated maintenance scripts - weekly system health checks" -LinkToDomain

# Step 1: Create the share and script on the DC
# The share will be writable by Domain Users (the vulnerability)
$SharePath = "C:\ITScripts"
$ScriptName = "Invoke-SystemHealthCheck.ps1"

if (-not (Test-Path $SharePath)) {
    New-Item -ItemType Directory -Path $SharePath -Force | Out-Null
    Write-Host "    [+] Created directory: $SharePath" -ForegroundColor Green
}

# Create a benign-looking maintenance script
$MaintenanceScript = @'
#=============================================================
# Invoke-SystemHealthCheck.ps1
# Automated system health check - runs weekly via GPO
# IT Operations - Do not modify without change control approval
#=============================================================

$LogPath = "C:\Windows\Temp\HealthCheck_$(Get-Date -Format 'yyyyMMdd').log"

# Collect basic health metrics
$disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" |
    Select-Object @{N='FreeGB';E={[math]::Round($_.FreeSpace/1GB,2)}}

$uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

$services = Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -ne 'Running'} |
    Select-Object Name, Status

$logEntry = @"
=== System Health Check - $(Get-Date) ===
Hostname:    $env:COMPUTERNAME
Free Disk:   $($disk.FreeGB) GB
Uptime:      $($uptime.Days) days, $($uptime.Hours) hours
Stopped Auto Services: $($services.Count)
$(if($services){$services | Format-Table -AutoSize | Out-String})
"@

$logEntry | Out-File -FilePath $LogPath -Append
'@

$MaintenanceScript | Out-File -FilePath "$SharePath\$ScriptName" -Encoding UTF8
Write-Host "    [+] Created script: $SharePath\$ScriptName" -ForegroundColor Green

# Step 2: Create the SMB share with WEAK permissions
# THIS IS THE VULNERABILITY: Domain Users get Change (Write) access
try {
    # Remove existing share if present
    $existingShare = Get-SmbShare -Name "ITScripts" -ErrorAction SilentlyContinue
    if ($existingShare) {
        Remove-SmbShare -Name "ITScripts" -Force -ErrorAction SilentlyContinue
    }

    New-SmbShare -Name "ITScripts" -Path $SharePath `
        -Description "IT Operations maintenance scripts (GPO-deployed)" `
        -FullAccess "Everyone" -ErrorAction Stop | Out-Null

    Write-Host "    [+] Created share: \\$env:COMPUTERNAME\ITScripts (Everyone=FullAccess)" -ForegroundColor Green

    # Set NTFS permissions: Domain Users get Modify
    $acl = Get-Acl $SharePath
    $DomainUsersSID = (Get-ADGroup "Domain Users").SID
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $DomainUsersSID,
        "Modify",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.AddAccessRule($rule)
    Set-Acl -Path $SharePath -AclObject $acl

    Write-Host "    [+] NTFS: 'Domain Users' has Modify on $SharePath" -ForegroundColor Yellow
    Write-Host "         -> ANY domain user can replace the maintenance script" -ForegroundColor Yellow

} catch {
    Write-Warning "  Failed to create SMB share: $_"
    Write-Warning "  Falling back to NTFS permissions only..."

    # At minimum set NTFS even if share creation fails
    try {
        $acl = Get-Acl $SharePath
        $DomainUsersSID = (Get-ADGroup "Domain Users").SID
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $DomainUsersSID, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.AddAccessRule($rule)
        Set-Acl -Path $SharePath -AclObject $acl
    } catch {
        Write-Warning "  Also failed to set NTFS permissions: $_"
    }
}

# Step 3: Deploy the Scheduled Task via GPO using ScheduledTasks.xml in SYSVOL
# This creates an Immediate Scheduled Task that runs as SYSTEM
$gpo20Path = "\\$DomainDNS\SYSVOL\$DomainDNS\Policies\{$($gpo20.Id)}"
$taskPrefPath = "$gpo20Path\Machine\Preferences\ScheduledTasks"
$sysvolTimeout = 30
$sysvolElapsed = 0
while (-not (Test-Path $gpo20Path) -and $sysvolElapsed -lt $sysvolTimeout) {
    Start-Sleep -Seconds 1
    $sysvolElapsed++
}
[System.IO.Directory]::CreateDirectory($taskPrefPath) | Out-Null

# Generate unique task GUID
$taskGuid = [GUID]::NewGuid().ToString("B").ToUpper()
$changedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$dcHostname = $env:COMPUTERNAME

$scheduledTaskXml = @"
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-AB94-2D6A11F4DC76}">
  <TaskV2 clsid="{D8896631-B747-47a7-84A6-C155337F3BC8}" name="IT-SystemHealthCheck"
          image="0" changed="$changedDate" uid="$taskGuid"
          userContext="0" removePolicy="0">
    <Properties action="C" name="IT-SystemHealthCheck" runAs="NT AUTHORITY\SYSTEM"
                logonType="S4U">
      <Task version="1.2">
        <RegistrationInfo>
          <Author>$DomainNetBIOS\Administrator</Author>
          <Description>Weekly system health check - IT Operations. Runs maintenance script from central repository.</Description>
        </RegistrationInfo>
        <Principals>
          <Principal id="Author">
            <UserId>NT AUTHORITY\SYSTEM</UserId>
            <LogonType>S4U</LogonType>
            <RunLevel>HighestAvailable</RunLevel>
          </Principal>
        </Principals>
        <Settings>
          <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
          <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
          <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
          <AllowHardTerminate>true</AllowHardTerminate>
          <StartWhenAvailable>true</StartWhenAvailable>
          <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
          <AllowStartOnDemand>true</AllowStartOnDemand>
          <Enabled>true</Enabled>
          <Hidden>false</Hidden>
          <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
          <Priority>7</Priority>
        </Settings>
        <Triggers>
          <CalendarTrigger>
            <StartBoundary>2024-01-01T02:00:00</StartBoundary>
            <Enabled>true</Enabled>
            <ScheduleByWeek>
              <DaysOfWeek><Sunday/></DaysOfWeek>
              <WeeksInterval>1</WeeksInterval>
            </ScheduleByWeek>
          </CalendarTrigger>
          <BootTrigger>
            <Enabled>true</Enabled>
            <Delay>PT5M</Delay>
          </BootTrigger>
        </Triggers>
        <Actions>
          <Exec>
            <Command>powershell.exe</Command>
            <Arguments>-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File "\\$dcHostname\ITScripts\$ScriptName"</Arguments>
          </Exec>
        </Actions>
      </Task>
    </Properties>
  </TaskV2>
</ScheduledTasks>
"@

[System.IO.File]::WriteAllText("$taskPrefPath\ScheduledTasks.xml", $scheduledTaskXml, [System.Text.Encoding]::UTF8)
Write-Host "    [+] Deployed ScheduledTasks.xml to SYSVOL" -ForegroundColor Green
Write-Host "    [+] Task: 'IT-SystemHealthCheck' runs as SYSTEM every Sunday + at boot" -ForegroundColor Green
Write-Host "    [+] Executes: \\$dcHostname\ITScripts\$ScriptName" -ForegroundColor Green
Write-Host "    [!] ATTACK: Any domain user can replace the script -> code execution as SYSTEM on all targets" -ForegroundColor Yellow

$CreatedGPOs.Add([PSCustomObject]@{
    Name = "IT-Maintenance-Tasks"
    GUID = $gpo20.Id
    Category = "GPO Persistence / Code Execution"
    Severity = "CRITICAL"
    Issue = "GPO deploys a Scheduled Task running as SYSTEM that executes \\$dcHostname\ITScripts\$ScriptName. The share and NTFS permissions grant 'Domain Users' write access. Any user can replace the script to get SYSTEM execution on every domain computer at next boot or weekly run"
    Fix = "1) Remove 'Domain Users' write from share AND NTFS ACL on $SharePath. 2) Grant only IT admin read to the share. 3) Remove Scheduled Task from GPO or point to a properly secured path. 4) Consider code signing for deployed scripts"
})

# ============================================================================
# GPO PERMISSION DELEGATION TO BADBLOOD OBJECTS
# ============================================================================
if ($BadderBloodPresent -and $BBUsers.Count -ge 5) {
    Write-Host "`n[*] Delegating GPO edit permissions to random BadderBlood users..." -ForegroundColor Cyan

    # Pick 3-5 random BadderBlood users to grant GPO edit rights to random GPOs
    $DelegationTargets = $BBUsers | Get-Random -Count ([Math]::Min(5, $BBUsers.Count))
    $GPOsToDelegate = $CreatedGPOs | Get-Random -Count ([Math]::Min(5, $CreatedGPOs.Count))

    foreach ($i in 0..([Math]::Min($DelegationTargets.Count, $GPOsToDelegate.Count) - 1)) {
        $targetUser = $DelegationTargets[$i]
        $targetGPO = $GPOsToDelegate[$i]
        try {
            Set-GPPermission -Name $targetGPO.Name -TargetName $targetUser.SamAccountName `
                -TargetType User -PermissionLevel GpoEditDeleteModifySecurity -ErrorAction Stop
            Write-Host "  [+] Granted GpoEditDeleteModifySecurity on '$($targetGPO.Name)' to '$($targetUser.SamAccountName)'" -ForegroundColor Yellow
        } catch {
            Write-Warning "  Failed to delegate on '$($targetGPO.Name)' to '$($targetUser.SamAccountName)': $_"
        }
    }

    # Also grant a couple BadderBlood groups
    if ($BBGroups.Count -ge 2) {
        $GroupDelegates = $BBGroups | Get-Random -Count 2
        $GPOsForGroups = $CreatedGPOs | Get-Random -Count 2
        foreach ($i in 0..1) {
            try {
                Set-GPPermission -Name $GPOsForGroups[$i].Name -TargetName $GroupDelegates[$i].SamAccountName `
                    -TargetType Group -PermissionLevel GpoEdit -ErrorAction Stop
                Write-Host "  [+] Granted GpoEdit on '$($GPOsForGroups[$i].Name)' to group '$($GroupDelegates[$i].SamAccountName)'" -ForegroundColor Yellow
            } catch {
                Write-Warning "  Failed to delegate on '$($GPOsForGroups[$i].Name)' to group '$($GroupDelegates[$i].SamAccountName)': $_"
            }
        }
    }
}

# ============================================================================
# DECOY GPOs (Optional - harmless but suspicious-looking)
# ============================================================================
if ($IncludeDecoyGPOs) {
    Write-Host "`n[*] Creating decoy GPOs (harmless red herrings)..." -ForegroundColor Cyan

    # Decoy 1: Suspicious name but actually just sets wallpaper
    $decoy1 = New-InsecureGPO -Name "SEC-EmergencyAccess-Override" `
        -Comment "Emergency access policy override" -LinkToDomain
    Set-GPORegistryValue -GPOName "SEC-EmergencyAccess-Override" `
        -Key "HKCU\Control Panel\Desktop" `
        -ValueName "WallPaper" -Type String -Value ""

    # Decoy 2: Sounds scary but just sets timezone
    $decoy2 = New-InsecureGPO -Name "IT-AdminBackdoor-Cleanup" `
        -Comment "Scheduled cleanup task configuration" -LinkToDomain

    # Decoy 3: Unlinked GPO that does nothing
    $decoy3 = New-InsecureGPO -Name "YOURORGANIZATION-TempPolicy-DELETE" `
        -Comment "Temporary policy - to be deleted after migration Q4 2024"
    # Deliberately NOT linked

    Write-Host "  [+] Created 3 decoy GPOs (2 linked, 1 unlinked)" -ForegroundColor Gray
}

# ============================================================================
# EXPORT MANIFEST
# ============================================================================
$manifestPath = "$PSScriptRoot\BadderBloodGPO_Manifest_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$CreatedGPOs | Export-Csv -Path $manifestPath -NoTypeInformation
Write-Host "`n[*] GPO manifest saved: $manifestPath" -ForegroundColor Green

# ============================================================================
# SUMMARY
# ============================================================================
Write-Host ""
Write-Host "=" * 80 -ForegroundColor Yellow
Write-Host "  BADBLOOD GPO COMPANION - DEPLOYMENT COMPLETE" -ForegroundColor Green
Write-Host "=" * 80 -ForegroundColor Yellow
Write-Host ""
Write-Host "  GPOs Created: $($CreatedGPOs.Count)" -ForegroundColor White
Write-Host "  Domain Links: $(if($SkipLinking){'SKIPPED'}else{'YES - all linked to domain root'})" -ForegroundColor White
Write-Host ""
Write-Host "  SEVERITY BREAKDOWN:" -ForegroundColor White
Write-Host "    CRITICAL: $(($CreatedGPOs | Where-Object Severity -eq 'CRITICAL').Count)" -ForegroundColor Red
Write-Host "    HIGH:     $(($CreatedGPOs | Where-Object Severity -eq 'HIGH').Count)" -ForegroundColor DarkYellow
Write-Host "    MEDIUM:   $(($CreatedGPOs | Where-Object Severity -eq 'MEDIUM').Count)" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Run BadderBloodAnswerKey.ps1 -IncludeGPOAnalysis to add these to the answer key." -ForegroundColor Cyan
Write-Host "  Or run BadderBloodGPO_AnswerKey.ps1 for a standalone GPO audit." -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Yellow
