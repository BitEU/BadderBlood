#Requires -Modules ActiveDirectory, GroupPolicy
<#
.SYNOPSIS
    BadBlood GPO Answer Key - Audits GPO misconfigurations deployed by Invoke-BadBloodGPO.ps1
.DESCRIPTION
    Scans all domain GPOs for common security misconfigurations and generates a detailed
    answer key matching the format of BadBloodAnswerKey.ps1. Reports include:
      - Every insecure setting found (what's wrong)
      - WHY it's a problem (attack scenario / security principle)
      - Severity ratings
      - Expected clean state (what students should fix)
      - GPO permission delegation issues

    Can run standalone or alongside the main BadBloodAnswerKey.ps1 report.

.PARAMETER OutputPath
    Directory for report output. Defaults to timestamped folder.
.PARAMETER ExportCSVs
    Also export findings as CSV files for easy filtering.
.PARAMETER Quiet
    Suppress progress output.

.EXAMPLE
    .\BadBloodGPO_AnswerKey.ps1
    .\BadBloodGPO_AnswerKey.ps1 -OutputPath "C:\AnswerKeys\GPO" -ExportCSVs
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\BadBloodGPO_AnswerKey_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch]$ExportCSVs,
    [switch]$Quiet
)

# ============================================================================
# SECURITY KNOWLEDGE BASE - GPO Misconfigurations
# ============================================================================

$GPORiskDatabase = @{

    # --- PASSWORD POLICY ---
    "WeakMinLength" = @{
        Category = "Weak Password Policy"
        Severity = "CRITICAL"
        Why = "Short passwords are trivially brute-forced. A 4-character password cracks in seconds with Hashcat."
        Attack = "Dump hashes via DCSync/NTDS.dit -> brute-force short passwords -> instant compromise of affected accounts."
        Principle = "Minimum 14 characters per Microsoft/NIST guidance. Length > complexity."
        Fix = "Set Minimum Password Length to 14+ characters."
    }
    "NoComplexity" = @{
        Category = "Weak Password Policy"
        Severity = "HIGH"
        Why = "Without complexity, users choose passwords like 'password' or '123456'. Trivially guessable."
        Attack = "Password spraying with top-1000 passwords. No complexity = most users pick dictionary words."
        Principle = "Enable complexity OR enforce long passphrases (14+). Both together is ideal."
        Fix = "Enable Password Complexity Requirements."
    }
    "NoMaxAge" = @{
        Category = "Weak Password Policy"
        Severity = "MEDIUM"
        Why = "Compromised passwords remain valid forever. No rotation = permanent attacker access."
        Attack = "Obtain hash from old breach -> password never expires -> permanent access until manually reset."
        Principle = "Max age 90-365 days. Balance security with usability. Use breach detection instead of frequent rotation."
        Fix = "Set Maximum Password Age to 90-365 days."
    }
    "NoLockout" = @{
        Category = "Weak Password Policy"
        Severity = "HIGH"
        Why = "No account lockout allows unlimited brute-force attempts against accounts."
        Attack = "Spray passwords forever with no lockout risk. Eventually crack weak passwords."
        Principle = "Lock after 5-10 failed attempts. 15-30 min lockout duration."
        Fix = "Set Account Lockout Threshold to 5-10 attempts."
    }
    "NoHistory" = @{
        Category = "Weak Password Policy"
        Severity = "MEDIUM"
        Why = "Users can immediately reuse their old password when forced to change. Password rotation becomes meaningless."
        Attack = "If password is compromised and changed, user can change it right back -> attacker retains access."
        Principle = "Remember at least 24 passwords to prevent reuse."
        Fix = "Set Enforce Password History to 24."
    }

    # --- DISABLED SECURITY CONTROLS ---
    "FirewallDisabled" = @{
        Category = "Disabled Security Control"
        Severity = "CRITICAL"
        Why = "No host-based firewall = any service is exposed. Worms and lateral movement tools have unrestricted network access."
        Attack = "WannaCry-style worm -> no firewall -> spreads to every machine instantly. EternalBlue, PetitPotam, etc."
        Principle = "Enable on ALL profiles. Use firewall rules for specific exceptions, never disable entirely."
        Fix = "Enable Windows Firewall on Domain, Private, and Public profiles."
    }
    "UACDisabled" = @{
        Category = "Disabled Security Control"
        Severity = "HIGH"
        Why = "UAC is the last barrier preventing malware running as a standard user from escalating to admin. Without it, any process inherits full admin rights."
        Attack = "Phishing -> malware runs -> no UAC prompt -> instant admin -> game over."
        Principle = "EnableLUA=1, ConsentPromptBehaviorAdmin=2 (consent for non-Windows binaries), FilterAdministratorToken=1."
        Fix = "Re-enable UAC: EnableLUA=1, ConsentPromptBehaviorAdmin=2, FilterAdministratorToken=1."
    }
    "DefenderDisabled" = @{
        Category = "Disabled Security Control"
        Severity = "CRITICAL"
        Why = "No antimalware = no detection of known threats, no behavior monitoring, no AMSI scanning of scripts."
        Attack = "Drop any known malware binary -> executes without detection. Mimikatz, Cobalt Strike, etc."
        Principle = "Always have active AV/EDR. If using third-party, verify it's running before disabling Defender."
        Fix = "Remove DisableAntiSpyware, DisableRealtimeMonitoring, DisableBehaviorMonitoring GPO settings."
    }

    # --- CREDENTIAL EXPOSURE ---
    "WDigestEnabled" = @{
        Category = "Credential Exposure"
        Severity = "CRITICAL"
        Why = "Stores plaintext passwords in LSASS memory. Any process with SeDebugPrivilege can dump them. Mimikatz 'sekurlsa::wdigest' extracts them trivially."
        Attack = "Get admin on one box -> Mimikatz -> plaintext passwords of all logged-in users -> lateral movement."
        Principle = "WDigest should be DISABLED (UseLogonCredential=0) on all modern Windows (8.1+/2012R2+)."
        Fix = "Set HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential to 0."
    }
    "LLMNREnabled" = @{
        Category = "Credential Exposure"
        Severity = "HIGH"
        Why = "LLMNR broadcasts name queries to the local subnet. Any machine can respond claiming to be the target, capturing NTLMv2 hashes."
        Attack = "Run Responder/Inveigh on network -> capture NTLMv2 hashes passively -> crack offline with Hashcat."
        Principle = "Disable LLMNR (EnableMulticast=0) and NetBIOS over TCP/IP. Use DNS exclusively."
        Fix = "Set EnableMulticast to 0 via GPO."
    }
    "NTLMv1Allowed" = @{
        Category = "Weak Authentication"
        Severity = "CRITICAL"
        Why = "LM/NTLMv1 hashes are cryptographically weak. NTLMv1 can be cracked in minutes. LM hashes in seconds."
        Attack = "MITM or Responder -> capture LM/NTLMv1 -> crack instantly -> plaintext password."
        Principle = "LmCompatibilityLevel=5: Send NTLMv2 only, refuse LM & NTLM. Test app compat, then enforce."
        Fix = "Set LmCompatibilityLevel to 5."
    }
    "ExcessiveCachedCreds" = @{
        Category = "Credential Exposure"
        Severity = "MEDIUM"
        Why = "Cached credentials are stored as DCC2 hashes. 50 cached entries = 50 targets for offline cracking on a stolen laptop."
        Attack = "Steal laptop -> extract DCC2 hashes for 50 accounts -> crack with Hashcat (slow but possible for weak passwords)."
        Principle = "CachedLogonsCount should be 1-2 max. Reduces exposure window on lost/stolen devices."
        Fix = "Set CachedLogonsCount to 1 or 2."
    }
    "CredGuardDisabled" = @{
        Category = "Credential Exposure"
        Severity = "HIGH"
        Why = "Without Credential Guard, LSASS runs in normal memory. Mimikatz and similar tools can dump all credentials. Without RunAsPPL, any admin process can read LSASS."
        Attack = "Admin on a box -> procdump lsass.exe -> extract hashes, tickets, plaintext creds offline."
        Principle = "Enable VBS + Credential Guard on supported hardware. Enable RunAsPPL as a minimum."
        Fix = "Set EnableVirtualizationBasedSecurity=1 and RunAsPPL=1."
    }
    "GPPPassword" = @{
        Category = "Credential Exposure"
        Severity = "CRITICAL"
        Why = "GPO Preferences passwords (cpassword) are encrypted with a publicly known AES key. Microsoft published the key in MSDN. ANY domain user can read SYSVOL and decrypt it instantly."
        Attack = "Any domain user -> dir \\domain\SYSVOL\...\Groups.xml -> gpp-decrypt / Get-GPPPassword -> plaintext password."
        Principle = "NEVER store passwords in GPO Preferences. Use LAPS for local admin passwords. Delete any Groups.xml with cpassword."
        Fix = "Delete the GPO or remove Groups.xml. Deploy LAPS for local admin management."
    }

    # --- LATERAL MOVEMENT ---
    "SMBSigningDisabled" = @{
        Category = "Lateral Movement Enabler"
        Severity = "CRITICAL"
        Why = "Without SMB signing, NTLM relay attacks are trivial. An attacker can relay captured authentication to any SMB service."
        Attack = "Responder captures auth -> ntlmrelayx relays to target without signing -> code execution as victim user."
        Principle = "RequireSecuritySignature=1 on both server (LanmanServer) and client (LanManWorkstation)."
        Fix = "Set RequireSecuritySignature=1 on both LanmanServer and LanManWorkstation."
    }
    "InsecureRDP" = @{
        Category = "Lateral Movement Enabler"
        Severity = "HIGH"
        Why = "RDP without NLA allows attackers to reach the login screen (and exploit pre-auth vulns like BlueKeep) without any credentials. Low encryption enables MITM."
        Attack = "BlueKeep/RCE pre-auth exploit -> no NLA means attacker reaches vulnerable code. Or MITM RDP session to capture creds."
        Principle = "Enable NLA, use High encryption, restrict access via firewall rules and RDP Gateway."
        Fix = "Set UserAuthentication=1 (NLA), MinEncryptionLevel=3 (High)."
    }
    "LDAPSigningDisabled" = @{
        Category = "Lateral Movement Enabler"
        Severity = "HIGH"
        Why = "Without LDAP signing, LDAP relay attacks allow attackers to modify AD objects. Can grant themselves privileges or create accounts."
        Attack = "MITM LDAP traffic -> inject modifications -> add attacker to Domain Admins or create backdoor account."
        Principle = "LDAPServerIntegrity=2 (Require), LDAPClientIntegrity=1 (Negotiate). Enforce channel binding."
        Fix = "Set LDAPServerIntegrity=2, LDAPClientIntegrity=1."
    }
    "InsecureWinRM" = @{
        Category = "Credential Exposure"
        Severity = "HIGH"
        Why = "WinRM with unencrypted traffic and Basic auth sends credentials in cleartext (Base64) over HTTP. Any network sniffer captures them."
        Attack = "Wireshark/tcpdump on network -> capture WinRM Basic auth -> Base64 decode -> plaintext credentials."
        Principle = "AllowUnencryptedTraffic=0, AllowBasic=0. Use Kerberos auth over HTTPS."
        Fix = "Disable unencrypted traffic and Basic auth on both WinRM service and client."
    }

    # --- INFORMATION DISCLOSURE ---
    "AnonymousEnumeration" = @{
        Category = "Information Disclosure"
        Severity = "HIGH"
        Why = "Anonymous/null session access allows unauthenticated enumeration of all users, groups, shares. Gives attackers a complete target list without any credentials."
        Attack = "enum4linux / rpcclient with null session -> full user/group listing -> targeted attacks."
        Principle = "RestrictAnonymousSAM=1, RestrictAnonymous=1, RestrictNullSessAccess=1."
        Fix = "Enable all RestrictAnonymous settings."
    }

    # --- LOGGING / AUDIT ---
    "PSLoggingDisabled" = @{
        Category = "Audit/Logging Suppression"
        Severity = "HIGH"
        Why = "Without PowerShell logging, attacker scripts leave no evidence. ScriptBlock logging catches obfuscated code. Module logging tracks cmdlet usage. Transcription provides full session recording."
        Attack = "Run Invoke-Mimikatz, PowerView, etc. -> no Script Block log -> no evidence in event logs -> invisible attack."
        Principle = "Enable ScriptBlockLogging, ModuleLogging (all modules: *), Transcription to a secured share."
        Fix = "Enable all three: ScriptBlockLogging=1, ModuleLogging=1, Transcription=1."
    }
    "EventLogCrippled" = @{
        Category = "Audit/Logging Suppression"
        Severity = "HIGH"
        Why = "A 64KB Security log fills in minutes on any active system. Evidence of attacks is overwritten before anyone can review it."
        Attack = "Attack occurs -> generate noise -> tiny log overwrites attack evidence within minutes -> forensic dead end."
        Principle = "Security log at least 1GB, System 256MB+. Forward to SIEM for retention. Archive, don't overwrite."
        Fix = "Set Security log to 1048576 KB (1 GB), System/PowerShell to at least 262144 KB (256 MB)."
    }

    # --- MALWARE VECTORS ---
    "AutoRunEnabled" = @{
        Category = "Malware Vector"
        Severity = "MEDIUM"
        Why = "AutoRun executes code from removable media automatically on insertion. Classic USB worm vector (Conficker, Stuxnet initial delivery)."
        Attack = "Drop USB in parking lot -> employee plugs in -> AutoRun executes malware -> initial access."
        Principle = "NoDriveTypeAutoRun=255 (disable all types). NoAutoplayfornonVolume=1."
        Fix = "Set NoDriveTypeAutoRun to 255 and NoAutoplayfornonVolume to 1."
    }

    # --- GPO DELEGATION ---
    "GPODelegation" = @{
        Category = "Excessive GPO Permissions"
        Severity = "HIGH"
        Why = "Non-admin users with GpoEdit/GpoEditDeleteModifySecurity can modify any setting in that GPO. Since GPOs apply to many machines, one GPO edit = code execution across the domain."
        Attack = "Compromise delegated user -> edit GPO to add malicious startup script -> every machine in scope runs attacker code at next gpupdate."
        Principle = "GPO edit rights should only be held by dedicated admin accounts. Review and remove non-admin GPO editors."
        Fix = "Remove non-admin users/groups from GPO permissions. Use dedicated GPO admin accounts."
    }

    # --- LAPS MISCONFIGURATION ---
    "LAPSBackdoor" = @{
        Category = "LAPS Misconfiguration"
        Severity = "CRITICAL"
        Why = "LAPS stores randomized local admin passwords in AD attributes (ms-Mcs-AdmPwd or ms-LAPS-Password). If 'Domain Users' has ExtendedRight on the OU, ANY authenticated user can read every local admin password - defeating the entire purpose of LAPS."
        Attack = "Any domain user -> Get-ADComputer -SearchBase <OU> -Properties ms-Mcs-AdmPwd -> plaintext local admin password -> lateral movement to every workstation."
        Principle = "LAPS password read rights should only be granted to specific admin/helpdesk groups via Set-AdmPwdReadPasswordPermission. Audit OU ACLs with Find-AdmPwdExtendedRights."
        Fix = "Remove 'Domain Users' ExtendedRight ACE from the OU. Grant ms-Mcs-AdmPwd read to dedicated helpdesk/admin groups only. Increase password length to 20+, reduce rotation to 30 days."
    }
    "LAPSWeakPolicy" = @{
        Category = "LAPS Misconfiguration"
        Severity = "MEDIUM"
        Why = "Short LAPS passwords (8 chars) with long rotation (365 days) reduce the security benefit. If a LAPS password is exposed, it remains valid for a year."
        Attack = "Shoulder-surf or screenshot local admin password -> valid for 365 days -> persistent local admin on that machine."
        Principle = "LAPS passwords should be 20+ characters, rotated every 30 days maximum."
        Fix = "Set PasswordLength to 20+, PasswordAgeDays to 30, PasswordComplexity to 4 (large letters + small letters + numbers + specials)."
    }

    # --- GPO PERSISTENCE / SCHEDULED TASK ---
    "ScheduledTaskGPO" = @{
        Category = "GPO Persistence / Code Execution"
        Severity = "CRITICAL"
        Why = "A GPO-deployed Scheduled Task running as SYSTEM that pulls scripts from a network share is a classic persistence vector. If the share permissions allow writes by non-admins, any domain user can replace the script to achieve code execution as SYSTEM on every targeted machine."
        Attack = "Any domain user -> modify \\server\share\script.ps1 -> next scheduled run (or boot) -> executes as SYSTEM on all GPO-targeted machines -> domain-wide compromise."
        Principle = "Scripts referenced by Scheduled Tasks must be on shares writable only by admins. Consider code-signing enforcement. Never run GPO-deployed tasks as SYSTEM from writable shares."
        Fix = "1) Remove Domain Users write from both share AND NTFS ACLs. 2) Grant only designated admin accounts write access. 3) Consider removing the GPO scheduled task or pointing it to a properly secured location. 4) Implement script code signing."
    }
    "WritableScriptShare" = @{
        Category = "GPO Persistence / Code Execution"
        Severity = "CRITICAL"
        Why = "The network share hosting scripts executed by SYSTEM-level scheduled tasks is writable by Domain Users (both SMB and NTFS). This is effectively granting every domain user the ability to run arbitrary code as SYSTEM."
        Attack = "dir \\server\ITScripts -> confirm writable -> replace Invoke-SystemHealthCheck.ps1 with reverse shell -> wait for boot trigger or weekly schedule -> SYSTEM shell."
        Principle = "Shares hosting executable content must follow least privilege: read-only for consumers, write only for designated script maintainers."
        Fix = "Set share permissions to Read for Authenticated Users, Full Control only for a dedicated IT scripts admin group. Match at NTFS level."
    }
}

# ============================================================================
# HELPER FUNCTIONS (matching BadBloodAnswerKey.ps1 format)
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Color = "Cyan")
    if (-not $Quiet) { Write-Host "[*] $Message" -ForegroundColor $Color }
}

function Write-Finding {
    param(
        [string]$Category,
        [string]$Severity,
        [string]$Finding,
        [string]$CurrentState,
        [string]$ExpectedState,
        [string]$WhyBad = "",
        [string]$AttackScenario = "",
        [string]$Principle = "",
        [string]$GPOName = "",
        [string]$GPOGUID = ""
    )
    [PSCustomObject]@{
        Category       = $Category
        Severity       = $Severity
        Finding        = $Finding
        CurrentState   = $CurrentState
        ExpectedState  = $ExpectedState
        WhyBad         = $WhyBad
        AttackScenario = $AttackScenario
        Principle      = $Principle
        GPOName        = $GPOName
        GPOGUID        = $GPOGUID
    }
}

# ============================================================================
# SETUP
# ============================================================================

Write-Host @"
===============================================================================
   BadBlood GPO Answer Key Generator
   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
===============================================================================
"@ -ForegroundColor Yellow

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$DomainInfo = Get-ADDomain
$DomainDN   = $DomainInfo.DistinguishedName
$DomainDNS  = $DomainInfo.DNSRoot

Write-Status "Domain: $DomainDNS"

# Collect all GPOs
$AllGPOs = Get-GPO -All
Write-Status "Found $($AllGPOs.Count) GPOs in domain"

$AllFindings = [System.Collections.Generic.List[PSObject]]::new()

# Description patterns that identify BadBlood-created objects
$BadBloodDescPatterns = @(
    "*secframe.com/badblood*"
    "*Badblood github.com*"
    "*davidprowe/badblood*"
    "*Created with secframe*"
    "*User Group Created by Badblood*"
)

# ============================================================================
# SECTION 1: AUDIT GPO REGISTRY SETTINGS
# ============================================================================
Write-Status "Auditing GPO registry-based settings..."

foreach ($gpo in $AllGPOs) {
    $gpoName = $gpo.DisplayName
    $gpoGuid = $gpo.Id

    # Build SYSVOL path
    $regPolPath = "\\$DomainDNS\SYSVOL\$DomainDNS\Policies\{$gpoGuid}"

    # --- CHECK: Windows Firewall Disabled ---
    try {
        $fwDomain = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "EnableFirewall" -ErrorAction Stop
        if ($fwDomain.Value -eq 0) {
            $risk = $GPORiskDatabase["FirewallDisabled"]
            $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                -Finding "Windows Firewall DISABLED via GPO '$gpoName'" `
                -CurrentState "EnableFirewall = 0 (Domain/Private/Public profiles)" `
                -ExpectedState "EnableFirewall = 1 on all profiles" `
                -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                -GPOName $gpoName -GPOGUID $gpoGuid))
        }
    } catch { <# Key doesn't exist in this GPO - fine #> }

    # --- CHECK: UAC Disabled ---
    try {
        $uac = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableLUA" -ErrorAction Stop
        if ($uac.Value -eq 0) {
            $risk = $GPORiskDatabase["UACDisabled"]
            $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                -Finding "UAC DISABLED via GPO '$gpoName'" `
                -CurrentState "EnableLUA = 0 (UAC completely off)" `
                -ExpectedState "EnableLUA = 1, ConsentPromptBehaviorAdmin = 2, FilterAdministratorToken = 1" `
                -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                -GPOName $gpoName -GPOGUID $gpoGuid))
        }
    } catch {}

    # --- CHECK: WDigest Enabled ---
    try {
        $wd = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ValueName "UseLogonCredential" -ErrorAction Stop
        if ($wd.Value -eq 1) {
            $risk = $GPORiskDatabase["WDigestEnabled"]
            $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                -Finding "WDigest authentication ENABLED via GPO '$gpoName'" `
                -CurrentState "UseLogonCredential = 1 (plaintext passwords in LSASS)" `
                -ExpectedState "UseLogonCredential = 0" `
                -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                -GPOName $gpoName -GPOGUID $gpoGuid))
        }
    } catch {}

    # --- CHECK: SMB Signing Disabled ---
    try {
        $smb = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "RequireSecuritySignature" -ErrorAction Stop
        if ($smb.Value -eq 0) {
            $risk = $GPORiskDatabase["SMBSigningDisabled"]
            $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                -Finding "SMB Signing NOT REQUIRED via GPO '$gpoName'" `
                -CurrentState "RequireSecuritySignature = 0 (server and/or client)" `
                -ExpectedState "RequireSecuritySignature = 1 on both LanmanServer and LanManWorkstation" `
                -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                -GPOName $gpoName -GPOGUID $gpoGuid))
        }
    } catch {}

    # --- CHECK: LLMNR Enabled ---
    try {
        $llmnr = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -ErrorAction Stop
        if ($llmnr.Value -eq 1) {
            $risk = $GPORiskDatabase["LLMNREnabled"]
            $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                -Finding "LLMNR explicitly ENABLED via GPO '$gpoName'" `
                -CurrentState "EnableMulticast = 1 (LLMNR active)" `
                -ExpectedState "EnableMulticast = 0 (LLMNR disabled)" `
                -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                -GPOName $gpoName -GPOGUID $gpoGuid))
        }
    } catch {}

    # --- CHECK: NTLMv1 Allowed ---
    try {
        $ntlm = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "LmCompatibilityLevel" -ErrorAction Stop
        if ($ntlm.Value -lt 3) {
            $levelText = switch ($ntlm.Value) {
                0 { "Send LM & NTLM (worst)" }
                1 { "Send LM & NTLM - use NTLMv2 session security if negotiated" }
                2 { "Send NTLM only" }
            }
            $risk = $GPORiskDatabase["NTLMv1Allowed"]
            $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                -Finding "Weak NTLM authentication allowed via GPO '$gpoName'" `
                -CurrentState "LmCompatibilityLevel = $($ntlm.Value) ($levelText)" `
                -ExpectedState "LmCompatibilityLevel = 5 (Send NTLMv2 only, refuse LM & NTLM)" `
                -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                -GPOName $gpoName -GPOGUID $gpoGuid))
        }
    } catch {}

    # --- CHECK: Windows Defender Disabled ---
    try {
        $def = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" -ValueName "DisableAntiSpyware" -ErrorAction Stop
        if ($def.Value -eq 1) {
            $risk = $GPORiskDatabase["DefenderDisabled"]
            $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                -Finding "Windows Defender DISABLED via GPO '$gpoName'" `
                -CurrentState "DisableAntiSpyware = 1 (Defender off)" `
                -ExpectedState "Remove setting or set to 0. Verify active AV/EDR" `
                -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                -GPOName $gpoName -GPOGUID $gpoGuid))
        }
    } catch {}

    # --- CHECK: PowerShell Logging Disabled ---
    try {
        $psl = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ValueName "EnableScriptBlockLogging" -ErrorAction Stop
        if ($psl.Value -eq 0) {
            $risk = $GPORiskDatabase["PSLoggingDisabled"]
            $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                -Finding "PowerShell Script Block Logging DISABLED via GPO '$gpoName'" `
                -CurrentState "ScriptBlockLogging=0, ModuleLogging=0, Transcription=0" `
                -ExpectedState "All three enabled (ScriptBlockLogging=1, ModuleLogging=1, Transcription=1)" `
                -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                -GPOName $gpoName -GPOGUID $gpoGuid))
        }
    } catch {}

    # --- CHECK: Excessive Cached Credentials ---
    try {
        $cc = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "CachedLogonsCount" -ErrorAction Stop
        if ([int]$cc.Value -gt 10) {
            $risk = $GPORiskDatabase["ExcessiveCachedCreds"]
            $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                -Finding "Excessive cached credentials via GPO '$gpoName'" `
                -CurrentState "CachedLogonsCount = $($cc.Value)" `
                -ExpectedState "CachedLogonsCount = 1 or 2" `
                -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                -GPOName $gpoName -GPOGUID $gpoGuid))
        }
    } catch {}

    # --- CHECK: RDP without NLA ---
    try {
        $nla = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ValueName "UserAuthentication" -ErrorAction Stop
        if ($nla.Value -eq 0) {
            $risk = $GPORiskDatabase["InsecureRDP"]
            $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                -Finding "RDP enabled WITHOUT Network Level Authentication via GPO '$gpoName'" `
                -CurrentState "UserAuthentication = 0 (NLA disabled), MinEncryptionLevel = Low" `
                -ExpectedState "UserAuthentication = 1 (NLA required), MinEncryptionLevel = 3 (High)" `
                -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                -GPOName $gpoName -GPOGUID $gpoGuid))
        }
    } catch {}

    # --- CHECK: AutoRun Enabled ---
    try {
        $ar = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoDriveTypeAutoRun" -ErrorAction Stop
        if ($ar.Value -eq 0) {
            $risk = $GPORiskDatabase["AutoRunEnabled"]
            $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                -Finding "AutoRun/AutoPlay ENABLED for all drives via GPO '$gpoName'" `
                -CurrentState "NoDriveTypeAutoRun = 0 (AutoRun on all drive types)" `
                -ExpectedState "NoDriveTypeAutoRun = 255 (disabled for all)" `
                -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                -GPOName $gpoName -GPOGUID $gpoGuid))
        }
    } catch {}

    # --- CHECK: Credential Guard / LSA Protection Disabled ---
    try {
        $rpl = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "RunAsPPL" -ErrorAction Stop
        if ($rpl.Value -eq 0) {
            $risk = $GPORiskDatabase["CredGuardDisabled"]
            $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                -Finding "LSA Protection (RunAsPPL) DISABLED via GPO '$gpoName'" `
                -CurrentState "RunAsPPL = 0, VBS disabled" `
                -ExpectedState "RunAsPPL = 1, EnableVirtualizationBasedSecurity = 1" `
                -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                -GPOName $gpoName -GPOGUID $gpoGuid))
        }
    } catch {}

    # --- CHECK: Anonymous Enumeration ---
    try {
        $anon = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "RestrictAnonymousSAM" -ErrorAction Stop
        if ($anon.Value -eq 0) {
            $risk = $GPORiskDatabase["AnonymousEnumeration"]
            $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                -Finding "Anonymous SAM enumeration ALLOWED via GPO '$gpoName'" `
                -CurrentState "RestrictAnonymousSAM = 0, RestrictAnonymous = 0, RestrictNullSessAccess = 0" `
                -ExpectedState "All RestrictAnonymous* = 1" `
                -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                -GPOName $gpoName -GPOGUID $gpoGuid))
        }
    } catch {}

    # --- CHECK: WinRM Insecure ---
    try {
        $wrm = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowUnencryptedTraffic" -ErrorAction Stop
        if ($wrm.Value -eq 1) {
            $risk = $GPORiskDatabase["InsecureWinRM"]
            $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                -Finding "WinRM allows UNENCRYPTED traffic and Basic auth via GPO '$gpoName'" `
                -CurrentState "AllowUnencryptedTraffic = 1, AllowBasic = 1" `
                -ExpectedState "AllowUnencryptedTraffic = 0, AllowBasic = 0 (use Kerberos over HTTPS)" `
                -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                -GPOName $gpoName -GPOGUID $gpoGuid))
        }
    } catch {}

    # --- CHECK: Event Log Size Crippled ---
    try {
        $evtSec = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -ValueName "MaxSize" -ErrorAction Stop
        if ([int]$evtSec.Value -lt 1024) {
            $risk = $GPORiskDatabase["EventLogCrippled"]
            $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                -Finding "Security Event Log crippled to $($evtSec.Value) KB via GPO '$gpoName'" `
                -CurrentState "Security MaxSize = $($evtSec.Value) KB (fills in minutes)" `
                -ExpectedState "Security MaxSize = 1048576 KB (1 GB), forward to SIEM" `
                -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                -GPOName $gpoName -GPOGUID $gpoGuid))
        }
    } catch {}

    # --- CHECK: LDAP Signing Disabled ---
    try {
        $ldap = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -ValueName "LDAPServerIntegrity" -ErrorAction Stop
        if ($ldap.Value -eq 0) {
            $risk = $GPORiskDatabase["LDAPSigningDisabled"]
            $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                -Finding "LDAP signing NOT REQUIRED via GPO '$gpoName'" `
                -CurrentState "LDAPServerIntegrity = 0 (None)" `
                -ExpectedState "LDAPServerIntegrity = 2 (Require signing)" `
                -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                -GPOName $gpoName -GPOGUID $gpoGuid))
        }
    } catch {}
}

# ============================================================================
# SECTION 2: AUDIT PASSWORD POLICY (Security Templates in SYSVOL)
# ============================================================================
Write-Status "Auditing password policies in SYSVOL security templates..."

foreach ($gpo in $AllGPOs) {
    $infPath = "\\$DomainDNS\SYSVOL\$DomainDNS\Policies\{$($gpo.Id)}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
    if (Test-Path $infPath) {
        $content = Get-Content $infPath -Raw

        if ($content -match "MinimumPasswordLength\s*=\s*(\d+)") {
            $minLen = [int]$Matches[1]
            if ($minLen -lt 8) {
                $risk = $GPORiskDatabase["WeakMinLength"]
                $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "Minimum password length set to $minLen via GPO '$($gpo.DisplayName)'" `
                    -CurrentState "MinimumPasswordLength = $minLen" `
                    -ExpectedState "MinimumPasswordLength = 14+" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpo.DisplayName -GPOGUID $gpo.Id))
            }
        }

        if ($content -match "PasswordComplexity\s*=\s*(\d+)") {
            if ([int]$Matches[1] -eq 0) {
                $risk = $GPORiskDatabase["NoComplexity"]
                $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "Password complexity DISABLED via GPO '$($gpo.DisplayName)'" `
                    -CurrentState "PasswordComplexity = 0" `
                    -ExpectedState "PasswordComplexity = 1" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpo.DisplayName -GPOGUID $gpo.Id))
            }
        }

        if ($content -match "MaximumPasswordAge\s*=\s*(\d+)") {
            if ([int]$Matches[1] -eq 0) {
                $risk = $GPORiskDatabase["NoMaxAge"]
                $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "Passwords NEVER EXPIRE via GPO '$($gpo.DisplayName)'" `
                    -CurrentState "MaximumPasswordAge = 0 (never)" `
                    -ExpectedState "MaximumPasswordAge = 90-365 days" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpo.DisplayName -GPOGUID $gpo.Id))
            }
        }

        if ($content -match "LockoutBadCount\s*=\s*(\d+)") {
            if ([int]$Matches[1] -eq 0) {
                $risk = $GPORiskDatabase["NoLockout"]
                $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "Account lockout DISABLED via GPO '$($gpo.DisplayName)'" `
                    -CurrentState "LockoutBadCount = 0 (unlimited attempts)" `
                    -ExpectedState "LockoutBadCount = 5-10" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpo.DisplayName -GPOGUID $gpo.Id))
            }
        }

        if ($content -match "PasswordHistorySize\s*=\s*(\d+)") {
            if ([int]$Matches[1] -eq 0) {
                $risk = $GPORiskDatabase["NoHistory"]
                $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "Password history NOT ENFORCED via GPO '$($gpo.DisplayName)'" `
                    -CurrentState "PasswordHistorySize = 0" `
                    -ExpectedState "PasswordHistorySize = 24" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpo.DisplayName -GPOGUID $gpo.Id))
            }
        }
    }
}

# ============================================================================
# SECTION 3: AUDIT GPP PASSWORD FILES (MS14-025)
# ============================================================================
Write-Status "Scanning SYSVOL for GPP password files (MS14-025 / cpassword)..."

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
                        $relPath = $path -replace [regex]::Escape($SYSVOLPath), "SYSVOL\Policies"
                        $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                            -Finding "GPP PASSWORD (cpassword) found in '$($gpo.DisplayName)' at $gppFile" `
                            -CurrentState "File: $relPath contains cpassword attribute (decryptable by ANY domain user)" `
                            -ExpectedState "Delete file. Use LAPS for local admin passwords. Never store creds in GPP" `
                            -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                            -GPOName $gpo.DisplayName -GPOGUID $gpo.Id))
                    }
                }
            }
        }
    }
}

# ============================================================================
# SECTION 4: AUDIT GPO PERMISSIONS
# ============================================================================
Write-Status "Auditing GPO permissions for non-admin delegations..."

# Well-known SIDs that should have GPO permissions
$LegitGPOEditors = @(
    "Domain Admins"
    "Enterprise Admins"
    "ENTERPRISE DOMAIN CONTROLLERS"
    "SYSTEM"
    "Authenticated Users"
)

foreach ($gpo in $AllGPOs) {
    try {
        $perms = Get-GPPermission -Name $gpo.DisplayName -All -ErrorAction Stop

        foreach ($perm in $perms) {
            $trustee = $perm.Trustee.Name
            $permLevel = $perm.Permission

            # Skip legitimate/expected trustees
            if ($trustee -in $LegitGPOEditors) { continue }
            if ($trustee -eq "Administrator") { continue }

            # Flag GpoEdit or higher permissions on non-standard trustees
            if ($permLevel -in @("GpoEdit", "GpoEditDeleteModifySecurity", "GpoCustom")) {

                # Check if this trustee is a BadBlood object
                $isBadBlood = $false
                try {
                    $obj = Get-ADObject -Filter "SamAccountName -eq '$trustee'" -Properties Description
                    if ($obj.Description) {
                        $isBadBlood = ($BadBloodDescPatterns | ForEach-Object { $obj.Description -like $_ }) -contains $true
                    }
                } catch {}

                $bbTag = if ($isBadBlood) { " [BADBLOOD USER]" } else { "" }
                $risk = $GPORiskDatabase["GPODelegation"]

                $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "'$trustee'$bbTag has $permLevel on GPO '$($gpo.DisplayName)'" `
                    -CurrentState "$trustee -> $permLevel on {$($gpo.Id)}" `
                    -ExpectedState "Only Domain Admins / dedicated GPO admin accounts should have edit rights" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName $gpo.DisplayName -GPOGUID $gpo.Id))
            }
        }
    } catch {
        Write-Warning "Could not read permissions for GPO '$($gpo.DisplayName)': $_"
    }
}

# ============================================================================
# SECTION 5: AUDIT LAPS CONFIGURATION AND OU PERMISSIONS
# ============================================================================
Write-Status "Auditing LAPS deployment and OU permissions..."

# Check for LAPS schema
$LAPSAttr = $null
$LAPSType = "None"
try {
    $null = Get-ADObject "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,$DomainDN" -ErrorAction Stop
    $LAPSAttr = "ms-Mcs-AdmPwd"
    $LAPSType = "Legacy"
} catch {}
if (-not $LAPSAttr) {
    try {
        $null = Get-ADObject "CN=ms-LAPS-Password,CN=Schema,CN=Configuration,$DomainDN" -ErrorAction Stop
        $LAPSAttr = "ms-LAPS-Password"
        $LAPSType = "Windows"
    } catch {}
}

# Scan all OUs for overpermissioned LAPS ACLs
$AllOUs = Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName
foreach ($ou in $AllOUs) {
    try {
        $ouPath = "AD:\$($ou.DistinguishedName)"
        $acl = Get-Acl $ouPath -ErrorAction Stop

        foreach ($ace in $acl.Access) {
            $identity = $ace.IdentityReference.Value

            # Flag if Domain Users, Authenticated Users, or Everyone has ExtendedRight
            $dangerousIdentities = @("*Domain Users*", "*Authenticated Users*", "*Everyone*", "*S-1-1-0*", "*S-1-5-11*")
            $isDangerous = $false
            foreach ($pattern in $dangerousIdentities) {
                if ($identity -like $pattern) { $isDangerous = $true; break }
            }

            if ($isDangerous -and $ace.ActiveDirectoryRights -match "ExtendedRight") {
                $risk = $GPORiskDatabase["LAPSBackdoor"]
                $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                    -Finding "'$identity' has ExtendedRight on OU '$($ou.DistinguishedName)' - can read LAPS passwords" `
                    -CurrentState "$identity -> ExtendedRight (All) on OU. Object type: $($ace.InheritedObjectType)" `
                    -ExpectedState "Only designated admin/helpdesk groups should have ExtendedRight. Domain Users must NEVER have this" `
                    -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                    -GPOName "OU ACL (not GPO-specific)" -GPOGUID "N/A"))
            }
        }
    } catch {
        # ACL read failure on some OUs is normal
    }
}

# Scan for LAPS GPO settings with weak configuration
foreach ($gpo in $AllGPOs) {
    $gpoName = $gpo.DisplayName

    # Check Legacy LAPS settings
    try {
        $lapsEnabled = Get-GPRegistryValue -Name $gpoName `
            -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" `
            -ValueName "AdmPwdEnabled" -ErrorAction Stop
        if ($lapsEnabled.Value -eq 1) {
            # Check password length
            try {
                $lapsLen = Get-GPRegistryValue -Name $gpoName `
                    -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" `
                    -ValueName "PasswordLength" -ErrorAction Stop
                if ([int]$lapsLen.Value -lt 14) {
                    $risk = $GPORiskDatabase["LAPSWeakPolicy"]
                    $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                        -Finding "LAPS password length only $($lapsLen.Value) chars via GPO '$gpoName'" `
                        -CurrentState "PasswordLength = $($lapsLen.Value)" `
                        -ExpectedState "PasswordLength = 20+" `
                        -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                        -GPOName $gpoName -GPOGUID $gpo.Id))
                }
            } catch {}

            # Check password age
            try {
                $lapsAge = Get-GPRegistryValue -Name $gpoName `
                    -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" `
                    -ValueName "PasswordAgeDays" -ErrorAction Stop
                if ([int]$lapsAge.Value -gt 90) {
                    $risk = $GPORiskDatabase["LAPSWeakPolicy"]
                    $AllFindings.Add((Write-Finding -Category $risk.Category -Severity "MEDIUM" `
                        -Finding "LAPS password age set to $($lapsAge.Value) days via GPO '$gpoName'" `
                        -CurrentState "PasswordAgeDays = $($lapsAge.Value)" `
                        -ExpectedState "PasswordAgeDays = 30" `
                        -WhyBad "Long rotation means compromised passwords remain valid for extended periods." `
                        -AttackScenario "Obtain LAPS password -> valid for $($lapsAge.Value) days -> persistent local admin." `
                        -Principle $risk.Principle `
                        -GPOName $gpoName -GPOGUID $gpo.Id))
                }
            } catch {}
        }
    } catch {}

    # Check Windows LAPS settings
    try {
        $winLapsLen = Get-GPRegistryValue -Name $gpoName `
            -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config" `
            -ValueName "PasswordLength" -ErrorAction Stop
        if ([int]$winLapsLen.Value -lt 14) {
            $risk = $GPORiskDatabase["LAPSWeakPolicy"]
            $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                -Finding "Windows LAPS password length only $($winLapsLen.Value) chars via GPO '$gpoName'" `
                -CurrentState "PasswordLength = $($winLapsLen.Value)" `
                -ExpectedState "PasswordLength = 20+" `
                -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                -GPOName $gpoName -GPOGUID $gpo.Id))
        }
    } catch {}
}

# ============================================================================
# SECTION 6: AUDIT GPO SCHEDULED TASKS AND SCRIPT SHARES
# ============================================================================
Write-Status "Auditing GPO-deployed Scheduled Tasks and script share permissions..."

$SYSVOLPolicies = "\\$DomainDNS\SYSVOL\$DomainDNS\Policies"

foreach ($gpo in $AllGPOs) {
    foreach ($scope in @("Machine", "User")) {
        $taskFile = "$SYSVOLPolicies\{$($gpo.Id)}\$scope\Preferences\ScheduledTasks\ScheduledTasks.xml"
        if (Test-Path $taskFile) {
            try {
                [xml]$taskXml = Get-Content $taskFile -Raw

                # Check for TaskV2 nodes (GPO Preferences Scheduled Tasks)
                $tasks = $taskXml.SelectNodes("//TaskV2")
                if (-not $tasks -or $tasks.Count -eq 0) {
                    $tasks = $taskXml.SelectNodes("//Task")
                }

                foreach ($task in $tasks) {
                    $taskName = $task.name
                    if (-not $taskName) { $taskName = $task.Properties.name }

                    # Extract execution info
                    $runAs = $task.Properties.runAs
                    if (-not $runAs) {
                        $principal = $task.SelectSingleNode(".//Principal/UserId")
                        if ($principal) { $runAs = $principal.InnerText }
                    }

                    # Find the command being executed
                    $execNode = $task.SelectSingleNode(".//Exec")
                    $command = ""
                    $arguments = ""
                    if ($execNode) {
                        $command = $execNode.Command
                        $arguments = $execNode.Arguments
                    }

                    # Check if SYSTEM is running scripts from network shares
                    $isSystem = $runAs -match "SYSTEM|LocalSystem|S-1-5-18"
                    $referencesShare = ($arguments -match "\\\\") -or ($command -match "\\\\")

                    if ($isSystem) {
                        $risk = $GPORiskDatabase["ScheduledTaskGPO"]
                        $cmdDisplay = if ($arguments) { "$command $arguments" } else { $command }

                        $AllFindings.Add((Write-Finding -Category $risk.Category -Severity $risk.Severity `
                            -Finding "GPO '$($gpo.DisplayName)' deploys Scheduled Task '$taskName' running as SYSTEM" `
                            -CurrentState "Task: $taskName | RunAs: $runAs | Command: $cmdDisplay" `
                            -ExpectedState "Scheduled tasks should not run as SYSTEM from writable network shares. Use least-privilege accounts and signed scripts" `
                            -WhyBad $risk.Why -AttackScenario $risk.Attack -Principle $risk.Principle `
                            -GPOName $gpo.DisplayName -GPOGUID $gpo.Id))

                        # If it references a UNC path, check if the share is writable
                        if ($referencesShare) {
                            $uncMatch = [regex]::Match("$command $arguments", '(\\\\[^\s"]+)')
                            if ($uncMatch.Success) {
                                $uncPath = $uncMatch.Groups[1].Value
                                # Extract just the share path (\\server\share)
                                $shareParts = $uncPath -split '\\'
                                if ($shareParts.Count -ge 4) {
                                    $shareRoot = "\\$($shareParts[2])\$($shareParts[3])"

                                    # Test write access
                                    $isWritable = $false
                                    try {
                                        $testFile = "$shareRoot\__laps_test_$(Get-Random).tmp"
                                        [System.IO.File]::WriteAllText($testFile, "test")
                                        Remove-Item $testFile -Force -ErrorAction SilentlyContinue
                                        $isWritable = $true
                                    } catch {
                                        $isWritable = $false
                                    }

                                    if ($isWritable) {
                                        $risk2 = $GPORiskDatabase["WritableScriptShare"]
                                        $AllFindings.Add((Write-Finding -Category $risk2.Category -Severity $risk2.Severity `
                                            -Finding "Script share '$shareRoot' referenced by SYSTEM task is WRITABLE by current user" `
                                            -CurrentState "Share: $shareRoot is writable. Script: $uncPath. Any domain user can replace the script" `
                                            -ExpectedState "Share should be read-only for non-admins. Only designated script maintainers should have write access" `
                                            -WhyBad $risk2.Why -AttackScenario $risk2.Attack -Principle $risk2.Principle `
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

# ============================================================================
# SECTION 7: AUDIT UNLINKED GPOs
# ============================================================================
Write-Status "Checking for unlinked GPOs..."

foreach ($gpo in $AllGPOs) {
    try {
        [xml]$report = Get-GPOReport -Name $gpo.DisplayName -ReportType XML -ErrorAction Stop
        $links = $report.GPO.LinksTo
        if (-not $links) {
            $AllFindings.Add((Write-Finding -Category "GPO Hygiene" -Severity "INFO" `
                -Finding "UNLINKED GPO: '$($gpo.DisplayName)' is not linked anywhere" `
                -CurrentState "GPO exists but has no links. May be orphaned, or may be staged for future deployment" `
                -ExpectedState "Delete if unused. If staging, document in GPO comment" `
                -GPOName $gpo.DisplayName -GPOGUID $gpo.Id))
        }
    } catch {}
}

# ============================================================================
# GENERATE REPORTS
# ============================================================================
Write-Status "Generating reports..."

$reportLines = [System.Collections.Generic.List[string]]::new()

$reportLines.Add("=" * 80)
$reportLines.Add("  BADBLOOD GPO ANSWER KEY - GROUP POLICY MISCONFIGURATIONS")
$reportLines.Add("  Domain: $DomainDNS")
$reportLines.Add("  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$reportLines.Add("  Total GPO Findings: $($AllFindings.Count)")
$reportLines.Add("=" * 80)
$reportLines.Add("")

# Severity summary
$critical = ($AllFindings | Where-Object Severity -eq "CRITICAL").Count
$high     = ($AllFindings | Where-Object Severity -eq "HIGH").Count
$medium   = ($AllFindings | Where-Object Severity -eq "MEDIUM").Count
$low      = ($AllFindings | Where-Object Severity -eq "LOW").Count
$info     = ($AllFindings | Where-Object Severity -eq "INFO").Count

$reportLines.Add("SEVERITY SUMMARY")
$reportLines.Add("-" * 40)
$reportLines.Add("  CRITICAL : $critical")
$reportLines.Add("  HIGH     : $high")
$reportLines.Add("  MEDIUM   : $medium")
$reportLines.Add("  LOW      : $low")
$reportLines.Add("  INFO     : $info")
$reportLines.Add("")

# Category summary
$reportLines.Add("CATEGORY SUMMARY")
$reportLines.Add("-" * 40)
$categories = $AllFindings | Group-Object Category | Sort-Object Count -Descending
foreach ($cat in $categories) {
    $reportLines.Add("  $($cat.Name): $($cat.Count) findings")
}
$reportLines.Add("")

# GPO Inventory
$reportLines.Add("=" * 80)
$reportLines.Add("  GPO INVENTORY")
$reportLines.Add("=" * 80)
$reportLines.Add("")
foreach ($gpo in ($AllGPOs | Sort-Object DisplayName)) {
    $linkStatus = "LINKED"
    try {
        [xml]$r = Get-GPOReport -Name $gpo.DisplayName -ReportType XML -ErrorAction Stop
        if (-not $r.GPO.LinksTo) { $linkStatus = "UNLINKED" }
    } catch { $linkStatus = "UNKNOWN" }

    $findingCount = ($AllFindings | Where-Object GPOName -eq $gpo.DisplayName).Count
    $reportLines.Add("  $($gpo.DisplayName.PadRight(45)) | $linkStatus | Findings: $findingCount | GUID: {$($gpo.Id)}")
}
$reportLines.Add("")

# Detailed findings by category
$reportLines.Add("=" * 80)
$reportLines.Add("  DETAILED FINDINGS (ANSWER KEY)")
$reportLines.Add("=" * 80)

foreach ($cat in $categories) {
    $reportLines.Add("")
    $reportLines.Add("=" * 80)
    $reportLines.Add("CATEGORY: $($cat.Name) ($($cat.Count) findings)")
    $reportLines.Add("=" * 80)
    $reportLines.Add("")

    $catFindings = $AllFindings | Where-Object Category -eq $cat.Name | Sort-Object Severity
    $findNum = 0

    foreach ($f in $catFindings) {
        $findNum++
        $reportLines.Add("-" * 70)
        $reportLines.Add("  Finding {$findNum}: [$($f.Severity)] $($f.Finding)")
        $reportLines.Add("  GPO:          $($f.GPOName) {$($f.GPOGUID)}")
        $reportLines.Add("  Current:      $($f.CurrentState)")
        $reportLines.Add("  Expected:     $($f.ExpectedState)")
        if ($f.WhyBad)         { $reportLines.Add("  Why Bad:      $($f.WhyBad)") }
        if ($f.AttackScenario) { $reportLines.Add("  Attack:       $($f.AttackScenario)") }
        if ($f.Principle)      { $reportLines.Add("  Principle:    $($f.Principle)") }
        $reportLines.Add("")
    }
}

# Expected clean state
$reportLines.Add("=" * 80)
$reportLines.Add("  EXPECTED CLEAN STATE - GPO SECURITY BASELINE")
$reportLines.Add("=" * 80)
$reportLines.Add("")
$reportLines.Add("After remediation, the domain GPO environment should have:")
$reportLines.Add("")
$reportLines.Add("  PASSWORD POLICY:")
$reportLines.Add("    - Minimum length: 14+ characters")
$reportLines.Add("    - Complexity: Enabled")
$reportLines.Add("    - Max age: 90-365 days")
$reportLines.Add("    - History: 24 passwords remembered")
$reportLines.Add("    - Lockout: 5-10 attempts, 15-30 min duration")
$reportLines.Add("")
$reportLines.Add("  AUTHENTICATION:")
$reportLines.Add("    - LmCompatibilityLevel: 5 (NTLMv2 only)")
$reportLines.Add("    - WDigest: Disabled (UseLogonCredential = 0)")
$reportLines.Add("    - LLMNR: Disabled (EnableMulticast = 0)")
$reportLines.Add("    - NetBIOS: Disabled via DHCP")
$reportLines.Add("")
$reportLines.Add("  NETWORK SECURITY:")
$reportLines.Add("    - SMB Signing: Required on all servers and clients")
$reportLines.Add("    - LDAP Signing: Required (LDAPServerIntegrity = 2)")
$reportLines.Add("    - WinRM: HTTPS only, no Basic auth, no unencrypted")
$reportLines.Add("    - Anonymous enumeration: Blocked")
$reportLines.Add("")
$reportLines.Add("  HOST SECURITY:")
$reportLines.Add("    - Windows Firewall: Enabled on all profiles")
$reportLines.Add("    - UAC: Enabled (EnableLUA = 1)")
$reportLines.Add("    - Windows Defender: Active (or verified third-party AV)")
$reportLines.Add("    - Credential Guard / RunAsPPL: Enabled")
$reportLines.Add("    - AutoRun: Disabled (NoDriveTypeAutoRun = 255)")
$reportLines.Add("    - RDP: NLA required, High encryption")
$reportLines.Add("")
$reportLines.Add("  LOGGING & MONITORING:")
$reportLines.Add("    - PowerShell: ScriptBlock + Module + Transcription enabled")
$reportLines.Add("    - Security event log: 1 GB minimum, forwarded to SIEM")
$reportLines.Add("    - System/PS logs: 256 MB minimum")
$reportLines.Add("")
$reportLines.Add("  GPO HYGIENE:")
$reportLines.Add("    - No cpassword/GPP passwords in SYSVOL")
$reportLines.Add("    - GPO edit rights limited to dedicated admin accounts")
$reportLines.Add("    - No orphaned/unlinked GPOs without documentation")
$reportLines.Add("")
$reportLines.Add("  LAPS DEPLOYMENT:")
$reportLines.Add("    - LAPS password read rights granted ONLY to designated helpdesk/admin groups")
$reportLines.Add("    - Domain Users / Authenticated Users / Everyone must NOT have ExtendedRight on any OU")
$reportLines.Add("    - Password length: 20+ characters")
$reportLines.Add("    - Password rotation: 30 days maximum")
$reportLines.Add("    - Audit OU ACLs with: Find-AdmPwdExtendedRights -Identity <OU>")
$reportLines.Add("")
$reportLines.Add("  GPO SCHEDULED TASKS:")
$reportLines.Add("    - No Scheduled Tasks running as SYSTEM that reference writable network shares")
$reportLines.Add("    - Script shares: Read-only for Authenticated Users, write only for admin group")
$reportLines.Add("    - Both SMB share permissions AND NTFS ACLs must be locked down")
$reportLines.Add("    - Consider code-signing enforcement for deployed scripts")
$reportLines.Add("    - Audit with: findstr /S /I ScheduledTasks.xml \\domain\SYSVOL\*.xml")
$reportLines.Add("")

# Write main report
$reportFile = Join-Path $OutputPath "GPO_AnswerKey_MasterReport.txt"
$reportLines | Out-File -FilePath $reportFile -Encoding UTF8
Write-Status "Master report: $reportFile" "Green"

# Write findings CSV
$findingsFile = Join-Path $OutputPath "GPO_AllFindings.csv"
$AllFindings | Export-Csv -Path $findingsFile -NoTypeInformation
Write-Status "Findings CSV: $findingsFile" "Green"

if ($ExportCSVs) {
    # Export per-category CSVs
    foreach ($cat in $categories) {
        $safeName = ($cat.Name -replace '[^a-zA-Z0-9]', '_')
        $catFile = Join-Path $OutputPath "GPO_Findings_$safeName.csv"
        $AllFindings | Where-Object Category -eq $cat.Name | Export-Csv -Path $catFile -NoTypeInformation
    }
    Write-Status "Per-category CSVs exported" "Green"
}

# ============================================================================
# QUICK REFERENCE CHEAT SHEET
# ============================================================================
$cheatLines = [System.Collections.Generic.List[string]]::new()
$cheatLines.Add("=" * 80)
$cheatLines.Add("  GPO QUICK REFERENCE - CHEAT SHEET FOR STUDENTS")
$cheatLines.Add("  Domain: $DomainDNS | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$cheatLines.Add("=" * 80)
$cheatLines.Add("")
$cheatLines.Add("TOTAL GPO FINDINGS: $($AllFindings.Count)")
$cheatLines.Add("  CRITICAL: $critical | HIGH: $high | MEDIUM: $medium | LOW: $low | INFO: $info")
$cheatLines.Add("")

$cheatLines.Add("TOOLS TO USE:")
$cheatLines.Add("  Get-GPO -All                              # List all GPOs")
$cheatLines.Add("  Get-GPOReport -Name <name> -ReportType HTML -Path report.html")
$cheatLines.Add("  Get-GPPermission -Name <name> -All        # Check delegation")
$cheatLines.Add("  Get-GPRegistryValue -Name <name> -Key ... # Read specific settings")
$cheatLines.Add("  dir \\$DomainDNS\SYSVOL\$DomainDNS\Policies\ # Browse raw GPO files")
$cheatLines.Add("  findstr /S /I cpassword \\$DomainDNS\SYSVOL\*.xml  # Find GPP passwords")
$cheatLines.Add("  findstr /S /I ScheduledTasks \\$DomainDNS\SYSVOL\*.xml  # Find GPO sched tasks")
$cheatLines.Add("")
$cheatLines.Add("LAPS AUDIT TOOLS:")
$cheatLines.Add("  Get-ADComputer -SearchBase <OU> -Properties ms-Mcs-AdmPwd  # Read LAPS passwords (if permitted)")
$cheatLines.Add("  (Get-Acl 'AD:\<OU>').Access | Where ActiveDirectoryRights -match ExtendedRight  # Who can read?")
$cheatLines.Add("")
$cheatLines.Add("SCHEDULED TASK / SHARE AUDIT:")
$cheatLines.Add("  Get-SmbShareAccess -Name <share>         # Check share permissions")
$cheatLines.Add("  icacls <path>                             # Check NTFS ACLs")
$cheatLines.Add("  echo test > \\\\server\\share\\test.txt       # Quick write-access test")
$cheatLines.Add("")

$cheatLines.Add("GPOs WITH FINDINGS:")
$cheatLines.Add("-" * 70)
$gpoSummary = $AllFindings | Group-Object GPOName | Sort-Object Count -Descending
foreach ($g in $gpoSummary) {
    $sevBreakdown = ($AllFindings | Where-Object GPOName -eq $g.Name | Group-Object Severity |
        ForEach-Object { "$($_.Name):$($_.Count)" }) -join ", "
    $cheatLines.Add("  $($g.Name.PadRight(45)) $($g.Count) findings ($sevBreakdown)")
}
$cheatLines.Add("")

$cheatLines.Add("CRITICAL FINDINGS TO ADDRESS FIRST:")
$cheatLines.Add("-" * 70)
$critFindings = $AllFindings | Where-Object Severity -eq "CRITICAL"
foreach ($f in $critFindings) {
    $cheatLines.Add("  [!] $($f.Finding)")
    $cheatLines.Add("      Fix: $($f.ExpectedState)")
    $cheatLines.Add("")
}

$cheatFile = Join-Path $OutputPath "GPO_QuickReference_CheatSheet.txt"
$cheatLines | Out-File -FilePath $cheatFile -Encoding UTF8
Write-Status "Cheat sheet: $cheatFile" "Green"

# ============================================================================
# FINAL SUMMARY
# ============================================================================
Write-Host ""
Write-Host "=" * 80 -ForegroundColor Yellow
Write-Host "  GPO ANSWER KEY GENERATION COMPLETE" -ForegroundColor Green
Write-Host "=" * 80 -ForegroundColor Yellow
Write-Host ""
Write-Host "  Total GPO Findings: $($AllFindings.Count)" -ForegroundColor White
Write-Host "    CRITICAL: $critical" -ForegroundColor Red
Write-Host "    HIGH:     $high" -ForegroundColor DarkYellow
Write-Host "    MEDIUM:   $medium" -ForegroundColor Yellow
Write-Host "    LOW:      $low" -ForegroundColor Gray
Write-Host "    INFO:     $info" -ForegroundColor Gray
Write-Host ""
Write-Host "  Output: $OutputPath" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Yellow
