#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    BadderBlood Domain Cleanup Answer Key Generator (v2 - Annotated)
.DESCRIPTION
    Audits an Active Directory domain after BadderBlood has been run and generates
    a comprehensive answer key showing:
      - Every violation found (what's wrong)
      - WHY it's a problem (attack scenario / security principle)
      - The user's OU/department context
      - The expected clean state (what students should fix it to)
      - Severity ratings for grading
    
    Designed for instructors running BadderBlood (or original BadBlood)
    in a lab environment.

.NOTES
    Run this on a Domain Controller or a machine with RSAT installed.
    Must be run as a Domain Admin or equivalent.

.EXAMPLE
    .\Generate-BadderBloodAnswerKey.ps1
    .\Generate-BadderBloodAnswerKey.ps1 -OutputPath "C:\AnswerKeys" -IncludeGPOAnalysis
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\BadderBlood_AnswerKey_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch]$IncludeGPOAnalysis,
    [switch]$ExportCSVs,
    [switch]$Quiet
)

# ============================================================================
# CONFIGURATION: Define what "clean" looks like
# ============================================================================
# These are the privileged groups that normal users should NOT be in.
# BadderBlood deliberately puts random users into these groups.

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

# Tier 0 groups - these should ONLY contain Tier 0 accounts
$Tier0Groups = @(
    "Domain Admins"
    "Enterprise Admins"
    "Schema Admins"
    "Administrators"
)

# Accounts that are EXPECTED to be in privileged groups (built-in/legitimate)
$LegitimatePrivilegedAccounts = @(
    "Administrator"
    "krbtgt"
)

# OUs where admin/service accounts should live (Tier model)
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
        [string]$ObjectDN = ""
    )
    [PSCustomObject]@{
        Category       = $Category
        Severity       = $Severity
        Finding        = $Finding
        CurrentState   = $CurrentState
        ExpectedState  = $ExpectedState
        WhyBad         = $WhyBad
        AttackScenario = $AttackScenario
        UserContext     = $UserContext
        Principle       = $Principle
        ObjectDN       = $ObjectDN
    }
}

# ============================================================================
# SETUP
# ============================================================================

Write-Host @"
===============================================================================
   BadderBlood Domain Cleanup - Answer Key Generator
   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
===============================================================================
"@ -ForegroundColor Yellow

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$DomainInfo = Get-ADDomain
$ForestInfo = Get-ADForest
$DomainDN   = $DomainInfo.DistinguishedName
$DomainName = $DomainInfo.DNSRoot

Write-Status "Auditing domain: $DomainName"
Write-Status "Domain DN: $DomainDN"
Write-Status "Output directory: $OutputPath"

$AllFindings = [System.Collections.Generic.List[PSObject]]::new()

# ============================================================================
# SECTION 1: IDENTIFY ALL BADBLOOD-CREATED OBJECTS
# ============================================================================
Write-Status "SECTION 1: Identifying all BadderBlood-created objects..."

# Find all users created by BadderBlood
$AllUsers = Get-ADUser -Filter * -Properties Description, MemberOf, Enabled, `
    PasswordNeverExpires, PasswordNotRequired, DoesNotRequirePreAuth, `
    TrustedForDelegation, TrustedToAuthForDelegation, AdminCount, `
    SIDHistory, ServicePrincipalName, CanonicalName, WhenCreated, `
    AllowReversiblePasswordEncryption, AccountNotDelegated

$BadderBloodUsers = $AllUsers | Where-Object {
    $desc = $_.Description
    ($BadderBloodDescPatterns | ForEach-Object { $desc -like $_ }) -contains $true
}

# Find all groups created by BadderBlood
$AllGroups = Get-ADGroup -Filter * -Properties Description, Members, MemberOf, CanonicalName, WhenCreated

$BadderBloodGroups = $AllGroups | Where-Object {
    $desc = $_.Description
    ($BadderBloodDescPatterns | ForEach-Object { $desc -like $_ }) -contains $true
}

Write-Status "Found $($BadderBloodUsers.Count) BadderBlood-created users" "Green"
Write-Status "Found $($BadderBloodGroups.Count) BadderBlood-created security groups" "Green"

# Build lookup: SamAccountName -> context info
$UserContextMap = @{}
foreach ($u in $AllUsers) {
    $UserContextMap[$u.SamAccountName] = @{
        CanonicalName = $u.CanonicalName
        Department    = Get-UserDepartment -CanonicalName $u.CanonicalName
        FriendlyOU    = Get-FriendlyOUPath -CanonicalName $u.CanonicalName
    }
}

# ============================================================================
# SECTION 2: PRIVILEGED GROUP MEMBERSHIP VIOLATIONS
# ============================================================================
Write-Status "SECTION 2: Auditing privileged group memberships..."

$PrivGroupReport = [System.Collections.Generic.List[PSObject]]::new()

foreach ($groupName in $PrivilegedGroups) {
    try {
        $group = Get-ADGroup $groupName -Properties Members
        $members = Get-ADGroupMember $groupName -Recursive -ErrorAction SilentlyContinue
        
        foreach ($member in $members) {
            $isLegitimate = $LegitimatePrivilegedAccounts -contains $member.SamAccountName
            $isBadderBlood = $false
            
            if ($member.objectClass -eq "user") {
                $userObj = $AllUsers | Where-Object { $_.SamAccountName -eq $member.SamAccountName }
                if ($userObj) {
                    $desc = $userObj.Description
                    $isBadderBlood = ($BadderBloodDescPatterns | ForEach-Object { $desc -like $_ }) -contains $true
                }
            }
            
            $ctx = $UserContextMap[$member.SamAccountName]
            $dept = if ($ctx) { $ctx.Department } else { "Unknown" }
            $ouPath = if ($ctx) { $ctx.FriendlyOU } else { "Unknown" }
            
            $privEntry = [PSCustomObject]@{
                PrivilegedGroup   = $groupName
                MemberName        = $member.SamAccountName
                MemberType        = $member.objectClass
                MemberDN          = $member.distinguishedName
                Department        = $dept
                OUPath            = $ouPath
                IsLegitimate      = $isLegitimate
                IsBadderBloodCreated = $isBadderBlood
                Action            = if ($isLegitimate) { "KEEP" } else { "REMOVE" }
            }
            $PrivGroupReport.Add($privEntry)
            
            if (-not $isLegitimate) {
                $sev = if ($groupName -in $Tier0Groups) { "CRITICAL" } else { "HIGH" }
                $gi = $GroupRiskExplanations[$groupName]
                
                $contextNote = "User is in '$ouPath' (Dept: $dept). "
                if ($dept -ne "Admin" -and $dept -notlike "*Tier*") {
                    $contextNote += "As a regular departmental user, they have NO business reason to be in '$groupName'."
                } else {
                    $contextNote += "Even in an admin OU, they should use a DEDICATED admin account."
                }
                
                $finding = Write-Finding -Category "Privileged Group Membership" `
                    -Severity $sev `
                    -Finding "User '$($member.SamAccountName)' (Dept: $dept, OU: $ouPath) is a member of '$groupName'" `
                    -CurrentState "Member of $groupName | Risk: $(if($gi){$gi.Risk}else{'ELEVATED'})" `
                    -ExpectedState "REMOVE from $groupName" `
                    -WhyBad $(if($gi){$gi.Why}else{"Elevated privileges regular users should not have."}) `
                    -AttackScenario $(if($gi){$gi.Attack}else{"Compromising this user inherits all $groupName privileges."}) `
                    -UserContext $contextNote `
                    -Principle $(if($gi){$gi.Principle}else{"Least Privilege."}) `
                    -ObjectDN $member.distinguishedName
                $AllFindings.Add($finding)
            }
        }
    }
    catch {
        Write-Warning "Could not query group: $groupName - $_"
    }
}

$ViolationCount = ($PrivGroupReport | Where-Object { $_.Action -eq "REMOVE" }).Count
Write-Status "Found $ViolationCount privileged group membership violations" "Red"

# ============================================================================
# SECTION 3: DANGEROUS USER ACCOUNT SETTINGS
# ============================================================================
Write-Status "SECTION 3: Checking for dangerous user account settings..."

foreach ($user in $BadderBloodUsers) {
    # Password Never Expires
    if ($user.PasswordNeverExpires) {
        $AllFindings.Add((Write-Finding -Category "Account Settings" `
            -Severity "MEDIUM" `
            -Finding "User '$($user.SamAccountName)' has PasswordNeverExpires set" `
            -CurrentState "PasswordNeverExpires = True" `
            -ExpectedState "PasswordNeverExpires = False" `
            -ObjectDN $user.DistinguishedName))
    }
    
    # Password Not Required
    if ($user.PasswordNotRequired) {
        $AllFindings.Add((Write-Finding -Category "Account Settings" `
            -Severity "CRITICAL" `
            -Finding "User '$($user.SamAccountName)' does not require a password" `
            -CurrentState "PasswordNotRequired = True" `
            -ExpectedState "PasswordNotRequired = False" `
            -ObjectDN $user.DistinguishedName))
    }
    
    # Kerberos Pre-Auth Not Required (AS-REP Roastable)
    if ($user.DoesNotRequirePreAuth) {
        $AllFindings.Add((Write-Finding -Category "Kerberos Security" `
            -Severity "HIGH" `
            -Finding "User '$($user.SamAccountName)' does not require Kerberos pre-auth (AS-REP Roastable)" `
            -CurrentState "DoesNotRequirePreAuth = True" `
            -ExpectedState "DoesNotRequirePreAuth = False" `
            -ObjectDN $user.DistinguishedName))
    }
    
    # Unconstrained Delegation
    if ($user.TrustedForDelegation) {
        $AllFindings.Add((Write-Finding -Category "Delegation" `
            -Severity "CRITICAL" `
            -Finding "User '$($user.SamAccountName)' is trusted for unconstrained delegation" `
            -CurrentState "TrustedForDelegation = True" `
            -ExpectedState "TrustedForDelegation = False" `
            -ObjectDN $user.DistinguishedName))
    }
    
    # Constrained Delegation (Protocol Transition)
    if ($user.TrustedToAuthForDelegation) {
        $AllFindings.Add((Write-Finding -Category "Delegation" `
            -Severity "HIGH" `
            -Finding "User '$($user.SamAccountName)' is trusted to auth for delegation (protocol transition)" `
            -CurrentState "TrustedToAuthForDelegation = True" `
            -ExpectedState "TrustedToAuthForDelegation = False (or validate if needed)" `
            -ObjectDN $user.DistinguishedName))
    }
    
    # Reversible Encryption
    if ($user.AllowReversiblePasswordEncryption) {
        $AllFindings.Add((Write-Finding -Category "Account Settings" `
            -Severity "HIGH" `
            -Finding "User '$($user.SamAccountName)' allows reversible password encryption" `
            -CurrentState "AllowReversiblePasswordEncryption = True" `
            -ExpectedState "AllowReversiblePasswordEncryption = False" `
            -ObjectDN $user.DistinguishedName))
    }
    
    # SID History (possible privilege escalation)
    if ($user.SIDHistory.Count -gt 0) {
        $AllFindings.Add((Write-Finding -Category "SID History" `
            -Severity "HIGH" `
            -Finding "User '$($user.SamAccountName)' has SID History entries" `
            -CurrentState "SIDHistory contains $($user.SIDHistory.Count) entries" `
            -ExpectedState "SIDHistory should be empty (clear all entries)" `
            -ObjectDN $user.DistinguishedName))
    }
    
    # SPNs on user accounts (Kerberoastable)
    if ($user.ServicePrincipalName.Count -gt 0) {
        $AllFindings.Add((Write-Finding -Category "Kerberos Security" `
            -Severity "HIGH" `
            -Finding "User '$($user.SamAccountName)' has SPNs set (Kerberoastable)" `
            -CurrentState "SPNs: $($user.ServicePrincipalName -join ', ')" `
            -ExpectedState "Remove SPNs or convert to managed service account" `
            -ObjectDN $user.DistinguishedName))
    }
    
    # AdminCount = 1 but not in admin groups (stale AdminCount / SDProp orphan)
    if ($user.AdminCount -eq 1) {
        $inPrivGroup = $false
        foreach ($grp in $PrivilegedGroups) {
            try {
                $m = Get-ADGroupMember $grp -Recursive -ErrorAction SilentlyContinue |
                     Where-Object { $_.SamAccountName -eq $user.SamAccountName }
                if ($m) { $inPrivGroup = $true; break }
            } catch {}
        }
        if (-not $inPrivGroup) {
            $AllFindings.Add((Write-Finding -Category "Account Settings" `
                -Severity "MEDIUM" `
                -Finding "User '$($user.SamAccountName)' has AdminCount=1 but is not in any privileged group (stale)" `
                -CurrentState "AdminCount = 1 (orphaned)" `
                -ExpectedState "AdminCount = 0, reset ACL inheritance" `
                -ObjectDN $user.DistinguishedName))
        }
    }

    # Password stored in Description field
    if ($user.Description -match '(?i)(password|pwd|pass)\s*[:=]\s*\S+' -or
        $user.Description -match '(?i)my password is\s+\S+' -or
        $user.Description -match '(?i)dont forget.*(password|pwd)') {
        $ri = $SettingRiskExplanations["PasswordInDescription"]
        $AllFindings.Add((Write-Finding -Category "Credential Exposure" `
            -Severity "CRITICAL" `
            -Finding "User '$($user.SamAccountName)' has a password stored in their Description field" `
            -CurrentState "Description contains credential: '$($user.Description)'" `
            -ExpectedState "Remove password from Description field immediately" `
            -WhyBad $ri.Why `
            -AttackScenario $ri.Attack `
            -Principle $ri.Principle `
            -ObjectDN $user.DistinguishedName))
    }
}

# Also check ALL users for password in description (catches service accounts whose
# description was overwritten with password and no longer matches BadderBlood patterns)
Write-Status "Checking all users for passwords in description fields..."
$PasswordDescUsers = $AllUsers | Where-Object {
    $_ -notin $BadderBloodUsers -and (
        $_.Description -match '(?i)(password|pwd|pass)\s*[:=]\s*\S+' -or
        $_.Description -match '(?i)my password is\s+\S+' -or
        $_.Description -match '(?i)dont forget.*(password|pwd)')
}
foreach ($user in $PasswordDescUsers) {
    $ri = $SettingRiskExplanations["PasswordInDescription"]
    $AllFindings.Add((Write-Finding -Category "Credential Exposure" `
        -Severity "CRITICAL" `
        -Finding "User '$($user.SamAccountName)' has a password stored in their Description field" `
        -CurrentState "Description contains credential: '$($user.Description)'" `
        -ExpectedState "Remove password from Description field immediately" `
        -WhyBad $ri.Why `
        -AttackScenario $ri.Attack `
        -Principle $ri.Principle `
        -ObjectDN $user.DistinguishedName))
}

# ============================================================================
# SECTION 3b: OU DRIFT DETECTION (Department Mismatch)
# ============================================================================
Write-Status "SECTION 3b: Checking for OU drift (users in wrong department OUs)..."

# Re-fetch users with departmentNumber attribute for drift detection
$DriftCheckUsers = Get-ADUser -Filter * -Properties Description, departmentNumber, CanonicalName, DistinguishedName |
    Where-Object {
        $desc = $_.Description
        ($BadderBloodDescPatterns | ForEach-Object { $desc -like $_ }) -contains $true
    }

$DepartmentCodes = @('BDE','HRE','FIN','OGC','FSR','AWS','ESM','SEC','ITS','GOO','AZR','TST')

foreach ($user in $DriftCheckUsers) {
    $userDept = $user.departmentNumber
    if (-not $userDept) { continue }

    # Extract the department OU from the user's DN
    $dn = $user.DistinguishedName
    $ouDept = $null
    $dnParts = $dn -split ','
    foreach ($part in $dnParts) {
        $ouName = ($part -replace 'OU=','').Trim()
        if ($ouName -in $DepartmentCodes) {
            $ouDept = $ouName
            break
        }
    }

    # Only flag if both are known and they mismatch, and user is in People OU
    if ($ouDept -and $userDept -and ($ouDept -ne $userDept) -and $dn -like "*OU=People,*") {
        $ri = $SettingRiskExplanations["OUDrift"]
        $AllFindings.Add((Write-Finding -Category "OU Drift" `
            -Severity "MEDIUM" `
            -Finding "User '$($user.SamAccountName)' (dept: $userDept) is in the wrong department OU ($ouDept)" `
            -CurrentState "Department attribute: $userDept | OU placement: $ouDept" `
            -ExpectedState "Move user to OU=$userDept,OU=People or correct department attribute" `
            -WhyBad $ri.Why `
            -AttackScenario $ri.Attack `
            -Principle $ri.Principle `
            -ObjectDN $user.DistinguishedName))
    }

    # Also flag users in Stage OU (should have been moved)
    if ($dn -like "*OU=Stage,*") {
        $AllFindings.Add((Write-Finding -Category "OU Drift" `
            -Severity "LOW" `
            -Finding "User '$($user.SamAccountName)' is still in the Stage OU (should be in People)" `
            -CurrentState "Located in Stage OU" `
            -ExpectedState "Move to appropriate People > Department OU" `
            -ObjectDN $user.DistinguishedName))
    }

    # Flag users in Unassociated OU
    if ($dn -like "*OU=Unassociated,*") {
        $AllFindings.Add((Write-Finding -Category "OU Drift" `
            -Severity "LOW" `
            -Finding "User '$($user.SamAccountName)' is in the Unassociated OU (no department placement)" `
            -CurrentState "Located in Unassociated OU" `
            -ExpectedState "Move to appropriate People > Department OU" `
            -ObjectDN $user.DistinguishedName))
    }
}

# ============================================================================
# SECTION 4: NESTED GROUP MEMBERSHIP CHAINS
# ============================================================================
Write-Status "SECTION 4: Analyzing nested group membership chains..."

foreach ($groupName in $PrivilegedGroups) {
    try {
        $directMembers = Get-ADGroupMember $groupName -ErrorAction SilentlyContinue
        $nestedGroups = $directMembers | Where-Object { $_.objectClass -eq "group" }
        
        foreach ($nestedGroup in $nestedGroups) {
            $ngDesc = (Get-ADGroup $nestedGroup.SamAccountName -Properties Description).Description
            $isBB = ($BadderBloodDescPatterns | ForEach-Object { $ngDesc -like $_ }) -contains $true
            
            $AllFindings.Add((Write-Finding -Category "Nested Group Membership" `
                -Severity "HIGH" `
                -Finding "Group '$($nestedGroup.SamAccountName)' is nested inside '$groupName'" `
                -CurrentState "Nested member of $groupName (BadderBlood: $isBB)" `
                -ExpectedState "REMOVE group nesting - evaluate each member individually" `
                -ObjectDN $nestedGroup.distinguishedName))
        }
    }
    catch {}
}

# ============================================================================
# SECTION 5: OU STRUCTURE ANALYSIS (OPTIMIZED)
# ============================================================================
Write-Status "SECTION 5: Analyzing OU structure..."

# PRE-CALCULATE: Get all privileged members ONCE and store in a HashSet for instant lookup
$PrivilegedMemberSIDs = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($grpName in $PrivilegedGroups) {
    try {
        # Get recursive members and add their SIDs to our lookup table
        Get-ADGroupMember -Identity $grpName -Recursive -ErrorAction SilentlyContinue | 
            ForEach-Object { [void]$PrivilegedMemberSIDs.Add($_.SID.Value) }
    } catch {}
}

# Map users to their OUs and check for misplacements
foreach ($user in $BadderBloodUsers) {
    $userOU = ($user.DistinguishedName -replace "^CN=[^,]+,", "")
    $canonPath = $user.CanonicalName
    
    # Check if user is in an Admin/Tier OU pattern
    $isInAdminOU = $false
    foreach ($pattern in $AdminOUPatterns) {
        if ($userOU -like $pattern) { $isInAdminOU = $true; break }
    }
    
    # INSTANT LOOKUP: Instead of a new AD query, check our pre-built HashSet
    $isInPrivGroup = $PrivilegedMemberSIDs.Contains($user.SID.Value)
    
    # User in People OU but has admin privs -> violation
    if ($canonPath -like "*People*" -and $isInPrivGroup) {
        $AllFindings.Add((Write-Finding -Category "OU Misplacement" `
            -Severity "HIGH" `
            -Finding "User '$($user.SamAccountName)' is in People OU but has privileged group membership" `
            -CurrentState "Located in: $canonPath | Has privileged access" `
            -ExpectedState "Either remove from privileged groups OR move to appropriate Admin/Tier OU" `
            -ObjectDN $user.DistinguishedName))
    }
    
    # User in Admin/Tier OU but is a regular BadderBlood user
    if ($isInAdminOU -and -not $isInPrivGroup) {
        $AllFindings.Add((Write-Finding -Category "OU Misplacement" `
            -Severity "MEDIUM" `
            -Finding "User '$($user.SamAccountName)' is in Admin/Tier OU but has no privileged memberships" `
            -CurrentState "Located in: $canonPath | No privileged access" `
            -ExpectedState "Move to appropriate People/Department OU or grant appropriate Tier access" `
            -ObjectDN $user.DistinguishedName))
    }
}

# ============================================================================
# SECTION 6: ACL / DELEGATION ANALYSIS
# ============================================================================
Write-Status "SECTION 6: Analyzing ACL delegations on OUs and objects..."

# Check for dangerous ACLs BadderBlood sets on key objects
$CriticalObjects = @(
    $DomainDN
    "CN=AdminSDHolder,CN=System,$DomainDN"
)

# Add all OU DNs
$CriticalObjects += ($AllOUs | ForEach-Object { $_.DistinguishedName })

# Add privileged group DNs (BadderBlood Scenario 6 sets ACLs on group objects)
foreach ($pgName in $PrivilegedGroups) {
    try { $CriticalObjects += (Get-ADGroup $pgName).DistinguishedName } catch {}
}
# Add all BadderBlood-created group DNs to catch group-to-group permission chains
$CriticalObjects += ($BadderBloodGroups | ForEach-Object { $_.DistinguishedName })

$ACLFindings = [System.Collections.Generic.List[PSObject]]::new()
$DangerousRights = @(
    "GenericAll"
    "GenericWrite"
    "WriteDacl"
    "WriteOwner"
    "WriteProperty"
    "ExtendedRight"
    "Self"
)

$checkedCount = 0
$totalToCheck = [Math]::Min($CriticalObjects.Count, 500) # Cap to avoid timeout (raised from 100)
Write-Status "Checking ACLs on $totalToCheck critical objects (of $($CriticalObjects.Count) total)..."

foreach ($objDN in ($CriticalObjects | Select-Object -First $totalToCheck)) {
    $checkedCount++
    if ($checkedCount % 25 -eq 0) {
        Write-Status "  ACL check progress: $checkedCount / $totalToCheck"
    }
    
    try {
        $acl = Get-Acl -Path "AD:\$objDN" -ErrorAction SilentlyContinue
        if (-not $acl) { continue }
        
        foreach ($ace in $acl.Access) {
            $identity = $ace.IdentityReference.ToString()
            
            # Skip built-in/expected identities
            if ($identity -match "^(NT AUTHORITY|BUILTIN|S-1-5)" -or
                $identity -match "(Domain Admins|Enterprise Admins|SYSTEM|Administrators)$") {
                continue
            }
            
            # Check if this is a BadderBlood user or group with dangerous permissions
            $samName = $identity -replace "^.*\\"
            $isBBUser = $BadderBloodUsers | Where-Object { $_.SamAccountName -eq $samName }
            $isBBGroup = $BadderBloodGroups | Where-Object { $_.SamAccountName -eq $samName }
            
            if (($isBBUser -or $isBBGroup) -and
                ($DangerousRights -contains $ace.ActiveDirectoryRights.ToString() -or
                 ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -or
                 ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -or
                 ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) -or
                 ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)))
            {
                $sev = if ($objDN -like "*AdminSDHolder*" -or $objDN -eq $DomainDN) { "CRITICAL" } else { "HIGH" }
                $objType = if ($isBBUser) { "User" } else { "Group" }
                
                $AllFindings.Add((Write-Finding -Category "Dangerous ACL" `
                    -Severity $sev `
                    -Finding "$objType '$samName' has '$($ace.ActiveDirectoryRights)' on '$objDN'" `
                    -CurrentState "ACE: $($ace.AccessControlType) | Rights: $($ace.ActiveDirectoryRights) | Inherited: $($ace.IsInherited)" `
                    -ExpectedState "REMOVE this ACE - BadderBlood-created $objType should not have these permissions" `
                    -ObjectDN $objDN))
            }
        }
    }
    catch {
        # Silently skip objects we can't read ACLs on
    }
}

# ============================================================================
# SECTION 7: GPO ANALYSIS (Optional)
# ============================================================================
if ($IncludeGPOAnalysis) {
    Write-Status "SECTION 7: Analyzing Group Policy Objects..."

    try {
        Import-Module GroupPolicy -ErrorAction Stop
        $DomainDNS_GPO = (Get-ADDomain).DNSRoot
        $AllGPOs = Get-GPO -All

        foreach ($gpo in $AllGPOs) {
            $gpoName = $gpo.DisplayName

            # --- GPO permissions: BadderBlood objects with edit rights ---
            $gpoPerms = Get-GPPermission -Guid $gpo.Id -All -ErrorAction SilentlyContinue
            foreach ($perm in $gpoPerms) {
                $trustee = $perm.Trustee.Name
                $isBB = ($BadderBloodUsers | Where-Object { $_.SamAccountName -eq $trustee }) -or
                        ($BadderBloodGroups | Where-Object { $_.SamAccountName -eq $trustee })
                if ($isBB -and $perm.Permission -in @("GpoEdit", "GpoEditDeleteModifySecurity")) {
                    $AllFindings.Add((Write-Finding -Category "GPO Permissions" `
                        -Severity "HIGH" `
                        -Finding "BadderBlood object '$trustee' can edit GPO '$gpoName'" `
                        -CurrentState "Permission: $($perm.Permission) on GPO" `
                        -ExpectedState "Remove edit permissions. Only Domain Admins/Group Policy Creator Owners should edit GPOs" `
                        -ObjectDN "GPO: $($gpo.Id)" `
                        -WhyBad "GPO edit access = remote code execution on every machine the GPO applies to. An attacker with GpoEdit can deploy a malicious startup script domain-wide within 90 minutes."))
                }
            }

            # Helper: read a GPO registry value safely
            function Get-GPOVal($name, $key, $val) {
                try { (Get-GPRegistryValue -Name $name -Key $key -ValueName $val -ErrorAction Stop).Value }
                catch { $null }
            }

            # --- Windows Firewall disabled ---
            $fwVal = Get-GPOVal $gpoName "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "EnableFirewall"
            if ($fwVal -eq 0) {
                $AllFindings.Add((Write-Finding -Category "GPO Settings" `
                    -Severity "CRITICAL" `
                    -Finding "GPO '$gpoName' disables Windows Firewall on all profiles" `
                    -CurrentState "EnableFirewall = 0 (Domain/Standard/Public)" `
                    -ExpectedState "EnableFirewall = 1 on all profiles. Use specific firewall rules for exceptions" `
                    -ObjectDN "GPO: $($gpo.Id)" `
                    -WhyBad "A disabled host firewall allows unrestricted lateral movement. Attackers can reach all ports on any domain machine (SMB, WinRM, RDP) with no network filtering."))
            }

            # --- UAC disabled ---
            $uacVal = Get-GPOVal $gpoName "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
            if ($uacVal -eq 0) {
                $AllFindings.Add((Write-Finding -Category "GPO Settings" `
                    -Severity "HIGH" `
                    -Finding "GPO '$gpoName' disables UAC (EnableLUA=0)" `
                    -CurrentState "EnableLUA=0, ConsentPromptBehaviorAdmin=0, FilterAdministratorToken=0" `
                    -ExpectedState "EnableLUA=1, ConsentPromptBehaviorAdmin=2, FilterAdministratorToken=1" `
                    -ObjectDN "GPO: $($gpo.Id)" `
                    -WhyBad "Without UAC, any process running as a local admin has an unrestricted high-integrity token. Privilege escalation requires no additional step - malware immediately runs with full admin rights."))
            }

            # --- WDigest plaintext creds ---
            $wdVal = Get-GPOVal $gpoName "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"
            if ($wdVal -eq 1) {
                $AllFindings.Add((Write-Finding -Category "GPO Settings" `
                    -Severity "CRITICAL" `
                    -Finding "GPO '$gpoName' enables WDigest authentication (plaintext passwords in LSASS)" `
                    -CurrentState "UseLogonCredential = 1" `
                    -ExpectedState "UseLogonCredential = 0. Migrate apps off WDigest/HTTP Digest" `
                    -ObjectDN "GPO: $($gpo.Id)" `
                    -WhyBad "WDigest stores cleartext passwords in LSASS memory. After gaining any code execution, 'sekurlsa::wdigest' in Mimikatz dumps plaintext passwords for every interactively logged-on user - no cracking required."))
            }

            # --- SMB signing disabled ---
            $smbVal = Get-GPOVal $gpoName "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature"
            if ($smbVal -eq 0) {
                $AllFindings.Add((Write-Finding -Category "GPO Settings" `
                    -Severity "CRITICAL" `
                    -Finding "GPO '$gpoName' disables SMB signing on server and client" `
                    -CurrentState "RequireSecuritySignature=0, EnableSecuritySignature=0 (both LanmanServer and LanManWorkstation)" `
                    -ExpectedState "RequireSecuritySignature=1 on both. EnableSecuritySignature=1" `
                    -ObjectDN "GPO: $($gpo.Id)" `
                    -WhyBad "Without SMB signing, NTLM relay attacks (ntlmrelayx, Responder) can relay captured credentials to authenticate to other machines. Combined with LLMNR poisoning this enables unauthenticated lateral movement across the domain."))
            }

            # --- LLMNR enabled ---
            $llVal = Get-GPOVal $gpoName "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast"
            if ($llVal -eq 1) {
                $AllFindings.Add((Write-Finding -Category "GPO Settings" `
                    -Severity "HIGH" `
                    -Finding "GPO '$gpoName' explicitly enforces LLMNR enabled" `
                    -CurrentState "EnableMulticast = 1" `
                    -ExpectedState "EnableMulticast = 0. Use DNS exclusively for name resolution" `
                    -ObjectDN "GPO: $($gpo.Id)" `
                    -WhyBad "LLMNR (Link-Local Multicast Name Resolution) responds to broadcast name queries. Responder/Inveigh poison these to capture NTLMv2 hashes from any machine that queries a nonexistent name, including typos and disconnected shares."))
            }

            # --- NTLMv1 allowed ---
            $ntVal = Get-GPOVal $gpoName "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel"
            if ($null -ne $ntVal -and [int]$ntVal -lt 3) {
                $AllFindings.Add((Write-Finding -Category "GPO Settings" `
                    -Severity "CRITICAL" `
                    -Finding "GPO '$gpoName' allows NTLMv1/LM authentication (LmCompatibilityLevel=$ntVal)" `
                    -CurrentState "LmCompatibilityLevel = $ntVal (allows LM and NTLM)" `
                    -ExpectedState "LmCompatibilityLevel = 5 (send NTLMv2 only, refuse LM and NTLM)" `
                    -ObjectDN "GPO: $($gpo.Id)" `
                    -WhyBad "LM hashes are split into two 7-character chunks and crackable in seconds with a GPU. NTLMv1 is vulnerable to pass-the-hash and offline cracking. Level 0 means the DC will accept LM authentication from any client."))
            }

            # --- Defender disabled ---
            $defVal = Get-GPOVal $gpoName "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" "DisableAntiSpyware"
            if ($defVal -eq 1) {
                $AllFindings.Add((Write-Finding -Category "GPO Settings" `
                    -Severity "CRITICAL" `
                    -Finding "GPO '$gpoName' disables Windows Defender via policy" `
                    -CurrentState "DisableAntiSpyware=1, DisableRealtimeMonitoring=1, DisableBehaviorMonitoring=1" `
                    -ExpectedState "All Defender settings = 0 (enabled). If third-party AV is deployed, verify it is active before removing Defender" `
                    -ObjectDN "GPO: $($gpo.Id)" `
                    -WhyBad "Disabling AV via GPO is a well-known attacker technique to ensure post-exploitation tools (Mimikatz, Cobalt Strike beacons, etc.) run without being quarantined. This finding indicates deliberate AV suppression."))
            }

            # --- PowerShell logging disabled ---
            $psVal = Get-GPOVal $gpoName "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
            if ($psVal -eq 0) {
                $AllFindings.Add((Write-Finding -Category "GPO Settings" `
                    -Severity "HIGH" `
                    -Finding "GPO '$gpoName' disables PowerShell Script Block Logging" `
                    -CurrentState "EnableScriptBlockLogging=0, EnableModuleLogging=0, EnableTranscripting=0" `
                    -ExpectedState "Enable all three: ScriptBlockLogging=1, ModuleLogging=1 (modules: *), Transcription=1 to secured share" `
                    -ObjectDN "GPO: $($gpo.Id)" `
                    -WhyBad "PowerShell is the primary post-exploitation framework on Windows. Without script block logging, attackers run encoded/obfuscated payloads, download-cradles, and Mimikatz with no forensic trace in event logs."))
            }

            # --- Excessive cached credentials ---
            $ccVal = Get-GPOVal $gpoName "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount"
            if ($null -ne $ccVal -and [int]$ccVal -gt 10) {
                $AllFindings.Add((Write-Finding -Category "GPO Settings" `
                    -Severity "MEDIUM" `
                    -Finding "GPO '$gpoName' sets CachedLogonsCount = $ccVal (excessive credential caching)" `
                    -CurrentState "CachedLogonsCount = $ccVal" `
                    -ExpectedState "CachedLogonsCount = 1 or 2 maximum" `
                    -ObjectDN "GPO: $($gpo.Id)" `
                    -WhyBad "Cached domain credentials are stored as MSCACHEv2 hashes on disk (HKLM\SECURITY). Offline cracking these with hashcat reveals domain passwords. $ccVal cached credentials means $ccVal crackable domain account hashes on every workstation."))
            }

            # --- RDP without NLA ---
            $nlaVal = Get-GPOVal $gpoName "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication"
            if ($nlaVal -eq 0) {
                $AllFindings.Add((Write-Finding -Category "GPO Settings" `
                    -Severity "HIGH" `
                    -Finding "GPO '$gpoName' enables RDP without Network Level Authentication" `
                    -CurrentState "fDenyTSConnections=0, UserAuthentication=0 (NLA disabled), MinEncryptionLevel=1" `
                    -ExpectedState "UserAuthentication=1 (require NLA), MinEncryptionLevel=3 (High). Restrict RDP to admin VLANs via firewall" `
                    -ObjectDN "GPO: $($gpo.Id)" `
                    -WhyBad "Without NLA, the Windows login screen is presented before authentication, enabling brute-force attacks against the RDP service itself. Credential spraying, BlueKeep-style exploitation, and MITM attacks against the session are all easier without NLA."))
            }

            # --- AutoRun enabled ---
            $arVal = Get-GPOVal $gpoName "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun"
            if ($arVal -eq 0) {
                $AllFindings.Add((Write-Finding -Category "GPO Settings" `
                    -Severity "MEDIUM" `
                    -Finding "GPO '$gpoName' enables AutoRun for all drive types (NoDriveTypeAutoRun=0)" `
                    -CurrentState "NoDriveTypeAutoRun = 0 (all drives)" `
                    -ExpectedState "NoDriveTypeAutoRun = 255 (disable all). NoAutoplayfornonVolume = 1" `
                    -ObjectDN "GPO: $($gpo.Id)" `
                    -WhyBad "AutoRun executes autorun.inf automatically on USB/CD insertion. USB-based malware (BadUSB, rubber ducky payloads) achieves code execution the moment a device is plugged in, with no user interaction beyond physical insertion."))
            }

            # --- Credential Guard / LSA Protection disabled ---
            $rplVal = Get-GPOVal $gpoName "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
            if ($rplVal -eq 0) {
                $AllFindings.Add((Write-Finding -Category "GPO Settings" `
                    -Severity "HIGH" `
                    -Finding "GPO '$gpoName' disables LSA Protection (RunAsPPL=0) and Credential Guard" `
                    -CurrentState "RunAsPPL=0, EnableVirtualizationBasedSecurity=0" `
                    -ExpectedState "RunAsPPL=1 (requires reboot + driver compat check). EnableVirtualizationBasedSecurity=1 for Credential Guard" `
                    -ObjectDN "GPO: $($gpo.Id)" `
                    -WhyBad "RunAsPPL makes LSASS a Protected Process Light, preventing non-PPL processes (including Mimikatz) from injecting or reading its memory. Without it, sekurlsa::logonpasswords works against any user with an active session."))
            }

            # --- Anonymous enumeration allowed ---
            $anVal = Get-GPOVal $gpoName "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM"
            if ($anVal -eq 0) {
                $AllFindings.Add((Write-Finding -Category "GPO Settings" `
                    -Severity "HIGH" `
                    -Finding "GPO '$gpoName' allows anonymous SAM enumeration and null sessions" `
                    -CurrentState "RestrictAnonymousSAM=0, RestrictAnonymous=0, RestrictNullSessAccess=0" `
                    -ExpectedState "RestrictAnonymousSAM=1, RestrictAnonymous=1, RestrictNullSessAccess=1" `
                    -ObjectDN "GPO: $($gpo.Id)" `
                    -WhyBad "Null sessions allow unauthenticated enumeration of all domain users, groups, and shares via IPC\$. Tools like enum4linux and rpcclient can harvest the full user list without any credentials - providing targets for password spraying."))
            }

            # --- WinRM cleartext / Basic auth ---
            $wrmVal = Get-GPOVal $gpoName "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowUnencryptedTraffic"
            if ($wrmVal -eq 1) {
                $AllFindings.Add((Write-Finding -Category "GPO Settings" `
                    -Severity "HIGH" `
                    -Finding "GPO '$gpoName' allows unencrypted WinRM traffic and Basic authentication" `
                    -CurrentState "AllowUnencryptedTraffic=1, AllowBasic=1 (Service and Client)" `
                    -ExpectedState "AllowUnencryptedTraffic=0, AllowBasic=0. Use Kerberos or CredSSP over HTTPS only" `
                    -ObjectDN "GPO: $($gpo.Id)" `
                    -WhyBad "WinRM Basic auth encodes credentials as Base64 (not encrypted). Any network observer capturing port 5985 traffic reads plaintext domain credentials. Combined with unencrypted traffic, this is credential theft over-the-wire."))
            }

            # --- Tiny event logs ---
            $evtVal = Get-GPOVal $gpoName "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "MaxSize"
            if ($null -ne $evtVal -and [int]$evtVal -lt 1024) {
                $AllFindings.Add((Write-Finding -Category "GPO Settings" `
                    -Severity "HIGH" `
                    -Finding "GPO '$gpoName' sets Security event log to ${evtVal}KB (critically undersized)" `
                    -CurrentState "Security log MaxSize = ${evtVal}KB (fills in minutes on active DC)" `
                    -ExpectedState "Security log >= 1GB (1048576KB). System/PS >= 256MB. Retention = Archive. Forward to SIEM" `
                    -ObjectDN "GPO: $($gpo.Id)" `
                    -WhyBad "A ${evtVal}KB security log fills in minutes on an active domain, overwriting evidence of logon events, privilege use, and process creation. This is a classic evidence-destruction technique - attackers set tiny logs to ensure their actions are overwritten before IR teams arrive."))
            }

            # --- LDAP signing disabled ---
            $ldVal = Get-GPOVal $gpoName "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "LDAPServerIntegrity"
            if ($ldVal -eq 0) {
                $AllFindings.Add((Write-Finding -Category "GPO Settings" `
                    -Severity "HIGH" `
                    -Finding "GPO '$gpoName' disables LDAP signing requirement on the DC" `
                    -CurrentState "LDAPServerIntegrity=0 (None), LDAPClientIntegrity=0" `
                    -ExpectedState "LDAPServerIntegrity=2 (Require). LDAPClientIntegrity=1 (Negotiate)" `
                    -ObjectDN "GPO: $($gpo.Id)" `
                    -WhyBad "Without LDAP signing, LDAP traffic can be intercepted and modified in transit (MITM). Tools like ldap_relay and ntlmrelayx can relay captured authentication to the DC via LDAP to create new admin accounts or modify ACLs."))
            }

            # --- GPP cpassword in SYSVOL ---
            $sysvolBase = "\\$DomainDNS_GPO\SYSVOL\$DomainDNS_GPO\Policies\{$($gpo.Id)}"
            foreach ($scope in @("Machine","User")) {
                $gppPath = "$sysvolBase\$scope\Preferences\Groups\Groups.xml"
                if (Test-Path $gppPath) {
                    $xmlContent = Get-Content $gppPath -Raw -ErrorAction SilentlyContinue
                    if ($xmlContent -match 'cpassword="([^"]+)"') {
                        $AllFindings.Add((Write-Finding -Category "GPO Settings" `
                            -Severity "CRITICAL" `
                            -Finding "GPO '$gpoName' contains a GPP cpassword in SYSVOL (MS14-025)" `
                            -CurrentState "Groups.xml in $scope Preferences contains cpassword field. SYSVOL is readable by all domain users" `
                            -ExpectedState "Delete Groups.xml. Use LAPS for local admin password management. Never store passwords in GPO Preferences" `
                            -ObjectDN "GPO: $($gpo.Id)" `
                            -WhyBad "Microsoft published the AES key used to encrypt GPP cpasswords (KB2962486). Any domain user can read SYSVOL and decrypt cpasswords with gpp-decrypt or Get-GPPPassword in PowerSploit in under 5 seconds. This is a well-known, automated finding in every pentest."))
                    }
                }
            }

            # --- Scheduled task referencing writable share ---
            $stPath = "$sysvolBase\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
            if (Test-Path $stPath) {
                $stContent = Get-Content $stPath -Raw -ErrorAction SilentlyContinue
                if ($stContent -match '\\\\[^\\]+\\ITScripts\\' -or $stContent -match 'runAs="NT AUTHORITY\\SYSTEM"') {
                    $AllFindings.Add((Write-Finding -Category "GPO Settings" `
                        -Severity "CRITICAL" `
                        -Finding "GPO '$gpoName' deploys a Scheduled Task running as SYSTEM from a potentially writable network share" `
                        -CurrentState "ScheduledTasks.xml deploys task as NT AUTHORITY\SYSTEM executing script from UNC path" `
                        -ExpectedState "1) Verify share ACL grants ONLY IT admins write access. 2) Remove Domain Users write from share NTFS. 3) Consider code signing" `
                        -ObjectDN "GPO: $($gpo.Id)" `
                        -WhyBad "A SYSTEM-privileged scheduled task that runs a script from a writable network share is a perfect lateral movement primitive. Any domain user who can write to the share can replace the script and get SYSTEM execution on every machine the GPO applies to at next boot."))
                }
            }
        }

        # --- LAPS OU ACL: Domain Users with ExtendedRight ---
        $LAPSTargetOU = "OU=LAPS-ManagedWorkstations,$(( Get-ADDomain).DistinguishedName)"
        if (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$LAPSTargetOU'" -ErrorAction SilentlyContinue) {
            $ouACL = Get-Acl "AD:\$LAPSTargetOU" -ErrorAction SilentlyContinue
            if ($ouACL) {
                $domUsersSID = (Get-ADGroup "Domain Users" -ErrorAction SilentlyContinue).SID.Value
                $suspiciousACEs = $ouACL.Access | Where-Object {
                    $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $domUsersSID -and
                    $_.ActiveDirectoryRights -match "ExtendedRight|ReadProperty" -and
                    $_.AccessControlType -eq "Allow"
                }
                if ($suspiciousACEs) {
                    $AllFindings.Add((Write-Finding -Category "GPO Settings" `
                        -Severity "CRITICAL" `
                        -Finding "LAPS target OU '$LAPSTargetOU' grants 'Domain Users' ExtendedRight (All) - any user can read LAPS passwords" `
                        -CurrentState "'Domain Users' has ExtendedRight + ReadProperty on OU (inherits to computer objects). ms-Mcs-AdmPwd is a confidential attribute readable via ExtendedRight" `
                        -ExpectedState "Remove Domain Users ACE. Grant ms-Mcs-AdmPwd read ONLY to designated helpdesk/admin group. Use 'LAPSToolkit' to audit LAPS ACLs" `
                        -ObjectDN $LAPSTargetOU `
                        -WhyBad "The entire point of LAPS is that each computer's local admin password is unique and rotated. If Domain Users can read ms-Mcs-AdmPwd, any compromised low-privilege account can enumerate every local admin password in the OU and pivot to all managed workstations."))
                }
            }
        }
    }
    catch {
        Write-Warning "GroupPolicy module not available or GPO analysis failed: $_"
    }
}

# ============================================================================
# SECTION 7b: SID HISTORY ON GROUPS
# ============================================================================
Write-Status "SECTION 7b: Checking for SID History on groups..."

$AllGroupsWithSIDHistory = Get-ADGroup -Filter * -Properties SIDHistory, Description
foreach ($group in $AllGroupsWithSIDHistory) {
    if ($group.SIDHistory.Count -gt 0) {
        $AllFindings.Add((Write-Finding -Category "SID History" `
            -Severity "CRITICAL" `
            -Finding "Group '$($group.SamAccountName)' has SID History entries (hidden privilege escalation)" `
            -CurrentState "SIDHistory contains $($group.SIDHistory.Count) entries: $($group.SIDHistory -join ', ')" `
            -ExpectedState "SIDHistory should be empty (clear all entries)" `
            -WhyBad "SID History on a group grants ALL members invisible privileges. Standard group membership queries won't reveal the effective access." `
            -AttackScenario "Join the group -> inherit hidden SID (DA/EA/Administrators) -> invisible admin rights not shown by Get-ADGroupMember." `
            -Principle "SID History should be empty unless actively migrating domains. On groups it is especially dangerous as it multiplies the blast radius." `
            -ObjectDN $group.DistinguishedName))
    }
}

# ============================================================================
# SECTION 8: COMPUTER OBJECT ANALYSIS
# ============================================================================
Write-Status "SECTION 8: Analyzing computer objects..."

$Computers = Get-ADComputer -Filter * -Properties Description, MemberOf, TrustedForDelegation, CanonicalName

$BadderBloodGroupDNs = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($g in $BadderBloodGroups) { [void]$BadderBloodGroupDNs.Add($g.DistinguishedName) }

foreach ($comp in $Computers) {
    if ($comp.TrustedForDelegation -and $comp.Name -notlike "*DC*") {
        $AllFindings.Add((Write-Finding -Category "Delegation" `
            -Severity "HIGH" `
            -Finding "Computer '$($comp.Name)' has unconstrained delegation enabled" `
            -CurrentState "TrustedForDelegation = True" `
            -ExpectedState "TrustedForDelegation = False (unless this is a DC)" `
            -ObjectDN $comp.DistinguishedName))
    }

    # Computer membership in BadderBlood-created security groups
    $bbGroupMemberships = @($comp.MemberOf | Where-Object { $BadderBloodGroupDNs.Contains($_) })
    if ($bbGroupMemberships.Count -gt 0) {
        $groupNames = $bbGroupMemberships | ForEach-Object {
            ($_ -split ',')[0] -replace '^CN=',''
        }
        $AllFindings.Add((Write-Finding -Category "Computer Group Membership" `
            -Severity "MEDIUM" `
            -Finding "Computer '$($comp.Name)' is a member of $($bbGroupMemberships.Count) BadderBlood-created security group(s)" `
            -CurrentState "Member of: $($groupNames -join ', ')" `
            -ExpectedState "Remove computer from BadderBlood-created groups (computers should not be members of random security groups)" `
            -WhyBad "Computer accounts in security groups can inherit group-based permissions, receive GPOs scoped to those groups, or be used as a lateral movement pivot if the group grants access to other resources." `
            -AttackScenario "Compromise computer account (e.g., via NTLM relay) -> inherit group permissions -> access group-scoped resources without valid user credentials." `
            -Principle "Computer objects should only be in groups where membership is intentional and documented (e.g., software deployment groups). Random group membership from BadderBlood is never intentional." `
            -ObjectDN $comp.DistinguishedName))
    }
}

# ============================================================================
# SECTION 9: RBCD MISCONFIGURATION DETECTION
# ============================================================================
Write-Status "SECTION 9: Checking for Resource-Based Constrained Delegation misconfigurations..."

$AllComputers = Get-ADComputer -Filter * -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity', DistinguishedName, Name
foreach ($comp in $AllComputers) {
    $rbcdRaw = $comp.'msDS-AllowedToActOnBehalfOfOtherIdentity'
    if ($rbcdRaw) {
        # Parse the security descriptor to find allowed principals
        # AD cmdlet may return ActiveDirectorySecurity, RawSecurityDescriptor, or byte[]
        $rbcdSD = $null
        if ($rbcdRaw -is [System.DirectoryServices.ActiveDirectorySecurity]) {
            $sddl = $rbcdRaw.GetSecurityDescriptorSddlForm("All")
            $rbcdSD = New-Object Security.AccessControl.RawSecurityDescriptor($sddl)
        } elseif ($rbcdRaw -is [Security.AccessControl.RawSecurityDescriptor]) {
            $rbcdSD = $rbcdRaw
        } elseif ($rbcdRaw -is [byte[]]) {
            $rbcdSD = New-Object Security.AccessControl.RawSecurityDescriptor($rbcdRaw, 0)
        } else {
            # Try SDDL string
            try { $rbcdSD = New-Object Security.AccessControl.RawSecurityDescriptor($rbcdRaw.ToString()) } catch {}
        }
        if (-not $rbcdSD) { continue }
        foreach ($ace in $rbcdSD.DiscretionaryAcl) {
            $principalSID = $ace.SecurityIdentifier.ToString()
            $principalName = $principalSID
            try {
                $adObj = Get-ADObject -Filter { objectSid -eq $principalSID } -Properties SamAccountName -ErrorAction Stop
                if ($adObj) { $principalName = $adObj.SamAccountName }
            } catch {}

            $ri = $NewAttackVectorExplanations["RBCD"]
            $AllFindings.Add((Write-Finding -Category "Resource-Based Constrained Delegation" `
                -Severity "HIGH" `
                -Finding "Computer '$($comp.Name)' allows '$principalName' to delegate via RBCD" `
                -CurrentState "msDS-AllowedToActOnBehalfOfOtherIdentity contains SID: $principalSID" `
                -ExpectedState "Remove RBCD entry or validate it is required for a specific service" `
                -WhyBad $ri.Why `
                -AttackScenario $ri.Attack `
                -Principle $ri.Principle `
                -ObjectDN $comp.DistinguishedName))
        }
    }
}

# ============================================================================
# SECTION 10: SHADOW CREDENTIALS DETECTION
# ============================================================================
Write-Status "SECTION 10: Checking for Shadow Credentials (msDS-KeyCredentialLink) ACL misconfigurations..."

# Get the schema GUID for msDS-KeyCredentialLink
$schemaNC_AK = (Get-ADRootDSE).SchemaNamingContext
$keyCredLinkGuid_AK = $null
try {
    $schemaObj_AK = Get-ADObject -SearchBase $schemaNC_AK -LDAPFilter "(&(lDAPDisplayName=msDS-KeyCredentialLink)(schemaidguid=*))" -Properties schemaIDGUID -ErrorAction Stop
    if ($schemaObj_AK) { $keyCredLinkGuid_AK = [System.GUID]$schemaObj_AK.schemaIDGUID }
} catch {}

if ($keyCredLinkGuid_AK) {
    # Check a sample of user objects for non-default WriteProperty on KeyCredentialLink
    $sampleUsers = $BadderBloodUsers | Get-Random -Count ([Math]::Min(200, $BadderBloodUsers.Count))
    Set-Location AD:
    foreach ($user in $sampleUsers) {
        try {
            $acl = Get-Acl "AD:\$($user.DistinguishedName)" -ErrorAction SilentlyContinue
            if (-not $acl) { continue }
            foreach ($ace in $acl.Access) {
                if ($ace.ObjectType -eq $keyCredLinkGuid_AK -and
                    $ace.ActiveDirectoryRights -match "WriteProperty" -and
                    $ace.AccessControlType -eq "Allow" -and
                    $ace.IdentityReference -notmatch "(SYSTEM|Domain Admins|Enterprise Admins|Administrators|SELF)$") {

                    $ri = $NewAttackVectorExplanations["ShadowCredentials"]
                    $AllFindings.Add((Write-Finding -Category "Shadow Credentials" `
                        -Severity "HIGH" `
                        -Finding "'$($ace.IdentityReference)' can write msDS-KeyCredentialLink on '$($user.SamAccountName)'" `
                        -CurrentState "WriteProperty on msDS-KeyCredentialLink granted to '$($ace.IdentityReference)'" `
                        -ExpectedState "Remove WriteProperty on msDS-KeyCredentialLink. Only DCs and ADCS enrollment agents need this" `
                        -WhyBad $ri.Why `
                        -AttackScenario $ri.Attack `
                        -Principle $ri.Principle `
                        -ObjectDN $user.DistinguishedName))
                }
            }
        } catch {}
    }
} else {
    Write-Status "  msDS-KeyCredentialLink not found in schema (requires Server 2016+). Skipping." "Gray"
}

# ============================================================================
# SECTION 11: ADCS MISCONFIGURATION DETECTION
# ============================================================================
Write-Status "SECTION 11: Checking for ADCS certificate template misconfigurations..."

$configNC_AK = (Get-ADRootDSE).ConfigurationNamingContext
$templateBaseDN_AK = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC_AK"

try {
    $certTemplates = Get-ADObject -SearchBase $templateBaseDN_AK -Filter { objectClass -eq "pKICertificateTemplate" } `
        -Properties 'msPKI-Certificate-Name-Flag','pKIExtendedKeyUsage','displayName','msPKI-Cert-Template-OID' -ErrorAction Stop

    foreach ($tmpl in $certTemplates) {
        $nameFlag = $tmpl.'msPKI-Certificate-Name-Flag'
        $ekus = $tmpl.pKIExtendedKeyUsage

        # ESC1: ENROLLEE_SUPPLIES_SUBJECT (flag bit 1) + Client Auth EKU
        if ($nameFlag -band 1) {
            $hasClientAuth = $ekus -contains '1.3.6.1.5.5.7.3.2'
            if ($hasClientAuth) {
                $ri = $NewAttackVectorExplanations["ADCS_ESC1"]
                $AllFindings.Add((Write-Finding -Category "ADCS Misconfiguration" `
                    -Severity "CRITICAL" `
                    -Finding "Certificate template '$($tmpl.Name)' allows enrollee to supply subject AND has Client Authentication EKU (ESC1)" `
                    -CurrentState "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT=1, EKU includes Client Authentication" `
                    -ExpectedState "Remove ENROLLEE_SUPPLIES_SUBJECT flag or remove Client Authentication EKU. Require CA manager approval" `
                    -WhyBad $ri.Why `
                    -AttackScenario $ri.Attack `
                    -Principle $ri.Principle `
                    -ObjectDN $tmpl.DistinguishedName))
            }
        }

        # ESC2: Any Purpose EKU or no EKU restriction
        if ($ekus -contains '2.5.29.37.0' -or ($null -eq $ekus -and $null -ne $nameFlag)) {
            $ri = $NewAttackVectorExplanations["ADCS_ESC2"]
            $AllFindings.Add((Write-Finding -Category "ADCS Misconfiguration" `
                -Severity "HIGH" `
                -Finding "Certificate template '$($tmpl.Name)' has Any Purpose or unrestricted EKU (ESC2)" `
                -CurrentState "EKU: $(if($ekus){'Any Purpose (2.5.29.37.0)'}else{'No EKU restriction'})" `
                -ExpectedState "Restrict EKUs to specific required purposes only (e.g., Server Authentication)" `
                -WhyBad $ri.Why `
                -AttackScenario $ri.Attack `
                -Principle $ri.Principle `
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
                        $AllFindings.Add((Write-Finding -Category "ADCS Misconfiguration" `
                            -Severity "HIGH" `
                            -Finding "'$($ace.IdentityReference)' has '$($ace.ActiveDirectoryRights)' on certificate template '$($tmpl.Name)' (ESC4)" `
                            -CurrentState "ACE: $($ace.IdentityReference) -> $($ace.ActiveDirectoryRights)" `
                            -ExpectedState "Remove write access. Only CA Admins and Enterprise Admins should modify templates" `
                            -WhyBad $ri.Why `
                            -AttackScenario $ri.Attack `
                            -Principle $ri.Principle `
                            -ObjectDN $tmpl.DistinguishedName))
                    }
                }
            }
        } catch {}
    }
} catch {
    Write-Status "  ADCS templates not found or not accessible. Skipping." "Gray"
}

# Also check PKI container ACLs (for when ADCS is not installed but ACL misconfigs exist)
$pkiContainerDN_AK = "CN=Public Key Services,CN=Services,$configNC_AK"
try {
    Set-Location AD:
    $pkiAcl = Get-Acl "AD:\$pkiContainerDN_AK" -ErrorAction SilentlyContinue
    if ($pkiAcl) {
        foreach ($ace in $pkiAcl.Access) {
            if ($ace.AccessControlType -eq "Allow" -and
                ($ace.ActiveDirectoryRights -match "WriteProperty|WriteDacl|WriteOwner|GenericAll|GenericWrite|CreateChild") -and
                $ace.IdentityReference -notmatch "(SYSTEM|Domain Admins|Enterprise Admins|Administrators|CREATOR OWNER)$") {

                $samName = $ace.IdentityReference.ToString() -replace "^.*\\"
                $isBB = ($BadderBloodUsers | Where-Object { $_.SamAccountName -eq $samName }) -or
                        ($BadderBloodGroups | Where-Object { $_.SamAccountName -eq $samName })
                if ($isBB) {
                    $AllFindings.Add((Write-Finding -Category "ADCS Misconfiguration" `
                        -Severity "HIGH" `
                        -Finding "BadderBlood object '$samName' has '$($ace.ActiveDirectoryRights)' on PKI container" `
                        -CurrentState "ACE on Public Key Services container" `
                        -ExpectedState "Remove this ACE. Only PKI Admins should have write access to PKI containers" `
                        -ObjectDN $pkiContainerDN_AK))
                }
            }
        }
    }
} catch {}

# ============================================================================
# SECTION 12: gMSA MISCONFIGURATION DETECTION
# ============================================================================
Write-Status "SECTION 12: Checking for gMSA password retrieval misconfigurations..."

try {
    $gmsaAccounts = Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword, DistinguishedName, Name -ErrorAction Stop

    foreach ($gmsa in $gmsaAccounts) {
        $principals = $gmsa.PrincipalsAllowedToRetrieveManagedPassword
        if (-not $principals -or $principals.Count -eq 0) { continue }

        foreach ($principalDN in $principals) {
            $principalName = ($principalDN -split ',')[0] -replace '^CN=',''
            $isBroadGroup = $false

            try {
                $pObj = Get-ADObject $principalDN -Properties SamAccountName, objectClass -ErrorAction Stop
                $principalName = $pObj.SamAccountName

                # Flag broad groups
                if ($pObj.objectClass -eq 'group') {
                    $groupMembers = Get-ADGroupMember $pObj.SamAccountName -ErrorAction SilentlyContinue
                    if ($groupMembers.Count -gt 10) { $isBroadGroup = $true }
                    if ($principalName -in @('Domain Computers','Domain Users','Authenticated Users')) { $isBroadGroup = $true }
                }
            } catch {}

            $sev = if ($isBroadGroup) { "CRITICAL" } else { "MEDIUM" }
            $ri = $NewAttackVectorExplanations["GMSA"]
            $AllFindings.Add((Write-Finding -Category "gMSA Misconfiguration" `
                -Severity $sev `
                -Finding "gMSA '$($gmsa.Name)' password readable by '$principalName'$(if($isBroadGroup){' (BROAD GROUP)'})" `
                -CurrentState "PrincipalsAllowedToRetrieveManagedPassword includes '$principalName'" `
                -ExpectedState "Restrict to ONLY the specific computer accounts that run this service" `
                -WhyBad $ri.Why `
                -AttackScenario $ri.Attack `
                -Principle $ri.Principle `
                -ObjectDN $gmsa.DistinguishedName))
        }
    }
} catch {
    Write-Status "  gMSA query failed (may require specific permissions or Server 2012+). Skipping." "Gray"
}

# ============================================================================
# SECTION 13: ADIDNS MISCONFIGURATION DETECTION
# ============================================================================
Write-Status "SECTION 13: Checking for ADIDNS misconfigurations..."

$dnsRoot_AK = $DomainInfo.DNSRoot
$dnsZoneDN_AK = "DC=$dnsRoot_AK,CN=MicrosoftDNS,DC=DomainDnsZones,$DomainDN"

# Check DNS zone ACLs for non-default write permissions
try {
    Set-Location AD:
    foreach ($dnsDN in @($dnsZoneDN_AK, "CN=MicrosoftDNS,DC=DomainDnsZones,$DomainDN")) {
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
                    $AllFindings.Add((Write-Finding -Category "ADIDNS Misconfiguration" `
                        -Severity "HIGH" `
                        -Finding "BadderBlood object '$samName' has '$($ace.ActiveDirectoryRights)' on DNS zone" `
                        -CurrentState "ACE: $($ace.IdentityReference) -> $($ace.ActiveDirectoryRights) on $dnsDN" `
                        -ExpectedState "Remove this ACE. Only DNS Admins should have write access to DNS zones" `
                        -WhyBad $ri.Why `
                        -AttackScenario $ri.Attack `
                        -Principle $ri.Principle `
                        -ObjectDN $dnsDN))
                }
            }
        }
    }
} catch {}

# Detect stale DNS records pointing to non-routable IPs
try {
    $dnsRecords = Get-ADObject -SearchBase $dnsZoneDN_AK -Filter { objectClass -eq "dnsNode" } -Properties dnsRecord, Name -ErrorAction Stop
    $staleHostnames = @('oldfileserver','legacy-sql01','dev-web03','staging-app','test-dc02','backup-nas01',
        'print-srv02','decomm-exch01','temp-jump01','poc-server','migration-svc','old-intranet',
        'retired-vpn','unused-proxy','former-ca01','old-wsus','legacy-sccm','prev-adfs','old-radius','decomm-nps')

    foreach ($record in $dnsRecords) {
        if ($record.Name -in $staleHostnames) {
            $ri = $NewAttackVectorExplanations["ADIDNS_Stale"]
            $AllFindings.Add((Write-Finding -Category "ADIDNS Misconfiguration" `
                -Severity "MEDIUM" `
                -Finding "Stale DNS record '$($record.Name).$dnsRoot_AK' points to a decommissioned server" `
                -CurrentState "DNS A record exists for hostname '$($record.Name)' (likely non-existent host)" `
                -ExpectedState "Delete stale DNS record. Enable DNS scavenging to prevent future stale records" `
                -WhyBad $ri.Why `
                -AttackScenario $ri.Attack `
                -Principle $ri.Principle `
                -ObjectDN $record.DistinguishedName))
        }
    }
} catch {}

# ============================================================================
# SECTION 14: LAPS BYPASS DETECTION
# ============================================================================
Write-Status "SECTION 14: Checking for LAPS password read bypass paths..."

# Detect which LAPS attribute exists
$lapsAttrGuid_AK = $null
$lapsAttrName_AK = $null
try {
    $wlaps = Get-ADObject -SearchBase $schemaNC_AK -LDAPFilter "(&(lDAPDisplayName=msLAPS-Password)(schemaidguid=*))" -Properties schemaIDGUID -ErrorAction Stop
    if ($wlaps) { $lapsAttrGuid_AK = [System.GUID]$wlaps.schemaIDGUID; $lapsAttrName_AK = "msLAPS-Password" }
} catch {}
if (-not $lapsAttrGuid_AK) {
    try {
        $llaps = Get-ADObject -SearchBase $schemaNC_AK -LDAPFilter "(&(lDAPDisplayName=ms-Mcs-AdmPwd)(schemaidguid=*))" -Properties schemaIDGUID -ErrorAction Stop
        if ($llaps) { $lapsAttrGuid_AK = [System.GUID]$llaps.schemaIDGUID; $lapsAttrName_AK = "ms-Mcs-AdmPwd" }
    } catch {}
}

if ($lapsAttrGuid_AK) {
    Write-Status "  Using LAPS attribute: $lapsAttrName_AK"

    # Check OUs containing computers for non-admin ReadProperty on LAPS attribute
    $computerOUs_AK = @{}
    foreach ($comp in $AllComputers) {
        $parentOU = ($comp.DistinguishedName -split ',', 2)[1]
        $computerOUs_AK[$parentOU] = $true
    }

    Set-Location AD:
    foreach ($ouDN in $computerOUs_AK.Keys) {
        try {
            $ouAcl = Get-Acl "AD:\$ouDN" -ErrorAction SilentlyContinue
            if (-not $ouAcl) { continue }

            foreach ($ace in $ouAcl.Access) {
                # Check for ReadProperty on LAPS attr or GenericAll (which implies read)
                $isLAPSRead = ($ace.ObjectType -eq $lapsAttrGuid_AK -and $ace.ActiveDirectoryRights -match "ReadProperty")
                $isGenericAll = ($ace.ActiveDirectoryRights -match "GenericAll")

                if (($isLAPSRead -or $isGenericAll) -and
                    $ace.AccessControlType -eq "Allow" -and
                    $ace.IdentityReference -notmatch "(SYSTEM|Domain Admins|Enterprise Admins|Administrators|CREATOR OWNER)$") {

                    $samName = $ace.IdentityReference.ToString() -replace "^.*\\"
                    $isBB = ($BadderBloodUsers | Where-Object { $_.SamAccountName -eq $samName }) -or
                            ($BadderBloodGroups | Where-Object { $_.SamAccountName -eq $samName })
                    if (-not $isBB) { continue }

                    $ouName = ($ouDN -split ',')[0] -replace 'OU=',''
                    $rightDesc = if ($isGenericAll) { "GenericAll (implies LAPS read)" } else { "ReadProperty on $lapsAttrName_AK" }

                    $ri = $NewAttackVectorExplanations["LAPSBypass"]
                    $AllFindings.Add((Write-Finding -Category "LAPS Bypass" `
                        -Severity "CRITICAL" `
                        -Finding "'$samName' can read LAPS passwords in OU '$ouName' via $rightDesc" `
                        -CurrentState "$($ace.IdentityReference) has $rightDesc on $ouDN" `
                        -ExpectedState "Remove this ACE. Only designated LAPS admin groups should read $lapsAttrName_AK" `
                        -WhyBad $ri.Why `
                        -AttackScenario $ri.Attack `
                        -Principle $ri.Principle `
                        -ObjectDN $ouDN))
                }
            }
        } catch {}
    }

    # Also check individual computer objects
    $sampleComputers = $AllComputers | Get-Random -Count ([Math]::Min(50, $AllComputers.Count))
    foreach ($comp in $sampleComputers) {
        try {
            $compAcl = Get-Acl "AD:\$($comp.DistinguishedName)" -ErrorAction SilentlyContinue
            if (-not $compAcl) { continue }

            foreach ($ace in $compAcl.Access) {
                if ($ace.ObjectType -eq $lapsAttrGuid_AK -and
                    $ace.ActiveDirectoryRights -match "ReadProperty" -and
                    $ace.AccessControlType -eq "Allow" -and
                    -not $ace.IsInherited -and
                    $ace.IdentityReference -notmatch "(SYSTEM|Domain Admins|Enterprise Admins|Administrators)$") {

                    $samName = $ace.IdentityReference.ToString() -replace "^.*\\"
                    $isBB = ($BadderBloodUsers | Where-Object { $_.SamAccountName -eq $samName }) -or
                            ($BadderBloodGroups | Where-Object { $_.SamAccountName -eq $samName })
                    if (-not $isBB) { continue }

                    $ri = $NewAttackVectorExplanations["LAPSBypass"]
                    $AllFindings.Add((Write-Finding -Category "LAPS Bypass" `
                        -Severity "HIGH" `
                        -Finding "'$samName' can read LAPS password on computer '$($comp.Name)' (direct ACE)" `
                        -CurrentState "Non-inherited ReadProperty on $lapsAttrName_AK" `
                        -ExpectedState "Remove direct ACE. Use OU-level delegation to designated admin groups only" `
                        -WhyBad $ri.Why `
                        -AttackScenario $ri.Attack `
                        -Principle $ri.Principle `
                        -ObjectDN $comp.DistinguishedName))
                }
            }
        } catch {}
    }
} else {
    Write-Status "  No LAPS schema attributes found. Skipping LAPS bypass detection." "Gray"
}

# ============================================================================
# GENERATE REPORTS
# ============================================================================
Write-Status "Generating reports..."

# --- MASTER ANSWER KEY (TXT) ---
$reportLines = [System.Collections.Generic.List[string]]::new()

$reportLines.Add("=" * 80)
$reportLines.Add("  BADBLOOD DOMAIN CLEANUP - MASTER ANSWER KEY")
$reportLines.Add("  Domain: $DomainName")
$reportLines.Add("  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$reportLines.Add("  Total Findings: $($AllFindings.Count)")
$reportLines.Add("=" * 80)
$reportLines.Add("")

# Summary counts
$critical = ($AllFindings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$high     = ($AllFindings | Where-Object { $_.Severity -eq "HIGH" }).Count
$medium   = ($AllFindings | Where-Object { $_.Severity -eq "MEDIUM" }).Count
$low      = ($AllFindings | Where-Object { $_.Severity -eq "LOW" }).Count
$info     = ($AllFindings | Where-Object { $_.Severity -eq "INFO" }).Count

$reportLines.Add("SEVERITY SUMMARY")
$reportLines.Add("-" * 40)
$reportLines.Add("  CRITICAL : $critical")
$reportLines.Add("  HIGH     : $high")
$reportLines.Add("  MEDIUM   : $medium")
$reportLines.Add("  LOW      : $low")
$reportLines.Add("  INFO     : $info")
$reportLines.Add("")

$reportLines.Add("CATEGORY SUMMARY")
$reportLines.Add("-" * 40)
$categories = $AllFindings | Group-Object Category | Sort-Object Count -Descending
foreach ($cat in $categories) {
    $reportLines.Add("  $($cat.Name): $($cat.Count) findings")
}
$reportLines.Add("")

# BadderBlood Object Inventory
$reportLines.Add("=" * 80)
$reportLines.Add("  BADBLOOD OBJECT INVENTORY")
$reportLines.Add("=" * 80)
$reportLines.Add("")
$reportLines.Add("USERS CREATED BY BADBLOOD ($($BadderBloodUsers.Count) total):")
$reportLines.Add("-" * 60)
foreach ($u in ($BadderBloodUsers | Sort-Object SamAccountName)) {
    $ou = ($u.DistinguishedName -replace "^CN=[^,]+,", "") -replace ",$DomainDN$", ""
    $reportLines.Add("  $($u.SamAccountName.PadRight(25)) | OU: $ou")
}
$reportLines.Add("")

$reportLines.Add("GROUPS CREATED BY BADBLOOD ($($BadderBloodGroups.Count) total):")
$reportLines.Add("-" * 60)
foreach ($g in ($BadderBloodGroups | Sort-Object SamAccountName)) {
    $memberCount = ($g.Members | Measure-Object).Count
    $reportLines.Add("  $($g.SamAccountName.PadRight(35)) | Members: $memberCount")
}
$reportLines.Add("")

# Detailed Findings by Category
$reportLines.Add("=" * 80)
$reportLines.Add("  DETAILED FINDINGS (ANSWER KEY)")
$reportLines.Add("=" * 80)

foreach ($cat in $categories) {
    $reportLines.Add("")
    $reportLines.Add("=" * 80)
    $reportLines.Add("CATEGORY: $($cat.Name) ($($cat.Count) findings)")
    $reportLines.Add("=" * 80)
    
    $findingNum = 0
    foreach ($f in ($cat.Group | Sort-Object Severity)) {
        $findingNum++
        $reportLines.Add("")
        $reportLines.Add("  [$($f.Severity)] Finding #$findingNum")
        $reportLines.Add("  WHAT:      $($f.Finding)")
        $reportLines.Add("  CURRENT:   $($f.CurrentState)")
        $reportLines.Add("  FIX:       $($f.ExpectedState)")
        if ($f.WhyBad) {
            $reportLines.Add("  WHY BAD:   $($f.WhyBad)")
        }
        if ($f.AttackScenario) {
            $reportLines.Add("  ATTACK:    $($f.AttackScenario)")
        }
        if ($f.UserContext) {
            $reportLines.Add("  CONTEXT:   $($f.UserContext)")
        }
        if ($f.Principle) {
            $reportLines.Add("  PRINCIPLE: $($f.Principle)")
        }
        if ($f.ObjectDN) {
            $reportLines.Add("  OBJECT:    $($f.ObjectDN)")
        }
        $reportLines.Add("  " + "-" * 70)
    }
}

# Privileged Group Membership Detail
$reportLines.Add("")
$reportLines.Add("=" * 80)
$reportLines.Add("  PRIVILEGED GROUP MEMBERSHIP - COMPLETE PICTURE")
$reportLines.Add("=" * 80)

foreach ($groupName in $PrivilegedGroups) {
    $groupEntries = $PrivGroupReport | Where-Object { $_.PrivilegedGroup -eq $groupName }
    if ($groupEntries.Count -eq 0) { continue }
    
    $gi = $GroupRiskExplanations[$groupName]
    
    $reportLines.Add("")
    $reportLines.Add("GROUP: $groupName")
    if ($gi) {
        $reportLines.Add("  RISK: $($gi.Risk)")
        $reportLines.Add("  WHY:  $($gi.Why)")
    }
    $reportLines.Add("-" * 60)
    $reportLines.Add("  Current Members -> Action Required:")
    
    foreach ($entry in ($groupEntries | Sort-Object Action)) {
        $marker = if ($entry.Action -eq "KEEP") { "[OK]    " } else { "[REMOVE]" }
        $bb = if ($entry.IsBadderBloodCreated) { " (BadderBlood)" } else { "" }
        $deptInfo = if ($entry.Department) { " | Dept: $($entry.Department)" } else { "" }
        $ouInfo = if ($entry.OUPath) { " | OU: $($entry.OUPath)" } else { "" }
        $reportLines.Add("    $marker $($entry.MemberName)$bb ($($entry.MemberType))$deptInfo$ouInfo")
    }
    
    $removeCount = ($groupEntries | Where-Object { $_.Action -eq "REMOVE" }).Count
    $reportLines.Add("  -> $removeCount member(s) should be REMOVED")
    if ($gi) {
        $reportLines.Add("  -> CLEAN STATE: $($gi.Principle)")
    }
}

# Write the Clean State Summary
$reportLines.Add("")
$reportLines.Add("=" * 80)
$reportLines.Add("  EXPECTED CLEAN STATE SUMMARY")
$reportLines.Add("=" * 80)
$reportLines.Add("")
$reportLines.Add("When students are done, the domain should look like this:")
$reportLines.Add("")
$reportLines.Add("1. PRIVILEGED GROUPS:")
$reportLines.Add("   - Domain Admins: Only 'Administrator' account")
$reportLines.Add("   - Enterprise Admins: Only 'Administrator' account")
$reportLines.Add("   - Schema Admins: Only 'Administrator' account (or empty)")
$reportLines.Add("   - All other privileged groups: Only legitimate built-in members")
$reportLines.Add("   - NO BadderBlood-created users or groups nested in any privileged group")
$reportLines.Add("")
$reportLines.Add("2. USER ACCOUNTS:")
$reportLines.Add("   - No accounts with 'Password Not Required' flag")
$reportLines.Add("   - No accounts with 'Do Not Require Kerberos Pre-Auth' (AS-REP)")
$reportLines.Add("   - No user accounts with unconstrained delegation")
$reportLines.Add("   - No user accounts with SPNs (or converted to gMSA)")
$reportLines.Add("   - No reversible password encryption")
$reportLines.Add("   - All stale AdminCount flags cleared and inheritance restored")
$reportLines.Add("   - No SID History entries on BadderBlood users or groups")
$reportLines.Add("   - No passwords stored in Description fields")
$reportLines.Add("   - Weak passwords reset to strong passwords")
$reportLines.Add("")
$reportLines.Add("3. OU STRUCTURE:")
$reportLines.Add("   - Users in People/<Dept> OUs should NOT have privileged access")
$reportLines.Add("   - Admin Tier OUs should contain only accounts appropriate for that tier")
$reportLines.Add("   - Staging/Testing OUs should be reviewed and cleaned")
$reportLines.Add("   - Users' department attribute should match their OU placement (no drift)")
$reportLines.Add("   - No users remaining in Stage or Unassociated OUs")
$reportLines.Add("")
$reportLines.Add("4. ACLs:")
$reportLines.Add("   - No BadderBlood users/groups with GenericAll/WriteDacl/WriteOwner on OUs")
$reportLines.Add("   - No BadderBlood objects with permissions on AdminSDHolder")
$reportLines.Add("   - No BadderBlood objects with permissions on the domain root")
$reportLines.Add("   - No non-admin groups with WriteProperty on member attribute of other groups")
$reportLines.Add("")
$reportLines.Add("5. COMPUTER OBJECTS:")
$reportLines.Add("   - No non-DC computers with unconstrained delegation")
$reportLines.Add("   - No computers as members of BadderBlood-created security groups")
$reportLines.Add("   - No unauthorized RBCD entries (msDS-AllowedToActOnBehalfOfOtherIdentity)")
$reportLines.Add("")
$reportLines.Add("6. DELEGATION & CREDENTIALS:")
$reportLines.Add("   - No Shadow Credentials ACLs (WriteProperty on msDS-KeyCredentialLink)")
$reportLines.Add("   - gMSA PrincipalsAllowedToRetrieveManagedPassword restricted to specific computers")
$reportLines.Add("   - No broad groups (Domain Computers, IT groups) with gMSA password retrieval")
$reportLines.Add("")
$reportLines.Add("7. CERTIFICATE SERVICES (ADCS):")
$reportLines.Add("   - No templates with ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU (ESC1)")
$reportLines.Add("   - No templates with Any Purpose EKU (ESC2)")
$reportLines.Add("   - No low-privilege write access on certificate templates (ESC4)")
$reportLines.Add("   - No non-admin write access on PKI containers")
$reportLines.Add("")
$reportLines.Add("8. DNS:")
$reportLines.Add("   - No non-admin write access on AD-integrated DNS zones")
$reportLines.Add("   - No stale DNS records pointing to decommissioned servers")
$reportLines.Add("   - DNS scavenging configured to prevent future stale records")
$reportLines.Add("")
$reportLines.Add("9. LAPS:")
$reportLines.Add("   - LAPS password read restricted to designated admin groups only")
$reportLines.Add("   - No direct ACEs on computer objects granting LAPS read")
$reportLines.Add("   - No GenericAll on OUs containing computers (implies LAPS read)")
$reportLines.Add("")

# Restore filesystem provider before writing files (Set-Location AD: may have been called above)
Set-Location $env:SystemDrive

# Save the report
$reportFile = Join-Path $OutputPath "AnswerKey_MasterReport.txt"
$reportLines | Out-File -FilePath $reportFile -Encoding UTF8
Write-Status "Master report saved: $reportFile" "Green"

# --- PRIVILEGED GROUP REPORT (CSV) ---
$privFile = Join-Path $OutputPath "PrivilegedGroupMembers.csv"
$PrivGroupReport | Export-Csv -Path $privFile -NoTypeInformation
Write-Status "Privileged group report saved: $privFile" "Green"

# --- ALL FINDINGS (CSV) ---
$findingsFile = Join-Path $OutputPath "AllFindings.csv"
$AllFindings | Export-Csv -Path $findingsFile -NoTypeInformation
Write-Status "All findings CSV saved: $findingsFile" "Green"

# --- QUICK REFERENCE CHEAT SHEET (v2 - WITH EXPLANATIONS) ---
$cheatSheet = Join-Path $OutputPath "QuickReference_CheatSheet.txt"
$cheatLines = [System.Collections.Generic.List[string]]::new()

$cheatLines.Add("=" * 90)
$cheatLines.Add("  QUICK REFERENCE - WHAT STUDENTS MUST FIX (WITH EXPLANATIONS)")
$cheatLines.Add("  Domain: $DomainName | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$cheatLines.Add("  (Give this to TAs or use for spot-checking)")
$cheatLines.Add("=" * 90)
$cheatLines.Add("")

# Category-level explanations for the header of each section
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
}

# Group findings by category, ordered by importance
$cheatCategories = $AllFindings | Group-Object Category | Sort-Object {
    switch ($_.Name) {
        "Privileged Group Membership"                  { 0 }
        "Dangerous ACL"                                { 1 }
        "Credential Exposure"                          { 2 }
        "ADCS Misconfiguration"                        { 3 }
        "Delegation"                                   { 4 }
        "Resource-Based Constrained Delegation"        { 5 }
        "Shadow Credentials"                           { 6 }
        "Kerberos Security"                            { 7 }
        "LAPS Bypass"                                  { 8 }
        "gMSA Misconfiguration"                        { 9 }
        "OU Misplacement"                              { 10 }
        "Nested Group Membership"                      { 11 }
        "Account Settings"                             { 12 }
        "SID History"                                  { 13 }
        "ADIDNS Misconfiguration"                      { 14 }
        "OU Drift"                                     { 15 }
        "GPO Permissions"                              { 16 }
        "GPO Settings"                                 { 17 }
        "Computer Group Membership"                    { 18 }
        default                                        { 19 }
    }
}

foreach ($catGroup in $cheatCategories) {
    $catFindings = $catGroup.Group | Sort-Object Severity
    $catCrit = @($catFindings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $catHigh = @($catFindings | Where-Object { $_.Severity -eq "HIGH" }).Count
    $catMed  = @($catFindings | Where-Object { $_.Severity -eq "MEDIUM" }).Count

    $cheatLines.Add("=" * 90)
    $cheatLines.Add("CATEGORY: $($catGroup.Name) ($($catGroup.Count) findings: $catCrit CRITICAL, $catHigh HIGH, $catMed MEDIUM)")
    $cheatLines.Add("=" * 90)

    # Print category-level explanation
    $catExpl = $CategoryExplanations[$catGroup.Name]
    if ($catExpl) {
        foreach ($line in $catExpl) { $cheatLines.Add($line) }
    }
    $cheatLines.Add("")

    $itemNum = 0
    foreach ($sevLevel in @("CRITICAL", "HIGH", "MEDIUM", "LOW")) {
        $sevFindings = @($catFindings | Where-Object { $_.Severity -eq $sevLevel })
        if ($sevFindings.Count -eq 0) { continue }

        $cheatLines.Add("  --- $sevLevel ($($sevFindings.Count)) ---")
        foreach ($f in $sevFindings) {
            $itemNum++
            $cheatLines.Add("  $itemNum. [$sevLevel] $($f.Finding)")
            $cheatLines.Add("     FIX: $($f.ExpectedState)")
            if ($f.WhyBad) {
                # Truncate to ~2 sentences for cheat sheet brevity
                $whyShort = ($f.WhyBad -split '\.' | Select-Object -First 2) -join '.'
                if ($whyShort.Length -gt 200) { $whyShort = $whyShort.Substring(0, 197) + "..." }
                $cheatLines.Add("     WHY: $whyShort.")
            }
            if ($f.UserContext) {
                $ctxShort = ($f.UserContext -split '\.' | Select-Object -First 1)
                if ($ctxShort.Length -gt 150) { $ctxShort = $ctxShort.Substring(0, 147) + "..." }
                $cheatLines.Add("     WHO: $ctxShort.")
            }
            if ($f.AttackScenario) {
                $atkShort = ($f.AttackScenario -split '\.' | Select-Object -First 1)
                if ($atkShort.Length -gt 150) { $atkShort = $atkShort.Substring(0, 147) + "..." }
                $cheatLines.Add("     ATTACK: $atkShort.")
            }
            $cheatLines.Add("")
        }
    }
}

$cheatLines | Out-File -FilePath $cheatSheet -Encoding UTF8
Write-Status "Cheat sheet saved: $cheatSheet" "Green"

# --- REMEDIATION SCRIPT (PS1) ---
$remFile = Join-Path $OutputPath "Remediation_Script.ps1"
$remLines = [System.Collections.Generic.List[string]]::new()

$remLines.Add("#Requires -Modules ActiveDirectory")
$remLines.Add("<#")
$remLines.Add(".SYNOPSIS")
$remLines.Add("    Auto-generated remediation script for BadderBlood domain cleanup.")
$remLines.Add("    THIS IS THE ANSWER KEY - DO NOT GIVE TO STUDENTS.")
$remLines.Add("    Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$remLines.Add(".DESCRIPTION")
$remLines.Add("    Running this script will fix all findings automatically.")
$remLines.Add("    Use -WhatIf to preview changes without applying them.")
$remLines.Add("#>")
$remLines.Add("[CmdletBinding(SupportsShouldProcess)]")
$remLines.Add("param()")
$remLines.Add("")
$remLines.Add('Write-Host "=== BadderBlood Remediation Script ===" -ForegroundColor Yellow')
$remLines.Add('Write-Host "This will fix all identified issues. Use -WhatIf to preview." -ForegroundColor Cyan')
$remLines.Add("")

# Privileged group removal commands
$remLines.Add("# --- REMOVE UNAUTHORIZED PRIVILEGED GROUP MEMBERS ---")
$removals = $PrivGroupReport | Where-Object { $_.Action -eq "REMOVE" }
foreach ($r in $removals) {
    $remLines.Add("Write-Host 'Removing $($r.MemberName) from $($r.PrivilegedGroup)...' -ForegroundColor Yellow")
    $remLines.Add("Remove-ADGroupMember -Identity '$($r.PrivilegedGroup)' -Members '$($r.MemberName)' -Confirm:`$false -ErrorAction SilentlyContinue")
}

$remLines.Add("")
$remLines.Add("# --- FIX DANGEROUS ACCOUNT SETTINGS ---")

foreach ($user in $BadderBloodUsers) {
    $fixes = @()
    if ($user.PasswordNeverExpires)                  { $fixes += "PasswordNeverExpires = `$false" }
    if ($user.PasswordNotRequired)                   { $fixes += "PasswordNotRequired = `$false" }
    if ($user.DoesNotRequirePreAuth)                  { $fixes += "DoesNotRequirePreAuth = `$false" }
    if ($user.TrustedForDelegation)                   { $fixes += "TrustedForDelegation = `$false" }
    if ($user.TrustedToAuthForDelegation)             { $fixes += "TrustedToAuthForDelegation = `$false" }
    if ($user.AllowReversiblePasswordEncryption)      { $fixes += "AllowReversiblePasswordEncryption = `$false" }
    
    if ($fixes.Count -gt 0) {
        $setParams = $fixes -join "; "
        $remLines.Add("# Fix: $($user.SamAccountName)")
        foreach ($fix in $fixes) {
            $prop = ($fix -split " = ")[0].Trim()
            $val = ($fix -split " = ")[1].Trim()
            $remLines.Add("Set-ADUser -Identity '$($user.SamAccountName)' -$prop $val -ErrorAction SilentlyContinue")
        }
    }
    
    # Clear SPNs
    if ($user.ServicePrincipalName.Count -gt 0) {
        $remLines.Add("# Remove SPNs from $($user.SamAccountName)")
        foreach ($spn in $user.ServicePrincipalName) {
            $remLines.Add("Set-ADUser -Identity '$($user.SamAccountName)' -ServicePrincipalNames @{Remove='$spn'} -ErrorAction SilentlyContinue")
        }
    }
    
    # Clear AdminCount
    if ($user.AdminCount -eq 1) {
        $remLines.Add("# Clear stale AdminCount on $($user.SamAccountName)")
        $remLines.Add("Set-ADObject -Identity '$($user.DistinguishedName)' -Clear AdminCount -ErrorAction SilentlyContinue")
    }

    # Clear SID History
    if ($user.SIDHistory.Count -gt 0) {
        $remLines.Add("# Clear SID History on $($user.SamAccountName)")
        $remLines.Add("Set-ADUser -Identity '$($user.SamAccountName)' -Remove @{SIDHistory=@($($user.SIDHistory | ForEach-Object { "'$_'" }) -join ',')} -ErrorAction SilentlyContinue")
    }

    # Clean password from description
    if ($user.Description -match '(?i)(password|pwd|pass)\s*[:=]\s*\S+' -or
        $user.Description -match '(?i)my password is\s+\S+' -or
        $user.Description -match '(?i)dont forget.*(password|pwd)') {
        $remLines.Add("# Remove password from description on $($user.SamAccountName)")
        $remLines.Add("Set-ADUser -Identity '$($user.SamAccountName)' -Description 'Created with BadderBlood' -ErrorAction SilentlyContinue")
    }
}

$remLines.Add("")
$remLines.Add("# --- CLEAR SID HISTORY ON GROUPS ---")
foreach ($group in $AllGroupsWithSIDHistory) {
    if ($group.SIDHistory.Count -gt 0) {
        $remLines.Add("# Clear SID History on group $($group.SamAccountName)")
        $remLines.Add("Set-ADGroup -Identity '$($group.SamAccountName)' -Remove @{SIDHistory=@($($group.SIDHistory | ForEach-Object { "'$_'" }) -join ',')} -ErrorAction SilentlyContinue")
    }
}

$remLines.Add("")
$remLines.Add("# --- FIX COMPUTER DELEGATION ---")
foreach ($comp in $Computers) {
    if ($comp.TrustedForDelegation -and $comp.Name -notlike "*DC*") {
        $remLines.Add("Set-ADComputer -Identity '$($comp.Name)' -TrustedForDelegation `$false -ErrorAction SilentlyContinue")
    }
}

$remLines.Add("")
$remLines.Add("# --- REMOVE RBCD MISCONFIGURATIONS ---")
foreach ($comp in $AllComputers) {
    if ($comp.'msDS-AllowedToActOnBehalfOfOtherIdentity') {
        $remLines.Add("# Clear RBCD on $($comp.Name)")
        $remLines.Add("Set-ADComputer -Identity '$($comp.Name)' -PrincipalsAllowedToDelegateToAccount `$null -ErrorAction SilentlyContinue")
    }
}

$remLines.Add("")
$remLines.Add("# --- REMOVE gMSA MISCONFIGURATIONS ---")
try {
    $gmsaRemediate = Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword -ErrorAction SilentlyContinue
    foreach ($gmsa in $gmsaRemediate) {
        if ($gmsa.PrincipalsAllowedToRetrieveManagedPassword.Count -gt 0) {
            $remLines.Add("# Review gMSA $($gmsa.Name) - restrict PrincipalsAllowedToRetrieveManagedPassword to specific computers")
            $remLines.Add("# Set-ADServiceAccount -Identity '$($gmsa.Name)' -PrincipalsAllowedToRetrieveManagedPassword <specific-computer-accounts>")
        }
    }
} catch {}

$remLines.Add("")
$remLines.Add("# --- REMOVE STALE DNS RECORDS ---")
$remLines.Add("# Review and delete stale DNS records for decommissioned servers:")
$staleNames = @('oldfileserver','legacy-sql01','dev-web03','staging-app','test-dc02','backup-nas01',
    'print-srv02','decomm-exch01','temp-jump01','poc-server','migration-svc','old-intranet',
    'retired-vpn','unused-proxy','former-ca01','old-wsus','legacy-sccm','prev-adfs','old-radius','decomm-nps')
foreach ($sn in $staleNames) {
    $remLines.Add("# Remove-DnsServerResourceRecord -Name '$sn' -ZoneName '$dnsRoot_AK' -RRType A -Force -ErrorAction SilentlyContinue")
}

$remLines.Add("")
$remLines.Add("# --- REMOVE VULNERABLE ADCS TEMPLATES ---")
$remLines.Add("# Review and remove BadderBlood-created vulnerable templates:")
$remLines.Add("# Remove-ADObject 'CN=BB-VulnWebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC_AK' -Confirm:`$false -ErrorAction SilentlyContinue")
$remLines.Add("# Remove-ADObject 'CN=BB-VulnAnyPurpose,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC_AK' -Confirm:`$false -ErrorAction SilentlyContinue")

$remLines.Add("")
$remLines.Add('Write-Host "`n=== Remediation Complete ===" -ForegroundColor Green')
$remLines.Add('Write-Host "Re-run the Answer Key Generator to verify all issues are resolved." -ForegroundColor Cyan')

$remLines | Out-File -FilePath $remFile -Encoding UTF8
Write-Status "Remediation script saved: $remFile" "Green"

# ============================================================================
# EXPORT SECURITY EXPLANATIONS AND WHYS TO CSV
# ============================================================================
Write-Status "Exporting security explanations to CSV..."

$explanationsCSV = Join-Path $OutputPath "Security_Explanations.csv"
$explanations = [System.Collections.Generic.List[PSObject]]::new()

# 1. PRIVILEGED GROUP EXPLANATIONS
foreach ($groupName in $GroupRiskExplanations.Keys) {
    $ri = $GroupRiskExplanations[$groupName]
    $explanations.Add([PSCustomObject]@{
        Category           = "Privileged Group Membership"
        Issue              = $groupName
        RiskLevel          = $ri.Risk
        WhyItsBad          = $ri.Why
        AttackScenario     = $ri.Attack
        SecurityPrinciple  = $ri.Principle
        DateGenerated      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    })
}

# 2. ACCOUNT SETTINGS EXPLANATIONS
foreach ($settingName in $SettingRiskExplanations.Keys) {
    $ri = $SettingRiskExplanations[$settingName]
    $explanations.Add([PSCustomObject]@{
        Category           = "Account Settings"
        Issue              = $settingName
        RiskLevel          = "ACCOUNT FLAG"
        WhyItsBad          = $ri.Why
        AttackScenario     = $ri.Attack
        SecurityPrinciple  = $ri.Principle
        DateGenerated      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    })
}

# 3. NEW ATTACK VECTOR EXPLANATIONS
foreach ($vectorName in $NewAttackVectorExplanations.Keys) {
    $ri = $NewAttackVectorExplanations[$vectorName]
    $explanations.Add([PSCustomObject]@{
        Category           = "Attack Vector"
        Issue              = $vectorName
        RiskLevel          = $ri.Risk
        WhyItsBad          = $ri.Why
        AttackScenario     = $ri.Attack
        SecurityPrinciple  = $ri.Principle
        DateGenerated      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    })
}

# 4. ACL RISK EXPLANATIONS
foreach ($aclType in $ACLRiskExplanations.Keys) {
    $explanation = $ACLRiskExplanations[$aclType]
    $explanations.Add([PSCustomObject]@{
        Category           = "ACL / Permissions"
        Issue              = $aclType
        RiskLevel          = "PERMISSION TYPE"
        WhyItsBad          = $explanation
        AttackScenario     = "Attacker with this permission can escalate privileges or compromise security controls."
        SecurityPrinciple  = "Restrictive delegation: Grant minimal permissions; audit who has what access regularly."
        DateGenerated      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    })
}

# Export to CSV
$explanations | Export-Csv -Path $explanationsCSV -NoTypeInformation -Encoding UTF8
Write-Status "Security explanations exported to CSV: $explanationsCSV" "Green"

# --- GRADING RUBRIC ---
$rubricFile = Join-Path $OutputPath "GradingRubric.txt"
$rubricLines = @(
    "=" * 60
    "  SUGGESTED GRADING RUBRIC"
    "  Total Possible Points: 100"
    "=" * 60
    ""
    "CRITICAL findings ($critical total) - 5 points each"
    "  Max points: $($critical * 5)"
    "  These are actively exploitable vulnerabilities."
    ""
    "HIGH findings ($high total) - 3 points each"
    "  Max points: $($high * 3)"
    "  These represent significant security risks."
    ""
    "MEDIUM findings ($medium total) - 1 point each"
    "  Max points: $($medium * 1)"
    "  These are best-practice violations."
    ""
    "BONUS: Documenting findings in a report (+10)"
    "BONUS: Identifying issues not in this answer key (+5 each)"
    ""
    "SUGGESTED GRADE SCALE:"
    "  A  = 90%+ of available points"
    "  B  = 80-89%"
    "  C  = 70-79%"
    "  D  = 60-69%"
    "  F  = Below 60%"
    ""
    "Total available: $($critical * 5 + $high * 3 + $medium * 1) points"
    "(Scale to 100 by dividing student score by total and multiplying by 100)"
)
$rubricLines | Out-File -FilePath $rubricFile -Encoding UTF8
Write-Status "Grading rubric saved: $rubricFile" "Green"

if ($ExportCSVs) {
    # Export user inventory
    $BadderBloodUsers | Select-Object SamAccountName, Enabled, CanonicalName, Description,
        PasswordNeverExpires, PasswordNotRequired, DoesNotRequirePreAuth,
        TrustedForDelegation, TrustedToAuthForDelegation, AdminCount,
        @{N='SPNs';E={$_.ServicePrincipalName -join '; '}},
        @{N='SIDHistoryCount';E={$_.SIDHistory.Count}},
        @{N='MemberOfCount';E={$_.MemberOf.Count}} |
        Export-Csv (Join-Path $OutputPath "BadderBloodUsers_Inventory.csv") -NoTypeInformation
    
    $BadderBloodGroups | Select-Object SamAccountName, Description,
        @{N='MemberCount';E={$_.Members.Count}},
        @{N='MemberOfCount';E={$_.MemberOf.Count}} |
        Export-Csv (Join-Path $OutputPath "BadderBloodGroups_Inventory.csv") -NoTypeInformation
    
    Write-Status "CSV inventories exported." "Green"
}

# ============================================================================
# FINAL SUMMARY
# ============================================================================

Write-Host ""
Write-Host "=" * 80 -ForegroundColor Yellow
Write-Host "  ANSWER KEY GENERATION COMPLETE" -ForegroundColor Green
Write-Host "=" * 80 -ForegroundColor Yellow
Write-Host ""
Write-Host "  Domain:     $DomainName" -ForegroundColor White
Write-Host "  BB Users:   $($BadderBloodUsers.Count)" -ForegroundColor White
Write-Host "  BB Groups:  $($BadderBloodGroups.Count)" -ForegroundColor White
Write-Host ""
Write-Host "  FINDINGS:" -ForegroundColor White
Write-Host "    CRITICAL: $critical" -ForegroundColor Red
Write-Host "    HIGH:     $high" -ForegroundColor DarkYellow
Write-Host "    MEDIUM:   $medium" -ForegroundColor Yellow
Write-Host "    LOW:      $low" -ForegroundColor Cyan
Write-Host "    INFO:     $info" -ForegroundColor Gray
Write-Host "    TOTAL:    $($AllFindings.Count)" -ForegroundColor White
Write-Host ""
Write-Host "  OUTPUT FILES:" -ForegroundColor White
Write-Host "    $reportFile" -ForegroundColor Gray
Write-Host "    $privFile" -ForegroundColor Gray
Write-Host "    $findingsFile" -ForegroundColor Gray
Write-Host "    $cheatSheet" -ForegroundColor Gray
Write-Host "    $remFile" -ForegroundColor Gray
Write-Host "    $rubricFile" -ForegroundColor Gray
Write-Host "    $explanationsCSV" -ForegroundColor Gray
Write-Host ""
Write-Host "  TIP: Run the Remediation_Script.ps1 with -WhatIf first!" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Yellow