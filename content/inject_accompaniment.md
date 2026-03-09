# Inject Answer Key Mapping
# BadderBlood - sirshanova.com
# For TA/Instructor use only

This file maps each inject to the specific findings students are expected to identify and remediate.
Source files: `GPO_AnswerKey_MasterReport.txt` and `QuickReference_CheatSheet.txt`

---

## Inject 1: Privileged Group Membership Audit

**Answer Key Source:** QuickReference_CheatSheet.txt - Category: Privileged Group Membership

| Severity | Finding |
|----------|---------|
| CRITICAL | `Jeannette_Simpson` is a member of `Administrators` |
| CRITICAL | `Jeannette_Simpson` is a member of `Domain Admins` |
| HIGH | `8434233498SA` is a member of `Group Policy Creator Owners` |
| HIGH | `Ines_Arnold` is a member of `Server Operators` |

**What students must do:** Identify all four accounts, explain the specific attack path each enables (e.g., DCSync for DA, service binary hijack for Server Operators), and remove them from those groups.

**Bonus/stretch:** QuickRef also flags `Jeannette_Simpson` and `Ines_Arnold` for OU Misplacement (HIGH) - they are in People OUs despite having privileged memberships. Students may note this but OU remediation is not required.

---

## Inject 2: Domain Root Access Control Audit

**Answer Key Source:** QuickReference_CheatSheet.txt - Category: Dangerous ACL

| Severity | Finding |
|----------|---------|
| CRITICAL | `1486749344SA` has `GenericAll` on `DC=sirshanova,DC=com` (domain root) |
| HIGH | `1486749344SA` has `GenericAll` on `CN=Server Operators` |
| HIGH | `1486749344SA` has `GenericAll` on `CN=Backup Operators` |
| HIGH | `1486749344SA` has `GenericAll` on `CN=Print Operators` |
| HIGH | `1486749344SA` has `GenericAll` on `CN=Group Policy Creator Owners` |
| HIGH | `1486749344SA` has `GenericAll` on `CN=DnsAdmins` |
| HIGH | `1486749344SA` has `GenericAll` on `CN=Enterprise Admins` |
| HIGH | `1486749344SA` has `GenericAll` on `CN=Domain Admins` |
| HIGH | `1486749344SA` has `GenericAll` on `CN=Schema Admins` |
| HIGH | `1486749344SA` has `GenericAll` on `CN=Account Operators` |
| HIGH | `1486749344SA` has `GenericAll` on `CN=Administrators` |

**What students must do:** Identify `1486749344SA` as having dangerous ACL rights, explain that GenericAll on the domain root grants effective full control over the domain to a non-admin account, and remove all 11 ACEs. The CRITICAL finding (domain root) is the anchor; the HIGH findings on privileged groups are secondary.

---

## Inject 3: Kerberoasting Exposure Audit

**Answer Key Source:** QuickReference_CheatSheet.txt - Category: Kerberos Security (SPN accounts only)

| Severity | Account | Fix |
|----------|---------|-----|
| HIGH | `Coleen_Goodman` | Remove SPNs or convert to managed service account |
| HIGH | `5798262727SA` | Remove SPNs or convert to managed service account |
| HIGH | `Mauro_Phelps` | Remove SPNs or convert to managed service account |
| HIGH | `6488786674SA` | Remove SPNs or convert to managed service account |
| HIGH | `2510174521SA` | Remove SPNs or convert to managed service account |
| HIGH | `2712947373SA` | Remove SPNs or convert to managed service account |
| HIGH | `4609181115SA` | Remove SPNs or convert to managed service account |
| HIGH | `6588802721SA` | Remove SPNs or convert to managed service account |
| HIGH | `Deanna_Delacruz` | Remove SPNs or convert to managed service account |

**What students must do:** Enumerate all 9 Kerberoastable accounts, explain the offline cracking attack, and either remove SPNs or convert accounts to Group Managed Service Accounts (gMSAs).

---

## Inject 4: AS-REP Roasting Vulnerability Investigation

**Answer Key Source:** QuickReference_CheatSheet.txt - Category: Kerberos Security (DoesNotRequirePreAuth accounts only)

| Severity | Account | Fix |
|----------|---------|-----|
| HIGH | `Willard_Miranda` | Set `DoesNotRequirePreAuth = False` |
| HIGH | `Graciela_Bowman` | Set `DoesNotRequirePreAuth = False` |
| HIGH | `Violet_Glass` | Set `DoesNotRequirePreAuth = False` |
| HIGH | `Christine_Ramirez` | Set `DoesNotRequirePreAuth = False` |
| HIGH | `Terence_French` | Set `DoesNotRequirePreAuth = False` |

**What students must do:** Enumerate all 5 AS-REP Roastable accounts, explain that this attack requires *no credentials* to initiate (unlike Kerberoasting), re-enable pre-authentication on each account, and produce an executive summary. The executive summary deliverable distinguishes this from Inject 3.

---

## Inject 5: Plaintext Credential Exposure

**Answer Key Source:** Both files

### Exposure Point 1: WDigest Authentication Enabled
**Source:** GPO_AnswerKey_MasterReport.txt - Category: Credential Exposure

| Severity | Finding |
|----------|---------|
| CRITICAL | GPO `SEC-Authentication-Legacy`: `UseLogonCredential = 1` - plaintext passwords cached in LSASS |

**Fix:** Set `UseLogonCredential = 0` in `SEC-Authentication-Legacy`.
**Attack:** Any admin on a box can run Mimikatz `sekurlsa::wdigest` and retrieve plaintext passwords for all logged-in users.

### Exposure Point 2: Plaintext Passwords in AD Description Fields
**Source:** QuickReference_CheatSheet.txt - Category: Credential Exposure (32 findings)

| Severity | Count | Finding |
|----------|-------|---------|
| CRITICAL | 32 | Plaintext passwords stored in `Description` attribute on user accounts - readable by any authenticated domain user via LDAP |

Affected accounts include: `Cristina_May`, `Kelsey_Herrera`, `Emilio_Garza`, `Bobbie_Orr`, `Gena_Garner`, `Catherine_Ashley`, `Tessa_Castaneda`, `Tanya_Mills`, `Lessie_Knox`, `7728217838SA`, `Leta_Noble`, `Kip_Higgins`, `Isaiah_Witt`, `Arthur_Sanchez`, `Aaron_Fitzgerald`, `Abraham_Wolfe`, `8722392695SA`, `Gerardo_Montoya`, `Fran_Rocha`, `Dawn_Giles`, `Archie_Armstrong`, `Janine_Atkins`, `1013885964SA`, `Nancy_Lynch`, `Wilson_Stevens`, `Marlene_Savage`, `Fidel_Green`, `Freda_Rivera`, `Elvis_Merritt`, `Coleen_Merritt`, `1441181171SA`, `Jeffry_Dickerson`

**Fix:** Clear the `Description` field on all affected accounts. Enforce a provisioning policy prohibiting credential storage in any AD attribute.
**Attack:** Any domain user → `Get-ADUser -Filter * -Properties Description | Where-Object {$_.Description}` → instant plaintext credentials.

**Grading note:** Students must find both. Finding only one of the two is partial credit. The inject's "how accounts are provisioned and documented" clue points to Description fields; "how Windows handles authentication" points to WDigest.

---

## Inject 6: Privileged Group Membership via Group Nesting

**Answer Key Source:** QuickReference_CheatSheet.txt - Category: Nested Group Membership

| Severity | Finding |
|----------|---------|
| HIGH | `Enterprise Admins` is nested inside `Administrators` |
| HIGH | `Domain Admins` is nested inside `Administrators` |

**What students must do:** Discover that these two privileged groups are themselves members of `Administrators` (creating recursive membership), explain that this silently grants all members of those groups the combined rights of `Administrators` on top of their existing rights, enumerate which users are transitively affected, and remove the nesting. Students should use `Get-ADGroupMember -Recursive` or equivalent.

**Note:** The inject asks students to confirm or debunk - a correct "debunk" answer (if they find no nesting) would also be accepted in theory, but the findings confirm it is real.

---

## Inject 7: GPO Permission Audit

**Answer Key Source:** GPO_AnswerKey_MasterReport.txt - Category: Excessive GPO Permissions

| Severity | Account | GPO | Permission |
|----------|---------|-----|------------|
| HIGH | `431747973SA` | `SEC-CredentialProtection-Config` | `GpoEditDeleteModifySecurity` |
| HIGH | `Tyler_Bass` | `SEC-Authentication-Legacy` | `GpoEditDeleteModifySecurity` |
| HIGH | `Constance_Foster` | `IT-MediaPolicy-Standard` | `GpoEditDeleteModifySecurity` |
| HIGH | `Rickie_Key` | `NET-Firewall-Exceptions` | `GpoEditDeleteModifySecurity` |
| HIGH | `Tyrone_Mejia` | `IT-LocalAdmin-Deploy` | `GpoEditDeleteModifySecurity` |

**What students must do:** Identify all 5 non-admin accounts with GPO edit rights, explain that this permission allows domain-wide code execution by modifying startup scripts, and remove the delegated rights from each.

---

## Inject 8: Local Administrator Credential Exposure and Privilege Escalation Path

**Answer Key Source:** GPO_AnswerKey_MasterReport.txt - Categories: Credential Exposure + GPO Persistence / Code Execution

### Claim 1: Low-privileged employee obtained local admin credentials
**Finding:**

| Severity | Finding |
|----------|---------|
| CRITICAL | GPO `IT-LocalAdmin-Deploy`: `Groups.xml` in SYSVOL contains a `cpassword` attribute - decryptable by any domain user using the publicly known AES key |

**Fix:** Delete the `Groups.xml` file containing `cpassword`. Deploy LAPS for local admin password management instead.
**Attack:** Any domain user → browse SYSVOL → `Get-GPPPassword` or `gpp-decrypt` → plaintext local admin password.

### Claim 2: Routine maintenance process exploitable by any domain user
**Findings:**

| Severity | Finding |
|----------|---------|
| CRITICAL | GPO `IT-Maintenance-Tasks`: Script share `\\WIN-MCG9FQLEO5Q\ITScripts` is writable by domain users |
| CRITICAL | GPO `IT-Maintenance-Tasks`: Scheduled Task `IT-SystemHealthCheck` runs as `NT AUTHORITY\SYSTEM` and executes `\\WIN-MCG9FQLEO5Q\ITScripts\Invoke-SystemHealthCheck.ps1` |

**Fix:** Remove write access for non-admins on the `ITScripts` share (both SMB permissions and NTFS ACLs). Either change the task's run-as account to a least-privilege service account, or enforce code signing.
**Attack:** Any domain user → overwrite `Invoke-SystemHealthCheck.ps1` with a reverse shell → wait for scheduled trigger → SYSTEM shell on every targeted machine.

**Grading note:** Students must address both claims. Finding only the GPP password satisfies Claim 1; finding only the writable share satisfies Claim 2. Full credit requires both remediations.
