# BadderBlood - Realistic AD Lab Generator

**Rewritten core scripts** for generating realistic Active Directory lab environments.

## What Changed vs Original BadBlood

### The Problem
Original BadBlood creates ~1,800 findings where ~85% are "user in wrong OU" because everything is placed randomly. ACLs are GenericAll-on-domain-root from random groups. SPNs are sprayed on random users. It doesn't look like a real company.

### The Solution
BadderBlood rewrites the core generation scripts so the domain looks like a **real company that has accumulated 5-10 years of drift and shortcuts**.

## Key Changes

### CreateUsers.ps1 (REWRITTEN)
- Users placed in **correct department OUs** (People > BDE, People > FIN, etc.)
- Full AD attributes: GivenName, Surname, Department, Title, Phone, Office, City, State, EmployeeID, Company, Manager
- **8% drift rate** (configurable): users in wrong dept, stuck in staging, misplaced in tier OUs
- Service accounts (3%) go to proper ServiceAccounts OUs with `SA` suffix
- ~1% chance of password in Description field (realistic misconfiguration)
- Department-weighted distribution (BDE gets more users than SEC)

### CreateComputers.ps1 (REWRITTEN)
- Consistent naming: `DEPT-TYPE-NNNNN` (e.g., `BDE-WKS-00142`, `ITS-SQL-003`)
- Types: WKS (desktop), LPT (laptop), VDI (virtual), APP/WEB/SQL/FIL/CTX/INF (servers)
- Workstations → Tier 2 OUs, Servers → Tier 1 OUs
- Populated: OperatingSystem, OperatingSystemVersion, Location, Description, ManagedBy
- OS versions match type (Win10/11 for workstations, Server 2016/2019/2022 for servers)

### CreateGroup.ps1 (REWRITTEN)
- Realistic naming prefixes: `APP-`, `DEPT-`, `PRJ-`, `DL-`, `ROLE-`, `ADM-`
- Examples: `APP-SharePoint-Admin`, `DEPT-FIN-Managers`, `PRJ-Phoenix-Members`, `ROLE-Helpdesk-PasswordReset`
- Proper GroupCategory (Security vs Distribution) and GroupScope
- Groups placed in department-specific Groups OUs

### AddRandomToGroups.ps1 (REWRITTEN)
- Users added to **department-matching groups first**, then some cross-department
- Only 1-2 users per critical group (not 5+)
- 15% of groups nested (not 100%)
- One intentional nested group attack path (project group → critical group)
- Computers in groups at ~15% rate

### GenerateRandomPermissions.ps1 (REWRITTEN)
- **6 realistic ACL scenarios** instead of random GenericAll spray:
  1. Helpdesk with password reset on Tier 1 OU (overly broad delegation)
  2. IT groups with FullControl on department OUs
  3. Individual user ACL grants (5 users with specific permissions)
  4. 1 migration leftover GenericAll on root (not dozens)
  5. WriteDACL on critical OUs (escalation path)
  6. Group-to-group permission chains (BloodHound paths)

### CreateRandomSPNs.ps1 (REWRITTEN)
- Realistic SPNs: MSSQLSvc, HTTP, TERMSRV, exchangeMDB (not kafka/POP3)
- 80% on service accounts, 20% on regular users (the misconfiguration)
- Default 12 SPNs (not 50)

### ASREP_NotReqPreAuth.ps1 (REWRITTEN)
- Default 5 accounts (not 5% of all users)
- Simulates "vendor said to disable pre-auth" scenario

### Invoke-BadBlood.ps1 (REWRITTEN)
- Clear phase-by-phase execution with progress bars
- All misconfiguration counts are **configurable parameters**
- Summary report of what was injected
- `DriftPercent`, `ASREPCount`, `SPNCount`, `WeakPasswordCount` parameters

## Usage

```powershell
# Default (2500 users, 500 groups, 100 computers, 8% drift)
.\Invoke-BadBlood.ps1

# Smaller lab
.\Invoke-BadBlood.ps1 -UserCount 500 -GroupCount 100 -ComputerCount 25

# More misconfigurations for harder lab
.\Invoke-BadBlood.ps1 -DriftPercent 15 -ASREPCount 10 -SPNCount 20 -WeakPasswordCount 25

# Non-interactive (for automation)
.\Invoke-BadBlood.ps1 -NonInteractive -SkipLapsInstall

# Skip OU creation (already done)
.\Invoke-BadBlood.ps1 -SkipOuCreation -SkipLapsInstall
```

## Expected Findings Profile (vs Original)

| Category | Original BadBlood | BadderBlood |
|----------|------------------|-------------|
| OU Misplacement | ~1,500 (random) | ~200 (8% drift, plausible) |
| Kerberos (SPN) | ~50 random | ~12 targeted |
| Kerberos (ASREP) | ~125 (5% of users) | ~5 targeted |
| Dangerous ACL | ~14 (GenericAll on root) | ~10 (varied, chained) |
| Privileged Groups | ~19 (random users) | ~6-10 (1-2 per group) |
| Account Settings | ~6 | Similar |
| Passwords in Desc | Random | ~1-2% of users |

The result: a domain that **looks real** but has discoverable, exploitable misconfigurations that chain together into realistic attack paths.
