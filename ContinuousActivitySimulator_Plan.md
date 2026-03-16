# BadderBlood Continuous Activity Simulator — Implementation Plan

## Executive Summary

This plan transforms the static BadderBlood AD lab into a **living, breathing enterprise environment** with continuous network traffic, user sessions, helpdesk operations, customer orders, supplier transactions, and internal email — all resilient to Blue Team remediation. The simulator creates the "background noise" that makes the lab feel like a real company and forces defenders to maintain service uptime while hardening the domain.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Phase 1: Out-of-Band Scoring Engine & Black Team Infrastructure](#2-phase-1-out-of-band-scoring-engine--black-team-infrastructure)
3. [Phase 2: Supplier Deliveries (SQL Transactions)](#3-phase-2-supplier-deliveries-sql-transactions)
4. [Phase 3: Level One Helpdesk (AD Lockouts & Ticketing)](#4-phase-3-level-one-helpdesk-ad-lockouts--ticketing)
5. [Phase 4: User Sessions & File Operations](#5-phase-4-user-sessions--file-operations)
6. [Phase 5: Customer Orders (IIS Web Requests)](#6-phase-5-customer-orders-iis-web-requests)
7. [Phase 6: Realistic Email & Communications](#7-phase-6-realistic-email--communications)
8. [Integration & Orchestration](#8-integration--orchestration)
9. [Scoring & Observability](#9-scoring--observability)
10. [Testing & Validation](#10-testing--validation)

---

## 1. Architecture Overview

### Current State

BadderBlood currently deploys:

- **Invoke-BadderBlood.ps1** — Creates 1,500 users, 500 groups, 100 computers, realistic ACL misconfigurations, attack vectors (Kerberoasting, ASREP, RBCD, Shadow Credentials, ADCS, gMSA, ADIDNS, LAPS bypass), and 18–20 insecure GPOs.
- **BadFS.ps1** — Generates a realistic corporate file share at `C:\CorpShares` with department folders, project folders, resumes, performance reviews, financial CSVs, meeting minutes, legal docs, and PII. Sets AD home folder/profile/logon script attributes. Deploys `logon.bat` and `Set-Wallpaper.ps1` to NETLOGON.
- **BadIIS.ps1** — Deploys a themed IIS site (Springfield Box Factory) with a public-facing knowledgebase, employee portal, and intentionally misconfigured `/it_docs/` and `/legacy_backups/` directories. Dynamically generates content from live AD (leadership, DCs, service accounts, Kerberoastable accounts).
- **BadSQL.ps1** — Installs SQL Server Express with NailInventoryDB, TimesheetLegacy, HRConfidential, BoxArchive2019, and SqlReports databases. Cross-references BadFS and BadIIS data for credential/salary consistency. Deploys IIS web apps at `/apps/inventory/`, `/apps/timesheet/`, `/apps/hr/`, `/apps/orders/`. Creates 12+ intentional SQL misconfigurations (xp_cmdshell, TRUSTWORTHY, SQL injection, weak logins, linked servers, GPP-style password exposure).

### Target State

A **Continuous Activity Simulator** running on a dedicated out-of-band VM that generates persistent, realistic network traffic across all BadderBlood services. Traffic survives standard Blue Team remediations (password rotations, GPO hardening, SMB signing enforcement, protocol upgrades) because it uses dedicated "Black Team" accounts and modern protocol support.

### Network Topology

```
┌──────────────────────────────────────────────────────────────┐
│                  BADDERBLOOD LAB NETWORK                      │
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌───────────────┐  │
│  │  DC01         │    │  DC01 (IIS)  │    │  DC01 (SQL)   │  │
│  │  AD / DNS     │    │  Port 80     │    │  Port 1433    │  │
│  │  LDAP / Kerb  │    │  /apps/*     │    │  BADSQL inst  │  │
│  └──────┬───────┘    └──────┬───────┘    └──────┬────────┘  │
│         │                   │                   │            │
│         └───────────┬───────┴───────────────────┘            │
│                     │                                        │
│              ┌──────┴──────┐                                 │
│              │ CORE SWITCH │                                 │
│              └──────┬──────┘                                 │
│                     │                                        │
│         ┌───────────┴───────────┐                            │
│         │                       │                            │
│  ┌──────┴──────┐    ┌──────────┴──────────┐                 │
│  │ Client VMs  │    │ SIMULATOR VM         │                 │
│  │ (Students)  │    │ (WORKGROUP - Win10)  │                 │
│  │ Blue Team   │    │ Black Team Scripts   │                 │
│  └─────────────┘    │ Out-of-Band Scoring  │                 │
│                     │ MailEnable Server    │                 │
│                     └─────────────────────┘                 │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## 2. Phase 1: Out-of-Band Scoring Engine & Black Team Infrastructure

### Difficulty: Foundational (Must complete first)
### Estimated Effort: 4–6 hours
### Dependencies: None (runs after `Invoke-BadderBlood.ps1` completes)

### 2.1 Deploy the Simulator VM

**Objective:** A standalone Windows 10/11 or Server 2019/2022 VM on the lab network that is NOT domain-joined. Students cannot log in or kill scripts because they don't have the local credentials.

**Action Items:**

| # | Task | Detail |
|---|------|--------|
| 1 | Provision VM | Windows 10/11 or Server 2019/2022, 4GB RAM, 2 vCPU minimum. Leave in WORKGROUP. |
| 2 | Network config | Same virtual switch as DC. Static IP in the lab subnet. DNS pointed at DC. |
| 3 | Local admin | Set a strong local admin password. Do NOT share with students. |
| 4 | PowerShell | Ensure PowerShell 5.1+ and .NET Framework 4.7.2+. Install RSAT (for `ActiveDirectory` module): `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0` |
| 5 | SQL Client | Install `SqlClient` or SQL Server Management Studio for SQL connectivity. |
| 6 | Script deployment | Copy all simulator scripts to `C:\Simulator\` on the VM. |
| 7 | Modern OS benefits | SMBv3 + SMB Signing native support — scripts won't break when defenders enforce signing. NTLMv2 negotiation works out of the box. TLS 1.2/1.3 for web requests. |

### 2.2 Provision Black Team AD Accounts

**Objective:** Dedicated AD accounts that students are instructed NOT to disable, delete, or change passwords on. These accounts generate all simulator traffic.

**Action Items:**

| # | Task | Detail |
|---|------|--------|
| 1 | Create OU | `New-ADOrganizationalUnit -Name "BlackTeam" -Path "OU=Admin,$DomainDN" -ProtectedFromAccidentalDeletion $true` |
| 2 | Create scorebot user | `New-ADUser -Name "BlackTeam_Scorebot" -SamAccountName "BlackTeam_Scorebot" -Path "OU=BlackTeam,OU=Admin,$DomainDN" -AccountPassword (ConvertTo-SecureString "B!ackT3am_Sc0reb0t_2025#" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true` |
| 3 | Create SQL user | `BlackTeam_SQLBot` with `db_datareader`/`db_datawriter` on NailInventoryDB, TimesheetLegacy |
| 4 | Create IIS user | `BlackTeam_WebBot` with Read access to IIS sites |
| 5 | Create file user | `BlackTeam_FileBot` with Read/Write on `CorpData` share |
| 6 | Create mail user | `BlackTeam_MailBot` for SMTP relay |
| 7 | Grant permissions | Each account gets ONLY the minimum permissions needed for its traffic type |
| 8 | Document RoE | Write a `Rules_of_Engagement.txt` that explicitly lists what students cannot touch |

**Script:** `Deploy-BlackTeamAccounts.ps1`

```powershell
# Skeleton — full implementation needed
param(
    [string]$DomainDN = (Get-ADDomain).DistinguishedName,
    [string]$ScoreBotPassword = "B!ackT3am_Sc0reb0t_2025#"
)

$BlackTeamOU = "OU=BlackTeam,OU=Admin,$DomainDN"
New-ADOrganizationalUnit -Name "BlackTeam" -Path "OU=Admin,$DomainDN" -ProtectedFromAccidentalDeletion $true -ErrorAction SilentlyContinue

$Accounts = @(
    @{Name="BlackTeam_Scorebot"; Desc="Scoring engine service account"; Perms="AD Read"}
    @{Name="BlackTeam_SQLBot";   Desc="SQL traffic generator";         Perms="SQL datareader/datawriter"}
    @{Name="BlackTeam_WebBot";   Desc="IIS traffic generator";         Perms="IIS Read"}
    @{Name="BlackTeam_FileBot";  Desc="SMB file operations generator"; Perms="CorpData Read/Write"}
    @{Name="BlackTeam_MailBot";  Desc="Email traffic generator";       Perms="SMTP Relay"}
)

foreach ($acct in $Accounts) {
    New-ADUser -Name $acct.Name -SamAccountName $acct.Name `
        -Path $BlackTeamOU `
        -Description $acct.Desc `
        -AccountPassword (ConvertTo-SecureString $ScoreBotPassword -AsPlainText -Force) `
        -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true `
        -ErrorAction SilentlyContinue
}
```

### 2.3 Scoring Portal (Optional Credential Rotation Bridge)

**Objective:** If defenders rotate service account passwords (e.g., `svc_sql`), they can update the new password in a shared JSON file on the simulator VM. The simulator reads from this file dynamically so traffic doesn't break.

**Action Items:**

| # | Task | Detail |
|---|------|--------|
| 1 | Create `C:\Simulator\credentials.json` | JSON structure with service name → username/password mappings |
| 2 | Build `Get-SimulatorCredential` function | Reads the JSON, returns a PSCredential object |
| 3 | Document the 5-minute SLA | Students must update this file within 5 minutes of any password rotation |
| 4 | Monitor for staleness | Script logs warnings if credentials fail and waits for update |

**JSON Schema:**

```json
{
  "sql": {
    "username": "BlackTeam_SQLBot",
    "password": "B!ackT3am_Sc0reb0t_2025#",
    "lastUpdated": "2025-03-16T00:00:00Z"
  },
  "iis": {
    "username": "BlackTeam_WebBot",
    "password": "B!ackT3am_Sc0reb0t_2025#",
    "lastUpdated": "2025-03-16T00:00:00Z"
  },
  "smb": {
    "username": "BlackTeam_FileBot",
    "password": "B!ackT3am_Sc0reb0t_2025#",
    "lastUpdated": "2025-03-16T00:00:00Z"
  },
  "smtp": {
    "username": "BlackTeam_MailBot",
    "password": "B!ackT3am_Sc0reb0t_2025#",
    "lastUpdated": "2025-03-16T00:00:00Z"
  }
}
```

### 2.4 Rules of Engagement Document

**File:** `Rules_of_Engagement.txt` (deployed to `C:\CorpShares\Public_Company_Data\` and printed for students)

Content should specify:
- Black Team accounts are off-limits (no disable, delete, or password change)
- Black Team accounts must maintain Read access to IIS sites, Read/Write to CorpData share, appropriate SQL permissions
- If students rotate compromised service account passwords, they must update `credentials.json` on the simulator VM within 5 minutes
- Scoring engine runs continuously; uptime is graded

---

## 3. Phase 2: Supplier Deliveries (SQL Transactions)

### Difficulty: Easiest
### Estimated Effort: 2–3 hours
### Dependencies: Phase 1 (Black Team accounts), BadSQL.ps1 already run

### Why This Is Easy

`BadSQL.ps1` already installs SQL Server Express, creates NailInventoryDB with `Inventory`, `PurchaseOrders`, `NailTypes`, and `Suppliers` tables, enables SQL Agent, and creates SQL logins. We're just adding a scheduled job that runs T-SQL on an interval.

### 3.1 Implementation Details

**New SQL Agent Job:** `SBF - Supplier Delivery Simulation`

| Setting | Value |
|---------|-------|
| Schedule | Every 15–20 minutes |
| Owner | `BlackTeam_SQLBot` (NOT `sa`) |
| Step Type | T-SQL |
| Database | NailInventoryDB |
| Auth | Windows Auth via `BlackTeam_SQLBot` AD account |

**T-SQL Logic:**

```sql
-- Step 1: Simulate a supplier delivery (UPDATE Inventory + INSERT PurchaseOrder)
BEGIN TRY
    BEGIN TRANSACTION

    -- Pick a random inventory item and supplier
    DECLARE @NailTypeID INT = (SELECT TOP 1 NailTypeID FROM NailTypes ORDER BY NEWID())
    DECLARE @SupplierID INT = (SELECT TOP 1 SupplierID FROM Suppliers ORDER BY NEWID())
    DECLARE @Qty INT = ABS(CHECKSUM(NEWID())) % 500 + 50
    DECLARE @UnitCost DECIMAL(10,4) = (SELECT UnitCostUSD FROM NailTypes WHERE NailTypeID = @NailTypeID)

    -- Update inventory (simulates delivery receipt)
    UPDATE Inventory WITH (TABLOCKX) -- Intentional: creates lock contention for realism
    SET QuantityOnHand = QuantityOnHand + @Qty,
        LastAuditDate = GETDATE(),
        LastAuditBy = 'BlackTeam_SQLBot'
    WHERE NailTypeID = @NailTypeID AND SupplierID = @SupplierID

    -- Insert purchase order
    INSERT INTO PurchaseOrders (SupplierID, OrderDate, ExpectedDate, TotalUSD, Status, ApprovedBy, Notes)
    VALUES (@SupplierID, GETDATE(), DATEADD(day, 7, GETDATE()),
            @Qty * @UnitCost, 'DELIVERED',
            'BlackTeam_SQLBot',
            'Automated supplier delivery - Simulator')

    COMMIT TRANSACTION
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION
    -- Log the failure (simulates realistic constraint violations / deadlocks)
    INSERT INTO PurchaseOrders (SupplierID, OrderDate, TotalUSD, Status, Notes)
    VALUES (@SupplierID, GETDATE(), 0, 'FAILED',
            'Delivery simulation failed: ' + ERROR_MESSAGE())
END CATCH
```

**Crucial Guardrail:** The job runs as `BlackTeam_SQLBot` (AD Windows Auth), NOT `sa`. This means:
- Traffic survives when defenders disable Mixed Mode authentication
- Traffic survives when defenders change the `sa` password
- Traffic breaks ONLY if defenders revoke `BlackTeam_SQLBot`'s `db_datareader`/`db_datawriter` on NailInventoryDB (which violates the RoE)

### 3.2 Deployment Script

**File:** `Deploy-SupplierDeliveryJob.ps1`

Appends a new `sp_add_job` block to BadSQL.ps1's existing SQL Agent configuration:

```powershell
# Add to BadSQL.ps1 after existing Agent job creation (Section 16)
Invoke-Sql @"
USE [msdb];
IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = 'SBF - Supplier Delivery Simulation')
BEGIN
    EXEC sp_add_job
        @job_name = N'SBF - Supplier Delivery Simulation',
        @enabled = 1,
        @description = N'Simulates supplier deliveries every 15-20 minutes. Uses BlackTeam_SQLBot.',
        @owner_login_name = N'BlackTeam_SQLBot'

    EXEC sp_add_jobstep
        @job_name = N'SBF - Supplier Delivery Simulation',
        @step_name = N'Execute Delivery',
        @subsystem = N'TSQL',
        @command = N'<T-SQL from above>',
        @database_name = N'NailInventoryDB',
        @on_success_action = 1

    EXEC sp_add_schedule
        @schedule_name = N'Every15Min',
        @freq_type = 4,
        @freq_interval = 1,
        @freq_subday_type = 4,
        @freq_subday_interval = 15

    EXEC sp_attach_schedule
        @job_name = N'SBF - Supplier Delivery Simulation',
        @schedule_name = N'Every15Min'

    EXEC sp_add_jobserver
        @job_name = N'SBF - Supplier Delivery Simulation',
        @server_name = N'(local)'
END
"@
```

### 3.3 Scoring Criteria

| Check | Pass Condition | Points |
|-------|----------------|--------|
| SQL Agent running | Service status = Running | 5 |
| Job exists and enabled | `sysjobs.enabled = 1` | 5 |
| Last run successful | `sysjobhistory.run_status = 1` within last 30 min | 10 |
| PurchaseOrders growing | Row count increased since last check | 5 |
| Inventory values changing | `LastAuditDate` within last 30 min on any row | 5 |

---

## 4. Phase 3: Level One Helpdesk (AD Lockouts & Ticketing)

### Difficulty: Easy/Moderate
### Estimated Effort: 6–8 hours
### Dependencies: Phase 1, BadIIS.ps1 already run, BadSQL.ps1 already run

### 4.1 Component Overview

This feature has three sub-components:

1. **Lockout Generator** — PowerShell script that intentionally trips AD lockout policies by sending bad passwords for random users
2. **Ticket System** — Lightweight ASP.NET endpoint on BadIIS that writes help desk tickets to a new SQL database
3. **Auto-Resolution Engine** — Background loop that reads tickets and automatically resolves 80% by running `Unlock-ADAccount`
4. **Ticket Management Frontend** — HTML interface integrated with AD for viewing/managing tickets

### 4.2 Lockout Generator

**File:** `Invoke-LockoutSimulator.ps1` (runs on Simulator VM)

**Logic:**

```powershell
# Every 5-10 minutes, pick 1-3 random users and generate bad auth attempts
$AllUsers = Get-ADUser -Filter { Enabled -eq $true } -Server $DCHostname -Credential $BlackTeamCred
$LockoutThreshold = (Get-ADDefaultDomainPasswordPolicy).LockoutThreshold
if ($LockoutThreshold -eq 0) { $LockoutThreshold = 5 } # Default if not set

while ($true) {
    $targetCount = Get-Random -Minimum 1 -Maximum 4
    $targets = $AllUsers | Get-Random -Count $targetCount

    foreach ($user in $targets) {
        $attempts = Get-Random -Minimum ($LockoutThreshold) -Maximum ($LockoutThreshold + 3)
        for ($i = 0; $i -lt $attempts; $i++) {
            try {
                $badEntry = New-Object System.DirectoryServices.DirectoryEntry(
                    "LDAP://$DCHostname",
                    "$DomainNB\$($user.SamAccountName)",
                    "WrongPassword_Attempt$i!"
                )
                $badEntry.NativeObject | Out-Null # Force bind attempt
            } catch { } # Expected to fail
        }

        # Submit a ticket to the helpdesk endpoint
        $ticketBody = @{
            UserSam = $user.SamAccountName
            DisplayName = $user.Name
            Issue = "Account locked out after $attempts failed login attempts"
            Priority = "Medium"
            Source = "Automated Monitoring"
        } | ConvertTo-Json

        Invoke-WebRequest -Uri "http://$DCHostname/apps/helpdesk/api/submit" `
            -Method POST -Body $ticketBody -ContentType "application/json" `
            -UseDefaultCredentials -ErrorAction SilentlyContinue
    }

    Start-Sleep -Seconds (Get-Random -Minimum 300 -Maximum 600) # 5-10 min
}
```

**Key Design Decisions:**
- Uses `DirectoryEntry` LDAP bind (not `Test-ADAuthentication`) to generate authentic Event ID 4625/4771 logon failures
- Number of bad attempts is tuned to the actual domain lockout policy
- Uses `UseDefaultCredentials` for the HTTP call so it works with both Basic Auth and Windows Auth (survives when defenders switch from Basic to NTLM/Kerberos)

### 4.3 Helpdesk Ticket Database

**New database:** `ITDeskDB` (added to BadSQL.ps1)

```sql
CREATE DATABASE ITDeskDB;
GO
USE ITDeskDB;

CREATE TABLE Tickets (
    TicketID       INT IDENTITY(1,1) PRIMARY KEY,
    TicketNumber   AS ('HD-' + RIGHT('00000' + CAST(TicketID AS VARCHAR), 5)) PERSISTED,
    UserSam        NVARCHAR(50) NOT NULL,
    DisplayName    NVARCHAR(100),
    Issue          NVARCHAR(500) NOT NULL,
    Priority       NVARCHAR(20) DEFAULT 'Medium',
    Status         NVARCHAR(20) DEFAULT 'Open',  -- Open, Assigned, Resolved, Closed
    AssignedTo     NVARCHAR(50),
    Source         NVARCHAR(50) DEFAULT 'User',
    CreatedDate    DATETIME DEFAULT GETDATE(),
    ResolvedDate   DATETIME,
    ResolvedBy     NVARCHAR(50),
    Resolution     NVARCHAR(500),
    Department     NVARCHAR(50),
    Notes          NVARCHAR(1000)
);

CREATE TABLE TicketHistory (
    HistoryID      INT IDENTITY(1,1) PRIMARY KEY,
    TicketID       INT REFERENCES Tickets(TicketID),
    Action         NVARCHAR(50),
    PerformedBy    NVARCHAR(50),
    Timestamp      DATETIME DEFAULT GETDATE(),
    Details        NVARCHAR(500)
);
```

### 4.4 ASP.NET Helpdesk Endpoint

**Deployment:** Extend `BadIIS.ps1` to create `/apps/helpdesk/` with a simple ASPX page that accepts POST requests and writes to the ITDeskDB.

This is an `.aspx` file because BadIIS already runs on IIS with ASP.NET support. The endpoint:
- Accepts JSON POST with `UserSam`, `DisplayName`, `Issue`, `Priority`, `Source`
- INSERTs into `Tickets` table
- Returns ticket number in response

### 4.5 Auto-Resolution Engine

**File:** `Invoke-HelpdeskAutoResolve.ps1` (runs on Simulator VM)

**Logic:**
- Every 2–5 minutes, query `ITDeskDB.Tickets` for `Status = 'Open'`
- For 80% of tickets: automatically run `Unlock-ADAccount -Identity $UserSam`, update ticket to `Resolved`, set `ResolvedBy = 'AutoResolve_Bot'`
- For 20% of tickets: set `Status = 'Assigned'`, leave for Blue Team to complete manually
- Log all actions to `TicketHistory`

### 4.6 Ticket Management Frontend

**File:** `/apps/helpdesk/index.html`

A simple HTML page that:
- Displays all open/assigned tickets in a table
- Shows ticket history
- Allows Blue Team to manually resolve tickets (update status, add resolution notes)
- Integrates with AD to show the locked-out user's department, title, and manager
- Uses the same Brown/Springfield Box Factory CSS theme as the rest of the site

### 4.7 Scoring Criteria

| Check | Pass Condition | Points |
|-------|----------------|--------|
| Lockout events generating | Event ID 4740 in Security log within last 15 min | 5 |
| Ticket system accepting POSTs | HTTP 200 from `/apps/helpdesk/api/submit` | 5 |
| Tickets being created | Row count in `Tickets` table increasing | 5 |
| Auto-resolution working | Tickets moving from Open → Resolved | 5 |
| Manual tickets visible | 20% of tickets in `Assigned` status for Blue Team | 5 |
| Frontend accessible | HTTP 200 from `/apps/helpdesk/` | 5 |

---

## 5. Phase 4: User Sessions & File Operations

### Difficulty: Moderate/Hard
### Estimated Effort: 8–10 hours
### Dependencies: Phase 1, BadFS.ps1 already run

### 5.1 Component Overview

This feature generates realistic interactive logon events (Event ID 4624, Logon Type 2/3) and SMB file operations using actual AD user identities. It directly leverages the file share structure at `C:\CorpShares` already created by BadFS.ps1.

### 5.2 Win32 LogonUser API Wrapper

**Objective:** Use `Add-Type` to compile a C# wrapper for the Win32 `LogonUser` API, allowing the simulator to impersonate real AD users and perform file operations under their security context.

**C# Wrapper:**

```csharp
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

public class UserImpersonation {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(
        string lpszUsername, string lpszDomain, string lpszPassword,
        int dwLogonType, int dwLogonProvider, out IntPtr phToken);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    public const int LOGON32_LOGON_INTERACTIVE = 2;
    public const int LOGON32_LOGON_NETWORK = 3;
    public const int LOGON32_PROVIDER_DEFAULT = 0;
}
```

**PowerShell Integration:**

```powershell
Add-Type -TypeDefinition $CSharpSource

# Generate logon event for a real user
$token = [IntPtr]::Zero
$success = [UserImpersonation]::LogonUser(
    $UserSam, $DomainNB, $UserPassword,
    [UserImpersonation]::LOGON32_LOGON_INTERACTIVE,
    [UserImpersonation]::LOGON32_PROVIDER_DEFAULT,
    [ref]$token
)

if ($success) {
    # Impersonate and perform file operations
    [System.Security.Principal.WindowsIdentity]::RunImpersonated(
        [Microsoft.Win32.SafeHandles.SafeAccessTokenHandle]::new($token),
        [Action]{
            # Map share and do file ops under this user's context
            $drive = New-PSDrive -Name "SimUser" -PSProvider FileSystem `
                -Root "\\$env:COMPUTERNAME\CorpData" -Credential $cred
            # ... file operations ...
            Remove-PSDrive "SimUser"
        }
    )
    [UserImpersonation]::CloseHandle($token)
}
```

### 5.3 File Operation Patterns

The simulator performs randomized file operations that mimic real employee behavior:

| Operation | Weight | Detail |
|-----------|--------|--------|
| Create document | 25% | Creates a new `.txt`, `.md`, or `.csv` in the user's home dir or department folder |
| Modify existing file | 30% | Appends text to an existing file (simulates editing a document) |
| Rename file | 10% | Renames a file with a version suffix (e.g., `_v2`, `_FINAL`) |
| Delete file | 10% | Deletes an older/temporary file |
| Read/Copy file | 25% | Copies a file from a department folder to the user's home dir |

### 5.4 Session Lifecycle

Each simulated user session follows this pattern:

1. **Logon** (Event ID 4624) — Generate interactive logon using `LogonUser` API
2. **Map share** — Connect to `\\DC\CorpData` under the user's context
3. **Perform 2–8 file operations** — Random mix from the table above
4. **Dwell time** — Wait 2–5 minutes (simulates user working)
5. **Disconnect** — Unmap share, close token (Event ID 4634)

**Concurrency:** Run 3–8 simultaneous sessions at any time. Stagger start times by 30–90 seconds.

### 5.5 Password Challenge

The simulator needs passwords for real AD users to call `LogonUser`. Options:

| Approach | Pros | Cons |
|----------|------|------|
| **A. Use Black Team account for all sessions** | Simple, no password management | All logon events show same account — unrealistic |
| **B. Set known passwords on a subset of users** | Realistic per-user logons | Must coordinate with BadderBlood's password creation |
| **C. Use `BlackTeam_FileBot` with delegation** | Single account, but realistic SMB events | Requires constrained delegation setup |
| **D. Randomly generate and export all user passwords on AD entity creation** | Allows most realistic activity | Kinda annoying to implement |

**Recommended: Approach D** — Realism is the name of the game, per user logons, it's just Option B on steroids.

### 5.6 Scoring Criteria

| Check | Pass Condition | Points |
|-------|----------------|--------|
| Logon events generating | Event ID 4624 (Type 2 or 3) in last 10 min | 5 |
| SMB sessions active | `Get-SmbSession` shows active connections | 5 |
| File modifications detected | `LastWriteTime` on CorpShares files within last 10 min | 5 |
| User home dirs being accessed | Logon events for multiple distinct users | 5 |
| Sessions cycling | Both 4624 and 4634 events (connect + disconnect) | 5 |

---

## 6. Phase 5: Customer Orders (IIS Web Requests)

### Difficulty: Hard
### Estimated Effort: 10–12 hours
### Dependencies: Phase 1, BadIIS.ps1 already run, BadSQL.ps1 already run

### 6.1 Component Overview

Currently, BadIIS generates purely static HTML pages. This phase upgrades the order system to accept dynamic POST requests that write customer orders to the SQL databases.

### 6.2 Upgrade BadIIS to Active Server Pages

**Objective:** Deploy `.aspx` files at `/apps/orders/` that can:
- Accept `Invoke-WebRequest -Method POST` payloads containing Customer, BoxType, Quantity data
- Execute backend logic to INSERT into `BoxArchive2019.ArchivedOrders` (and optionally `NailInventoryDB`)
- Return order confirmation with an order number

**New File:** `C:\inetpub\SpringfieldBoxFactory\apps\orders\api\submit.aspx`

This ASPX page:
1. Reads the POST body (JSON: `{ "customer": "...", "boxType": "...", "quantity": N }`)
2. Connects to SQL using `UseDefaultCredentials` (Windows Auth) or reads connection string from IIS app settings
3. INSERTs into `ArchivedOrders`
4. Returns JSON response with order ID

### 6.3 Order Traffic Generator

**File:** `Invoke-OrderSimulator.ps1` (runs on Simulator VM)

```powershell
$Customers = @(
    "Acme Roadrunner Supplies", "Shelbyville Paper Co",
    "Globex Export LLC", "Brockway Industries",
    "Ogdenville Crafts", "Capital City Logistics"
)
$BoxTypes = @(
    "Finisher Box", "Standard Corrugated",
    "Heavy Duty Double Wall", "Mailer Box", "The Mistake"
)

while ($true) {
    $orderCount = Get-Random -Minimum 1 -Maximum 5

    for ($i = 0; $i -lt $orderCount; $i++) {
        $order = @{
            customer = $Customers | Get-Random
            boxType  = $BoxTypes | Get-Random
            quantity = Get-Random -Minimum 10 -Maximum 500
        } | ConvertTo-Json

        Invoke-WebRequest -Uri "http://$DCHostname/apps/orders/api/submit" `
            -Method POST -Body $order -ContentType "application/json" `
            -UseDefaultCredentials -ErrorAction SilentlyContinue
    }

    Start-Sleep -Seconds (Get-Random -Minimum 60 -Maximum 300) # 1-5 min
}
```

**Crucial Guardrail:** Uses `UseDefaultCredentials` which negotiates NTLM/Kerberos natively. If defenders switch IIS from Basic Auth to Windows Auth (a remediation step), this script continues working without changes.

### 6.4 Scoring Criteria

| Check | Pass Condition | Points |
|-------|----------------|--------|
| ASPX endpoint responding | HTTP 200 from `/apps/orders/api/submit` (POST) | 5 |
| Orders being inserted | Row count in `ArchivedOrders` increasing | 10 |
| IIS access logs growing | W3C log entries for POST to `/apps/orders/` | 5 |
| Response time < 5 sec | POST completes within 5 seconds | 5 |

---

## 7. Phase 6: Realistic Email & Communications

### Difficulty: Hardest
### Estimated Effort: 15–20 hours
### Dependencies: Phase 1, BadFS.ps1 (for user data and department jargon)

### 7.1 Component Overview

BadderBlood currently does NOT deploy a mail server. This phase installs MailEnable (free community edition), provisions mailboxes from AD, and generates continuous inter-office email traffic using department-specific jargon from BadFS.

### 7.2 MailEnable Installation

**File:** `Deploy-MailServer.ps1`

| # | Task | Detail |
|---|------|--------|
| 1 | Download MailEnable CE | Silent command-line install from MailEnable website |
| 2 | Configure domain | Set mail domain to match `$DomainDNS` (e.g., `spboxfactory.com`) |
| 3 | Provision mailboxes | Iterate through `$global:AllADUsers` array (from BadFS) and create MailEnable mailboxes using its administration API/COM objects |
| 4 | Configure SMTP relay | Allow relay from the lab subnet for the simulator VM |
| 5 | Set DNS MX record | Add MX record pointing to the DC (or mail server) |

### 7.3 Email Traffic Generator

**File:** `Invoke-EmailSimulator.ps1` (runs on Simulator VM)

**Email Distribution Algorithm:**

The distribution model ensures realistic communication patterns:

```
For each email:
  75% chance: INTRA-PROJECT (sender and recipient share a project/department)
  25% chance: CROSS-DEPARTMENT, with hierarchy weighting:
    50% → Same management level (peer-to-peer)
    25% → One level above or below (direct manager/report)
    12.5% → Two levels above or below
    12.5% → Three levels above or below
    If the org chart doesn't go that deep/high, gracefully clamp to available levels
```

**Content Generation:** Leverage BadFS's `Get-CorporateIpsum` function and department jargon from `$global:DepartmentContexts` to make email bodies look legitimate.

**Email Template Types:**

| Type | Weight | Subject Pattern | Body Pattern |
|------|--------|-----------------|--------------|
| Status update | 25% | "RE: [Project] Status Update" | Corporate ipsum with project jargon |
| Meeting request | 15% | "[Dept] Sync - [Date]" | Meeting time + agenda items |
| Escalation | 10% | "URGENT: [Issue] requires attention" | Problem description + action items |
| FYI/Forward | 20% | "FW: [Topic]" | Short note + forwarded content |
| Question | 15% | "Question about [Topic]" | Short question + context |
| Approval request | 10% | "Approval needed: [Item]" | Budget/purchase/access request |
| Social/casual | 5% | "Lunch?" / "Happy Birthday!" | Short casual message |

### 7.4 Hierarchy-Aware Recipient Selection

```powershell
function Get-EmailRecipient {
    param(
        [object]$Sender,
        [int]$SenderLevel,  # 1-8 from jobtitles.csv
        [string]$SenderDept
    )

    $roll = Get-Random -Minimum 1 -Maximum 101

    if ($roll -le 75) {
        # Same project/department
        $deptUsers = $AllADUsers | Where-Object { $_.Department -eq $SenderDept -and $_.SamAccountName -ne $Sender.SamAccountName }
        return $deptUsers | Get-Random
    }

    # Cross-department with hierarchy weighting
    $levelRoll = Get-Random -Minimum 1 -Maximum 101
    $targetLevel = if ($levelRoll -le 50) {
        $SenderLevel  # Same level
    } elseif ($levelRoll -le 75) {
        $SenderLevel + (1, -1 | Get-Random)  # ±1
    } elseif ($levelRoll -le 87) {
        $SenderLevel + (2, -2 | Get-Random)  # ±2
    } else {
        $SenderLevel + (3, -3 | Get-Random)  # ±3
    }

    # Clamp to valid range (1-8)
    $targetLevel = [Math]::Max(1, [Math]::Min(8, $targetLevel))

    # Find users at the target level in any department
    $candidates = $AllADUsers | Where-Object {
        $_.SamAccountName -ne $Sender.SamAccountName -and
        (Get-TitleLevel -Title $_.Title) -eq $targetLevel
    }

    if ($candidates.Count -gt 0) { return $candidates | Get-Random }

    # Graceful fallback: any user not the sender
    return $AllADUsers | Where-Object { $_.SamAccountName -ne $Sender.SamAccountName } | Get-Random
}
```

### 7.5 SMTP Sending

```powershell
$SmtpServer = $DCHostname  # or dedicated mail server
$From = $Sender.EmailAddress
$To = $Recipient.EmailAddress

Send-MailMessage -SmtpServer $SmtpServer -From $From -To $To `
    -Subject $Subject -Body $Body -Priority Normal `
    -ErrorAction SilentlyContinue
```

**Alternative:** Use `System.Net.Mail.SmtpClient` for more control over headers and authentication.

### 7.6 Scoring Criteria

| Check | Pass Condition | Points |
|-------|----------------|--------|
| SMTP service running | Port 25 accepting connections | 5 |
| Mailboxes provisioned | MailEnable mailbox count ≥ AD user count × 80% | 5 |
| Emails being sent | SMTP log entries within last 10 min | 10 |
| Inter-department emails | Sender and recipient from different departments | 5 |
| Hierarchy distribution correct | Sample of 20 emails shows expected level distribution | 5 |

---

## 8. Integration & Orchestration

### 8.1 Master Orchestrator Script

**File:** `Invoke-ContinuousSimulator.ps1`

This is the single entry point that starts all simulators as background jobs:

```powershell
param(
    [string]$DCHostname = (Resolve-DnsName -Name $env:USERDNSDOMAIN -Type A | Select -First 1).IPAddress,
    [string]$CredentialFile = "C:\Simulator\credentials.json",
    [switch]$SkipEmail,
    [switch]$SkipHelpdesk,
    [switch]$SkipOrders,
    [switch]$SkipFileSessions,
    [switch]$SkipSupplierDeliveries
)

Write-Host "Starting BadderBlood Continuous Activity Simulator..." -ForegroundColor Green

# Start each simulator as a background job
if (-not $SkipSupplierDeliveries) {
    Start-Job -Name "Supplier_Deliveries" -FilePath "C:\Simulator\Invoke-SupplierDelivery.ps1" -ArgumentList $DCHostname
}
if (-not $SkipHelpdesk) {
    Start-Job -Name "Helpdesk_Lockouts" -FilePath "C:\Simulator\Invoke-LockoutSimulator.ps1" -ArgumentList $DCHostname
    Start-Job -Name "Helpdesk_AutoResolve" -FilePath "C:\Simulator\Invoke-HelpdeskAutoResolve.ps1" -ArgumentList $DCHostname
}
if (-not $SkipFileSessions) {
    Start-Job -Name "User_Sessions" -FilePath "C:\Simulator\Invoke-UserSessionSimulator.ps1" -ArgumentList $DCHostname
}
if (-not $SkipOrders) {
    Start-Job -Name "Customer_Orders" -FilePath "C:\Simulator\Invoke-OrderSimulator.ps1" -ArgumentList $DCHostname
}
if (-not $SkipEmail) {
    Start-Job -Name "Email_Traffic" -FilePath "C:\Simulator\Invoke-EmailSimulator.ps1" -ArgumentList $DCHostname
}

# Monitor loop
while ($true) {
    $jobs = Get-Job | Where-Object { $_.Name -like "*Simulator*" -or $_.Name -like "*Deliveries*" -or $_.Name -like "*Lockouts*" -or $_.Name -like "*AutoResolve*" -or $_.Name -like "*Sessions*" -or $_.Name -like "*Orders*" -or $_.Name -like "*Traffic*" }
    foreach ($job in $jobs) {
        if ($job.State -eq "Failed") {
            Write-Warning "Job $($job.Name) failed. Restarting..."
            $job | Remove-Job -Force
            # Restart logic here
        }
    }
    Start-Sleep -Seconds 60
}
```

### 8.2 Scheduled Task Deployment

Deploy the orchestrator as a Windows Scheduled Task on the simulator VM that starts at boot:

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -NoProfile -File C:\Simulator\Invoke-ContinuousSimulator.ps1"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
Register-ScheduledTask -TaskName "BadderBlood_Simulator" -Action $action -Trigger $trigger -Principal $principal
```

### 8.3 Integration with Invoke-BadderBlood.ps1

Add a new phase to `Invoke-BadderBlood.ps1` (Phase 11) that:
1. Runs `Deploy-BlackTeamAccounts.ps1` on the DC
2. Copies simulator scripts to the simulator VM (or provides instructions for manual deployment)
3. Optionally triggers `Deploy-MailServer.ps1`

---

## 9. Scoring & Observability

### 9.1 Service Uptime Scoring

**File:** `Invoke-UptimeScorer.ps1` (runs on Simulator VM every 5 minutes)

Checks each service and writes a score to `C:\Simulator\scores.json`:

```json
{
  "timestamp": "2025-03-16T12:00:00Z",
  "services": {
    "sql_agent": { "status": "UP", "score": 10, "lastCheck": "..." },
    "supplier_deliveries": { "status": "UP", "score": 10, "lastCheck": "..." },
    "helpdesk_api": { "status": "UP", "score": 10, "lastCheck": "..." },
    "iis_site": { "status": "UP", "score": 10, "lastCheck": "..." },
    "order_api": { "status": "UP", "score": 10, "lastCheck": "..." },
    "smb_share": { "status": "UP", "score": 10, "lastCheck": "..." },
    "email_smtp": { "status": "UP", "score": 10, "lastCheck": "..." },
    "ad_ldap": { "status": "UP", "score": 10, "lastCheck": "..." }
  },
  "totalScore": 80,
  "maxScore": 80,
  "uptimePercent": 100.0
}
```

### 9.2 Scoring Dashboard

Optional: Deploy a simple HTML dashboard on the simulator VM (port 8080) that displays real-time service status with green/red indicators and uptime percentages over time.

---

## 10. Testing & Validation

### 10.1 Test Matrix

| Test | Pre-Condition | Action | Expected Result |
|------|---------------|--------|-----------------|
| T1: Baseline traffic | All services running | Start simulator | All 6 traffic types generating |
| T2: Password rotation | Simulator running | Change `svc_sql` password | SQL traffic fails → update `credentials.json` → traffic resumes |
| T3: SMB signing enforcement | Simulator running | GPO: RequireSecuritySignature=1 | File session traffic continues (modern OS supports signing) |
| T4: Disable Basic Auth | Simulator running | Switch IIS to Windows Auth only | Web traffic continues (UseDefaultCredentials handles NTLM) |
| T5: Firewall enforcement | Simulator running | Enable Windows Firewall | Traffic continues if proper exceptions exist |
| T6: NTLM hardening | Simulator running | Set LmCompatibilityLevel=5 | Traffic continues (modern OS negotiates NTLMv2) |
| T7: SQL Mixed Mode disabled | Simulator running | Set SQL to Windows Auth only | SQL traffic continues (BlackTeam accounts use Windows Auth) |
| T8: Service restart | Simulator running | Restart SQL/IIS service | Traffic resumes after service comes back |

### 10.2 Deployment Order

```
1. Run Invoke-BadderBlood.ps1 (creates AD objects, OU structure, users, groups, etc.)
2. Run BadFS.ps1 (creates file shares, user home dirs, corporate data)
3. Run BadIIS.ps1 (deploys IIS site with dynamic content from AD)
4. Run BadSQL.ps1 (installs SQL, creates databases, deploys web apps)
5. Run Deploy-BlackTeamAccounts.ps1 (creates Black Team AD accounts)
6. Deploy Simulator VM (provision, install RSAT, copy scripts)
7. Run Deploy-SupplierDeliveryJob.ps1 (adds SQL Agent job)
8. Run Deploy-HelpdeskSystem.ps1 (creates ITDeskDB, deploys ASPX endpoint)
9. Run Deploy-OrderEndpoint.ps1 (deploys order submission ASPX)
10. Run Deploy-MailServer.ps1 (installs MailEnable, provisions mailboxes)
11. Run Invoke-ContinuousSimulator.ps1 (starts all traffic generators)
12. Run Invoke-UptimeScorer.ps1 (starts scoring)
13. Run BadderBloodAnswerKey.ps1 (generates answer key with all findings)
```

---

## Appendix A: File Inventory

| File | Location | Purpose |
|------|----------|---------|
| `Deploy-BlackTeamAccounts.ps1` | `C:\BadderBlood\ADServices\` | Creates Black Team AD accounts and OU |
| `Deploy-SupplierDeliveryJob.ps1` | `C:\BadderBlood\ADServices\` | Adds SQL Agent job for supplier deliveries |
| `Deploy-HelpdeskSystem.ps1` | `C:\BadderBlood\ADServices\` | Creates ITDeskDB, deploys ASPX helpdesk endpoint |
| `Deploy-OrderEndpoint.ps1` | `C:\BadderBlood\ADServices\` | Deploys order submission ASPX endpoint |
| `Deploy-MailServer.ps1` | `C:\BadderBlood\ADServices\` | Installs MailEnable, provisions mailboxes |
| `Invoke-ContinuousSimulator.ps1` | `C:\Simulator\` (on simulator VM) | Master orchestrator |
| `Invoke-SupplierDelivery.ps1` | `C:\Simulator\` | SQL transaction generator |
| `Invoke-LockoutSimulator.ps1` | `C:\Simulator\` | AD lockout generator |
| `Invoke-HelpdeskAutoResolve.ps1` | `C:\Simulator\` | Ticket auto-resolution engine |
| `Invoke-UserSessionSimulator.ps1` | `C:\Simulator\` | User logon/file ops simulator |
| `Invoke-OrderSimulator.ps1` | `C:\Simulator\` | Customer order HTTP POST generator |
| `Invoke-EmailSimulator.ps1` | `C:\Simulator\` | Email traffic generator |
| `Invoke-UptimeScorer.ps1` | `C:\Simulator\` | Service uptime scoring engine |
| `credentials.json` | `C:\Simulator\` | Dynamic credential store |
| `Rules_of_Engagement.txt` | `C:\CorpShares\Public_Company_Data\` | Student RoE document |

## Appendix B: Estimated Total Effort

| Phase | Hours | Difficulty |
|-------|-------|------------|
| Phase 1: Infrastructure & Black Team | 4–6 | Foundational |
| Phase 2: Supplier Deliveries (SQL) | 2–3 | Easiest |
| Phase 3: Helpdesk (Lockouts + Tickets) | 6–8 | Easy/Moderate |
| Phase 4: User Sessions & File Ops | 8–10 | Moderate/Hard |
| Phase 5: Customer Orders (IIS) | 10–12 | Hard |
| Phase 6: Email/Communications | 15–20 | Hardest |
| Integration & Scoring | 4–6 | Moderate |
| Testing & Validation | 4–6 | Moderate |
| **TOTAL** | **53–71 hours** | |

## Appendix C: Wargaming Scenarios

Once the simulator is running, here are some thought experiments for the lab:

**Scenario: What if the Blue Team blocks NTLM entirely?**
- Supplier deliveries (SQL): Survives — uses Kerberos via Windows Auth
- Helpdesk: Survives if IIS is switched to Kerberos auth
- File sessions: Breaks if `LogonUser` used NTLM — must switch to Kerberos delegation
- Orders: Survives if `UseDefaultCredentials` negotiates Kerberos
- Email: SMTP typically doesn't use NTLM — survives

**Scenario: What if they segment the network and firewall off the simulator VM?**
- ALL traffic stops. This is a valid Blue Team strategy — but they must explain why they chose to break all business services. The scoring portal would show 0% uptime. Teaches that security without availability is not security.

**Scenario: What if they find and read credentials.json?**
- They learn Black Team account passwords. Since the RoE says they can't change them, this is information disclosure but not actionable. Teaches that defense-in-depth matters even when you can see the credentials.

**Scenario: What if they deploy Sysmon and see all the simulator traffic?**
- Great! That's the point. They can now baseline "normal" and spot anomalies from actual Red Team activity. Teaches the value of behavioral analysis over signature-based detection.
