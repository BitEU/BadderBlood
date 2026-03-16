# BadderBlood Continuous Activity Simulator — Phases 1–4

Generates realistic AD/network noise so Blue Team defenders have authentic telemetry to monitor, triage, and score.

---

## Quick Start

Run the orchestrator on the **DC** to deploy all phases in order:

```powershell
.\Invoke-ContinuousActivitySimulator.ps1 `
    -HMailAdminPassword (Read-Host "hMailServer admin password" -AsSecureString) `
    -LabSubnet "192.168.10.0/24"
```

Skip phases you've already deployed with `-SkipPhase1` through `-SkipPhase6`.
Phase 6 requires hMailServer to be manually installed first (see Phase 6 details below).

---

## Script Reference

### Deployment Scripts — run once, on the appropriate server

| Script | Run On | Purpose |
|---|---|---|
| `Deploy-BlackTeamAccounts.ps1` | **DC** (Domain Admin) | Phase 1 — creates BlackTeam OU + 5 service accounts |
| `Deploy-SupplierDeliveryJob.ps1` | **SQL host** (sysadmin) | Phase 2 — installs SQL Agent jobs |
| `Deploy-HelpdeskSystem.ps1` | **IIS + SQL host** (admin) | Phase 3 — creates ITDeskDB + ASPX helpdesk endpoints |
| `Deploy-UserPasswordExport.ps1` | **DC** (Domain Admin) | Phase 4 — sets known passwords on ~40 users, exports `user_passwords.json` |
| `Deploy-OrderEndpoint.ps1` | **IIS + SQL host** (admin) | Phase 5 — deploys order ASPX API + OrdersAppPool |
| `Deploy-MailServer.ps1` | **DC / mail host** (Domain Admin) | Phase 6 — configures hMailServer, provisions mailboxes |

### Runtime Scripts — run continuously on the **Simulator VM**

| Script | Purpose |
|---|---|
| `Invoke-LockoutSimulator.ps1` | Phase 3 — generates account lockouts + helpdesk tickets |
| `Invoke-HelpdeskAutoResolve.ps1` | Phase 3 — auto-resolves 80% of lockout tickets via LDAP |
| `Invoke-UserSessionSimulator.ps1` | Phase 4 — simulates interactive user logons + SMB file activity |
| `Invoke-OrderSimulator.ps1` | Phase 5 — sends customer order HTTP POSTs to the orders API |
| `Invoke-EmailSimulator.ps1` | Phase 6 — generates inter-office email traffic via SMTP |

---

## Phase Details

### Phase 1 — BlackTeam Accounts
**Script:** `Deploy-BlackTeamAccounts.ps1` | **Runs on:** DC

Creates `OU=BlackTeam,OU=Admin` (protected from deletion) with five dedicated service accounts:

| Account | Role |
|---|---|
| `BlackTeam_Scorebot` | Reads AD/scoring state |
| `BlackTeam_SQLBot` | Owns SQL Agent jobs (Windows Auth) |
| `BlackTeam_WebBot` | IIS application pool identity |
| `BlackTeam_FileBot` | SMB file operations (Modify on C:\CorpShares\CorpData) |
| `BlackTeam_MailBot` | Reserved for Phase 6 SMTP simulation |

Outputs:
- `credentials.json` — credential store for runtime scripts (Blue Team must update within 5 min of rotation)
- `Rules_of_Engagement.txt` — full RoE covering off-limits accounts, scoring, and flags

Default password for all accounts: `B!ackT3am_Sc0reb0t_2025#`

---

### Phase 2 — Supplier Delivery Simulation
**Script:** `Deploy-SupplierDeliveryJob.ps1` | **Runs on:** SQL host

Creates two SQL Server Agent jobs on **NailInventoryDB** owned by `DOMAIN\BlackTeam_SQLBot` (Windows Auth — survives Mixed Mode disablement):

| Job | Schedule | Activity |
|---|---|---|
| SBF - Supplier Delivery Simulation | Every 15 min | Inserts random nail deliveries into Inventory + PurchaseOrders |
| SBF - Inventory Reorder Check | Every 30 min | Checks low-stock items, inserts reorder POs |

T-SQL uses `WITH (TABLOCKX)` on Inventory — intentional contention defenders can observe.

---

### Phase 3 — Helpdesk System + Lockout Simulation
**Deploy script:** `Deploy-HelpdeskSystem.ps1` | **Runs on:** IIS + SQL host
**Runtime scripts:** `Invoke-LockoutSimulator.ps1`, `Invoke-HelpdeskAutoResolve.ps1` | **Run on:** Simulator VM

**Database:** `ITDeskDB` with `Tickets` and `TicketHistory` tables. Tickets get auto-generated numbers (`HD-XXXXX`).
Stored procedures: `usp_SubmitTicket`, `usp_GetOpenTickets`, `usp_ResolveTicket`

**IIS endpoints** at `/apps/helpdesk/api/` (Windows Auth, no anonymous):

| Endpoint | Method | Purpose |
|---|---|---|
| `submit.aspx` | POST | Create new ticket |
| `status.aspx` | GET | Single ticket status |
| `tickets.aspx` | GET | List open tickets |
| `resolve.aspx` | POST | Update ticket status/assignee |
| `index.html` | GET | Ticket management UI (polls every 30s) |

**Lockout loop** (`Invoke-LockoutSimulator.ps1`):
- Every 5–10 min: picks 1–3 random non-privileged users
- Binds to LDAP with bad passwords `lockoutThreshold + 1–3` times → generates real **Event ID 4625** (failed logon) and **4740** (account lockout)
- Submits a helpdesk ticket for each lockout

**Auto-resolve loop** (`Invoke-HelpdeskAutoResolve.ps1`):
- Every 2–5 min: fetches open tickets
- **80%** → unlocks account via DirectoryEntry, resolves ticket
- **20%** → assigns to L1 (manual Blue Team triage opportunity)

---

### Phase 4 — User Session Simulation
**Deploy script:** `Deploy-UserPasswordExport.ps1` | **Runs on:** DC
**Runtime script:** `Invoke-UserSessionSimulator.ps1` | **Runs on:** Simulator VM

**Credential bootstrap** (`Deploy-UserPasswordExport.ps1`):
- Selects ~40 enabled, non-privileged users (excludes Domain Admins, service accounts, BlackTeam, Protected Users)
- Sets passwords from a themed pool (`SpringField1!`, `BoxFactory1!`, `Nails2025!`, `Cardboard1!`, etc.)
- Writes `user_passwords.json` to `$SimulatorPath`

**Session simulator** (`Invoke-UserSessionSimulator.ps1`):
- Compiles a C# `SimLogon` class at runtime via `Add-Type` (Win32 `LogonUser` + `SafeAccessTokenHandle` from `advapi32.dll`)
- Runs 3–8 concurrent jobs per wave, staggered 0–90 s apart
- Each job:
  1. `LogonUser(LOGON32_LOGON_INTERACTIVE)` → **Event ID 4624**
  2. `WindowsIdentity.RunImpersonated` → map `\\DC\CorpData`
  3. 2–8 random file ops (Create 25% / Modify 30% / Rename 10% / Delete 10% / Copy 25%)
  4. Dwell 2–5 min
  5. Token dispose → **Event ID 4634**
- Stale users (password rotated) are skipped gracefully until `user_passwords.json` reloads every 30 min
- Logs to `C:\Simulator\Logs\UserSessionSimulator_YYYYMMDD.log`

---

### Phase 5 — Customer Order Simulation
**Deploy script:** `Deploy-OrderEndpoint.ps1` | **Runs on:** IIS + SQL host
**Runtime script:** `Invoke-OrderSimulator.ps1` | **Runs on:** Simulator VM

**Database target:** `BoxArchive2019.ArchivedOrders` (created by BadSQL.ps1). The deploy script grants `BlackTeam_WebBot` `db_datareader`/`db_datawriter` on this database.

**IIS setup:**
- New app pool `OrdersAppPool` (.NET CLR v4.0, Integrated, AlwaysRunning) running as `DOMAIN\BlackTeam_WebBot`
- IIS application at `/apps/orders/api` (Windows Auth, no anonymous)

**ASPX endpoints** at `/apps/orders/api/`:

| Endpoint | Method | Purpose |
|---|---|---|
| `submit.aspx` | POST | Accept `{ customer, boxType, quantity }` → INSERT ArchivedOrders → return `{ orderId, orderNumber }` |
| `status.aspx?id=N` | GET | Return single order as JSON |
| `orders.aspx` | GET | Return last 50 orders as JSON array |

**Order simulator** (`Invoke-OrderSimulator.ps1`):
- Every 1–5 min: sends 1–4 order POSTs
- Uses `System.Net.WebClient` with `NetworkCredential` for NTLM (Windows Auth — survives IIS auth hardening)
- Customers: Acme Roadrunner Supplies, Globex Export LLC, Brockway Industries, Ogdenville Crafts, etc.
- BoxTypes: Finisher Box, Standard Corrugated, Heavy Duty Double Wall, Mailer Box, The Mistake, etc.
- Reloads `credentials.json` every 5 min; force-reloads on 3 consecutive failures
- Logs to `C:\Simulator\Logs\OrderSimulator_YYYYMMDD.log`

---

### Phase 6 — Email Simulation
**Pre-requisite:** Install **hMailServer** (free) manually on the DC/mail host before running Deploy-MailServer.ps1 from https://www.hmailserver.com/download_getfile?performdownload=1&downloadid=271
**Deploy script:** `Deploy-MailServer.ps1` | **Runs on:** DC / mail host (Domain Admin)
**Runtime script:** `Invoke-EmailSimulator.ps1` | **Runs on:** Simulator VM

**hMailServer setup** (`Deploy-MailServer.ps1`):
1. Verifies hMailServer COM object exists (`hMailServer.Application`) — aborts with install instructions if missing
2. Creates mail domain matching AD DNS root (e.g. `springfield.local`)
3. Provisions up to 500 hMailServer accounts for enabled AD users (constructs `firstname.lastname@domain` if EmailAddress is blank)
4. Configures SMTP relay from `127.0.0.1` and `$LabSubnet`
5. Creates `blackteam_mailbot@<domain>` relay account
6. Updates `credentials.json` smtp section with SMTP host
7. Adds DNS MX record (best-effort — requires DNS Server role on the host)

**Email simulator** (`Invoke-EmailSimulator.ps1`):
- Reads user list from `user_passwords.json` (Phase 4); constructs email addresses
- **Distribution model:**
  - 75% intra-department emails
  - 25% cross-department, weighted by org hierarchy: same level 50%, ±1 level 25%, ±2 level 12.5%, ±3 level 12.5%
- **Template types:** Status Update (25%), FYI/Forward (20%), Meeting Request (15%), Question (15%), Escalation (10%), Approval Request (10%), Social/Casual (5%)
- Content: Springfield Box Factory themed (nail types, box types, customers, department jargon)
- Sends via `System.Net.Mail.SmtpClient`, authenticated as `BlackTeam_MailBot`
- Every 30–120 sec: sends 1–4 emails
- Reloads credentials every 5 min; force-reloads on 3 consecutive SMTP failures
- Logs to `C:\Simulator\Logs\EmailSimulator_YYYYMMDD.log`

---

## Execution Order

```
1.  Invoke-BadderBlood.ps1          (DC)       — base AD environment
2.  BadSQL.ps1                      (SQL host) — NailInventoryDB + BoxArchive2019
3.  BadIIS.ps1                      (IIS host) — Springfield Box Factory site
4.  BadFS.ps1                       (DC/FS)    — CorpData SMB share
    [Install hMailServer on DC/mail host before Phase 6]
5.  Deploy-BlackTeamAccounts.ps1    (DC)       — Phase 1
6.  Deploy-SupplierDeliveryJob.ps1  (SQL host) — Phase 2
7.  Deploy-HelpdeskSystem.ps1       (IIS host) — Phase 3
8.  Deploy-UserPasswordExport.ps1   (DC)       — Phase 4
9.  Deploy-OrderEndpoint.ps1        (IIS host) — Phase 5
10. Deploy-MailServer.ps1           (DC/mail)  — Phase 6
--- simulator VM boots ---
11. Invoke-LockoutSimulator.ps1     (sim VM)   — Phase 3 runtime (continuous)
12. Invoke-HelpdeskAutoResolve.ps1  (sim VM)   — Phase 3 runtime (continuous)
13. Invoke-UserSessionSimulator.ps1 (sim VM)   — Phase 4 runtime (continuous)
14. Invoke-OrderSimulator.ps1       (sim VM)   — Phase 5 runtime (continuous)
15. Invoke-EmailSimulator.ps1       (sim VM)   — Phase 6 runtime (continuous)
```

Or use the orchestrator (`Invoke-ContinuousActivitySimulator.ps1`) on the DC to run steps 5–10 in one shot.

---

## Logs

All runtime scripts write daily rolling logs to `C:\Simulator\Logs\`:

| Log file | Source |
|---|---|
| `LockoutSimulator_YYYYMMDD.log` | `Invoke-LockoutSimulator.ps1` |
| `HelpdeskAutoResolve_YYYYMMDD.log` | `Invoke-HelpdeskAutoResolve.ps1` |
| `UserSessionSimulator_YYYYMMDD.log` | `Invoke-UserSessionSimulator.ps1` |
| `OrderSimulator_YYYYMMDD.log` | `Invoke-OrderSimulator.ps1` |
| `EmailSimulator_YYYYMMDD.log` | `Invoke-EmailSimulator.ps1` |

---

## Blue Team Notes

- **BlackTeam accounts are off-limits** — disabling/modifying them stops the simulator and voids scoring
- Credentials in `credentials.json` must be updated within **5 minutes** of any password rotation
- Lockout tickets assigned to L1 (`Invoke-HelpdeskAutoResolve`) require manual triage via the helpdesk UI
- `user_passwords.json` reloads every 30 min — rotated user passwords will naturally fall out of session simulation
