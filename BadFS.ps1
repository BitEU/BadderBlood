<#
.SYNOPSIS
    Advanced Corporate File Share & Unstructured Data Generator for BadderBlood.
.DESCRIPTION
    This script generates a highly realistic corporate file server structure.
    It simulates unstructured data sprawl by generating context-aware documents, 
    including employee resumes, department-specific project proposals, financial 
    ledgers, meeting minutes, and PII (Personal Identifiable Information) such as 
    employee rosters with simulated salaries and SSNs.
    
    It intentionally avoids cheap tricks (like hardcoded passwords) in favor of 
    realistic enterprise risk: over-permissioned PII, intellectual property, 
    and sensitive business communications.
.NOTES
    Author: BadderBlood Integration
    Version: 3.0 (Native BadderBlood Org Integration Engine)
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)][string]$BaseSharePath = "C:\CorpShares",
    [Parameter(Mandatory=$false)][string]$ShareName = "CorpData",
    [Parameter(Mandatory=$false)][int]$MaxFilesPerFolder = 15,
    [Parameter(Mandatory=$false)][int]$UserPopulationPercentage = 50,
    [Parameter(Mandatory=$false)][switch]$ForceLocalMode # Runs without AD, generates random names
)

$ErrorActionPreference = "SilentlyContinue"
Write-Verbose "Starting Advanced Corporate File Share Generation..."

# ==============================================================================
# SECTION 0: BADDERBLOOD INTEGRATION (REAL AD DATA)
# Fetch real users early so all generators (PII, CSVs, Resumes) use actual entities
# ==============================================================================
$global:AllADUsers = @()
if (-not $ForceLocalMode) {
    try {
        # Note: Grabbing the Manager property to build realistic Performance Reviews based on the Org Chart
        $global:AllADUsers = Get-ADUser -Filter * -Properties Title, Department, EmailAddress, Manager, DistinguishedName -ErrorAction Stop | 
            Where-Object { $_.SamAccountName -notmatch "Administrator|Guest|krbtgt" }
        Write-Verbose "Successfully fetched $($global:AllADUsers.Count) real users from Active Directory."
    } catch {
        Write-Warning "Active Directory not reachable during initialization. Will fallback to list generation."
    }
}

# ==============================================================================
# SECTION 1: NATIVE BADDERBLOOD DATA PARSING
# Reads the OG BadderBlood CSVs to construct dynamic themes, jargon, and locations.
# ==============================================================================

# 1A. Load BadderBlood Names Lists
$NamesDir = Join-Path $PSScriptRoot "..\AD_Users_Create\Names"
if (Test-Path (Join-Path $NamesDir "femalenames-usa-top1000.txt")) {
    $global:FirstNames = Get-Content (Join-Path $NamesDir "femalenames-usa-top1000.txt")
    $global:FirstNames += Get-Content (Join-Path $NamesDir "malenames-usa-top1000.txt")
} else {
    $global:FirstNames = @("James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda", "David", "Elizabeth")
}

if (Test-Path (Join-Path $NamesDir "familynames-usa-top1000.txt")) {
    $global:LastNames = Get-Content (Join-Path $NamesDir "familynames-usa-top1000.txt")
} else {
    $global:LastNames = @("Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez")
}

# 1B. Load BadderBlood Organizational Data CSVs
$DeptsCSVPath = Join-Path $PSScriptRoot "..\AD_Data\AD_Departments.csv"
$JobTitlesCSVPath = Join-Path $PSScriptRoot "..\AD_Data\jobtitles.csv"
$OfficesCSVPath = Join-Path $PSScriptRoot "..\AD_Data\offices.csv"
$OrgHierarchyCSVPath = Join-Path $PSScriptRoot "..\AD_Data\org_hierarchy.csv"

$csvDepts = @()
if (Test-Path $DeptsCSVPath) { $csvDepts = Import-Csv $DeptsCSVPath }

$csvJobs = @()
if (Test-Path $JobTitlesCSVPath) { $csvJobs = Import-Csv $JobTitlesCSVPath }

$global:Offices = @()
if (Test-Path $OfficesCSVPath) { $global:Offices = Import-Csv $OfficesCSVPath }

$global:OrgHierarchy = @()
if (Test-Path $OrgHierarchyCSVPath) { $global:OrgHierarchy = Import-Csv $OrgHierarchyCSVPath }

# 1C. Build Dynamic Department Contexts using REAL Job Titles & Roles
$global:DepartmentContexts = @{}

# Mapping baseline jargon flavors for the standard BadderBlood departments
$AcronymJargonMap = @{
    "ITS" = @("Zero Trust", "Packet Loss", "Uptime", "Latency", "Helpdesk SLA", "Sysadmin")
    "HRE" = @("Talent Acquisition", "Retention Rate", "Benefits Enrollment", "Culture Fit", "Offboarding")
    "FIN" = @("EBITDA", "CapEx", "OpEx", "ROI", "Amortization", "Payroll")
    "BDE" = @("Conversion Rate", "Funnel", "Upsell", "Churn", "Quota", "B2B")
    "SEC" = @("SOC", "Incident Response", "Threat Hunting", "Penetration Testing", "Vulnerability Scan", "GRC")
    "OGC" = @("Liability", "Indemnification", "Jurisdiction", "Litigation", "Due Diligence")
    "AWS" = @("EC2", "S3 Bucket", "IAM Policy", "VPC Peering", "Lambda", "CloudFormation")
    "GOO" = @("GKE", "BigQuery", "Cloud Run", "IAM Roles", "Anthos", "Compute Engine")
    "AZR" = @("Entra ID", "ARM Templates", "Blob Storage", "ExpressRoute", "AKS")
    "ESM" = @("Intune", "SCCM", "Patch Management", "Endpoint Protection", "MDM")
    "FSR" = @("Dispatch", "On-site", "Truck Roll", "Hardware Swap", "Client Site")
    "CORP" = @("Synergy", "Market Share", "Shareholder Value", "C-Suite", "Board of Directors")
}

foreach ($dept in $csvDepts) {
    $acronym = $dept.Acronym
    $fullName = $dept.'Department Name'
    $role = $dept.'Department Role'
    
    $themes = @("$fullName Strategy Review", "Q3 $fullName Objectives", "Strategic Execution: $role")
    $jargon = @()
    
    if ($AcronymJargonMap.ContainsKey($acronym)) {
        $jargon += $AcronymJargonMap[$acronym]
        $themes += $AcronymJargonMap[$acronym] | ForEach-Object { "$_ Optimization" }
    } else {
        $jargon += @("Deliverables", "Optimization", "Workflow")
    }

    # Inject actual BadderBlood job titles into the jargon and themes
    $deptJobs = $csvJobs | Where-Object { $_.Acronym -eq $acronym }
    foreach ($job in $deptJobs) {
        $jargon += $job.Title
        $themes += "Hiring: $($job.Title)"
        $themes += "$($job.Title) Sync/Standup"
    }
    
    $global:DepartmentContexts[$acronym] = @{
        FullName = $fullName
        Role = $role
        Themes = $themes | Select-Object -Unique
        Jargon = $jargon | Select-Object -Unique
    }
}

# 1D. Static Background Data (Universities, Soft Skills, Companies)
$global:Universities = @(
    "Massachusetts Institute of Technology (MIT)", "Stanford University", "Harvard University", 
    "California Institute of Technology (Caltech)", "University of Chicago", "Princeton University", 
    "Cornell University", "Yale University", "Columbia University", "University of Pennsylvania",
    "University of Michigan", "Johns Hopkins University", "Northwestern University", "Brown University"
)
$global:Degrees = @("Bachelor of Science in Computer Science", "Bachelor of Arts in Business Administration", "Master of Business Administration (MBA)", "Master of Science in Cybersecurity")
$global:Companies = @("Acme Corp", "Globex Corporation", "Soylent Corp", "Initech", "Umbrella Corporation", "Wayne Enterprises", "Pied Piper", "Massive Dynamic")
$global:SoftSkills = @("Leadership", "Communication", "Problem Solving", "Teamwork", "Time Management", "Adaptability", "Critical Thinking")
$global:TechSkills = @("Python", "Java", "C++", "C#", "JavaScript", "HTML/CSS", "React", "Angular", "Vue.js", "Node.js", "SQL", "AWS", "Azure", "GCP", "Kubernetes", "Git")
$global:ProjectPrefixes = @("Project", "Initiative", "Operation", "Code Name:", "Phase 1:", "Global", "Enterprise", "NextGen", "Quantum", "Nexus")
$global:ProjectSuffixes = @("Migration", "Overhaul", "Transformation", "Integration", "Deployment", "Optimization", "Expansion", "Consolidation", "Modernization")
$global:MeetingTopics = @("Q3 Budget Review", "Project Status Update", "Vendor Negotiation", "Client Escalation", "Team All-Hands", "Performance Metrics", "Compliance Audit Prep")

$global:LegalClauses = @(
    "1. CONFIDENTIALITY. The Receiving Party shall hold and maintain the Confidential Information in strictest confidence for the sole and exclusive benefit of the Disclosing Party.",
    "2. NON-DISCLOSURE. The Receiving Party shall carefully restrict access to Confidential Information to employees, contractors, and third parties as is reasonably required.",
    "3. TERM. The non-disclosure provisions of this Agreement shall survive the termination of this Agreement and the Receiving Party's duty to hold Confidential Information in confidence shall remain in effect until the Confidential Information no longer qualifies as a trade secret.",
    "4. INDEMNIFICATION. The Company agrees to indemnify and hold harmless the Client against any and all claims, demands, losses, costs, expenses, obligations, liabilities, damages, recoveries, and deficiencies."
)

$global:PositiveFeedback = @(
    "Consistently exceeds expectations in project delivery.",
    "Demonstrates exceptional leadership and mentoring skills.",
    "Has a profound understanding of complex technical architectures.",
    "Always maintains a positive attitude, even under tight deadlines."
)
$global:ConstructiveFeedback = @(
    "Needs to improve time management to avoid last-minute rushes.",
    "Should focus on delegating tasks rather than taking everything on themselves.",
    "Communication in large meetings could be more concise and focused.",
    "Occasionally struggles to adapt to sudden changes in project scope."
)

# ==============================================================================
# SECTION 2: HELPER FUNCTIONS
# ==============================================================================

function Get-RandomString {
    param([int]$Length = 10)
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return -join ($chars.ToCharArray() | Get-Random -Count $Length)
}

function Get-RandomDate {
    param([int]$DaysBack = 365)
    $date = (Get-Date).AddDays(-(Get-Random -Minimum 1 -Maximum $DaysBack))
    return $date.ToString("yyyy-MM-dd")
}

function Get-RandomCurrency {
    param([int]$Min = 1000, [int]$Max = 150000)
    $amount = Get-Random -Minimum $Min -Maximum $Max
    return "{0:C0}" -f $amount
}

function Get-RandomSSN {
    return "{0:d3}-{1:d2}-{2:d4}" -f (Get-Random -Min 100 -Max 999), (Get-Random -Min 10 -Max 99), (Get-Random -Min 1000 -Max 9999)
}

function Get-CorporateIpsum {
    param(
        [int]$Sentences = 5,
        [array]$JargonPool = @()
    )
    
    # --- MASSIVE JARGON EXPANSION ---
    $verbs = @(
        "leverage", "synergize", "actualize", "incentivize", "streamline", "optimize", 
        "pivot", "align", "orchestrate", "architect", "benchmark", "conceptualize", 
        "deploy", "empower", "facilitate", "incubate", "innovate", "integrate", 
        "maximize", "monetize", "network", "scale", "transition", "transform", 
        "operationalize", "whiteboard", "fast-track", "double-down on", "drill down into",
        "future-proof", "gamify", "growth-hack", "flesh out", "circle back to"
    )
    
    $adjectives = @(
        "seamless", "value-added", "cross-platform", "robust", "scalable", "granular", 
        "mission-critical", "frictionless", "bleeding-edge", "next-generation", 
        "client-centric", "core", "out-of-the-box", "plug-and-play", "best-of-breed", 
        "end-to-end", "synergistic", "proactive", "dynamic", "agile", "lean", 
        "holistic", "disruptive", "turnkey", "enterprise-grade", "data-driven"
    )
    
    $nouns = @(
        "synergies", "paradigms", "action items", "deliverables", "moving parts", 
        "bandwidth", "alignment", "core competencies", "low-hanging fruit", 
        "pain points", "deep dives", "touchpoints", "mindshare", "wheelhouses", 
        "value propositions", "bottlenecks", "ecosystems", "methodologies", 
        "optics", "metrics", "milestones", "swimlanes", "key performance indicators",
        "market trends", "change management protocols"
    )

    # Blend department-specific jargon dynamically so the text remains highly contextual
    if ($JargonPool.Count -gt 0) {
        $nouns += $JargonPool
        # Add a bit of randomness to ensure the custom jargon also gets used as verbs where appropriate
        $verbs += $JargonPool 
    }

    $paragraph = @()
    for ($i = 0; $i -lt $Sentences; $i++) {
        $v = $verbs | Get-Random
        $a = $adjectives | Get-Random
        $n = $nouns | Get-Random
        $n2 = $nouns | Get-Random # Second noun for complex sentences
        
        # Expanded sentence structures to prevent repetitive cadence
        $templates = @(
            "We need to effectively $v our $n to ensure a $a approach across the board.",
            "By focusing on $a $n, we can execute and $v the upcoming $n2.",
            "Our primary objective is to $v, leveraging $a $n to maximize $n2.",
            "To maintain our $a edge, we must aggressively target the $n via a new strategy.",
            "Let's take a deep dive into $n and see how we can $v our $n2.",
            "Going forward, we need more $n to adequately $v our $a $n2.",
            "The optics on our $n aren't great, so let's $v and re-align our $n2.",
            "If we $v the $n, we can clear the $n2 and achieve a $a state.",
            "Please ensure that the $a $n are ready before we $v the next phase.",
            "We are currently lacking the bandwidth to $v, so let's shift our focus to $a $n2.",
            "To move the needle on $n, leadership wants us to $v and adopt $a $n2.",
            "Let's circle back on the $n and make sure we $v before Q4.",
            "This is highly $a; we must $v our $n to prevent further issues with the $n2."
        )
        $paragraph += $templates | Get-Random
    }
    return $paragraph -join " "
}

function Get-FakeUser {
    # Returns a hashtable with user properties. Leverages REAL AD Users if available!
    if ($global:AllADUsers.Count -gt 0) {
        $RealUser = $global:AllADUsers | Get-Random
        return @{
            GivenName = $RealUser.GivenName
            Surname = $RealUser.Surname
            Name = $RealUser.Name
            SamAccountName = $RealUser.SamAccountName
            Department = if ($RealUser.Department) { $RealUser.Department } else { $global:DepartmentContexts.Keys | Get-Random }
            Title = if ($RealUser.Title) { $RealUser.Title } else { "Staff" }
            EmailAddress = if ($RealUser.EmailAddress) { $RealUser.EmailAddress } else { "$($RealUser.SamAccountName)@corp.local" }
            Manager = $RealUser.Manager
        }
    }

    # Fallback to pure generation
    $first = $global:FirstNames | Get-Random
    $last = $global:LastNames | Get-Random
    $dept = $global:DepartmentContexts.Keys | Get-Random
    return @{
        GivenName = $first
        Surname = $last
        Name = "$first $last"
        SamAccountName = ($first.Substring(0,1) + $last).ToLower()
        Department = $dept
        Title = "$dept Specialist"
        EmailAddress = "$first.$last@corp.local".ToLower()
        Manager = $null
    }
}

# ==============================================================================
# SECTION 3: CONTENT GENERATORS (The "Real, Good, Actual Data")
# ==============================================================================

function New-ResumeContent {
    param($User, $DeptFullName)
    
    $uni = $global:Universities | Get-Random
    $deg = $global:Degrees | Get-Random
    $comp1 = $global:Companies | Get-Random
    $comp2 = $global:Companies | Get-Random
    $skills = ($global:TechSkills | Get-Random -Count 5) -join ", "
    $soft = ($global:SoftSkills | Get-Random -Count 3) -join ", "

    $content = @"
# RESUME: $($User.Name)
Email: $($User.EmailAddress) | Phone: (555) $(Get-Random -Min 100 -Max 999)-$(Get-Random -Min 1000 -Max 9999)
Department: $DeptFullName | Title: $($User.Title)

## SUMMARY
Dedicated professional with extensive experience in $DeptFullName aiming to $(Get-CorporateIpsum -Sentences 1) Known for expertise in $soft.

## EXPERIENCE

**$comp1** - Senior Analyst (2018 - Present)
- Led initiative to $(Get-CorporateIpsum -Sentences 1)
- Managed cross-functional teams to deliver projects 15% under budget.
- Developed workflows utilizing $skills.

**$comp2** - Associate (2014 - 2018)
- Assisted in the rollout of enterprise software affecting 500+ users.
- Promoted $(Get-CorporateIpsum -Sentences 1)
- Awarded 'Employee of the Month' in Q3 2017.

## EDUCATION
**$uni**
$deg - Graduated 2014
GPA: 3.$(Get-Random -Min 4 -Max 9)

## SKILLS
- **Technical:** $skills
- **Professional:** $soft

"@
    return $content
}

function New-PerformanceReviewContent {
    param($User, $ManagerName, $DeptFullName)
    
    $pos = $global:PositiveFeedback | Get-Random
    $con = $global:ConstructiveFeedback | Get-Random
    $score = Get-Random -Minimum 3 -Maximum 6 # 3 to 5 out of 5
    $salary = Get-Random -Minimum 65000 -Maximum 145000

    $content = @"
======================================================================
EMPLOYEE PERFORMANCE REVIEW - CONFIDENTIAL HR DATA
======================================================================
Employee Name: $($User.Name)
Employee ID: EMP-$(Get-Random -Min 10000 -Max 99999)
Department: $DeptFullName
Job Title: $($User.Title)
Review Date: $(Get-RandomDate -DaysBack 60)
Reviewing Manager: $ManagerName
Current Base Salary: $("{0:C0}" -f $salary)
Recommended Bonus: $("{0:C0}" -f ($salary * 0.08))

----------------------------------------------------------------------
PERFORMANCE RATING: $score / 5
----------------------------------------------------------------------

1. ACHIEVEMENTS & STRENGTHS
$pos
$(Get-CorporateIpsum -Sentences 2)

2. AREAS FOR IMPROVEMENT
$con
$(Get-CorporateIpsum -Sentences 1)

3. GOALS FOR NEXT REVIEW PERIOD
- Achieve 100% compliance with new department protocols.
- Lead the upcoming "$($global:ProjectPrefixes | Get-Random) $($global:ProjectSuffixes | Get-Random)" initiative.

MANAGER SIGNATURE: $ManagerName
EMPLOYEE SIGNATURE: [Signed Electronically]

*Note: This document contains sensitive compensation data. Do not distribute.*
======================================================================
"@
    return $content
}

function New-MeetingMinutesContent {
    param($DeptFullName, $DeptAcronym)
    
    $topic = $global:MeetingTopics | Get-Random
    $deptData = $global:DepartmentContexts[$DeptAcronym]
    
    $jargonList = @("Corporate Synergies")
    if ($deptData) {
        $topic = $deptData.Themes | Get-Random
        $jargonList = $deptData.Jargon
    }

    $attendees = @()
    for($i=0; $i -lt (Get-Random -Min 3 -Max 8); $i++) {
        if ($global:AllADUsers.Count -gt 0) {
            $attendees += ($global:AllADUsers | Get-Random).Name
        } else {
            $attendees += "$($global:FirstNames | Get-Random) $($global:LastNames | Get-Random)"
        }
    }

    $officeStr = "Virtual Conference"
    if ($global:Offices.Count -gt 0) {
        $randOffice = $global:Offices | Get-Random
        $officeStr = "$($randOffice.Office) ($($randOffice.City), $($randOffice.State))"
    }

    $content = @"
MEETING MINUTES
Date: $(Get-RandomDate -DaysBack 30)
Location: $officeStr
Department: $DeptFullName
Topic: $topic

ATTENDEES:
$($attendees -join "`n")

AGENDA:
1. Review previous action items.
2. Discuss $topic and strategic alignment.
3. Open floor / AOB.

NOTES:
- The meeting commenced at 09:00 AM.
- $(Get-CorporateIpsum -Sentences 3 -JargonPool $jargonList)
- Point of contention regarding budget allocation for QNext. It was agreed that we need to $(Get-CorporateIpsum -Sentences 1 -JargonPool $jargonList)

ACTION ITEMS:
- $[$attendees[0]] to finalize the draft report by Friday.
- $[$attendees[1]] to schedule a follow-up with the vendor.
- All team members to review the updated policy documents on the SharePoint.

Meeting adjourned at 10:15 AM.
"@
    return $content
}

function New-FinancialReportCSV {
    $rows = @("TransactionID,Date,Department,Category,Amount,Status,ApprovedBy")
    $categories = @("Software License", "Hardware", "Consulting", "Travel", "Marketing Ad Spend", "Legal Fees", "Office Supplies")
    $statuses = @("Cleared", "Pending", "In Dispute", "Reconciled")

    $numRows = Get-Random -Minimum 50 -Maximum 200
    for ($i = 0; $i -lt $numRows; $i++) {
        $tid = "TXN-$(Get-Random -Min 100000 -Max 999999)"
        $date = Get-RandomDate -DaysBack 90
        
        $deptAcronym = $global:DepartmentContexts.Keys | Get-Random
        $deptFull = if ($global:DepartmentContexts[$deptAcronym]) { $global:DepartmentContexts[$deptAcronym].FullName } else { $deptAcronym }
        
        $cat = $categories | Get-Random
        $amount = (Get-Random -Min 50 -Max 25000) + ([math]::Round((Get-Random -Minimum 0.0 -Maximum 0.99), 2))
        $status = $statuses | Get-Random
        
        $approver = ""
        if ($global:AllADUsers.Count -gt 0) {
            $approver = ($global:AllADUsers | Get-Random).Name
        } else {
            $approver = "$($global:FirstNames | Get-Random) $($global:LastNames | Get-Random)"
        }
        
        $rows += "$tid,$date,$deptFull,$cat,$amount,$status,$approver"
    }
    return $rows -join "`n"
}

function New-EmployeeRosterCSV {
    $rows = @("EmpID,LastName,FirstName,Department,Title,OfficeLocation,HireDate,BaseSalary,BonusTarget,SSN,HomePhone")
    
    $numRows = Get-Random -Minimum 100 -Maximum 300
    for ($i = 0; $i -lt $numRows; $i++) {
        $eid = "E$(Get-Random -Min 10000 -Max 99999)"
        
        $last = ""
        $first = ""
        $deptFull = ""
        $title = ""
        
        if ($global:AllADUsers.Count -gt 0) {
            $realU = $global:AllADUsers | Get-Random
            $last = if ($realU.Surname) { $realU.Surname } else { $global:LastNames | Get-Random }
            $first = if ($realU.GivenName) { $realU.GivenName } else { $global:FirstNames | Get-Random }
            $deptAcronym = if ($realU.Department) { $realU.Department } else { $global:DepartmentContexts.Keys | Get-Random }
            $deptFull = if ($global:DepartmentContexts[$deptAcronym]) { $global:DepartmentContexts[$deptAcronym].FullName } else { $deptAcronym }
            $title = if ($realU.Title) { $realU.Title } else { "$deptAcronym Analyst" }
        } else {
            $last = $global:LastNames | Get-Random
            $first = $global:FirstNames | Get-Random
            $deptAcronym = $global:DepartmentContexts.Keys | Get-Random
            $deptFull = if ($global:DepartmentContexts[$deptAcronym]) { $global:DepartmentContexts[$deptAcronym].FullName } else { $deptAcronym }
            $title = "$deptFull Analyst"
        }

        $officeStr = "HQ-Floor1"
        if ($global:Offices.Count -gt 0) {
            $officeStr = ($global:Offices | Get-Random).Office
        }
        
        $hire = Get-RandomDate -DaysBack 2000
        $sal = Get-Random -Minimum 45000 -Maximum 185000
        $bonus = Get-Random -Minimum 0 -Maximum 25
        $ssn = Get-RandomSSN
        $phone = "(555) $(Get-Random -Min 100 -Max 999)-$(Get-Random -Min 1000 -Max 9999)"
        
        $rows += "$eid,$last,$first,$deptFull,$title,$officeStr,$hire,$sal,$bonus%,$ssn,$phone"
    }
    return $rows -join "`n"
}

function New-LegalDocumentContent {
    $clauses = ($global:LegalClauses | Get-Random -Count (Get-Random -Min 2 -Max 4)) -join "`n`n"
    $company = $global:Companies | Get-Random
    
    $content = @"
MASTER SERVICES AND NON-DISCLOSURE AGREEMENT

This Agreement is entered into on $(Get-RandomDate -DaysBack 10) by and between Our Corporation ("Company") and $company ("Client").

WHEREAS, the Company and the Client desire to enter into discussions regarding a potential business relationship;

NOW, THEREFORE, in consideration of the mutual covenants contained herein, the parties agree as follows:

$clauses

IN WITNESS WHEREOF, the parties hereto have executed this Agreement as of the date first above written.

COMPANY: ____________________
Title: Chief Operating Officer

CLIENT ($company): ____________________
Title: Authorized Representative
"@
    return $content
}

function New-ProjectSpecContent {
    param($DeptFullName, $DeptAcronym)
    
    $projName = "$($global:ProjectPrefixes | Get-Random) $($global:ProjectSuffixes | Get-Random)"
    $deptData = $global:DepartmentContexts[$DeptAcronym]
    
    $jargonList = @("Enterprise Solutions")
    if ($deptData) {
        $jargonList = $deptData.Jargon
    }

    $leadName = "$($global:FirstNames | Get-Random) $($global:LastNames | Get-Random)"
    if ($global:AllADUsers.Count -gt 0) {
        $leadName = ($global:AllADUsers | Where-Object { $_.Department -eq $DeptAcronym } | Get-Random).Name
        if (-not $leadName) { $leadName = ($global:AllADUsers | Get-Random).Name }
    }

    $content = @"
PROJECT SPECIFICATION & CHARTER
Project Name: $projName
Sponsoring Department: $DeptFullName
Project Lead: $leadName
Status: DRAFT / PRE-APPROVAL
Date: $(Get-RandomDate -DaysBack 5)

1. EXECUTIVE SUMMARY
The goal of $projName is to $(Get-CorporateIpsum -Sentences 2 -JargonPool $jargonList). This initiative is critical for maintaining our competitive edge and addressing current limitations regarding $(($jargonList | Get-Random -Count 2) -join " and ").

2. SCOPE OF WORK
In Scope:
- Analysis of current infrastructure.
- Deployment of Phase 1 deliverables.
- $(Get-CorporateIpsum -Sentences 1 -JargonPool $jargonList)

Out of Scope:
- Legacy system deprecation (reserved for Phase 2).
- External vendor auditing.

3. RESOURCE ALLOCATION & BUDGET
Estimated Timeline: 6 Months
Required Personnel: 4 FTEs
Estimated Budget: $(Get-RandomCurrency -Min 50000 -Max 500000)
Capital Expenditure (CapEx) approved conditionally.

4. RISK MANAGEMENT
The primary risks involve resource contention and scope creep. Mitigation strategies include strict adherence to Agile methodologies and weekly stakeholder check-ins.

Prepared by the Project Management Office (PMO).
"@
    return $content
}

# ==============================================================================
# SECTION 4: FILE WRITING LOGIC
# ==============================================================================

function New-DynamicFile {
    param(
        [string]$FolderPath,
        [string]$DepartmentAcronym = "General",
        [hashtable]$UserObj = $null
    )
    
    $FileTypeRoll = Get-Random -Minimum 1 -Maximum 100
    
    $DeptFull = $DepartmentAcronym
    if ($global:DepartmentContexts.ContainsKey($DepartmentAcronym)) {
        $DeptFull = $global:DepartmentContexts[$DepartmentAcronym].FullName
    }
    
    $FileName = ""
    $Ext = ""
    $Content = ""
    $UseFsutil = $false

    if ($FileTypeRoll -le 20) {
        # Resume
        $Ext = ".md"
        $TargetUser = if ($UserObj) { $UserObj } else { Get-FakeUser }
        $FileName = "Resume_$($TargetUser.GivenName)_$($TargetUser.Surname)_$(Get-Random -Min 2020 -Max 2024)"
        $Content = New-ResumeContent -User $TargetUser -DeptFullName $DeptFull
    }
    elseif ($FileTypeRoll -le 40) {
        # Project Spec
        $Ext = ".docx.md"
        $Proj = "$($global:ProjectPrefixes | Get-Random)_$($global:ProjectSuffixes | Get-Random)".Replace(" ","")
        $FileName = "Draft_Spec_$Proj"
        $Content = New-ProjectSpecContent -DeptFullName $DeptFull -DeptAcronym $DepartmentAcronym
    }
    elseif ($FileTypeRoll -le 55) {
        # Meeting Minutes
        $Ext = ".txt"
        $FileName = "Minutes_$(Get-RandomDate -DaysBack 30)_$DepartmentAcronym"
        $Content = New-MeetingMinutesContent -DeptFullName $DeptFull -DeptAcronym $DepartmentAcronym
    }
    elseif ($FileTypeRoll -le 65) {
        # Financial / CSV Data
        $Ext = ".csv"
        if ((Get-Random -Min 1 -Max 10) -gt 7) {
            $FileName = "CONFIDENTIAL_Employee_Roster_Salaries"
            $Content = New-EmployeeRosterCSV
        } else {
            $FileName = "Q$(Get-Random -Min 1 -Max 4)_Ledger_Extract_$(Get-Random -Min 1000 -Max 9999)"
            $Content = New-FinancialReportCSV
        }
    }
    elseif ($FileTypeRoll -le 75) {
        # HR / Performance Review (Highly Sensitive)
        $Ext = ".txt"
        $TargetUser = if ($UserObj) { $UserObj } else { Get-FakeUser }
        
        $ManagerName = "Department Supervisor"
        if ($TargetUser.Manager) {
            # Try to map the AD Manager DN to a real user name
            $ManagerObj = $global:AllADUsers | Where-Object { $_.DistinguishedName -eq $TargetUser.Manager }
            if ($ManagerObj) { $ManagerName = $ManagerObj.Name }
        } else {
            $ManagerName = "$($global:FirstNames | Get-Random) $($global:LastNames | Get-Random)"
        }

        $FileName = "PerfReview_$($TargetUser.SamAccountName)_CONFIDENTIAL"
        $Content = New-PerformanceReviewContent -User $TargetUser -ManagerName $ManagerName -DeptFullName $DeptFull
    }
    elseif ($FileTypeRoll -le 85) {
        # Legal
        $Ext = ".pdf.txt"
        $FileName = "Signed_NDA_$($global:Companies | Get-Random | ForEach-Object {$_ -replace '\s','_'})"
        $Content = New-LegalDocumentContent
    }
    else {
        # Binary Dummy File
        $UseFsutil = $true
        $Ext = @('.pdf', '.pptx', '.xlsx', '.zip', '.iso') | Get-Random
        $FileName = "Archive_Data_$(Get-RandomString -Length 8)"
    }

    $FullPath = Join-Path $FolderPath ($FileName + $Ext)
    
    if ($UseFsutil) {
        $SizeInBytes = Get-Random -Minimum 1048576 -Maximum 15728640 # 1MB to 15MB
        try {
            $null = Invoke-Expression "fsutil file createnew `"$FullPath`" $SizeInBytes"
        } catch {
            "dummy archive data" | Out-File -Path $FullPath
        }
    } else {
        Set-Content -Path $FullPath -Value $Content -Encoding UTF8
    }
}

# ==============================================================================
# SECTION 5: MAIN EXECUTION & DIRECTORY CRAWLING
# ==============================================================================

Write-Host "[*] Initializing Base Directories..." -ForegroundColor Cyan
if (-not (Test-Path $BaseSharePath)) {
    New-Item -Path $BaseSharePath -ItemType Directory -Force | Out-Null
}

$existingShare = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
if (-not $existingShare) {
    try {
        New-SmbShare -Name $ShareName -Path $BaseSharePath -FullAccess "Everyone" -ErrorAction Stop | Out-Null
        Write-Host "[+] SMB Share Created: \\$env:COMPUTERNAME\$ShareName" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to create SMB share. Files will be created locally at $BaseSharePath"
    }
}

$DepartmentsPath = Join-Path $BaseSharePath "Departments"
$UsersPath = Join-Path $BaseSharePath "Users"
$PublicPath = Join-Path $BaseSharePath "Public_Company_Data"
New-Item -Path $DepartmentsPath, $UsersPath, $PublicPath -ItemType Directory -Force | Out-Null

# --- POPULATE PUBLIC SHARES ---
Write-Host "[*] Populating Public Company Data Share..." -ForegroundColor Cyan
for ($i=0; $i -lt 10; $i++) {
    New-DynamicFile -FolderPath $PublicPath -DepartmentAcronym "CORP"
}
# Guarantee a massive sensitive CSV in the public share
$PublicRosterPath = Join-Path $PublicPath "GLOBAL_ROSTER_WITH_COMPENSATION_DO_NOT_SHARE.csv"
Set-Content -Path $PublicRosterPath -Value (New-EmployeeRosterCSV) -Encoding UTF8

# --- POPULATE DEPARTMENT SHARES ---
Write-Host "[*] Generating Department File Shares..." -ForegroundColor Cyan
$Departments = $global:DepartmentContexts.Keys
foreach ($DeptAcronym in $Departments) {
    # Name the folder using the Full Department Name for realism
    $FolderName = $global:DepartmentContexts[$DeptAcronym].FullName -replace '[<>:"/\\|?*]', ''
    $DeptPath = Join-Path $DepartmentsPath $FolderName
    New-Item -Path $DeptPath -ItemType Directory -Force | Out-Null
    
    $NumFiles = Get-Random -Minimum ($MaxFilesPerFolder/2) -Maximum $MaxFilesPerFolder
    for ($i=0; $i -lt $NumFiles; $i++) {
        New-DynamicFile -FolderPath $DeptPath -DepartmentAcronym $DeptAcronym
    }
}

# --- POPULATE USER HOME DIRECTORIES ---
Write-Host "[*] Selecting Target Users for Home Directories..." -ForegroundColor Cyan

$TargetUsers = @()
if ($global:AllADUsers.Count -gt 0) {
    $SubsetCount = [math]::Max(1, [math]::Round($global:AllADUsers.Count * ($UserPopulationPercentage / 100)))
    $TargetUsers = $global:AllADUsers | Get-Random -Count $SubsetCount
    Write-Host "[+] Found $($TargetUsers.Count) real AD users to populate home directories for." -ForegroundColor Green
} else {
    $ForceLocalMode = $true
}

if ($ForceLocalMode) {
    for ($i=0; $i -lt 50; $i++) {
        $TargetUsers += Get-FakeUser
    }
    Write-Host "[+] Generated 50 local dummy users for file share population." -ForegroundColor Yellow
}

$progress = 0
$TotalUsers = $TargetUsers.Count

foreach ($User in $TargetUsers) {
    $progress++
    if ($progress % 10 -eq 0) {
        Write-Progress -Activity "Creating User Home Directories and Data" -Status "User $progress of $TotalUsers" -PercentComplete (($progress / $TotalUsers) * 100)
    }
    
    $UserDirPath = Join-Path $UsersPath $User.SamAccountName
    New-Item -Path $UserDirPath -ItemType Directory -Force | Out-Null
    
    $UserObj = @{
        GivenName = $User.GivenName
        Surname = $User.Surname
        Name = $User.Name
        SamAccountName = $User.SamAccountName
        Department = if ($User.Department) { $User.Department } else { $global:DepartmentContexts.Keys | Get-Random }
        Title = if ($User.Title) { $User.Title } else { "Staff" }
        EmailAddress = if ($User.EmailAddress) { $User.EmailAddress } else { "$($User.SamAccountName)@corp.local" }
        Manager = $User.Manager
    }
    
    # Guarantee at least one resume per user in their home dir
    $ResumePath = Join-Path $UserDirPath "My_Resume_Updated.md"
    $DeptFull = if ($global:DepartmentContexts[$UserObj.Department]) { $global:DepartmentContexts[$UserObj.Department].FullName } else { $UserObj.Department }
    Set-Content -Path $ResumePath -Value (New-ResumeContent -User $UserObj -DeptFullName $DeptFull) -Encoding UTF8

    $NumFiles = Get-Random -Minimum 2 -Maximum $MaxFilesPerFolder
    for ($i=0; $i -lt $NumFiles; $i++) {
        New-DynamicFile -FolderPath $UserDirPath -DepartmentAcronym $UserObj.Department -UserObj $UserObj
    }
}
Write-Progress -Activity "Creating User Home Directories and Data" -Completed

Write-Host "==========================================================================" -ForegroundColor Green
Write-Host "[+] ADVANCED DATA GENERATION COMPLETE!" -ForegroundColor Green
Write-Host "    Files are located at: \\$env:COMPUTERNAME\$ShareName" -ForegroundColor Green
Write-Host "    Simulated unstructured PII, financials, and project specs generated." -ForegroundColor Green
Write-Host "==========================================================================" -ForegroundColor Green