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
$global:AllADGroups = @()
if (-not $ForceLocalMode) {
    try {
        # Note: Grabbing the Manager property to build realistic Performance Reviews based on the Org Chart
        $global:AllADUsers = Get-ADUser -Filter * -Properties Title, Department, EmailAddress, Manager, DistinguishedName -ErrorAction Stop | 
            Where-Object { $_.SamAccountName -notmatch "Administrator|Guest|krbtgt" }
        Write-Verbose "Successfully fetched $($global:AllADUsers.Count) real users from Active Directory."
        
        # Fetch AD Groups for Project Folder Generation
        $global:AllADGroups = Get-ADGroup -Filter * -Properties Description, ManagedBy, Members -ErrorAction Stop | 
            Where-Object { $_.Name -notmatch "^(Domain|Enterprise|Schema|Administrators|Users|Guests|Computers|Controllers)" }
        Write-Verbose "Successfully fetched $($global:AllADGroups.Count) real groups from Active Directory."
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

# Try to load CSVs if available (fallback method)
$csvDepts = @()
if (Test-Path $DeptsCSVPath) { $csvDepts = Import-Csv $DeptsCSVPath }

$csvJobs = @()
if (Test-Path $JobTitlesCSVPath) { $csvJobs = Import-Csv $JobTitlesCSVPath }

$global:Offices = @()
if (Test-Path $OfficesCSVPath) { 
    $global:Offices = Import-Csv $OfficesCSVPath 
} else {
    # Fallback office data if CSV not available
    $global:Offices = @(
        @{Office="HQ"; City="New York"; State="NY"}
        @{Office="West Coast"; City="San Francisco"; State="CA"}
        @{Office="Midwest Regional"; City="Chicago"; State="IL"}
        @{Office="South Regional"; City="Austin"; State="TX"}
        @{Office="East Coast"; City="Boston"; State="MA"}
    )
}

# 1B2. Build title-to-level lookup and level-based salary/bonus helper
# Levels 1-8 map to realistic corporate compensation bands
$global:TitleLevelMap = @{}
foreach ($j in $csvJobs) { $global:TitleLevelMap[$j.Title] = [int]$j.Level }

function Get-LevelCompensation {
    param([int]$Level)
    # Realistic corporate salary bands by level (annual USD)
    #   Level 1: C-suite (CEO)           350k-500k
    #   Level 2: C-suite (CxO)           250k-400k
    #   Level 3: VP                       190k-300k
    #   Level 4: Director                 150k-230k
    #   Level 5: Manager                  115k-175k
    #   Level 6: Senior IC                90k-140k
    #   Level 7: Team Lead / Mid IC       72k-110k
    #   Level 8: Individual Contributor   50k-80k
    $bands = @{
        1 = @{ Min = 350000; Max = 500000; BonusMin = 25; BonusMax = 50; StockMin = 8000;  StockMax = 25000 }
        2 = @{ Min = 250000; Max = 400000; BonusMin = 20; BonusMax = 40; StockMin = 5000;  StockMax = 15000 }
        3 = @{ Min = 190000; Max = 300000; BonusMin = 15; BonusMax = 30; StockMin = 3000;  StockMax = 10000 }
        4 = @{ Min = 150000; Max = 230000; BonusMin = 12; BonusMax = 25; StockMin = 2000;  StockMax = 7000  }
        5 = @{ Min = 115000; Max = 175000; BonusMin = 8;  BonusMax = 20; StockMin = 1000;  StockMax = 4000  }
        6 = @{ Min = 90000;  Max = 140000; BonusMin = 5;  BonusMax = 15; StockMin = 500;   StockMax = 2500  }
        7 = @{ Min = 72000;  Max = 110000; BonusMin = 3;  BonusMax = 10; StockMin = 100;   StockMax = 1500  }
        8 = @{ Min = 50000;  Max = 80000;  BonusMin = 0;  BonusMax = 8;  StockMin = 0;     StockMax = 500   }
    }
    $band = if ($bands.ContainsKey($Level)) { $bands[$Level] } else { $bands[8] }
    $salary = Get-Random -Minimum $band.Min -Maximum ($band.Max + 1)
    $bonus  = Get-Random -Minimum $band.BonusMin -Maximum ($band.BonusMax + 1)
    $stock  = Get-Random -Minimum $band.StockMin -Maximum ($band.StockMax + 1)
    return @{ Salary = $salary; BonusPct = $bonus; Stock = $stock }
}

function Get-TitleLevel {
    param([string]$Title)
    if ($global:TitleLevelMap.ContainsKey($Title)) { return $global:TitleLevelMap[$Title] }
    # Heuristic fallback for titles not in CSV
    if ($Title -match '^Chief ')       { return 2 }
    if ($Title -match '^VP ')          { return 3 }
    if ($Title -match '^Director ')    { return 4 }
    if ($Title -match '^Manager |Manager$') { return 5 }
    if ($Title -match '^Senior ')      { return 6 }
    if ($Title -match 'Lead')          { return 7 }
    return 8
}

# 1C. Build Dynamic Department Contexts - PREFER AD DATA OVER CSVs
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

# BUILD FROM AD FIRST - Extract unique departments and titles from real AD users
if ($global:AllADUsers.Count -gt 0) {
    Write-Verbose "Building department contexts from Active Directory data..."
    
    # Get unique departments from AD
    $adDepartments = $global:AllADUsers | Where-Object { $_.Department } | 
        Select-Object -ExpandProperty Department -Unique | Sort-Object
    
    foreach ($deptName in $adDepartments) {
        # Use department name as both acronym and full name (we'll clean it up)
        $acronym = $deptName
        $fullName = $deptName
        
        # Get all users in this department
        $deptUsers = $global:AllADUsers | Where-Object { $_.Department -eq $deptName }
        
        # Extract unique job titles for this department
        $deptTitles = $deptUsers | Where-Object { $_.Title } | 
            Select-Object -ExpandProperty Title -Unique
        
        $themes = @("$fullName Strategy Review", "Q3 $fullName Objectives", "Strategic Planning")
        $jargon = @()
        
        # Use predefined jargon if the acronym matches
        if ($AcronymJargonMap.ContainsKey($acronym)) {
            $jargon += $AcronymJargonMap[$acronym]
            $themes += $AcronymJargonMap[$acronym] | ForEach-Object { "$_ Optimization" }
        } else {
            $jargon += @("Deliverables", "Optimization", "Workflow", "Cross-functional Collaboration")
        }
        
        # Add job titles to jargon and themes
        foreach ($title in $deptTitles) {
            $jargon += $title
            $themes += "Hiring: $title"
            $themes += "$title Sync/Standup"
        }
        
        $global:DepartmentContexts[$acronym] = @{
            FullName = $fullName
            Role = "Department Operations"
            Themes = $themes | Select-Object -Unique
            Jargon = $jargon | Select-Object -Unique
        }
    }
    
    Write-Verbose "Built $($global:DepartmentContexts.Count) department contexts from AD."
}

# FALLBACK: If no AD data, use CSVs if available
if ($global:DepartmentContexts.Count -eq 0 -and $csvDepts.Count -gt 0) {
    Write-Verbose "No AD departments found, falling back to CSV data..."
    
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
}

# 1D. Static Background Data (Universities, Soft Skills, Companies)
$global:Universities = @(
    "Massachusetts Institute of Technology (MIT)", "Stanford University", "Harvard University", 
    "California Institute of Technology (Caltech)", "University of Chicago", "Princeton University", 
    "Cornell University", "Yale University", "Columbia University", "University of Pennsylvania",
    "University of Michigan", "Johns Hopkins University", "Northwestern University", "Brown University",
    "Duke University", "Dartmouth College", "Vanderbilt University", "Rice University", 
    "Washington University in St. Louis", "University of Notre Dame", "University of California Berkeley", 
    "University of California Los Angeles", "Emory University", "Georgetown University", 
    "Carnegie Mellon University", "University of Virginia", "University of Southern California", 
    "New York University", "Tufts University", "University of North Carolina at Chapel Hill", 
    "Wake Forest University", "University of Florida", "University of Texas at Austin", 
    "Georgia Institute of Technology", "University of Rochester", "Boston College", "Boston University", 
    "College of William & Mary", "Brandeis University", "Case Western Reserve University", 
    "University of Wisconsin-Madison", "Pace University", "University of Illinois Urbana-Champaign"
)

$global:Degrees = @(
    "Bachelor of Science in Computer Science", "Bachelor of Arts in Business Administration", 
    "Master of Business Administration (MBA)", "Master of Science in Cybersecurity",
    "Bachelor of Science in Electrical Engineering", "Bachelor of Arts in English Literature",
    "Bachelor of Fine Arts in Graphic Design", "Master of Science in Data Science",
    "Master of Arts in Education", "Doctor of Philosophy in Physics",
    "Juris Doctor (JD)", "Doctor of Medicine (MD)"
)

$global:Companies = @(
    "Acme Corp", "Globex Corporation", "Soylent Corp", "Initech", "Umbrella Corporation", 
    "Wayne Enterprises", "Pied Piper", "Massive Dynamic", "Stark Industries", "Oscorp", 
    "LexCorp", "Cyberdyne Systems", "Tyrell Corporation", "Weyland-Yutani", "Dunder Mifflin", 
    "Vandelay Industries", "Oceanic Airlines", "Hooli", "Aperture Science", "Black Mesa", 
    "Buy n Large", "Wonka Industries", "Monarch", "Gringotts",
    "Omni Consumer Products", "InGen", "Vault-Tec", "Shinra Electric Power Company", "Abstergo Industries",
    "MomCorp", "Planet Express", "Virtucon", "Evil Corp", "Delos Inc.",
    "Blue Sun Corporation", "Dharma Initiative", "Wallace Corporation", "BiffCo", "Spacely Space Sprockets",
    "Cogswell Cogs", "The Krusty Krab", "Daily Bugle", "Daily Planet", "Queen Consolidated",
    "Kord Industries", "S.T.A.R. Labs", "Pym Technologies", "Roxxon Energy Corporation", "Hammer Industries",
    "Capsule Corporation", "KaibaCorp", "Sarif Industries", "Arasaka", "Militech",
    "Union Aerospace Corporation", "Hyperion Corporation", "Paper Street Soap Company", "Wolfram & Hart", "Yoyodyne Propulsion Systems",
    "Sirius Cybernetics Corporation", "Very Good Building & Development Co.", "Aviato", "Globo Gym", "Initrode",
    "Chotchkie's", "Los Pollos Hermanos", "Genco Pura Olive Oil Company", "Nakatomi Trading Corp", "Ryan Industries",
    "Fontaine Futuristics", "Nuka-Cola Corporation", "Slurm Corporation", "Central Perk", "Cross Technological Enterprises",
    "A.I.M.", "Silph Co.", "Devon Co.", "Red Ribbon Army", "NERV",
    "Aesir Corporation", "Versalife", "Tai Yong Medical", "SoroSuub Corporation", "Czerka Corporation",
    "Kuat Drive Yards", "Corellian Engineering Corporation", "Kang Tao", "Trauma Team International", "CHOAM",
    "Tricell", "G Corporation", "Shadaloo", "Maliwan", "Jakobs",
    "Torgue", "Atlas Corporation"
)

$global:SoftSkills = @(
    "Leadership", "Communication", "Problem Solving", "Teamwork", 
    "Time Management", "Adaptability", "Critical Thinking",
    "Active Listening", "Conflict Resolution", "Emotional Intelligence", "Empathy", 
    "Negotiation", "Public Speaking", "Creativity", "Collaboration", "Flexibility", 
    "Interpersonal Skills", "Work Ethic", "Decision Making", "Stress Management", 
    "Attention to Detail",
    "Patience", "Resilience", "Persuasion", "Mentoring", "Coaching",
    "Networking", "Delegation", "Dependability", "Reliability", "Accountability",
    "Innovation", "Strategic Thinking", "Brainstorming", "Self-Motivation", "Open-Mindedness",
    "Receptiveness to Feedback", "Organization", "Multitasking", "Prioritization", "Resourcefulness",
    "Cultural Awareness", "Diversity and Inclusion", "Self-Awareness", "Positivity", "Confidence",
    "Assertiveness", "Trustworthiness", "Ethical Judgment", "Integrity", "Motivation",
    "Observation", "Reading Body Language", "Storytelling", "Presentation Skills", "Facilitation",
    "Interviewing", "Diplomacy", "Dispute Resolution", "Consensus Building", "Influence",
    "Tact", "Team Building", "Mentorship", "Conflict Management", "Crisis Management",
    "De-escalation", "Customer Service", "Client Relations", "Active Learning", "Agility",
    "Tolerance for Ambiguity", "Curiosity", "Visionary Thinking", "Goal Setting", "Planning",
    "Self-Regulation", "Focus", "Dedication", "Tenacity", "Perseverance",
    "Grit", "Enthusiasm", "Constructive Criticism"
)

$global:TechSkills = @(
    "Python", "Java", "C++", "C#", "JavaScript", "HTML/CSS", "React", "Angular", 
    "Vue.js", "Node.js", "SQL", "AWS", "Azure", "GCP", "Kubernetes", "Git",
    "Ruby", "PHP", "Swift", "Kotlin", "Go", "Rust", "TypeScript", "R", "Perl", 
    "Scala", "Docker", "Terraform", "Jenkins", "Ansible", "Linux", "Bash", 
    "PowerShell", "MongoDB", "PostgreSQL", "Redis", "Elasticsearch", "Kafka", 
    "GraphQL", "Spring Boot", "Django", "Flask", "Express.js", "Tailwind CSS", 
    "Sass", "Figma", "Jira", "Datadog"
)

$global:ProjectPrefixes = @(
    "Project", "Initiative", "Operation", "Code Name:", "Phase 1:", 
    "Global", "Enterprise", "NextGen", "Quantum", "Nexus",
    "Strategic", "Alpha", "Beta", "Delta", "Apex", "Pinnacle", "Vision", "Core", 
    "Frontier", "Catalyst", "Vanguard", "Titan", "Phoenix", "Cyber", "Omni", 
    "Synergy", "Dynamic", "Agile", "Stealth", "Prime"
)

$global:ProjectSuffixes = @(
    "Migration", "Overhaul", "Transformation", "Integration", "Deployment", 
    "Optimization", "Expansion", "Consolidation", "Modernization",
    "Implementation", "Redesign", "Enhancement", "Upgrade", "Refactoring", 
    "Automation", "Restructuring", "Launch", "Rollout", "Assessment", "Audit", 
    "Synchronization", "Pipeline", "Framework", "Matrix", "Interface", 
    "Gateway", "Engine"
)

$global:MeetingTopics = @(
    "Q3 Budget Review", "Project Status Update", "Vendor Negotiation", 
    "Client Escalation", "Team All-Hands", "Performance Metrics", "Compliance Audit Prep",
    "Sprint Planning", "Retrospective", "Daily Standup", "Architecture Review", 
    "Incident Post-Mortem", "Product Roadmap Alignment", "OKR Brainstorming", 
    "Risk Management Committee", "Marketing Campaign Launch", "Quarterly Earnings Prep", 
    "Cross-Functional Sync", "User Research Readout", "Security Training", "New Hire Onboarding"
)

$global:LegalClauses = @(
    "1. CONFIDENTIALITY. The Receiving Party shall hold and maintain the Confidential Information in strictest confidence for the sole and exclusive benefit of the Disclosing Party.",
    "2. NON-DISCLOSURE. The Receiving Party shall carefully restrict access to Confidential Information to employees, contractors, and third parties as is reasonably required.",
    "3. TERM. The non-disclosure provisions of this Agreement shall survive the termination of this Agreement and the Receiving Party's duty to hold Confidential Information in confidence shall remain in effect until the Confidential Information no longer qualifies as a trade secret.",
    "4. INDEMNIFICATION. The Company agrees to indemnify and hold harmless the Client against any and all claims, demands, losses, costs, expenses, obligations, liabilities, damages, recoveries, and deficiencies.",
    "5. SEVERABILITY. If any provision of this Agreement is held to be invalid or unenforceable, such provision shall be struck and the remaining provisions shall be enforced.",
    "6. GOVERNING LAW. This Agreement shall be governed by and construed in accordance with the laws of the applicable jurisdiction, without regard to its conflict of law principles.",
    "7. TERMINATION. Either party may terminate this Agreement at any time upon thirty (30) days written notice to the other party.",
    "8. ENTIRE AGREEMENT. This Agreement constitutes the entire understanding between the parties and supersedes all prior discussions, representations, or agreements.",
    "9. FORCE MAJEURE. Neither party shall be liable for any failure to perform its obligations where such failure is as a result of Acts of Nature, fire, flood, or other events beyond their reasonable control.",
    "10. NON-COMPETE. The Employee agrees not to engage in any business competing with the Employer for a period of one (1) year following termination.",
    "11. ASSIGNMENT. Neither party may assign or transfer this Agreement or any rights or obligations hereunder without the prior written consent of the other party.",
    "12. WAIVER. The failure of either party to enforce any right or provision of this Agreement shall not constitute a waiver of such right or provision."
)

$global:PositiveFeedback = @(
    "Consistently exceeds expectations in project delivery.",
    "Demonstrates exceptional leadership and mentoring skills.",
    "Has a profound understanding of complex technical architectures.",
    "Always maintains a positive attitude, even under tight deadlines.",
    "Quickly grasps new concepts and applies them effectively to tasks.",
    "Fosters a highly collaborative and inclusive team environment.",
    "Consistently produces high-quality, bug-free code.",
    "Shows great initiative in identifying and solving bottlenecks.",
    "Communicates complex ideas clearly to non-technical stakeholders.",
    "Is a reliable and dependable team player who always delivers on promises.",
    "Approaches challenges with creativity and an innovative mindset.",
    "Handles client interactions with exceptional professionalism and care."
)

$global:ConstructiveFeedback = @(
    "Needs to improve time management to avoid last-minute rushes.",
    "Should focus on delegating tasks rather than taking everything on themselves.",
    "Communication in large meetings could be more concise and focused.",
    "Occasionally struggles to adapt to sudden changes in project scope.",
    "Could benefit from seeking clarification earlier when requirements are ambiguous.",
    "Needs to ensure documentation is kept up to date alongside code changes.",
    "Should work on receiving peer review feedback more objectively.",
    "Would be more effective by participating more actively in brainstorming sessions.",
    "Needs to prioritize critical path items over less impactful side tasks.",
    "Should focus on improving the clarity and detail of pull request descriptions.",
    "Could improve presentation skills when addressing external clients.",
    "Needs to proactively communicate when deliverables are at risk of delay."
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
        "future-proof", "gamify", "growth-hack", "flesh out", "circle back to",
        "ideate", "iterate", "socialize", "champion", "spearhead", "onboard", 
        "offboard", "upskill", "reskill", "right-size", "solution", "mobilize", 
        "catalyze", "drive", "execute", "expedite", "mitigate", "normalize", 
        "scope", "sunset", "supercharge", "track", "validate", "vet", 
        "wireframe", "unpack", "un-silo", "cross-pollinate", "greenlight", "interface", 
        "workshop", "re-engineer", "recontextualize", "democratize", "surface", "escalate", 
        "baseline", "map", "parse", "repurpose", "synchronize", "future-cast", 
        "backfill", "calibrate", "triage", "dogfood", "lean into", "push back", 
        "tee up", "touch base", "dial in", "level up", "value-engineer", "blue-sky", 
        "ping", "crowdsource", "bucket", "action", "productize", "platformize", 
        "index on", "boil the ocean", "move the needle on", "table", "synthesize", 
        "quantify", "qualify", "contextualize"
    )

    $adjectives = @(
        "seamless", "value-added", "cross-platform", "robust", "scalable", "granular", 
        "mission-critical", "frictionless", "bleeding-edge", "next-generation", 
        "client-centric", "core", "out-of-the-box", "plug-and-play", "best-of-breed", 
        "end-to-end", "synergistic", "proactive", "dynamic", "agile", "lean", 
        "holistic", "disruptive", "turnkey", "enterprise-grade", "data-driven",
        "bespoke", "cloud-native", "modular", "omni-channel", "ubiquitous", "high-level", 
        "high-impact", "low-level", "atomic", "extensible", "future-ready", "best-in-class", 
        "state-of-the-art", "paradigm-shifting", "game-changing", "forward-looking", 
        "thought-leading", "sticky", "strategic", "tactical", "actionable", 
        "immersive", "cross-functional", "purpose-built", "cloud-first", "mobile-first", 
        "user-centric", "customer-facing", "front-end", "back-end", "full-stack", 
        "top-down", "bottom-up", "macro", "micro", "asynchronous", "synchronous", 
        "organic", "grassroots", "value-driven", "outcome-oriented", "process-oriented", 
        "high-fidelity", "low-fidelity", "native", "hybrid", "transformational", 
        "transactional", "predictive", "prescriptive", "hyper-local", "zero-sum"
    )

    $nouns = @(
        "synergies", "paradigms", "action items", "deliverables", "moving parts", 
        "bandwidth", "alignment", "core competencies", "low-hanging fruit", 
        "pain points", "deep dives", "touchpoints", "mindshare", "wheelhouses", 
        "value propositions", "bottlenecks", "ecosystems", "methodologies", 
        "optics", "metrics", "milestones", "swimlanes", "key performance indicators",
        "market trends", "change management protocols",
        "best practices", "learnings", "takeaways", "stand-ups", "syncs", 
        "cadences", "roadmaps", "trajectories", "runways", "guardrails", 
        "thought leadership", "core values", "verticals", "horizontals", "value streams", 
        "flywheels", "quick wins", "white space", "silos", "face time", 
        "heavy lifting", "game changers", "paradigm shifts", "delta", "ROI", 
        "OKRs", "single source of truth", "North Star", "ideation", "cross-pollination", 
        "buy-in", "pushback", "critical mass", "moving target", "tipping point", 
        "landscape", "footprint", "workflows", "lifecycles", "pipelines", 
        "funnels", "sweet spot", "bottom line", "10,000-foot view", "helicopter view", 
        "blue ocean", "growth hacking", "tech debt", "scope creep", "burn rate"
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
            "This is highly $a; we must $v our $n to prevent further issues with the $n2.",
            "We need to $v our $n to drive a $a culture of innovation.",
            "At the end of the day, it's about how we $v the $a $n.",
            "Let's $v the $n to ensure we are $a with our core mission.",
            "It's time to $v and double down on $a $n for better $n2.",
            "Can we $v the $n to create a more $a ecosystem?",
            "We should $v our $n to foster $a growth in the $n2 space.",
            "Our $a $n is the key driver for how we $v the $n2.",
            "We must $v the $n to capture the $a value of our $n2.",
            "Let's look for $a ways to $v the $n and reduce $n2 overhead.",
            "By the time we $v the $n, the $a landscape will have shifted.",
            "We need a $a post-mortem to $v the $n and improve the $n2.",
            "The $a paradigm shift requires us to $v our $n immediately.",
            "If we don't $v the $n, we risk losing our $a $n2 position.",
            "Let's $v the $n to create a $a roadmap for the $n2.",
            "We need to $v our $n to optimize for $a $n2 outcomes.",
            "Success depends on our ability to $v the $a $n across the $n2.",
            "We should $v our $n to ensure $a scalability for the $n2.",
            "Let's $v the $n and create a $a value proposition for the $n2.",
            "The $a nature of our $n allows us to $v the $n2 seamlessly.",
            "We must $v our $n to achieve $a synergy within the $n2.",
            "Our $n is $a, so let's $v and pivot toward the $n2.",
            "Let's $v the $n to unlock $a potential in our $n2.",
            "We need to $v our $n to provide a $a experience for the $n2.",
            "The $n requires a $a $n2 to $v the overall strategy.",
            "We should $v the $n to maintain $a momentum on the $n2.",
            "Let's $v the $n to create a $a framework for $n2 development.",
            "Our $n is the $a foundation we need to $v the $n2.",
            "We must $v our $n to drive $a transformation of the $n2.",
            "Let's $v the $n to align with the $a $n2 vision.",
            "We need to $v the $n to ensure $a integration with the $n2.",
            "The $n is a $a asset that helps us $v the $n2.",
            "We should $v our $n to deliver $a results for the $n2.",
            "Let's $v the $n to establish a $a footprint in the $n2 market.",
            "Our $n allows us to $v the $n2 in a $a way.",
            "We must $v the $n to maximize the $a impact of our $n2.",
            "Let's $v our $n to achieve a $a balance with the $n2.",
            "We need to $v the $n to leverage the $a power of the $n2.",
            "The $n is the $a catalyst we need to $v the $n2.",
            "We should $v our $n to ensure $a sustainability of the $n2.",
            "Let's $v the $n to create a $a journey for the $n2.",
            "Our $n provides a $a platform to $v the $n2.",
            "We must $v the $n to drive $a innovation across the $n2.",
            "Let's $v our $n to align with $a $n2 best practices.",
            "We need to $v the $n to optimize $a $n2 performance.",
            "The $n is a $a driver of our ability to $v the $n2.",
            "We should $v our $n to foster $a collaboration on the $n2.",
            "Let's $v the $n to create a $a environment for the $n2.",
            "Our $n is essential to $v the $a $n2 effectively.",
            "We must $v the $n to achieve $a excellence in the $n2.",
            "Let's $v our $n to ensure $a alignment with the $n2 goals.",
            "We need to $v the $n to capture $a $n2 opportunities.",
            "The $n will $v our $a $n2 and strengthen our market position."
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
# SECTION 3: CONTENT GENERATORS (OVERHAULED FOR MASSIVE VARIETY)
# ==============================================================================

function New-ResumeContent {
    param($User, $DeptFullName)
    
    $uni = $global:Universities | Get-Random
    $deg = $global:Degrees | Get-Random
    $comp1 = $global:Companies | Get-Random
    $comp2 = $global:Companies | Get-Random
    $skills = ($global:TechSkills | Get-Random -Count (Get-Random -Min 4 -Max 8)) -join ", "
    $soft = ($global:SoftSkills | Get-Random -Count (Get-Random -Min 3 -Max 5)) -join ", "

    # Dynamic Experience Bullets
    $ActionVerbs = @("Spearheaded", "Architected", "Championed", "Overhauled", "Engineered", "Streamlined", "Pioneered", "Executed")
    $Impacts = @("resulting in a 20% cost reduction.", "driving $1.2M in new ARR.", "reducing system latency by 40%.", "affecting 5,000+ global users.", "completing the initiative 2 months ahead of schedule.", "improving employee retention by 15%.")
    $Tasks = @("cross-functional team alignment", "cloud infrastructure migration", "vendor contract negotiation", "agile workflow implementation", "legacy system deprecation")

    $content = @"
# RESUME: $($User.Name)
Email: $($User.EmailAddress) | Phone: (555) $(Get-Random -Min 100 -Max 999)-$(Get-Random -Min 1000 -Max 9999)
Department: $DeptFullName | Title: $($User.Title)

## SUMMARY
Dedicated professional with extensive experience in $DeptFullName aiming to $(Get-CorporateIpsum -Sentences 1) Known for expertise in $soft.

## EXPERIENCE

**$comp1** - Senior $($User.Title) (2018 - Present)
- $($ActionVerbs | Get-Random) $($Tasks | Get-Random) $(Get-CorporateIpsum -Sentences 1)
- Managed cross-functional teams to deliver projects 15% under budget.
- Developed workflows utilizing $skills, $($Impacts | Get-Random)

**$comp2** - Associate (2014 - 2018)
- Assisted in the rollout of enterprise initiatives $(Get-CorporateIpsum -Sentences 1)
- $($ActionVerbs | Get-Random) processes, $($Impacts | Get-Random)
- Awarded 'Employee of the Month' in Q$(Get-Random -Min 1 -Max 4) 2017.

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
    
    # Expanded Feedback Arrays
    $PosList = @(
        "Consistently exceeds expectations in project delivery.",
        "Demonstrates exceptional leadership and mentoring skills under pressure.",
        "Has a profound understanding of complex technical architectures.",
        "Pivoted seamlessly during the Q3 restructuring.",
        "Acts as a force multiplier for the entire $DeptFullName team.",
        "Continually fosters a collaborative and inclusive environment within $DeptFullName.",
        "Brought immense value to the team through proactive problem-solving.",
        "Masterfully handled stakeholder expectations during critical release cycles.",
        "Showcases remarkable innovation when tackling legacy system limitations.",
        "Serves as a reliable subject matter expert for cross-functional initiatives.",
        "Consistently delivers high-quality work with minimal need for revisions.",
        "Demonstrated exceptional resilience during unexpected system outages.",
        "Effectively bridged the gap between technical and non-technical teams.",
        "Shows outstanding dedication to continuous learning and skill development.",
        "Streamlined critical workflows, saving $DeptFullName valuable time.",
        "Radiates a positive attitude that boosts overall team morale.",
        "Anticipates potential roadblocks and mitigates risks proactively.",
        "Elevated the quality of our internal documentation significantly.",
        "Drives consensus efficiently among dissenting viewpoints.",
        "Frequently volunteers for complex tasks outside of normal duties.",
        "Played a pivotal role in the successful launch of recent key features.",
        "Maintains composure and clarity during high-stress troubleshooting.",
        "Empowers peers by generously sharing industry knowledge.",
        "Exhibits a strong sense of ownership over end-to-end deliverables.",
        "Reaches key milestones consistently ahead of schedule."
    )

    $ConList = @(
        "Needs to improve time management to avoid last-minute rushes.",
        "Should focus on delegating tasks rather than bottlenecking production.",
        "Communication in large meetings could be more concise.",
        "Occasionally struggles to adapt to sudden changes in project scope.",
        "Needs to ensure compliance documentation is filed prior to deployment.",
        "Should strive to provide more frequent status updates on long-term tasks.",
        "Needs to cultivate stronger relationships with external vendors.",
        "Could benefit from participating more actively in brainstorming sessions.",
        "Must ensure all code reviews are completed within the agreed SLA.",
        "Needs to balance perfectionism with the need for timely delivery.",
        "Should seek out more peer feedback before finalizing major proposals.",
        "Could improve upon setting clearer boundaries to prevent burnout.",
        "Needs to thoroughly test edge cases before submitting work for QA.",
        "Should focus on upskilling in emerging technologies relevant to the role.",
        "Needs to document tribal knowledge to reduce team dependencies.",
        "Could be more proactive in escalating blocking issues to management.",
        "Needs to refine presentation skills for executive-level audiences.",
        "Should aim to reduce reliance on legacy tools and adopt new standards.",
        "Needs to pay closer attention to detail in formatting customer-facing reports.",
        "Could improve active listening skills during one-on-one discussions.",
        "Should work on transitioning from reactive troubleshooting to proactive monitoring.",
        "Needs to take more initiative in owning post-mortem follow-up action items.",
        "Could benefit from a more structured approach to daily prioritization.",
        "Must strictly adhere to the change management processes for all updates.",
        "Should focus on providing more actionable and constructive peer reviews."
    )

    $GoalTemplates = @(
        "Achieve 100% compliance with new department protocols.",
        "Lead the upcoming '$($global:ProjectPrefixes | Get-Random) $($global:ProjectSuffixes | Get-Random)' initiative.",
        "Reduce operational overhead in $DeptFullName by 10%.",
        "Obtain advanced certification relevant to current role by Q4.",
        "Mentorship of 2 junior analysts over the next 6 months.",
        "Design and implement an automated reporting solution for $DeptFullName by Q3.",
        "Cross-train 3 team members on the core '$($global:ProjectPrefixes | Get-Random)' architecture.",
        "Decrease average ticket resolution time by 15% over the next two quarters.",
        "Present a technical deep-dive at the next $DeptFullName all-hands meeting.",
        "Successfully migrate the legacy database to the new cloud infrastructure by end of year.",
        "Complete leadership training and apply concepts to a pilot project.",
        "Spearhead the '$($global:ProjectPrefixes | Get-Random) $($global:ProjectSuffixes | Get-Random)' phase 2 rollout.",
        "Improve unit test coverage of the primary codebase to 85%.",
        "Reduce system downtime events by 20% through proactive monitoring enhancements.",
        "Establish a weekly knowledge-sharing guild within $DeptFullName.",
        "Earn the necessary vendor certifications to support the upcoming tech stack migration.",
        "Audit and update all standard operating procedures for the '$($global:ProjectPrefixes | Get-Random)' pipeline.",
        "Decrease onboarding time for new hires in $DeptFullName by standardizing documentation.",
        "Lead a cross-departmental tiger team to resolve the '$($global:ProjectSuffixes | Get-Random)' bottleneck.",
        "Contribute at least 4 significant optimizations to the shared code repository.",
        "Act as the primary technical liaison for the new vendor integration project.",
        "Achieve a 95% satisfaction rating on internal stakeholder feedback surveys.",
        "Organize and facilitate a quarterly hackathon for $DeptFullName.",
        "Transition all active '$($global:ProjectPrefixes | Get-Random)' modules to the new CI/CD pipeline.",
        "Publish an internal whitepaper on best practices derived from recent project retrospectives."
    )

    $score = Get-Random -Minimum 3 -Maximum 6 # 3 to 5 out of 5
    $lvl = Get-TitleLevel -Title $User.Title
    $comp = Get-LevelCompensation -Level $lvl
    $salary = $comp.Salary

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
Recommended Bonus: $("{0:C0}" -f ($salary * $comp.BonusPct / 100))

----------------------------------------------------------------------
PERFORMANCE RATING: $score / 5
----------------------------------------------------------------------

1. ACHIEVEMENTS & STRENGTHS
- $($PosList | Get-Random)
- $(Get-CorporateIpsum -Sentences 2)

2. AREAS FOR IMPROVEMENT
- $($ConList | Get-Random)
- $(Get-CorporateIpsum -Sentences 1)

3. GOALS FOR NEXT REVIEW PERIOD
- $($GoalTemplates | Get-Random)
- $($GoalTemplates | Get-Random)

MANAGER SIGNATURE: $ManagerName
EMPLOYEE SIGNATURE: [Signed Electronically]

*Note: This document contains sensitive compensation data. Do not distribute.*
======================================================================
"@
    return $content
}

function New-MeetingMinutesContent {
    param($DeptFullName, $DeptAcronym)
    
    $deptData = $global:DepartmentContexts[$DeptAcronym]
    $jargonList = if ($deptData) { $deptData.Jargon } else { @("Corporate Synergies") }
    $topic = if ($deptData) { $deptData.Themes | Get-Random } else { $global:MeetingTopics | Get-Random }

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

    # Expanded Meeting Elements
    $AgendaItems = @("Review previous action items", "Discuss $topic and strategic alignment", "Budget reallocation for Q$(Get-Random -Min 1 -Max 4)", "Vendor dispute resolution", "Post-mortem on recent outage", "Resource planning for upcoming sprint")
    $Contentions = @("Point of contention regarding budget allocation.", "Pushback from legal regarding compliance risks.", "Timeline delays discussed due to resource constraints.", "Debate over whether to build internally or buy vendor solution.")
    $ActionVerbs = @("finalize the draft report", "schedule a follow-up with the vendor", "escalate to the C-suite", "run a financial audit", "deploy the hotfix to staging")

    $content = @"
MEETING MINUTES
Date: $(Get-RandomDate -DaysBack 30)
Location: $officeStr
Department: $DeptFullName
Topic: $topic

ATTENDEES:
$($attendees | Select-Object -Unique | Out-String)

AGENDA:
1. $($AgendaItems | Get-Random)
2. $($AgendaItems | Get-Random)
3. Open floor / AOB.

NOTES:
- The meeting commenced at 0$(Get-Random -Min 8 -Max 9):$(Get-Random -Min 10 -Max 59) AM.
- $(Get-CorporateIpsum -Sentences 2 -JargonPool $jargonList)
- $($Contentions | Get-Random) It was agreed that we need to $(Get-CorporateIpsum -Sentences 1 -JargonPool $jargonList)

ACTION ITEMS:
- $($attendees[0]) to $($ActionVerbs | Get-Random) by Friday.
- $($attendees[1]) to $($ActionVerbs | Get-Random).
- All team members to review the updated policy documents on the SharePoint.

Meeting adjourned at $(Get-Random -Min 10 -Max 11):$(Get-Random -Min 10 -Max 59) AM.
"@
    return $content
}

function New-FinancialReportCSV {
    $rows = @("TransactionID,Date,Department,CostCenter,Category,Amount,Status,ApprovedBy")
    # Massively expanded categories
    $categories = @("Software License", "Hardware Allocation", "Consulting", "Travel", "Marketing Ad Spend", "Legal Retainer", "Office Supplies", "Cloud Compute (AWS/Azure)", "SaaS Subscription", "Catered Lunches", "Corporate Retreat", "Compliance Audit Fee")
    $statuses = @("Cleared", "Pending", "In Dispute", "Reconciled", "Flagged for Review", "Rejected")

    $numRows = Get-Random -Minimum 50 -Maximum 200
    for ($i = 0; $i -lt $numRows; $i++) {
        $tid = "TXN-$(Get-Random -Min 100000 -Max 999999)"
        $date = Get-RandomDate -DaysBack 90
        $cc = "CC-$(Get-Random -Min 100 -Max 999)" # Added Cost Center
        
        $deptAcronym = $global:DepartmentContexts.Keys | Get-Random
        $deptFull = if ($global:DepartmentContexts[$deptAcronym]) { $global:DepartmentContexts[$deptAcronym].FullName } else { $deptAcronym }
        
        $cat = $categories | Get-Random
        $amount = (Get-Random -Min 50 -Max 25000) + ([math]::Round((Get-Random -Minimum 0.0 -Maximum 0.99), 2))
        $status = $statuses | Get-Random
        
        $approver = if ($global:AllADUsers.Count -gt 0) { ($global:AllADUsers | Get-Random).Name } else { "$($global:FirstNames | Get-Random) $($global:LastNames | Get-Random)" }
        
        $rows += "$tid,$date,$deptFull,$cc,$cat,$amount,$status,$approver"
    }
    return $rows -join "`n"
}

function New-EmployeeRosterCSV {
    $rows = @("EmpID,LastName,FirstName,Department,Title,OfficeLocation,HireDate,BaseSalary,BonusTarget,StockOptions,SSN,HomePhone")
    
    $numRows = Get-Random -Minimum 100 -Maximum 300
    for ($i = 0; $i -lt $numRows; $i++) {
        $eid = "E$(Get-Random -Min 10000 -Max 99999)"
        
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

        $officeStr = "HQ-Floor$(Get-Random -Min 1 -Max 12)"
        if ($global:Offices.Count -gt 0) {
            $officeStr = ($global:Offices | Get-Random).Office
        }
        
        $hire = Get-RandomDate -DaysBack 3000
        $lvl = Get-TitleLevel -Title $title
        $comp = Get-LevelCompensation -Level $lvl
        $sal = $comp.Salary
        $bonus = $comp.BonusPct
        $stock = $comp.Stock
        $ssn = Get-RandomSSN
        $phone = "(555) $(Get-Random -Min 100 -Max 999)-$(Get-Random -Min 1000 -Max 9999)"
        
        $rows += "$eid,$last,$first,$deptFull,$title,$officeStr,$hire,$sal,$bonus%,$stock,$ssn,$phone"
    }
    return $rows -join "`n"
}

function New-LegalDocumentContent {
    # Added variety to agreement types
    $DocTypes = @("MASTER SERVICES AND NON-DISCLOSURE AGREEMENT", "STATEMENT OF WORK (SOW)", "VENDOR INDEMNIFICATION AGREEMENT", "SOFTWARE LICENSING AGREEMENT")
    $DocType = $DocTypes | Get-Random
    
    # Massive Legal Clause Expansion
    $LegalPool = @(
        "1. CONFIDENTIALITY. The Receiving Party shall hold and maintain the Confidential Information in strictest confidence.",
        "2. NON-DISCLOSURE. Access to Confidential Information is strictly limited to authorized personnel with a verifiable 'need to know'.",
        "3. TERM. The non-disclosure provisions shall survive the termination of this Agreement for a period of five (5) years.",
        "4. INDEMNIFICATION. The Company agrees to indemnify and hold harmless the Client against any and all claims, liabilities, and damages.",
        "5. INTELLECTUAL PROPERTY. All rights, title, and interest in and to the software remain exclusively with the Disclosing Party.",
        "6. GOVERNING LAW. This Agreement shall be governed by and construed in accordance with the laws of the State of Delaware.",
        "7. SEVERABILITY. If any provision is held invalid, the remainder of this Agreement shall continue in full force and effect.",
        "8. ARBITRATION. Any dispute arising under this Agreement shall be resolved by binding arbitration in accordance with AAA rules.",
        "9. LIMITATION OF LIABILITY. In no event shall either party be liable for any indirect, incidental, or consequential damages."
    )
    
    $clauses = ($LegalPool | Get-Random -Count (Get-Random -Min 3 -Max 6)) -join "`n`n"
    $company = $global:Companies | Get-Random
    
    $content = @"
$DocType

This Agreement is entered into on $(Get-RandomDate -DaysBack 60) by and between Our Corporation ("Company") and $company ("Client").

WHEREAS, the Company and the Client desire to enter into discussions regarding a potential business relationship;

NOW, THEREFORE, in consideration of the mutual covenants contained herein, the parties agree as follows:

$clauses

IN WITNESS WHEREOF, the parties hereto have executed this Agreement as of the date first above written.

COMPANY: ____________________
Title: Authorized Signatory

CLIENT ($company): ____________________
Title: Chief Executive Officer
"@
    return $content
}

function New-ProjectSpecContent {
    param($DeptFullName, $DeptAcronym, $ProjectName = $null)
    
    $projName = if ($ProjectName) { $ProjectName } else { "$($global:ProjectPrefixes | Get-Random) $($global:ProjectSuffixes | Get-Random)" }
    $deptData = $global:DepartmentContexts[$DeptAcronym]
    $jargonList = if ($deptData) { $deptData.Jargon } else { @("Enterprise Solutions") }

    $leadName = if ($global:AllADUsers.Count -gt 0) { 
        $u = $global:AllADUsers | Where-Object { $_.Department -eq $DeptAcronym } | Get-Random
        if ($u) { $u.Name } else { ($global:AllADUsers | Get-Random).Name }
    } else { "$($global:FirstNames | Get-Random) $($global:LastNames | Get-Random)" }

    # Dynamic Scopes and Risks
    $ScopesIn = @("Analysis of current infrastructure.", "Deployment of Phase 1 deliverables.", "End-user training and documentation.", "API integration with legacy CRM.", "Automated failover testing.")
    $ScopesOut = @("Legacy system deprecation (reserved for Phase 2).", "External vendor auditing.", "Hardware procurement.", "Post-launch Tier 1 support.")
    $Risks = @("resource contention and scope creep", "budget overruns due to vendor licensing", "unforeseen downtime during data migration", "lack of stakeholder alignment", "compliance bottlenecks in the EU market")

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
- $($ScopesIn | Get-Random)
- $($ScopesIn | Get-Random)
- $(Get-CorporateIpsum -Sentences 1 -JargonPool $jargonList)

Out of Scope:
- $($ScopesOut | Get-Random)
- $($ScopesOut | Get-Random)

3. RESOURCE ALLOCATION & BUDGET
Estimated Timeline: $(Get-Random -Min 3 -Max 18) Months
Required Personnel: $(Get-Random -Min 2 -Max 12) FTEs
Estimated Budget: $(Get-RandomCurrency -Min 50000 -Max 1500000)
Capital Expenditure (CapEx) conditionally approved pending review by Finance.

4. RISK MANAGEMENT
The primary risks involve $($Risks | Get-Random) and $($Risks | Get-Random). Mitigation strategies include strict adherence to Agile methodologies, weekly stakeholder check-ins, and leveraging $(Get-CorporateIpsum -Sentences 1 -JargonPool $jargonList)

Prepared by the Project Management Office (PMO).
"@
    return $content
}

function New-SprintRetrospectiveContent {
    param($ProjectName, $DeptAcronym, $TeamMembers = @())
    
    $deptData = $global:DepartmentContexts[$DeptAcronym]
    $jargonList = if ($deptData) { $deptData.Jargon } else { @("deliverables") }
    
    $sprintNum = Get-Random -Min 1 -Max 25
    
    $WentWell = @(
        "Team velocity increased by 15% this sprint.",
        "Successfully deployed the hotfix with zero rollback incidents.",
        "Daily standups were concise and actionable.",
        "Cross-functional collaboration with $(($global:DepartmentContexts.Keys | Get-Random)) team was excellent.",
        "Automated testing coverage reached 87%.",
        "The new CI/CD pipeline reduced deployment time by 40%."
    )
    
    $NeedsImprovement = @(
        "Too many unplanned tasks disrupted the sprint goal.",
        "Technical debt tickets keep getting pushed to next sprint.",
        "Product Owner was unavailable during critical decision points.",
        "Code review turnaround time averaged 36 hours (target: 24h).",
        "Insufficient test environment led to last-minute blockers.",
        "Estimation accuracy was off; we over-committed by 30%."
    )
    
    $ActionItems = @(
        "Refactor the authentication module to reduce cyclomatic complexity.",
        "Schedule a deep-dive session on architectural patterns with the team.",
        "Implement feature flags for gradual rollout of experimental features.",
        "Update runbook documentation for on-call engineers.",
        "Migrate remaining services to container orchestration platform.",
        "Conduct load testing before next production deployment."
    )
    
    $participants = if ($TeamMembers.Count -gt 0) {
        $TeamMembers | ForEach-Object { "- $_" }
    } else {
        1..(Get-Random -Min 4 -Max 8) | ForEach-Object {
            $u = Get-FakeUser
            "- $($u.Name)"
        }
    }
    
    $content = @"
==============================================================================
SPRINT $sprintNum RETROSPECTIVE
==============================================================================
Project: $ProjectName
Date: $(Get-RandomDate -DaysBack 14)
Facilitator: $(if ($TeamMembers.Count -gt 0) { $TeamMembers[0] } else { (Get-FakeUser).Name })

PARTICIPANTS:
$($participants -join "`n")

------------------------------------------------------------------------------
1. WHAT WENT WELL
------------------------------------------------------------------------------
✓ $($WentWell | Get-Random)
✓ $($WentWell | Get-Random)
✓ $(Get-CorporateIpsum -Sentences 1 -JargonPool $jargonList)

------------------------------------------------------------------------------
2. WHAT NEEDS IMPROVEMENT
------------------------------------------------------------------------------
✗ $($NeedsImprovement | Get-Random)
✗ $($NeedsImprovement | Get-Random)
✗ The team expressed concerns about $(($jargonList | Get-Random)) impacting delivery timelines.

------------------------------------------------------------------------------
3. ACTION ITEMS FOR NEXT SPRINT
------------------------------------------------------------------------------
→ $($ActionItems | Get-Random) [Owner: $(if ($TeamMembers.Count -gt 1) { $TeamMembers[1] } else { (Get-FakeUser).Name })]
→ $($ActionItems | Get-Random) [Owner: $(if ($TeamMembers.Count -gt 2) { $TeamMembers[2] } else { (Get-FakeUser).Name })]
→ Review and prioritize technical debt during next grooming session. [Owner: Tech Lead]

------------------------------------------------------------------------------
4. SPRINT METRICS
------------------------------------------------------------------------------
Planned Story Points: $(Get-Random -Min 30 -Max 60)
Completed Story Points: $(Get-Random -Min 25 -Max 55)
Velocity Trend: $(if ((Get-Random -Min 0 -Max 1) -eq 0) { "`u{2191} Improving" } else { "`u{2193} Declining" })
Bugs Found in Production: $(Get-Random -Min 0 -Max 5)
Code Review Cycle Time: $(Get-Random -Min 18 -Max 48) hours

Next retrospective scheduled for Sprint $($sprintNum + 1).
==============================================================================
"@
    return $content
}

function New-StandupNotesContent {
    param($ProjectName, $DeptAcronym, $TeamMembers = @())
    
    $deptData = $global:DepartmentContexts[$DeptAcronym]
    $jargonList = if ($deptData) { $deptData.Jargon } else { @("tasks") }
    
    $Yesterday = @(
        "Completed unit tests for the payment processing module.",
        "Fixed critical P0 bug in production (Ticket #$(Get-Random -Min 1000 -Max 9999)).",
        "Conducted knowledge transfer session with offshore team.",
        "Reviewed and approved 3 pull requests.",
        "Refactored database migration scripts.",
        "Updated API documentation in Confluence."
    )
    
    $Today = @(
        "Working on $(($jargonList | Get-Random)) integration with external vendor API.",
        "Deploying hotfix to staging environment for QA validation.",
        "Attending architecture review board meeting at 2 PM.",
        "Optimizing SQL queries that are causing performance bottlenecks.",
        "Updating Terraform scripts for infrastructure as code.",
        "Pairing with junior dev on TDD best practices."
    )
    
    $Blockers = @(
        "Waiting on security team approval for VPN access.",
        "Third-party API documentation is incomplete.",
        "Test environment is down due to database corruption.",
        "Blocked on design mockups from UX team.",
        "Need clarification from Product Owner on acceptance criteria.",
        "No blockers."
    )
    
    $members = if ($TeamMembers.Count -gt 0) { $TeamMembers } else {
        1..(Get-Random -Min 3 -Max 6) | ForEach-Object { (Get-FakeUser).Name }
    }
    
    $updates = $members | ForEach-Object {
        $memberName = $_
        @"

${memberName}:
  Yesterday: $($Yesterday | Get-Random)
  Today: $($Today | Get-Random)
  Blockers: $($Blockers | Get-Random)
"@
    }
    
    $content = @"
DAILY STANDUP NOTES
Project: $ProjectName
Date: $(Get-RandomDate -DaysBack 3)
Scrum Master: $(if ($TeamMembers.Count -gt 0) { $TeamMembers[0] } else { (Get-FakeUser).Name })

==============================================================================
TEAM UPDATES
==============================================================================
$($updates -join "`n")

==============================================================================
PARKING LOT (For Follow-up)
==============================================================================
- Discuss $(($jargonList | Get-Random)) architecture patterns in next tech sync
- Schedule incident post-mortem for last week's outage
- Review capacity planning for Q$(Get-Random -Min 2 -Max 4)

Next standup: Tomorrow, $(Get-Random -Min 9 -Max 10):$(if ((Get-Random -Min 0 -Max 1) -eq 0) { "00" } else { "30" }) AM
"@
    return $content
}

function New-BugReportContent {
    param($ProjectName, $DeptAcronym)
    
    $deptData = $global:DepartmentContexts[$DeptAcronym]
    $jargonList = if ($deptData) { $deptData.Jargon } else { @("system") }
    
    $Severities = @("P0 - Critical", "P1 - High", "P2 - Medium", "P3 - Low")
    $Statuses = @("Open", "In Progress", "Code Review", "QA Testing", "Resolved", "Closed", "Won't Fix")
    $Components = @("Authentication", "Database", "API Gateway", "Frontend UI", "Background Jobs", "Notification Service", "Payment Processing", "User Management")
    
    $ErrorMessages = @(
        "NullPointerException in SessionManager.validateToken()",
        "Database connection pool exhausted after 300 concurrent requests",
        "CORS policy blocking requests from app.corp.local",
        "Memory leak in background worker process consuming 8GB+ RAM",
        "Race condition in distributed cache causing stale data reads",
        "SQL injection vulnerability in search parameter (SQLMap detected)",
        "Unhandled promise rejection in async payment processor"
    )
    
    $ReproSteps = @(
        "1. Navigate to the dashboard as an authenticated user",
        "2. Click on the 'Export Data' button in the upper right",
        "3. Select CSV format and date range of last 90 days",
        "4. Observe that the download fails with 500 Internal Server Error",
        "5. Check browser console for stack trace"
    )
    
    $ticketId = "BUG-$(Get-Random -Min 1000 -Max 9999)"
    $severity = $Severities | Get-Random
    
    $content = @"
==============================================================================
BUG REPORT: $ticketId
==============================================================================
Project: $ProjectName
Reported By: $(Get-FakeUser | ForEach-Object { $_.Name })
Assigned To: $(Get-FakeUser | ForEach-Object { $_.Name })
Date Reported: $(Get-RandomDate -DaysBack 7)
Severity: $severity
Status: $($Statuses | Get-Random)
Component: $($Components | Get-Random)

------------------------------------------------------------------------------
SUMMARY
------------------------------------------------------------------------------
$($ErrorMessages | Get-Random)

------------------------------------------------------------------------------
DESCRIPTION
------------------------------------------------------------------------------
The $(($jargonList | Get-Random)) is failing intermittently under high load conditions.
$(Get-CorporateIpsum -Sentences 2 -JargonPool $jargonList)

Users are reporting degraded performance and frequent timeout errors during peak hours
(9-11 AM EST). This is impacting approximately $(Get-Random -Min 50 -Max 500) concurrent users.

------------------------------------------------------------------------------
STEPS TO REPRODUCE
------------------------------------------------------------------------------
$($ReproSteps | Get-Random)

Expected Result: Operation completes successfully within 2 seconds
Actual Result: Request times out after 30 seconds, returns error code 500

------------------------------------------------------------------------------
ENVIRONMENT
------------------------------------------------------------------------------
OS: Windows Server 2019 / Linux Ubuntu 22.04
Browser: Chrome 110.0.5481.77 (if applicable)
Database: PostgreSQL 14.5 / MS SQL Server 2019
Environment: $(if ((Get-Random -Min 0 -Max 1) -eq 0) { "Production" } else { "Staging" })

------------------------------------------------------------------------------
ROOT CAUSE ANALYSIS (if resolved)
------------------------------------------------------------------------------
$(if (($Statuses | Get-Random) -match "Resolved|Closed") {
    "The issue was caused by missing index on the UserActivity table. Query was performing
table scan on $(Get-Random -Min 5 -Max 50)M+ rows. Added composite index on (userId, timestamp)
columns which reduced query time from 28s to 340ms."
} else {
    "Investigation in progress. Initial analysis suggests $(($jargonList | Get-Random)) may be
misconfigured. Will update after reproducing in dev environment."
})

------------------------------------------------------------------------------
WORKAROUND
------------------------------------------------------------------------------
$(if ((Get-Random -Min 0 -Max 1) -eq 0) {
    "Temporarily increased connection pool size to 200 and reduced timeout to 15s."
} else {
    "None available. Recommend disabling feature until fix is deployed."
})

Related Tickets: BUG-$(Get-Random -Min 1000 -Max 9999), TASK-$(Get-Random -Min 1000 -Max 9999)
"@
    return $content
}

function New-TechnicalDesignDocContent {
    param($ProjectName, $DeptAcronym)
    
    $deptData = $global:DepartmentContexts[$DeptAcronym]
    $jargonList = if ($deptData) { $deptData.Jargon } else { @("system", "platform") }
    
    $Patterns = @("Microservices", "Event-Driven Architecture", "CQRS with Event Sourcing", "Serverless", "Monolithic (with modular design)", "Layered Architecture")
    $Databases = @("PostgreSQL with read replicas", "MongoDB sharded cluster", "Amazon DynamoDB", "Redis for caching + MySQL for persistence", "Elasticsearch for search + SQL for OLTP")
    $AuthMethods = @("OAuth 2.0 with JWT tokens", "SAML 2.0 federated SSO", "API keys with rate limiting", "mTLS certificate-based authentication", "OpenID Connect (OIDC)")
    
    $content = @"
==============================================================================
TECHNICAL DESIGN DOCUMENT
==============================================================================
Project: $ProjectName
Document Version: $(Get-Random -Min 1 -Max 5).$(Get-Random -Min 0 -Max 9)
Author: $(Get-FakeUser | ForEach-Object { "$($_.Name) ($($_.Title))" })
Last Updated: $(Get-RandomDate -DaysBack 10)
Status: $(if ((Get-Random -Min 0 -Max 1) -eq 0) { "Draft" } else { "Approved" })

==============================================================================
1. OVERVIEW
==============================================================================
This document outlines the technical architecture for $ProjectName. The goal is to
$(Get-CorporateIpsum -Sentences 1 -JargonPool $jargonList) while maintaining scalability,
security, and operational excellence.

Key Objectives:
- Process $(Get-Random -Min 10 -Max 500)K transactions per day with 99.9% uptime
- Reduce latency from current $(Get-Random -Min 500 -Max 2000)ms to under 200ms (p95)
- Support horizontal scaling to handle $(Get-Random -Min 2 -Max 10)x traffic growth
- Implement comprehensive observability and alerting

==============================================================================
2. ARCHITECTURAL APPROACH
==============================================================================
We will adopt a $($Patterns | Get-Random) approach to ensure $(($jargonList | Get-Random)).

High-Level Components:
┌─────────────────────────────────────────────────────────────────┐
│ Load Balancer (AWS ALB / NGINX)                                 │
└──────────────────┬──────────────────────────────────────────────┘
                   │
        ┌──────────┴──────────┐
        │                     │
  ┌─────▼─────┐         ┌─────▼─────┐
  │  API       │         │  Web      │
  │  Gateway   │         │  Frontend │
  └─────┬──────┘         └───────────┘
        │
  ┌─────▼────────────────────┐
  │  Core Business Logic     │
  └─────┬────────────────────┘
        │
  ┌─────▼─────┐    ┌──────────┐    ┌─────────────┐
  │ Database  │    │ Cache    │    │ Message     │
  │ Cluster   │    │ (Redis)  │    │ Queue       │
  └───────────┘    └──────────┘    └─────────────┘

==============================================================================
3. DATA ARCHITECTURE
==============================================================================
Primary Database: $($Databases | Get-Random)

Schema Design Highlights:
- Normalized to 3NF for transactional tables
- Denormalized read models for analytics workloads
- Partitioning strategy: Range-based on timestamp (monthly partitions)
- Retention policy: 7 years for compliance (GDPR, SOX)

Backup & DR:
- Automated daily backups with 7-day retention
- Point-in-time recovery (PITR) enabled
- Cross-region replication for disaster recovery (RTO: 4 hours, RPO: 15 minutes)

==============================================================================
4. SECURITY ARCHITECTURE
==============================================================================
Authentication: $($AuthMethods | Get-Random)

Authorization: Role-Based Access Control (RBAC) with fine-grained permissions

Data Protection:
- Encryption at rest: AES-256
- Encryption in transit: TLS 1.3
- Secrets management: HashiCorp Vault / AWS Secrets Manager
- PII fields encrypted with application-level encryption (field-level)

Compliance: SOC 2 Type II, ISO 27001, HIPAA-ready architecture

==============================================================================
5. SCALABILITY & PERFORMANCE
==============================================================================
- Auto-scaling policies based on CPU (>70%) and request count metrics
- CDN for static assets (CloudFront / Cloudflare)
- Database connection pooling (pgBouncer / HikariCP)
- Asynchronous processing for non-critical workflows
- Circuit breakers to prevent cascade failures

Performance Targets:
- API response time: p50 < 100ms, p95 < 200ms, p99 < 500ms
- Database query time: p95 < 50ms
- Page load time: < 2 seconds (Lighthouse score > 90)

==============================================================================
6. MONITORING & OBSERVABILITY
==============================================================================
- Logging: Centralized logging with ELK stack (Elasticsearch, Logstash, Kibana)
- Metrics: Prometheus + Grafana dashboards
- Tracing: Distributed tracing with Jaeger / OpenTelemetry
- Alerting: PagerDuty integration for critical incidents
- SLIs/SLOs defined for availability, latency, and error rate

==============================================================================
7. DEPLOYMENT STRATEGY
==============================================================================
CI/CD Pipeline:
  GitHub → Jenkins/GitLab CI → Docker Build → Push to ECR → 
  Deploy to Kubernetes (EKS) → Automated Smoke Tests → Gradual Rollout

Deployment Model: Blue-Green deployment with automated rollback on failure

Infrastructure as Code: Terraform for all cloud resources

==============================================================================
8. OPEN QUESTIONS & RISKS
==============================================================================
- Q: Should we cache at CDN level or application level? A: Both (layered caching)
  
- Risk: Third-party payment gateway has 99.5% SLA (lower than our target)
  Mitigation: Implement fallback to secondary provider

- Risk: $(Get-CorporateIpsum -Sentences 1 -JargonPool $jargonList)
  Mitigation: $(Get-CorporateIpsum -Sentences 1 -JargonPool $jargonList)

==============================================================================
9. DECISION LOG
==============================================================================
[$(Get-RandomDate -DaysBack 20)] DECIDED: Use PostgreSQL over MongoDB for stronger 
consistency guarantees. Team voted 5-2 in favor.

[$(Get-RandomDate -DaysBack 15)] DECIDED: Adopt Kubernetes for container orchestration.
Evaluated ECS vs EKS; chose EKS for better ecosystem support.

[$(Get-RandomDate -DaysBack 5)] DECIDED: Defer GraphQL adoption to Phase 2. REST API
sufficient for current requirements.

==============================================================================
APPROVAL SIGNATURES
==============================================================================
Tech Lead: ________________________  Date: $(Get-RandomDate -DaysBack 3)
Engineering Manager: ______________  Date: $(Get-RandomDate -DaysBack 3)
Security Architect: _______________  Date: $(Get-RandomDate -DaysBack 2)
"@
    return $content
}

function New-DeploymentPlanContent {
    param($ProjectName)
    
    $Environments = @("Development", "Staging", "Production")
    $RollbackTriggers = @(
        "Error rate exceeds 1% for 5 consecutive minutes",
        "API response time p95 > 2 seconds",
        "More than 10 user-reported critical bugs within 1 hour",
        "Database connection pool saturation (>95%)",
        "Memory usage exceeds 90% on any instance"
    )
    
    $content = @"
==============================================================================
DEPLOYMENT PLAN & RUNBOOK
==============================================================================
Project: $ProjectName
Release Version: v$(Get-Random -Min 1 -Max 5).$(Get-Random -Min 0 -Max 20).$(Get-Random -Min 0 -Max 100)
Deployment Date: $(Get-RandomDate -DaysBack 2)
Deployment Window: $(Get-Random -Min 1 -Max 3):00 AM - $(Get-Random -Min 4 -Max 6):00 AM EST (Low Traffic Period)
Deployment Lead: $(Get-FakeUser | ForEach-Object { $_.Name })

==============================================================================
PRE-DEPLOYMENT CHECKLIST
==============================================================================
[✓] Code freeze initiated 48 hours before deployment
[✓] All automated tests passing (unit, integration, E2E)
[✓] Security scan completed (no critical vulnerabilities)
[✓] Database migration scripts reviewed and tested in staging
[✓] Rollback plan documented and tested
[✓] Stakeholder notification sent (Slack #deployments channel)
[✓] On-call engineer confirmed availability
[✓] Feature flags configured for gradual rollout
[✓] Backup of production database completed
[ ] Final go/no-go decision from Engineering Manager

==============================================================================
DEPLOYMENT STEPS
==============================================================================

STEP 1: STAGING DEPLOYMENT (T-24 hours)
1.1. Deploy build to staging environment
     Command: kubectl apply -f k8s/staging/deployment.yaml
     
1.2. Run smoke tests and integration test suite
     Expected Duration: 30 minutes
     
1.3. QA team performs manual regression testing
     Test Cases: 47 critical user flows
     
1.4. Performance testing with load simulator (500 concurrent users)
     Target: No degradation compared to previous release

STEP 2: PRODUCTION DEPLOYMENT (T=0)
2.1. Enable maintenance mode (optional, for breaking changes)
     Command: kubectl annotate deployment app maintenance=true
     
2.2. Run database migrations
     Command: flyway migrate -url=jdbc:postgresql://prod-db.corp.local/appdb
     Expected Duration: 5-15 minutes
     ⚠ Migration is reversible via: flyway undo
     
2.3. Deploy application (Blue-Green strategy)
     2.3.1. Deploy to Green environment (inactive)
     2.3.2. Validate health checks on Green pods
     2.3.3. Switch traffic from Blue to Green (50% initially)
     2.3.4. Monitor error rates for 10 minutes
     2.3.5. Gradually increase to 100% traffic on Green
     2.3.6. Keep Blue environment running for 24h (quick rollback)
     
2.4. Disable maintenance mode
     Command: kubectl annotate deployment app maintenance-

2.5. Verify critical workflows
     - User login/logout
     - Payment processing (test transaction)
     - Report generation
     - API health endpoint returns 200 OK

STEP 3: POST-DEPLOYMENT MONITORING (T+1 hour to T+24 hours)
3.1. Monitor Grafana dashboards for anomalies
     - Application metrics: /d/application-overview
     - Database metrics: /d/database-performance
     - Business metrics: /d/revenue-transactions
     
3.2. Review logs for errors in Kibana
     Query: level:ERROR AND timestamp:[now-1h TO now]
     
3.3. Verify PagerDuty is not triggering alerts
     
3.4. Confirm with Product Owner that key features are functional

==============================================================================
ROLLBACK PROCEDURE
==============================================================================
Automatically trigger rollback if any of the following occurs:
- $($RollbackTriggers | Get-Random)
- $($RollbackTriggers | Get-Random)

Manual Rollback Steps:
1. Switch traffic back to Blue environment
   Command: kubectl patch service app -p '{"spec":{"selector":{"version":"blue"}}}'
   
2. Revert database migration (if applicable)
   Command: flyway undo -url=jdbc:postgresql://prod-db.corp.local/appdb
   
3. Notify stakeholders in #incidents Slack channel
   
4. Schedule post-mortem within 48 hours

Expected Rollback Time: < 5 minutes

==============================================================================
COMMUNICATION PLAN
==============================================================================
T-48h: Email to all stakeholders with deployment details
T-24h: Reminder in #engineering Slack channel
T-2h: Final reminder + standby alert for on-call team
T=0: "Deployment in progress" message in #general
T+30m: "Deployment complete, monitoring" update
T+24h: "Deployment successful, Blue environment decommissioned" closure

==============================================================================
CONTACTS
==============================================================================
Deployment Lead: [Name]        Phone: (555) $(Get-Random -Min 100 -Max 999)-$(Get-Random -Min 1000 -Max 9999)
Engineering Manager: [Name]    Phone: (555) $(Get-Random -Min 100 -Max 999)-$(Get-Random -Min 1000 -Max 9999)
Database Admin: [Name]         Phone: (555) $(Get-Random -Min 100 -Max 999)-$(Get-Random -Min 1000 -Max 9999)
Product Owner: [Name]          Phone: (555) $(Get-Random -Min 100 -Max 999)-$(Get-Random -Min 1000 -Max 9999)

War Room (if needed): Zoom link - https://corp.zoom.us/j/$(Get-Random -Min 100000000 -Max 999999999)

==============================================================================
POST-DEPLOYMENT REPORT (To be filled after deployment)
==============================================================================
Actual Deployment Start Time: __________
Actual Deployment End Time: __________
Issues Encountered: __________
Rollback Triggered: Yes / No
Lessons Learned: __________

"@
    return $content
}

function New-IncidentReportContent {
    param($ProjectName, $DeptAcronym)
    
    $deptData = $global:DepartmentContexts[$DeptAcronym]
    $jargonList = if ($deptData) { $deptData.Jargon } else { @("infrastructure") }
    
    $IncidentTypes = @("Service Outage", "Data Breach", "Performance Degradation", "Security Vulnerability", "Data Loss", "Configuration Error")
    $Severities = @("SEV-1 (Critical)", "SEV-2 (High)", "SEV-3 (Medium)")
    
    $RootCauses = @(
        "Misconfigured load balancer caused traffic to route to dead instances",
        "Database ran out of disk space due to uncontrolled log growth",
        "Memory leak in background worker process after 72 hours of uptime",
        "DDoS attack from botnet targeting public API endpoints",
        "Expired SSL certificate not renewed by automated system",
        "Kubernetes pod crashed due to out-of-memory (OOMKilled)",
        "Network partition between availability zones causing split-brain",
        "Third-party API dependency failure (cascading failure)"
    )
    
    $content = @"
==============================================================================
INCIDENT REPORT - POST-MORTEM
==============================================================================
Incident ID: INC-$(Get-Random -Min 10000 -Max 99999)
Project: $ProjectName
Severity: $($Severities | Get-Random)
Type: $($IncidentTypes | Get-Random)

==============================================================================
TIMELINE (All times in EST)
==============================================================================
$(Get-RandomDate -DaysBack 5) 14:23 - First alert triggered in PagerDuty (API error rate spike)
$(Get-RandomDate -DaysBack 5) 14:25 - On-call engineer acknowledges incident
$(Get-RandomDate -DaysBack 5) 14:27 - War room initiated, Zoom bridge opened
$(Get-RandomDate -DaysBack 5) 14:35 - Root cause identified: $($RootCauses | Get-Random)
$(Get-RandomDate -DaysBack 5) 14:42 - Mitigation deployed (restarted affected pods)
$(Get-RandomDate -DaysBack 5) 14:50 - Service recovery confirmed, error rate normalized
$(Get-RandomDate -DaysBack 5) 15:10 - Incident declared resolved, monitoring continues
$(Get-RandomDate -DaysBack 5) 16:00 - Post-mortem scheduled for $(Get-RandomDate -DaysBack 3)

Total Duration: $(Get-Random -Min 27 -Max 180) minutes
Time to Detect (TTD): $(Get-Random -Min 3 -Max 15) minutes
Time to Mitigate (TTM): $(Get-Random -Min 15 -Max 60) minutes

==============================================================================
IMPACT ASSESSMENT
==============================================================================
Users Affected: Approximately $(Get-Random -Min 500 -Max 50000) active users

Business Impact:
- $(Get-Random -Min 100 -Max 5000) failed transactions (estimated revenue loss: $(Get-RandomCurrency -Min 5000 -Max 500000))
- Customer support received $(Get-Random -Min 20 -Max 200) complaint tickets
- SLA breach: Availability dropped to $(Get-Random -Min 85 -Max 99).$(Get-Random -Min 0 -Max 9)% (target: 99.9%)

Affected Services:
- Primary API Gateway (100% unavailable)
- Web Frontend (degraded performance)
- $(($jargonList | Get-Random)) (partial functionality)

==============================================================================
ROOT CAUSE ANALYSIS
==============================================================================
Primary Root Cause:
$($RootCauses | Get-Random)

Contributing Factors:
- Insufficient monitoring on $(($jargonList | Get-Random)) metrics
- Missing alerting threshold for disk space utilization
- Runbook was outdated (last updated $(Get-Random -Min 6 -Max 24) months ago)
- No automated circuit breaker to prevent cascade failure

Why Did This Happen?
The recent deployment introduced a change to $(($jargonList | Get-Random)) which increased
memory consumption by approximately $(Get-Random -Min 30 -Max 200)%. This was not caught during
load testing because test duration was only 15 minutes (insufficient to trigger the leak).

==============================================================================
RESOLUTION & RECOVERY
==============================================================================
Immediate Mitigation:
1. Restarted all affected application pods via kubectl rollout restart
2. Increased memory limits from $(Get-Random -Min 1 -Max 4)GB to $(Get-Random -Min 2 -Max 8)GB per pod
3. Manually scaled replica count from $(Get-Random -Min 3 -Max 6) to $(Get-Random -Min 10 -Max 20) for redundancy

Long-Term Fix:
1. Fixed memory leak in code (merged PR #$(Get-Random -Min 1000 -Max 9999))
2. Deployed patch to production on $(Get-RandomDate -DaysBack 2)
3. Enhanced monitoring with new alert: "Memory usage trend increasing >10% per hour"

==============================================================================
ACTION ITEMS (Preventive Measures)
==============================================================================
[ASSIGNED: Engineering] Implement automated canary deployments with traffic-based rollback
   Due: $(Get-RandomDate -DaysBack -30)
   
[ASSIGNED: DevOps] Add memory profiling to CI/CD pipeline (heap dump analysis)
   Due: $(Get-RandomDate -DaysBack -20)
   
[ASSIGNED: SRE Team] Update runbooks with incident response procedures
   Due: $(Get-RandomDate -DaysBack -14)
   
[ASSIGNED: Product] Review monitoring coverage gaps and add 10 new critical alerts
   Due: $(Get-RandomDate -DaysBack -21)
   
[ASSIGNED: Engineering Manager] Conduct Game Day exercise simulating similar failure
   Due: $(Get-RandomDate -DaysBack -45)

==============================================================================
LESSONS LEARNED
==============================================================================
What Went Well:
✓ Detection was fast (3 minutes from first symptom to alert)
✓ War room convened quickly with clear communication
✓ Rollback procedure was well-documented and executed successfully

What Went Poorly:
✗ Load testing duration was insufficient to catch memory leak
✗ $(Get-CorporateIpsum -Sentences 1 -JargonPool $jargonList)
✗ Post-deployment monitoring was passive; should have been proactive

Where We Got Lucky:
~ Incident occurred during low-traffic period (2 PM, not peak hours)
~ Database remained healthy; otherwise recovery would have taken hours

==============================================================================
APPROVALS
==============================================================================
Incident Commander: ____________________  Date: $(Get-RandomDate -DaysBack 1)
Engineering Manager: ___________________  Date: $(Get-RandomDate -DaysBack 1)
VP Engineering: ________________________  Date: $(Get-RandomDate -DaysBack 1)

Distribution: Engineering, Product, Customer Support, Executive Leadership
"@
    return $content
}

function New-APIDocumentationContent {
    param($ProjectName, $DeptAcronym)
    
    $Methods = @("GET", "POST", "PUT", "DELETE", "PATCH")
    $StatusCodes = @(
        "200 OK - Request successful",
        "201 Created - Resource created successfully",
        "400 Bad Request - Invalid input parameters",
        "401 Unauthorized - Authentication required",
        "403 Forbidden - Insufficient permissions",
        "404 Not Found - Resource does not exist",
        "429 Too Many Requests - Rate limit exceeded",
        "500 Internal Server Error - Server-side failure"
    )
    
    $content = @"
==============================================================================
API DOCUMENTATION
==============================================================================
Project: $ProjectName
API Version: v$(Get-Random -Min 1 -Max 3)
Base URL: https://api.corp.local/v$(Get-Random -Min 1 -Max 3)
Last Updated: $(Get-RandomDate -DaysBack 5)

==============================================================================
AUTHENTICATION
==============================================================================
All API requests require authentication via Bearer token in the Authorization header.

Example:
  Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

To obtain a token, POST credentials to /auth/login endpoint.

Rate Limiting: 1000 requests per hour per API key
Exceeding limit returns 429 status code with Retry-After header.

==============================================================================
ENDPOINTS
==============================================================================

───────────────────────────────────────────────────────────────────────────
$($Methods | Get-Random) /users
───────────────────────────────────────────────────────────────────────────
Description: Retrieve list of users with pagination support

Query Parameters:
  - page (integer, optional): Page number (default: 1)
  - limit (integer, optional): Results per page (default: 20, max: 100)
  - sort (string, optional): Sort field (default: "createdAt")
  - order (string, optional): Sort order "asc" or "desc" (default: "desc")

Request Example:
  GET /users?page=2&limit=50&sort=lastName&order=asc

Response (200 OK):
  {
    "data": [
      {
        "id": "usr_$(Get-RandomString -Length 16)",
        "email": "john.doe@corp.local",
        "firstName": "John",
        "lastName": "Doe",
        "role": "admin",
        "createdAt": "$(Get-RandomDate -DaysBack 100)T10:30:00Z"
      },
      ...
    ],
    "pagination": {
      "currentPage": 2,
      "totalPages": 15,
      "totalRecords": 742,
      "hasNext": true,
      "hasPrev": true
    }
  }

Error Responses:
  - $($StatusCodes | Get-Random)
  - $($StatusCodes | Get-Random)

───────────────────────────────────────────────────────────────────────────
$($Methods | Get-Random) /users/{userId}
───────────────────────────────────────────────────────────────────────────
Description: Retrieve specific user by ID

Path Parameters:
  - userId (string, required): Unique user identifier

Response (200 OK):
  {
    "id": "usr_$(Get-RandomString -Length 16)",
    "email": "jane.smith@corp.local",
    "firstName": "Jane",
    "lastName": "Smith",
    "role": "user",
    "department": "Engineering",
    "createdAt": "$(Get-RandomDate -DaysBack 200)T14:22:00Z",
    "lastLogin": "$(Get-RandomDate -DaysBack 1)T09:15:00Z"
  }

───────────────────────────────────────────────────────────────────────────
POST /users
───────────────────────────────────────────────────────────────────────────
Description: Create a new user

Request Body:
  {
    "email": "newuser@corp.local",
    "firstName": "New",
    "lastName": "User",
    "password": "SecureP@ssw0rd!",
    "role": "user",
    "department": "Marketing"
  }

Validation Rules:
  - email: Must be valid email format, unique in system
  - password: Minimum 12 characters, must include upper, lower, number, special char
  - role: Must be one of: ["user", "admin", "superadmin"]

Response (201 Created):
  {
    "id": "usr_$(Get-RandomString -Length 16)",
    "email": "newuser@corp.local",
    "firstName": "New",
    "lastName": "User",
    "role": "user",
    "createdAt": "$(Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")"
  }

───────────────────────────────────────────────────────────────────────────
$($Methods | Get-Random) /projects/{projectId}/tasks
───────────────────────────────────────────────────────────────────────────
Description: Retrieve tasks associated with a project

Path Parameters:
  - projectId (string, required): Project identifier

Query Parameters:
  - status (string, optional): Filter by status ["open", "in_progress", "completed"]
  - assignee (string, optional): Filter by assigned user ID

Response (200 OK):
  {
    "projectId": "prj_$(Get-RandomString -Length 16)",
    "tasks": [
      {
        "id": "tsk_$(Get-RandomString -Length 16)",
        "title": "Implement user authentication",
        "description": "Add JWT-based authentication to API",
        "status": "in_progress",
        "priority": "high",
        "assignee": {
          "id": "usr_$(Get-RandomString -Length 16)",
          "name": "John Doe"
        },
        "dueDate": "$(Get-RandomDate -DaysBack -7)",
        "createdAt": "$(Get-RandomDate -DaysBack 30)T10:00:00Z"
      }
    ]
  }

==============================================================================
WEBHOOKS
==============================================================================
The API supports webhooks for real-time event notifications.

Available Events:
  - user.created
  - user.updated
  - user.deleted
  - project.status_changed
  - task.completed

Webhook Payload Example:
  POST to your configured endpoint:
  {
    "event": "user.created",
    "timestamp": "$(Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")",
    "data": {
      "userId": "usr_$(Get-RandomString -Length 16)",
      "email": "newuser@corp.local"
    }
  }

==============================================================================
ERROR HANDLING
==============================================================================
All error responses follow this format:
  {
    "error": {
      "code": "VALIDATION_ERROR",
      "message": "Email address is already in use",
      "field": "email",
      "timestamp": "$(Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")"
    }
  }

Common Error Codes:
  - VALIDATION_ERROR: Input validation failed
  - AUTHENTICATION_ERROR: Invalid or expired token
  - AUTHORIZATION_ERROR: Insufficient permissions
  - NOT_FOUND: Requested resource does not exist
  - RATE_LIMIT_EXCEEDED: Too many requests
  - INTERNAL_ERROR: Server-side failure

==============================================================================
CODE EXAMPLES
==============================================================================

Python:
  import requests
  
  headers = {"Authorization": "Bearer YOUR_API_KEY"}
  response = requests.get("https://api.corp.local/v1/users", headers=headers)
  users = response.json()

JavaScript (Node.js):
  const axios = require('axios');
  
  const response = await axios.get('https://api.corp.local/v1/users', {
    headers: { 'Authorization': 'Bearer YOUR_API_KEY' }
  });
  console.log(response.data);

cURL:
  curl -X GET https://api.corp.local/v1/users \\
    -H "Authorization: Bearer YOUR_API_KEY"

==============================================================================
SUPPORT
==============================================================================
For API support, contact: api-support@corp.local
Swagger/OpenAPI spec: https://api.corp.local/v1/swagger.json
Status page: https://status.corp.local
"@
    return $content
}

# ==============================================================================
# SECTION 4: FILE WRITING LOGIC
# ==============================================================================

function New-ProjectFile {
    param(
        [string]$FolderPath,
        [string]$ProjectName,
        [string]$DepartmentAcronym = "General",
        [array]$TeamMembers = @()
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
    
    # Project-specific file types with higher variety
    if ($FileTypeRoll -le 15) {
        # Sprint Retrospective
        $Ext = ".txt"
        $sprintNum = Get-Random -Min 1 -Max 30
        $FileName = "Sprint_${sprintNum}_Retrospective_$(Get-RandomDate -DaysBack 14)"
        $Content = New-SprintRetrospectiveContent -ProjectName $ProjectName -DeptAcronym $DepartmentAcronym -TeamMembers $TeamMembers
    }
    elseif ($FileTypeRoll -le 30) {
        # Daily Standup Notes
        $Ext = ".txt"
        $FileName = "Standup_Notes_$(Get-RandomDate -DaysBack 5)"
        $Content = New-StandupNotesContent -ProjectName $ProjectName -DeptAcronym $DepartmentAcronym -TeamMembers $TeamMembers
    }
    elseif ($FileTypeRoll -le 40) {
        # Bug Report / Issue
        $Ext = ".md"
        $FileName = "BUG-$(Get-Random -Min 1000 -Max 9999)_$(Get-RandomDate -DaysBack 10)"
        $Content = New-BugReportContent -ProjectName $ProjectName -DeptAcronym $DepartmentAcronym
    }
    elseif ($FileTypeRoll -le 50) {
        # Technical Design Document
        $Ext = ".md"
        $FileName = "Technical_Design_${ProjectName}_v$(Get-Random -Min 1 -Max 5)"
        $Content = New-TechnicalDesignDocContent -ProjectName $ProjectName -DeptAcronym $DepartmentAcronym
    }
    elseif ($FileTypeRoll -le 60) {
        # Deployment Plan
        $Ext = ".txt"
        $FileName = "Deployment_Runbook_v$(Get-Random -Min 1 -Max 20)"
        $Content = New-DeploymentPlanContent -ProjectName $ProjectName
    }
    elseif ($FileTypeRoll -le 68) {
        # Incident Report 
        $Ext = ".md"
        $FileName = "INCIDENT_INC-$(Get-Random -Min 10000 -Max 99999)_PostMortem"
        $Content = New-IncidentReportContent -ProjectName $ProjectName -DeptAcronym $DepartmentAcronym
    }
    elseif ($FileTypeRoll -le 75) {
        # API Documentation
        $Ext = ".md"
        $FileName = "API_Documentation_${ProjectName}"
        $Content = New-APIDocumentationContent -ProjectName $ProjectName -DeptAcronym $DepartmentAcronym
    }
    elseif ($FileTypeRoll -le 82) {
        # Project Spec (now pass ProjectName)
        $Ext = ".docx.md"
        $FileName = "Project_Charter_${ProjectName}"
        $Content = New-ProjectSpecContent -DeptFullName $DeptFull -DeptAcronym $DepartmentAcronym -ProjectName $ProjectName
    }
    elseif ($FileTypeRoll -le 88) {
        # Meeting Minutes (project-specific)
        $Ext = ".txt"
        $FileName = "${ProjectName}_Meeting_Minutes_$(Get-RandomDate -DaysBack 20)"
        $Content = New-MeetingMinutesContent -DeptFullName $DeptFull -DeptAcronym $DepartmentAcronym
    }
    elseif ($FileTypeRoll -le 93) {
        # Financial / Budget tracking
        $Ext = ".csv"
        $FileName = "${ProjectName}_Budget_Tracking_Q$(Get-Random -Min 1 -Max 4)"
        $Content = New-FinancialReportCSV
    }
    else {
        # Binary project artifacts (builds, diagrams, etc.)
        $UseFsutil = $true
        $Ext = @('.pdf', '.pptx', '.xlsx', '.zip', '.png', '.vsdx') | Get-Random
        $FileName = "${ProjectName}_Artifact_$(Get-RandomString -Length 8)"
    }
    
    $FullPath = Join-Path $FolderPath ($FileName + $Ext)
    
    if ($UseFsutil) {
        $SizeInBytes = Get-Random -Minimum 524288 -Maximum 10485760 # 512KB to 10MB
        try {
            $null = Invoke-Expression "fsutil file createnew `"$FullPath`" $SizeInBytes"
        } catch {
            "binary project artifact" | Out-File -Path $FullPath
        }
    } else {
        Set-Content -Path $FullPath -Value $Content -Encoding UTF8
    }
}

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
    
    # Generate files directly in the department root
    $NumFiles = Get-Random -Minimum ($MaxFilesPerFolder/2) -Maximum $MaxFilesPerFolder
    for ($i=0; $i -lt $NumFiles; $i++) {
        New-DynamicFile -FolderPath $DeptPath -DepartmentAcronym $DeptAcronym
    }
    
    # --- POPULATE PROJECT FOLDERS BASED ON AD GROUPS ---
    Write-Host "[*] Creating Project Folders for Department: $FolderName" -ForegroundColor Cyan
    
    # Find groups that match this department (by name or description)
    $DeptGroups = @()
    if ($global:AllADGroups.Count -gt 0) {
        $DeptGroups = $global:AllADGroups | Where-Object { 
            $_.Name -match $DeptAcronym -or 
            $_.Description -match $DeptAcronym -or
            $_.Description -match $FolderName
        }
    }
    
    # If no groups match, create some synthetic project folders
    if ($DeptGroups.Count -eq 0) {
        Write-Verbose "No AD groups found for $DeptAcronym, creating synthetic project folders"
        $ProjectNames = @(
            "$($global:ProjectPrefixes | Get-Random) $($global:ProjectSuffixes | Get-Random)",
            "$($global:ProjectPrefixes | Get-Random) $($global:ProjectSuffixes | Get-Random)",
            "$($global:ProjectPrefixes | Get-Random) $($global:ProjectSuffixes | Get-Random)"
        )
        foreach ($ProjName in $ProjectNames) {
            $SafeProjName = $ProjName -replace '[<>:"/\\|?*]', '_'
            $ProjectPath = Join-Path $DeptPath $SafeProjName
            New-Item -Path $ProjectPath -ItemType Directory -Force | Out-Null
            
            # Generate synthetic team members for the project
            $SyntheticTeam = @()
            for ($t=0; $t -lt (Get-Random -Min 3 -Max 7); $t++) {
                $SyntheticTeam += (Get-FakeUser).Name
            }
            
            $NumProjFiles = Get-Random -Minimum 8 -Maximum $MaxFilesPerFolder
            for ($j=0; $j -lt $NumProjFiles; $j++) {
                New-ProjectFile -FolderPath $ProjectPath -ProjectName $SafeProjName -DepartmentAcronym $DeptAcronym -TeamMembers $SyntheticTeam
            }
        }
    } else {
        # Create project folders based on actual AD groups
        foreach ($Group in $DeptGroups) {
            $SafeGroupName = $Group.Name -replace '[<>:"/\\|?*]', '_'
            $ProjectPath = Join-Path $DeptPath $SafeGroupName
            New-Item -Path $ProjectPath -ItemType Directory -Force | Out-Null
            Write-Verbose "Created project folder: $SafeGroupName"
            
            # Get actual team members from the group
            $TeamMemberNames = @()
            try {
                $GroupMembers = Get-ADGroupMember -Identity $Group.SamAccountName -ErrorAction SilentlyContinue
                if ($GroupMembers) {
                    $TeamMemberNames = $GroupMembers | ForEach-Object { $_.Name }
                    
                    # Create a detailed group roster/membership file
                    $RosterContent = @("=" * 78)
                    $RosterContent += "PROJECT TEAM ROSTER"
                    $RosterContent += "=" * 78
                    $RosterContent += "Group: $($Group.Name)"
                    $RosterContent += "Description: $($Group.Description)"
                    $RosterContent += "Created: $(Get-RandomDate -DaysBack 365)"
                    $RosterContent += "Manager: $(if ($Group.ManagedBy) { (Get-ADUser -Identity $Group.ManagedBy -ErrorAction SilentlyContinue).Name } else { "Not Assigned" })"
                    $RosterContent += ""
                    $RosterContent += "TEAM MEMBERS (Total: $($GroupMembers.Count))"
                    $RosterContent += "-" * 78
                    
                    foreach ($Member in $GroupMembers) {
                        try {
                            $UserDetails = Get-ADUser -Identity $Member.SamAccountName -Properties Title, Department, EmailAddress -ErrorAction SilentlyContinue
                            if ($UserDetails) {
                                $RosterContent += "Name: $($UserDetails.Name)"
                                $RosterContent += "  Title: $($UserDetails.Title)"
                                $RosterContent += "  Department: $($UserDetails.Department)"
                                $RosterContent += "  Email: $($UserDetails.EmailAddress)"
                                $RosterContent += "  Username: $($UserDetails.SamAccountName)"
                                $RosterContent += ""
                            } else {
                                $RosterContent += "- $($Member.Name) ($($Member.SamAccountName))"
                            }
                        } catch {
                            $RosterContent += "- $($Member.Name) ($($Member.SamAccountName))"
                        }
                    }
                    
                    $RosterContent += "=" * 78
                    $RosterContent += "RESPONSIBILITIES & ROLES"
                    $RosterContent += "=" * 78
                    $RosterContent += "This project team is responsible for $(Get-CorporateIpsum -Sentences 2)"
                    $RosterContent += ""
                    $RosterContent += "Key Deliverables:"
                    $RosterContent += "- $($global:ProjectSuffixes | Get-Random) for $DeptFull"
                    $RosterContent += "- $($global:ProjectSuffixes | Get-Random) as part of Q$(Get-Random -Min 1 -Max 4) roadmap"
                    $RosterContent += "- Regular stakeholder updates and progress reports"
                    
                    $RosterPath = Join-Path $ProjectPath "Team_Roster_$SafeGroupName.txt"
                    Set-Content -Path $RosterPath -Value ($RosterContent -join "`n") -Encoding UTF8
                }
            } catch {
                Write-Verbose "Could not fetch members for group $($Group.Name)"
            }
            
            # Generate project-specific files using the new function
            $NumProjFiles = Get-Random -Minimum 8 -Maximum ($MaxFilesPerFolder + 5)
            for ($j=0; $j -lt $NumProjFiles; $j++) {
                New-ProjectFile -FolderPath $ProjectPath -ProjectName $SafeGroupName -DepartmentAcronym $DeptAcronym -TeamMembers $TeamMemberNames
            }
        }
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

    # Set AD home folder, profile path, and logon script on the user now that the directory exists.
    # HomeDrive H: maps to \\SERVER\CorpData\Users\<sam>
    # ProfilePath points to \\SERVER\CorpData\Users\<sam>\Profile (roaming profile)
    # ScriptPath is relative to NETLOGON share (logon.bat)
    $homeUNC     = "\\$env:COMPUTERNAME\$ShareName\Users\$($User.SamAccountName)"
    $profileUNC  = "$homeUNC\Profile"
    try {
        Set-ADUser -Identity $User.SamAccountName `
            -HomeDirectory $homeUNC `
            -HomeDrive     'H:' `
            -ProfilePath   $profileUNC `
            -ScriptPath    'logon.bat' `
            -ErrorAction Stop
    } catch {
        Write-Verbose "Could not set home/profile/logon attrs for $($User.SamAccountName): $_"
    }

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

# --- LOGON SCRIPTS: drop logon.bat + Set-Wallpaper.ps1 into NETLOGON ---
# logon.bat maps H: and calls the wallpaper script.
# Set-Wallpaper.ps1 composites user info (name, domain, IP, computer) onto
# Background.png using System.Drawing and sets it as the user's wallpaper.
# Both files are world-readable from \\DOMAIN\NETLOGON - intentional for the lab.
$netlogonPath = "$env:SystemRoot\SYSVOL\sysvol\$((Get-ADDomain).DNSRoot)\scripts"
$bgSrc = Join-Path $PSScriptRoot "..\BadderBlood\AD_Data\Background.png"
# Normalise to an absolute path regardless of how PSScriptRoot resolves
$bgSrc = [System.IO.Path]::GetFullPath($bgSrc)

if (Test-Path $netlogonPath) {

    # Copy background image into NETLOGON so the wallpaper script can reach it via UNC
    $bgNetlogon = Join-Path $netlogonPath 'Background.png'
    if ((Test-Path $bgSrc) -and -not (Test-Path $bgNetlogon)) {
        Copy-Item -Path $bgSrc -Destination $bgNetlogon -Force
        Write-Host "[+] Background.png copied to NETLOGON" -ForegroundColor Green
    }

    # Set-Wallpaper.ps1 - composites live session info onto the base image
    $wallpaperPs1 = Join-Path $netlogonPath 'Set-Wallpaper.ps1'
    if (-not (Test-Path $wallpaperPs1)) {
        Set-Content -Path $wallpaperPs1 -Encoding UTF8 -Value @'
# Set-Wallpaper.ps1 - deployed via BadderBlood/BadFS
# Runs at logon (called from logon.bat). Composites session info onto the
# corporate wallpaper and sets it as the current user's desktop background.
# System.Drawing renders text directly onto a copy of Background.png.

Add-Type -AssemblyName System.Drawing

# prefer LOGONSERVER but fall back to local machine name if unset (e.g. on a DC logon)
# LOGONSERVER is normally a UNC (\\DCNAME), so strip any leading backslashes
$logonSrv = if ($env:LOGONSERVER) { $env:LOGONSERVER.TrimStart('\') } else { $env:COMPUTERNAME }
$netlogon  = "\\$logonSrv\NETLOGON"
$bgSource  = "$netlogon\Background.png"
$outDir    = "$env:APPDATA\Microsoft\Wallpaper"
$outFile   = "$outDir\desktop.bmp"

if (-not (Test-Path $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }
if (-not (Test-Path $bgSource)) { exit 0 }

try {
    # Collect session info
    $username   = $env:USERNAME
    $domain     = $env:USERDOMAIN
    $computer   = $env:COMPUTERNAME
    $dnsDomain  = $env:USERDNSDOMAIN
    $ipAddrs    = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                   Where-Object { $_.InterfaceAlias -notmatch 'Loopback' } |
                   Select-Object -ExpandProperty IPAddress) -join ', '
    if (-not $ipAddrs) { $ipAddrs = (ipconfig | Select-String 'IPv4' | ForEach-Object { ($_ -split ':')[1].Trim() }) -join ', ' }

    $displayName = $username
    $title       = ''
    $dept        = ''
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectClass=user)(sAMAccountName=$username))"
        $searcher.PropertiesToLoad.AddRange(@('displayName','title','department'))
        $result = $searcher.FindOne()
        if ($result) {
            $p = $result.Properties
            if ($p['displayName'])  { $displayName = $p['displayName'][0] }
            if ($p['title'])        { $title       = $p['title'][0] }
            if ($p['department'])   { $dept        = $p['department'][0] }
        }
    } catch {}

    $lines = @(
        "User:        $displayName ($username)"
        "Domain:      $domain$(if($dnsDomain -and $dnsDomain -ne $domain){" ($dnsDomain)"})"
        "Computer:    $computer"
        "IP Address:  $ipAddrs"
    )
    if ($title) { $lines += "Title:       $title" }
    if ($dept)  { $lines += "Department:  $dept" }
    $lines += "Logon:       $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

    $src = [System.Drawing.Image]::FromFile($bgSource)
    $bmp = New-Object System.Drawing.Bitmap($src.Width, $src.Height, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g   = [System.Drawing.Graphics]::FromImage($bmp)
    $g.DrawImage($src, 0, 0, $src.Width, $src.Height)
    $src.Dispose()

    # Semi-transparent dark panel bottom-left
    $panelH = 36 + ($lines.Count * 28)
    $panelW = 520
    $panelX = 48
    $panelY = $bmp.Height - $panelH - 48
    $panel  = New-Object System.Drawing.RectangleF($panelX, $panelY, $panelW, $panelH)
    $brush  = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(180, 0, 0, 0))
    $g.FillRectangle($brush, $panel)
    $brush.Dispose()

    # Header line
    $hFont  = New-Object System.Drawing.Font('Segoe UI', 13, [System.Drawing.FontStyle]::Bold)
    $hBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 0, 180, 255))
    $g.DrawString('Springfield Box Factory', $hFont, $hBrush,
        [System.Drawing.PointF]::new($panelX + 16, $panelY + 10))
    $hFont.Dispose(); $hBrush.Dispose()

    # Info lines
    $font  = New-Object System.Drawing.Font('Consolas', 11, [System.Drawing.FontStyle]::Regular)
    $white = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
    $y = $panelY + 38
    foreach ($line in $lines) {
        $g.DrawString($line, $font, $white, [System.Drawing.PointF]::new($panelX + 16, $y))
        $y += 28
    }
    $font.Dispose(); $white.Dispose()
    $g.Dispose()

    $bmp.Save($outFile, [System.Drawing.Imaging.ImageFormat]::Bmp)
    $bmp.Dispose()

    # Apply wallpaper via registry + SystemParametersInfo
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name Wallpaper      -Value $outFile
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name WallpaperStyle -Value '2'
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name TileWallpaper  -Value '0'

    Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Wallpaper {
    [DllImport("user32.dll", CharSet=CharSet.Auto)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
"@
    [Wallpaper]::SystemParametersInfo(20, 0, $outFile, 3) | Out-Null

} catch {
    # Silently fail - don't disrupt logon
}
'@
        Write-Host "[+] Set-Wallpaper.ps1 deployed to NETLOGON" -ForegroundColor Green
    }

    # logon.bat - maps H: then calls the wallpaper script
    $logonBat = Join-Path $netlogonPath 'logon.bat'
    $logonContent = @'
@echo off
:: ensure we have a server name; some sessions (notably local DC logons)
:: may not set LOGONSERVER, so fall back to COMPUTERNAME.
set "LOGONSRV=%LOGONSERVER%"
if "%LOGONSRV%"=="" set "LOGONSRV=%COMPUTERNAME%"
:: strip leading \\ if present (LOGONSERVER comes in as \\\NAME)
if "%LOGONSRV:~0,2%"=="\\" set "LOGONSRV=%LOGONSRV:~2%"

net use H: \\\%LOGONSRV%\CorpData\Users\%USERNAME% /persistent:yes >nul 2>&1
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "\\%LOGONSRV%\NETLOGON\Set-Wallpaper.ps1" >nul 2>&1
'@
    Set-Content -Path $logonBat -Value $logonContent -Encoding ASCII
    Write-Host "[+] logon.bat deployed to NETLOGON" -ForegroundColor Green

    # Set ScriptPath on built-in accounts excluded from the user loop (Administrator, etc.)
    # so they also get the personalised wallpaper on logon.
    foreach ($builtIn in @('Administrator')) {
        try {
            Set-ADUser -Identity $builtIn -ScriptPath 'logon.bat' -ErrorAction Stop
            Write-Host "[+] ScriptPath set on $builtIn" -ForegroundColor Green
        } catch {
            Write-Verbose "Could not set ScriptPath on ${builtIn}: $_"
        }
    }

} else {
    Write-Warning "NETLOGON scripts path not found at '$netlogonPath' - logon scripts not deployed"
}

Write-Host "==========================================================================" -ForegroundColor Green
Write-Host "[+] ADVANCED DATA GENERATION COMPLETE!" -ForegroundColor Green
Write-Host "    Files are located at: \\$env:COMPUTERNAME\$ShareName" -ForegroundColor Green
Write-Host "    Simulated unstructured PII, financials, and project specs generated." -ForegroundColor Green
Write-Host "==========================================================================" -ForegroundColor Green