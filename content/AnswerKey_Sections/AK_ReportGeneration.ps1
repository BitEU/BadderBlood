################################
# AK_ReportGeneration.ps1 - Report generation (master report, CSVs, cheat sheet, rubric, remediation script)
# Extracted from BadderBloodAnswerKey.ps1 lines 1462-2172
# Dot-sourced by BadderBloodAnswerKey.ps1
################################
function Invoke-AKReportGeneration {
    <#
        .SYNOPSIS
            Generates all answer key output files from collected findings.
        .PARAMETER AllFindings
            Array of all finding objects from all audit sections.
        .PARAMETER PrivGroupReport
            Array of privileged group membership report entries.
        .PARAMETER BadderBloodUsers
            Array of BadderBlood-created user objects.
        .PARAMETER BadderBloodGroups
            Array of BadderBlood-created group objects.
        .PARAMETER Computers
            Array of computer objects from computer audit.
        .PARAMETER AllComputers
            Array of all computers (from RBCD audit).
        .PARAMETER DomainName
            Domain DNS name.
        .PARAMETER DomainDN
            Domain distinguished name.
        .PARAMETER OutputPath
            Directory for output files.
        .PARAMETER ExportCSVs
            Export detailed inventory CSVs.
    #>
    param(
        [Parameter(Mandatory)]
        [array]$AllFindings,
        [Parameter(Mandatory)]
        [array]$PrivGroupReport,
        [Parameter(Mandatory)]
        [array]$BadderBloodUsers,
        [Parameter(Mandatory)]
        [array]$BadderBloodGroups,
        [array]$Computers = @(),
        [array]$AllComputers = @(),
        [Parameter(Mandatory)]
        [string]$DomainName,
        [Parameter(Mandatory)]
        [string]$DomainDN,
        [Parameter(Mandatory)]
        [string]$OutputPath,
        [switch]$ExportCSVs
    )

    Write-Status "Generating reports..."

    # Restore filesystem provider before writing files (Set-Location AD: may have been called above)
    Set-Location $env:SystemDrive

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

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
    foreach ($group in $BadderBloodGroups) {
        if ($group.SIDHistory -and $group.SIDHistory.Count -gt 0) {
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
        $remLines.Add("# Remove-DnsServerResourceRecord -Name '$sn' -ZoneName '$DomainName' -RRType A -Force -ErrorAction SilentlyContinue")
    }

    $remLines.Add("")
    $remLines.Add("# --- REMOVE VULNERABLE ADCS TEMPLATES ---")
    $remLines.Add("# Review and remove BadderBlood-created vulnerable templates:")
    $configNC = "CN=Configuration,$DomainDN"
    $remLines.Add("# Remove-ADObject 'CN=BB-VulnWebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC' -Confirm:`$false -ErrorAction SilentlyContinue")
    $remLines.Add("# Remove-ADObject 'CN=BB-VulnAnyPurpose,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC' -Confirm:`$false -ErrorAction SilentlyContinue")

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
    Write-Host ("=" * 80) -ForegroundColor Yellow
    Write-Host "  ANSWER KEY GENERATION COMPLETE" -ForegroundColor Green
    Write-Host ("=" * 80) -ForegroundColor Yellow
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
    Write-Host ("=" * 80) -ForegroundColor Yellow
}
