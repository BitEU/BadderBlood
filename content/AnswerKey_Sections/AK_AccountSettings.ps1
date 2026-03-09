################################
# AK_AccountSettings.ps1 - Section 3: Dangerous User Account Settings
# Dot-sourced by BadderBloodAnswerKey.ps1
################################
function Invoke-AKAccountSettingsAudit {
    <#
        .SYNOPSIS
            Checks for dangerous user account settings on BadderBlood-created users
            and password-in-description on all users.
        .PARAMETER AllUsers
            All AD users (pre-fetched).
        .PARAMETER BadderBloodUsers
            Users created by BadderBlood.
        .OUTPUTS
            List of findings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$AllUsers,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$BadderBloodUsers
    )

    Write-Status "SECTION 3: Checking for dangerous user account settings..."

    $Findings = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($user in $BadderBloodUsers) {
        # Password Never Expires
        if ($user.PasswordNeverExpires) {
            $Findings.Add((Write-Finding -Category "Account Settings" `
                -Severity "MEDIUM" `
                -Finding "User '$($user.SamAccountName)' has PasswordNeverExpires set" `
                -CurrentState "PasswordNeverExpires = True" `
                -ExpectedState "PasswordNeverExpires = False" `
                -ObjectDN $user.DistinguishedName))
        }

        # Password Not Required
        if ($user.PasswordNotRequired) {
            $Findings.Add((Write-Finding -Category "Account Settings" `
                -Severity "CRITICAL" `
                -Finding "User '$($user.SamAccountName)' does not require a password" `
                -CurrentState "PasswordNotRequired = True" `
                -ExpectedState "PasswordNotRequired = False" `
                -ObjectDN $user.DistinguishedName))
        }

        # Kerberos Pre-Auth Not Required (AS-REP Roastable)
        if ($user.DoesNotRequirePreAuth) {
            $Findings.Add((Write-Finding -Category "Kerberos Security" `
                -Severity "HIGH" `
                -Finding "User '$($user.SamAccountName)' does not require Kerberos pre-auth (AS-REP Roastable)" `
                -CurrentState "DoesNotRequirePreAuth = True" `
                -ExpectedState "DoesNotRequirePreAuth = False" `
                -ObjectDN $user.DistinguishedName))
        }

        # Unconstrained Delegation
        if ($user.TrustedForDelegation) {
            $Findings.Add((Write-Finding -Category "Delegation" `
                -Severity "CRITICAL" `
                -Finding "User '$($user.SamAccountName)' is trusted for unconstrained delegation" `
                -CurrentState "TrustedForDelegation = True" `
                -ExpectedState "TrustedForDelegation = False" `
                -ObjectDN $user.DistinguishedName))
        }

        # Constrained Delegation (Protocol Transition)
        if ($user.TrustedToAuthForDelegation) {
            $Findings.Add((Write-Finding -Category "Delegation" `
                -Severity "HIGH" `
                -Finding "User '$($user.SamAccountName)' is trusted to auth for delegation (protocol transition)" `
                -CurrentState "TrustedToAuthForDelegation = True" `
                -ExpectedState "TrustedToAuthForDelegation = False (or validate if needed)" `
                -ObjectDN $user.DistinguishedName))
        }

        # Reversible Encryption
        if ($user.AllowReversiblePasswordEncryption) {
            $Findings.Add((Write-Finding -Category "Account Settings" `
                -Severity "HIGH" `
                -Finding "User '$($user.SamAccountName)' allows reversible password encryption" `
                -CurrentState "AllowReversiblePasswordEncryption = True" `
                -ExpectedState "AllowReversiblePasswordEncryption = False" `
                -ObjectDN $user.DistinguishedName))
        }

        # SID History (possible privilege escalation)
        if ($user.SIDHistory.Count -gt 0) {
            $Findings.Add((Write-Finding -Category "SID History" `
                -Severity "HIGH" `
                -Finding "User '$($user.SamAccountName)' has SID History entries" `
                -CurrentState "SIDHistory contains $($user.SIDHistory.Count) entries" `
                -ExpectedState "SIDHistory should be empty (clear all entries)" `
                -ObjectDN $user.DistinguishedName))
        }

        # SPNs on user accounts (Kerberoastable)
        if ($user.ServicePrincipalName.Count -gt 0) {
            $Findings.Add((Write-Finding -Category "Kerberos Security" `
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
                $Findings.Add((Write-Finding -Category "Account Settings" `
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
            $Findings.Add((Write-Finding -Category "Credential Exposure" `
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
    # description was overwritten and no longer matches BadderBlood patterns)
    Write-Status "Checking all users for passwords in description fields..."
    $PasswordDescUsers = $AllUsers | Where-Object {
        $_ -notin $BadderBloodUsers -and (
            $_.Description -match '(?i)(password|pwd|pass)\s*[:=]\s*\S+' -or
            $_.Description -match '(?i)my password is\s+\S+' -or
            $_.Description -match '(?i)dont forget.*(password|pwd)')
    }
    foreach ($user in $PasswordDescUsers) {
        $ri = $SettingRiskExplanations["PasswordInDescription"]
        $Findings.Add((Write-Finding -Category "Credential Exposure" `
            -Severity "CRITICAL" `
            -Finding "User '$($user.SamAccountName)' has a password stored in their Description field" `
            -CurrentState "Description contains credential: '$($user.Description)'" `
            -ExpectedState "Remove password from Description field immediately" `
            -WhyBad $ri.Why `
            -AttackScenario $ri.Attack `
            -Principle $ri.Principle `
            -ObjectDN $user.DistinguishedName))
    }

    $Findings
}
