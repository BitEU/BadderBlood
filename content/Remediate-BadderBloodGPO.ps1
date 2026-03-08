#Requires -Modules ActiveDirectory, GroupPolicy
<#
.SYNOPSIS
    BadderBlood GPO Remediation - Fixes all insecure GPO configurations
.DESCRIPTION
    Remediates GPO misconfigurations deployed by Invoke-BadderBloodGPO.ps1. Can operate in
    two modes:
      - REPORT mode (default): Shows what would be fixed without making changes
      - FIX mode (-Apply): Actually applies remediation

    Remediation strategies per GPO:
      - Delete GPOs that are entirely insecure (preferred - removes the bad config)
      - For GPOs with mixed settings, override with secure values

    Also removes GPO permission delegations to BadderBlood users/groups.

.PARAMETER Apply
    Actually apply fixes. Without this, runs in report-only mode.
.PARAMETER DeleteInsecureGPOs
    Delete GPOs created by Invoke-BadderBloodGPO.ps1 entirely instead of reconfiguring.
    This is the cleanest approach for lab cleanup.
.PARAMETER BackupFirst
    Back up all GPOs before making changes (recommended).
.PARAMETER OutputPath
    Directory for backup and logs.

.EXAMPLE
    .\Remediate-BadderBloodGPO.ps1                              # Report only
    .\Remediate-BadderBloodGPO.ps1 -Apply -BackupFirst           # Fix with backup
    .\Remediate-BadderBloodGPO.ps1 -Apply -DeleteInsecureGPOs    # Nuclear option
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Apply,
    [switch]$DeleteInsecureGPOs,
    [switch]$BackupFirst,
    [string]$OutputPath = ".\BadderBloodGPO_Remediation_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

# ============================================================================
# SETUP
# ============================================================================

Write-Host @"
===============================================================================
   BadderBlood GPO Remediation Script
   Mode: $(if($Apply){"APPLY (changes WILL be made)"}else{"REPORT ONLY (dry run)"})
   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
===============================================================================
"@ -ForegroundColor $(if($Apply){"Red"}else{"Yellow"})

if ($Apply) {
    Write-Host "`n  WARNING: This script will modify Group Policy Objects!" -ForegroundColor Red
    Write-Host "  Press Ctrl+C within 5 seconds to abort...`n" -ForegroundColor Red
    Start-Sleep -Seconds 5
}

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

$DomainInfo = Get-ADDomain
$DomainDN = $DomainInfo.DistinguishedName
$DomainDNS = $DomainInfo.DNSRoot

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Log all actions
$logFile = Join-Path $OutputPath "Remediation_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$logLines = [System.Collections.Generic.List[string]]::new()

function Write-Log {
    param([string]$Message, [string]$Color = "White", [string]$Level = "INFO")
    $timestamp = Get-Date -Format 'HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    $logLines.Add($logEntry)
    Write-Host "  $Message" -ForegroundColor $Color
}

$BadderBloodDescPatterns = @(
    # BadderBlood patterns
    "*Created with BadderBlood*"
    "*Created by BadderBlood*"
    "*Service Account*Created by BadderBlood*"
    "*BadderBlood*"
    # Original BadBlood patterns (backwards compat)
    "*secframe.com/badblood*"
    "*Badblood github.com*"
    "*davidprowe/badblood*"
    "*Created with secframe*"
    "*User Group Created by Badblood*"
)

# ============================================================================
# KNOWN INSECURE GPOs (created by Invoke-BadderBloodGPO.ps1)
# ============================================================================
# These GPO names are the ones our deployment script creates.
# The remediation works on ANY GPO with insecure settings, but these are targeted.

$KnownBadGPONames = @(
    "IT-PasswordPolicy-Standard"
    "NET-Firewall-Exceptions"
    "APP-Compatibility-UAC"
    "SEC-Authentication-Legacy"
    "NET-SMBPerformance-Tuning"
    "NET-NameResolution-Compat"
    "SEC-NTLM-Compatibility"
    "APP-Antivirus-Exclusions"
    "IT-PowerShell-Config"
    "IT-OfflineLogon-Policy"
    "IT-RemoteAccess-Standard"
    "IT-MediaPolicy-Standard"
    "SEC-CredentialProtection-Config"
    "NET-AnonymousAccess-Legacy"
    "IT-WinRM-Management"
    "IT-EventLog-Retention"
    "IT-LocalAdmin-Deploy"
    "NET-LDAP-Compatibility"
    "SEC-LAPS-Deployment"
    "IT-Maintenance-Tasks"
    # Decoys
    "SEC-EmergencyAccess-Override"
    "IT-AdminBackdoor-Cleanup"
    "YOURORGANIZATION-TempPolicy-DELETE"
)

# ============================================================================
# BACKUP (if requested)
# ============================================================================
if ($BackupFirst -and $Apply) {
    Write-Host "`n[*] Backing up all GPOs..." -ForegroundColor Cyan
    $backupDir = Join-Path $OutputPath "GPO_Backups"
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

    $AllGPOs = Get-GPO -All
    foreach ($gpo in $AllGPOs) {
        try {
            Backup-GPO -Name $gpo.DisplayName -Path $backupDir -ErrorAction Stop | Out-Null
            Write-Log "Backed up: $($gpo.DisplayName)" "Gray"
        } catch {
            Write-Log "FAILED backup: $($gpo.DisplayName) - $_" "Red" "ERROR"
        }
    }
    Write-Log "Backups saved to: $backupDir" "Green"
}

# ============================================================================
# REMEDIATION ACTIONS
# ============================================================================

$RemediationLog = [System.Collections.Generic.List[PSObject]]::new()
$fixCount = 0
$skipCount = 0

function Add-Remediation {
    param(
        [string]$GPOName,
        [string]$Action,
        [string]$Setting,
        [string]$OldValue,
        [string]$NewValue,
        [string]$Status
    )
    $RemediationLog.Add([PSCustomObject]@{
        GPOName  = $GPOName
        Action   = $Action
        Setting  = $Setting
        OldValue = $OldValue
        NewValue = $NewValue
        Status   = $Status
    })
}

# ============================================================================
# OPTION A: DELETE INSECURE GPOs ENTIRELY
# ============================================================================
if ($DeleteInsecureGPOs) {
    Write-Host "`n[*] MODE: Delete all known insecure GPOs" -ForegroundColor Cyan

    foreach ($gpoName in $KnownBadGPONames) {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) { continue }

        if ($Apply) {
            try {
                # Remove all links first
                [xml]$report = Get-GPOReport -Name $gpoName -ReportType XML -ErrorAction Stop
                if ($report.GPO.LinksTo) {
                    foreach ($link in $report.GPO.LinksTo) {
                        $linkPath = $link.SOMPath
                        # Convert SOM path to DN
                        Remove-GPLink -Name $gpoName -Target $DomainDN -ErrorAction SilentlyContinue
                    }
                }

                Remove-GPO -Name $gpoName -ErrorAction Stop
                Write-Log "[DELETED] GPO: $gpoName" "Green" "FIX"
                Add-Remediation -GPOName $gpoName -Action "DELETE" -Setting "Entire GPO" `
                    -OldValue "Existed with insecure settings" -NewValue "DELETED" -Status "APPLIED"
                $fixCount++
            } catch {
                Write-Log "[FAILED] Could not delete $gpoName : $_" "Red" "ERROR"
                Add-Remediation -GPOName $gpoName -Action "DELETE" -Setting "Entire GPO" `
                    -OldValue "Exists" -NewValue "FAILED: $_" -Status "FAILED"
            }
        } else {
            Write-Log "[WOULD DELETE] GPO: $gpoName {$($gpo.Id)}" "Yellow" "PLAN"
            Add-Remediation -GPOName $gpoName -Action "DELETE" -Setting "Entire GPO" `
                -OldValue "Exists" -NewValue "Would be deleted" -Status "PLANNED"
            $fixCount++
        }
    }

} else {
    # ============================================================================
    # OPTION B: FIX SETTINGS IN-PLACE (more educational for students)
    # ============================================================================
    Write-Host "`n[*] MODE: Remediate insecure settings in-place" -ForegroundColor Cyan

    $AllGPOs = Get-GPO -All

    foreach ($gpo in $AllGPOs) {
        $gpoName = $gpo.DisplayName

        # --- FIX: Windows Firewall ---
        try {
            $fwVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "EnableFirewall" -ErrorAction Stop
            if ($fwVal.Value -eq 0) {
                if ($Apply) {
                    foreach ($profile in @("DomainProfile","StandardProfile","PublicProfile")) {
                        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\$profile" `
                            -ValueName "EnableFirewall" -Type DWord -Value 1 -ErrorAction Stop | Out-Null
                    }
                    Write-Log "[FIXED] $gpoName - Windows Firewall ENABLED on all profiles" "Green" "FIX"
                } else {
                    Write-Log "[WOULD FIX] $gpoName - Enable Windows Firewall on all profiles" "Yellow" "PLAN"
                }
                Add-Remediation -GPOName $gpoName -Action "SET" -Setting "EnableFirewall" -OldValue "0" -NewValue "1" `
                    -Status $(if($Apply){"APPLIED"}else{"PLANNED"})
                $fixCount++
            }
        } catch {}

        # --- FIX: UAC ---
        try {
            $uacVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableLUA" -ErrorAction Stop
            if ($uacVal.Value -eq 0) {
                if ($Apply) {
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                        -ValueName "EnableLUA" -Type DWord -Value 1 | Out-Null
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                        -ValueName "ConsentPromptBehaviorAdmin" -Type DWord -Value 2 | Out-Null
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                        -ValueName "FilterAdministratorToken" -Type DWord -Value 1 | Out-Null
                    Write-Log "[FIXED] $gpoName - UAC re-enabled with secure defaults" "Green" "FIX"
                } else {
                    Write-Log "[WOULD FIX] $gpoName - Re-enable UAC" "Yellow" "PLAN"
                }
                Add-Remediation -GPOName $gpoName -Action "SET" -Setting "EnableLUA + ConsentPrompt + FilterAdmin" `
                    -OldValue "0, 0, 0" -NewValue "1, 2, 1" -Status $(if($Apply){"APPLIED"}else{"PLANNED"})
                $fixCount++
            }
        } catch {}

        # --- FIX: WDigest ---
        try {
            $wdVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ValueName "UseLogonCredential" -ErrorAction Stop
            if ($wdVal.Value -eq 1) {
                if ($Apply) {
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
                        -ValueName "UseLogonCredential" -Type DWord -Value 0 | Out-Null
                    Write-Log "[FIXED] $gpoName - WDigest DISABLED" "Green" "FIX"
                } else {
                    Write-Log "[WOULD FIX] $gpoName - Disable WDigest" "Yellow" "PLAN"
                }
                Add-Remediation -GPOName $gpoName -Action "SET" -Setting "UseLogonCredential" -OldValue "1" -NewValue "0" `
                    -Status $(if($Apply){"APPLIED"}else{"PLANNED"})
                $fixCount++
            }
        } catch {}

        # --- FIX: SMB Signing ---
        try {
            $smbVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "RequireSecuritySignature" -ErrorAction Stop
            if ($smbVal.Value -eq 0) {
                if ($Apply) {
                    foreach ($svc in @("LanmanServer","LanManWorkstation")) {
                        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\$svc\Parameters" `
                            -ValueName "RequireSecuritySignature" -Type DWord -Value 1 | Out-Null
                        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\$svc\Parameters" `
                            -ValueName "EnableSecuritySignature" -Type DWord -Value 1 | Out-Null
                    }
                    Write-Log "[FIXED] $gpoName - SMB Signing REQUIRED on server and client" "Green" "FIX"
                } else {
                    Write-Log "[WOULD FIX] $gpoName - Require SMB Signing" "Yellow" "PLAN"
                }
                Add-Remediation -GPOName $gpoName -Action "SET" -Setting "SMB RequireSecuritySignature" -OldValue "0" -NewValue "1" `
                    -Status $(if($Apply){"APPLIED"}else{"PLANNED"})
                $fixCount++
            }
        } catch {}

        # --- FIX: LLMNR ---
        try {
            $llVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -ErrorAction Stop
            if ($llVal.Value -eq 1) {
                if ($Apply) {
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
                        -ValueName "EnableMulticast" -Type DWord -Value 0 | Out-Null
                    Write-Log "[FIXED] $gpoName - LLMNR DISABLED" "Green" "FIX"
                } else {
                    Write-Log "[WOULD FIX] $gpoName - Disable LLMNR" "Yellow" "PLAN"
                }
                Add-Remediation -GPOName $gpoName -Action "SET" -Setting "EnableMulticast" -OldValue "1" -NewValue "0" `
                    -Status $(if($Apply){"APPLIED"}else{"PLANNED"})
                $fixCount++
            }
        } catch {}

        # --- FIX: NTLMv1 ---
        try {
            $ntVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "LmCompatibilityLevel" -ErrorAction Stop
            if ($ntVal.Value -lt 3) {
                if ($Apply) {
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
                        -ValueName "LmCompatibilityLevel" -Type DWord -Value 5 | Out-Null
                    Write-Log "[FIXED] $gpoName - LmCompatibilityLevel set to 5 (NTLMv2 only)" "Green" "FIX"
                } else {
                    Write-Log "[WOULD FIX] $gpoName - Set LmCompatibilityLevel to 5" "Yellow" "PLAN"
                }
                Add-Remediation -GPOName $gpoName -Action "SET" -Setting "LmCompatibilityLevel" `
                    -OldValue "$($ntVal.Value)" -NewValue "5" -Status $(if($Apply){"APPLIED"}else{"PLANNED"})
                $fixCount++
            }
        } catch {}

        # --- FIX: Defender ---
        try {
            $defVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" -ValueName "DisableAntiSpyware" -ErrorAction Stop
            if ($defVal.Value -eq 1) {
                if ($Apply) {
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" `
                        -ValueName "DisableAntiSpyware" -Type DWord -Value 0 | Out-Null
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
                        -ValueName "DisableRealtimeMonitoring" -Type DWord -Value 0 | Out-Null
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
                        -ValueName "DisableBehaviorMonitoring" -Type DWord -Value 0 | Out-Null
                    Write-Log "[FIXED] $gpoName - Windows Defender RE-ENABLED" "Green" "FIX"
                } else {
                    Write-Log "[WOULD FIX] $gpoName - Re-enable Windows Defender" "Yellow" "PLAN"
                }
                Add-Remediation -GPOName $gpoName -Action "SET" -Setting "DisableAntiSpyware + RealTime + Behavior" `
                    -OldValue "1, 1, 1" -NewValue "0, 0, 0" -Status $(if($Apply){"APPLIED"}else{"PLANNED"})
                $fixCount++
            }
        } catch {}

        # --- FIX: PowerShell Logging ---
        try {
            $psVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ValueName "EnableScriptBlockLogging" -ErrorAction Stop
            if ($psVal.Value -eq 0) {
                if ($Apply) {
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
                        -ValueName "EnableScriptBlockLogging" -Type DWord -Value 1 | Out-Null
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
                        -ValueName "EnableModuleLogging" -Type DWord -Value 1 | Out-Null
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
                        -ValueName "EnableTranscripting" -Type DWord -Value 1 | Out-Null
                    Write-Log "[FIXED] $gpoName - PowerShell logging ENABLED (all three)" "Green" "FIX"
                } else {
                    Write-Log "[WOULD FIX] $gpoName - Enable all PowerShell logging" "Yellow" "PLAN"
                }
                Add-Remediation -GPOName $gpoName -Action "SET" -Setting "PS ScriptBlock + Module + Transcription" `
                    -OldValue "0, 0, 0" -NewValue "1, 1, 1" -Status $(if($Apply){"APPLIED"}else{"PLANNED"})
                $fixCount++
            }
        } catch {}

        # --- FIX: Cached Credentials ---
        try {
            $ccVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "CachedLogonsCount" -ErrorAction Stop
            if ([int]$ccVal.Value -gt 10) {
                if ($Apply) {
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
                        -ValueName "CachedLogonsCount" -Type String -Value "2" | Out-Null
                    Write-Log "[FIXED] $gpoName - CachedLogonsCount reduced to 2" "Green" "FIX"
                } else {
                    Write-Log "[WOULD FIX] $gpoName - Reduce CachedLogonsCount to 2" "Yellow" "PLAN"
                }
                Add-Remediation -GPOName $gpoName -Action "SET" -Setting "CachedLogonsCount" `
                    -OldValue "$($ccVal.Value)" -NewValue "2" -Status $(if($Apply){"APPLIED"}else{"PLANNED"})
                $fixCount++
            }
        } catch {}

        # --- FIX: RDP NLA ---
        try {
            $nlaVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ValueName "UserAuthentication" -ErrorAction Stop
            if ($nlaVal.Value -eq 0) {
                if ($Apply) {
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
                        -ValueName "UserAuthentication" -Type DWord -Value 1 | Out-Null
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
                        -ValueName "MinEncryptionLevel" -Type DWord -Value 3 | Out-Null
                    Write-Log "[FIXED] $gpoName - RDP NLA enabled, High encryption" "Green" "FIX"
                } else {
                    Write-Log "[WOULD FIX] $gpoName - Enable RDP NLA + High encryption" "Yellow" "PLAN"
                }
                Add-Remediation -GPOName $gpoName -Action "SET" -Setting "RDP UserAuthentication + MinEncryption" `
                    -OldValue "0, 1" -NewValue "1, 3" -Status $(if($Apply){"APPLIED"}else{"PLANNED"})
                $fixCount++
            }
        } catch {}

        # --- FIX: AutoRun ---
        try {
            $arVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoDriveTypeAutoRun" -ErrorAction Stop
            if ($arVal.Value -eq 0) {
                if ($Apply) {
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
                        -ValueName "NoDriveTypeAutoRun" -Type DWord -Value 255 | Out-Null
                    Write-Log "[FIXED] $gpoName - AutoRun DISABLED for all drives" "Green" "FIX"
                } else {
                    Write-Log "[WOULD FIX] $gpoName - Disable AutoRun" "Yellow" "PLAN"
                }
                Add-Remediation -GPOName $gpoName -Action "SET" -Setting "NoDriveTypeAutoRun" -OldValue "0" -NewValue "255" `
                    -Status $(if($Apply){"APPLIED"}else{"PLANNED"})
                $fixCount++
            }
        } catch {}

        # --- FIX: Credential Guard / LSA Protection ---
        try {
            $rplVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "RunAsPPL" -ErrorAction Stop
            if ($rplVal.Value -eq 0) {
                if ($Apply) {
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
                        -ValueName "RunAsPPL" -Type DWord -Value 1 | Out-Null
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
                        -ValueName "EnableVirtualizationBasedSecurity" -Type DWord -Value 1 | Out-Null
                    Write-Log "[FIXED] $gpoName - RunAsPPL + VBS ENABLED" "Green" "FIX"
                } else {
                    Write-Log "[WOULD FIX] $gpoName - Enable RunAsPPL + VBS" "Yellow" "PLAN"
                }
                Add-Remediation -GPOName $gpoName -Action "SET" -Setting "RunAsPPL + VBS" -OldValue "0, 0" -NewValue "1, 1" `
                    -Status $(if($Apply){"APPLIED"}else{"PLANNED"})
                $fixCount++
            }
        } catch {}

        # --- FIX: Anonymous Enumeration ---
        try {
            $anVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "RestrictAnonymousSAM" -ErrorAction Stop
            if ($anVal.Value -eq 0) {
                if ($Apply) {
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
                        -ValueName "RestrictAnonymousSAM" -Type DWord -Value 1 | Out-Null
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
                        -ValueName "RestrictAnonymous" -Type DWord -Value 1 | Out-Null
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
                        -ValueName "RestrictNullSessAccess" -Type DWord -Value 1 | Out-Null
                    Write-Log "[FIXED] $gpoName - Anonymous enumeration BLOCKED" "Green" "FIX"
                } else {
                    Write-Log "[WOULD FIX] $gpoName - Block anonymous enumeration" "Yellow" "PLAN"
                }
                Add-Remediation -GPOName $gpoName -Action "SET" -Setting "RestrictAnonymous*" -OldValue "0" -NewValue "1" `
                    -Status $(if($Apply){"APPLIED"}else{"PLANNED"})
                $fixCount++
            }
        } catch {}

        # --- FIX: WinRM ---
        try {
            $wrmVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowUnencryptedTraffic" -ErrorAction Stop
            if ($wrmVal.Value -eq 1) {
                if ($Apply) {
                    foreach ($side in @("Service","Client")) {
                        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\$side" `
                            -ValueName "AllowUnencryptedTraffic" -Type DWord -Value 0 | Out-Null
                        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\$side" `
                            -ValueName "AllowBasic" -Type DWord -Value 0 | Out-Null
                    }
                    Write-Log "[FIXED] $gpoName - WinRM secured (no unencrypted, no Basic)" "Green" "FIX"
                } else {
                    Write-Log "[WOULD FIX] $gpoName - Secure WinRM settings" "Yellow" "PLAN"
                }
                Add-Remediation -GPOName $gpoName -Action "SET" -Setting "WinRM AllowUnencrypted + AllowBasic" `
                    -OldValue "1, 1" -NewValue "0, 0" -Status $(if($Apply){"APPLIED"}else{"PLANNED"})
                $fixCount++
            }
        } catch {}

        # --- FIX: Event Log Size ---
        try {
            $evtVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -ValueName "MaxSize" -ErrorAction Stop
            if ([int]$evtVal.Value -lt 1024) {
                if ($Apply) {
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" `
                        -ValueName "MaxSize" -Type DWord -Value 1048576 | Out-Null
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" `
                        -ValueName "MaxSize" -Type DWord -Value 262144 | Out-Null
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Windows PowerShell" `
                        -ValueName "MaxSize" -Type DWord -Value 262144 | Out-Null
                    Write-Log "[FIXED] $gpoName - Event logs sized properly (Security=1GB, System/PS=256MB)" "Green" "FIX"
                } else {
                    Write-Log "[WOULD FIX] $gpoName - Increase event log sizes" "Yellow" "PLAN"
                }
                Add-Remediation -GPOName $gpoName -Action "SET" -Setting "EventLog MaxSize (Sec/Sys/PS)" `
                    -OldValue "64 KB" -NewValue "1048576 / 262144 / 262144 KB" -Status $(if($Apply){"APPLIED"}else{"PLANNED"})
                $fixCount++
            }
        } catch {}

        # --- FIX: LDAP Signing ---
        try {
            $ldVal = Get-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -ValueName "LDAPServerIntegrity" -ErrorAction Stop
            if ($ldVal.Value -eq 0) {
                if ($Apply) {
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
                        -ValueName "LDAPServerIntegrity" -Type DWord -Value 2 | Out-Null
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" `
                        -ValueName "LDAPClientIntegrity" -Type DWord -Value 1 | Out-Null
                    Write-Log "[FIXED] $gpoName - LDAP signing REQUIRED" "Green" "FIX"
                } else {
                    Write-Log "[WOULD FIX] $gpoName - Require LDAP signing" "Yellow" "PLAN"
                }
                Add-Remediation -GPOName $gpoName -Action "SET" -Setting "LDAPServerIntegrity + LDAPClientIntegrity" `
                    -OldValue "0, 0" -NewValue "2, 1" -Status $(if($Apply){"APPLIED"}else{"PLANNED"})
                $fixCount++
            }
        } catch {}
    }

    # ============================================================================
    # FIX: PASSWORD POLICY (Security Templates)
    # ============================================================================
    Write-Host "`n[*] Remediating password policies in SYSVOL..." -ForegroundColor Cyan

    foreach ($gpo in $AllGPOs) {
        $infPath = "\\$DomainDNS\SYSVOL\$DomainDNS\Policies\{$($gpo.Id)}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
        if (Test-Path $infPath) {
            $content = Get-Content $infPath -Raw
            $needsFix = $false

            if ($content -match "MinimumPasswordLength\s*=\s*(\d+)" -and [int]$Matches[1] -lt 8) { $needsFix = $true }
            if ($content -match "PasswordComplexity\s*=\s*0") { $needsFix = $true }
            if ($content -match "MaximumPasswordAge\s*=\s*0") { $needsFix = $true }
            if ($content -match "LockoutBadCount\s*=\s*0") { $needsFix = $true }

            if ($needsFix) {
                $secureInf = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 90
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
ClearTextPassword = 0
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
                if ($Apply) {
                    $secureInf | Out-File -FilePath $infPath -Encoding Unicode -Force
                    Write-Log "[FIXED] $($gpo.DisplayName) - Password policy hardened (14 char, complexity, lockout)" "Green" "FIX"
                } else {
                    Write-Log "[WOULD FIX] $($gpo.DisplayName) - Harden password policy" "Yellow" "PLAN"
                }
                Add-Remediation -GPOName $gpo.DisplayName -Action "REPLACE" -Setting "GptTmpl.inf password policy" `
                    -OldValue "Weak (len 4, no complexity, no lockout)" `
                    -NewValue "Hardened (len 14, complexity, lockout 5, history 24)" `
                    -Status $(if($Apply){"APPLIED"}else{"PLANNED"})
                $fixCount++
            }
        }
    }

    # ============================================================================
    # FIX: GPP PASSWORDS (MS14-025) - Delete Groups.xml files
    # ============================================================================
    Write-Host "`n[*] Removing GPP password files from SYSVOL..." -ForegroundColor Cyan

    $SYSVOLPath = "\\$DomainDNS\SYSVOL\$DomainDNS\Policies"
    foreach ($gpo in $AllGPOs) {
        foreach ($scope in @("Machine","User")) {
            $gppGroupsPath = "$SYSVOLPath\{$($gpo.Id)}\$scope\Preferences\Groups\Groups.xml"
            if (Test-Path $gppGroupsPath) {
                $xml = Get-Content $gppGroupsPath -Raw
                if ($xml -match "cpassword") {
                    if ($Apply) {
                        Remove-Item $gppGroupsPath -Force
                        Write-Log "[FIXED] Deleted GPP password file from '$($gpo.DisplayName)'" "Green" "FIX"
                    } else {
                        Write-Log "[WOULD FIX] Delete GPP password file from '$($gpo.DisplayName)'" "Yellow" "PLAN"
                    }
                    Add-Remediation -GPOName $gpo.DisplayName -Action "DELETE" -Setting "Groups.xml with cpassword" `
                        -OldValue "cpassword present (decryptable)" -NewValue "File deleted" `
                        -Status $(if($Apply){"APPLIED"}else{"PLANNED"})
                    $fixCount++
                }
            }
        }
    }
}

# ============================================================================
# FIX: GPO PERMISSION DELEGATION
# ============================================================================
Write-Host "`n[*] Reviewing GPO permission delegations..." -ForegroundColor Cyan

$LegitGPOEditors = @("Domain Admins","Enterprise Admins","ENTERPRISE DOMAIN CONTROLLERS","SYSTEM","Authenticated Users","Administrator")

foreach ($gpo in (Get-GPO -All)) {
    try {
        $perms = Get-GPPermission -Name $gpo.DisplayName -All -ErrorAction Stop
        foreach ($perm in $perms) {
            $trustee = $perm.Trustee.Name
            $permLevel = $perm.Permission

            if ($trustee -in $LegitGPOEditors) { continue }

            if ($permLevel -in @("GpoEdit","GpoEditDeleteModifySecurity","GpoCustom")) {
                # Check if BadderBlood object
                $isBB = $false
                try {
                    $obj = Get-ADObject -Filter "SamAccountName -eq '$trustee'" -Properties Description
                    if ($obj.Description) {
                        $isBB = ($BadderBloodDescPatterns | ForEach-Object { $obj.Description -like $_ }) -contains $true
                    }
                } catch {}

                if ($Apply) {
                    try {
                        # Determine trustee type
                        $type = "User"
                        try { Get-ADGroup $trustee -ErrorAction Stop; $type = "Group" } catch {}

                        Set-GPPermission -Name $gpo.DisplayName -TargetName $trustee -TargetType $type `
                            -PermissionLevel None -Replace -ErrorAction Stop
                        Write-Log "[FIXED] Removed $permLevel from '$trustee' on '$($gpo.DisplayName)'" "Green" "FIX"
                    } catch {
                        Write-Log "[FAILED] Could not remove '$trustee' from '$($gpo.DisplayName)': $_" "Red" "ERROR"
                    }
                } else {
                    $bbTag = if ($isBB) { " [BADDERBLOOD]" } else { "" }
                    Write-Log "[WOULD FIX] Remove $permLevel from '$trustee'$bbTag on '$($gpo.DisplayName)'" "Yellow" "PLAN"
                }
                Add-Remediation -GPOName $gpo.DisplayName -Action "REMOVE_PERM" -Setting "$trustee -> $permLevel" `
                    -OldValue "$permLevel" -NewValue "None (removed)" `
                    -Status $(if($Apply){"APPLIED"}else{"PLANNED"})
                $fixCount++
            }
        }
    } catch {}
}

# ============================================================================
# EXPORT LOG AND SUMMARY
# ============================================================================

$RemediationLog | Export-Csv -Path (Join-Path $OutputPath "Remediation_Actions.csv") -NoTypeInformation
$logLines | Out-File -FilePath $logFile -Encoding UTF8

Write-Host ""
Write-Host "=" * 80 -ForegroundColor Yellow
Write-Host "  GPO REMEDIATION $(if($Apply){'COMPLETE'}else{'PLAN (DRY RUN)'})" -ForegroundColor $(if($Apply){"Green"}else{"Yellow"})
Write-Host "=" * 80 -ForegroundColor Yellow
Write-Host ""
Write-Host "  Actions $(if($Apply){'applied'}else{'planned'}): $fixCount" -ForegroundColor White
Write-Host "  Log: $logFile" -ForegroundColor Cyan
Write-Host "  Actions CSV: $(Join-Path $OutputPath 'Remediation_Actions.csv')" -ForegroundColor Cyan
if ($BackupFirst -and $Apply) {
    Write-Host "  Backups: $(Join-Path $OutputPath 'GPO_Backups')" -ForegroundColor Cyan
}
Write-Host ""
if (-not $Apply) {
    Write-Host "  To apply these changes, re-run with -Apply flag:" -ForegroundColor Yellow
    Write-Host "    .\Remediate-BadderBloodGPO.ps1 -Apply -BackupFirst" -ForegroundColor White
    Write-Host ""
}
Write-Host "=" * 80 -ForegroundColor Yellow
