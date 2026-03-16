# ===================================================================
# CONFIGURATION BLOCK
# ===================================================================
$TargetUser     = "Kyle"
$PlainPassword  = "WinTeamMem1!" 
$TargetGroups   = @("Domain Admins")

$SecurePassword = ConvertTo-SecureString $PlainPassword -AsPlainText -Force
# ===================================================================

Import-Module ActiveDirectory

function Reset-ADUserAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserName,
        [Parameter(Mandatory = $true)]
        [securestring]$Password,
        [Parameter(Mandatory = $false)]
        [string[]]$GroupsToAdd
    )

    try {
        $existingUser = Get-ADUser -Filter "SamAccountName -eq '$UserName'" -ErrorAction SilentlyContinue

        if ($existingUser) {
            Write-Host "User '$UserName' found. Removing account..." -ForegroundColor Yellow
            Remove-ADUser -Identity $UserName -Confirm:$false -ErrorAction Stop
            # Small sleep to allow AD to process the deletion
            Start-Sleep -Seconds 2
        }

        Write-Host "Creating new user account for '$UserName'..." -ForegroundColor Cyan
        New-ADUser -Name $UserName `
                   -SamAccountName $UserName `
                   -AccountPassword $Password `
                   -Enabled $true `
                   -ChangePasswordAtLogon $false `
                   -ErrorAction Stop
        
        Write-Host "Successfully created user '$UserName'." -ForegroundColor Green

        foreach ($group in $TargetGroups) {
            Add-ADGroupMember -Identity $group -Members $UserName -ErrorAction Stop
            Write-Host "Added '$UserName' to the '$group' group." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Error resetting account '$UserName': $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
    return $true
}

function Test-ADUserAuthentication {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserName,
        [Parameter(Mandatory = $true)]
        [securestring]$Password
    )

    $domain = (Get-ADDomain).NetBIOSName
    $cred = New-Object System.Management.Automation.PSCredential("$domain\$UserName", $Password)
    
    try {
        Write-Host "Testing authentication for '$UserName'..." -ForegroundColor Cyan
        # Give AD a moment to "see" the new account
        Start-Sleep -Seconds 2
        $null = Get-ADUser -Identity $UserName -Credential $cred -ErrorAction Stop
        Write-Host "Success: Login credentials for '$UserName' are valid." -ForegroundColor Green
    } catch {
        Write-Host "Error: Authentication failed for '$UserName'. Details: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ===================================================================
# MAIN EXECUTION
# ===================================================================

Write-Host "`n--- Starting Account Reset Process ---" -ForegroundColor White
$resetSuccess = Reset-ADUserAccount -UserName $TargetUser -Password $SecurePassword -GroupsToAdd $TargetGroups

# Only test authentication if the user was actually created
if ($resetSuccess) {
    Write-Host "`n--- Starting Authentication Test ---" -ForegroundColor White
    Test-ADUserAuthentication -UserName $TargetUser -Password $SecurePassword
} else {
    Write-Host "`n--- Skipping Auth Test (User Creation Failed) ---" -ForegroundColor Red
}