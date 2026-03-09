################################
# AK_ShadowCredentials.ps1 - Section 10: Shadow Credentials Detection
# Dot-sourced by BadderBloodAnswerKey.ps1
################################
function Invoke-AKShadowCredentialsAudit {
    <#
        .SYNOPSIS
            Checks for Shadow Credentials (msDS-KeyCredentialLink) ACL misconfigurations.
        .PARAMETER BadderBloodUsers
            Users created by BadderBlood.
        .OUTPUTS
            List of findings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$BadderBloodUsers
    )

    Write-Status "SECTION 10: Checking for Shadow Credentials (msDS-KeyCredentialLink) ACL misconfigurations..."

    $Findings = [System.Collections.Generic.List[PSObject]]::new()

    $schemaNC = (Get-ADRootDSE).SchemaNamingContext
    $keyCredLinkGuid = $null
    try {
        $schemaObj = Get-ADObject -SearchBase $schemaNC -LDAPFilter "(&(lDAPDisplayName=msDS-KeyCredentialLink)(schemaidguid=*))" -Properties schemaIDGUID -ErrorAction Stop
        if ($schemaObj) { $keyCredLinkGuid = [System.GUID]$schemaObj.schemaIDGUID }
    } catch {}

    if ($keyCredLinkGuid) {
        $sampleUsers = $BadderBloodUsers | Get-Random -Count ([Math]::Min(200, $BadderBloodUsers.Count))
        Set-Location AD:
        foreach ($user in $sampleUsers) {
            try {
                $acl = Get-Acl "AD:\$($user.DistinguishedName)" -ErrorAction SilentlyContinue
                if (-not $acl) { continue }
                foreach ($ace in $acl.Access) {
                    if ($ace.ObjectType -eq $keyCredLinkGuid -and
                        $ace.ActiveDirectoryRights -match "WriteProperty" -and
                        $ace.AccessControlType -eq "Allow" -and
                        $ace.IdentityReference -notmatch "(SYSTEM|Domain Admins|Enterprise Admins|Administrators|SELF)$") {

                        $ri = $NewAttackVectorExplanations["ShadowCredentials"]
                        $Findings.Add((Write-Finding -Category "Shadow Credentials" `
                            -Severity "HIGH" `
                            -Finding "'$($ace.IdentityReference)' can write msDS-KeyCredentialLink on '$($user.SamAccountName)'" `
                            -CurrentState "WriteProperty on msDS-KeyCredentialLink granted to '$($ace.IdentityReference)'" `
                            -ExpectedState "Remove WriteProperty on msDS-KeyCredentialLink. Only DCs and ADCS enrollment agents need this" `
                            -WhyBad $ri.Why -AttackScenario $ri.Attack -Principle $ri.Principle `
                            -ObjectDN $user.DistinguishedName))
                    }
                }
            } catch {}
        }
    } else {
        Write-Status "  msDS-KeyCredentialLink not found in schema (requires Server 2016+). Skipping." "Gray"
    }

    $Findings
}
