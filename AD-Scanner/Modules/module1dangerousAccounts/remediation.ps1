<#
.SYNOPSIS
    Remediation data collection functions for Module 1

.DESCRIPTION
    Contains functions to collect remediation data for automatically fixable AD security issues.
    Includes parameter validation and comprehensive error handling.

    Supported remediations:
    - Password Never Expires
    - Password Not Required
    - Cannot Change Password
    - Disabled Accounts
    - Orphaned AdminCount

.NOTES
    This file collects data about fixable issues.
    Not all issues can be automatically fixed - some require manual review.

#>

#region Import Required Functions

try {
    $dangerousSettingsPath = Join-Path $PSScriptRoot "dangerousSettings.ps1"
    if (-not (Test-Path $dangerousSettingsPath)) {
        Write-Error "Dangerous settings script not found at: $dangerousSettingsPath"
        return
    }
    . $dangerousSettingsPath
    Write-Verbose "Dangerous settings functions loaded successfully"
}
catch {
    Write-Error "Failed to load dangerous settings functions: $($_.Exception.Message)"
    return
}

#endregion

#region Helper Functions

<#
.SYNOPSIS
    Builds a standardized remediation result object
.PARAMETER Accounts
    Array of accounts that need remediation
.PARAMETER IssueType
    Description of the issue type
.OUTPUTS
    Hashtable containing accounts, message, and count
#>
function Build-RemediationResultAccounts {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [Object[]]$Accounts,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$IssueType
    )

    try {
        if ($Accounts -and $Accounts.Count -gt 0) {
            $count = ($Accounts | Measure-Object).Count
            $message = "$count account(s) with $IssueType found"
        }
        else {
            $count = 0
            $message = "No accounts with $IssueType found."
        }

        return @{
            Accounts = $Accounts
            Message  = $message
            Count    = $count
        }
    }
    catch {
        Write-Error "Failed to build remediation result: $($_.Exception.Message)"
        return @{
            Accounts = @()
            Message  = "Error collecting data for $IssueType"
            Count    = 0
        }
    }
}

#endregion

#region Account Remediation Data Collection

<#
.SYNOPSIS
    Collects accounts with Password Never Expires setting
.OUTPUTS
    Hashtable with remediation data
#>
function Get-PasswordNeverExpiresRemediation {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    try {
        $accounts = Get-PasswordNeverExpiresAccounts
        return Build-RemediationResultAccounts -Accounts $accounts -IssueType "PasswordNeverExpires setting"
    }
    catch {
        Write-Error "Failed to get Password Never Expires remediation data: $($_.Exception.Message)"
        return Build-RemediationResultAccounts -Accounts @() -IssueType "PasswordNeverExpires setting"
    }
}

<#
.SYNOPSIS
    Collects accounts with Password Not Required setting
.OUTPUTS
    Hashtable with remediation data
#>
function Get-PasswordNotRequiredAccountsRemedation {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    try {
        $accounts = Get-PasswordNotRequiredAccounts
        return Build-RemediationResultAccounts -Accounts $accounts -IssueType "PasswordNotRequired setting"
    }
    catch {
        Write-Error "Failed to get Password Not Required remediation data: $($_.Exception.Message)"
        return Build-RemediationResultAccounts -Accounts @() -IssueType "PasswordNotRequired setting"
    }
}

<#
.SYNOPSIS
    Collects accounts with Cannot Change Password setting
.OUTPUTS
    Hashtable with remediation data
#>
function Get-CannotChangePasswordAccountsRemedation {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    try {
        $accounts = Get-CannotChangePasswordAccounts
        return Build-RemediationResultAccounts -Accounts $accounts -IssueType "CannotChangePassword setting"
    }
    catch {
        Write-Error "Failed to get Cannot Change Password remediation data: $($_.Exception.Message)"
        return Build-RemediationResultAccounts -Accounts @() -IssueType "CannotChangePassword setting"
    }
}

<#
.SYNOPSIS
    Collects disabled accounts for remediation
.OUTPUTS
    Hashtable with remediation data
#>
function Get-DisabledAccountsRemedation {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    try {
        $accounts = Get-DisabledAccounts
        return Build-RemediationResultAccounts -Accounts $accounts -IssueType "disabled accounts"
    }
    catch {
        Write-Error "Failed to get Disabled Accounts remediation data: $($_.Exception.Message)"
        return Build-RemediationResultAccounts -Accounts @() -IssueType "disabled accounts"
    }
}

<#
.SYNOPSIS
    Collects orphaned adminCount accounts for remediation
.OUTPUTS
    Hashtable with remediation data
#>
function Get-AdminCountAccountsRemedation {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    try {
        $accounts = Get-AdminCountAccounts
        return Build-RemediationResultAccounts -Accounts $accounts -IssueType "orphaned AdminCount"
    }
    catch {
        Write-Error "Failed to get AdminCount remediation data: $($_.Exception.Message)"
        return Build-RemediationResultAccounts -Accounts @() -IssueType "orphaned AdminCount"
    }
}

#endregion
