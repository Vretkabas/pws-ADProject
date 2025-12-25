# this file we will automatically update issues if user confirms remediation
# we will not be able to fix all issues automatically, some need manuel review
# Things we will fix automatically:
# password never expires, pw not required, cannot change password, disabled accounts, orphaned admincount

. "$PSScriptRoot\dangerousSettings.ps1"

#region helper functions

# Helper function to build remediation message (DRY)
function Build-RemediationResultAccounts {
    param(
        [Object[]]$Accounts,
        [string]$IssueType
    )

    if ($Accounts) {
        $count = ($Accounts | Measure-Object).Count
        $message = "$count account(s) with $IssueType found"
    } else {
        $message = "No accounts with $IssueType found."
    }

    return @{
        Accounts = $Accounts
        Message = $message
        Count = if ($Accounts) { ($Accounts | Measure-Object).Count } else { 0 }
    }
}

#endregion

#region account remedation

# pw expired
function Get-PasswordNeverExpiresRemediation {
    $accounts = Get-PasswordNeverExpiresAccounts
    return Build-RemediationResultAccounts -Accounts $accounts -IssueType "PasswordNeverExpires setting"
}

# get pw not required
function Get-PasswordNotRequiredAccountsRemedation {
    $accounts = Get-PasswordNotRequiredAccounts
    return Build-RemediationResultAccounts -Accounts $accounts -IssueType "PasswordNotRequired setting"
}

# cannot change pw
function Get-CannotChangePasswordAccountsRemedation {
    $accounts = Get-CannotChangePasswordAccounts
    return Build-RemediationResultAccounts -Accounts $accounts -IssueType "CannotChangePassword setting"
}

#disabled accounts
function Get-DisabledAccountsRemedation {
    $accounts = Get-DisabledAccounts
    return Build-RemediationResultAccounts -Accounts $accounts -IssueType "disabled accounts"
}

function Get-AdminCountAccountsRemedation {
    $accounts = Get-AdminCountAccounts
    return Build-RemediationResultAccounts -Accounts $accounts -IssueType "orphaned AdminCount"
}

#endregion

