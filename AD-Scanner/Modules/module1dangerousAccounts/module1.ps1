# Module 1: Dangerous Accounts & Password Policies
# Dit script verzamelt alle gevaarlijke account settings en password policy data

# Import functies
. "$PSScriptRoot\dangerousSettings.ps1"
. "$PSScriptRoot\passwordSettings.ps1"

Write-Host "`n=== Module 1: Dangerous Accounts ===" -ForegroundColor Cyan

# Account checks
$module1Results = @{
    "Password Never Expires" = Get-PasswordNeverExpiresAccounts
    "Disabled Accounts (>30 days)" = Get-DisabledAccounts -DaysDisabled 30
    "Inactive Accounts (>60 days)" = Get-InactiveAccounts -DaysInactive 60
    "Expired Accounts" = Get-ExpiredAccounts -DaysExpired 30
    "Locked Out Accounts" = Get-LockedOutAccounts
    "Password Expired" = Get-PasswordExpiredAccounts
    "Passwords in Description" = Get-DescriptionPassword
    "Password Not Required" = Get-PasswordNotRequiredAccounts
    "Cannot Change Password" = Get-CannotChangePasswordAccounts
    "Old Passwords (>90 days)" = Get-OldPasswordAccounts -DaysOld 90
    "Orphaned AdminCount" = Get-AdminCountAccounts
    "SID History" = Get-SIDHistoryAccounts
}

# Password Policy data
$passwordPolicyResults = Get-PasswordPolicyAnalysis

Write-Host "Module 1 completed." -ForegroundColor Green

# Return beide resultaten als hashtable
return @{
    AccountChecks    = $module1Results
    PasswordPolicies = $passwordPolicyResults
}
