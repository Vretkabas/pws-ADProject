# Module 1: Dangerous Accounts
# Dit script verzamelt alle gevaarlijke account settings en returned de resultaten

# Import functies
. "$PSScriptRoot\dangerousSettings.ps1"

Write-Host "`n=== Module 1: Dangerous Accounts ===" -ForegroundColor Cyan

# Verzamel alle resultaten module 1
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

Write-Host "Module 1 completed." -ForegroundColor Green

# Return resultaten voor gebruik in main script
return $module1Results
