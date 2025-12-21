# deze script verzamelt alle gegevens dat we nodig hebben in module 2
. "$PSScriptRoot\SPNAudit.ps1"

# Encryptie settings SPN accounts
$encryptionSettingsSPN = Get-EncryptionType -servicePrincipalName $(Get-ServiceAccounts)
# Account settings SPN accounts
$accountSettings = Get-SPNAccountSettings -servicePrincipalName $(Get-ServiceAccounts)

# mapping for checks.ps1 later
$module2Results = @{
    "Weak Encryption (DES or RC4 without AES)" = $encryptionSettingsSPN | Where-Object { $_.HasWeakEncryption -eq $true } | Select-Object SamAccountName
    "DES Encryption (Critical)" = $encryptionSettingsSPN | Where-Object { $_.HasDES -eq $true } | Select-Object SamAccountName
    "RC4 Only (No AES)" = $encryptionSettingsSPN | Where-Object { $_.HasRC4Only -eq $true } | Select-Object SamAccountName
    "AES Only (Best Practice)" = $encryptionSettingsSPN | Where-Object { $_.HasAESOnly -eq $true } | Select-Object SamAccountName
    "AES with RC4 (Acceptable)" = $encryptionSettingsSPN | Where-Object { $_.HasAES -eq $true -and $_.HasRC4 -eq $true -and $_.HasDES -eq $false } | Select-Object SamAccountName
    "Password never expires on SPN accounts" = $accountSettings | Where-Object { $_.PasswordNeverExpires -eq $true } | Select-Object SamAccountName
    "Password not required on SPN accounts" = $accountSettings | Where-Object { $_.PasswordNotRequired -eq $true } | Select-Object SamAccountName
    "Cannot change password on SPN accounts" = $accountSettings | Where-Object { $_.CannotChangePassword -eq $true } | Select-Object SamAccountName
    "Password expired on SPN accounts" = $accountSettings | Where-Object { $_.PasswordExpired -eq $true } | Select-Object SamAccountName
    "Disabled SPN accounts" = $accountSettings | Where-Object { $_.Enabled -eq $false } | Select-Object SamAccountName
    "Locked out SPN accounts" = $accountSettings | Where-Object { $_.LockedOut -eq $true } | Select-Object SamAccountName
    "Allow reversible password encryption on SPN accounts" = $accountSettings | Where-Object { $_.allowReversiblePasswordEncryption -eq $true } | Select-Object SamAccountName
    "Does not require pre-authentication on SPN accounts" = $accountSettings | Where-Object { $_.doesNotRequirePreAuth -eq $true } | Select-Object SamAccountName
    "Trusted for delegation SPN accounts" = $accountSettings | Where-Object { $_.trustedForDelegation -eq $true } | Select-Object SamAccountName
    "Trusted to authenticate for delegation SPN accounts" = $accountSettings | Where-Object { $_.trustedToAuthForDelegation -eq $true } | Select-Object SamAccountName
    "Account not delegated SPN accounts" = $accountSettings | Where-Object { $_.accountNotDelegated -eq $true } | Select-Object SamAccountName
    "SPN accounts with password age >90 days" = $accountSettings | Where-Object { $_.passwordAgeDays -gt 90  } | Select-Object SamAccountName
}


# get all FGPP issues for SPN accounts (or default policy if no FGPP)
$fgppIssuesSPN = Get-PasswordPoliciesSPN

#return results as hashtable
return @{
    AccountChecks    = $module2Results
    PasswordPolicies = $fgppIssuesSPN
}