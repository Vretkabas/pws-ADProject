# Module 2: Kerberos SPN Audit & Remediation
# Dit script verzamelt alle SPN account settings, encryption types en password policy data

# Import functies
. "$PSScriptRoot\SPNAudit.ps1"

Write-Host "`n=== Module 2: Kerberos SPN Audit ===" -ForegroundColor Cyan

# ============================================
# STAP 1: Eerste scan (met output)
# ============================================
Write-Host "`nScanning Active Directory for SPN accounts and settings...`n" -ForegroundColor Yellow

# Haal SPN accounts op
$serviceAccounts = Get-ServiceAccounts
$accountCount = ($serviceAccounts | Measure-Object).Count
Write-Host "Found $accountCount SPN account(s)" -ForegroundColor Cyan

# Encryptie settings SPN accounts
$encryptionSettingsSPN = Get-EncryptionType -servicePrincipalName $serviceAccounts

# Account settings SPN accounts
$accountSettingsSPN = Get-SPNAccountSettings -servicePrincipalName $serviceAccounts

# ============================================
# Show Account Check Results
# ============================================
Write-Host "`n--- Encryption Settings ---" -ForegroundColor Cyan

$weakEncryption = $encryptionSettingsSPN | Where-Object { $_.HasWeakEncryption -eq $true } | Select-Object SamAccountName
$spnParams = @{
    Accounts = $weakEncryption
    MessageFound = "SPN account(s) with weak encryption (DES or RC4 without AES)"
    MessageNotFound = "No SPN accounts with weak encryption found."
}
Show-SPNResults @spnParams

$desEncryption = $encryptionSettingsSPN | Where-Object { $_.HasDES -eq $true } | Select-Object SamAccountName
$spnParams = @{
    Accounts = $desEncryption
    MessageFound = "SPN account(s) with DES encryption (CRITICAL)"
    MessageNotFound = "No SPN accounts with DES encryption found."
}
Show-SPNResults @spnParams

$rc4Only = $encryptionSettingsSPN | Where-Object { $_.HasRC4Only -eq $true } | Select-Object SamAccountName
$spnParams = @{
    Accounts = $rc4Only
    MessageFound = "SPN account(s) with RC4 only (no AES)"
    MessageNotFound = "No SPN accounts with RC4 only found."
}
Show-SPNResults @spnParams

Write-Host "`n--- Account Settings ---" -ForegroundColor Cyan

$pwNeverExpires = $accountSettingsSPN | Where-Object { $_.PasswordNeverExpires -eq $true } | Select-Object SamAccountName
$spnParams = @{
    Accounts = $pwNeverExpires
    MessageFound = "SPN account(s) with password never expires"
    MessageNotFound = "No SPN accounts with password never expires found."
}
Show-SPNResults @spnParams

$pwNotRequired = $accountSettingsSPN | Where-Object { $_.PasswordNotRequired -eq $true } | Select-Object SamAccountName
$spnParams = @{
    Accounts = $pwNotRequired
    MessageFound = "SPN account(s) with password not required"
    MessageNotFound = "No SPN accounts with password not required found."
}
Show-SPNResults @spnParams

$cannotChangePw = $accountSettingsSPN | Where-Object { $_.CannotChangePassword -eq $true } | Select-Object SamAccountName
$spnParams = @{
    Accounts = $cannotChangePw
    MessageFound = "SPN account(s) that cannot change password"
    MessageNotFound = "No SPN accounts that cannot change password found."
}
Show-SPNResults @spnParams

$pwExpired = $accountSettingsSPN | Where-Object { $_.PasswordExpired -eq $true } | Select-Object SamAccountName
$spnParams = @{
    Accounts = $pwExpired
    MessageFound = "SPN account(s) with expired password"
    MessageNotFound = "No SPN accounts with expired password found."
}
Show-SPNResults @spnParams

$disabledAccounts = $accountSettingsSPN | Where-Object { $_.Enabled -eq $false } | Select-Object SamAccountName
$spnParams = @{
    Accounts = $disabledAccounts
    MessageFound = "disabled SPN account(s)"
    MessageNotFound = "No disabled SPN accounts found."
}
Show-SPNResults @spnParams

$lockedOut = $accountSettingsSPN | Where-Object { $_.LockedOut -eq $true } | Select-Object SamAccountName
$spnParams = @{
    Accounts = $lockedOut
    MessageFound = "locked out SPN account(s)"
    MessageNotFound = "No locked out SPN accounts found."
}
Show-SPNResults @spnParams

$reversiblePw = $accountSettingsSPN | Where-Object { $_.allowReversiblePasswordEncryption -eq $true } | Select-Object SamAccountName
$spnParams = @{
    Accounts = $reversiblePw
    MessageFound = "SPN account(s) with reversible password encryption"
    MessageNotFound = "No SPN accounts with reversible password encryption found."
}
Show-SPNResults @spnParams

$noPreAuth = $accountSettingsSPN | Where-Object { $_.doesNotRequirePreAuth -eq $true } | Select-Object SamAccountName
$spnParams = @{
    Accounts = $noPreAuth
    MessageFound = "SPN account(s) that do not require pre-authentication (AS-REP Roasting)"
    MessageNotFound = "No SPN accounts without pre-auth requirement found."
}
Show-SPNResults @spnParams

$trustedDelegation = $accountSettingsSPN | Where-Object { $_.trustedForDelegation -eq $true } | Select-Object SamAccountName
$spnParams = @{
    Accounts = $trustedDelegation
    MessageFound = "SPN account(s) trusted for delegation (Unconstrained)"
    MessageNotFound = "No SPN accounts with unconstrained delegation found."
}
Show-SPNResults @spnParams

$trustedAuthDelegation = $accountSettingsSPN | Where-Object { $_.trustedToAuthForDelegation -eq $true } | Select-Object SamAccountName
$spnParams = @{
    Accounts = $trustedAuthDelegation
    MessageFound = "SPN account(s) trusted to authenticate for delegation"
    MessageNotFound = "No SPN accounts with constrained delegation found."
}
Show-SPNResults @spnParams

$oldPasswords = $accountSettingsSPN | Where-Object { $_.passwordAgeDays -gt 90 } | Select-Object SamAccountName
$spnParams = @{
    Accounts = $oldPasswords
    MessageFound = "SPN account(s) with password age >90 days"
    MessageNotFound = "No SPN accounts with old passwords (>90 days) found."
}
Show-SPNResults @spnParams

# Mapping for checks.ps1 & HTML export
$module2Results = @{
    "Weak Encryption (DES or RC4 without AES)" = $weakEncryption
    "DES Encryption (Critical)" = $desEncryption
    "RC4 Only (No AES)" = $rc4Only
    "AES Only (Best Practice)" = $encryptionSettingsSPN | Where-Object { $_.HasAESOnly -eq $true } | Select-Object SamAccountName
    "AES with RC4 (Acceptable)" = $encryptionSettingsSPN | Where-Object { $_.HasAES -eq $true -and $_.HasRC4 -eq $true -and $_.HasDES -eq $false } | Select-Object SamAccountName
    "Password never expires on SPN accounts" = $pwNeverExpires
    "Password not required on SPN accounts" = $pwNotRequired
    "Cannot change password on SPN accounts" = $cannotChangePw
    "Password expired on SPN accounts" = $pwExpired
    "Disabled SPN accounts" = $disabledAccounts
    "Locked out SPN accounts" = $lockedOut
    "Allow reversible password encryption on SPN accounts" = $reversiblePw
    "Does not require pre-authentication on SPN accounts" = $noPreAuth
    "Trusted for delegation SPN accounts" = $trustedDelegation
    "Trusted to authenticate for delegation SPN accounts" = $trustedAuthDelegation
    "Account not delegated SPN accounts" = $accountSettingsSPN | Where-Object { $_.accountNotDelegated -eq $true } | Select-Object SamAccountName
    "SPN accounts with password age >90 days" = $oldPasswords
}

# ============================================
# Show Password Policy Results
# ============================================
Write-Host "`n--- Password Policies ---" -ForegroundColor Cyan

# Get all FGPP issues for SPN accounts (or default policy if no FGPP)
$fgppIssuesSPN = Get-PasswordPoliciesSPN

Write-Host "`n=== Initial Scan Completed ===" -ForegroundColor Green

# ============================================
# STAP 2 & 3: Remediation Menu (from separate file)
# ============================================
$issuesFixed = . "$PSScriptRoot\remediationMenu.ps1" -Module2Results $module2Results

# ============================================
# STAP 4: Re-scan ALLEEN als er iets gefixt is
# ============================================
if ($issuesFixed) {
    Write-Host "`n=== Re-scanning to update results ===" -ForegroundColor Cyan
    Write-Host "Running silent scan...`n" -ForegroundColor Gray

    $global:SilentScan = $true

    # Re-scan alle checks (identiek aan eerste scan)
    $serviceAccounts = Get-ServiceAccounts
    $encryptionSettingsSPN = Get-EncryptionType -servicePrincipalName $serviceAccounts
    $accountSettingsSPN = Get-SPNAccountSettings -servicePrincipalName $serviceAccounts

    $module2Results = @{
        "Weak Encryption (DES or RC4 without AES)" = $encryptionSettingsSPN | Where-Object { $_.HasWeakEncryption -eq $true } | Select-Object SamAccountName
        "DES Encryption (Critical)" = $encryptionSettingsSPN | Where-Object { $_.HasDES -eq $true } | Select-Object SamAccountName
        "RC4 Only (No AES)" = $encryptionSettingsSPN | Where-Object { $_.HasRC4Only -eq $true } | Select-Object SamAccountName
        "AES Only (Best Practice)" = $encryptionSettingsSPN | Where-Object { $_.HasAESOnly -eq $true } | Select-Object SamAccountName
        "AES with RC4 (Acceptable)" = $encryptionSettingsSPN | Where-Object { $_.HasAES -eq $true -and $_.HasRC4 -eq $true -and $_.HasDES -eq $false } | Select-Object SamAccountName
        "Password never expires on SPN accounts" = $accountSettingsSPN | Where-Object { $_.PasswordNeverExpires -eq $true } | Select-Object SamAccountName
        "Password not required on SPN accounts" = $accountSettingsSPN | Where-Object { $_.PasswordNotRequired -eq $true } | Select-Object SamAccountName
        "Cannot change password on SPN accounts" = $accountSettingsSPN | Where-Object { $_.CannotChangePassword -eq $true } | Select-Object SamAccountName
        "Password expired on SPN accounts" = $accountSettingsSPN | Where-Object { $_.PasswordExpired -eq $true } | Select-Object SamAccountName
        "Disabled SPN accounts" = $accountSettingsSPN | Where-Object { $_.Enabled -eq $false } | Select-Object SamAccountName
        "Locked out SPN accounts" = $accountSettingsSPN | Where-Object { $_.LockedOut -eq $true } | Select-Object SamAccountName
        "Allow reversible password encryption on SPN accounts" = $accountSettingsSPN | Where-Object { $_.allowReversiblePasswordEncryption -eq $true } | Select-Object SamAccountName
        "Does not require pre-authentication on SPN accounts" = $accountSettingsSPN | Where-Object { $_.doesNotRequirePreAuth -eq $true } | Select-Object SamAccountName
        "Trusted for delegation SPN accounts" = $accountSettingsSPN | Where-Object { $_.trustedForDelegation -eq $true } | Select-Object SamAccountName
        "Trusted to authenticate for delegation SPN accounts" = $accountSettingsSPN | Where-Object { $_.trustedToAuthForDelegation -eq $true } | Select-Object SamAccountName
        "Account not delegated SPN accounts" = $accountSettingsSPN | Where-Object { $_.accountNotDelegated -eq $true } | Select-Object SamAccountName
        "SPN accounts with password age >90 days" = $accountSettingsSPN | Where-Object { $_.passwordAgeDays -gt 90 } | Select-Object SamAccountName
    }

    $global:SilentScan = $false

    Write-Host "[SUCCESS] Re-scan completed with updated data!" -ForegroundColor Green
}

# Return results as hashtable
return @{
    AccountChecks    = $module2Results
    PasswordPolicies = $fgppIssuesSPN
}
