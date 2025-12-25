# this file we will automatically update issues if user confirms remediation
# we will not be able to fix all issues automatically, some need manuel review
# Things we will fix automatically:
# passwordNeverExpires, passwordNotRequired, cannotChangePassword, useDESKeyOnly, allowReversiblePasswordEncryption, doesNotRequirePreAuth, trustedForDelegation,
# trustedToAuthForDelegation, accountNotDelegated, enabled

. "$PSScriptRoot\SPNAudit.ps1"

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

$accountSettings = Get-SPNAccountSettings -servicePrincipalName (Get-ServiceAccounts)

# Password Never Expires
function Get-PasswordNeverExpiresAccounts {
    $accounts = $accountSettings | Where-Object { $_.PasswordNeverExpires -eq $true } | Select-Object SamAccountName
    return Build-RemediationResultAccounts -Accounts $accounts -IssueType "PasswordNeverExpires setting"
}

# Password Not Required
function Get-PasswordNotRequiredAccounts {
    $accounts = $accountSettings | Where-Object { $_.PasswordNotRequired -eq $true } | Select-Object SamAccountName
    return Build-RemediationResultAccounts -Accounts $accounts -IssueType "PasswordNotRequired setting"
}

# Cannot Change Password
function Get-CannotChangePasswordAccounts {
    $accounts = $accountSettings | Where-Object { $_.CannotChangePassword -eq $true } | Select-Object SamAccountName
    return Build-RemediationResultAccounts -Accounts $accounts -IssueType "CannotChangePassword setting"
}

# Use DES Key Only
function Get-UseDESKeyOnlyAccounts {
    $accounts = $accountSettings | Where-Object { $_.UseDESKeyOnly -eq $true } | Select-Object SamAccountName
    return Build-RemediationResultAccounts -Accounts $accounts -IssueType "UseDESKeyOnly setting"
}

# Reversible Password Encryption
function Get-ReversiblePasswordEncryptionAccounts {
    $accounts = $accountSettings | Where-Object { $_.AllowReversiblePasswordEncryption -eq $true } | Select-Object SamAccountName
    return Build-RemediationResultAccounts -Accounts $accounts -IssueType "AllowReversiblePasswordEncryption setting"
}

# Does Not Require PreAuth (AS-REP Roasting vulnerability)
function Get-DoesNotRequirePreAuthAccounts {
    $accounts = $accountSettings | Where-Object { $_.DoesNotRequirePreAuth -eq $true } | Select-Object SamAccountName
    return Build-RemediationResultAccounts -Accounts $accounts -IssueType "DoesNotRequirePreAuth setting (AS-REP Roasting)"
}

# Trusted For Delegation (Unconstrained Delegation)
function Get-TrustedForDelegationAccounts {
    $accounts = $accountSettings | Where-Object { $_.TrustedForDelegation -eq $true } | Select-Object SamAccountName
    return Build-RemediationResultAccounts -Accounts $accounts -IssueType "TrustedForDelegation setting (Unconstrained)"
}

# Trusted To Auth For Delegation (Constrained Delegation with Protocol Transition)
function Get-TrustedToAuthForDelegationAccounts {
    $accounts = $accountSettings | Where-Object { $_.TrustedToAuthForDelegation -eq $true } | Select-Object SamAccountName
    return Build-RemediationResultAccounts -Accounts $accounts -IssueType "TrustedToAuthForDelegation setting"
}

# Disabled SPN Accounts (should be removed/cleaned up)
function Get-DisabledSPNAccounts {
    $accounts = $accountSettings | Where-Object { $_.Enabled -eq $false } | Select-Object SamAccountName
    return Build-RemediationResultAccounts -Accounts $accounts -IssueType "Disabled state"
}

#endregion

#region encryption remediation

$encryptionSettings = Get-EncryptionType -servicePrincipalName (Get-ServiceAccounts)

# Weak Encryption (DES or RC4 without AES)
function Get-WeakEncryptionAccounts {
    $accounts = $encryptionSettings | Where-Object { $_.HasWeakEncryption -eq $true } | Select-Object SamAccountName, EncryptionTypes, EncryptionTypeValue
    return Build-RemediationResultAccounts -Accounts $accounts -IssueType "Weak Encryption (DES/RC4 only)"
}

#endregion


