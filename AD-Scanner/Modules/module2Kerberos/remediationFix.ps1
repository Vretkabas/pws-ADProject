
#region fix functions

# Fix: Password Never Expires
function Set-PasswordNeverExpiresFix {
    param([Object[]]$Accounts)
    foreach ($account in $Accounts) {
        Set-ADUser -Identity $account.SamAccountName -PasswordNeverExpires $false
        Write-Host "  [OK] Fixed: $($account.SamAccountName)" -ForegroundColor Green
    }
}

# Fix: Password Not Required
function Set-PasswordNotRequiredFix {
    param([Object[]]$Accounts)
    foreach ($account in $Accounts) {
        Set-ADUser -Identity $account.SamAccountName -PasswordNotRequired $false
        Write-Host "  [OK] Fixed: $($account.SamAccountName)" -ForegroundColor Green
    }
}

# Fix: Cannot Change Password
function Set-CannotChangePasswordFix {
    param([Object[]]$Accounts)
    foreach ($account in $Accounts) {
        Set-ADAccountControl -Identity $account.SamAccountName -CannotChangePassword $false
        Write-Host "  [OK] Fixed: $($account.SamAccountName)" -ForegroundColor Green
    }
}

# Fix: Use DES Key Only
function Set-UseDESKeyOnlyFix {
    param([Object[]]$Accounts)
    foreach ($account in $Accounts) {
        Set-ADAccountControl -Identity $account.SamAccountName -UseDESKeyOnly $false
        Write-Host "  [OK] Fixed: $($account.SamAccountName)" -ForegroundColor Green
    }
}

# Fix: Reversible Password Encryption
function Set-ReversiblePasswordEncryptionFix {
    param([Object[]]$Accounts)
    foreach ($account in $Accounts) {
        Set-ADUser -Identity $account.SamAccountName -AllowReversiblePasswordEncryption $false
        Write-Host "  [OK] Fixed: $($account.SamAccountName)" -ForegroundColor Green
    }
}

# Fix: Does Not Require PreAuth
function Set-RequirePreAuthFix {
    param([Object[]]$Accounts)
    foreach ($account in $Accounts) {
        Set-ADAccountControl -Identity $account.SamAccountName -DoesNotRequirePreAuth $false
        Write-Host "  [OK] Fixed: $($account.SamAccountName)" -ForegroundColor Green
    }
}

# Fix: Trusted For Delegation (Disable Unconstrained Delegation)
function Set-TrustedForDelegationFix {
    param([Object[]]$Accounts)
    Write-Host "  WARNING: Disabling delegation may break services!" -ForegroundColor Yellow
    foreach ($account in $Accounts) {
        Set-ADAccountControl -Identity $account.SamAccountName -TrustedForDelegation $false
        Write-Host "  [OK] Fixed: $($account.SamAccountName)" -ForegroundColor Green
    }
}

# Fix: Trusted To Auth For Delegation
function Set-TrustedToAuthForDelegationFix {
    param([Object[]]$Accounts)
    Write-Host "  WARNING: Disabling delegation may break services!" -ForegroundColor Yellow
    foreach ($account in $Accounts) {
        # First clear the delegation list using -Clear instead of -Replace with $null
        Set-ADUser -Identity $account.SamAccountName -Clear 'msDS-AllowedToDelegateTo'
        # Then disable the account control flag
        Set-ADAccountControl -Identity $account.SamAccountName -TrustedToAuthForDelegation $false
        Write-Host "  [OK] Fixed: $($account.SamAccountName)" -ForegroundColor Green
    }
}

# Fix: Disable SPN Accounts (mark for cleanup)
function Disable-SPNAccountsFix {
    param([Object[]]$Accounts)
    Write-Host "  WARNING: This will disable the accounts!" -ForegroundColor Yellow
    foreach ($account in $Accounts) {
        Disable-ADAccount -Identity $account.SamAccountName
        Write-Host "  [OK] Disabled: $($account.SamAccountName)" -ForegroundColor Green
    }
}

# Fix: Weak Encryption (Set to AES256)
function Set-EncryptionToAESFix {
    param([Object[]]$Accounts)
    Write-Host "  Setting encryption to AES128 + AES256 (value 24)" -ForegroundColor Yellow
    Write-Host "  WARNING: Services may need to be restarted!" -ForegroundColor Yellow
    foreach ($account in $Accounts) {
        # Set msDS-SupportedEncryptionTypes to 24 (AES128-CTS-HMAC-SHA1-96 + AES256-CTS-HMAC-SHA1-96)
        Set-ADUser -Identity $account.SamAccountName -Replace @{'msDS-SupportedEncryptionTypes'=24}
        Write-Host "  [OK] Fixed: $($account.SamAccountName) - Encryption set to AES128+AES256" -ForegroundColor Green
    }
}

#endregion