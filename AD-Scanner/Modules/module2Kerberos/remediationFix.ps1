<#
.SYNOPSIS
    Remediation fix functions for Module 2 (Kerberos/SPN issues)

.DESCRIPTION
    Contains functions to fix dangerous Kerberos and SPN-related settings.
    Includes parameter validation and comprehensive error handling.
#>

#region Fix Functions

<#
.SYNOPSIS
    Fixes PasswordNeverExpires setting on accounts
.PARAMETER Accounts
    Array of account objects to fix
#>
function Set-PasswordNeverExpiresFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [Object[]]$Accounts
    )

    try {
        foreach ($account in $Accounts) {
            try {
                Set-ADUser -Identity $account.SamAccountName -PasswordNeverExpires $false -ErrorAction Stop
                Write-Host "  [OK] Fixed: $($account.SamAccountName)" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Failed to fix PasswordNeverExpires for $($account.SamAccountName): $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Error in Set-PasswordNeverExpiresFix: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Fixes PasswordNotRequired setting on accounts
.PARAMETER Accounts
    Array of account objects to fix
#>
function Set-PasswordNotRequiredFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [Object[]]$Accounts
    )

    try {
        foreach ($account in $Accounts) {
            try {
                Set-ADUser -Identity $account.SamAccountName -PasswordNotRequired $false -ErrorAction Stop
                Write-Host "  [OK] Fixed: $($account.SamAccountName)" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Failed to fix PasswordNotRequired for $($account.SamAccountName): $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Error in Set-PasswordNotRequiredFix: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Fixes CannotChangePassword setting on accounts
.PARAMETER Accounts
    Array of account objects to fix
#>
function Set-CannotChangePasswordFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [Object[]]$Accounts
    )

    try {
        foreach ($account in $Accounts) {
            try {
                Set-ADAccountControl -Identity $account.SamAccountName -CannotChangePassword $false -ErrorAction Stop
                Write-Host "  [OK] Fixed: $($account.SamAccountName)" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Failed to fix CannotChangePassword for $($account.SamAccountName): $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Error in Set-CannotChangePasswordFix: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Disables UseDESKeyOnly setting on accounts
.PARAMETER Accounts
    Array of account objects to fix
.DESCRIPTION
    DES encryption is deprecated and insecure. This removes the DES-only restriction.
#>
function Set-UseDESKeyOnlyFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [Object[]]$Accounts
    )

    try {
        foreach ($account in $Accounts) {
            try {
                Set-ADAccountControl -Identity $account.SamAccountName -UseDESKeyOnly $false -ErrorAction Stop
                Write-Host "  [OK] Fixed: $($account.SamAccountName)" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Failed to fix UseDESKeyOnly for $($account.SamAccountName): $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Error in Set-UseDESKeyOnlyFix: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Disables reversible password encryption on accounts
.PARAMETER Accounts
    Array of account objects to fix
.DESCRIPTION
    Reversible encryption stores passwords in a way that can be decrypted, which is a security risk.
#>
function Set-ReversiblePasswordEncryptionFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [Object[]]$Accounts
    )

    try {
        foreach ($account in $Accounts) {
            try {
                Set-ADUser -Identity $account.SamAccountName -AllowReversiblePasswordEncryption $false -ErrorAction Stop
                Write-Host "  [OK] Fixed: $($account.SamAccountName)" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Failed to fix ReversiblePasswordEncryption for $($account.SamAccountName): $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Error in Set-ReversiblePasswordEncryptionFix: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Enables Kerberos pre-authentication requirement on accounts
.PARAMETER Accounts
    Array of account objects to fix
.DESCRIPTION
    Accounts that don't require pre-authentication are vulnerable to AS-REP roasting attacks.
#>
function Set-RequirePreAuthFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [Object[]]$Accounts
    )

    try {
        foreach ($account in $Accounts) {
            try {
                Set-ADAccountControl -Identity $account.SamAccountName -DoesNotRequirePreAuth $false -ErrorAction Stop
                Write-Host "  [OK] Fixed: $($account.SamAccountName)" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Failed to fix PreAuth requirement for $($account.SamAccountName): $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Error in Set-RequirePreAuthFix: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Disables unconstrained delegation on accounts
.PARAMETER Accounts
    Array of account objects to fix
.DESCRIPTION
    Unconstrained delegation allows any service to be impersonated, which is a critical security risk.
    WARNING: Disabling delegation may break services that depend on it!
#>
function Set-TrustedForDelegationFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [Object[]]$Accounts
    )

    try {
        Write-Host "  WARNING: Disabling delegation may break services!" -ForegroundColor Yellow

        foreach ($account in $Accounts) {
            try {
                Set-ADAccountControl -Identity $account.SamAccountName -TrustedForDelegation $false -ErrorAction Stop
                Write-Host "  [OK] Fixed: $($account.SamAccountName)" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Failed to fix TrustedForDelegation for $($account.SamAccountName): $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Error in Set-TrustedForDelegationFix: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Disables constrained delegation on accounts
.PARAMETER Accounts
    Array of account objects to fix
.DESCRIPTION
    Removes constrained delegation settings by clearing the delegation list and disabling the flag.
    WARNING: Disabling delegation may break services that depend on it!
#>
function Set-TrustedToAuthForDelegationFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [Object[]]$Accounts
    )

    try {
        Write-Host "  WARNING: Disabling delegation may break services!" -ForegroundColor Yellow

        foreach ($account in $Accounts) {
            try {
                # First clear the delegation list using -Clear instead of -Replace with $null
                Set-ADUser -Identity $account.SamAccountName -Clear 'msDS-AllowedToDelegateTo' -ErrorAction Stop

                # Then disable the account control flag
                Set-ADAccountControl -Identity $account.SamAccountName -TrustedToAuthForDelegation $false -ErrorAction Stop

                Write-Host "  [OK] Fixed: $($account.SamAccountName)" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Failed to fix TrustedToAuthForDelegation for $($account.SamAccountName): $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Error in Set-TrustedToAuthForDelegationFix: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Disables SPN accounts for cleanup
.PARAMETER Accounts
    Array of account objects to disable
.DESCRIPTION
    Disables accounts instead of deleting them, allowing for recovery if needed.
    WARNING: This will disable the accounts and may break services!
#>
function Disable-SPNAccountsFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [Object[]]$Accounts
    )

    try {
        Write-Host "  WARNING: This will disable the accounts!" -ForegroundColor Yellow

        foreach ($account in $Accounts) {
            try {
                Disable-ADAccount -Identity $account.SamAccountName -ErrorAction Stop
                Write-Host "  [OK] Disabled: $($account.SamAccountName)" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Failed to disable $($account.SamAccountName): $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Error in Disable-SPNAccountsFix: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Upgrades encryption to AES128 and AES256
.PARAMETER Accounts
    Array of account objects to fix
.DESCRIPTION
    Sets msDS-SupportedEncryptionTypes to 24 (AES128 + AES256).
    This removes support for weak encryption (DES, RC4) and enables only strong AES encryption.
    WARNING: Services may need to be restarted after this change!
#>
function Set-EncryptionToAESFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [Object[]]$Accounts
    )

    try {
        Write-Host "  Setting encryption to AES128 + AES256 (value 24)" -ForegroundColor Yellow
        Write-Host "  WARNING: Services may need to be restarted!" -ForegroundColor Yellow

        foreach ($account in $Accounts) {
            try {
                # Set msDS-SupportedEncryptionTypes to 24 (AES128-CTS-HMAC-SHA1-96 + AES256-CTS-HMAC-SHA1-96)
                Set-ADUser -Identity $account.SamAccountName -Replace @{'msDS-SupportedEncryptionTypes' = 24 } -ErrorAction Stop
                Write-Host "  [OK] Fixed: $($account.SamAccountName) - Encryption set to AES128+AES256" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Failed to set encryption for $($account.SamAccountName): $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Error in Set-EncryptionToAESFix: $($_.Exception.Message)"
    }
}

#endregion
