<#
.SYNOPSIS
    Remediation fix functions for Module 1 (Dangerous Account Settings)

.DESCRIPTION
    Contains functions to fix dangerous account configurations in Active Directory.
    Includes parameter validation and comprehensive error handling.
#>

#region Fix Functions

<#
.SYNOPSIS
    Fixes PasswordNeverExpires setting on accounts
.PARAMETER Accounts
    Array of account objects to fix
.DESCRIPTION
    Disables the PasswordNeverExpires flag, requiring accounts to follow password expiration policies.
#>
function Set-PasswordNeverExpiresFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [ValidateCount(1, [int]::MaxValue)]
        [Object[]]$Accounts
    )

    try {
        Write-Host "`nFixing Password Never Expires accounts..." -ForegroundColor Cyan

        foreach ($account in $Accounts) {
            try {
                Set-ADUser -Identity $account.SamAccountName -PasswordNeverExpires $false -ErrorAction Stop
                Write-Host "  [OK] Fixed: $($account.Name) ($($account.SamAccountName))" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Failed to fix $($account.Name): $($_.Exception.Message)"
            }
        }

        Write-Host "Password Never Expires fix completed." -ForegroundColor Green
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
.DESCRIPTION
    Disables the PasswordNotRequired flag, requiring accounts to have a password.
#>
function Set-PasswordNotRequiredFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [ValidateCount(1, [int]::MaxValue)]
        [Object[]]$Accounts
    )

    try {
        Write-Host "`nFixing Password Not Required accounts..." -ForegroundColor Cyan

        foreach ($account in $Accounts) {
            try {
                Set-ADUser -Identity $account.SamAccountName -PasswordNotRequired $false -ErrorAction Stop
                Write-Host "  [OK] Fixed: $($account.Name) ($($account.SamAccountName))" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Failed to fix $($account.Name): $($_.Exception.Message)"
            }
        }

        Write-Host "Password Not Required fix completed." -ForegroundColor Green
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
.DESCRIPTION
    Disables the CannotChangePassword flag, allowing users to change their passwords.
#>
function Set-CannotChangePasswordFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [ValidateCount(1, [int]::MaxValue)]
        [Object[]]$Accounts
    )

    try {
        Write-Host "`nFixing Cannot Change Password accounts..." -ForegroundColor Cyan

        foreach ($account in $Accounts) {
            try {
                Set-ADUser -Identity $account.SamAccountName -CannotChangePassword $false -ErrorAction Stop
                Write-Host "  [OK] Fixed: $($account.Name) ($($account.SamAccountName))" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Failed to fix $($account.Name): $($_.Exception.Message)"
            }
        }

        Write-Host "Cannot Change Password fix completed." -ForegroundColor Green
    }
    catch {
        Write-Error "Error in Set-CannotChangePasswordFix: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Permanently deletes disabled accounts
.PARAMETER Accounts
    Array of account objects to delete
.DESCRIPTION
    DESTRUCTIVE OPERATION: Permanently removes disabled accounts from Active Directory.
    Requires explicit confirmation from user before proceeding.
    WARNING: This cannot be undone!
#>
function Remove-DisabledAccountsFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [ValidateCount(1, [int]::MaxValue)]
        [Object[]]$Accounts
    )

    try {
        Write-Host "`nWARNING: This will PERMANENTLY DELETE disabled accounts!" -ForegroundColor Red
        Write-Host "Accounts to be deleted:" -ForegroundColor Yellow
        $Accounts | Format-Table -AutoSize

        $confirm = Read-Host "`nAre you ABSOLUTELY SURE you want to DELETE these accounts? (type 'DELETE' to confirm)"

        if ($confirm -eq "DELETE") {
            Write-Host "`nDeleting disabled accounts..." -ForegroundColor Cyan

            foreach ($account in $Accounts) {
                try {
                    Remove-ADUser -Identity $account.SamAccountName -Confirm:$false -ErrorAction Stop
                    Write-Host "  [OK] Deleted: $($account.Name) ($($account.SamAccountName))" -ForegroundColor Green
                }
                catch {
                    Write-Warning "  Failed to delete $($account.Name): $($_.Exception.Message)"
                }
            }

            Write-Host "Disabled accounts removal completed." -ForegroundColor Green
        }
        else {
            Write-Host "Account deletion cancelled." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error "Error in Remove-DisabledAccountsFix: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Clears adminCount attribute from orphaned administrative accounts
.PARAMETER Accounts
    Array of account objects to fix
.DESCRIPTION
    Removes the adminCount=1 attribute and restores ACL inheritance for accounts
    that are no longer in protected administrative groups.
    This removes the AdminSDHolder protection that persists after group removal.
#>
function Clear-AdminCountFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [ValidateCount(1, [int]::MaxValue)]
        [Object[]]$Accounts
    )

    try {
        Write-Host "`nClearing AdminCount attribute for orphaned accounts..." -ForegroundColor Cyan

        foreach ($account in $Accounts) {
            try {
                # Clear adminCount attribute
                Set-ADUser -Identity $account.SamAccountName -Clear adminCount -ErrorAction Stop

                # Also restore ACL inheritance (remove AdminSDHolder protection)
                $user = Get-ADUser -Identity $account.SamAccountName -ErrorAction Stop
                $acl = Get-Acl -Path "AD:$($user.DistinguishedName)" -ErrorAction Stop
                $acl.SetAccessRuleProtection($false, $true) # Enable inheritance, preserve existing ACEs
                Set-Acl -Path "AD:$($user.DistinguishedName)" -AclObject $acl -ErrorAction Stop

                Write-Host "  [OK] Fixed: $($account.Name) ($($account.SamAccountName))" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Failed to fix $($account.Name): $($_.Exception.Message)"
            }
        }

        Write-Host "AdminCount fix completed." -ForegroundColor Green
    }
    catch {
        Write-Error "Error in Clear-AdminCountFix: $($_.Exception.Message)"
    }
}

#endregion