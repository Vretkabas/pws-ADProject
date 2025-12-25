# Remediation Fix Functions
# This file contains the actual fix functions that modify AD accounts

# Fix Password Never Expires
function Set-PasswordNeverExpiresFix {
    param(
        [Parameter(Mandatory = $true)]
        [Object[]]$Accounts
    )

    Write-Host "`nFixing Password Never Expires accounts..." -ForegroundColor Cyan

    foreach ($account in $Accounts) {
        try {
            Set-ADUser -Identity $account.SamAccountName -PasswordNeverExpires $false
            Write-Host "  [OK] Fixed: $($account.Name) ($($account.SamAccountName))" -ForegroundColor Green
        }
        catch {
            Write-Host "  [ERROR] Failed to fix $($account.Name): $_" -ForegroundColor Red
        }
    }

    Write-Host "Password Never Expires fix completed." -ForegroundColor Green
}

# Fix Password Not Required
function Set-PasswordNotRequiredFix {
    param(
        [Parameter(Mandatory = $true)]
        [Object[]]$Accounts
    )

    Write-Host "`nFixing Password Not Required accounts..." -ForegroundColor Cyan

    foreach ($account in $Accounts) {
        try {
            Set-ADUser -Identity $account.SamAccountName -PasswordNotRequired $false
            Write-Host "  [OK] Fixed: $($account.Name) ($($account.SamAccountName))" -ForegroundColor Green
        }
        catch {
            Write-Host "  [ERROR] Failed to fix $($account.Name): $_" -ForegroundColor Red
        }
    }

    Write-Host "Password Not Required fix completed." -ForegroundColor Green
}

# Fix Cannot Change Password
function Set-CannotChangePasswordFix {
    param(
        [Parameter(Mandatory = $true)]
        [Object[]]$Accounts
    )

    Write-Host "`nFixing Cannot Change Password accounts..." -ForegroundColor Cyan

    foreach ($account in $Accounts) {
        try {
            Set-ADUser -Identity $account.SamAccountName -CannotChangePassword $false
            Write-Host "  [OK] Fixed: $($account.Name) ($($account.SamAccountName))" -ForegroundColor Green
        }
        catch {
            Write-Host "  [ERROR] Failed to fix $($account.Name): $_" -ForegroundColor Red
        }
    }

    Write-Host "Cannot Change Password fix completed." -ForegroundColor Green
}

# Remove Disabled Accounts (DELETE accounts)
function Remove-DisabledAccountsFix {
    param(
        [Parameter(Mandatory = $true)]
        [Object[]]$Accounts
    )

    Write-Host "`nWARNING: This will PERMANENTLY DELETE disabled accounts!" -ForegroundColor Red
    Write-Host "Accounts to be deleted:" -ForegroundColor Yellow
    $Accounts | Format-Table -AutoSize

    $confirm = Read-Host "`nAre you ABSOLUTELY SURE you want to DELETE these accounts? (type 'DELETE' to confirm)"

    if ($confirm -eq "DELETE") {
        Write-Host "`nDeleting disabled accounts..." -ForegroundColor Cyan

        foreach ($account in $Accounts) {
            try {
                Remove-ADUser -Identity $account.SamAccountName -Confirm:$false
                Write-Host "  [OK] Deleted: $($account.Name) ($($account.SamAccountName))" -ForegroundColor Green
            }
            catch {
                Write-Host "  [ERROR] Failed to delete $($account.Name): $_" -ForegroundColor Red
            }
        }

        Write-Host "Disabled accounts removal completed." -ForegroundColor Green
    }
    else {
        Write-Host "Account deletion cancelled." -ForegroundColor Yellow
    }
}

# Clear AdminCount attribute
function Clear-AdminCountFix {
    param(
        [Parameter(Mandatory = $true)]
        [Object[]]$Accounts
    )

    Write-Host "`nClearing AdminCount attribute for orphaned accounts..." -ForegroundColor Cyan

    foreach ($account in $Accounts) {
        try {
            # Clear adminCount attribute
            Set-ADUser -Identity $account.SamAccountName -Clear adminCount

            # Also restore ACL inheritance (adminSDHolder protection)
            $user = Get-ADUser -Identity $account.SamAccountName
            $acl = Get-Acl -Path "AD:$($user.DistinguishedName)"
            $acl.SetAccessRuleProtection($false, $true) # Enable inheritance
            Set-Acl -Path "AD:$($user.DistinguishedName)" -AclObject $acl

            Write-Host "  [OK] Fixed: $($account.Name) ($($account.SamAccountName))" -ForegroundColor Green
        }
        catch {
            Write-Host "  [ERROR] Failed to fix $($account.Name): $_" -ForegroundColor Red
        }
    }

    Write-Host "AdminCount fix completed." -ForegroundColor Green
}
