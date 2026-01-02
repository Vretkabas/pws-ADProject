<#
.SYNOPSIS
    Dangerous account settings detection functions for Module 1

.DESCRIPTION
    Contains functions to detect risky account configurations in Active Directory.
    Includes parameter validation and comprehensive error handling.

#>

#region Helper Functions

<#
.SYNOPSIS
    Displays account search results with color-coded output
.PARAMETER Accounts
    Array of account objects to display
.PARAMETER MessageFound
    Message to display when accounts are found
.PARAMETER MessageNotFound
    Message to display when no accounts are found
#>
function Show-AccountResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [Object[]]$Accounts,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$MessageFound,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$MessageNotFound
    )

    try {
        # Skip output in silent mode (during re-scan)
        if ($global:SilentScan) {
            return
        }

        if ($Accounts -and $Accounts.Count -gt 0) {
            $count = ($Accounts | Measure-Object).Count
            Write-Host "$count $MessageFound" -ForegroundColor Yellow
        }
        else {
            Write-Host $MessageNotFound -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "Error displaying results: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Filters out default system accounts and SPN accounts from results
.PARAMETER Accounts
    Array of account objects to filter
.OUTPUTS
    Filtered array of account objects
#>
function Remove-DefaultAccounts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyCollection()]
        [Object[]]$Accounts
    )

    begin {
        # Default Windows built-in accounts to exclude
        $defaultAccounts = @("Guest", "Administrator", "krbtgt", "DefaultAccount")
    }

    process {
        try {
            # Filter out default accounts and SPN accounts
            # SPN accounts are audited in Module 2 (Kerberos)
            $Accounts | Where-Object {
                $defaultAccounts -notcontains $_.SamAccountName
            } | ForEach-Object {
                try {
                    # Get full user details to check for SPN
                    $userDetails = Get-ADUser $_.SamAccountName -Properties ServicePrincipalName -ErrorAction Stop

                    # Only return if NO SPN
                    if (-not $userDetails.ServicePrincipalName) {
                        $_
                    }
                }
                catch {
                    Write-Verbose "Could not check SPN for $($_.SamAccountName): $($_.Exception.Message)"
                    # Return account anyway if we can't check SPN
                    $_
                }
            }
        }
        catch {
            Write-Warning "Error filtering accounts: $($_.Exception.Message)"
            # Return original accounts on error
            $Accounts
        }
    }
}

#endregion

#region Account Detection Functions

<#
.SYNOPSIS
    Finds accounts with PasswordNeverExpires setting enabled
.OUTPUTS
    Array of accounts with PasswordNeverExpires enabled
#>
function Get-PasswordNeverExpiresAccounts {
    [CmdletBinding()]
    [OutputType([Object[]])]
    param()

    try {
        $accounts = Search-ADAccount -PasswordNeverExpires -UsersOnly -ErrorAction Stop |
            Select-Object Name, SamAccountName |
            Remove-DefaultAccounts

        $showParams = @{
            Accounts = $accounts
            MessageFound = "account(s) with PasswordNeverExpires setting found"
            MessageNotFound = "No accounts with PasswordNeverExpires setting found."
        }
        Show-AccountResults @showParams

        return $accounts
    }
    catch {
        Write-Error "Failed to search for PasswordNeverExpires accounts: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Finds accounts disabled for longer than specified days
.PARAMETER DaysDisabled
    Number of days account must be disabled (default: 30)
.OUTPUTS
    Array of disabled accounts
#>
function Get-DisabledAccounts {
    [CmdletBinding()]
    [OutputType([Object[]])]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 3650)]
        [int]$DaysDisabled = 30
    )

    try {
        $accounts = Search-ADAccount -AccountDisabled -UsersOnly -ErrorAction Stop |
            ForEach-Object {
                try {
                    Get-ADUser $_.SamAccountName -Properties whenChanged -ErrorAction Stop |
                        Where-Object { $_.whenChanged -lt (Get-Date).AddDays(-$DaysDisabled) } |
                        Select-Object Name, SamAccountName, whenChanged
                }
                catch {
                    Write-Verbose "Could not get details for $($_.SamAccountName): $($_.Exception.Message)"
                    $null
                }
            } | Where-Object { $_ -ne $null } |
            Remove-DefaultAccounts

        $showParams = @{
            Accounts = $accounts
            MessageFound = "disabled account(s) older than $DaysDisabled days"
            MessageNotFound = "No disabled accounts older than $DaysDisabled days found."
        }
        Show-AccountResults @showParams

        return $accounts
    }
    catch {
        Write-Error "Failed to search for disabled accounts: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Finds accounts inactive for longer than specified days
.PARAMETER DaysInactive
    Number of days account must be inactive (default: 60)
.OUTPUTS
    Array of inactive accounts
#>
function Get-InactiveAccounts {
    [CmdletBinding()]
    [OutputType([Object[]])]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 3650)]
        [int]$DaysInactive = 60
    )

    try {
        $accounts = Search-ADAccount -AccountInactive -UsersOnly -TimeSpan ([TimeSpan]::FromDays($DaysInactive)) -ErrorAction Stop |
            ForEach-Object {
                try {
                    Get-ADUser $_.SamAccountName -Properties LastLogonDate -ErrorAction Stop |
                        Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt (Get-Date).AddDays(-$DaysInactive) } |
                        Select-Object Name, SamAccountName, LastLogonDate
                }
                catch {
                    Write-Verbose "Could not get details for $($_.SamAccountName): $($_.Exception.Message)"
                    $null
                }
            } | Where-Object { $_ -ne $null } |
            Remove-DefaultAccounts

        $showParams = @{
            Accounts = $accounts
            MessageFound = "inactive account(s) older than $DaysInactive days"
            MessageNotFound = "No inactive accounts older than $DaysInactive days found."
        }
        Show-AccountResults @showParams

        return $accounts
    }
    catch {
        Write-Error "Failed to search for inactive accounts: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Finds accounts expired for longer than specified days
.PARAMETER DaysExpired
    Number of days account must be expired (default: 30)
.OUTPUTS
    Array of expired accounts
#>
function Get-ExpiredAccounts {
    [CmdletBinding()]
    [OutputType([Object[]])]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 3650)]
        [int]$DaysExpired = 30
    )

    try {
        $accounts = Search-ADAccount -AccountExpired -UsersOnly -ErrorAction Stop |
            ForEach-Object {
                try {
                    Get-ADUser $_.SamAccountName -Properties AccountExpirationDate -ErrorAction Stop |
                        Where-Object { $_.AccountExpirationDate -and $_.AccountExpirationDate -lt (Get-Date).AddDays(-$DaysExpired) } |
                        Select-Object Name, SamAccountName, AccountExpirationDate
                }
                catch {
                    Write-Verbose "Could not get details for $($_.SamAccountName): $($_.Exception.Message)"
                    $null
                }
            } | Where-Object { $_ -ne $null } |
            Remove-DefaultAccounts

        $showParams = @{
            Accounts = $accounts
            MessageFound = "expired account(s) older than $DaysExpired days"
            MessageNotFound = "No expired accounts older than $DaysExpired days found."
        }
        Show-AccountResults @showParams

        return $accounts
    }
    catch {
        Write-Error "Failed to search for expired accounts: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Finds currently locked out accounts
.OUTPUTS
    Array of locked out accounts
#>
function Get-LockedOutAccounts {
    [CmdletBinding()]
    [OutputType([Object[]])]
    param()

    try {
        $accounts = Search-ADAccount -LockedOut -UsersOnly -ErrorAction Stop |
            Select-Object Name, SamAccountName |
            Remove-DefaultAccounts

        $showParams = @{
            Accounts = $accounts
            MessageFound = "locked out account(s) found"
            MessageNotFound = "No locked out accounts found."
        }
        Show-AccountResults @showParams

        return $accounts
    }
    catch {
        Write-Error "Failed to search for locked out accounts: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Finds accounts with expired passwords
.OUTPUTS
    Array of accounts with expired passwords
#>
function Get-PasswordExpiredAccounts {
    [CmdletBinding()]
    [OutputType([Object[]])]
    param()

    try {
        $accounts = Search-ADAccount -PasswordExpired -UsersOnly -ErrorAction Stop |
            Select-Object Name, SamAccountName |
            Remove-DefaultAccounts

        $showParams = @{
            Accounts = $accounts
            MessageFound = "account(s) with expired passwords found"
            MessageNotFound = "No accounts with expired passwords found."
        }
        Show-AccountResults @showParams

        return $accounts
    }
    catch {
        Write-Error "Failed to search for password expired accounts: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Finds accounts with passwords in description field
.DESCRIPTION
    Checks for common password-related keywords in user descriptions.
    May produce false positives but often indicates security issues.
.OUTPUTS
    Array of accounts with passwords in description
#>
function Get-DescriptionPassword {
    [CmdletBinding()]
    [OutputType([Object[]])]
    param()

    try {
        $allUsers = Get-ADUser -Filter * -Properties Description -ErrorAction Stop

        # Keywords indicating passwords in description
        $passwordKeywords = @('pw', 'password', 'pass', 'wachtwoord', 'passwd', 'pwd', 'psw', 'passw')
        $pattern = ($passwordKeywords | ForEach-Object { [regex]::Escape($_) }) -join '|'

        $accounts = $allUsers | Where-Object {
            $_.Description -and ($_.Description -match $pattern)
        } | Select-Object Name, SamAccountName, Description |
            Remove-DefaultAccounts

        $showParams = @{
            Accounts = $accounts
            MessageFound = "account(s) with password in description found"
            MessageNotFound = "No accounts with password in description found."
        }
        Show-AccountResults @showParams

        return $accounts
    }
    catch {
        Write-Error "Failed to search for passwords in descriptions: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Finds accounts with PasswordNotRequired setting enabled
.OUTPUTS
    Array of accounts with PasswordNotRequired enabled
#>
function Get-PasswordNotRequiredAccounts {
    [CmdletBinding()]
    [OutputType([Object[]])]
    param()

    try {
        $accounts = Get-ADUser -Filter { PasswordNotRequired -eq $true } -Properties PasswordNotRequired -ErrorAction Stop |
            Select-Object Name, SamAccountName |
            Remove-DefaultAccounts

        $showParams = @{
            Accounts = $accounts
            MessageFound = "account(s) with PasswordNotRequired setting found"
            MessageNotFound = "No accounts with PasswordNotRequired setting found."
        }
        Show-AccountResults @showParams

        return $accounts
    }
    catch {
        Write-Error "Failed to search for PasswordNotRequired accounts: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Finds accounts that cannot change their password
.OUTPUTS
    Array of accounts that cannot change password
#>
function Get-CannotChangePasswordAccounts {
    [CmdletBinding()]
    [OutputType([Object[]])]
    param()

    try {
        $accounts = Get-ADUser -Filter * -Properties CannotChangePassword -ErrorAction Stop |
            Where-Object { $_.CannotChangePassword -eq $true } |
            Select-Object Name, SamAccountName |
            Remove-DefaultAccounts

        $showParams = @{
            Accounts = $accounts
            MessageFound = "account(s) that cannot change password found"
            MessageNotFound = "No accounts that cannot change password found."
        }
        Show-AccountResults @showParams

        return $accounts
    }
    catch {
        Write-Error "Failed to search for CannotChangePassword accounts: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Finds accounts with passwords older than specified days
.PARAMETER DaysOld
    Number of days password must be old (default: 90)
.OUTPUTS
    Array of accounts with old passwords
#>
function Get-OldPasswordAccounts {
    [CmdletBinding()]
    [OutputType([Object[]])]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 3650)]
        [int]$DaysOld = 90
    )

    try {
        $accounts = Get-ADUser -Filter * -Properties PasswordLastSet -ErrorAction Stop |
            Where-Object {
                $_.PasswordLastSet -and
                ($_.PasswordLastSet -lt (Get-Date).AddDays(-$DaysOld))
            } |
            Select-Object Name, SamAccountName, PasswordLastSet |
            Remove-DefaultAccounts

        $showParams = @{
            Accounts = $accounts
            MessageFound = "account(s) with passwords older than $DaysOld days found"
            MessageNotFound = "No accounts with passwords older than $DaysOld days found."
        }
        Show-AccountResults @showParams

        return $accounts
    }
    catch {
        Write-Error "Failed to search for old password accounts: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Finds orphaned accounts with adminCount=1 but not in protected groups
.DESCRIPTION
    Finds accounts with adminCount=1 that are no longer in protected groups.
    These accounts retain elevated ACL permissions which is a security risk.
    See module1.txt documentation for more information.
.OUTPUTS
    Array of orphaned adminCount accounts
#>
function Get-AdminCountAccounts {
    [CmdletBinding()]
    [OutputType([Object[]])]
    param()

    try {
        $protectedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")

        $accounts = Get-ADUser -Filter { adminCount -eq 1 } -Properties adminCount, MemberOf -ErrorAction Stop |
            Where-Object {
                # Filter only users NOT in protected groups anymore
                $inProtectedGroup = $false
                foreach ($group in $_.MemberOf) {
                    if ($protectedGroups | Where-Object { $group -like "*$_*" }) {
                        $inProtectedGroup = $true
                        break
                    }
                }
                -not $inProtectedGroup
            } |
            Select-Object Name, SamAccountName |
            Remove-DefaultAccounts

        $showParams = @{
            Accounts = $accounts
            MessageFound = "account(s) with adminCount=1 but not in protected groups found"
            MessageNotFound = "No orphaned adminCount accounts found."
        }
        Show-AccountResults @showParams

        return $accounts
    }
    catch {
        Write-Error "Failed to search for adminCount accounts: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Finds accounts with SID History
.DESCRIPTION
    SID History can be abused for privilege escalation and persistence.
    See module1.txt documentation for more information.
.OUTPUTS
    Array of accounts with SID History
#>
function Get-SIDHistoryAccounts {
    [CmdletBinding()]
    [OutputType([Object[]])]
    param()

    try {
        $accounts = Get-ADUser -Filter * -Properties SIDHistory -ErrorAction Stop |
            Where-Object { $_.SIDHistory } |
            Select-Object Name, SamAccountName, @{Name = 'SIDHistory'; Expression = { $_.SIDHistory -join ', ' } } |
            Remove-DefaultAccounts

        $showParams = @{
            Accounts = $accounts
            MessageFound = "account(s) with SID history found"
            MessageNotFound = "No accounts with SID history found."
        }
        Show-AccountResults @showParams

        return $accounts
    }
    catch {
        Write-Error "Failed to search for SID History accounts: $($_.Exception.Message)"
        return @()
    }
}

#endregion
