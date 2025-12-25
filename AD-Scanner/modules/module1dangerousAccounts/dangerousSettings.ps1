# Helper functie om resultaten te tonen (DRY)
# wil be shown when running script in terminal messaged
function Show-AccountResults {
    param(
        [Object[]]$Accounts,
        [string]$MessageFound,
        [string]$MessageNotFound
    )

    # Skip output als we in silent mode zijn (tijdens re-scan)
    if ($global:SilentScan) {
        return
    }

    if ($Accounts) {
        $count = ($Accounts | Measure-Object).Count
        Write-Host "$count $MessageFound" -ForegroundColor Yellow
    }
    else {
        Write-Host $MessageNotFound -ForegroundColor Green
    }
}

function Get-PasswordNeverExpiresAccounts {
    $accounts = Search-ADAccount -PasswordNeverExpires -UsersOnly |
    Select-Object Name, SamAccountName |
    Remove-DefaultAccounts


    Show-AccountResults -Accounts $accounts `
        -MessageFound "account(s) with PasswordNeverExpires setting found" `
        -MessageNotFound "No accounts with PasswordNeverExpires setting found."

    return $accounts
}

function Get-DisabledAccounts {
    param([int]$DaysDisabled = 30)

    $accounts = Search-ADAccount -AccountDisabled -UsersOnly |
    ForEach-Object {
        Get-ADUser $_.SamAccountName -Properties whenChanged |
        Where-Object { $_.whenChanged -lt (Get-Date).AddDays(-$DaysDisabled) } |
        Select-Object Name, SamAccountName, whenChanged
    } |
    Remove-DefaultAccounts

    Show-AccountResults -Accounts $accounts `
        -MessageFound "disabled account(s) older than $DaysDisabled days" `
        -MessageNotFound "No disabled accounts older than $DaysDisabled days found."

    return $accounts
}

function Get-InactiveAccounts {
    param([int]$DaysInactive = 60)

    $accounts = Search-ADAccount -AccountInactive -UsersOnly |
    ForEach-Object {
        Get-ADUser $_.SamAccountName -Properties LastLogonDate |
        Where-Object { $_.LastLogonDate -lt (Get-Date).AddDays(-$DaysInactive) } |
        Select-Object Name, SamAccountName, LastLogonDate
    } |
    Remove-DefaultAccounts

    Show-AccountResults -Accounts $accounts `
        -MessageFound "inactive account(s) older than $DaysInactive days" `
        -MessageNotFound "No inactive accounts older than $DaysInactive days found."

    return $accounts
}

function Get-ExpiredAccounts {
    param([int]$DaysExpired = 30)

    $accounts = Search-ADAccount -AccountExpired -UsersOnly |
    ForEach-Object {
        Get-ADUser $_.SamAccountName -Properties AccountExpirationDate |
        Where-Object { $_.AccountExpirationDate -lt (Get-Date).AddDays(-$DaysExpired) } |
        Select-Object Name, SamAccountName, AccountExpirationDate
    } |
    Remove-DefaultAccounts

    Show-AccountResults -Accounts $accounts `
        -MessageFound "expired account(s) older than $DaysExpired days" `
        -MessageNotFound "No expired accounts older than $DaysExpired days found."

    return $accounts
}

function Get-LockedOutAccounts {
    $accounts = Search-ADAccount -LockedOut -UsersOnly |
    Select-Object Name, SamAccountName |
    Remove-DefaultAccounts

    Show-AccountResults -Accounts $accounts `
        -MessageFound "locked out account(s) found" `
        -MessageNotFound "No locked out accounts found."

    return $accounts
}

function Get-PasswordExpiredAccounts {
    $accounts = Search-ADAccount -PasswordExpired -UsersOnly |
    Select-Object Name, SamAccountName |
    Remove-DefaultAccounts

    Show-AccountResults -Accounts $accounts `
        -MessageFound "account(s) with expired passwords found" `
        -MessageNotFound "No accounts with expired passwords found."

    return $accounts
}

#soms zetten administrators de passwoord in description ==> checken voor dit
#kan false positives geven maar is vaak een goede indicatie
function Get-DescriptionPassword {
    $allUsers = Get-ADUser -Filter * -Properties Description

    # Keywords die duiden op passwords in description
    $passwordKeywords = @('pw', 'password', 'pass', 'wachtwoord', 'passwd', 'pwd', 'psw', 'passw')
    $pattern = ($passwordKeywords | ForEach-Object { [regex]::Escape($_) }) -join '|'

    $accounts = $allUsers | Where-Object {
        $_.Description -and ($_.Description -match $pattern)
    } | Select-Object Name, SamAccountName, Description |
    Remove-DefaultAccounts

    Show-AccountResults -Accounts $accounts `
        -MessageFound "account(s) with password in description found" `
        -MessageNotFound "No accounts with password in description found."

    return $accounts
}

function Get-PasswordNotRequiredAccounts {
    $accounts = Get-ADUser -Filter { PasswordNotRequired -eq $true } -Properties PasswordNotRequired |
    Select-Object Name, SamAccountName |
    Remove-DefaultAccounts

    Show-AccountResults -Accounts $accounts `
        -MessageFound "account(s) with PasswordNotRequired setting found" `
        -MessageNotFound "No accounts with PasswordNotRequired setting found."

    return $accounts
}

function Get-CannotChangePasswordAccounts {
    $accounts = Get-ADUser -Filter * -Properties CannotChangePassword |
    Where-Object { $_.CannotChangePassword -eq $true } |
    Select-Object Name, SamAccountName |
    Remove-DefaultAccounts

    Show-AccountResults -Accounts $accounts `
        -MessageFound "account(s) that cannot change password found" `
        -MessageNotFound "No accounts that cannot change password found."

    return $accounts
}

function Get-OldPasswordAccounts {
    param([int]$DaysOld = 90)

    $accounts = Get-ADUser -Filter * -Properties PasswordLastSet |
    Where-Object {
        $_.PasswordLastSet -and
        ($_.PasswordLastSet -lt (Get-Date).AddDays(-$DaysOld))
    } |
    Select-Object Name, SamAccountName, PasswordLastSet |
    Remove-DefaultAccounts

    Show-AccountResults -Accounts $accounts `
        -MessageFound "account(s) with passwords older than $DaysOld days found" `
        -MessageNotFound "No accounts with passwords older than $DaysOld days found."

    return $accounts
}

#functie om accounts met adminCount=1 te vinden maar niet meer in protected groups zitten
#voor meer info check documentatie module1.txt
function Get-AdminCountAccounts {
    $accounts = Get-ADUser -Filter { adminCount -eq 1 } -Properties adminCount, MemberOf |
    Where-Object {
        # Filter alleen users die NIET meer in protected groups zitten
        $protectedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
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

    Show-AccountResults -Accounts $accounts `
        -MessageFound "account(s) with adminCount=1 but not in protected groups found" `
        -MessageNotFound "No orphaned adminCount accounts found."

    return $accounts
}

#functie om accounts met SIDHistory te vinden
#zie documentatie module1.txt voor meer info
function Get-SIDHistoryAccounts {
    $accounts = Get-ADUser -Filter * -Properties SIDHistory |
    Where-Object { $_.SIDHistory } |
    Select-Object Name, SamAccountName, @{Name = 'SIDHistory'; Expression = { $_.SIDHistory -join ', ' } } |
    Remove-DefaultAccounts

    Show-AccountResults -Accounts $accounts `
        -MessageFound "account(s) with SID history found" `
        -MessageNotFound "No accounts with SID history found."

    return $accounts
}

#functie om default accounts en SPN accounts uit te sluiten
function Remove-DefaultAccounts {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Object[]]$Accounts
    )

    begin {
        # Standaard Windows built-in accounts die uitgesloten moeten worden
        $defaultAccounts = @("Guest", "Administrator", "krbtgt", "DefaultAccount")
    }

    process {
        # Filter de default accounts en SPN accounts eruit
        # SPN accounts worden geaudit in Module 2 (Kerberos)
        $Accounts | Where-Object {
            $defaultAccounts -notcontains $_.SamAccountName
        } | ForEach-Object {
            # Haal volledige user details op om SPN te checken
            $userDetails = Get-ADUser $_.SamAccountName -Properties ServicePrincipalName -ErrorAction SilentlyContinue

            # Alleen retourneren als GEEN SPN
            if (-not $userDetails.ServicePrincipalName) {
                $_
            }
        }
    }
}