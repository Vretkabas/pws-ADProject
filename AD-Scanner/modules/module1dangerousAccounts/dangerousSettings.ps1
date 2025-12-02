function Get-OldDisabledAccounts {
    param(
        [int]$DaysDisabled = 30
    )

    # zoek uitgeschakelde accounts die langer dan $DaysDisabled dagen geleden zijn uitgeschakeld
    $accountsDisabled = Search-ADAccount -AccountDisabled -UsersOnly |
    ForEach-Object {
        Get-ADUser $_.SamAccountName -Properties whenChanged |
        Where-Object {$_.whenChanged -lt (Get-Date).AddDays(-$DaysDisabled)} |
        Select-Object Name, SamAccountName, whenChanged
    }

    # Standaard accounts uitsluiten
    $accountsDisabled = Remove-DefaultAccounts -Accounts $accountsDisabled

    # resultaat tonen
    if ($accountsDisabled) {
        $count = ($accountsDisabled | Measure-Object).Count
        Write-Host "$count disabled account(s) older than $DaysDisabled days" -ForegroundColor Yellow
    } else {
        Write-Host "No disabled accounts older than $DaysDisabled days found." -ForegroundColor Green
    }
}

function Get-PasswordNeverExpiresAccounts {
    # zoek accounts met PasswordNeverExpires instelling
    $accountPWNeverExpires = Search-ADAccount -PasswordNeverExpires -UsersOnly | Select-Object Name, SamAccountName
    # resultaat tonen
    $accountPWNeverExpires = Remove-DefaultAccounts -Accounts $accountPWNeverExpires

    if ($accountPWNeverExpires) {
        $count = ($accountPWNeverExpires | Measure-Object).Count
        Write-Host "$count account(s) with PasswordNeverExpires setting found" -ForegroundColor Yellow
    } else {
        Write-Host "No accounts with PasswordNeverExpires setting found." -ForegroundColor Green
    }
}


#functie om default accounts uit te sluiten
function Remove-DefaultAccounts {
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [Object[]]$Accounts
    )

    # Standaard Windows built-in accounts die uitgesloten moeten worden
    $defaultAccounts = @("Guest", "Administrator", "krbtgt", "DefaultAccount")

    # Filter de default accounts eruit
    $filteredAccounts = $Accounts | Where-Object {
        $defaultAccounts -notcontains $_.SamAccountName
    }

    return $filteredAccounts
}


# functies aanroepen
Get-OldDisabledAccounts -DaysDisabled 0
Get-PasswordNeverExpiresAccounts