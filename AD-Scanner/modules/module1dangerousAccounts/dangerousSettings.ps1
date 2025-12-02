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
    $defaultDisabledAccounts = @("Guest", "Administrator", "krbtgt", "DefaultAccount")
    $accountsDisabled = $accountsDisabled | Where-Object {
        $defaultDisabledAccounts -notcontains $_.SamAccountName
    }

    # resultaat tonen
    if ($accountsDisabled) {
        $count = ($accountsDisabled | Measure-Object).Count
        Write-Host "$count disabled account(s) older than $DaysDisabled days" -ForegroundColor Yellow
    } else {
        Write-Host "No disabled accounts older than $DaysDisabled days found." -ForegroundColor Green
    }
}

# functies aanroepen
Get-OldDisabledAccounts -DaysDisabled 0