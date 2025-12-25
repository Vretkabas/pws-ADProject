# Remediation Menu - Interactive menu for fixing AD issues
# User can select which issues to fix or skip all (0)

. "$PSScriptRoot\remediation.ps1"
. "$PSScriptRoot\remediationFix.ps1"

Write-Host "`n=== Remediation Menu ===" -ForegroundColor Cyan
Write-Host "The following issues can be automatically fixed:`n" -ForegroundColor Yellow

# Collect all remediation data
$remediationIssues = @{
    "1" = @{
        Name = "Password Never Expires"
        Data = Get-PasswordNeverExpiresRemediation
        FixFunction = "Set-PasswordNeverExpiresFix"
    }
    "2" = @{
        Name = "Password Not Required"
        Data = Get-PasswordNotRequiredAccountsRemedation
        FixFunction = "Set-PasswordNotRequiredFix"
    }
    "3" = @{
        Name = "Cannot Change Password"
        Data = Get-CannotChangePasswordAccountsRemedation
        FixFunction = "Set-CannotChangePasswordFix"
    }
    "4" = @{
        Name = "Disabled Accounts"
        Data = Get-DisabledAccountsRemedation
        FixFunction = "Remove-DisabledAccountsFix"
    }
    "5" = @{
        Name = "Orphaned AdminCount"
        Data = Get-AdminCountAccountsRemedation
        FixFunction = "Clear-AdminCountFix"
    }
}

# Display menu with only issues that have accounts
$availableIssues = @{}
$menuIndex = 1

foreach ($key in $remediationIssues.Keys | Sort-Object) {
    $issue = $remediationIssues[$key]
    if ($issue.Data.Count -gt 0) {
        Write-Host "$menuIndex. $($issue.Data.Message)" -ForegroundColor Yellow
        $availableIssues[$menuIndex.ToString()] = $issue
        $menuIndex++
    }
}

# If no issues found, skip remediation
if ($availableIssues.Count -eq 0) {
    Write-Host "No fixable issues found. Skipping remediation." -ForegroundColor Green
    return
}

Write-Host "0. Skip remediation (continue to report generation)" -ForegroundColor Cyan
Write-Host "`nSelect an issue to fix (or 0 to skip):" -ForegroundColor White

# User selection loop
while ($true) {
    $selection = Read-Host "`nEnter your choice"

    # Exit remediation
    if ($selection -eq "0") {
        Write-Host "Skipping remediation." -ForegroundColor Cyan
        break
    }

    # Check if valid selection
    if ($availableIssues.ContainsKey($selection)) {
        $selectedIssue = $availableIssues[$selection]

        Write-Host "`nYou selected: $($selectedIssue.Name)" -ForegroundColor Yellow
        Write-Host "Accounts to be fixed:" -ForegroundColor White
        $selectedIssue.Data.Accounts | Format-Table -AutoSize

        # Confirm fix
        $confirm = Read-Host "`nAre you sure you want to fix these accounts? (Y/N)"

        if ($confirm -eq "Y" -or $confirm -eq "y") {
            # Execute the fix function
            $fixFunction = $selectedIssue.FixFunction
            & $fixFunction -Accounts $selectedIssue.Data.Accounts

            Write-Host "`nFix completed. Returning to menu..." -ForegroundColor Green

            # Ask if user wants to fix more issues
            $continue = Read-Host "`nDo you want to fix another issue? (Y/N)"
            if ($continue -ne "Y" -and $continue -ne "y") {
                Write-Host "Exiting remediation menu." -ForegroundColor Cyan
                break
            }

            # Refresh menu (re-run to show updated counts)
            Write-Host "`nRefreshing issue list..." -ForegroundColor Cyan
            . "$PSScriptRoot\remediationMenu.ps1"
            return
        }
        else {
            Write-Host "Fix cancelled." -ForegroundColor Red
        }
    }
    else {
        Write-Host "Invalid selection. Please try again." -ForegroundColor Red
    }
}

Write-Host "`nRemediation flow completed." -ForegroundColor Green
