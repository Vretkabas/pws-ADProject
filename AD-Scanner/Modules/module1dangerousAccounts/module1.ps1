# Module 1: Dangerous Accounts & Password Policies (IMPROVED VERSION)
# Dit script verzamelt alle gevaarlijke account settings en password policy data

# Import functies
. "$PSScriptRoot\dangerousSettings.ps1"
. "$PSScriptRoot\passwordSettings.ps1"
. "$PSScriptRoot\remediationFix.ps1"

Write-Host "`n=== Module 1: Dangerous Accounts Scanner ===" -ForegroundColor Cyan

# First scan
Write-Host "`nScanning Active Directory for dangerous account settings...`n" -ForegroundColor Yellow

$module1Results = @{
    "Password Never Expires" = Get-PasswordNeverExpiresAccounts
    "Disabled Accounts (>30 days)" = Get-DisabledAccounts -DaysDisabled 30
    "Inactive Accounts (>60 days)" = Get-InactiveAccounts -DaysInactive 60
    "Expired Accounts" = Get-ExpiredAccounts -DaysExpired 30
    "Locked Out Accounts" = Get-LockedOutAccounts
    "Password Expired" = Get-PasswordExpiredAccounts
    "Passwords in Description" = Get-DescriptionPassword
    "Password Not Required" = Get-PasswordNotRequiredAccounts
    "Cannot Change Password" = Get-CannotChangePasswordAccounts
    "Old Passwords (>90 days)" = Get-OldPasswordAccounts -DaysOld 90
    "Orphaned AdminCount" = Get-AdminCountAccounts
    "SID History" = Get-SIDHistoryAccounts
}

# Password Policy data (altijd nodig, geen remediation voor)
$passwordPolicyResults = Get-PasswordPolicyAnalysis

Write-Host "`n=== Initial Scan Completed ===" -ForegroundColor Green


# Remediation Menu
Write-Host "`n=== Remediation Options ===" -ForegroundColor Cyan
Write-Host "The following issues can be automatically fixed:`n" -ForegroundColor Yellow

# build menu of existing results no new scan
$fixableIssues = @{
    "1" = @{
        Name = "Password Never Expires"
        Accounts = $module1Results["Password Never Expires"]
        FixFunction = "Set-PasswordNeverExpiresFix"
    }
    "2" = @{
        Name = "Password Not Required"
        Accounts = $module1Results["Password Not Required"]
        FixFunction = "Set-PasswordNotRequiredFix"
    }
    "3" = @{
        Name = "Cannot Change Password"
        Accounts = $module1Results["Cannot Change Password"]
        FixFunction = "Set-CannotChangePasswordFix"
    }
    "4" = @{
        Name = "Disabled Accounts (DELETE)"
        Accounts = $module1Results["Disabled Accounts (>30 days)"]
        FixFunction = "Remove-DisabledAccountsFix"
    }
    "5" = @{
        Name = "Orphaned AdminCount"
        Accounts = $module1Results["Orphaned AdminCount"]
        FixFunction = "Clear-AdminCountFix"
    }
}

# show availableoptions (only with accounts found)
$availableOptions = @{}
$menuIndex = 1

foreach ($key in ($fixableIssues.Keys | Sort-Object)) {
    $issue = $fixableIssues[$key]
    $count = if ($issue.Accounts) { ($issue.Accounts | Measure-Object).Count } else { 0 }

    if ($count -gt 0) {
        $availableOptions[$menuIndex.ToString()] = $issue
        $menuIndex++
    }
}

if ($availableOptions.Count -eq 0) {
    Write-Host "No fixable issues found!" -ForegroundColor Green
    Write-Host "Skipping remediation...`n" -ForegroundColor Cyan
}
else {
    # Remediation Loop
    $issuesFixed = $false
    $fixedIssues = @{}  # Track which issues have been fixed

    while ($true) {
        # Re-display menu showing current status
        Write-Host "`n=== Available Remediation Options ===" -ForegroundColor Cyan

        $hasUnfixedIssues = $false
        foreach ($key in ($availableOptions.Keys | Sort-Object)) {
            $issue = $availableOptions[$key]

            if ($fixedIssues.ContainsKey($key)) {
                # Issue was fixed - show as completed
                Write-Host "$key. $($issue.Name): ✓ FIXED" -ForegroundColor Green
            } else {
                # Issue not yet fixed - show count
                $count = if ($issue.Accounts) { ($issue.Accounts | Measure-Object).Count } else { 0 }
                Write-Host "$key. $($issue.Name): $count account(s)" -ForegroundColor Yellow
                $hasUnfixedIssues = $true
            }
        }

        Write-Host "0. Exit remediation" -ForegroundColor Cyan

        # If all issues are fixed, auto-exit
        if (-not $hasUnfixedIssues) {
            Write-Host "`n✓ All fixable issues have been resolved!" -ForegroundColor Green
            break
        }

        $selection = Read-Host "`nSelect option (0 to exit)"

        if ($selection -eq "0") {
            Write-Host "Exiting remediation.`n" -ForegroundColor Cyan
            break
        }

        # Check if already fixed
        if ($fixedIssues.ContainsKey($selection)) {
            Write-Host "This issue has already been fixed! Please select another option.`n" -ForegroundColor Yellow
            continue
        }

        if ($availableOptions.ContainsKey($selection)) {
            $selectedIssue = $availableOptions[$selection]

            Write-Host "`n--- $($selectedIssue.Name) ---" -ForegroundColor Yellow

            # Check if accounts exist
            $accountCount = if ($selectedIssue.Accounts) { ($selectedIssue.Accounts | Measure-Object).Count } else { 0 }
            Write-Host "Found $accountCount account(s) to fix`n" -ForegroundColor Cyan

            if ($accountCount -gt 0) {
                # Show accounts in Out-GridView for better visibility
                Write-Host "Opening account list in grid view..." -ForegroundColor Yellow
                $selectedIssue.Accounts | Out-GridView -Title "Accounts to fix: $($selectedIssue.Name)" -Wait
            } else {
                Write-Host "ERROR: No accounts found for this issue!" -ForegroundColor Red
                Write-Host "This should not happen - skipping this option.`n" -ForegroundColor Red
                continue
            }

            $confirm = Read-Host "`nProceed with fix? (Y/N)"

            if ($confirm -eq "Y" -or $confirm -eq "y") {
                # Voer fix uit
                & $selectedIssue.FixFunction -Accounts $selectedIssue.Accounts
                $issuesFixed = $true

                # Mark this issue as fixed
                $fixedIssues[$selection] = $true

                Write-Host "`n✓ Fix completed!" -ForegroundColor Green
                Write-Host "Returning to menu...`n" -ForegroundColor Cyan
                Start-Sleep -Seconds 1
            }
            else {
                Write-Host "Fix cancelled.`n" -ForegroundColor Red
            }
        }
        else {
            Write-Host "Invalid selection!`n" -ForegroundColor Red
        }
    }

    # only re-scan if something is fixed
    if ($issuesFixed) {
        Write-Host "`n=== Re-scanning to update results ===" -ForegroundColor Cyan
        Write-Host "Please wait...`n" -ForegroundColor Yellow

        # Gebruik Write-Host in plaats van functie output voor stille scan
        $global:SilentScan = $true

        $module1Results = @{
            "Password Never Expires" = Get-PasswordNeverExpiresAccounts
            "Disabled Accounts (>30 days)" = Get-DisabledAccounts -DaysDisabled 30
            "Inactive Accounts (>60 days)" = Get-InactiveAccounts -DaysInactive 60
            "Expired Accounts" = Get-ExpiredAccounts -DaysExpired 30
            "Locked Out Accounts" = Get-LockedOutAccounts
            "Password Expired" = Get-PasswordExpiredAccounts
            "Passwords in Description" = Get-DescriptionPassword
            "Password Not Required" = Get-PasswordNotRequiredAccounts
            "Cannot Change Password" = Get-CannotChangePasswordAccounts
            "Old Passwords (>90 days)" = Get-OldPasswordAccounts -DaysOld 90
            "Orphaned AdminCount" = Get-AdminCountAccounts
            "SID History" = Get-SIDHistoryAccounts
        }

        $global:SilentScan = $false

        Write-Host "✓ Re-scan completed with updated data!" -ForegroundColor Green
    }
}

Write-Host "`n=== Module 1: Completed ===" -ForegroundColor Green

# Return resultaten
return @{
    AccountChecks    = $module1Results
    PasswordPolicies = $passwordPolicyResults
}
