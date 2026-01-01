<#
.SYNOPSIS
    Module 1: Dangerous Accounts & Password Policies Scanner

.DESCRIPTION
    Scans Active Directory for dangerous account settings and password policy issues.
    Includes optional interactive remediation for automatically fixable issues.
    Includes parameter validation and comprehensive error handling.

    Account checks performed:
    - Password Never Expires
    - Disabled Accounts (>30 days)
    - Inactive Accounts (>60 days)
    - Expired Accounts
    - Locked Out Accounts
    - Password Expired
    - Passwords in Description
    - Password Not Required
    - Cannot Change Password
    - Old Passwords (>90 days)
    - Orphaned AdminCount
    - SID History

    Password policy checks:
    - Default Domain Policy
    - Fine-Grained Password Policies (FGPP)

.OUTPUTS
    Hashtable containing AccountChecks and PasswordPolicies results

.NOTES
    This module supports interactive remediation for certain issues.
    Users can selectively fix issues and re-scan to verify changes.

#>

[CmdletBinding()]
param()

#region Import Required Functions

try {
    # Import dangerous settings detection functions
    $dangerousSettingsPath = Join-Path $PSScriptRoot "dangerousSettings.ps1"
    if (-not (Test-Path $dangerousSettingsPath)) {
        Write-Error "Dangerous settings script not found at: $dangerousSettingsPath"
        return @{}
    }
    . $dangerousSettingsPath

    # Import password settings functions
    $passwordSettingsPath = Join-Path $PSScriptRoot "passwordSettings.ps1"
    if (-not (Test-Path $passwordSettingsPath)) {
        Write-Error "Password settings script not found at: $passwordSettingsPath"
        return @{}
    }
    . $passwordSettingsPath

    # Import remediation fix functions
    $remediationFixPath = Join-Path $PSScriptRoot "remediationFix.ps1"
    if (-not (Test-Path $remediationFixPath)) {
        Write-Error "Remediation fix script not found at: $remediationFixPath"
        return @{}
    }
    . $remediationFixPath

    Write-Verbose "All module functions loaded successfully"
}
catch {
    Write-Error "Failed to load module functions: $($_.Exception.Message)"
    return @{}
}

#endregion

#region Display Header and Perform Initial Scan

try {
    Write-Host "`n=== Module 1: Dangerous Accounts Scanner ===" -ForegroundColor Cyan
    Write-Host "`nScanning Active Directory for dangerous account settings...`n" -ForegroundColor Yellow

    # Perform initial account checks
    $module1Results = @{
        "Password Never Expires"        = $null
        "Disabled Accounts (>30 days)"  = $null
        "Inactive Accounts (>60 days)"  = $null
        "Expired Accounts"              = $null
        "Locked Out Accounts"           = $null
        "Password Expired"              = $null
        "Passwords in Description"      = $null
        "Password Not Required"         = $null
        "Cannot Change Password"        = $null
        "Old Passwords (>90 days)"      = $null
        "Orphaned AdminCount"           = $null
        "SID History"                   = $null
    }

    # Collect each check with error handling
    try {
        $module1Results["Password Never Expires"] = Get-PasswordNeverExpiresAccounts
    }
    catch {
        Write-Warning "Failed to check Password Never Expires: $($_.Exception.Message)"
        $module1Results["Password Never Expires"] = @()
    }

    try {
        $module1Results["Disabled Accounts (>30 days)"] = Get-DisabledAccounts -DaysDisabled 30
    }
    catch {
        Write-Warning "Failed to check Disabled Accounts: $($_.Exception.Message)"
        $module1Results["Disabled Accounts (>30 days)"] = @()
    }

    try {
        $module1Results["Inactive Accounts (>60 days)"] = Get-InactiveAccounts -DaysInactive 60
    }
    catch {
        Write-Warning "Failed to check Inactive Accounts: $($_.Exception.Message)"
        $module1Results["Inactive Accounts (>60 days)"] = @()
    }

    try {
        $module1Results["Expired Accounts"] = Get-ExpiredAccounts -DaysExpired 30
    }
    catch {
        Write-Warning "Failed to check Expired Accounts: $($_.Exception.Message)"
        $module1Results["Expired Accounts"] = @()
    }

    try {
        $module1Results["Locked Out Accounts"] = Get-LockedOutAccounts
    }
    catch {
        Write-Warning "Failed to check Locked Out Accounts: $($_.Exception.Message)"
        $module1Results["Locked Out Accounts"] = @()
    }

    try {
        $module1Results["Password Expired"] = Get-PasswordExpiredAccounts
    }
    catch {
        Write-Warning "Failed to check Password Expired: $($_.Exception.Message)"
        $module1Results["Password Expired"] = @()
    }

    try {
        $module1Results["Passwords in Description"] = Get-DescriptionPassword
    }
    catch {
        Write-Warning "Failed to check Passwords in Description: $($_.Exception.Message)"
        $module1Results["Passwords in Description"] = @()
    }

    try {
        $module1Results["Password Not Required"] = Get-PasswordNotRequiredAccounts
    }
    catch {
        Write-Warning "Failed to check Password Not Required: $($_.Exception.Message)"
        $module1Results["Password Not Required"] = @()
    }

    try {
        $module1Results["Cannot Change Password"] = Get-CannotChangePasswordAccounts
    }
    catch {
        Write-Warning "Failed to check Cannot Change Password: $($_.Exception.Message)"
        $module1Results["Cannot Change Password"] = @()
    }

    try {
        $module1Results["Old Passwords (>90 days)"] = Get-OldPasswordAccounts -DaysOld 90
    }
    catch {
        Write-Warning "Failed to check Old Passwords: $($_.Exception.Message)"
        $module1Results["Old Passwords (>90 days)"] = @()
    }

    try {
        $module1Results["Orphaned AdminCount"] = Get-AdminCountAccounts
    }
    catch {
        Write-Warning "Failed to check Orphaned AdminCount: $($_.Exception.Message)"
        $module1Results["Orphaned AdminCount"] = @()
    }

    try {
        $module1Results["SID History"] = Get-SIDHistoryAccounts
    }
    catch {
        Write-Warning "Failed to check SID History: $($_.Exception.Message)"
        $module1Results["SID History"] = @()
    }

    # Password Policy Analysis (always needed, no remediation available)
    try {
        $passwordPolicyResults = Get-PasswordPolicyAnalysis
    }
    catch {
        Write-Error "Failed to analyze password policies: $($_.Exception.Message)"
        $passwordPolicyResults = @{}
    }

    Write-Host "`n=== Initial Scan Completed ===" -ForegroundColor Green
}
catch {
    Write-Error "Failed to perform initial scan: $($_.Exception.Message)"
    return @{
        AccountChecks    = @{}
        PasswordPolicies = @{}
    }
}

#endregion

#region Remediation Menu

try {
    Write-Host "`n=== Remediation Options ===" -ForegroundColor Cyan
    Write-Host "The following issues can be automatically fixed:`n" -ForegroundColor Yellow

    # Build menu from existing results (no new scan)
    $fixableIssues = @{
        "1" = @{
            Name        = "Password Never Expires"
            Accounts    = $module1Results["Password Never Expires"]
            FixFunction = "Set-PasswordNeverExpiresFix"
        }
        "2" = @{
            Name        = "Password Not Required"
            Accounts    = $module1Results["Password Not Required"]
            FixFunction = "Set-PasswordNotRequiredFix"
        }
        "3" = @{
            Name        = "Cannot Change Password"
            Accounts    = $module1Results["Cannot Change Password"]
            FixFunction = "Set-CannotChangePasswordFix"
        }
        "4" = @{
            Name        = "Disabled Accounts (DELETE)"
            Accounts    = $module1Results["Disabled Accounts (>30 days)"]
            FixFunction = "Remove-DisabledAccountsFix"
        }
        "5" = @{
            Name        = "Orphaned AdminCount"
            Accounts    = $module1Results["Orphaned AdminCount"]
            FixFunction = "Clear-AdminCountFix"
        }
    }

    # Show available options (only with accounts found)
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
                    Write-Host "$key. $($issue.Name): [FIXED]" -ForegroundColor Green
                }
                else {
                    # Issue not yet fixed - show count
                    $count = if ($issue.Accounts) { ($issue.Accounts | Measure-Object).Count } else { 0 }
                    Write-Host "$key. $($issue.Name): $count account(s)" -ForegroundColor Yellow
                    $hasUnfixedIssues = $true
                }
            }

            Write-Host "0. Exit remediation" -ForegroundColor Cyan

            # If all issues are fixed, auto-exit
            if (-not $hasUnfixedIssues) {
                Write-Host "`n[SUCCESS] All fixable issues have been resolved!" -ForegroundColor Green
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
                    try {
                        Write-Host "Opening account list in grid view..." -ForegroundColor Yellow
                        $selectedIssue.Accounts | Out-GridView -Title "Accounts to fix: $($selectedIssue.Name)" -Wait
                    }
                    catch {
                        Write-Warning "Could not open grid view: $($_.Exception.Message)"
                        Write-Host "Displaying in console instead:" -ForegroundColor Yellow
                        $selectedIssue.Accounts | Format-Table -AutoSize
                    }
                }
                else {
                    Write-Host "ERROR: No accounts found for this issue!" -ForegroundColor Red
                    Write-Host "This should not happen - skipping this option.`n" -ForegroundColor Red
                    continue
                }

                $confirm = Read-Host "`nProceed with fix? (Y/N)"

                if ($confirm -eq "Y" -or $confirm -eq "y") {
                    try {
                        # Execute fix
                        & $selectedIssue.FixFunction -Accounts $selectedIssue.Accounts
                        $issuesFixed = $true

                        # Mark this issue as fixed
                        $fixedIssues[$selection] = $true

                        Write-Host "`n[SUCCESS] Fix completed!" -ForegroundColor Green
                        Write-Host "Returning to menu...`n" -ForegroundColor Cyan
                        Start-Sleep -Seconds 1
                    }
                    catch {
                        Write-Error "Failed to execute fix: $($_.Exception.Message)"
                    }
                }
                else {
                    Write-Host "Fix cancelled.`n" -ForegroundColor Red
                }
            }
            else {
                Write-Host "Invalid selection!`n" -ForegroundColor Red
            }
        }

        # Only re-scan if something was fixed
        if ($issuesFixed) {
            try {
                Write-Host "`n=== Re-scanning to update results ===" -ForegroundColor Cyan
                Write-Host "Please wait...`n" -ForegroundColor Yellow

                # Use silent scan mode (suppresses output from detection functions)
                $global:SilentScan = $true

                # Re-run all checks
                $module1Results = @{
                    "Password Never Expires"        = Get-PasswordNeverExpiresAccounts
                    "Disabled Accounts (>30 days)"  = Get-DisabledAccounts -DaysDisabled 30
                    "Inactive Accounts (>60 days)"  = Get-InactiveAccounts -DaysInactive 60
                    "Expired Accounts"              = Get-ExpiredAccounts -DaysExpired 30
                    "Locked Out Accounts"           = Get-LockedOutAccounts
                    "Password Expired"              = Get-PasswordExpiredAccounts
                    "Passwords in Description"      = Get-DescriptionPassword
                    "Password Not Required"         = Get-PasswordNotRequiredAccounts
                    "Cannot Change Password"        = Get-CannotChangePasswordAccounts
                    "Old Passwords (>90 days)"      = Get-OldPasswordAccounts -DaysOld 90
                    "Orphaned AdminCount"           = Get-AdminCountAccounts
                    "SID History"                   = Get-SIDHistoryAccounts
                }

                $global:SilentScan = $false

                Write-Host "[SUCCESS] Re-scan completed with updated data!" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to re-scan: $($_.Exception.Message)"
                $global:SilentScan = $false
            }
        }
    }
}
catch {
    Write-Error "Failed during remediation process: $($_.Exception.Message)"
}

#endregion

#region Display Completion and Return Results

try {
    Write-Host "`n=== Module 1: Completed ===" -ForegroundColor Green

    # Return results
    return @{
        AccountChecks    = $module1Results
        PasswordPolicies = $passwordPolicyResults
    }
}
catch {
    Write-Error "Failed to return results: $($_.Exception.Message)"
    return @{
        AccountChecks    = @{}
        PasswordPolicies = @{}
    }
}

#endregion
