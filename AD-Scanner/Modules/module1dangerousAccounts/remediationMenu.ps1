<#
.SYNOPSIS
    Interactive remediation menu for AD security issues

.DESCRIPTION
    Provides an interactive menu for users to select and fix AD security issues.
    Includes parameter validation and comprehensive error handling.

    Supported remediations:
    - Password Never Expires
    - Password Not Required
    - Cannot Change Password
    - Disabled Accounts (deletion)
    - Orphaned AdminCount

.NOTES
    This menu allows selective remediation of issues found during the scan.
    Users can review accounts before applying fixes and choose to skip remediation entirely.

#>

[CmdletBinding()]
param()

#region Import Required Functions

try {
    # Import remediation data collection functions
    $remediationPath = Join-Path $PSScriptRoot "remediation.ps1"
    if (-not (Test-Path $remediationPath)) {
        Write-Error "Remediation script not found at: $remediationPath"
        return
    }
    . $remediationPath

    # Import remediation fix functions
    $remediationFixPath = Join-Path $PSScriptRoot "remediationFix.ps1"
    if (-not (Test-Path $remediationFixPath)) {
        Write-Error "Remediation fix script not found at: $remediationFixPath"
        return
    }
    . $remediationFixPath

    Write-Verbose "Remediation functions loaded successfully"
}
catch {
    Write-Error "Failed to load remediation functions: $($_.Exception.Message)"
    return
}

#endregion

#region Display Header

try {
    Write-Host "`n=== Remediation Menu ===" -ForegroundColor Cyan
    Write-Host "The following issues can be automatically fixed:`n" -ForegroundColor Yellow
}
catch {
    Write-Warning "Failed to display header: $($_.Exception.Message)"
}

#endregion

#region Collect Remediation Data

try {
    # Define all available remediation options
    $remediationIssues = @{
        "1" = @{
            Name        = "Password Never Expires"
            Data        = $null
            FixFunction = "Set-PasswordNeverExpiresFix"
        }
        "2" = @{
            Name        = "Password Not Required"
            Data        = $null
            FixFunction = "Set-PasswordNotRequiredFix"
        }
        "3" = @{
            Name        = "Cannot Change Password"
            Data        = $null
            FixFunction = "Set-CannotChangePasswordFix"
        }
        "4" = @{
            Name        = "Disabled Accounts"
            Data        = $null
            FixFunction = "Remove-DisabledAccountsFix"
        }
        "5" = @{
            Name        = "Orphaned AdminCount"
            Data        = $null
            FixFunction = "Clear-AdminCountFix"
        }
    }

    # Collect data for each issue
    try {
        $remediationIssues["1"].Data = Get-PasswordNeverExpiresRemediation
    }
    catch {
        Write-Warning "Failed to collect Password Never Expires data: $($_.Exception.Message)"
    }

    try {
        $remediationIssues["2"].Data = Get-PasswordNotRequiredAccountsRemedation
    }
    catch {
        Write-Warning "Failed to collect Password Not Required data: $($_.Exception.Message)"
    }

    try {
        $remediationIssues["3"].Data = Get-CannotChangePasswordAccountsRemedation
    }
    catch {
        Write-Warning "Failed to collect Cannot Change Password data: $($_.Exception.Message)"
    }

    try {
        $remediationIssues["4"].Data = Get-DisabledAccountsRemedation
    }
    catch {
        Write-Warning "Failed to collect Disabled Accounts data: $($_.Exception.Message)"
    }

    try {
        $remediationIssues["5"].Data = Get-AdminCountAccountsRemedation
    }
    catch {
        Write-Warning "Failed to collect AdminCount data: $($_.Exception.Message)"
    }
}
catch {
    Write-Error "Failed to collect remediation data: $($_.Exception.Message)"
    return
}

#endregion

#region Build Available Issues Menu

try {
    # Display menu with only issues that have accounts
    $availableIssues = @{}
    $menuIndex = 1

    foreach ($key in ($remediationIssues.Keys | Sort-Object)) {
        $issue = $remediationIssues[$key]

        # Check if data was collected and contains accounts
        if ($issue.Data -and $issue.Data.Count -gt 0) {
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
}
catch {
    Write-Error "Failed to build remediation menu: $($_.Exception.Message)"
    return
}

#endregion

#region User Selection Loop

try {
    while ($true) {
        try {
            $selection = Read-Host "`nEnter your choice"

            # Exit remediation
            if ($selection -eq "0") {
                Write-Host "Skipping remediation." -ForegroundColor Cyan
                break
            }

            # Check if valid selection
            if ($availableIssues.ContainsKey($selection)) {
                $selectedIssue = $availableIssues[$selection]

                # Display selected issue
                Write-Host "`nYou selected: $($selectedIssue.Name)" -ForegroundColor Yellow
                Write-Host "Accounts to be fixed:" -ForegroundColor White

                # Display accounts safely
                try {
                    if ($selectedIssue.Data.Accounts -and $selectedIssue.Data.Accounts.Count -gt 0) {
                        $selectedIssue.Data.Accounts | Format-Table -AutoSize
                    }
                    else {
                        Write-Host "No accounts to display." -ForegroundColor Gray
                    }
                }
                catch {
                    Write-Warning "Failed to display accounts: $($_.Exception.Message)"
                }

                # Confirm fix
                $confirm = Read-Host "`nAre you sure you want to fix these accounts? (Y/N)"

                if ($confirm -eq "Y" -or $confirm -eq "y") {
                    try {
                        # Execute the fix function
                        $fixFunction = $selectedIssue.FixFunction
                        & $fixFunction -Accounts $selectedIssue.Data.Accounts

                        Write-Host "`nFix completed. Returning to menu..." -ForegroundColor Green
                    }
                    catch {
                        Write-Error "Failed to execute fix: $($_.Exception.Message)"
                    }

                    # Ask if user wants to fix more issues
                    $continue = Read-Host "`nDo you want to fix another issue? (Y/N)"
                    if ($continue -ne "Y" -and $continue -ne "y") {
                        Write-Host "Exiting remediation menu." -ForegroundColor Cyan
                        break
                    }

                    # Refresh menu (re-run to show updated counts)
                    Write-Host "`nRefreshing issue list..." -ForegroundColor Cyan
                    try {
                        . "$PSScriptRoot\remediationMenu.ps1"
                        return
                    }
                    catch {
                        Write-Error "Failed to refresh menu: $($_.Exception.Message)"
                        break
                    }
                }
                else {
                    Write-Host "Fix cancelled." -ForegroundColor Red
                }
            }
            else {
                Write-Host "Invalid selection. Please try again." -ForegroundColor Red
            }
        }
        catch {
            Write-Error "Error during selection processing: $($_.Exception.Message)"
            $retry = Read-Host "`nDo you want to try again? (Y/N)"
            if ($retry -ne "Y" -and $retry -ne "y") {
                break
            }
        }
    }
}
catch {
    Write-Error "Fatal error in selection loop: $($_.Exception.Message)"
}

#endregion

#region Display Completion

try {
    Write-Host "`nRemediation flow completed." -ForegroundColor Green
}
catch {
    Write-Warning "Failed to display completion message: $($_.Exception.Message)"
}

#endregion
