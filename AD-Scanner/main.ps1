<#
.SYNOPSIS
    AD Security Scanner - Master orchestration script

.DESCRIPTION
    Main entry point for the AD Security Scanner tool.
    Coordinates execution of all security audit modules and generates comprehensive HTML reports.
    Includes parameter validation, prerequisite checks, and comprehensive error handling.

.PARAMETER Modules
    Specifies which modules to run. Valid values: "All", "1", "2", "3", "4"
    Default: "All"
    - "1": Dangerous Accounts & Password Policies
    - "2": Kerberos SPN Audit
    - "3": Delegation Abuse Scanner
    - "4": Dangerous ACL Permissions Scanner

.PARAMETER SkipHTML
    Skip HTML report generation. Results will still be processed but not exported.

.PARAMETER Force
    Skip prerequisite checks (NOT RECOMMENDED).
    Use this only if you understand the risks and know the environment is configured correctly.

.EXAMPLE
    .\main.ps1
    Runs all modules and generates an HTML report

.EXAMPLE
    .\main.ps1 -Modules "1","2"
    Runs only Module 1 and Module 2

.EXAMPLE
    .\main.ps1 -SkipHTML
    Runs all modules but skips HTML report generation

.EXAMPLE
    .\main.ps1 -Force
    Runs all modules while skipping prerequisite checks (use with caution)

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "1", "2", "3", "4")]
    [string[]]$Modules = @("All"),

    [Parameter(Mandatory = $false)]
    [switch]$SkipHTML,

    [Parameter(Mandatory = $false)]
    [switch]$Force  # Force to skip prerequisite checks
)

#region Display Header

try {
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "   AD Security Scanner - Starting Analysis" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "Scan started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""
}
catch {
    Write-Error "Failed to display header: $($_.Exception.Message)"
}

#endregion

#region Prerequisite Checks

if (-not $Force) {
    try {
        # Load prerequisite check script
        $checksScriptPath = "$PSScriptRoot\Modules\Checks.ps1"
        if (-not (Test-Path $checksScriptPath)) {
            Write-Error "Prerequisite checks script not found at: $checksScriptPath"
            exit 1
        }

        . $checksScriptPath

        # Run prerequisite checks
        $checksPass = Test-Prerequisites -StopOnFailure:$false

        if (-not $checksPass) {
            Write-Host "`nCritical prerequisite checks failed." -ForegroundColor Red
            Write-Host "The scan cannot proceed." -ForegroundColor Red
            Write-Host "`nOptions:" -ForegroundColor Yellow
            Write-Host "  1. Fix the issues above and try again" -ForegroundColor Gray
            Write-Host "  2. Use -Force to skip checks (NOT RECOMMENDED)" -ForegroundColor Gray
            Write-Host ""
            exit 1
        }

        Write-Host "All prerequisite checks passed.`n" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to perform prerequisite checks: $($_.Exception.Message)"
        exit 1
    }
}
else {
    Write-Host "WARNING: Prerequisite checks are being skipped (-Force used)" -ForegroundColor Yellow
    Write-Host "Results may be unreliable!`n" -ForegroundColor Yellow
}

#endregion

#region Module Execution Setup

try {
    # Determine which modules to run
    $runAll = $Modules -contains "All"

    # Import the HTML export function
    $exportScriptPath = "$PSScriptRoot\exportHTMLOutput.ps1"
    if (-not (Test-Path $exportScriptPath)) {
        Write-Error "HTML export script not found at: $exportScriptPath"
        exit 1
    }
    . $exportScriptPath

    # Initialize results collection
    $allModuleResults = [ordered]@{}
}
catch {
    Write-Error "Failed to initialize module execution: $($_.Exception.Message)"
    exit 1
}

#endregion

#region Module 1: Dangerous Accounts & Password Policies

if ($runAll -or $Modules -contains "1") {
    $module1Path = "$PSScriptRoot\Modules\module1dangerousAccounts\module1.ps1"

    if (Test-Path $module1Path) {
        try {
            Write-Host "`nRunning Module 1: Dangerous Accounts..." -ForegroundColor Yellow

            $module1Results = & $module1Path

            if (-not $module1Results) {
                Write-Warning "Module 1 returned no results"
            }
            else {
                # Account checks go to Module 1
                if ($module1Results.AccountChecks) {
                    $allModuleResults["Module 1 - Dangerous Accounts"] = $module1Results.AccountChecks
                }
                else {
                    Write-Verbose "No account checks found in Module 1 results"
                }

                # Password Policies get their own section
                if ($module1Results.PasswordPolicies) {
                    $allModuleResults["Module 1 - Password Policies"] = $module1Results.PasswordPolicies
                }
                else {
                    Write-Verbose "No password policies found in Module 1 results"
                }
            }

            Write-Host "Module 1 completed successfully." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to execute Module 1: $($_.Exception.Message)"
            Write-Warning "Continuing with remaining modules..."
        }
    }
    else {
        Write-Warning "Module 1 script not found at: $module1Path"
    }
}

#endregion

#region Module 2: Kerberos SPN Audit

if ($runAll -or $Modules -contains "2") {
    $module2Path = "$PSScriptRoot\Modules\module2Kerberos\module2.ps1"

    if (Test-Path $module2Path) {
        try {
            Write-Host "`nRunning Module 2: Kerberos SPN Audit..." -ForegroundColor Yellow

            $module2Results = & $module2Path

            if (-not $module2Results) {
                Write-Warning "Module 2 returned no results"
            }
            else {
                # Account checks go to Module 2
                if ($module2Results.AccountChecks) {
                    $allModuleResults["Module 2 - Kerberos SPN Audit"] = $module2Results.AccountChecks
                }
                else {
                    Write-Verbose "No account checks found in Module 2 results"
                }

                # Password policy for SPN accounts
                if ($module2Results.PasswordPolicies) {
                    $allModuleResults["Module 2 - SPN Password Policies"] = $module2Results.PasswordPolicies
                }
                else {
                    Write-Verbose "No password policies found in Module 2 results"
                }
            }

            Write-Host "Module 2 completed successfully." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to execute Module 2: $($_.Exception.Message)"
            Write-Warning "Continuing with remaining modules..."
        }
    }
    else {
        Write-Warning "Module 2 script not found at: $module2Path"
    }
}

#endregion

#region Module 3: Delegation Abuse Scanner

if ($runAll -or $Modules -contains "3") {
    $module3Path = "$PSScriptRoot\Modules\module3DelegationAbuse\module3.ps1"

    if (Test-Path $module3Path) {
        try {
            Write-Host "`nRunning Module 3: Delegation Abuse Scanner..." -ForegroundColor Yellow

            $module3Results = & $module3Path

            if (-not $module3Results) {
                Write-Warning "Module 3 returned no results"
            }
            else {
                $allModuleResults["Module 3 - Delegation"] = $module3Results
            }

            Write-Host "Module 3 completed successfully." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to execute Module 3: $($_.Exception.Message)"
            Write-Warning "Continuing with remaining modules..."
        }
    }
    else {
        Write-Warning "Module 3 script not found at: $module3Path"
    }
}

#endregion

#region Module 4: Dangerous ACL Permissions Scanner

if ($runAll -or $Modules -contains "4") {
    $module4Path = "$PSScriptRoot\Modules\module4DangerousACLs\module4.ps1"

    if (Test-Path $module4Path) {
        try {
            Write-Host "`nRunning Module 4: Dangerous ACL Permissions Scanner..." -ForegroundColor Yellow

            $module4Results = & $module4Path

            if (-not $module4Results) {
                Write-Warning "Module 4 returned no results"
            }
            else {
                $allModuleResults["Module 4 - Dangerous ACL Permissions"] = $module4Results
            }

            Write-Host "Module 4 completed successfully." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to execute Module 4: $($_.Exception.Message)"
            Write-Warning "Continuing with remaining modules..."
        }
    }
    else {
        Write-Warning "Module 4 script not found at: $module4Path"
    }
}

#endregion

#region Report Generation

try {
    Write-Host "`n==================================================" -ForegroundColor Cyan
    Write-Host "   All modules completed - Generating report..." -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan

    # Check if we have any results to report
    if ($allModuleResults.Count -eq 0) {
        Write-Warning "No results to report. No modules were executed or all modules returned empty results."
    }
    elseif (-not $SkipHTML) {
        # Ensure Reports directory exists
        $reportsDir = Join-Path $PSScriptRoot "Reports"
        if (-not (Test-Path $reportsDir)) {
            try {
                New-Item -ItemType Directory -Path $reportsDir -Force -ErrorAction Stop | Out-Null
                Write-Verbose "Created Reports directory: $reportsDir"
            }
            catch {
                Write-Error "Failed to create Reports directory: $($_.Exception.Message)"
                throw
            }
        }

        # Generate report with timestamp
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $reportPath = Join-Path $reportsDir "AD-Security-Report-$timestamp.html"

        try {
            Export-ToHTML -Results $allModuleResults -OutputPath $reportPath
            Write-Host "`nReport generated successfully!" -ForegroundColor Green
            Write-Host "Location: $reportPath" -ForegroundColor Cyan
        }
        catch {
            Write-Error "Failed to generate HTML report: $($_.Exception.Message)"
            Write-Warning "Results were collected but report generation failed."
        }
    }
    else {
        Write-Host "`nHTML report skipped (use -SkipHTML:`$false to generate)" -ForegroundColor Yellow
        Write-Host "Results collected: $($allModuleResults.Count) module(s)" -ForegroundColor Gray
    }
}
catch {
    Write-Error "Failed during report generation phase: $($_.Exception.Message)"
}

#endregion

#region Display Footer

try {
    Write-Host "`n==================================================" -ForegroundColor Cyan
    Write-Host "Scan completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "==================================================" -ForegroundColor Cyan
}
catch {
    Write-Error "Failed to display footer: $($_.Exception.Message)"
}

#endregion
