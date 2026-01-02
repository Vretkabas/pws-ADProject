<#
.SYNOPSIS
    AD Security Scanner PowerShell Module

.DESCRIPTION
    This module provides comprehensive Active Directory security scanning capabilities.
    It includes functions for detecting dangerous account configurations, weak password policies,
    Kerberos SPN vulnerabilities, delegation abuse, and dangerous ACL permissions.

.NOTES
    Version: 1.0.0
    Author: AD Security Scanner Project
    Created: 2026-01-02
    Requires: ActiveDirectory PowerShell Module
    Requires: Domain Admin or equivalent permissions for full functionality
#>

#region Module Variables

# Store module root path
$script:ModuleRoot = $PSScriptRoot

#endregion

#region Helper Functions

<#
.SYNOPSIS
    Tests if all prerequisites are met for running the scanner
.DESCRIPTION
    Validates that the ActiveDirectory module is available and that the user
    has sufficient permissions to query Active Directory
.PARAMETER StopOnFailure
    If $true, stops execution on first failed check. If $false, continues all checks.
#>
function Test-Prerequisites {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [bool]$StopOnFailure = $true
    )

    $checksScriptPath = Join-Path $script:ModuleRoot "Modules\Checks.ps1"
    if (Test-Path $checksScriptPath) {
        . $checksScriptPath
        return Test-Prerequisites -StopOnFailure:$StopOnFailure
    }
    else {
        Write-Warning "Prerequisite checks script not found. Skipping validation."
        return $true
    }
}

#endregion

#region Main Scanner Functions

<#
.SYNOPSIS
    Runs the complete AD Security Scanner
.DESCRIPTION
    Executes all configured security audit modules and generates a comprehensive HTML report.
    Scans for dangerous account settings, weak password policies, Kerberos vulnerabilities,
    delegation misconfigurations, and dangerous ACL permissions.
.PARAMETER Modules
    Specifies which modules to run. Valid values: "All", "1", "2", "3", "4"
    Default: "All"
    - "1": Dangerous Accounts & Password Policies
    - "2": Kerberos SPN Audit
    - "3": Delegation Abuse Scanner
    - "4": Dangerous ACL Permissions Scanner
.PARAMETER SkipHTML
    Skip HTML report generation. Results will still be collected but not exported.
.PARAMETER Force
    Skip prerequisite checks (NOT RECOMMENDED).
    Use this only if you understand the risks and know the environment is configured correctly.
.PARAMETER OutputPath
    Specify custom path for the HTML report. If not specified, saves to Reports folder with timestamp.
.EXAMPLE
    Invoke-ADSecurityScan
    Runs all modules and generates an HTML report in the Reports folder
.EXAMPLE
    Invoke-ADSecurityScan -Modules "1","2"
    Runs only Module 1 and Module 2
.EXAMPLE
    Invoke-ADSecurityScan -OutputPath "C:\Reports\MyReport.html"
    Runs all modules and saves report to specified path
.EXAMPLE
    Invoke-ADSecurityScan -SkipHTML
    Runs all modules but skips HTML report generation (returns results object)
.OUTPUTS
    Returns hashtable of results when -SkipHTML is used, otherwise generates HTML report
#>
function Invoke-ADSecurityScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "1", "2", "3", "4")]
        [string[]]$Modules = @("All"),

        [Parameter(Mandatory = $false)]
        [switch]$SkipHTML,

        [Parameter(Mandatory = $false)]
        [switch]$Force,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath
    )

    # Execute main.ps1 with parameters
    $mainScriptPath = Join-Path $script:ModuleRoot "main.ps1"

    if (-not (Test-Path $mainScriptPath)) {
        Write-Error "Main scanner script not found at: $mainScriptPath"
        return
    }

    try {
        # Build parameter hashtable
        $params = @{
            Modules = $Modules
            SkipHTML = $SkipHTML
            Force = $Force
        }

        # Execute the main script
        if ($SkipHTML) {
            # Return results object
            $results = & $mainScriptPath @params
            return $results
        }
        else {
            # Just run the script (it will handle HTML generation)
            & $mainScriptPath @params

            # If custom output path was specified, move the report
            if ($OutputPath) {
                $reportsDir = Join-Path $script:ModuleRoot "Reports"
                $latestReport = Get-ChildItem -Path $reportsDir -Filter "AD-Security-Report-*.html" |
                    Sort-Object LastWriteTime -Descending |
                    Select-Object -First 1

                if ($latestReport) {
                    Move-Item -Path $latestReport.FullName -Destination $OutputPath -Force
                    Write-Host "Report moved to: $OutputPath" -ForegroundColor Green
                }
            }
        }
    }
    catch {
        Write-Error "Failed to execute AD Security Scanner: $($_.Exception.Message)"
        throw
    }
}

#endregion

#region Module 1: Remediation Functions (Dangerous Accounts)

<#
.SYNOPSIS
    Fixes PasswordNeverExpires setting on accounts
.PARAMETER Accounts
    Array of account objects to fix
.DESCRIPTION
    Disables the PasswordNeverExpires flag, requiring accounts to follow password expiration policies.
.EXAMPLE
    $accounts = Get-ADUser -Filter {PasswordNeverExpires -eq $true}
    Set-PasswordNeverExpiresFix -Accounts $accounts
#>
function Set-PasswordNeverExpiresFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [ValidateCount(1, [int]::MaxValue)]
        [Object[]]$Accounts
    )

    $remediationScript = Join-Path $script:ModuleRoot "Modules\module1dangerousAccounts\remediationFix.ps1"
    if (Test-Path $remediationScript) {
        . $remediationScript
        Set-PasswordNeverExpiresFix -Accounts $Accounts
    }
    else {
        Write-Error "Remediation script not found at: $remediationScript"
    }
}

<#
.SYNOPSIS
    Fixes PasswordNotRequired setting on accounts
.PARAMETER Accounts
    Array of account objects to fix
.DESCRIPTION
    Disables the PasswordNotRequired flag, requiring accounts to have a password.
.EXAMPLE
    $accounts = Get-ADUser -Filter {PasswordNotRequired -eq $true}
    Set-PasswordNotRequiredFix -Accounts $accounts
#>
function Set-PasswordNotRequiredFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [ValidateCount(1, [int]::MaxValue)]
        [Object[]]$Accounts
    )

    $remediationScript = Join-Path $script:ModuleRoot "Modules\module1dangerousAccounts\remediationFix.ps1"
    if (Test-Path $remediationScript) {
        . $remediationScript
        Set-PasswordNotRequiredFix -Accounts $Accounts
    }
    else {
        Write-Error "Remediation script not found at: $remediationScript"
    }
}

<#
.SYNOPSIS
    Fixes CannotChangePassword setting on accounts
.PARAMETER Accounts
    Array of account objects to fix
.DESCRIPTION
    Disables the CannotChangePassword flag, allowing users to change their passwords.
.EXAMPLE
    $accounts = Get-ADUser -Filter * -Properties CannotChangePassword | Where-Object {$_.CannotChangePassword -eq $true}
    Set-CannotChangePasswordFix -Accounts $accounts
#>
function Set-CannotChangePasswordFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [ValidateCount(1, [int]::MaxValue)]
        [Object[]]$Accounts
    )

    $remediationScript = Join-Path $script:ModuleRoot "Modules\module1dangerousAccounts\remediationFix.ps1"
    if (Test-Path $remediationScript) {
        . $remediationScript
        Set-CannotChangePasswordFix -Accounts $Accounts
    }
    else {
        Write-Error "Remediation script not found at: $remediationScript"
    }
}

<#
.SYNOPSIS
    Permanently deletes disabled accounts
.PARAMETER Accounts
    Array of account objects to delete
.DESCRIPTION
    DESTRUCTIVE OPERATION: Permanently removes disabled accounts from Active Directory.
    Requires explicit confirmation from user before proceeding.
    WARNING: This cannot be undone!
.EXAMPLE
    $accounts = Get-ADUser -Filter {Enabled -eq $false}
    Remove-DisabledAccountsFix -Accounts $accounts
#>
function Remove-DisabledAccountsFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [ValidateCount(1, [int]::MaxValue)]
        [Object[]]$Accounts
    )

    $remediationScript = Join-Path $script:ModuleRoot "Modules\module1dangerousAccounts\remediationFix.ps1"
    if (Test-Path $remediationScript) {
        . $remediationScript
        Remove-DisabledAccountsFix -Accounts $Accounts
    }
    else {
        Write-Error "Remediation script not found at: $remediationScript"
    }
}

<#
.SYNOPSIS
    Clears adminCount attribute from orphaned administrative accounts
.PARAMETER Accounts
    Array of account objects to fix
.DESCRIPTION
    Removes the adminCount=1 attribute and restores ACL inheritance for accounts
    that are no longer in protected administrative groups.
    This removes the AdminSDHolder protection that persists after group removal.
.EXAMPLE
    $accounts = Get-ADUser -Filter {adminCount -eq 1 -and Enabled -eq $true} -Properties adminCount
    Clear-AdminCountFix -Accounts $accounts
#>
function Clear-AdminCountFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [ValidateCount(1, [int]::MaxValue)]
        [Object[]]$Accounts
    )

    $remediationScript = Join-Path $script:ModuleRoot "Modules\module1dangerousAccounts\remediationFix.ps1"
    if (Test-Path $remediationScript) {
        . $remediationScript
        Clear-AdminCountFix -Accounts $Accounts
    }
    else {
        Write-Error "Remediation script not found at: $remediationScript"
    }
}

#endregion

#region Module 2: Remediation Functions (Kerberos SPN)

<#
.SYNOPSIS
    Fixes weak RC4 encryption for Kerberos accounts
.PARAMETER Accounts
    Array of account objects to fix
.DESCRIPTION
    Disables RC4 encryption and enables AES256 encryption for Kerberos service accounts.
    This significantly improves security against Kerberoasting attacks.
.EXAMPLE
    $spnAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties msDS-SupportedEncryptionTypes
    Set-KerberosEncryptionFix -Accounts $spnAccounts
#>
function Set-KerberosEncryptionFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [ValidateCount(1, [int]::MaxValue)]
        [Object[]]$Accounts
    )

    $remediationScript = Join-Path $script:ModuleRoot "Modules\module2Kerberos\remediationFix.ps1"
    if (Test-Path $remediationScript) {
        . $remediationScript
        Set-KerberosEncryptionFix -Accounts $Accounts
    }
    else {
        Write-Error "Remediation script not found at: $remediationScript"
    }
}

<#
.SYNOPSIS
    Enables Kerberos Pre-Authentication on accounts
.PARAMETER Accounts
    Array of account objects to fix
.DESCRIPTION
    Enables Kerberos Pre-Authentication (removes DONT_REQ_PREAUTH flag).
    Protects against AS-REP Roasting attacks.
.EXAMPLE
    $accounts = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}
    Enable-KerberosPreAuthFix -Accounts $accounts
#>
function Enable-KerberosPreAuthFix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [ValidateCount(1, [int]::MaxValue)]
        [Object[]]$Accounts
    )

    $remediationScript = Join-Path $script:ModuleRoot "Modules\module2Kerberos\remediationFix.ps1"
    if (Test-Path $remediationScript) {
        . $remediationScript
        Enable-KerberosPreAuthFix -Accounts $Accounts
    }
    else {
        Write-Error "Remediation script not found at: $remediationScript"
    }
}

#endregion

#region Export Module Members

# Export main scanner function
Export-ModuleMember -Function Invoke-ADSecurityScan

# Export remediation functions
Export-ModuleMember -Function Set-PasswordNeverExpiresFix
Export-ModuleMember -Function Set-PasswordNotRequiredFix
Export-ModuleMember -Function Set-CannotChangePasswordFix
Export-ModuleMember -Function Remove-DisabledAccountsFix
Export-ModuleMember -Function Clear-AdminCountFix
Export-ModuleMember -Function Set-KerberosEncryptionFix
Export-ModuleMember -Function Enable-KerberosPreAuthFix

#endregion
