<#
.SYNOPSIS
    Module 3: Delegation Abuse Scanner

.DESCRIPTION
    Scans and reports delegation misconfigurations and security issues in Active Directory.
    Includes parameter validation and comprehensive error handling.

    Audited delegation types:
    - Unconstrained Delegation
    - Constrained Delegation (with/without Protocol Transition)
    - Resource-Based Constrained Delegation (RBCD)
    - Sensitive Accounts Not Protected
    - Admins Not in Protected Users Group
    - Dangerous SPN Delegation
    - Delegation to Domain Controllers
    - Pre-Windows 2000 Compatible Access
    - Service Account Delegation

.OUTPUTS
    Hashtable containing categorized delegation audit findings

.NOTES
    Delegation misconfigurations are common attack vectors in Active Directory.
    Findings should be reviewed carefully to identify legitimate configurations
    versus potential security risks.

#>

[CmdletBinding()]
param()

#region Import Functions

try {
    $delegationAuditPath = Join-Path $PSScriptRoot "delegationAudit.ps1"

    if (-not (Test-Path $delegationAuditPath)) {
        Write-Error "Delegation audit script not found at: $delegationAuditPath"
        return @{}
    }

    . $delegationAuditPath
    Write-Verbose "Delegation audit functions loaded successfully"
}
catch {
    Write-Error "Failed to load delegation audit functions: $($_.Exception.Message)"
    return @{}
}

#endregion

#region Display Header

try {
    Write-Host "`n=== Module 3: Delegation Abuse Scanner ===" -ForegroundColor Cyan
}
catch {
    Write-Warning "Failed to display module header: $($_.Exception.Message)"
}

#endregion

#region Execute Delegation Audit

try {
    # Call the main audit function with verbose output
    Write-Verbose "Invoking delegation audit..."
    $auditResults = Invoke-DelegationAudit -Verbose

    if (-not $auditResults -or $auditResults.Count -eq 0) {
        Write-Warning "Delegation audit returned no results"
        return @{}
    }

    Write-Verbose "Delegation audit completed successfully"
}
catch {
    Write-Error "Failed to execute delegation audit: $($_.Exception.Message)"
    return @{}
}

#endregion

#region Map and Categorize Results

try {
    # Organize results by category with severity levels
    $module3Results = @{
        # ============================================
        # 1. UNCONSTRAINED DELEGATION
        # ============================================
        "Unconstrained Delegation" = @{
            "Users (CRITICAL)" = $auditResults.UnconstrainedDelegation.Users
            "Computers (HIGH)" = $auditResults.UnconstrainedDelegation.Computers
            "Service Accounts (HIGH)" = $auditResults.UnconstrainedDelegation.ServiceAccounts
            "Domain Controllers (Informational)" = $auditResults.UnconstrainedDelegation.DomainControllers
        }

        # ============================================
        # 2. CONSTRAINED DELEGATION
        # ============================================
        "Constrained Delegation" = @{
            "Users - Kerberos Only (MEDIUM)" = $auditResults.ConstrainedDelegation.Users_KerberosOnly
            "Users - With Protocol Transition (HIGH)" = $auditResults.ConstrainedDelegation.Users_WithProtocolTransition
            "Computers - Kerberos Only (LOW)" = $auditResults.ConstrainedDelegation.Computers_KerberosOnly
            "Computers - With Protocol Transition (MEDIUM)" = $auditResults.ConstrainedDelegation.Computers_WithProtocolTransition
            "Service Accounts - Kerberos Only (LOW)" = $auditResults.ConstrainedDelegation.ServiceAccounts_KerberosOnly
            "Service Accounts - With Protocol Transition (MEDIUM)" = $auditResults.ConstrainedDelegation.ServiceAccounts_WithProtocolTransition
        }

        # ============================================
        # 3. RESOURCE-BASED CONSTRAINED DELEGATION (RBCD)
        # ============================================
        "Resource-Based Constrained Delegation (RBCD)" = @{
            "Target Computers (MEDIUM-CRITICAL)" = $auditResults.RBCD.TargetComputers
            "Target Users (CRITICAL)" = $auditResults.RBCD.TargetUsers
            "Target Service Accounts (MEDIUM)" = $auditResults.RBCD.TargetGMSA
        }

        # ============================================
        # 4. SENSITIVE ACCOUNTS NOT PROTECTED
        # ============================================
        "Sensitive Accounts Not Protected" = @{
            "Enabled Accounts (HIGH)" = $auditResults.SensitiveAccountsNotProtected.Enabled
            "Disabled Accounts (MEDIUM)" = $auditResults.SensitiveAccountsNotProtected.Disabled
        }

        # ============================================
        # 5. ADMINS NOT IN PROTECTED USERS
        # ============================================
        "Admins Not in Protected Users" = @{
            "Enabled Accounts (MEDIUM)" = $auditResults.AdminsNotInProtectedUsers.Enabled
            "Disabled Accounts (LOW)" = $auditResults.AdminsNotInProtectedUsers.Disabled
        }

        # ============================================
        # 6. DANGEROUS SPN DELEGATION
        # ============================================
        "Dangerous SPN Delegation" = @{
            "CRITICAL Services (ldap, krbtgt)" = $auditResults.DangerousSPNDelegation.Critical
            "HIGH Risk Services (cifs, host, wsman, mssql, gc)" = $auditResults.DangerousSPNDelegation.High
            "MEDIUM Risk Services (http, https)" = $auditResults.DangerousSPNDelegation.Medium
        }

        # ============================================
        # 7. DELEGATION TO DOMAIN CONTROLLERS
        # ============================================
        "Delegation to Domain Controllers" = @{
            "LDAP Delegation (CRITICAL - DCSync Risk)" = $auditResults.DelegationToDCs.LDAP
            "CIFS Delegation (CRITICAL)" = $auditResults.DelegationToDCs.CIFS
            "HOST Delegation (CRITICAL)" = $auditResults.DelegationToDCs.HOST
            "Other Services (HIGH)" = $auditResults.DelegationToDCs.Other
        }

        # ============================================
        # 8. PRE-WINDOWS 2000 COMPATIBLE ACCESS
        # ============================================
        "Pre-Windows 2000 Compatible Access" = @{
            "Dangerous Members (HIGH)" = $auditResults.PreWindows2000.Dangerous
            "Other Members (LOW)" = $auditResults.PreWindows2000.Other
        }

        # ============================================
        # 9. SERVICE ACCOUNT (gMSA) DELEGATION
        # ============================================
        "Service Account Delegation" = @{
            "Unconstrained Delegation (HIGH)" = $auditResults.ServiceAccountDelegation.Unconstrained
            "Protocol Transition (MEDIUM)" = $auditResults.ServiceAccountDelegation.ProtocolTransition
            "Constrained Only (LOW)" = $auditResults.ServiceAccountDelegation.Constrained
            "RBCD Target (MEDIUM)" = $auditResults.ServiceAccountDelegation.RBCD
        }
    }

    Write-Verbose "Results categorized successfully"
}
catch {
    Write-Error "Failed to categorize delegation audit results: $($_.Exception.Message)"
    return @{}
}

#endregion

#region Display Completion Message

try {
    Write-Host "Module 3 completed successfully." -ForegroundColor Green
}
catch {
    Write-Warning "Failed to display completion message: $($_.Exception.Message)"
}

#endregion

#region Return Results

try {
    return $module3Results
}
catch {
    Write-Error "Failed to return results: $($_.Exception.Message)"
    return @{}
}

#endregion
