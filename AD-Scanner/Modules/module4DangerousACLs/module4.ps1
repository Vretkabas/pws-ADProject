<#
.SYNOPSIS
    Module 4: Dangerous ACL Permissions Scanner

.DESCRIPTION
    Scans and reports dangerous ACL permissions on critical Active Directory objects.
    Includes parameter validation and comprehensive error handling.

    IMPORTANT: These findings are not necessarily security issues, but represent
    an overview of who has which ACL permissions on sensitive objects such as:
    - AdminSDHolder
    - Domain Object
    - Privileged Groups
    - GPOs
    - Privileged Users
    - Organizational Units

    Review each result to determine if the permissions are legitimate (e.g., delegated admin)
    or pose a security risk (e.g., regular user with excessive permissions).

.OUTPUTS
    Hashtable containing categorized ACL permission findings

.NOTES
    This module should be reviewed carefully as it audits critical security boundaries
    in Active Directory. Not all findings indicate compromise, but they warrant review.

#>

[CmdletBinding()]
param()

#region Import Functions

try {
    $aclAuditPath = Join-Path $PSScriptRoot "aclAudit.ps1"

    if (-not (Test-Path $aclAuditPath)) {
        Write-Error "ACL audit script not found at: $aclAuditPath"
        return @{}
    }

    . $aclAuditPath
    Write-Verbose "ACL audit functions loaded successfully"
}
catch {
    Write-Error "Failed to load ACL audit functions: $($_.Exception.Message)"
    return @{}
}

#endregion

#region Display Header

try {
    Write-Host "`n=== Module 4: Dangerous ACL Permissions Scanner ===" -ForegroundColor Cyan
    Write-Host "Note: This shows an overview of ACL permissions on sensitive objects." -ForegroundColor Yellow
    Write-Host "      Review each result to determine if it is legitimate or dangerous.`n" -ForegroundColor Yellow
}
catch {
    Write-Warning "Failed to display module header: $($_.Exception.Message)"
}

#endregion

#region Execute ACL Audit

try {
    # Call the main audit function
    Write-Verbose "Invoking ACL audit..."
    $auditResults = Invoke-ACLAudit

    if (-not $auditResults -or $auditResults.Count -eq 0) {
        Write-Warning "ACL audit returned no results"
        return @{}
    }

    Write-Verbose "ACL audit completed successfully"
}
catch {
    Write-Error "Failed to execute ACL audit: $($_.Exception.Message)"
    return @{}
}

#endregion

#region Map and Categorize Results

try {
    # Organize results by category with severity levels
    $module4Results = @{
        # AdminSDHolder - Critical security boundary
        "AdminSDHolder Permissions" = @{
            "Dangerous Permissions (CRITICAL)" = $auditResults.AdminSDHolder.All
        }

        # Domain Object - Highest privilege level
        "Domain Object Permissions" = @{
            "DCSync Rights (CRITICAL - Domain Takeover)" = $auditResults.DomainObject.DCSync
            "Other Dangerous Rights (HIGH)" = $auditResults.DomainObject.Other
        }

        # Privileged Groups - Control over admin membership
        "Privileged Group Permissions" = @{
            "Domain Admins Group (CRITICAL)" = $auditResults.PrivilegedGroups.DomainAdmins
            "Enterprise Admins Group (CRITICAL)" = $auditResults.PrivilegedGroups.EnterpriseAdmins
            "Other Privileged Groups (HIGH)" = $auditResults.PrivilegedGroups.Other
        }

        # GPO Objects - Potential for code execution and persistence
        "GPO Permissions" = @{
            "Dangerous GPO Permissions (HIGH - Code Execution)" = $auditResults.GPOs.All
        }

        # Privileged Users - Direct access to admin accounts
        "Privileged User Permissions" = @{
            "Password Reset Rights (CRITICAL)" = $auditResults.PrivilegedUsers.PasswordReset
            "Other Dangerous Rights (HIGH)" = $auditResults.PrivilegedUsers.Other
        }

        # Organizational Units - Affects all contained objects
        "Organizational Unit Permissions" = @{
            "Top-Level OU Permissions (MEDIUM-HIGH)" = $auditResults.OrganizationalUnits.All
        }
    }

    Write-Verbose "Results categorized successfully"
}
catch {
    Write-Error "Failed to categorize ACL audit results: $($_.Exception.Message)"
    return @{}
}

#endregion

#region Display Completion Message

try {
    Write-Host "Module 4 completed successfully." -ForegroundColor Green
}
catch {
    Write-Warning "Failed to display completion message: $($_.Exception.Message)"
}

#endregion

#region Return Results

try {
    return $module4Results
}
catch {
    Write-Error "Failed to return results: $($_.Exception.Message)"
    return @{}
}

#endregion
