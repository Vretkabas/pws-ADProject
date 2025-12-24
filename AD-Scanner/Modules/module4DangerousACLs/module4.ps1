# Module 4: Dangerous ACL Permissions Scanner
# Dit script verzamelt alle dangerous ACL configuraties op kritieke AD objecten
#
# BELANGRIJK: Dit zijn niet persé security issues, maar een overzicht van wie welke
# ACL rechten heeft op gevoelige objecten zoals AdminSDHolder, Domain Object,
# privileged groups, GPOs, privileged users en OUs. Review deze rechten om te
# bepalen of ze legitiem zijn of een security risk vormen.

# Import functies
. "$PSScriptRoot\aclAudit.ps1"

Write-Host "`n=== Module 4: Dangerous ACL Permissions Scanner ===" -ForegroundColor Cyan
Write-Host "Note: Dit toont een overzicht van ACL rechten op gevoelige objecten." -ForegroundColor Yellow
Write-Host "      Review elk resultaat om te bepalen of het legitiem of gevaarlijk is.`n" -ForegroundColor Yellow

# Roep de main audit functie aan
$auditResults = Invoke-ACLAudit

# map issues

$module4Results = @{
    # ADMINSDHOLDER
    "AdminSDHolder Permissions" = @{
        "Dangerous Permissions (CRITICAL)" = $auditResults.AdminSDHolder.All
    }

    # DOMAIN OBJECT
    "Domain Object Permissions" = @{
        "DCSync Rights (CRITICAL - Domain Takeover)" = $auditResults.DomainObject.DCSync
        "Other Dangerous Rights (HIGH)" = $auditResults.DomainObject.Other
    }

    # PRIVILEGED GROUPS
    "Privileged Group Permissions" = @{
        "Domain Admins Group (CRITICAL)" = $auditResults.PrivilegedGroups.DomainAdmins
        "Enterprise Admins Group (CRITICAL)" = $auditResults.PrivilegedGroups.EnterpriseAdmins
        "Other Privileged Groups (HIGH)" = $auditResults.PrivilegedGroups.Other
    }

    # GPO OBJECTS
    "GPO Permissions" = @{
        "Dangerous GPO Permissions (HIGH - Code Execution)" = $auditResults.GPOs.All
    }

    # PRIVILEGED USERS
    "Privileged User Permissions" = @{
        "Password Reset Rights (CRITICAL)" = $auditResults.PrivilegedUsers.PasswordReset
        "Other Dangerous Rights GPO(HIGH)" = $auditResults.PrivilegedUsers.Other
    }

    # ORGANIZATIONAL UNITS
    "Organizational Unit Permissions" = @{
        "Top-Level OU Permissions (MEDIUM-HIGH)" = $auditResults.OrganizationalUnits.All
    }
}

Write-Host "Module 4 completed." -ForegroundColor Green

# Return resultaten
return $module4Results
