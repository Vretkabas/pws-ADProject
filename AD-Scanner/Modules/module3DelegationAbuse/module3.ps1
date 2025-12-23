# Module 3: Delegation Abuse Scanner
# Dit script verzamelt alle delegation misconfiguraties en security issues

# Import functies
. "$PSScriptRoot\delegationAudit.ps1"

Write-Host "`n=== Module 3: Delegation Abuse Scanner ===" -ForegroundColor Cyan

# Roep de main audit functie aan
$auditResults = Invoke-DelegationAudit -Verbose

# map issues 

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

Write-Host "Module 3 completed." -ForegroundColor Green

# Return resultaten
return $module3Results
