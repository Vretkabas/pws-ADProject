# ============================================
# Check Information Database
# ============================================
# hastable met alle informatie over de checks in module 1

$checkInfo = @{
    # Module 1: Dangerous Accounts
    "Password Never Expires" = @{
        RiskLevel = "High"
        RiskColor = "#dc3545"
        Description = "Accounts with passwords set to never expire are a significant security risk. If these passwords are compromised, they remain valid indefinitely, providing persistent access to attackers."
        Remediation = @"
1. Review each account and determine if password expiration is appropriate
2. For service accounts, consider using Managed Service Accounts (MSA) or Group Managed Service Accounts (gMSA)
3. For user accounts, enable password expiration policy
4. Document any exceptions with business justification
5. Implement regular password rotation schedule
"@
        References = ""
    }

    "Disabled Accounts (>30 days)" = @{
        RiskLevel = "Medium"
        RiskColor = "#ffc107"
        Description = "Accounts that have been disabled for an extended period should be reviewed and potentially removed. Stale disabled accounts can be re-enabled by attackers or may indicate poor account lifecycle management."
        Remediation = @"
1. Review each disabled account and determine the reason for disabling
2. If the account is no longer needed, delete it permanently
3. Document retention requirements for legal/compliance purposes
4. Move disabled accounts to a dedicated OU for easier management
5. Implement automated cleanup policies for disabled accounts after 90 days
"@
        References = ""
    }

    "Inactive Accounts (>60 days)" = @{
        RiskLevel = "Medium"
        RiskColor = "#ffc107"
        Description = "Accounts that haven't logged in for 60+ days may indicate terminated employees, abandoned accounts, or compromised credentials being held for later use. These accounts represent unnecessary attack surface."
        Remediation = @"
1. Contact account owners to verify if accounts are still needed
2. Disable inactive accounts after verification
3. Delete accounts after 90 days of being disabled
4. Implement automated monitoring for inactive accounts
5. Establish clear offboarding procedures for departing employees
"@
        References = ""
    }

    "Expired Accounts" = @{
        RiskLevel = "Low"
        RiskColor = "#28a745"
        Description = "These accounts have passed their expiration date. While they cannot be used for login, they should be reviewed and cleaned up to maintain a clean AD environment."
        Remediation = @"
1. Review expired accounts to confirm they are no longer needed
2. Delete accounts that are no longer required
3. Extend expiration for accounts that still need access
4. Verify that account expiration policies are properly configured
"@
        References = ""
    }

    "Locked Out Accounts" = @{
        RiskLevel = "Low"
        RiskColor = "#17a2b8"
        Description = "Locked accounts may indicate brute-force attacks, forgotten passwords, or automated systems with incorrect credentials. Monitor these for potential security incidents."
        Remediation = @"
1. Investigate the reason for each account lockout
2. Check for signs of brute-force attacks or credential stuffing
3. Verify with users if lockouts are legitimate (forgotten passwords)
4. Review service account configurations if automated systems are affected
5. Consider implementing account lockout policies and monitoring
"@
        References = ""
    }

    "Password Expired" = @{
        RiskLevel = "Low"
        RiskColor = "#28a745"
        Description = "Accounts with expired passwords cannot be used until the password is reset. However, a large number may indicate poor password management or inactive accounts."
        Remediation = @"
1. Contact users to reset their passwords
2. Investigate accounts that consistently have expired passwords
3. Consider if these accounts should be disabled or deleted
4. Ensure password expiration notifications are working correctly
"@
        References = ""
    }

    "Passwords in Description" = @{
        RiskLevel = "Critical"
        RiskColor = "#dc3545"
        Description = "CRITICAL: Storing passwords in the description field is a severe security violation. These passwords are visible to anyone with read access to AD and are often stored in plain text."
        Remediation = @"
1. IMMEDIATELY change all passwords found in descriptions
2. Clear the description field or replace with appropriate information
3. Educate users and administrators about secure password storage
4. Implement regular scans for this issue
5. Consider using a password manager for shared credentials
6. Investigate how these passwords were added and prevent recurrence
"@
        References = ""
    }

    "Password Not Required" = @{
        RiskLevel = "Critical"
        RiskColor = "#dc3545"
        Description = "CRITICAL: Accounts configured with 'Password Not Required' can be accessed without any password, providing an easy entry point for attackers."
        Remediation = @"
1. IMMEDIATELY disable the 'Password Not Required' flag
2. Set a strong password for each affected account
3. Investigate why this flag was set and by whom
4. Verify no unauthorized access occurred while the account was passwordless
5. Implement GPO to prevent this setting from being enabled
"@
        References = ""
    }

    "Cannot Change Password" = @{
        RiskLevel = "Medium"
        RiskColor = "#ffc107"
        Description = "Accounts with 'Cannot Change Password' set are typically service accounts or special-purpose accounts. Verify this is intentional and properly documented."
        Remediation = @"
1. Review each account to verify the business need
2. Ensure service accounts use this setting appropriately
3. Consider using Managed Service Accounts instead
4. Document all exceptions
5. Implement regular review process for these accounts
"@
        References = ""
    }

    "Old Passwords (>90 days)" = @{
        RiskLevel = "High"
        RiskColor = "#dc3545"
        Description = "Passwords that haven't been changed in over 90 days may be compromised without detection. Regular password rotation reduces the window of opportunity for attackers."
        Remediation = @"
1. Implement password expiration policies (60-90 days)
2. Force password reset for affected accounts
3. Educate users on creating strong, unique passwords
4. Consider implementing multi-factor authentication (MFA)
5. For service accounts, use Managed Service Accounts with automatic password rotation
"@
        References = ""
    }

    "Orphaned AdminCount" = @{
        RiskLevel = "High"
        RiskColor = "#dc3545"
        Description = "Accounts with AdminCount=1 but not in protected groups retain elevated permissions and protections without proper justification. This is often a result of temporary privilege escalation that wasn't properly cleaned up."
        Remediation = @"
1. Verify if the account still needs elevated permissions
2. If not needed, reset AdminCount to 0
3. Re-enable permission inheritance from parent containers
4. Remove any residual privileged group memberships
5. Implement process for tracking temporary privilege escalations
"@
        References = ""
    }

    "SID History" = @{
        RiskLevel = "Medium"
        RiskColor = "#ffc107"
        Description = "SID History is used during domain migrations but can be abused for privilege escalation. Accounts with SID History should be reviewed to ensure they are legitimate and still needed."
        Remediation = @"
1. Verify the SID History is legitimate (from a domain migration)
2. Check if the SID History is still needed
3. Remove SID History that is no longer required using the AD Users and Computers tool
4. Monitor for unauthorized SID History additions
5. Implement alerts for SID History changes
"@
        References = ""
    }
}

# Export de hashtable zodat andere scripts het kunnen gebruiken
return $checkInfo
