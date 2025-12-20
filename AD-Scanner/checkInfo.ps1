# ============================================
# Check Information Database
# ============================================
# hastable met alle informatie over de checks in module 1

$checkInfo = @{
    # Module 1: Dangerous Settings
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

    # === Password Policy Checks ===
    "Minimum Password Length" = @{
        RiskLevel = "High"
        RiskColor = "#dc3545"
        Description = "Password policies with minimum password length below 12 characters are vulnerable to brute-force and dictionary attacks. Shorter passwords can be cracked exponentially faster."
        Remediation = @"
1. Set minimum password length to at least 12 characters (14+ recommended)
2. Update the Fine-Grained Password Policy or Default Domain Policy
3. Force password reset for all affected users
4. Educate users on creating strong passphrases
5. Consider implementing password complexity requirements alongside length
"@
        References = ""
    }

    "Maximum Password Age" = @{
        RiskLevel = "Medium"
        RiskColor = "#ffc107"
        Description = "Passwords that never expire (0 days) or expire too infrequently (>365 days) increase the risk window if credentials are compromised. However, overly frequent changes can lead to weaker password patterns."
        Remediation = @"
1. Set maximum password age between 60-365 days (90 days is common)
2. Balance security with usability (too frequent changes = weak patterns)
3. Consider implementing MFA as alternative to frequent password changes
4. For service accounts, use Managed Service Accounts instead
5. Update Fine-Grained Password Policy or Default Domain Policy
"@
        References = ""
    }

    "Minimum Password Age" = @{
        RiskLevel = "Low"
        RiskColor = "#ffc107"
        Description = "A minimum password age of 0 days allows users to change their password multiple times immediately to bypass password history requirements, effectively reusing old passwords."
        Remediation = @"
1. Set minimum password age to at least 1 day
2. This prevents rapid password cycling to bypass history
3. Update Fine-Grained Password Policy or Default Domain Policy
4. Ensure password history is also properly configured (12+ remembered passwords)
"@
        References = ""
    }

    "Password History" = @{
        RiskLevel = "Medium"
        RiskColor = "#ffc107"
        Description = "Password history below 12 allows users to quickly cycle back to previously used passwords, which may be compromised or weak. This defeats the purpose of password rotation."
        Remediation = @"
1. Set password history count to at least 12 (24 is recommended)
2. Combine with minimum password age to prevent rapid cycling
3. Update Fine-Grained Password Policy or Default Domain Policy
4. Consider implementing banned password lists for additional protection
"@
        References = ""
    }

    "Password Complexity" = @{
        RiskLevel = "High"
        RiskColor = "#dc3545"
        Description = "CRITICAL: Password complexity requirements are disabled. Without complexity, users can set simple passwords like 'password123' or 'companyname', making brute-force attacks trivial."
        Remediation = @"
1. IMMEDIATELY enable password complexity requirements
2. This enforces uppercase, lowercase, numbers, and special characters
3. Update Fine-Grained Password Policy or Default Domain Policy
4. Force password reset for all affected users with current simple passwords
5. Scan for common weak passwords and force changes
"@
        References = ""
    }

    "Account Lockout Threshold" = @{
        RiskLevel = "Medium"
        RiskColor = "#ffc107"
        Description = "Account lockout disabled (threshold = 0) allows unlimited password guessing attempts. Attackers can perform brute-force attacks without detection or interruption."
        Remediation = @"
1. Enable account lockout by setting threshold between 5-10 invalid attempts
2. Set lockout duration to at least 15 minutes
3. Configure lockout observation window appropriately
4. Update Fine-Grained Password Policy or Default Domain Policy
5. Implement monitoring for lockout events to detect attacks
"@
        References = ""
    }

    "Lockout Duration" = @{
        RiskLevel = "Low"
        RiskColor = "#ffc107"
        Description = "Lockout duration below 15 minutes may not provide sufficient deterrent against automated brute-force attacks. Very short durations allow attackers to resume quickly."
        Remediation = @"
1. Set lockout duration to at least 15 minutes
2. Consider 30-60 minutes for high-security environments
3. Balance security with user experience
4. Update Fine-Grained Password Policy or Default Domain Policy
5. Ensure helpdesk has procedures for legitimate lockouts
"@
        References = ""
    }

    "Reversible Encryption" = @{
        RiskLevel = "Critical"
        RiskColor = "#8B0000"
        Description = "CRITICAL VULNERABILITY: Reversible password encryption is enabled. This stores passwords in a format that can be decrypted back to plaintext, essentially defeating password hashing. If the AD database is compromised, ALL passwords can be recovered."
        Remediation = @"
1. IMMEDIATELY disable reversible encryption
2. Force password reset for ALL affected users (passwords are exposed)
3. Investigate why this was enabled and by whom
4. Audit for potential unauthorized access during exposure period
5. Update Fine-Grained Password Policy or Default Domain Policy
6. NEVER enable this setting unless absolutely required by legacy applications
"@
        References = ""
    }

    # ============================================
    # Module 2: Kerberos SPN Audit (Made with claude AI)
    # ============================================

    "Weak Encryption (DES or RC4 without AES)" = @{
        RiskLevel = "High"
        RiskColor = "#dc3545"
        Description = "Service accounts using weak Kerberos encryption (DES or RC4 without AES) are vulnerable to offline password cracking attacks. Attackers can capture Kerberos tickets and crack them to recover service account passwords."
        Remediation = @"
1. Enable AES256 or AES128 encryption for all service accounts
2. Use 'Set-ADUser' to configure msDS-SupportedEncryptionTypes attribute
3. Set value to 24 (AES128 + AES256) or 16 (AES256 only)
4. Test service functionality after encryption change
5. Disable DES and RC4-only configurations
"@
        References = ""
    }

    "DES Encryption (Critical)" = @{
        RiskLevel = "Critical"
        RiskColor = "#8B0000"
        Description = "CRITICAL: DES (Data Encryption Standard) is a deprecated and extremely weak encryption algorithm. Service accounts using DES can be cracked in seconds by modern tools and should be upgraded immediately."
        Remediation = @"
1. IMMEDIATELY disable DES encryption for all affected accounts
2. Enable AES256 encryption (msDS-SupportedEncryptionTypes = 16 or 24)
3. Force password reset for affected service accounts
4. Test all services using these accounts
5. Investigate if DES was required by legacy systems and upgrade those systems
"@
        References = ""
    }

    "RC4 Only (No AES)" = @{
        RiskLevel = "High"
        RiskColor = "#dc3545"
        Description = "Service accounts using only RC4 encryption without AES support are vulnerable to Kerberoasting attacks. RC4 is considered weak and can be cracked offline by attackers."
        Remediation = @"
1. Enable AES256 and/or AES128 encryption alongside RC4 for backward compatibility
2. Set msDS-SupportedEncryptionTypes to 28 (RC4 + AES128 + AES256)
3. Plan migration to AES-only (value 24) after ensuring compatibility
4. Update service account passwords to strong, random values
5. Monitor for Kerberoasting attempts in security logs
"@
        References = ""
    }

    "AES Only (Best Practice)" = @{
        RiskLevel = "Low"
        RiskColor = "#28a745"
        Description = "COMPLIANT: These service accounts use only AES encryption, which is the current best practice for Kerberos security. No action needed unless compatibility issues arise."
        Remediation = @"
No remediation required - this is the recommended configuration.
Continue monitoring these accounts and maintain strong password policies.
"@
        References = ""
    }

    "AES with RC4 (Acceptable)" = @{
        RiskLevel = "Low"
        RiskColor = "#ffc107"
        Description = "Service accounts support both AES and RC4 encryption. This is acceptable for backward compatibility but should eventually migrate to AES-only."
        Remediation = @"
1. Verify if RC4 is still needed for legacy application compatibility
2. Plan migration to AES-only configuration
3. Test applications to ensure they support AES
4. Remove RC4 support when legacy dependencies are resolved
5. Set msDS-SupportedEncryptionTypes to 24 (AES128 + AES256 only)
"@
        References = ""
    }

    "Password never expires on SPN accounts" = @{
        RiskLevel = "High"
        RiskColor = "#dc3545"
        Description = "Service accounts with passwords set to never expire pose a long-term security risk. If compromised, these credentials remain valid indefinitely."
        Remediation = @"
1. Migrate to Group Managed Service Accounts (gMSA) which auto-rotate passwords
2. If gMSA not possible, implement regular password rotation (90-365 days)
3. Use strong, random passwords (25+ characters)
4. Document business justification for any exceptions
5. Monitor these accounts for suspicious activity
"@
        References = ""
    }

    "Password not required on SPN accounts" = @{
        RiskLevel = "Critical"
        RiskColor = "#8B0000"
        Description = "CRITICAL: Service accounts with 'Password Not Required' flag can have blank passwords, allowing trivial unauthorized access."
        Remediation = @"
1. IMMEDIATELY set strong passwords for these accounts
2. Remove the 'Password Not Required' flag
3. Investigate how this configuration occurred
4. Audit for unauthorized access using these accounts
5. Migrate to Managed Service Accounts if possible
"@
        References = ""
    }

    "Cannot change password on SPN accounts" = @{
        RiskLevel = "Medium"
        RiskColor = "#ffc107"
        Description = "Service accounts configured to prevent password changes may indicate hardcoded credentials in applications or scripts, which is a security anti-pattern."
        Remediation = @"
1. Identify applications using these service accounts
2. Update applications to support password rotation
3. Remove 'Cannot Change Password' restriction
4. Implement password rotation schedule
5. Consider using Group Managed Service Accounts (gMSA)
"@
        References = ""
    }

    "Password expired on SPN accounts" = @{
        RiskLevel = "High"
        RiskColor = "#dc3545"
        Description = "Service accounts with expired passwords indicate service failures or authentication issues. This may cause application outages or force use of alternative (possibly less secure) credentials."
        Remediation = @"
1. Reset passwords for affected service accounts immediately
2. Update applications/services with new credentials
3. Implement Group Managed Service Accounts (gMSA) to prevent future expirations
4. Review password expiration policies for service accounts
5. Set up monitoring alerts for upcoming expirations
"@
        References = ""
    }

    "Disabled SPN accounts" = @{
        RiskLevel = "Medium"
        RiskColor = "#ffc107"
        Description = "Disabled service accounts with SPNs may indicate decommissioned services. These should be removed to maintain clean Active Directory hygiene."
        Remediation = @"
1. Verify the service account is no longer needed
2. Remove SPN registrations before deleting account
3. Delete the account if confirmed unnecessary
4. Document decommissioning for audit trail
5. Review regularly for cleanup opportunities
"@
        References = ""
    }

    "Locked out SPN accounts" = @{
        RiskLevel = "High"
        RiskColor = "#dc3545"
        Description = "Locked service accounts indicate failed authentication attempts, which may be signs of attack, misconfiguration, or service issues causing authentication failures."
        Remediation = @"
1. Unlock the account immediately if legitimate
2. Investigate lockout cause in security logs
3. Check for Kerberoasting or brute-force attempts
4. Verify service is using correct credentials
5. Reset password if compromise is suspected
"@
        References = ""
    }

    "Allow reversible password encryption on SPN accounts" = @{
        RiskLevel = "Critical"
        RiskColor = "#8B0000"
        Description = "CRITICAL: Reversible encryption on service accounts stores passwords in easily decryptable format. This defeats password security entirely."
        Remediation = @"
1. IMMEDIATELY disable reversible encryption
2. Force password reset for all affected accounts
3. Investigate why this was enabled
4. Audit for potential password exposure
5. Never enable unless absolutely required by legacy protocols (very rare)
"@
        References = ""
    }

    "Does not require pre-authentication on SPN accounts" = @{
        RiskLevel = "Critical"
        RiskColor = "#8B0000"
        Description = "CRITICAL: Service accounts not requiring Kerberos pre-authentication (DONT_REQ_PREAUTH) are vulnerable to AS-REP Roasting attacks where attackers can obtain crackable password hashes without valid credentials."
        Remediation = @"
1. IMMEDIATELY enable Kerberos pre-authentication
2. Verify no legitimate reason for this setting
3. Reset passwords for affected accounts
4. Monitor for AS-REP Roasting attempts
5. Audit security logs for suspicious TGT requests
"@
        References = ""
    }

    "Trusted for delegation SPN accounts" = @{
        RiskLevel = "High"
        RiskColor = "#dc3545"
        Description = "Unconstrained delegation allows service accounts to impersonate users to any service. If compromised, attackers can abuse this to escalate privileges across the domain."
        Remediation = @"
1. Review if unconstrained delegation is truly necessary
2. Migrate to constrained delegation where possible
3. Limit delegation to specific services only
4. Use Resource-Based Constrained Delegation (RBCD) for better control
5. Monitor these accounts closely for abuse
"@
        References = ""
    }

    "Trusted to authenticate for delegation SPN accounts" = @{
        RiskLevel = "Medium"
        RiskColor = "#ffc107"
        Description = "Constrained delegation allows service accounts to impersonate users to specific services. While more secure than unconstrained, it still requires careful management and monitoring."
        Remediation = @"
1. Verify delegation is limited to necessary services only
2. Regularly review delegation targets
3. Consider Resource-Based Constrained Delegation
4. Monitor for delegation abuse
5. Document business justification for delegation
"@
        References = ""
    }

    "Account not delegated SPN accounts" = @{
        RiskLevel = "Low"
        RiskColor = "#28a745"
        Description = "Service accounts marked 'Account is sensitive and cannot be delegated' are protected from delegation abuse. This is a security best practice for high-privilege accounts."
        Remediation = @"
This is a positive security finding. Continue applying this setting to sensitive accounts.
Consider enabling for all service accounts that don't require delegation.
"@
        References = ""
    }

    "SPN accounts with password age >90 days" = @{
        RiskLevel = "Medium"
        RiskColor = "#ffc107"
        Description = "Service account passwords older than 90 days increase risk of compromise through various attack vectors. Regular rotation limits exposure window."
        Remediation = @"
1. Implement Group Managed Service Accounts (gMSA) for automatic rotation
2. If gMSA not possible, establish password rotation schedule
3. Use strong, random passwords (25+ characters)
4. Set maximum password age policy (90-365 days depending on risk)
5. Document password changes and coordinate with service owners
"@
        References = ""
    }
}

# Export de hashtable zodat andere scripts het kunnen gebruiken
return $checkInfo
