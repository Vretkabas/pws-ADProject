# ============================================
# Check Information Database
# ============================================
# Hashtable met alle informatie over de checks
# Inclusief risk scoring (Severity × Exploitability × Exposure)
# Made with Claude AI

#region Risk Scoring Functions

<#
.SYNOPSIS
Calculates the overall risk score and determines risk level and color.

.DESCRIPTION
Risk Score Formula: (Severity × Exploitability × Exposure) / 10
- Severity (1-10): Impact if exploited
- Exploitability (1-10): Ease of exploitation
- Exposure (1-10): Likelihood of occurrence/visibility

Result: 0-100 score mapped to Risk Levels:
- 0-12.5: Low (Green)
- 12.6-34.3: Medium (Yellow)
- 34.4-72.9: High (Red)
- 73-100: Critical (Dark Red)

.EXAMPLE
Get-RiskInfo -severity 9 -exploitability 8 -exposure 7
Returns: @{ RiskScore=50.4; RiskLevel="High"; Color="#dc3545" }
#>
function Get-RiskInfo {
    param(
        [ValidateRange(1, 10)]
        [int]$severity,
        [ValidateRange(1, 10)]
        [int]$exploitability,
        [ValidateRange(1, 10)]
        [int]$exposure
    )

    # Calculate risk score on 0-100 scale
    $riskScore = ($severity * $exploitability * $exposure) / 10

    # Determine risk level based on score (0-100 scale)
    if ($riskScore -ge 70) {
        $riskLevel = "Critical"
        $color = "#8B0000"  # Dark Red
    }
    elseif ($riskScore -ge 35) {
        $riskLevel = "High"
        $color = "#dc3545"  # Red
    }
    elseif ($riskScore -ge 12) {
        $riskLevel = "Medium"
        $color = "#ffc107"  # Yellow/Orange
    }
    else {
        $riskLevel = "Low"
        $color = "#28a745"  # Green
    }

    # Return risk info
    return @{
        RiskLevel = $riskLevel
        Color     = $color
        Score     = $riskScore
    }
}

#endregion

# Build checkInfo hashtable with calculated risk scores
$checkInfo = @{}

# ============================================
# Module 1: Dangerous Accounts
# ============================================

# Password Never Expires
$riskInfo = Get-RiskInfo -severity 7 -exploitability 6 -exposure 8
$checkInfo["Password Never Expires"] = @{
    Severity       = 7
    Exploitability = 6
    Exposure       = 8
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Accounts with passwords set to never expire are a significant security risk. If these passwords are compromised, they remain valid indefinitely, providing persistent access to attackers."
    Remediation    = @"
1. Review each account and determine if password expiration is appropriate
2. For service accounts, consider using Managed Service Accounts (MSA) or Group Managed Service Accounts (gMSA)
3. For user accounts, enable password expiration policy
4. Document any exceptions with business justification
5. Implement regular password rotation schedule
"@
    References     = "https://attack.mitre.org/techniques/T1078/"
    MITRETechnique = "T1078 - Valid Accounts"
}

# Disabled Accounts (>30 days)
$riskInfo = Get-RiskInfo -severity 3 -exploitability 4 -exposure 6
$checkInfo["Disabled Accounts (>30 days)"] = @{
    Severity       = 3
    Exploitability = 4
    Exposure       = 6
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Accounts that have been disabled for an extended period should be reviewed and potentially removed. Stale disabled accounts can be re-enabled by attackers or may indicate poor account lifecycle management."
    Remediation    = @"
1. Review each disabled account and determine the reason for disabling
2. If the account is no longer needed, delete it permanently
3. Document retention requirements for legal/compliance purposes
4. Move disabled accounts to a dedicated OU for easier management
5. Implement automated cleanup policies for disabled accounts after 90 days
"@
    References     = ""
}

# Inactive Accounts (>60 days)
$riskInfo = Get-RiskInfo -severity 5 -exploitability 5 -exposure 7
$checkInfo["Inactive Accounts (>60 days)"] = @{
    Severity       = 5
    Exploitability = 5
    Exposure       = 7
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Accounts that haven't logged in for 60+ days may indicate terminated employees, abandoned accounts, or compromised credentials being held for later use. These accounts represent unnecessary attack surface."
    Remediation    = @"
1. Contact account owners to verify if accounts are still needed
2. Disable inactive accounts after verification
3. Delete accounts after 90 days of being disabled
4. Implement automated monitoring for inactive accounts
5. Establish clear offboarding procedures for departing employees
"@
    References     = ""
}

# Expired Accounts
$riskInfo = Get-RiskInfo -severity 2 -exploitability 2 -exposure 4
$checkInfo["Expired Accounts"] = @{
    Severity       = 2
    Exploitability = 2
    Exposure       = 4
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "These accounts have passed their expiration date. While they cannot be used for login, they should be reviewed and cleaned up to maintain a clean AD environment."
    Remediation    = @"
1. Review expired accounts to confirm they are no longer needed
2. Delete accounts that are no longer required
3. Extend expiration for accounts that still need access
4. Verify that account expiration policies are properly configured
"@
    References     = ""
}

# Locked Out Accounts
$riskInfo = Get-RiskInfo -severity 3 -exploitability 2 -exposure 4
$checkInfo["Locked Out Accounts"] = @{
    Severity       = 3
    Exploitability = 2
    Exposure       = 4
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Locked accounts may indicate brute-force attacks, forgotten passwords, or automated systems with incorrect credentials. Monitor these for potential security incidents."
    Remediation    = @"
1. Investigate the reason for each account lockout
2. Check for signs of brute-force attacks or credential stuffing
3. Verify with users if lockouts are legitimate (forgotten passwords)
4. Review service account configurations if automated systems are affected
5. Consider implementing account lockout policies and monitoring
"@
    References     = ""
}

# Password Expired
$riskInfo = Get-RiskInfo -severity 2 -exploitability 2 -exposure 5
$checkInfo["Password Expired"] = @{
    Severity       = 2
    Exploitability = 2
    Exposure       = 5
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Accounts with expired passwords cannot be used until the password is reset. However, a large number may indicate poor password management or inactive accounts."
    Remediation    = @"
1. Contact users to reset their passwords
2. Investigate accounts that consistently have expired passwords
3. Consider if these accounts should be disabled or deleted
4. Ensure password expiration notifications are working correctly
"@
    References     = ""
}

# Passwords in Description
$riskInfo = Get-RiskInfo -severity 10 -exploitability 10 -exposure 7
$checkInfo["Passwords in Description"] = @{
    Severity       = 10
    Exploitability = 10
    Exposure       = 2
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "CRITICAL: Storing passwords in the description field is a severe security violation. These passwords are visible to anyone with read access to AD and are often stored in plain text."
    Remediation    = @"
1. IMMEDIATELY change all passwords found in descriptions
2. Clear the description field or replace with appropriate information
3. Educate users and administrators about secure password storage
4. Implement regular scans for this issue
5. Consider using a password manager for shared credentials
6. Investigate how these passwords were added and prevent recurrence
"@
    References     = "https://attack.mitre.org/techniques/T1552/001/"
    MITRETechnique = "T1552.001 - Unsecured Credentials: Credentials In Files"
}

# Password Not Required
$riskInfo = Get-RiskInfo -severity 10 -exploitability 10 -exposure 5
$checkInfo["Password Not Required"] = @{
    Severity       = 10
    Exploitability = 10
    Exposure       = 3
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "CRITICAL: Accounts configured with 'Password Not Required' can be accessed without any password, providing an easy entry point for attackers."
    Remediation    = @"
1. IMMEDIATELY disable the 'Password Not Required' flag
2. Set a strong password for each affected account
3. Investigate why this flag was set and by whom
4. Verify no unauthorized access occurred while the account was passwordless
5. Implement GPO to prevent this setting from being enabled
"@
    References     = "https://attack.mitre.org/techniques/T1078/"
    MITRETechnique = "T1078 - Valid Accounts"
}

# Cannot Change Password
$riskInfo = Get-RiskInfo -severity 4 -exploitability 3 -exposure 5
$checkInfo["Cannot Change Password"] = @{
    Severity       = 4
    Exploitability = 3
    Exposure       = 5
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Accounts with 'Cannot Change Password' set are typically service accounts or special-purpose accounts. Verify this is intentional and properly documented."
    Remediation    = @"
1. Review each account to verify the business need
2. Ensure service accounts use this setting appropriately
3. Consider using Managed Service Accounts instead
4. Document all exceptions
5. Implement regular review process for these accounts
"@
    References     = ""
}

# Old Passwords (>90 days)
$riskInfo = Get-RiskInfo -severity 6 -exploitability 5 -exposure 7
$checkInfo["Old Passwords (>90 days)"] = @{
    Severity       = 6
    Exploitability = 5
    Exposure       = 7
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Passwords that haven't been changed in over 90 days may be compromised without detection. Regular password rotation reduces the window of opportunity for attackers."
    Remediation    = @"
1. Implement password expiration policies (60-90 days)
2. Force password reset for affected accounts
3. Educate users on creating strong, unique passwords
4. Consider implementing multi-factor authentication (MFA)
5. For service accounts, use Managed Service Accounts with automatic password rotation
"@
    References     = "https://attack.mitre.org/techniques/T1110/"
    MITRETechnique = "T1110 - Brute Force"
}

# Orphaned AdminCount
$riskInfo = Get-RiskInfo -severity 7 -exploitability 6 -exposure 4
$checkInfo["Orphaned AdminCount"] = @{
    Severity       = 7
    Exploitability = 6
    Exposure       = 4
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Accounts with AdminCount=1 but not in protected groups retain elevated permissions and protections without proper justification. This is often a result of temporary privilege escalation that wasn't properly cleaned up."
    Remediation    = @"
1. Verify if the account still needs elevated permissions
2. If not needed, reset AdminCount to 0
3. Re-enable permission inheritance from parent containers
4. Remove any residual privileged group memberships
5. Implement process for tracking temporary privilege escalations
"@
    References     = "https://adsecurity.org/?p=1906"
    MITRETechnique = "T1098 - Account Manipulation"
}

# SID History
$riskInfo = Get-RiskInfo -severity 6 -exploitability 7 -exposure 3
$checkInfo["SID History"] = @{
    Severity       = 6
    Exploitability = 7
    Exposure       = 3
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "SID History is used during domain migrations but can be abused for privilege escalation. Accounts with SID History should be reviewed to ensure they are legitimate and still needed."
    Remediation    = @"
1. Verify the SID History is legitimate (from a domain migration)
2. Check if the SID History is still needed
3. Remove SID History that is no longer required using the AD Users and Computers tool
4. Monitor for unauthorized SID History additions
5. Implement alerts for SID History changes
"@
    References     = "https://adsecurity.org/?p=1772"
    MITRETechnique = "T1134.005 - Access Token Manipulation: SID-History Injection"
}

# ============================================
# Module 1: Password Policy Checks
# ============================================

# Minimum Password Length
$riskInfo = Get-RiskInfo -severity 8 -exploitability 7 -exposure 6
$checkInfo["Minimum Password Length"] = @{
    Severity       = 8
    Exploitability = 7
    Exposure       = 6
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Password policies with minimum password length below 12 characters are vulnerable to brute-force and dictionary attacks. Shorter passwords can be cracked exponentially faster."
    Remediation    = @"
1. Set minimum password length to at least 12 characters (14+ recommended)
2. Update the Fine-Grained Password Policy or Default Domain Policy
3. Force password reset for all affected users
4. Educate users on creating strong passphrases
5. Consider implementing password complexity requirements alongside length
"@
    References     = "https://attack.mitre.org/techniques/T1110/"
    MITRETechnique = "T1110.002 - Brute Force: Password Cracking"
}

# Minimum Password Length (SPN)
$riskInfo = Get-RiskInfo -severity 9 -exploitability 9 -exposure 7
$checkInfo["Minimum Password Length (SPN)"] = @{
    Severity       = 9
    Exploitability = 9
    Exposure       = 7
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Service accounts (SPN accounts) require stronger password policies than regular user accounts. Passwords below 24 characters are vulnerable to Kerberoasting attacks where attackers can crack service account passwords offline."
    Remediation    = @"
1. Set minimum password length to at least 24 characters for service accounts (32+ recommended)
2. Update the Fine-Grained Password Policy for service accounts
3. Force password reset for all affected service accounts with strong, random passwords
4. Consider implementing Group Managed Service Accounts (gMSA) which use 120+ character auto-generated passwords
5. Use password generators to create strong, random passwords for manual service accounts
"@
    References     = "https://attack.mitre.org/techniques/T1558/003/"
    MITRETechnique = "T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting"
}

# Maximum Password Age
$riskInfo = Get-RiskInfo -severity 5 -exploitability 4 -exposure 7
$checkInfo["Maximum Password Age"] = @{
    Severity       = 5
    Exploitability = 4
    Exposure       = 7
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Passwords that never expire (0 days) or expire too infrequently (>90 days) increase the risk window if credentials are compromised."
    Remediation    = @"
1. Set maximum password age between 60-90 days (90 days is recommended)
2. Balance security with usability (too frequent changes = weak patterns)
3. Consider implementing MFA as alternative to frequent password changes
4. For service accounts, use Managed Service Accounts instead
5. Update Fine-Grained Password Policy or Default Domain Policy
"@
    References     = ""
}

# Maximum Password Age (SPN)
$riskInfo = Get-RiskInfo -severity 6 -exploitability 5 -exposure 6
$checkInfo["Maximum Password Age (SPN)"] = @{
    Severity       = 6
    Exploitability = 5
    Exposure       = 6
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Service accounts with passwords that expire too infrequently (>120 days) pose higher security risk. If compromised through Kerberoasting, the longer validity provides extended attack window."
    Remediation    = @"
1. Set maximum password age to 120 days for service accounts
2. Implement Group Managed Service Accounts (gMSA) which automatically rotate passwords every 30 days
3. For manual service accounts, establish documented password rotation schedule
4. Use strong, random passwords (24+ characters) to compensate for longer rotation periods
5. Update Fine-Grained Password Policy for service accounts
"@
    References     = ""
}

# Minimum Password Age
$riskInfo = Get-RiskInfo -severity 3 -exploitability 5 -exposure 5
$checkInfo["Minimum Password Age"] = @{
    Severity       = 3
    Exploitability = 5
    Exposure       = 5
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "A minimum password age of 0 days allows users to change their password multiple times immediately to bypass password history requirements."
    Remediation    = @"
1. Set minimum password age to at least 1 day
2. This prevents rapid password cycling to bypass history
3. Update Fine-Grained Password Policy or Default Domain Policy
4. Ensure password history is also properly configured (12+ remembered passwords)
"@
    References     = ""
}

# Password History
$riskInfo = Get-RiskInfo -severity 5 -exploitability 6 -exposure 6
$checkInfo["Password History"] = @{
    Severity       = 5
    Exploitability = 6
    Exposure       = 6
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Password history below 12 allows users to quickly cycle back to previously used passwords, which may be compromised or weak."
    Remediation    = @"
1. Set password history count to at least 12 (24 is recommended)
2. Combine with minimum password age to prevent rapid cycling
3. Update Fine-Grained Password Policy or Default Domain Policy
4. Consider implementing banned password lists for additional protection
"@
    References     = ""
}

# Password Complexity
$riskInfo = Get-RiskInfo -severity 8 -exploitability 8 -exposure 5
$checkInfo["Password Complexity"] = @{
    Severity       = 8
    Exploitability = 8
    Exposure       = 5
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "CRITICAL: Password complexity requirements are disabled. Without complexity, users can set simple passwords like 'password123', making brute-force attacks trivial."
    Remediation    = @"
1. IMMEDIATELY enable password complexity requirements
2. This enforces uppercase, lowercase, numbers, and special characters
3. Update Fine-Grained Password Policy or Default Domain Policy
4. Force password reset for all affected users with current simple passwords
5. Scan for common weak passwords and force changes
"@
    References     = "https://attack.mitre.org/techniques/T1110/"
    MITRETechnique = "T1110 - Brute Force"
}

# Account Lockout Threshold
$riskInfo = Get-RiskInfo -severity 6 -exploitability 7 -exposure 6
$checkInfo["Account Lockout Threshold"] = @{
    Severity       = 6
    Exploitability = 7
    Exposure       = 6
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Account lockout disabled (threshold = 0) allows unlimited password guessing attempts. Attackers can perform brute-force attacks without detection or interruption."
    Remediation    = @"
1. Enable account lockout by setting threshold between 5-10 invalid attempts
2. Set lockout duration to at least 15 minutes
3. Configure lockout observation window appropriately
4. Update Fine-Grained Password Policy or Default Domain Policy
5. Implement monitoring for lockout events to detect attacks
"@
    References     = "https://attack.mitre.org/techniques/T1110/"
}

# Lockout Duration
$riskInfo = Get-RiskInfo -severity 3 -exploitability 5 -exposure 5
$checkInfo["Lockout Duration"] = @{
    Severity       = 3
    Exploitability = 5
    Exposure       = 5
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Lockout duration below 15 minutes may not provide sufficient deterrent against automated brute-force attacks."
    Remediation    = @"
1. Set lockout duration to at least 15 minutes
2. Consider 30-60 minutes for high-security environments
3. Balance security with user experience
4. Update Fine-Grained Password Policy or Default Domain Policy
5. Ensure helpdesk has procedures for legitimate lockouts
"@
    References     = ""
}

# Reversible Encryption
$riskInfo = Get-RiskInfo -severity 10 -exploitability 10 -exposure 2
$checkInfo["Reversible Encryption"] = @{
    Severity       = 10
    Exploitability = 10
    Exposure       = 2
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "CRITICAL VULNERABILITY: Reversible password encryption is enabled. This stores passwords in a format that can be decrypted back to plaintext. If the AD database is compromised, ALL passwords can be recovered."
    Remediation    = @"
1. IMMEDIATELY disable reversible encryption
2. Force password reset for ALL affected users (passwords are exposed)
3. Investigate why this was enabled and by whom
4. Audit for potential unauthorized access during exposure period
5. Update Fine-Grained Password Policy or Default Domain Policy
6. NEVER enable this setting unless absolutely required by legacy applications
"@
    References     = "https://attack.mitre.org/techniques/T1552/001/"
    MITRETechnique = "T1552.001 - Unsecured Credentials"
}

# ============================================
# Module 2: Kerberos SPN Audit
# ============================================

# Weak Encryption (DES or RC4 without AES)
$riskInfo = Get-RiskInfo -severity 8 -exploitability 8 -exposure 7
$checkInfo["Weak Encryption (DES or RC4 without AES)"] = @{
    Severity       = 8
    Exploitability = 8
    Exposure       = 7
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Service accounts using weak Kerberos encryption (DES or RC4 without AES) are vulnerable to offline password cracking attacks (Kerberoasting)."
    Remediation    = @"
1. Enable AES256 or AES128 encryption for all service accounts
2. Use Set-ADUser to configure msDS-SupportedEncryptionTypes attribute
3. Set value to 24 (AES128 + AES256) or 16 (AES256 only)
4. Test service functionality after encryption change
5. Disable DES and RC4-only configurations
"@
    References     = "https://attack.mitre.org/techniques/T1558/003/"
    MITRETechnique = "T1558.003 - Kerberoasting"
}

# DES Encryption (Critical)
$riskInfo = Get-RiskInfo -severity 10 -exploitability 10 -exposure 3
$checkInfo["DES Encryption (Critical)"] = @{
    Severity       = 10
    Exploitability = 10
    Exposure       = 3
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "CRITICAL: DES (Data Encryption Standard) is deprecated and extremely weak. Service accounts using DES can be cracked in seconds by modern tools."
    Remediation    = @"
1. IMMEDIATELY disable DES encryption for all affected accounts
2. Enable AES256 encryption (msDS-SupportedEncryptionTypes = 16 or 24)
3. Force password reset for affected service accounts
4. Test all services using these accounts
5. Investigate if DES was required by legacy systems and upgrade those systems
"@
    References     = "https://attack.mitre.org/techniques/T1558/003/"
    MITRETechnique = "T1558.003 - Kerberoasting"
}

# RC4 Only (No AES)
$riskInfo = Get-RiskInfo -severity 7 -exploitability 8 -exposure 7
$checkInfo["RC4 Only (No AES)"] = @{
    Severity       = 7
    Exploitability = 8
    Exposure       = 7
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Service accounts using only RC4 encryption without AES support are vulnerable to Kerberoasting attacks. RC4 is considered weak and can be cracked offline."
    Remediation    = @"
1. Enable AES256 and/or AES128 encryption alongside RC4 for backward compatibility
2. Set msDS-SupportedEncryptionTypes to 28 (RC4 + AES128 + AES256)
3. Plan migration to AES-only (value 24) after ensuring compatibility
4. Update service account passwords to strong, random values
5. Monitor for Kerberoasting attempts in security logs
"@
    References     = "https://attack.mitre.org/techniques/T1558/003/"
    MITRETechnique = "T1558.003 - Kerberoasting"
}

# AES Only (Best Practice)
$riskInfo = Get-RiskInfo -severity 1 -exploitability 1 -exposure 1
$checkInfo["AES Only (Best Practice)"] = @{
    Severity       = 1
    Exploitability = 1
    Exposure       = 1
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "COMPLIANT: These service accounts use only AES encryption, which is the current best practice for Kerberos security. No action needed."
    Remediation    = @"
No remediation required - this is the recommended configuration.
Continue monitoring these accounts and maintain strong password policies.
"@
    References     = ""
}

# AES with RC4 (Acceptable)
$riskInfo = Get-RiskInfo -severity 2 -exploitability 3 -exposure 6
$checkInfo["AES with RC4 (Acceptable)"] = @{
    Severity       = 2
    Exploitability = 3
    Exposure       = 6
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Service accounts support both AES and RC4 encryption. This is acceptable for backward compatibility but should eventually migrate to AES-only."
    Remediation    = @"
1. Verify if RC4 is still needed for legacy application compatibility
2. Plan migration to AES-only configuration
3. Test applications to ensure they support AES
4. Remove RC4 support when legacy dependencies are resolved
5. Set msDS-SupportedEncryptionTypes to 24 (AES128 + AES256 only)
"@
    References     = ""
}

# Password never expires on SPN accounts
$riskInfo = Get-RiskInfo -severity 7 -exploitability 6 -exposure 8
$checkInfo["Password never expires on SPN accounts"] = @{
    Severity       = 7
    Exploitability = 6
    Exposure       = 8
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Service accounts with passwords set to never expire pose long-term security risk. If compromised via Kerberoasting, credentials remain valid indefinitely."
    Remediation    = @"
1. Migrate to Group Managed Service Accounts (gMSA) which auto-rotate passwords
2. If gMSA not possible, implement regular password rotation (90-365 days)
3. Use strong, random passwords (25+ characters)
4. Document business justification for any exceptions
5. Monitor these accounts for suspicious activity
"@
    References     = ""
}

# Password not required on SPN accounts
$riskInfo = Get-RiskInfo -severity 10 -exploitability 10 -exposure 7
$checkInfo["Password not required on SPN accounts"] = @{
    Severity       = 10
    Exploitability = 10
    Exposure       = 2
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "CRITICAL: Service accounts with 'Password Not Required' flag can have blank passwords, allowing trivial unauthorized access."
    Remediation    = @"
1. IMMEDIATELY set strong passwords for these accounts
2. Remove the 'Password Not Required' flag
3. Investigate how this configuration occurred
4. Audit for unauthorized access using these accounts
5. Migrate to Managed Service Accounts if possible
"@
    References     = "https://attack.mitre.org/techniques/T1078/"
    MITRETechnique = "T1078 - Valid Accounts"
}

# Cannot change password on SPN accounts
$riskInfo = Get-RiskInfo -severity 5 -exploitability 4 -exposure 6
$checkInfo["Cannot change password on SPN accounts"] = @{
    Severity       = 5
    Exploitability = 4
    Exposure       = 6
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Service accounts configured to prevent password changes may indicate hardcoded credentials in applications or scripts, which is a security anti-pattern."
    Remediation    = @"
1. Identify applications using these service accounts
2. Update applications to support password rotation
3. Remove 'Cannot Change Password' restriction
4. Implement password rotation schedule
5. Consider using Group Managed Service Accounts (gMSA)
"@
    References     = ""
}

# Password expired on SPN accounts
$riskInfo = Get-RiskInfo -severity 6 -exploitability 5 -exposure 4
$checkInfo["Password expired on SPN accounts"] = @{
    Severity       = 6
    Exploitability = 5
    Exposure       = 4
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Service accounts with expired passwords indicate service failures or authentication issues. This may cause application outages or force use of alternative credentials."
    Remediation    = @"
1. Reset passwords for affected service accounts immediately
2. Update applications/services with new credentials
3. Implement Group Managed Service Accounts (gMSA) to prevent future expirations
4. Review password expiration policies for service accounts
5. Set up monitoring alerts for upcoming expirations
"@
    References     = ""
}

# Disabled SPN accounts
$riskInfo = Get-RiskInfo -severity 3 -exploitability 4 -exposure 5
$checkInfo["Disabled SPN accounts"] = @{
    Severity       = 3
    Exploitability = 4
    Exposure       = 5
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Disabled service accounts with SPNs may indicate decommissioned services. These should be removed to maintain clean Active Directory hygiene."
    Remediation    = @"
1. Verify the service account is no longer needed
2. Remove SPN registrations before deleting account
3. Delete the account if confirmed unnecessary
4. Document decommissioning for audit trail
5. Review regularly for cleanup opportunities
"@
    References     = ""
}

# Locked out SPN accounts
$riskInfo = Get-RiskInfo -severity 6 -exploitability 7 -exposure 3
$checkInfo["Locked out SPN accounts"] = @{
    Severity       = 6
    Exploitability = 7
    Exposure       = 3
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Locked service accounts indicate failed authentication attempts, which may be signs of attack, misconfiguration, or service issues."
    Remediation    = @"
1. Unlock the account immediately if legitimate
2. Investigate lockout cause in security logs
3. Check for Kerberoasting or brute-force attempts
4. Verify service is using correct credentials
5. Reset password if compromise is suspected
"@
    References     = ""
}

# Allow reversible password encryption on SPN accounts
$riskInfo = Get-RiskInfo -severity 10 -exploitability 10 -exposure 1
$checkInfo["Allow reversible password encryption on SPN accounts"] = @{
    Severity       = 10
    Exploitability = 10
    Exposure       = 1
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "CRITICAL: Reversible encryption on service accounts stores passwords in easily decryptable format. This defeats password security entirely."
    Remediation    = @"
1. IMMEDIATELY disable reversible encryption
2. Force password reset for all affected accounts
3. Investigate why this was enabled
4. Audit for potential password exposure
5. Never enable unless absolutely required by legacy protocols (very rare)
"@
    References     = "https://attack.mitre.org/techniques/T1552/001/"
    MITRETechnique = "T1552.001 - Unsecured Credentials"
}

# Does not require pre-authentication on SPN accounts
$riskInfo = Get-RiskInfo -severity 9 -exploitability 10 -exposure 3
$checkInfo["Does not require pre-authentication on SPN accounts"] = @{
    Severity       = 9
    Exploitability = 10
    Exposure       = 3
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "CRITICAL: Service accounts not requiring Kerberos pre-authentication (DONT_REQ_PREAUTH) are vulnerable to AS-REP Roasting attacks where attackers can obtain crackable password hashes without valid credentials."
    Remediation    = @"
1. IMMEDIATELY enable Kerberos pre-authentication
2. Verify no legitimate reason for this setting
3. Reset passwords for affected accounts
4. Monitor for AS-REP Roasting attempts
5. Audit security logs for suspicious TGT requests
"@
    References     = "https://attack.mitre.org/techniques/T1558/004/"
    MITRETechnique = "T1558.004 - AS-REP Roasting"
}

# Trusted for delegation SPN accounts
$riskInfo = Get-RiskInfo -severity 8 -exploitability 7 -exposure 4
$checkInfo["Trusted for delegation SPN accounts"] = @{
    Severity       = 8
    Exploitability = 7
    Exposure       = 4
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Unconstrained delegation allows service accounts to impersonate users to any service. If compromised, attackers can abuse this to escalate privileges across the domain."
    Remediation    = @"
1. Review if unconstrained delegation is truly necessary
2. Migrate to constrained delegation where possible
3. Limit delegation to specific services only
4. Use Resource-Based Constrained Delegation (RBCD) for better control
5. Monitor these accounts closely for abuse
"@
    References     = "https://attack.mitre.org/techniques/T1134/002/"
    MITRETechnique = "T1134.002 - Kerberos Delegation"
}

# Trusted to authenticate for delegation SPN accounts
$riskInfo = Get-RiskInfo -severity 5 -exploitability 6 -exposure 5
$checkInfo["Trusted to authenticate for delegation SPN accounts"] = @{
    Severity       = 5
    Exploitability = 6
    Exposure       = 5
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Constrained delegation allows service accounts to impersonate users to specific services. While more secure than unconstrained, it still requires careful management."
    Remediation    = @"
1. Verify delegation is limited to necessary services only
2. Regularly review delegation targets
3. Consider Resource-Based Constrained Delegation
4. Monitor for delegation abuse
5. Document business justification for delegation
"@
    References     = ""
}

# Account not delegated SPN accounts
$riskInfo = Get-RiskInfo -severity 1 -exploitability 1 -exposure 1
$checkInfo["Account not delegated SPN accounts"] = @{
    Severity       = 1
    Exploitability = 1
    Exposure       = 1
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Service accounts marked 'Account is sensitive and cannot be delegated' are protected from delegation abuse. This is a security best practice."
    Remediation    = @"
This is a positive security finding. Continue applying this setting to sensitive accounts.
Consider enabling for all service accounts that don't require delegation.
"@
    References     = ""
}

# SPN accounts with password age >90 days
$riskInfo = Get-RiskInfo -severity 5 -exploitability 5 -exposure 7
$checkInfo["SPN accounts with password age >90 days"] = @{
    Severity       = 5
    Exploitability = 5
    Exposure       = 7
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Service account passwords older than 90 days increase risk of compromise through various attack vectors. Regular rotation limits exposure window."
    Remediation    = @"
1. Implement Group Managed Service Accounts (gMSA) for automatic rotation
2. If gMSA not possible, establish password rotation schedule
3. Use strong, random passwords (25+ characters)
4. Set maximum password age policy (90-365 days depending on risk)
5. Document password changes and coordinate with service owners
"@
    References     = ""
}

# ============================================
# Module 3: Delegation Abuse Scanner
# ============================================

# Section 1: Unconstrained Delegation
$riskInfo = Get-RiskInfo -severity 10 -exploitability 8 -exposure 2
$checkInfo["Users (CRITICAL)"] = @{
    Severity       = 10
    Exploitability = 8
    Exposure       = 2
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "CRITICAL: User accounts with unconstrained delegation can cache TGTs from any service and impersonate any user, including Domain Admins. This is extremely dangerous and almost never needed for user accounts."
    Remediation    = @"
1. IMMEDIATELY remove unconstrained delegation from these user accounts
2. Investigate why this was configured - this is highly unusual
3. Audit security logs for potential abuse of these accounts
4. If delegation is needed, use constrained delegation instead
5. Reset passwords for affected accounts
6. Monitor these accounts for suspicious activity
"@
    References     = "https://adsecurity.org/?p=1667"
    MITRETechnique = "T1134.002 - Access Token Manipulation: Create Process with Token"
}

$riskInfo = Get-RiskInfo -severity 8 -exploitability 7 -exposure 4
$checkInfo["Computers (HIGH)"] = @{
    Severity       = 8
    Exploitability = 7
    Exposure       = 4
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Computer accounts (non-DC) with unconstrained delegation can cache TGTs and impersonate users. If compromised, attackers can extract cached credentials and escalate privileges."
    Remediation    = @"
1. Review each computer to verify if unconstrained delegation is truly necessary
2. Migrate to constrained delegation where possible
3. Limit delegation to specific services only (Resource-Based Constrained Delegation)
4. Isolate these computers in a separate OU with strict access controls
5. Enable enhanced monitoring and logging for these systems
"@
    References     = "https://adsecurity.org/?p=1667"
    MITRETechnique = "T1134.002 - Kerberos Delegation"
}

$riskInfo = Get-RiskInfo -severity 8 -exploitability 7 -exposure 3
$checkInfo["Service Accounts (HIGH)"] = @{
    Severity       = 8
    Exploitability = 7
    Exposure       = 3
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Service accounts (gMSA) with unconstrained delegation pose significant risk. If the service is compromised, attackers can harvest TGTs and impersonate any user."
    Remediation    = @"
1. Remove unconstrained delegation from gMSA accounts
2. Use constrained delegation limited to specific SPNs
3. Implement Resource-Based Constrained Delegation (RBCD) for better control
4. Ensure service accounts use strong, random passwords (120+ chars for gMSA)
5. Monitor these accounts for unusual authentication patterns
"@
    References     = "https://adsecurity.org/?p=1667"
}

$riskInfo = Get-RiskInfo -severity 1 -exploitability 1 -exposure 10
$checkInfo["Domain Controllers (Informational)"] = @{
    Severity       = 1
    Exploitability = 1
    Exposure       = 10
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Domain Controllers have unconstrained delegation by design - this is expected and necessary for DC functionality. No action needed unless you find non-DC servers in this category."
    Remediation    = @"
This is expected configuration for Domain Controllers.
Verify that only legitimate DCs appear in this list.
If non-DC computers appear here, investigate immediately.
"@
    References     = ""
}

# Section 2: Constrained Delegation
$riskInfo = Get-RiskInfo -severity 6 -exploitability 5 -exposure 3
$checkInfo["Users - Kerberos Only (MEDIUM)"] = @{
    Severity       = 6
    Exploitability = 5
    Exposure       = 3
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "User accounts with constrained delegation (Kerberos-only) can delegate to specific services but require a valid TGT. Review if users actually need delegation."
    Remediation    = @"
1. Review why user accounts have delegation configured
2. Verify the delegated services are necessary and minimal
3. Consider using dedicated service accounts (gMSA) instead
4. Remove delegation if not actively used
5. Document business justification for any remaining user delegation
"@
    References     = "https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"
}

$riskInfo = Get-RiskInfo -severity 8 -exploitability 7 -exposure 2
$checkInfo["Users - With Protocol Transition (HIGH)"] = @{
    Severity       = 8
    Exploitability = 7
    Exposure       = 2
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "User accounts with Protocol Transition (S4U2Self) can obtain service tickets on behalf of ANY user without their TGT. This is extremely powerful and rarely justified for user accounts."
    Remediation    = @"
1. Review and remove Protocol Transition unless absolutely necessary
2. This setting allows S4U2Self - the account can request tickets for any user
3. Migrate to dedicated service accounts (gMSA) if delegation is needed
4. Disable Protocol Transition if only Kerberos-to-Kerberos delegation is required
5. Monitor these accounts for abuse
"@
    References     = "https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"
}

$riskInfo = Get-RiskInfo -severity 3 -exploitability 4 -exposure 6
$checkInfo["Computers - Kerberos Only (LOW)"] = @{
    Severity       = 3
    Exploitability = 4
    Exposure       = 6
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Computer accounts with constrained delegation (Kerberos-only) to specific services. This is acceptable if properly scoped to necessary services only."
    Remediation    = @"
1. Review delegated services to ensure they follow least privilege
2. Verify delegation is still needed for the application
3. Remove any unnecessary delegations
4. Document the business purpose for each delegation
5. Consider Resource-Based Constrained Delegation for better control
"@
    References     = ""
}

$riskInfo = Get-RiskInfo -severity 5 -exploitability 6 -exposure 5
$checkInfo["Computers - With Protocol Transition (MEDIUM)"] = @{
    Severity       = 5
    Exploitability = 6
    Exposure       = 5
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Computer accounts with Protocol Transition can authenticate on behalf of users without their credentials. Common for web servers doing front-end authentication, but should be carefully reviewed."
    Remediation    = @"
1. Verify Protocol Transition (S4U2Self) is actually needed
2. Confirm the application requires user impersonation
3. Limit delegated services to minimum necessary
4. Disable Protocol Transition if only Kerberos-to-Kerberos is needed
5. Monitor for delegation abuse
"@
    References     = ""
}

$riskInfo = Get-RiskInfo -severity 3 -exploitability 4 -exposure 5
$checkInfo["Service Accounts - Kerberos Only (LOW)"] = @{
    Severity       = 3
    Exploitability = 4
    Exposure       = 5
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Service accounts (gMSA) with constrained delegation (Kerberos-only) is the recommended approach when delegation is required. Verify scope is limited to necessary services."
    Remediation    = @"
1. Review delegated services list for each account
2. Apply principle of least privilege
3. Remove any unnecessary delegations
4. Document business justification
5. Regularly audit delegation configurations
"@
    References     = ""
}

$riskInfo = Get-RiskInfo -severity 5 -exploitability 5 -exposure 5
$checkInfo["Service Accounts - With Protocol Transition (MEDIUM)"] = @{
    Severity       = 5
    Exploitability = 5
    Exposure       = 5
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Service accounts with Protocol Transition can obtain tickets on behalf of users. While sometimes necessary for web applications, this should be carefully controlled."
    Remediation    = @"
1. Verify Protocol Transition is required for the application
2. Review and minimize delegated services
3. Consider if Resource-Based Constrained Delegation is a better fit
4. Disable Protocol Transition if not strictly needed
5. Monitor for suspicious delegation usage
"@
    References     = ""
}

# Section 3: Resource-Based Constrained Delegation
$riskInfo = Get-RiskInfo -severity 7 -exploitability 7 -exposure 4
$checkInfo["Target Computers (MEDIUM-CRITICAL)"] = @{
    Severity       = 7
    Exploitability = 7
    Exposure       = 4
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Computers configured as RBCD targets allow specified principals to delegate to them. Risk level depends on WHO is allowed to delegate (check AllowedToActOnBehalf)."
    Remediation    = @"
1. Review 'AllowedToActOnBehalf' principals - ensure they are specific accounts
2. Remove overly broad permissions (Everyone, Authenticated Users, Domain Computers)
3. Limit RBCD to specific computer/service accounts
4. Verify the business need for RBCD configuration
5. Use RBCD instead of traditional delegation where possible for better control
"@
    References     = "https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html"
}

$riskInfo = Get-RiskInfo -severity 10 -exploitability 8 -exposure 1
$checkInfo["Target Users (CRITICAL)"] = @{
    Severity       = 10
    Exploitability = 8
    Exposure       = 1
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "CRITICAL: User accounts as RBCD targets is extremely unusual and likely indicates misconfiguration or attack. RBCD should typically only be configured on computer/service accounts."
    Remediation    = @"
1. IMMEDIATELY investigate why user accounts have RBCD configured
2. Review who is allowed to delegate to these users
3. Remove RBCD configuration from user accounts
4. Audit for potential security incidents or privilege escalation
5. This may indicate an active attack - engage security team
"@
    References     = "https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html"
}

$riskInfo = Get-RiskInfo -severity 5 -exploitability 6 -exposure 4
$checkInfo["Target Service Accounts (MEDIUM)"] = @{
    Severity       = 5
    Exploitability = 6
    Exposure       = 4
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Service accounts (gMSA) configured as RBCD targets. Review the principals allowed to delegate and ensure they are appropriate and limited."
    Remediation    = @"
1. Verify the RBCD configuration is intentional
2. Review AllowedToActOnBehalf principals for least privilege
3. Ensure only necessary accounts can delegate
4. Document the business justification
5. Regularly audit RBCD configurations
"@
    References     = ""
}

# Section 4: Sensitive Accounts Not Protected
$riskInfo = Get-RiskInfo -severity 8 -exploitability 7 -exposure 5
$checkInfo["Enabled Accounts (HIGH)"] = @{
    Severity       = 8
    Exploitability = 7
    Exposure       = 5
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Privileged accounts (Domain Admins, Enterprise Admins, etc.) without the 'Account is sensitive and cannot be delegated' flag can be abused via delegation attacks."
    Remediation    = @"
1. IMMEDIATELY enable 'Account is sensitive and cannot be delegated' flag
2. Set AccountNotDelegated attribute to True for all privileged accounts
3. Use PowerShell: Set-ADUser <user> -AccountNotDelegated `$true
4. Verify setting is applied: Get-ADUser <user> -Properties AccountNotDelegated
5. Add to Protected Users group for additional Kerberos hardening
"@
    References     = "https://adsecurity.org/?p=3377"
}

$riskInfo = Get-RiskInfo -severity 4 -exploitability 5 -exposure 3
$checkInfo["Disabled Accounts (MEDIUM)"] = @{
    Severity       = 4
    Exploitability = 5
    Exposure       = 3
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Disabled privileged accounts without delegation protection. While lower risk due to being disabled, these should still be fixed to prevent accidental re-enabling without protection."
    Remediation    = @"
1. Enable 'Account is sensitive and cannot be delegated' flag
2. Set AccountNotDelegated attribute to True
3. Review if these disabled accounts should be deleted
4. Document retention requirements
5. Move to disabled accounts OU for better management
"@
    References     = ""
}

# Section 5: Admins Not in Protected Users
$riskInfo = Get-RiskInfo -severity 6 -exploitability 5 -exposure 6
$checkInfo["Enabled Accounts (MEDIUM)"] = @{
    Severity       = 6
    Exploitability = 5
    Exposure       = 6
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Domain/Enterprise/Schema Admins not in Protected Users group miss critical Kerberos protections: no NTLM, no delegation, no DES/RC4, 4-hour TGT lifetime."
    Remediation    = @"
1. Add privileged accounts to 'Protected Users' group
2. Test application compatibility first (breaks NTLM and delegation)
3. Use PowerShell: Add-ADGroupMember -Identity 'Protected Users' -Members <user>
4. NOTE: Do NOT add service accounts to Protected Users (breaks services)
5. Requires Windows Server 2012 R2 domain functional level minimum
"@
    References     = "https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group"
}

$riskInfo = Get-RiskInfo -severity 2 -exploitability 3 -exposure 3
$checkInfo["Disabled Accounts (LOW)"] = @{
    Severity       = 2
    Exploitability = 3
    Exposure       = 3
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Disabled admin accounts not in Protected Users. Lower priority since accounts are disabled, but should still be added if accounts may be re-enabled."
    Remediation    = @"
1. Add to Protected Users group if accounts may be re-enabled
2. Consider deleting accounts that are permanently disabled
3. Document retention requirements for compliance
4. Move to disabled accounts OU
"@
    References     = ""
}

# Section 6: Dangerous SPN Delegation
$riskInfo = Get-RiskInfo -severity 10 -exploitability 9 -exposure 2
$checkInfo["CRITICAL Services (ldap, krbtgt)"] = @{
    Severity       = 10
    Exploitability = 9
    Exposure       = 2
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "CRITICAL: Delegation to LDAP services enables DCSync attacks (replicating AD passwords). Delegation to krbtgt could enable Golden Ticket attacks. These should NEVER be delegated to."
    Remediation    = @"
1. IMMEDIATELY remove delegation to ldap/* and krbtgt/* SPNs
2. Investigate why this was configured - likely misconfiguration or attack
3. Audit for DCSync attacks in security logs (Event ID 4662)
4. Engage security team - this may indicate active compromise
5. Reset passwords for affected service accounts
"@
    References     = "https://adsecurity.org/?p=1729"
    MITRETechnique = "T1003.006 - DCSync"
}

$riskInfo = Get-RiskInfo -severity 8 -exploitability 7 -exposure 3
$checkInfo["HIGH Risk Services (cifs, host, wsman, mssql, gc)"] = @{
    Severity       = 8
    Exploitability = 7
    Exposure       = 3
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Delegation to high-value services: CIFS (file shares), HOST (full server access), WSMAN (PowerShell remoting), MSSQL (databases), GC (Global Catalog). These enable significant lateral movement."
    Remediation    = @"
1. Review each delegation and verify business necessity
2. Replace 'host/*' with specific service SPNs (more restrictive)
3. Limit CIFS delegation to specific servers only
4. Remove WSMAN delegation unless required for management tools
5. Scope MSSQL delegation to specific database servers only
6. Document all remaining delegations with justification
"@
    References     = ""
}

$riskInfo = Get-RiskInfo -severity 5 -exploitability 6 -exposure 6
$checkInfo["MEDIUM Risk Services (http, https)"] = @{
    Severity       = 5
    Exploitability = 6
    Exposure       = 6
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Delegation to HTTP/HTTPS services. Common for web applications requiring backend authentication, but should be scoped to specific servers."
    Remediation    = @"
1. Verify delegation is needed for web application functionality
2. Replace http/* with specific server FQDNs (http/webapp.domain.com)
3. Use Resource-Based Constrained Delegation for better control
4. Remove wildcard delegations
5. Document web applications requiring delegation
"@
    References     = ""
}

# Section 7: Delegation to Domain Controllers
$riskInfo = Get-RiskInfo -severity 10 -exploitability 9 -exposure 1
$checkInfo["LDAP Delegation (CRITICAL - DCSync Risk)"] = @{
    Severity       = 10
    Exploitability = 9
    Exposure       = 1
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "CRITICAL: Delegation to LDAP on Domain Controllers enables DCSync attacks - attackers can replicate all domain passwords including KRBTGT. This is a path to full domain compromise."
    Remediation    = @"
1. IMMEDIATELY remove all delegation to ldap/DC* SPNs
2. Investigate how this was configured - likely attack or serious misconfiguration
3. Audit for DCSync attempts (Event ID 4662 with GUID 1131f6ad-* or 1131f6aa-*)
4. Reset KRBTGT password twice (with 10-hour wait between)
5. Engage security team and consider incident response procedures
"@
    References     = "https://adsecurity.org/?p=1729"
    MITRETechnique = "T1003.006 - DCSync"
}

$riskInfo = Get-RiskInfo -severity 9 -exploitability 8 -exposure 1
$checkInfo["CIFS Delegation (CRITICAL)"] = @{
    Severity       = 9
    Exploitability = 8
    Exposure       = 1
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "CRITICAL: Delegation to CIFS on Domain Controllers provides access to SYSVOL, NETLOGON, and potentially NTDS.dit backups. This can lead to domain compromise."
    Remediation    = @"
1. IMMEDIATELY remove delegation to cifs/DC* SPNs
2. Verify no unauthorized access to SYSVOL or DC file shares
3. Review DC file share access logs
4. Investigate why this was configured
5. Reset service account passwords
"@
    References     = ""
}

$riskInfo = Get-RiskInfo -severity 10 -exploitability 8 -exposure 1
$checkInfo["HOST Delegation (CRITICAL)"] = @{
    Severity       = 10
    Exploitability = 8
    Exposure       = 1
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "CRITICAL: Delegation to HOST service on DCs grants broad access to multiple services. Combined with DC privileges, this can enable complete domain takeover."
    Remediation    = @"
1. IMMEDIATELY remove delegation to host/DC* SPNs
2. HOST SPN covers multiple services - very dangerous on DCs
3. Audit DC security logs for suspicious activity
4. Investigate configuration source
5. Engage security team for incident assessment
"@
    References     = ""
}

$riskInfo = Get-RiskInfo -severity 7 -exploitability 7 -exposure 2
$checkInfo["Other Services (HIGH)"] = @{
    Severity       = 7
    Exploitability = 7
    Exposure       = 2
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Delegation to other services on Domain Controllers. Any delegation to DCs should be carefully reviewed - DCs should rarely be delegation targets."
    Remediation    = @"
1. Review and remove delegation to any DC services
2. Verify business justification for ANY delegation to DCs
3. Consider alternative architectures that don't require DC delegation
4. Document exceptions with security review
5. Monitor DCs for suspicious delegation usage
"@
    References     = ""
}

# Section 8: Pre-Windows 2000 Compatible Access
$riskInfo = Get-RiskInfo -severity 7 -exploitability 8 -exposure 4
$checkInfo["Dangerous Members (HIGH)"] = @{
    Severity       = 7
    Exploitability = 8
    Exposure       = 4
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Pre-Windows 2000 Compatible Access group contains dangerous members (Anonymous, Everyone, or Authenticated Users). This allows anonymous or broad enumeration of AD objects."
    Remediation    = @"
1. IMMEDIATELY remove Anonymous Logon (S-1-5-7) from the group
2. Remove Everyone (S-1-1-0) from the group
3. Remove Authenticated Users (S-1-5-11) unless required for legacy systems
4. Test legacy application compatibility after removal
5. This group should typically be empty in modern environments
"@
    References     = "https://adsecurity.org/?p=3658"
}

$riskInfo = Get-RiskInfo -severity 2 -exploitability 3 -exposure 4
$checkInfo["Other Members (LOW)"] = @{
    Severity       = 2
    Exploitability = 3
    Exposure       = 4
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Pre-Windows 2000 Compatible Access group contains specific user/computer accounts. Review if these are still needed for legacy application compatibility."
    Remediation    = @"
1. Review each member and verify it's required
2. Contact application owners to confirm need
3. Remove members that are no longer necessary
4. Document any remaining members with business justification
5. Work to eliminate need for this group (legacy compatibility)
"@
    References     = ""
}

# Section 9: Service Account Delegation
$riskInfo = Get-RiskInfo -severity 8 -exploitability 7 -exposure 3
$checkInfo["Unconstrained Delegation (HIGH)"] = @{
    Severity       = 8
    Exploitability = 7
    Exposure       = 3
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Service accounts (gMSA) with unconstrained delegation can cache TGTs and impersonate any user. This should be migrated to constrained delegation."
    Remediation    = @"
1. Remove unconstrained delegation from gMSA accounts
2. Migrate to constrained delegation with specific SPN targets
3. Use Resource-Based Constrained Delegation for better control
4. Test application functionality after migration
5. Monitor for delegation abuse
"@
    References     = ""
}

$riskInfo = Get-RiskInfo -severity 5 -exploitability 6 -exposure 4
$checkInfo["Protocol Transition (MEDIUM)"] = @{
    Severity       = 5
    Exploitability = 6
    Exposure       = 4
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Service accounts with Protocol Transition (S4U2Self) can obtain tickets on behalf of users. Review if this is necessary or if Kerberos-only delegation is sufficient."
    Remediation    = @"
1. Verify Protocol Transition is required for application
2. Disable if only Kerberos-to-Kerberos delegation is needed
3. Review and minimize delegated service targets
4. Document business justification
5. Monitor for unusual delegation patterns
"@
    References     = ""
}

$riskInfo = Get-RiskInfo -severity 2 -exploitability 4 -exposure 5
$checkInfo["Constrained Only (LOW)"] = @{
    Severity       = 2
    Exploitability = 4
    Exposure       = 5
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Service accounts with constrained delegation (Kerberos-only) to specific services. This is the recommended approach when delegation is required."
    Remediation    = @"
1. Verify delegated services follow least privilege principle
2. Review and remove unnecessary delegation targets
3. Document business purpose for each delegation
4. Regularly audit delegation configurations
5. This is the preferred delegation method - no immediate action unless over-permissioned
"@
    References     = ""
}

$riskInfo = Get-RiskInfo -severity 5 -exploitability 5 -exposure 4
$checkInfo["RBCD Target (MEDIUM)"] = @{
    Severity       = 5
    Exploitability = 5
    Exposure       = 4
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Service accounts configured as Resource-Based Constrained Delegation targets. Review which principals are allowed to delegate."
    Remediation    = @"
1. Review AllowedToActOnBehalf principals
2. Ensure only necessary accounts can delegate
3. Remove overly broad permissions
4. Verify business justification for RBCD
5. Monitor for delegation abuse
"@
    References     = ""
}

# ============================================
# Module 4: Dangerous ACL Permissions Scanner
# ============================================

# Section 1: AdminSDHolder Permissions
$riskInfo = Get-RiskInfo -severity 10 -exploitability 8 -exposure 2
$checkInfo["Dangerous Permissions (CRITICAL)"] = @{
    Severity       = 10
    Exploitability = 8
    Exposure       = 2
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "CRITICAL: AdminSDHolder is a special container that serves as a template for permissions on privileged accounts. Unauthorized users with dangerous ACL rights can persist backdoor access. The SDProp process propagates these permissions to all protected accounts every 60 minutes."
    Remediation    = @"
1. IMMEDIATELY review all ACL entries on AdminSDHolder (CN=AdminSDHolder,CN=System,DC=domain,DC=com)
2. Remove any unauthorized trustees with GenericAll, WriteDacl, WriteOwner, or WriteProperty rights
3. Only Domain Admins and system accounts should have write access to AdminSDHolder
4. Investigate how unauthorized permissions were added
5. Audit all protected accounts for backdoor permissions that may have propagated
6. Monitor AdminSDHolder ACL changes with Event ID 5136
"@
    References     = "https://adsecurity.org/?p=1906"
    MITRETechnique = "T1098 - Account Manipulation"
}

# Section 2: Domain Object Permissions
$riskInfo = Get-RiskInfo -severity 10 -exploitability 9 -exposure 2
$checkInfo["DCSync Rights (CRITICAL - Domain Takeover)"] = @{
    Severity       = 10
    Exploitability = 9
    Exposure       = 2
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "CRITICAL: DCSync rights (DS-Replication-Get-Changes and DS-Replication-Get-Changes-All) allow an attacker to replicate all password hashes from AD, including KRBTGT. This enables complete domain takeover via Golden Ticket attacks."
    Remediation    = @"
1. IMMEDIATELY remove DCSync rights from unauthorized accounts
2. Only Domain Controllers and specific backup software should have these rights
3. Investigate how these permissions were granted - likely compromise or misconfiguration
4. Audit for DCSync attacks in security logs (Event ID 4662 with GUIDs 1131f6ad-* or 1131f6aa-*)
5. Reset KRBTGT password twice (wait 10 hours between resets)
6. Consider resetting passwords for all privileged accounts
7. Engage security incident response team
"@
    References     = "https://adsecurity.org/?p=1729"
    MITRETechnique = "T1003.006 - OS Credential Dumping: DCSync"
}

$riskInfo = Get-RiskInfo -severity 9 -exploitability 8 -exposure 2
$checkInfo["Other Dangerous Rights (HIGH)"] = @{
    Severity       = 9
    Exploitability = 8
    Exposure       = 2
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Domain object has dangerous ACL rights (GenericAll, GenericWrite, WriteDacl, WriteOwner) granted to unauthorized principals. These permissions can be escalated to DCSync or used to compromise the entire domain."
    Remediation    = @"
1. Review and remove unauthorized ACL entries on the domain object
2. Only Domain Admins, Enterprise Admins, and system accounts should have write access
3. Verify no unexpected service accounts or users have permissions
4. Audit for privilege escalation attempts
5. Implement regular ACL audits on domain object
6. Monitor with Event ID 5136 (directory service object modified)
"@
    References     = ""
}

# Section 3: Privileged Group Permissions
$riskInfo = Get-RiskInfo -severity 10 -exploitability 9 -exposure 2
$checkInfo["Domain Admins Group (CRITICAL)"] = @{
    Severity       = 10
    Exploitability = 9
    Exposure       = 2
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "CRITICAL: Unauthorized principals with dangerous ACL rights on the Domain Admins group can add themselves or other accounts to the group, gaining full domain administrative access."
    Remediation    = @"
1. IMMEDIATELY remove unauthorized ACL entries on Domain Admins group
2. Only Domain Admins and SYSTEM should have write access
3. Audit current Domain Admins membership for unauthorized additions
4. Review security logs for recent group membership changes (Event ID 4728, 4732)
5. Reset passwords for affected accounts
6. Investigate how permissions were added - possible compromise
"@
    References     = ""
    MITRETechnique = "T1098.003 - Account Manipulation: Additional Cloud Roles"
}

$riskInfo = Get-RiskInfo -severity 10 -exploitability 9 -exposure 1
$checkInfo["Enterprise Admins Group (CRITICAL)"] = @{
    Severity       = 10
    Exploitability = 9
    Exposure       = 1
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "CRITICAL: Enterprise Admins have administrative rights across the entire forest. Unauthorized ACL rights on this group enable forest-wide compromise."
    Remediation    = @"
1. IMMEDIATELY remove unauthorized ACL entries on Enterprise Admins group
2. Only Enterprise Admins and SYSTEM should have write access
3. Audit current Enterprise Admins membership
4. Review security logs for membership changes (Event ID 4728, 4732)
5. This is a forest-level security incident - engage security team
6. Consider forest-wide password reset for privileged accounts
"@
    References     = ""
}

$riskInfo = Get-RiskInfo -severity 8 -exploitability 8 -exposure 2
$checkInfo["Other Privileged Groups (HIGH)"] = @{
    Severity       = 8
    Exploitability = 8
    Exposure       = 2
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Other privileged groups (Schema Admins, Backup Operators, Account Operators, Server Operators, Print Operators) have unauthorized ACL entries. These groups have elevated privileges and should be tightly controlled."
    Remediation    = @"
1. Remove unauthorized ACL entries from privileged groups
2. Verify only appropriate administrators have write access
3. Audit group memberships for unauthorized additions
4. Document all exceptions with business justification
5. Implement regular ACL reviews for privileged groups
6. Enable auditing for group membership changes
"@
    References     = ""
}

# Section 4: GPO Permissions
$riskInfo = Get-RiskInfo -severity 9 -exploitability 8 -exposure 3
$checkInfo["Dangerous GPO Permissions (HIGH - Code Execution)"] = @{
    Severity       = 9
    Exploitability = 8
    Exposure       = 3
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Group Policy Objects with unauthorized write access can be modified to execute arbitrary code on all computers/users affected by the GPO. This includes computer startup scripts, user logon scripts, scheduled tasks, and software installation."
    Remediation    = @"
1. Review all unauthorized principals with write access to GPOs
2. Remove GenericAll, GenericWrite, WriteDacl, WriteOwner permissions from non-admin accounts
3. Verify GPO permissions follow least privilege principle
4. Audit GPO modifications with Event ID 5136 and 5137
5. Check for malicious GPO modifications (scripts, scheduled tasks, software deployment)
6. Only Domain Admins and specific delegated GPO administrators should have write access
7. Consider using GPO security filtering to limit scope
"@
    References     = "https://adsecurity.org/?p=2716"
    MITRETechnique = "T1484.001 - Domain Policy Modification: Group Policy Modification"
}

# Section 5: Privileged User Permissions
$riskInfo = Get-RiskInfo -severity 10 -exploitability 9 -exposure 2
$checkInfo["Password Reset Rights (CRITICAL)"] = @{
    Severity       = 10
    Exploitability = 9
    Exposure       = 2
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "CRITICAL: Unauthorized principals with User-Force-Change-Password extended right on privileged accounts can reset passwords and gain administrative access without knowing the current password."
    Remediation    = @"
1. IMMEDIATELY remove User-Force-Change-Password rights from unauthorized principals
2. Only Domain Admins and designated helpdesk accounts should have password reset rights
3. NEVER delegate password reset rights for privileged accounts to low-privilege users
4. Audit for recent password resets on privileged accounts (Event ID 4724)
5. Reset passwords for affected accounts if unauthorized resets detected
6. Investigate how these permissions were granted
"@
    References     = ""
}

$riskInfo = Get-RiskInfo -severity 9 -exploitability 8 -exposure 2
$checkInfo["Other Dangerous Rights GPO(HIGH)"] = @{
    Severity       = 9
    Exploitability = 8
    Exposure       = 2
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Privileged user accounts have other dangerous ACL rights (GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty). These can be used for account takeover, privilege escalation, or persistence."
    Remediation    = @"
1. Remove unauthorized dangerous ACL rights from privileged user accounts
2. Review what specific rights are granted and to whom
3. Verify no service accounts or regular users have write access
4. Audit for suspicious account modifications
5. Enable Protected Users group for privileged accounts
6. Set 'Account is sensitive and cannot be delegated' flag
"@
    References     = ""
}

# Section 6: Organizational Unit Permissions
$riskInfo = Get-RiskInfo -severity 7 -exploitability 7 -exposure 4
$checkInfo["Top-Level OU Permissions (MEDIUM-HIGH)"] = @{
    Severity       = 7
    Exploitability = 7
    Exposure       = 4
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Top-level Organizational Units with dangerous ACL rights granted to unauthorized principals. OU permissions can allow GPO linking (code execution), object creation/deletion, and modification of contained objects."
    Remediation    = @"
1. Review ACL entries on top-level OUs for unauthorized principals
2. Remove excessive permissions (GenericAll, WriteDacl, WriteOwner)
3. Verify delegated administrators have only necessary rights (no GenericAll)
4. Check for unauthorized GPO links on OUs
5. Audit OU structure modifications (Event ID 5136, 5137, 5139)
6. Implement least privilege delegation model for OU administration
7. Document all OU permission delegations with business justification
"@
    References     = ""
}

# Export de hashtable
return $checkInfo
