@{
    # Script module or binary module file associated with this manifest
    RootModule = 'ADSecurityScanner.psm1'

    # Version number of this module
    ModuleVersion = '1.0.0'

    # Supported PSEditions
    CompatiblePSEditions = @('Desktop', 'Core')

    # ID used to uniquely identify this module
    GUID = 'a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d'

    # Author of this module
    Author = 'Lucas Huygen'

    # Copyright statement for this module
    Copyright = '(c) 2026 AD Security Scanner Project. All rights reserved.'

    # Description of the functionality provided by this module
    Description = @'
AD Security Scanner - Comprehensive Active Directory Security Auditing Tool

This PowerShell module provides enterprise-grade security auditing capabilities for Active Directory environments.
It identifies common misconfigurations, weak security settings, and potential attack vectors across four main areas:

MODULE 1 - Dangerous Accounts & Password Policies
  - Detects accounts with PasswordNeverExpires
  - Identifies accounts with PasswordNotRequired
  - Finds accounts that CannotChangePassword
  - Discovers disabled accounts (cleanup candidates)
  - Detects orphaned adminCount attributes
  - Audits domain and default password policies

MODULE 2 - Kerberos SPN Audit
  - Identifies Kerberoastable accounts (SPN-enabled users)
  - Detects weak Kerberos encryption (RC4)
  - Finds accounts without Pre-Authentication (AS-REP Roasting)
  - Audits service account password policies

MODULE 3 - Delegation Abuse Scanner
  - Detects Unconstrained Delegation (users, computers, service accounts)
  - Identifies Constrained Delegation with/without Protocol Transition
  - Finds Resource-Based Constrained Delegation (RBCD)
  - Discovers sensitive accounts not protected
  - Identifies admins not in Protected Users group
  - Detects dangerous SPN delegation
  - Finds delegation to Domain Controllers

MODULE 4 - Dangerous ACL Permissions
  - Audits AdminSDHolder permissions
  - Identifies DCSync rights on domain object
  - Finds excessive permissions on privileged groups
  - Detects dangerous GPO permissions
  - Discovers password reset rights on privileged users
  - Audits organizational unit permissions

FEATURES:
  - Risk scoring system with MITRE ATT&CK mapping
  - Interactive HTML dashboard with collapsible sections
  - Comprehensive remediation functions
  - Robust error handling and parameter validation
  - Pester unit tests for critical functions
  - Detailed help documentation

REQUIREMENTS:
  - PowerShell 5.1 or later
  - ActiveDirectory PowerShell module
  - Domain Admin or equivalent permissions (read-only for scanning, write for remediation)

USAGE:
  Import-Module ADSecurityScanner
  Invoke-ADSecurityScan

For remediation:
  Set-PasswordNeverExpiresFix -Accounts $accounts
  Set-KerberosEncryptionFix -Accounts $spnAccounts
'@

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Modules that must be imported into the global environment prior to importing this module
    # Note: ActiveDirectory module is required but not enforced here to allow testing
    # RequiredModules = @('ActiveDirectory')

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry
    FunctionsToExport = @(
        'Invoke-ADSecurityScan',
        'Set-PasswordNeverExpiresFix',
        'Set-PasswordNotRequiredFix',
        'Set-CannotChangePasswordFix',
        'Remove-DisabledAccountsFix',
        'Clear-AdminCountFix',
        'Set-KerberosEncryptionFix',
        'Enable-KerberosPreAuthFix'
    )

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @(
                'ActiveDirectory',
                'Security',
                'Audit',
                'Scanner',
                'Kerberos',
                'Delegation',
                'ACL',
                'MITRE',
                'ATT&CK',
                'Remediation',
                'Hardening',
                'Compliance',
                'Vulnerability',
                'Assessment'
            )

            # ReleaseNotes of this module
            ReleaseNotes = @'
Version 1.0.0 (2026-01-02)
--------------------------
Initial release with comprehensive AD security scanning capabilities:

- Module 1: Dangerous Accounts & Password Policies
  * Account misconfiguration detection
  * Password policy auditing
  * Remediation functions with parameter validation

- Module 2: Kerberos SPN Audit
  * Kerberoasting detection
  * Weak encryption detection
  * AS-REP Roasting detection
  * Remediation functions for encryption and pre-auth

- Module 3: Delegation Abuse Scanner
  * Unconstrained delegation detection
  * Constrained delegation detection
  * RBCD detection
  * Protocol transition detection

- Module 4: Dangerous ACL Permissions
  * AdminSDHolder auditing
  * DCSync rights detection
  * GPO permission auditing
  * Privileged group permission auditing

- Features:
  * Interactive HTML dashboard
  * Risk scoring with MITRE ATT&CK mapping
  * Comprehensive error handling
  * Pester unit tests
  * Robust parameter validation
  * Detailed help documentation

- Requirements:
  * PowerShell 5.1+
  * ActiveDirectory module
  * Domain Admin permissions (read for scan, write for remediation)
'@

            # Prerelease string of this module
            Prerelease = ''

            # Flag to indicate whether the module requires explicit user acceptance for install/update
            RequireLicenseAcceptance = $false

            # External dependent modules of this module
            ExternalModuleDependencies = @('ActiveDirectory')
        }
    }

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix
    DefaultCommandPrefix = ''
}
