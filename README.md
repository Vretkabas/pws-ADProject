# AD Security Scanner

A comprehensive PowerShell-based Active Directory security auditing tool that scans for common misconfigurations, dangerous settings, and potential security vulnerabilities in Active Directory environments.

## Overview

The AD Security Scanner performs automated security assessments of Active Directory domains, focusing on identifying dangerous account configurations, weak Kerberos settings, delegation abuse, and risky ACL permissions. The tool generates detailed HTML reports and offers automated remediation for certain security issues.

## Features

- **Comprehensive Security Scanning**: Analyzes multiple security domains across your AD environment
- **Automated Remediation**: Offers interactive fixes for common security issues
- **HTML Reporting**: Generates detailed, timestamped reports for documentation and compliance
- **Modular Design**: Run individual modules or perform complete scans
- **Prerequisite Validation**: Ensures all requirements are met before scanning

## Modules

### Module 1: Dangerous Accounts & Password Policies

Identifies risky account configurations and weak password policies:

- Password Never Expires accounts
- Disabled Accounts (>30 days)
- Inactive Accounts (>60 days)
- Expired Accounts
- Locked Out Accounts
- Password Expired accounts
- Passwords in Description field
- Password Not Required accounts
- Cannot Change Password accounts
- Old Passwords (>90 days)
- Orphaned AdminCount accounts
- SID History accounts
- Password Policy Analysis (complexity, length, age requirements)

**Remediation Available**: Yes - for password settings, disabled accounts, and AdminCount issues

### Module 2: Kerberos SPN Audit

Scans Service Principal Name (SPN) accounts for security weaknesses:

**Encryption Analysis**:
- Weak Encryption (DES or RC4 without AES)
- DES Encryption (Critical vulnerability)
- RC4 Only (No AES support)
- AES encryption status

**Account Settings**:
- Password Never Expires on SPN accounts
- Password Not Required
- Cannot Change Password
- Password Expired
- Disabled SPN accounts
- Locked Out accounts
- Reversible Password Encryption
- Does Not Require Pre-Authentication (AS-REP Roasting vulnerability)
- Trusted for Delegation (Unconstrained)
- Trusted to Authenticate for Delegation (Constrained)
- Old Passwords (>90 days)

**Remediation Available**: Yes - for encryption settings and account configuration issues

### Module 3: Delegation Abuse Scanner

Detects delegation misconfigurations that could lead to privilege escalation:

**Unconstrained Delegation**:
- Users (CRITICAL)
- Computers (HIGH)
- Service Accounts (HIGH)
- Domain Controllers (Informational)

**Constrained Delegation**:
- Kerberos Only delegation
- Protocol Transition delegation

**Resource-Based Constrained Delegation (RBCD)**:
- Target Computers, Users, and Service Accounts

**Protection Analysis**:
- Sensitive Accounts Not Protected
- Admins Not in Protected Users group
- Dangerous SPN Delegation (LDAP, CIFS, HOST, etc.)
- Delegation to Domain Controllers (DCSync risk)

**Special Checks**:
- Pre-Windows 2000 Compatible Access group members
- Service Account (gMSA) delegation settings

**Remediation Available**: No - requires manual review and remediation

### Module 4: Dangerous ACL Permissions Scanner

Audits Access Control Lists on critical AD objects:

**AdminSDHolder Permissions**: Monitors the template object that protects privileged accounts

**Domain Object Permissions**:
- DCSync Rights (CRITICAL - allows domain data replication)
- Other Dangerous Rights

**Privileged Group Permissions**:
- Domain Admins Group
- Enterprise Admins Group
- Other Privileged Groups

**GPO Permissions**: Identifies who can modify Group Policy Objects (code execution risk)

**Privileged User Permissions**:
- Password Reset Rights
- Other Dangerous Rights

**Organizational Unit Permissions**: Reviews top-level OU access controls

**Remediation Available**: No - requires manual review and remediation

## Requirements

### System Requirements

- Windows PowerShell 5.1 or higher
- Administrator privileges
- Domain connectivity
- RSAT (Remote Server Administration Tools)

### Required PowerShell Modules

- ActiveDirectory
- GroupPolicy
- Microsoft.PowerShell.Security (optional)

### Recommended Permissions

- Domain Admin rights (some checks may fail without these permissions)
- Access to Domain Controllers

## Installation

1. Clone or download this repository
2. Ensure RSAT tools are installed:
   ```powershell
   Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
   ```
3. Open PowerShell as Administrator
4. Navigate to the AD-Scanner directory

## Usage

### Run All Modules

```powershell
.\main.ps1
```

### Run Specific Modules

```powershell
# Run only Module 1
.\main.ps1 -Modules "1"

# Run multiple modules
.\main.ps1 -Modules "1","2","3"

# Run specific modules
.\main.ps1 -Modules "2","4"
```

### Additional Options

```powershell
# Skip HTML report generation
.\main.ps1 -SkipHTML

# Force execution without prerequisite checks (NOT RECOMMENDED)
.\main.ps1 -Force
```

### Prerequisite Checks

Before running the scan, the tool automatically validates:
- PowerShell version (minimum 5.1)
- Execution Policy
- Administrator rights
- Required PowerShell modules
- RSAT installation
- Domain connectivity
- Domain Controller accessibility
- AD Web Services (ADWS) availability
- Domain Admin rights (warning if not available)

To run prerequisite checks manually:
```powershell
.\Modules\Checks.ps1
```

## Output

### Reports

HTML reports are generated in the `Reports` folder with timestamps:
```
Reports\AD-Security-Report-YYYYMMDD-HHmmss.html
```

**Report Features**:
- **Interactive Dashboard**: Click-through interface to explore findings by module
- **Risk Scoring**: Each finding is scored using a formula: `(Severity × Exploitability × Exposure) / 10`
  - **Critical** (73-100): Immediate action required
  - **High** (34.4-72.9): High priority remediation
  - **Medium** (12.6-34.3): Should be addressed
  - **Low** (0-12.5): Review and monitor
- **Detailed Information**: Expandable sections with descriptions, remediation steps, and references
- **MITRE ATT&CK Mapping**: Links to relevant attack techniques where applicable
- **Collapsible Sections**: Easy navigation through large datasets
- **Account Details**: Complete account information in sortable tables

The risk scoring system evaluates three dimensions:
- **Severity (1-10)**: Impact if the vulnerability is exploited
- **Exploitability (1-10)**: How easy it is to exploit
- **Exposure (1-10)**: Likelihood of occurrence or visibility to attackers


## Remediation

The tool offers interactive remediation menus for Modules 1 and 2:

1. After scanning, a menu displays fixable issues
2. Select an issue to view affected accounts
3. Review accounts in a grid view
4. Confirm to apply automated fixes
5. The tool re-scans to verify changes

**Important**:
- Always review accounts before applying fixes
- Some fixes are destructive (e.g., deleting disabled accounts)
- Test in a non-production environment first
- Modules 3 and 4 require manual remediation due to complexity

## Security Considerations

This tool performs read operations and optional write operations (during remediation) on Active Directory. Use with caution:

- Run in a test environment first
- Always review findings before remediation
- Backup AD before making changes
- Use Domain Admin privileges only when necessary
- Monitor logs for unexpected behavior

## Project Structure

```
AD-Scanner/
├── main.ps1                    # Master orchestration script
├── checkInfo.ps1               # Risk scoring & check metadata database
├── exportHTMLOutput.ps1        # HTML report generator with interactive UI
├── Modules/
│   ├── Checks.ps1              # Prerequisite validation (RSAT, permissions, connectivity)
│   ├── module1dangerousAccounts/
│   │   ├── module1.ps1         # Main module orchestrator
│   │   ├── dangerousSettings.ps1   # Account misconfiguration checks
│   │   ├── passwordSettings.ps1    # Password policy analysis
│   │   ├── remediation.ps1         # Remediation engine
│   │   ├── remediationMenu.ps1     # Interactive remediation menu
│   │   └── remediationFix.ps1      # Fix implementation functions
│   ├── module2Kerberos/
│   │   ├── module2.ps1         # Main module orchestrator
│   │   ├── SPNAudit.ps1        # SPN account & encryption auditing
│   │   ├── remediation.ps1     # Remediation engine
│   │   ├── remediationMenu.ps1 # Interactive remediation menu
│   │   └── remediationFix.ps1  # Fix implementation functions
│   ├── module3DelegationAbuse/
│   │   ├── module3.ps1         # Main module orchestrator
│   │   └── delegationAudit.ps1 # Delegation configuration scanner
│   └── module4DangerousACLs/
│       ├── module4.ps1         # Main module orchestrator
│       └── aclAudit.ps1        # ACL permissions auditor
├── Dependencies/               # External dependencies (VirtualBox, etc.)
├── Reports/                    # Generated HTML reports
```

## Key Features

### Risk-Based Prioritization
Every security finding is automatically scored based on severity, exploitability, and exposure. This helps security teams prioritize remediation efforts effectively.

### Comprehensive Check Database
The `checkInfo.ps1` file contains detailed metadata for over 100 security checks, including:
- Risk scoring parameters
- Detailed descriptions
- Step-by-step remediation instructions
- References to security resources
- MITRE ATT&CK technique mappings

### Interactive Remediation
Modules 1 and 2 provide guided remediation workflows:
1. Scan identifies issues
2. Interactive menu shows fixable problems
3. Review affected accounts in grid view
4. Apply fixes with confirmation
5. Automatic re-scan to verify changes

### Modular Architecture
Each module is self-contained and can be run independently. This allows for:
- Targeted scans of specific security domains
- Faster execution when full scans aren't needed
- Easier maintenance and updates
- Custom integration into existing security workflows

## Testing Environment

For testing purposes, you can use [BadBlood](https://github.com/davidprowe/BadBlood) to create a vulnerable Active Directory environment with intentionally misconfigured accounts and settings.

The `badblood` folder contains scripts to set up a test AD environment. The `Dependencies` folder includes required tools like VirtualBox for running isolated AD test environments.

## Contributing

Contributions are welcome! Please ensure:
- Code follows PowerShell best practices
- New modules follow the existing structure
- Documentation is updated accordingly

## License

This project is provided as-is for educational and security auditing purposes.

## Disclaimer

This tool is designed for authorized security testing and auditing only. Always obtain proper authorization before scanning any Active Directory environment. The authors are not responsible for misuse or damage caused by this tool.

## Example Findings

### High-Risk Findings Examples

**Passwords in Description Fields** (Risk Score: 70.0 - CRITICAL)
- Severity: 10, Exploitability: 10, Exposure: 7
- MITRE ATT&CK: T1552.001 - Unsecured Credentials

**DCSync Rights** (Risk Score: 90.0 - CRITICAL)
- Severity: 10, Exploitability: 9, Exposure: 2
- MITRE ATT&CK: T1003.006 - OS Credential Dumping: DCSync
- Allows complete domain password replication

**Kerberos DES Encryption** (Risk Score: 100.0 - CRITICAL)
- Severity: 10, Exploitability: 10, Exposure: 3
- MITRE ATT&CK: T1558.003 - Kerberoasting
- Deprecated encryption, crackable in seconds

**Unconstrained Delegation on Users** (Risk Score: 80.0 - CRITICAL)
- Severity: 10, Exploitability: 8, Exposure: 2
- MITRE ATT&CK: T1134.002 - Access Token Manipulation
- Enables TGT caching and impersonation attacks

## Frequently Asked Questions

**Q: Do I need Domain Admin rights to run the scanner?**
A: Some checks require Domain Admin privileges, but the scanner will run with warnings if you don't have them. For complete results, Domain Admin rights are recommended.

**Q: Will the scanner make changes to my Active Directory?**
A: No, not unless you explicitly choose to apply remediation fixes. By default, the scanner only performs read operations.

**Q: How long does a full scan take?**
A: Scan time varies based on AD size. Small environments (< 1000 users): 2-5 minutes. Medium environments (1000-10000 users): 5-15 minutes. Large environments: 15-30+ minutes.

**Q: Can I schedule automated scans?**
A: Yes, you can use Windows Task Scheduler to run the scanner with the `-SkipHTML:$false` parameter for regular automated scans.

**Q: Are the HTML reports safe to share?**
A: Reports contain sensitive security information about your AD environment. Share only with authorized security personnel and store securely.

## Version History

This project uses continuous development. Check git commit history for detailed changes.

## Support

For issues, questions, or contributions, please open an issue in the repository.

## Technical Architecture

### Data Flow Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                          main.ps1                                    │
│                    (Orchestrator Script)                             │
└──────────────────┬──────────────────────────────────────────────────┘
                   │
                   ├──► 1. Run Checks.ps1 (Prerequisite Validation)
                   │    └──► Returns: $true/$false
                   │
                   ├──► 2. Execute Selected Modules
                   │    │
                   │    ├──► Module 1 (module1.ps1)
                   │    │    ├─► dangerousSettings.ps1
                   │    │    ├─► passwordSettings.ps1
                   │    │    ├─► remediationMenu.ps1 (optional)
                   │    │    └─► Returns: @{
                   │    │           AccountChecks = @{
                   │    │              "Check Name" = @(Account Objects)
                   │    │           }
                   │    │           PasswordPolicies = @(Policy Objects)
                   │    │        }
                   │    │
                   │    ├──► Module 2 (module2.ps1)
                   │    │    └─► Returns: Same structure as Module 1
                   │    │
                   │    ├──► Module 3 (module3.ps1)
                   │    │    └─► Returns: @{
                   │    │           "Category" = @{
                   │    │              "Sub-Category" = @(Account Objects)
                   │    │           }
                   │    │        }
                   │    │
                   │    └──► Module 4 (module4.ps1)
                   │         └─► Returns: Same nested structure as Module 3
                   │
                   ├──► 3. Aggregate Results
                   │    └──► $allModuleResults = @{
                   │           "Module 1 - Dangerous Accounts" = {...}
                   │           "Module 1 - Password Policies" = {...}
                   │           "Module 2 - Kerberos SPN Audit" = {...}
                   │           "Module 3 - Delegation" = {...}
                   │           "Module 4 - Dangerous ACL Permissions" = {...}
                   │        }
                   │
                   └──► 4. Generate HTML Report
                        └──► exportHTMLOutput.ps1
                             ├─► Load checkInfo.ps1 (Risk Metadata)
                             ├─► Calculate Statistics per Module
                             ├─► Generate Interactive HTML
                             └─► Save to Reports/AD-Security-Report-*.html
```

### Module Return Data Structures

#### Module 1 & 2 Structure (Flat + Password Policies)
```powershell
# Module returns this structure:
@{
    AccountChecks = @{
        "Password Never Expires" = @(
            [PSCustomObject]@{
                SamAccountName = "user1"
                DistinguishedName = "CN=user1,OU=Users,DC=domain,DC=com"
                Enabled = $true
                # ... other properties
            },
            [PSCustomObject]@{ ... }
        )
        "Disabled Accounts (>30 days)" = @(...)
        # ... more checks
    }

    PasswordPolicies = @(
        [PSCustomObject]@{
            PolicyType = "Default Domain Policy"
            PolicyName = "Default Domain Policy"
            AppliedUsers = @("user1", "user2", ...)
            AppliedUserCount = 150
            Issues = @(
                @{
                    Setting = "Minimum Password Length"
                    CurrentValue = "7 characters"
                    Recommendation = "12+ characters"
                },
                @{ ... }
            )
        }
    )
}
```

#### Module 3 & 4 Structure (Nested Categories)
```powershell
# Module returns this nested structure:
@{
    "Unconstrained Delegation" = @{
        "Users (CRITICAL)" = @(
            [PSCustomObject]@{
                SamAccountName = "admin1"
                DistinguishedName = "CN=admin1,OU=Admins,DC=domain,DC=com"
                # ... properties
            }
        )
        "Computers (HIGH)" = @(...)
        "Service Accounts (HIGH)" = @(...)
    }

    "Constrained Delegation" = @{
        "Users - Kerberos Only (MEDIUM)" = @(...)
        "Users - With Protocol Transition (HIGH)" = @(...)
        # ... more sub-categories
    }

    # ... more categories
}
```

### HTML Export Process

The `exportHTMLOutput.ps1` script processes module results in three phases:

#### Phase 1: Load Risk Metadata
```powershell
# Load checkInfo.ps1 which returns a hashtable
$checkInfo = & "$PSScriptRoot\checkInfo.ps1"

# Example checkInfo entry:
$checkInfo["Password Never Expires"] = @{
    Severity = 7
    Exploitability = 6
    Exposure = 8
    RiskScore = 33.6        # (7 × 6 × 8) / 10
    RiskLevel = "Medium"
    RiskColor = "#ffc107"
    Description = "..."
    Remediation = "..."
    MITRETechnique = "T1078"
}
```

#### Phase 2: Calculate Module Statistics
```powershell
foreach ($moduleName in $Results.Keys) {
    $moduleData = $Results[$moduleName]

    # For Module 1 & 2 (flat structure):
    foreach ($checkName in $moduleData.Keys) {
        $accounts = $moduleData[$checkName]
        $count = ($accounts | Measure-Object).Count

        # Get risk info from checkInfo
        $info = $checkInfo[$checkName]
        $riskLevel = $info.RiskLevel  # Critical/High/Medium/Low

        # Aggregate statistics
        $moduleStats[$moduleName] += $count
    }

    # For Module 3 & 4 (nested structure):
    foreach ($categoryName in $moduleData.Keys) {
        foreach ($subCheckName in $moduleData[$categoryName].Keys) {
            $accounts = $moduleData[$categoryName][$subCheckName]
            # Same counting logic...
        }
    }
}
```

#### Phase 3: Generate HTML Components

**Dashboard Cards:**
```powershell
# For each module, create a clickable card
$html += @"
<div class="dashboard-card $riskClass" onclick="showView('$moduleId')">
    <div class="card-title">$moduleName</div>
    <div class="stat-value">$totalIssues issues</div>
    <div class="stat-label">Critical: $criticalCount</div>
</div>
"@
```

**Detail Views with Two Rendering Paths:**

**Path A: Flat Checks (Module 1 & 2)**
```powershell
# Regular account check
$html += "<div class='check'>"
$html += "  <div class='check-title'>$checkName"
$html += "    <span class='badge'>$count found - $riskLevel Risk</span>"
$html += "  </div>"
$html += "  <table>"
foreach ($account in $accounts) {
    $html += "<tr><td>$($account.SamAccountName)</td></tr>"
}
$html += "  </table>"
$html += "</div>"
```

**Path B: Nested Checks (Module 3 & 4)**
```powershell
# Category container
$html += "<div class='check'>"
$html += "  <h3>$categoryName</h3>"

# Sub-category checks
foreach ($subCheckName in $categoryData.Keys) {
    $html += "  <div class='check'>"
    $html += "    <div class='check-title'>$subCheckName"
    $html += "      <span class='badge'>$count - $riskLevel</span>"
    $html += "    </div>"
    $html += "    <table>...</table>"
    $html += "  </div>"
}
$html += "</div>"
```

### Adding a Custom Module

Here's a complete example of adding a new "Module 5: Certificate Services Audit":

#### Step 1: Create Module Structure

```powershell
# File: AD-Scanner/Modules/module5Certificates/module5.ps1

Write-Host "`n=== Module 5: Certificate Services Audit ===" -ForegroundColor Cyan

# Import your audit functions
. "$PSScriptRoot\certAudit.ps1"

# Run your checks
$vulnerableTemplates = Get-VulnerableCertTemplates
$expiringCerts = Get-ExpiringCertificates -DaysUntilExpiry 30

# IMPORTANT: Return data in the correct format
# Choose between:

# OPTION A: Flat structure (like Module 1 & 2)
return @{
    AccountChecks = @{
        "Vulnerable Certificate Templates" = $vulnerableTemplates
        "Expiring Certificates (30 days)" = $expiringCerts
        "Over-Permissioned Templates" = Get-OverPermissionedTemplates
    }
}

# OPTION B: Nested structure (like Module 3 & 4)
return @{
    "Certificate Templates" = @{
        "ESC1 - Client Authentication (CRITICAL)" = $esc1Vulns
        "ESC2 - Any Purpose (HIGH)" = $esc2Vulns
        "ESC3 - Enrollment Agent (HIGH)" = $esc3Vulns
    }
    "Certificate Authorities" = @{
        "Weak Key Length (MEDIUM)" = $weakKeyCAs
        "Expired Certificates (LOW)" = $expiredCerts
    }
}
```

#### Step 2: Create Audit Functions

```powershell
# File: AD-Scanner/Modules/module5Certificates/certAudit.ps1

function Get-VulnerableCertTemplates {
    # Your scanning logic here
    $templates = Get-ADObject -Filter * -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com"

    $results = @()
    foreach ($template in $templates) {
        # Check for vulnerabilities
        if (Test-TemplateVulnerable -Template $template) {
            $results += [PSCustomObject]@{
                TemplateName = $template.Name
                DistinguishedName = $template.DistinguishedName
                VulnerabilityType = "ESC1"
                # Add more properties as needed
            }
        }
    }

    return $results
}
```

#### Step 3: Register Module in main.ps1

```powershell
# File: AD-Scanner/main.ps1

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("All", "1", "2", "3", "4", "5")]  # Add "5"
    [string[]]$Modules = @("All"),
    # ... other parameters
)

# Add after Module 4 section:
# Module 5: Certificate Services Audit
if (($runAll -or $Modules -contains "5") -and (Test-Path "$PSScriptRoot\Modules\module5Certificates\module5.ps1")) {
    Write-Host "`nRunning Module 5: Certificate Services Audit..." -ForegroundColor Yellow
    $module5Results = & "$PSScriptRoot\Modules\module5Certificates\module5.ps1"

    # IMPORTANT: Choose the right key name based on your return structure

    # If using OPTION A (flat structure):
    $allModuleResults["Module 5 - Certificate Services"] = $module5Results.AccountChecks

    # If using OPTION B (nested structure):
    $allModuleResults["Module 5 - Certificate Services"] = $module5Results
}
```

#### Step 4: Add Risk Metadata to checkInfo.ps1

```powershell
# File: AD-Scanner/checkInfo.ps1

# Add at the end of the file, before the return statement:

# ============================================
# Module 5: Certificate Services Audit
# ============================================

# For OPTION A (flat structure) - each check gets an entry:
$riskInfo = Get-RiskInfo -severity 9 -exploitability 8 -exposure 4
$checkInfo["Vulnerable Certificate Templates"] = @{
    Severity       = 9
    Exploitability = 8
    Exposure       = 4
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Certificate templates with vulnerable configurations can be exploited for privilege escalation."
    Remediation    = @"
1. Review template permissions and remove unnecessary enrollment rights
2. Enable 'Manager Approval' for sensitive templates
3. Disable vulnerable templates if not needed
4. Implement certificate enrollment policies
"@
    References     = "https://posts.specterops.io/certified-pre-owned-d95910965cd2"
    MITRETechnique = "T1649 - Steal or Forge Authentication Certificates"
}

$riskInfo = Get-RiskInfo -severity 6 -exploitability 4 -exposure 7
$checkInfo["Expiring Certificates (30 days)"] = @{
    Severity       = 6
    Exploitability = 4
    Exposure       = 7
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Certificates expiring soon may cause service disruptions."
    Remediation    = "Renew certificates before expiration."
    References     = ""
}

# For OPTION B (nested structure) - each sub-category gets an entry:
$riskInfo = Get-RiskInfo -severity 10 -exploitability 9 -exposure 3
$checkInfo["ESC1 - Client Authentication (CRITICAL)"] = @{
    Severity       = 10
    Exploitability = 9
    Exposure       = 3
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "ESC1: Template allows client authentication and enrollment rights are too permissive."
    Remediation    = "Restrict enrollment permissions to specific security groups."
    References     = "https://posts.specterops.io/certified-pre-owned-d95910965cd2"
    MITRETechnique = "T1649"
}
```

#### Step 5: HTML Export Handles Both Structures Automatically

The `exportHTMLOutput.ps1` automatically detects the structure:

```powershell
# The export script checks if data is nested:
$isModule3Nested = ($moduleName -match "Module 3" -and $data -is [hashtable])
$isModule4Nested = ($moduleName -match "Module 4" -and $data -is [hashtable])

# For your module, update this check:
$isModuleNested = (
    ($moduleName -match "Module 3|Module 4|Module 5") -and
    $data -is [hashtable] -and
    ($data.Values[0] -is [hashtable])  # Nested structure check
)

if ($isModuleNested) {
    # Use nested rendering (categories > sub-categories > accounts)
} else {
    # Use flat rendering (checks > accounts)
}
```

### Complete Example: ESC1 Certificate Vulnerability Module

**Module File (`module5.ps1`):**
```powershell
. "$PSScriptRoot\certAudit.ps1"

$esc1Templates = Get-ESC1Vulnerabilities
$esc2Templates = Get-ESC2Vulnerabilities

return @{
    "Certificate Template Vulnerabilities" = @{
        "ESC1 - Client Authentication (CRITICAL)" = $esc1Templates
        "ESC2 - Any Purpose EKU (HIGH)" = $esc2Templates
    }
}
```

**Audit File (`certAudit.ps1`):**
```powershell
function Get-ESC1Vulnerabilities {
    $configNC = (Get-ADRootDSE).configurationNamingContext
    $templateDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

    $templates = Get-ADObject -SearchBase $templateDN -Filter * -Properties *

    $vulnTemplates = @()
    foreach ($template in $templates) {
        # Check for ESC1 conditions
        $hasClientAuth = $template.'msPKI-Certificate-Application-Policy' -contains "1.3.6.1.5.5.7.3.2"
        $allowsEnrollment = $template.nTSecurityDescriptor -match "Enroll"

        if ($hasClientAuth -and $allowsEnrollment) {
            $vulnTemplates += [PSCustomObject]@{
                TemplateName = $template.Name
                DisplayName = $template.DisplayName
                EnrollmentFlags = $template.'msPKI-Enrollment-Flag'
                IssuanceRequirements = $template.'msPKI-RA-Signature'
                DistinguishedName = $template.DistinguishedName
            }
        }
    }

    return $vulnTemplates
}
```

**Risk Metadata (`checkInfo.ps1`):**
```powershell
$riskInfo = Get-RiskInfo -severity 10 -exploitability 9 -exposure 3
$checkInfo["ESC1 - Client Authentication (CRITICAL)"] = @{
    Severity       = 10
    Exploitability = 9
    Exposure       = 3
    RiskScore      = $riskInfo.Score
    RiskLevel      = $riskInfo.RiskLevel
    RiskColor      = $riskInfo.Color
    Description    = "Certificate templates configured with client authentication EKU and permissive enrollment rights allow privilege escalation via certificate impersonation."
    Remediation    = @"
1. Remove enrollment permissions for low-privilege groups
2. Enable 'Manager Approval' requirement
3. Configure 'This number of authorized signatures' to require approval
4. Set 'Subject Type' to 'Supplied in Request' only for trusted templates
5. Review and restrict template publishing to specific CAs
"@
    References     = "https://posts.specterops.io/certified-pre-owned-d95910965cd2"
    MITRETechnique = "T1649 - Steal or Forge Authentication Certificates"
}
```

The HTML report will automatically render this as a nested category with expandable sections, risk badges, and detailed remediation information!

## Acknowledgments

### AI-Assisted Development
This project was developed with assistance from **Claude AI (Anthropic)** for:
- README.md documentation structure and content
- Risk scoring implementation in `checkInfo.ps1`
- HTML report generation and JavaScript interactivity in `exportHTMLOutput.ps1`
- Code optimization and PowerShell best practices

### Security Frameworks & Methodologies
- **OWASP Risk Rating Methodology** - Risk scoring calculation framework
  - [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)
- **MITRE ATT&CK Framework** - Attack technique mapping and categorization
  - [MITRE ATT&CK for Enterprise](https://attack.mitre.org/)
  - [Active Directory Attack Techniques](https://attack.mitre.org/tactics/TA0006/)

### Testing & Learning Resources
- **BadBlood** - Vulnerable Active Directory environment generator for testing
  - [BadBlood by David Rowe](https://github.com/davidprowe/BadBlood)
  - Used to create intentionally misconfigured AD environments for scanner validation
- **HackTheBox Academy** - Active Directory Enumeration & Attacks Course
  - [HTB Academy - AD Enumeration & Attacks](https://academy.hackthebox.com/)
  - Educational resource for understanding AD security concepts and attack vectors

### Microsoft Documentation
- **Active Directory Security Best Practices**
  - [Microsoft AD Security](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
- **Kerberos Authentication**
  - [How Kerberos Authentication Works](https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
- **Kerberos Constrained Delegation**
  - [Constrained Delegation Overview](https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- **Protected Users Security Group**
  - [Protected Users Group](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- **Group Managed Service Accounts (gMSA)**
  - [Group Managed Service Accounts Overview](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)

### Security Research & References
- **ADSecurity.org** - Sean Metcalf's Active Directory security research
  - [ADSecurity.org](https://adsecurity.org/)
  - Delegation attacks, AdminSDHolder, and privilege escalation techniques
- **SpecterOps Research** - Advanced AD attack research
  - [Certified Pre-Owned (AD CS Attacks)](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
  - [Kerberoasting](https://posts.specterops.io/kerberoasting-revisited-d434351bd4d1)
- **HarmJ0y Research** - PowerView and AD enumeration techniques
  - [HarmJ0y's Blog](https://blog.harmj0y.net/)

### Community & Open Source
- PowerShell Gallery and the PowerShell community for scripting patterns
- Active Directory security community for vulnerability research and remediation guidance

### Special Thanks
Special thanks to the information security community for continuous research and knowledge sharing that makes tools like this possible.

---

**Developed for educational and authorized security testing purposes only.**