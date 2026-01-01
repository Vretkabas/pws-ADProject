<#
.SYNOPSIS
    Password policy analysis functions for Module 1

.DESCRIPTION
    Collects and analyzes password policy data from Active Directory including:
    - Fine-Grained Password Policies (FGPP)
    - Default Domain Password Policy
    - Identifies weak configurations and affected users

    This module evaluates password policies against security best practices and
    identifies which users are affected by each policy. It respects FGPP precedence
    to ensure accurate policy assignment.

    Includes comprehensive parameter validation and error handling.

.NOTES
    Requires ActiveDirectory PowerShell module.
    Different security thresholds apply to regular users vs SPN (service) accounts.
#>

#region Module Import

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Verbose "ActiveDirectory module imported successfully"
}
catch {
    Write-Error "Failed to import ActiveDirectory module: $($_.Exception.Message)"
    Write-Error "This module requires the Active Directory PowerShell module to be installed."
    return
}

#endregion

#region Helper Functions

<#
.SYNOPSIS
    Identifies policy configuration issues based on security best practices

.DESCRIPTION
    Analyzes a password policy object (FGPP or Default Domain Policy) and identifies
    weaknesses based on industry security standards. Different thresholds apply to
    regular user accounts versus service principal name (SPN) accounts.

.PARAMETER Policy
    The password policy object to analyze (FGPP or default domain policy)

.PARAMETER PolicyType
    Type of policy being analyzed ("FGPP" or "Default")

.PARAMETER minPasswordLengthCK
    Minimum acceptable password length threshold
    Default: 12 characters for regular users, 24 for SPN accounts

.PARAMETER maxPasswordAgeDaysCK
    Maximum acceptable password age in days
    Default: 90 days for regular users, 120 for SPN accounts

.PARAMETER isSPNCK
    Whether analyzing SPN (service) accounts which require stronger policies
    Note: Lockout checks are skipped for SPN accounts by design

.OUTPUTS
    [Object[]] Array of PSCustomObjects describing policy weaknesses
    Each object contains: Setting, CurrentValue, RecommendedValue (optional), IsSPN (optional)

.EXAMPLE
    Get-PolicyIssues -Policy $fgpp -PolicyType "FGPP" -minPasswordLengthCK 24 -isSPNCK $true

.NOTES
    Service accounts (SPN) require stronger password policies:
    - Minimum 24 characters (vs 12 for regular users)
    - Maximum age 120 days (vs 90 for regular users)
    - Lockout policies intentionally not checked (prevent account lockout)
#>
function Get-PolicyIssues {
    [CmdletBinding()]
    [OutputType([Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [ValidateSet("FGPP", "Default")]
        [string]$PolicyType,

        [Parameter(Mandatory = $false)]
        [ValidateRange(8, 64)]
        [int]$minPasswordLengthCK = 12,

        [Parameter(Mandatory = $false)]
        [ValidateRange(30, 365)]
        [int]$maxPasswordAgeDaysCK = 90,

        [Parameter(Mandatory = $false)]
        [bool]$isSPNCK = $false
    )

    $issues = @()

    try {
        Write-Verbose "Analyzing $PolicyType policy for security issues..."

        # === Minimum Password Length Check ===
        # Passwords shorter than threshold are weak
        if ($Policy.MinPasswordLength -lt $minPasswordLengthCK) {
            $issues += [PSCustomObject]@{
                Setting          = if ($isSPNCK) {
                    "Minimum Password Length (SPN)"
                }
                else {
                    "Minimum Password Length"
                }
                CurrentValue     = $Policy.MinPasswordLength
                RecommendedValue = $minPasswordLengthCK
                IsSPN            = if ($isSPNCK) {
                    $true
                }
                else {
                    $false
                }
            }
        }

        # === Maximum Password Age Check ===
        # 0 = password never expires, >threshold = password can be too old
        $maxAgeDays = $Policy.MaxPasswordAge.Days

        # For SPN accounts with 24+ character passwords: skip max age check (password is strong enough)
        $skipMaxAgeCheck = ($isSPNCK -and $Policy.MinPasswordLength -ge 24)

        if ($maxAgeDays -eq 0 -and -not $skipMaxAgeCheck) {
            $issues += [PSCustomObject]@{
                Setting      = "Maximum Password Age"
                CurrentValue = "Never expires"
            }
        }
        elseif ($maxAgeDays -gt $maxPasswordAgeDaysCK -and -not $skipMaxAgeCheck) {
            $issues += [PSCustomObject]@{
                Setting          = if ($isSPNCK) {
                    "Maximum Password Age (SPN)"
                }
                else {
                    "Maximum Password Age"
                }
                CurrentValue     = "$maxAgeDays days"
                RecommendedValue = "$maxPasswordAgeDaysCK days"
                IsSPN            = if ($isSPNCK) {
                    $true
                }
                else {
                    $false
                }
            }
        }

        # === Minimum Password Age Check ===
        # 0 = users can change password immediately (allows rapid password cycling)
        if ($Policy.MinPasswordAge.Days -eq 0) {
            $issues += [PSCustomObject]@{
                Setting      = "Minimum Password Age"
                CurrentValue = "0 days (none)"
            }
        }

        # === Password History Check ===
        # Less than 24 passwords remembered allows password reuse too quickly
        if ($Policy.PasswordHistoryCount -lt 24) {
            $issues += [PSCustomObject]@{
                Setting      = "Password History"
                CurrentValue = $Policy.PasswordHistoryCount
            }
        }

        # === Password Complexity Check ===
        # Complexity requires mix of upper, lower, numbers, and special characters
        if (-not $Policy.ComplexityEnabled) {
            $issues += [PSCustomObject]@{
                Setting      = "Password Complexity"
                CurrentValue = "Disabled"
            }
        }

        # === Account Lockout Threshold Check ===
        # 0 = no lockout (allows unlimited failed login attempts)
        # Note: Skipped for SPN accounts to prevent service disruption
        if ($Policy.LockoutThreshold -eq 0 -and $isSPNCK -eq $false) {
            $issues += [PSCustomObject]@{
                Setting      = "Account Lockout Threshold"
                CurrentValue = "Disabled (no lockout)"
            }
        }

        # === Lockout Duration Check ===
        # Only applies if lockout is enabled; less than 15 minutes is too short
        # Note: Skipped for SPN accounts to prevent service disruption
        if ($Policy.LockoutThreshold -gt 0 -and $isSPNCK -eq $false) {
            $lockoutMinutes = $Policy.LockoutDuration.TotalMinutes
            if ($lockoutMinutes -lt 15 -and $lockoutMinutes -ne 0) {
                $issues += [PSCustomObject]@{
                    Setting      = "Lockout Duration"
                    CurrentValue = "$lockoutMinutes minutes"
                }
            }
        }

        # === Reversible Encryption Check (CRITICAL) ===
        # Reversible encryption stores passwords in a form that can be decrypted
        # This is a critical security vulnerability
        if ($Policy.ReversibleEncryptionEnabled) {
            $issues += [PSCustomObject]@{
                Setting      = "Reversible Encryption"
                CurrentValue = "Enabled (CRITICAL)"
            }
        }

        Write-Verbose "Found $($issues.Count) issue(s) in $PolicyType policy"
        return $issues
    }
    catch {
        Write-Error "Error analyzing policy issues for $PolicyType policy: $($_.Exception.Message)"
        Write-Verbose "Stack trace: $($_.ScriptStackTrace)"
        return @()
    }
}

#endregion

#region Main Function

<#
.SYNOPSIS
    Analyzes all password policies in Active Directory

.DESCRIPTION
    Examines both Fine-Grained Password Policies (FGPP) and Default Domain Policy.
    Identifies which users are affected by each policy and what security issues exist.
    Respects FGPP precedence rules to ensure accurate policy assignment.

    The function categorizes users into two types:
    - Regular users (no ServicePrincipalName attribute)
    - Service accounts (with ServicePrincipalName attribute)

    Each type has different security thresholds:
    - Regular users: Min 12 chars, Max age 90 days, lockout enabled
    - Service accounts: Min 24 chars, Max age 120 days, lockout checks skipped

.PARAMETER isSPNCK
    If $true, analyzes policies for SPN (service) accounts only
    If $false, analyzes policies for regular user accounts only
    Default: $false (regular users)

.OUTPUTS
    [hashtable] Policy analysis results keyed by policy name
    Each policy contains: PolicyType, Precedence, AppliedUsers, AppliedUserCount, Issues

.EXAMPLE
    Get-PasswordPolicyAnalysis
    Analyzes password policies for regular user accounts

.EXAMPLE
    Get-PasswordPolicyAnalysis -isSPNCK $true
    Analyzes password policies for service accounts (SPN)

.NOTES
    FGPP precedence rules:
    - Lower precedence number = higher priority
    - Users explicitly assigned to FGPP take precedence over group membership
    - Users inherit from highest-priority FGPP they are subject to
    - Remaining users fall under Default Domain Password Policy
#>
function Get-PasswordPolicyAnalysis {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [bool]$isSPNCK = $false
    )

    try {
        Write-Host "`nAnalyzing Password Policies..." -ForegroundColor Cyan
        Write-Verbose "Analyzing policies for $(if ($isSPNCK) { 'SPN (service) accounts' } else { 'regular user accounts' })"

        $results = @{}

        # === FINE-GRAINED PASSWORD POLICIES (FGPP) ===
        try {
            Write-Verbose "Retrieving Fine-Grained Password Policies..."
            $fgpps = Get-ADFineGrainedPasswordPolicy -Filter * -Properties * -ErrorAction Stop | Sort-Object Precedence
            Write-Verbose "Found $($fgpps.Count) FGPP(s)"

            # Track which users already have a FGPP assigned (respects precedence)
            $assignedUsers = @{}

            foreach ($fgpp in $fgpps) {
                try {
                    Write-Verbose "Processing FGPP: $($fgpp.Name) (Precedence: $($fgpp.Precedence))"

                    # Get subjects (users/groups) linked to this FGPP
                    $linkedSubjects = @()
                    try {
                        $linkedSubjects = Get-ADFineGrainedPasswordPolicySubject -Identity $fgpp.Name -ErrorAction Stop
                        Write-Verbose "  Found $($linkedSubjects.Count) linked subject(s)"
                    }
                    catch {
                        Write-Warning "Could not retrieve subjects for FGPP '$($fgpp.Name)': $($_.Exception.Message)"
                    }

                    $userSAMAccountNames = @()

                    # Process each subject (user or group)
                    foreach ($subject in $linkedSubjects) {
                        try {
                            # === Direct User Assignment ===
                            if ($subject.ObjectClass -eq 'user') {
                                try {
                                    $userDetails = Get-ADUser -Identity $subject.DistinguishedName -Properties ServicePrincipalName -ErrorAction Stop

                                    # Filter by SPN status based on isSPNCK parameter
                                    if ($isSPNCK -and $userDetails.ServicePrincipalName) {
                                        # Include only SPN accounts (service accounts)
                                        $userSAMAccountNames += $subject.SamAccountName
                                    }
                                    elseif (-not $isSPNCK -and -not $userDetails.ServicePrincipalName) {
                                        # Include only normal accounts (no SPN)
                                        $userSAMAccountNames += $subject.SamAccountName
                                    }
                                }
                                catch {
                                    Write-Verbose "  Could not retrieve user details for '$($subject.Name)': $($_.Exception.Message)"
                                }
                            }
                            # === Group Membership Assignment ===
                            elseif ($subject.ObjectClass -eq 'group') {
                                try {
                                    Write-Verbose "  Expanding group: $($subject.Name)"
                                    $groupMembers = Get-ADGroupMember -Identity $subject.DistinguishedName -Recursive -ErrorAction Stop |
                                    Where-Object { $_.objectClass -eq 'user' }

                                    Write-Verbose "    Found $($groupMembers.Count) user(s) in group"

                                    foreach ($member in $groupMembers) {
                                        try {
                                            $userDetails = Get-ADUser -Identity $member.DistinguishedName -Properties ServicePrincipalName -ErrorAction Stop

                                            # Filter by SPN status based on isSPNCK parameter
                                            if ($isSPNCK -and $userDetails.ServicePrincipalName) {
                                                # Include only SPN accounts (service accounts)
                                                $userSAMAccountNames += $member.SamAccountName
                                            }
                                            elseif (-not $isSPNCK -and -not $userDetails.ServicePrincipalName) {
                                                # Include only normal accounts (no SPN)
                                                $userSAMAccountNames += $member.SamAccountName
                                            }
                                        }
                                        catch {
                                            Write-Verbose "    Could not retrieve details for group member '$($member.Name)': $($_.Exception.Message)"
                                        }
                                    }
                                }
                                catch {
                                    Write-Warning "Could not retrieve members of group '$($subject.Name)': $($_.Exception.Message)"
                                }
                            }
                        }
                        catch {
                            Write-Verbose "Could not process subject '$($subject.Name)': $($_.Exception.Message)"
                        }
                    }

                    # Remove duplicates from user list
                    $userSAMAccountNames = $userSAMAccountNames | Select-Object -Unique
                    Write-Verbose "  Total unique users found: $($userSAMAccountNames.Count)"

                    # === Apply FGPP Precedence Rules ===
                    # Filter out users that already have a higher priority FGPP assigned
                    $finalUsers = @()
                    foreach ($user in $userSAMAccountNames) {
                        if (-not $assignedUsers.ContainsKey($user)) {
                            $finalUsers += $user
                            $assignedUsers[$user] = $fgpp.Precedence
                        }
                    }
                    $finalUsers = $finalUsers | Sort-Object
                    Write-Verbose "  Users after precedence filtering: $($finalUsers.Count)"

                    # === Analyze Policy for Security Issues ===
                    # SPN accounts require stronger password settings
                    $issues = @()
                    try {
                        if ($isSPNCK -and $finalUsers.Count -gt 0) {
                            # Service accounts: stricter thresholds (24 chars, 120 days)
                            $issues = Get-PolicyIssues -Policy $fgpp -PolicyType "FGPP" -minPasswordLengthCK 24 -maxPasswordAgeDaysCK 120 -isSPNCK $true
                        }
                        elseif ($finalUsers.Count -gt 0) {
                            # Regular users: standard thresholds (12 chars, 90 days)
                            $issues = Get-PolicyIssues -Policy $fgpp -PolicyType "FGPP"
                        }
                    }
                    catch {
                        Write-Warning "Failed to analyze issues for FGPP '$($fgpp.Name)': $($_.Exception.Message)"
                    }

                    # === Store Results ===
                    # Only add to results if there are issues AND there are affected users
                    if ($issues.Count -gt 0 -and $finalUsers.Count -gt 0) {
                        $results[$fgpp.Name] = [PSCustomObject]@{
                            PolicyType       = "FGPP"
                            Precedence       = $fgpp.Precedence
                            AppliedUsers     = $finalUsers
                            AppliedUserCount = $finalUsers.Count
                            Issues           = $issues
                        }

                        Write-Host "  [!] $($fgpp.Name): $($issues.Count) issue(s), $($finalUsers.Count) user(s)" -ForegroundColor Yellow
                    }
                    elseif ($issues.Count -gt 0 -and $finalUsers.Count -eq 0) {
                        # Policy has issues but no affected users in this category
                        Write-Host "  [SKIP] $($fgpp.Name): Has issues but only applies to service accounts (will be checked in Module 2)" -ForegroundColor Cyan
                    }
                    else {
                        # Policy is compliant
                        Write-Host "  [OK] $($fgpp.Name): No issues found" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning "Error processing FGPP '$($fgpp.Name)': $($_.Exception.Message)"
                    Write-Verbose "Stack trace: $($_.ScriptStackTrace)"
                }
            }
        }
        catch {
            Write-Warning "Error retrieving FGPPs: $($_.Exception.Message)"
            Write-Verbose "Stack trace: $($_.ScriptStackTrace)"
        }

        # === DEFAULT DOMAIN PASSWORD POLICY ===
        try {
            Write-Verbose "Retrieving Default Domain Password Policy..."
            $defaultPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop

            # === Get All Enabled Users (filtered by SPN status) ===
            $allUsers = @()
            try {
                if ($isSPNCK) {
                    # Only SPN accounts (service accounts)
                    Write-Verbose "Querying enabled SPN accounts..."
                    $allUsers = Get-ADUser -Filter { Enabled -eq $true } -Properties ServicePrincipalName -ErrorAction Stop |
                    Where-Object { $_.ServicePrincipalName } |
                    Select-Object -ExpandProperty SamAccountName
                }
                else {
                    # Only non-SPN accounts (regular users)
                    Write-Verbose "Querying enabled non-SPN accounts..."
                    $allUsers = Get-ADUser -Filter { Enabled -eq $true } -Properties ServicePrincipalName -ErrorAction Stop |
                    Where-Object { -not $_.ServicePrincipalName } |
                    Select-Object -ExpandProperty SamAccountName
                }
                Write-Verbose "Found $($allUsers.Count) total enabled users in this category"
            }
            catch {
                Write-Warning "Failed to retrieve enabled users: $($_.Exception.Message)"
                $allUsers = @()
            }

            # === Filter Out Users Already Assigned to FGPP ===
            # These users are already covered by FGPP analysis above
            $usersWithFGPP = $assignedUsers.Keys
            $defaultPolicyUsers = $allUsers | Where-Object { $_ -notin $usersWithFGPP } | Sort-Object
            Write-Verbose "Users under Default Domain Policy: $($defaultPolicyUsers.Count)"

            # === Analyze Default Policy for Security Issues ===
            $defaultIssues = @()
            try {
                if ($isSPNCK -and $defaultPolicyUsers.Count -gt 0) {
                    # Service accounts: stricter thresholds (24 chars, 120 days)
                    $defaultIssues = Get-PolicyIssues -Policy $defaultPolicy -PolicyType "Default" -minPasswordLengthCK 24 -maxPasswordAgeDaysCK 120 -isSPNCK $true
                }
                elseif ($defaultPolicyUsers.Count -gt 0) {
                    # Regular users: standard thresholds (12 chars, 90 days)
                    $defaultIssues = Get-PolicyIssues -Policy $defaultPolicy -PolicyType "Default"
                }
            }
            catch {
                Write-Warning "Failed to analyze Default Domain Password Policy: $($_.Exception.Message)"
            }

            # === Store Results ===
            # Only add to results if there are issues AND there are affected users
            if ($defaultIssues.Count -gt 0 -and $defaultPolicyUsers.Count -gt 0) {
                $results["Default Domain Password Policy"] = [PSCustomObject]@{
                    PolicyType       = "Default"
                    Precedence       = 999  # Lowest priority (applied when no FGPP matches)
                    AppliedUsers     = $defaultPolicyUsers
                    AppliedUserCount = $defaultPolicyUsers.Count
                    Issues           = $defaultIssues
                }

                Write-Host "  [!] Default Domain Password Policy: $($defaultIssues.Count) issue(s), $($defaultPolicyUsers.Count) user(s)" -ForegroundColor Yellow
            }
            elseif ($defaultIssues.Count -gt 0 -and $defaultPolicyUsers.Count -eq 0) {
                # Policy has issues but no affected users in this category
                Write-Host "  [SKIP] Default Domain Password Policy: Has issues but only applies to service accounts (will be checked in Module 2)" -ForegroundColor Cyan
            }
            else {
                # Policy is compliant
                Write-Host "  [OK] Default Domain Password Policy: No issues found" -ForegroundColor Green
            }
        }
        catch {
            Write-Error "Error analyzing default domain password policy: $($_.Exception.Message)"
            Write-Verbose "Stack trace: $($_.ScriptStackTrace)"
        }

        Write-Host "Password Policy analysis completed." -ForegroundColor Green
        Write-Verbose "Total policies with issues: $($results.Count)"

        return $results
    }
    catch {
        Write-Error "Fatal error in Get-PasswordPolicyAnalysis: $($_.Exception.Message)"
        Write-Verbose "Stack trace: $($_.ScriptStackTrace)"
        return @{}
    }
}

#endregion
