# Deze module verzamelt password policy data uit Active Directory
# Alleen ruwe data + issues - severity/recommendations worden in checkInfo.ps1 gedefinieerd

Import-Module ActiveDirectory

#region Helper Functions

function Get-PolicyIssues {
    param(
        [object]$Policy,
        [string]$PolicyType,
        [int]$minPasswordLengthCK = 12,
        [int]$maxPasswordAgeDaysCK = 90,
        [bool]$isSPNCK = $false  # We dont check lockout for SPN accounts (purposely block SPN accounts)

    )

    $issues = @()

    # Min Password Length check (< 12 is zwak)
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

    # Max Password Age check (0 = never, >365 = te lang)
    $maxAgeDays = $Policy.MaxPasswordAge.Days

    # Voor SPN accounts met 24+ karakters wachtwoord: skip de max age check (sterk genoeg)
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

    # Min Password Age check (0 = geen minimum)
    if ($Policy.MinPasswordAge.Days -eq 0) {
        $issues += [PSCustomObject]@{
            Setting      = "Minimum Password Age"
            CurrentValue = "0 days (none)"
        }
    }

    # Password History check (< 24 is zwak)
    if ($Policy.PasswordHistoryCount -lt 24) {
        $issues += [PSCustomObject]@{
            Setting      = "Password History"
            CurrentValue = $Policy.PasswordHistoryCount
        }
    }

    # Complexity check
    if (-not $Policy.ComplexityEnabled) {
        $issues += [PSCustomObject]@{
            Setting      = "Password Complexity"
            CurrentValue = "Disabled"
        }
    }

    # Lockout Threshold check (0 = geen lockout)
    if ($Policy.LockoutThreshold -eq 0 -and $isSPNCK -eq $false) {
        $issues += [PSCustomObject]@{
            Setting      = "Account Lockout Threshold"
            CurrentValue = "Disabled (no lockout)"
        }
    }

    # Lockout Duration check (alleen als lockout aan staat, < 15 min is zwak)
    if ($Policy.LockoutThreshold -gt 0 -and $isSPNCK -eq $false) {
        $lockoutMinutes = $Policy.LockoutDuration.TotalMinutes
        if ($lockoutMinutes -lt 15 -and $lockoutMinutes -ne 0) {
            $issues += [PSCustomObject]@{
                Setting      = "Lockout Duration"
                CurrentValue = "$lockoutMinutes minutes"
            }
        }
    }

    # Reversible Encryption check (CRITICAL)
    if ($Policy.ReversibleEncryptionEnabled) {
        $issues += [PSCustomObject]@{
            Setting      = "Reversible Encryption"
            CurrentValue = "Enabled"
        }
    }

    return $issues
}

#endregion

#region Main Function

function Get-PasswordPolicyAnalysis {
    param(
        [bool]$isSPNCK = $false
    )
    Write-Host "`nAnalyzing Password Policies..." -ForegroundColor Cyan

    $results = @{}

    # === FGPP Policies ===
    $fgpps = Get-ADFineGrainedPasswordPolicy -Filter * -Properties * | Sort-Object Precedence
    $assignedUsers = @{}  # Track welke users al een FGPP hebben

    foreach ($fgpp in $fgpps) {
        # Haal users op die onder deze FGPP vallen
        $linkedSubjects = Get-ADFineGrainedPasswordPolicySubject -Identity $fgpp.Name -ErrorAction SilentlyContinue
        $userSAMAccountNames = @()

        foreach ($subject in $linkedSubjects) {
            if ($subject.ObjectClass -eq 'user') {
                $userDetails = Get-ADUser -Identity $subject.DistinguishedName -Properties ServicePrincipalName -ErrorAction SilentlyContinue
                if ($userDetails) {
                    # if SPN check is enabled: only SPN accounts (service accounts)
                    # if not enabled: only normal accounts (no SPN)
                    if ($isSPNCK -and $userDetails.ServicePrincipalName) {
                        $userSAMAccountNames += $subject.SamAccountName
                    }
                    elseif (-not $isSPNCK -and -not $userDetails.ServicePrincipalName) {
                        $userSAMAccountNames += $subject.SamAccountName
                    }
                }
            }
            elseif ($subject.ObjectClass -eq 'group') {
                try {
                    $groupMembers = Get-ADGroupMember -Identity $subject.DistinguishedName -Recursive -ErrorAction SilentlyContinue |
                    Where-Object { $_.objectClass -eq 'user' }
                    foreach ($member in $groupMembers) {
                        $userDetails = Get-ADUser -Identity $member.DistinguishedName -Properties ServicePrincipalName -ErrorAction SilentlyContinue
                        if ($userDetails) {
                            # if SPN check is enabled: only SPN accounts (service accounts)
                            # if not enabled: only normal accounts (no SPN)
                            if ($isSPNCK -and $userDetails.ServicePrincipalName) {
                                $userSAMAccountNames += $member.SamAccountName
                            }
                            elseif (-not $isSPNCK -and -not $userDetails.ServicePrincipalName) {
                                $userSAMAccountNames += $member.SamAccountName
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Kon leden van groep '$($subject.Name)' niet ophalen: $_"
                }
            }
        }

        $userSAMAccountNames = $userSAMAccountNames | Select-Object -Unique

        # Filter users die al een hogere prioriteit FGPP hebben
        $finalUsers = @()
        foreach ($user in $userSAMAccountNames) {
            if (-not $assignedUsers.ContainsKey($user)) {
                $finalUsers += $user
                $assignedUsers[$user] = $fgpp.Precedence
            }
        }
        $finalUsers = $finalUsers | Sort-Object

        # Check voor issues in deze policy
        # if its SPN we need stronger settings
        if ($isSPNCK -and $finalUsers.Count -gt 0) {
            $issues = Get-PolicyIssues -Policy $fgpp -PolicyType "FGPP" -minPasswordLengthCK 24 -maxPasswordAgeDaysCK 120 -isSPNCK $true
        }
        else {
            $issues = Get-PolicyIssues -Policy $fgpp -PolicyType "FGPP"
        }

        # Alleen toevoegen als er issues zijn EN er zijn non-SPN users
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
            Write-Host "  [SKIP] $($fgpp.Name): Has issues but only applies to service accounts (will be checked in Module 2)" -ForegroundColor Cyan
        }
        else {
            Write-Host "  [OK] $($fgpp.Name): No issues found" -ForegroundColor Green
        }
    }

    # === Default Domain Password Policy ===
    $defaultPolicy = Get-ADDefaultDomainPasswordPolicy

    # Get all users without FGPP
    if ($isSPNCK) {
        # Only SPN accounts
        $allUsers = Get-ADUser -Filter { Enabled -eq $true } -Properties ServicePrincipalName |
        Where-Object { $_.ServicePrincipalName } |
        Select-Object -ExpandProperty SamAccountName
    }
    else {
        # Only non-SPN accounts
        $allUsers = Get-ADUser -Filter { Enabled -eq $true } -Properties ServicePrincipalName |
        Where-Object { -not $_.ServicePrincipalName } |
        Select-Object -ExpandProperty SamAccountName
    }

    $usersWithFGPP = $assignedUsers.Keys
    $defaultPolicyUsers = $allUsers | Where-Object { $_ -notin $usersWithFGPP } | Sort-Object

    # look for issues in default policy
    # if its SPN we need stronger settings
    if ($isSPNCK -and $defaultPolicyUsers.Count -gt 0) {
        $defaultIssues = Get-PolicyIssues -Policy $defaultPolicy -PolicyType "Default" -minPasswordLengthCK 24 -maxPasswordAgeDaysCK 120 -isSPNCK $true
    }
    else {
        $defaultIssues = Get-PolicyIssues -Policy $defaultPolicy -PolicyType "Default"
    }

    # Alleen toevoegen als er issues zijn EN er zijn non-SPN users
    if ($defaultIssues.Count -gt 0 -and $defaultPolicyUsers.Count -gt 0) {
        $results["Default Domain Password Policy"] = [PSCustomObject]@{
            PolicyType       = "Default"
            Precedence       = 999  # Laagste prioriteit
            AppliedUsers     = $defaultPolicyUsers
            AppliedUserCount = $defaultPolicyUsers.Count
            Issues           = $defaultIssues
        }

        Write-Host "  [!] Default Domain Password Policy: $($defaultIssues.Count) issue(s), $($defaultPolicyUsers.Count) user(s)" -ForegroundColor Yellow
    }
    elseif ($defaultIssues.Count -gt 0 -and $defaultPolicyUsers.Count -eq 0) {
        Write-Host "  [SKIP] Default Domain Password Policy: Has issues but only applies to service accounts (will be checked in Module 2)" -ForegroundColor Cyan
    }
    else {
        Write-Host "  [OK] Default Domain Password Policy: No issues found" -ForegroundColor Green
    }

    Write-Host "Password Policy analysis completed." -ForegroundColor Green

    return $results
}

#endregion
