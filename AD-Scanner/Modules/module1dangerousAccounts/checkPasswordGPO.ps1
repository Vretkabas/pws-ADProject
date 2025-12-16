# Deze module verzamelt password policy data uit Active Directory
# Severity checks worden gedaan in checkInfo.ps1

Import-Module ActiveDirectory

# Haal de default domain password policy op
function Get-DefaultPasswordPolicy {
    $defaultPolicy = Get-ADDefaultDomainPasswordPolicy
    $domainDN = (Get-ADDomain).DistinguishedName

    return [PSCustomObject]@{
        PolicyName                  = "Default Domain Password Policy"
        PolicyType                  = "Default"
        AppliesTo                   = $domainDN
        MinPasswordLength           = $defaultPolicy.MinPasswordLength
        MinPasswordAge              = $defaultPolicy.MinPasswordAge.Days
        MaxPasswordAge              = $defaultPolicy.MaxPasswordAge.Days
        PasswordHistoryCount        = $defaultPolicy.PasswordHistoryCount
        ComplexityEnabled           = $defaultPolicy.ComplexityEnabled
        LockoutThreshold            = $defaultPolicy.LockoutThreshold
        LockoutDuration             = $defaultPolicy.LockoutDuration.Minutes
        LockoutObservationWindow    = $defaultPolicy.LockoutObservationWindow.Minutes
        ReversibleEncryptionEnabled = $defaultPolicy.ReversibleEncryptionEnabled
    }
}

# Haal alle Fine-Grained Password Policies op met hun targets
function Get-FGPPPolicies {
    # Haal alle FGPP's op en sorteer op precedence (laagste eerst)
    $fgpps = Get-ADFineGrainedPasswordPolicy -Filter * -Properties AppliesTo, Name, Precedence | Sort-Object Precedence

    # Track welke gebruikers al zijn toegewezen aan een FGPP met hogere prioriteit
    $assignedUsers = @{}
    $results = @()

    # Voor elke FGPP, verzamel data en linked users
    foreach ($fgpp in $fgpps) {
        # Haal alle users/groups op waar deze FGPP aan gekoppeld is
        $linkedSubjects = Get-ADFineGrainedPasswordPolicySubject -Identity $fgpp.Name -ErrorAction SilentlyContinue

        # Verzamel alle SAMAccountNames van gebruikers die deze policy krijgen
        $userSAMAccountNames = @()

        foreach ($subject in $linkedSubjects) {
            if ($subject.ObjectClass -eq 'user') {
                # Directe gebruiker
                $userSAMAccountNames += $subject.SamAccountName
            }
            elseif ($subject.ObjectClass -eq 'group') {
                # Haal alle gebruikers uit de groep (recursief voor geneste groepen)
                try {
                    $groupMembers = Get-ADGroupMember -Identity $subject.DistinguishedName -Recursive -ErrorAction SilentlyContinue |
                                    Where-Object { $_.objectClass -eq 'user' }

                    foreach ($member in $groupMembers) {
                        $userSAMAccountNames += $member.SamAccountName
                    }
                }
                catch {
                    Write-Warning "Kon leden van groep '$($subject.Name)' niet ophalen: $_"
                }
            }
        }

        # Verwijder duplicaten
        $userSAMAccountNames = $userSAMAccountNames | Select-Object -Unique

        # Filter gebruikers die al zijn toegewezen aan een FGPP met hogere prioriteit (lagere precedence)
        $finalUsers = @()
        foreach ($user in $userSAMAccountNames) {
            if (-not $assignedUsers.ContainsKey($user)) {
                $finalUsers += $user
                # Markeer deze gebruiker als toegewezen
                $assignedUsers[$user] = $fgpp.Precedence
            }
        }

        # Sorteer de uiteindelijke lijst
        $finalUsers = $finalUsers | Sort-Object

        # Maak resultaat object met comma-separated SAMAccountNames
        $results += [PSCustomObject]@{
            PolicyName                  = $fgpp.Name
            PolicyType                  = "FGPP"
            Precedence                  = $fgpp.Precedence
            AppliedUsers                = ($finalUsers -join ',')
            AppliedUserCount            = $finalUsers.Count
            MinPasswordLength           = $fgpp.MinPasswordLength
            MinPasswordAge              = $fgpp.MinPasswordAge.Days
            MaxPasswordAge              = $fgpp.MaxPasswordAge.Days
            PasswordHistoryCount        = $fgpp.PasswordHistoryCount
            ComplexityEnabled           = $fgpp.ComplexityEnabled
            LockoutThreshold            = $fgpp.LockoutThreshold
            LockoutDuration             = $fgpp.LockoutDuration.Minutes
            LockoutObservationWindow    = $fgpp.LockoutObservationWindow.Minutes
            ReversibleEncryptionEnabled = $fgpp.ReversibleEncryptionEnabled
        }
    }

    return $results
}

# Hoofdfunctie om alle password policies te verzamelen
function Get-AllPasswordPolicies {
    $allPolicies = @()

    # Haal Default Domain Password Policy op
    $allPolicies += Get-DefaultPasswordPolicy

    # Haal alle FGPPs op
    $allPolicies += Get-FGPPPolicies

    return $allPolicies
}

# Return alle password policies
Get-AllPasswordPolicies
