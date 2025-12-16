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

# Haal alle Fine-Grained Password Policies op
function Get-FGPPPolicies {
    $fgppPolicies = Get-ADFineGrainedPasswordPolicy -Filter * -Properties AppliesTo, Name, Precedence
    $results = @()

    foreach ($fgpp in $fgppPolicies) {
        # Haal de groepen/users op waar deze FGPP op van toepassing is
        $appliesTo = @()
        foreach ($target in $fgpp.AppliesTo) {
            try {
                $adObject = Get-ADObject -Identity $target -Properties Name, ObjectClass
                $appliesTo += [PSCustomObject]@{
                    Name              = $adObject.Name
                    Type              = $adObject.ObjectClass
                    DistinguishedName = $adObject.DistinguishedName
                }
            }
            catch {
                Write-Warning "Could not resolve FGPP target: $target"
            }
        }

        $results += [PSCustomObject]@{
            PolicyName                  = $fgpp.Name
            PolicyType                  = "FGPP"
            Precedence                  = $fgpp.Precedence
            AppliesTo                   = $appliesTo
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
