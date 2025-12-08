# Deze module analyseert password policies binnen Active Directory
#
# Functionaliteit:
# 1. Default Domain Password Policy - De basis policy die voor alle users geldt
# 2. Fine-Grained Password Policies (FGPP) - Specifieke policies voor groepen/users
# 3. GPO Password Policies - Password settings geconfigureerd via Group Policy Objects
#
# De module controleert:
# - Of de ingestelde password policies voldoen aan security best practices
# - Welke policies daadwerkelijk van toepassing zijn (rekening houdend met precedence)
# - Of er conflicten zijn tussen meerdere GPOs met password settings
# - Of FGPPs correct toegewezen zijn aan de juiste groepen
#
# Output: Bevindingen met severity levels (Critical, High, Medium, Low) voor rapportage


# Eerst beginnen met de default password policy
function Get-DefaultPasswordPolicy {
    $defaultPolicy = Get-ADDefaultDomainPasswordPolicy
    $domainDN = (Get-ADDomain).DistinguishedName

    $settings = [PSCustomObject]@{
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

    return $settings
}

# Controleer of er FGPP's bestaan
function Get-FGPPPolicies {
    $fgppPolicies = Get-ADFineGrainedPasswordPolicy -Filter * -Properties AppliesTo, Name, Precedence

    $results = @()

    foreach ($fgpp in $fgppPolicies) {
        # Haal de groepen/users op waar deze FGPP op van toepassing is
        $appliesTo = @()
        foreach ($target in $fgpp.AppliesTo) {
            # $target = Distinguished Name (DN) van een groep of user
            # Bijvoorbeeld: "CN=Domain Admins,CN=Users,DC=corp,DC=testlab,DC=local"
            try {
                # Haal het AD object op (groep of user)
                $adObject = Get-ADObject -Identity $target -Properties Name, ObjectClass

                # Maak een custom object met duidelijke info
                $appliesTo += [PSCustomObject]@{
                    Name = $adObject.Name                              # Bijvoorbeeld: "Domain Admins"
                    Type = $adObject.ObjectClass                       # Bijvoorbeeld: "group" of "user"
                    DistinguishedName = $adObject.DistinguishedName
                }
            }
            catch {
                Write-Warning "Could not resolve target: $target"
            }
        }

        $settings = [PSCustomObject]@{
            PolicyName                  = $fgpp.Name                  
            PolicyType                  = "FGPP"
            Precedence                  = $fgpp.Precedence          # Hoe lager het nummer, hoe hoger de prioriteit
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

        $results += $settings
    }

    return $results
}




# Functie om te controleren of policy goed is of niet
function Get-PasswordPolicyCheck {
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Policy,

        [Parameter(Mandatory=$false)]
        [string]$TargetName,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Default', 'FGPP', 'OU', 'Group', 'User', 'GPO')]
        [string]$TargetType = 'Default',

        [Parameter(Mandatory=$false)]
        [hashtable]$RequiredSettings = @{
            MinPasswordLength = @{
                MinValue = 12
                Severity = 'High'
                Description = 'Minimum password length should be at least 12 characters'
            }
            MaxPasswordAge = @{
                MaxValue = 90
                Severity = 'Medium'
                Description = 'Maximum password age should not exceed 90 days'
            }
            MinPasswordAge = @{
                MinValue = 1
                Severity = 'Low'
                Description = 'Minimum password age should be at least 1 day to prevent rapid password changes'
            }
            PasswordHistoryCount = @{
                MinValue = 24
                Severity = 'Medium'
                Description = 'Password history should remember at least 24 previous passwords'
            }
            ComplexityEnabled = @{
                RequiredValue = $true
                Severity = 'High'
                Description = 'Password complexity requirements must be enabled'
            }
            LockoutThreshold = @{
                MinValue = 3
                MaxValue = 5
                Severity = 'Medium'
                Description = 'Account lockout threshold should be between 3-5 attempts'
            }
            LockoutDuration = @{
                MinValue = 15
                Severity = 'Low'
                Description = 'Account lockout duration should be at least 15 minutes'
            }
            ReversibleEncryptionEnabled = @{
                RequiredValue = $false
                Severity = 'Critical'
                Description = 'Reversible encryption must be disabled'
            }
        }
    )

    $findings = @()

    # Check MinPasswordLength
    if ($Policy.MinPasswordLength -lt $RequiredSettings.MinPasswordLength.MinValue) {
        $findings += [PSCustomObject]@{
            TargetName = $TargetName
            TargetType = $TargetType
            Severity = $RequiredSettings.MinPasswordLength.Severity
            Setting = 'MinPasswordLength'
            CurrentValue = $Policy.MinPasswordLength
            ExpectedValue = "At least $($RequiredSettings.MinPasswordLength.MinValue)"
            Description = $RequiredSettings.MinPasswordLength.Description
        }
    }

    # Check MaxPasswordAge
    if ($Policy.MaxPasswordAge -gt $RequiredSettings.MaxPasswordAge.MaxValue -or $Policy.MaxPasswordAge -eq 0) {
        $findings += [PSCustomObject]@{
            TargetName = $TargetName
            TargetType = $TargetType
            Severity = $RequiredSettings.MaxPasswordAge.Severity
            Setting = 'MaxPasswordAge'
            CurrentValue = if ($Policy.MaxPasswordAge -eq 0) { "Never expires" } else { "$($Policy.MaxPasswordAge) days" }
            ExpectedValue = "At most $($RequiredSettings.MaxPasswordAge.MaxValue) days"
            Description = $RequiredSettings.MaxPasswordAge.Description
        }
    }

    # Check MinPasswordAge
    if ($Policy.MinPasswordAge -lt $RequiredSettings.MinPasswordAge.MinValue) {
        $findings += [PSCustomObject]@{
            TargetName = $TargetName
            TargetType = $TargetType
            Severity = $RequiredSettings.MinPasswordAge.Severity
            Setting = 'MinPasswordAge'
            CurrentValue = "$($Policy.MinPasswordAge) days"
            ExpectedValue = "At least $($RequiredSettings.MinPasswordAge.MinValue) day"
            Description = $RequiredSettings.MinPasswordAge.Description
        }
    }

    # Check PasswordHistoryCount
    if ($Policy.PasswordHistoryCount -lt $RequiredSettings.PasswordHistoryCount.MinValue) {
        $findings += [PSCustomObject]@{
            TargetName = $TargetName
            TargetType = $TargetType
            Severity = $RequiredSettings.PasswordHistoryCount.Severity
            Setting = 'PasswordHistoryCount'
            CurrentValue = $Policy.PasswordHistoryCount
            ExpectedValue = "At least $($RequiredSettings.PasswordHistoryCount.MinValue)"
            Description = $RequiredSettings.PasswordHistoryCount.Description
        }
    }

    # Check ComplexityEnabled
    if ($Policy.ComplexityEnabled -ne $RequiredSettings.ComplexityEnabled.RequiredValue) {
        $findings += [PSCustomObject]@{
            TargetName = $TargetName
            TargetType = $TargetType
            Severity = $RequiredSettings.ComplexityEnabled.Severity
            Setting = 'ComplexityEnabled'
            CurrentValue = $Policy.ComplexityEnabled
            ExpectedValue = $RequiredSettings.ComplexityEnabled.RequiredValue
            Description = $RequiredSettings.ComplexityEnabled.Description
        }
    }

    # Check LockoutThreshold
    if ($Policy.LockoutThreshold -eq 0 -or
        $Policy.LockoutThreshold -lt $RequiredSettings.LockoutThreshold.MinValue -or
        $Policy.LockoutThreshold -gt $RequiredSettings.LockoutThreshold.MaxValue) {
        $findings += [PSCustomObject]@{
            TargetName = $TargetName
            TargetType = $TargetType
            Severity = $RequiredSettings.LockoutThreshold.Severity
            Setting = 'LockoutThreshold'
            CurrentValue = if ($Policy.LockoutThreshold -eq 0) { "Disabled" } else { $Policy.LockoutThreshold }
            ExpectedValue = "$($RequiredSettings.LockoutThreshold.MinValue)-$($RequiredSettings.LockoutThreshold.MaxValue) attempts"
            Description = $RequiredSettings.LockoutThreshold.Description
        }
    }

    # Check LockoutDuration
    if ($Policy.LockoutDuration -lt $RequiredSettings.LockoutDuration.MinValue) {
        $findings += [PSCustomObject]@{
            TargetName = $TargetName
            TargetType = $TargetType
            Severity = $RequiredSettings.LockoutDuration.Severity
            Setting = 'LockoutDuration'
            CurrentValue = "$($Policy.LockoutDuration) minutes"
            ExpectedValue = "At least $($RequiredSettings.LockoutDuration.MinValue) minutes"
            Description = $RequiredSettings.LockoutDuration.Description
        }
    }

    # Check ReversibleEncryptionEnabled (CRITICAL!)
    if ($Policy.ReversibleEncryptionEnabled -ne $RequiredSettings.ReversibleEncryptionEnabled.RequiredValue) {
        $findings += [PSCustomObject]@{
            TargetName = $TargetName
            TargetType = $TargetType
            Severity = $RequiredSettings.ReversibleEncryptionEnabled.Severity
            Setting = 'ReversibleEncryptionEnabled'
            CurrentValue = $Policy.ReversibleEncryptionEnabled
            ExpectedValue = $RequiredSettings.ReversibleEncryptionEnabled.RequiredValue
            Description = $RequiredSettings.ReversibleEncryptionEnabled.Description
        }
    }

    # Return results
    return $findings
}

# Functie om alle GPO's te checken op password policies
# TODO
function Get-GPOPasswordPolicies {
}


# Hoofdfunctie om alle password policies te checken
function Invoke-PasswordPolicyAudit {
    [CmdletBinding()]
    param()

    $allFindings = @()

    # Check Default Domain Password Policy
    Write-Verbose "Checking Default Domain Password Policy..."
    $defaultPolicy = Get-DefaultPasswordPolicy
    $findings = Get-PasswordPolicyCheck -Policy $defaultPolicy -TargetName $defaultPolicy.PolicyName -TargetType $defaultPolicy.PolicyType
    $allFindings += $findings

    # Check FGPP
    Write-Verbose "Checking Fine-Grained Password Policies..."
    $fgppPolicies = Get-FGPPPolicies

    foreach ($fgpp in $fgppPolicies) {
        # Check de FGPP zelf
        Write-Verbose "Checking FGPP: $($fgpp.PolicyName)"

        # Voor elke groep/user waar deze FGPP op van toepassing is
        if ($fgpp.AppliesTo.Count -gt 0) {
            # fgpp heeft targets!
            foreach ($target in $fgpp.AppliesTo) {
                $findings = Get-PasswordPolicyCheck -Policy $fgpp -TargetName $target.Name -TargetType $target.Type

                # Voeg extra info toe over de FGPP
                foreach ($finding in $findings) {
                    $finding | Add-Member -NotePropertyName 'PolicyName' -NotePropertyValue $fgpp.PolicyName -Force
                    $finding | Add-Member -NotePropertyName 'Precedence' -NotePropertyValue $fgpp.Precedence -Force
                    $finding | Add-Member -NotePropertyName 'PolicyType' -NotePropertyValue 'FGPP' -Force
                }

                $allFindings += $findings
            }
        } else {
            Write-Warning "FGPP '$($fgpp.PolicyName)' is not applied to any users or groups!"
        }
    }

    return $allFindings
}

# Invoke-PasswordPolicyAudit
Invoke-PasswordPolicyAudit