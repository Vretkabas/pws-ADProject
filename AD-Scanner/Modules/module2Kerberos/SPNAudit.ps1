# very helpful ==> https://adsecurity.org/?p=3458
# deze file zal SPN accounts auditen in de AD
Import-Module ActiveDirectory

# Zoek alle service accounts in de AD
function Get-ServiceAccounts {
    $serviceAccounts = Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties *
    return $serviceAccounts
}
# Get-ServiceAccounts
# #1 encyrptie controleren op service accounts
function Get-EncryptionType {
    param($servicePrincipalName)

    # Encryption type flags (bitmask)
    $encryptionFlags = @{
        1  = "DES-CBC-CRC"
        2  = "DES-CBC-MD5"
        4  = "RC4-HMAC"
        8  = "AES128-CTS-HMAC-SHA1-96"
        16 = "AES256-CTS-HMAC-SHA1-96"
    }

    $spnList = @()

    foreach ($spn in $servicePrincipalName) {
        # Haal user details op met encryption types
        $spnDetails = Get-ADUser $spn.SamAccountName -Properties 'msDS-SupportedEncryptionTypes', ServicePrincipalName

        # Parse de encryption type bitmask
        $encTypeValue = $spnDetails.'msDS-SupportedEncryptionTypes'
        $enabledEncTypes = @()

        if ($null -eq $encTypeValue -or $encTypeValue -eq 0) {
            $enabledEncTypes += "Not configured (defaults to RC4)"
        }
        else {
            # Check elke bit met bitwise AND
            foreach ($flag in $encryptionFlags.Keys | Sort-Object) {
                if ($encTypeValue -band $flag) {
                    $enabledEncTypes += $encryptionFlags[$flag]
                }
            }
        }

        # Maak resultaat object
        $hasAES = ($encTypeValue -band 24) -gt 0              # AES128 (8) + AES256 (16) = 24
        $hasDES = ($encTypeValue -band 3) -gt 0               # DES-CBC-CRC (1) + DES-CBC-MD5 (2) = 3
        $hasRC4 = ($encTypeValue -band 4) -gt 0 -or ($null -eq $encTypeValue -or $encTypeValue -eq 0)  # RC4 (4) or not configured

        $result = [PSCustomObject]@{
            SamAccountName        = $spnDetails.SamAccountName
            ServicePrincipalNames = ($spnDetails.ServicePrincipalName -join "; ")
            EncryptionTypeValue   = $encTypeValue
            EncryptionTypes       = ($enabledEncTypes -join ", ")
            HasDES                = $hasDES
            HasRC4                = $hasRC4
            HasRC4Only            = $hasRC4 -and -not $hasAES -and -not $hasDES  # Only RC4, no AES or DES
            HasAES                = $hasAES
            HasAESOnly            = $hasAES -and -not $hasRC4 -and -not $hasDES  # Only AES (best practice)
            HasWeakEncryption     = ($hasDES -or ($hasRC4 -and -not $hasAES))    # DES OR (RC4 without AES)
        }

        $spnList += $result
    }

    return $spnList
}

# #2 Account settings SPN accounts controleren 
function Get-SPNAccountSettings {
    param($servicePrincipalName)
    
    # Alle pw gerelateerde settings ophalen
    $pswSettings = @()

    # Elke SPN acc afgaan
    foreach ($spn in $servicePrincipalName) {

        # account can be disabled so skip if we see this account in disabled state
        $isKrbtgt = $spn.SamAccountName -eq "krbtgt"

        $passwordDetailsSPN = [PSCustomObject]@{
            samAccountName                    = $spn.SamAccountName
            servicePrincipalName              = $spn.ServicePrincipalName
            passwordLastSet                   = $spn.PasswordLastSet
            passwordNeverExpires              = $spn.PasswordNeverExpires
            passwordNotRequired               = $spn.PasswordNotRequired
            cannotChangePassword              = $spn.CannotChangePassword
            passwordExpired                   = $spn.PasswordExpired
            enabled                           = if (-not $isKrbtgt) { $spn.Enabled } else { $null }
            lockedOut                         = $spn.LockedOut
            useDESKeyOnly                     = $spn.useDESKeyOnly
            allowReversiblePasswordEncryption = $spn.allowReversiblePasswordEncryption
            doesNotRequirePreAuth             = $spn.doesNotRequirePreAuth
            trustedForDelegation              = $spn.trustedForDelegation
            trustedToAuthForDelegation        = $spn.TrustedToAuthForDelegation
            accountNotDelegated               = $spn.AccountNotDelegated
            passwordAgeDays                   = if ($spn.PasswordLastSet) {
                (New-TimeSpan -Start $spn.PasswordLastSet -End (Get-Date)).Days
            }
            else { $null }

        }
        # Alle resultaten toevoegen aan array
        $pswSettings += $passwordDetailsSPN
    }

    return $pswSettings
}

# Get-SPNAccountSettings -servicePrincipalName $(Get-ServiceAccounts)
# Get-EncryptionType -servicePrincipalName $(Get-ServiceAccounts)