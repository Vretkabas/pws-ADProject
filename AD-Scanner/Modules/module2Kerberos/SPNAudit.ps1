<#
.SYNOPSIS
    SPN (Service Principal Name) audit functions for Module 2

.DESCRIPTION
    Contains functions to audit SPN accounts, encryption types, and Kerberos-related settings.
    Includes parameter validation and comprehensive error handling.

.NOTES
    Helpful reference: https://adsecurity.org/?p=3458
#>

Import-Module ActiveDirectory

#region Helper Functions

<#
.SYNOPSIS
    Displays SPN search results with color-coded output
.PARAMETER Accounts
    Array of account objects to display
.PARAMETER MessageFound
    Message to display when accounts are found
.PARAMETER MessageNotFound
    Message to display when no accounts are found
#>
function Show-SPNResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [Object[]]$Accounts,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$MessageFound,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$MessageNotFound
    )

    try {
        # Skip output in silent mode (during re-scan)
        if ($global:SilentScan) {
            return
        }

        if ($Accounts -and $Accounts.Count -gt 0) {
            $count = ($Accounts | Measure-Object).Count
            Write-Host "$count $MessageFound" -ForegroundColor Yellow
        }
        else {
            Write-Host $MessageNotFound -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "Error displaying SPN results: $($_.Exception.Message)"
    }
}

#endregion

#region SPN Account Discovery

<#
.SYNOPSIS
    Finds all service accounts with SPNs in Active Directory
.OUTPUTS
    Array of service account objects with all properties
#>
function Get-ServiceAccounts {
    [CmdletBinding()]
    [OutputType([Object[]])]
    param()

    try {
        $serviceAccounts = Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties * -ErrorAction Stop

        Write-Verbose "Found $($serviceAccounts.Count) service accounts with SPNs"

        return $serviceAccounts
    }
    catch {
        Write-Error "Failed to retrieve service accounts: $($_.Exception.Message)"
        return @()
    }
}

#endregion

#region Encryption Analysis

<#
.SYNOPSIS
    Analyzes encryption types configured for SPN accounts
.PARAMETER servicePrincipalName
    Array of service principal name objects to analyze
.DESCRIPTION
    Checks the msDS-SupportedEncryptionTypes attribute to identify weak encryption.
    Flags accounts using DES or RC4-only encryption as vulnerable.
.OUTPUTS
    Array of objects containing encryption type analysis for each SPN account
#>
function Get-EncryptionType {
    [CmdletBinding()]
    [OutputType([Object[]])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [Object[]]$servicePrincipalName
    )

    begin {
        # Encryption type flags (bitmask)
        $encryptionFlags = @{
            1  = "DES-CBC-CRC"
            2  = "DES-CBC-MD5"
            4  = "RC4-HMAC"
            8  = "AES128-CTS-HMAC-SHA1-96"
            16 = "AES256-CTS-HMAC-SHA1-96"
        }

        $spnList = @()
    }

    process {
        try {
            foreach ($spn in $servicePrincipalName) {
                try {
                    # Get user details with encryption types
                    $spnDetails = Get-ADUser $spn.SamAccountName -Properties 'msDS-SupportedEncryptionTypes', ServicePrincipalName -ErrorAction Stop

                    # Parse the encryption type bitmask
                    $encTypeValue = $spnDetails.'msDS-SupportedEncryptionTypes'
                    $enabledEncTypes = @()

                    if ($null -eq $encTypeValue -or $encTypeValue -eq 0) {
                        $enabledEncTypes += "Not configured (defaults to RC4)"
                    }
                    else {
                        # Check each bit with bitwise AND
                        foreach ($flag in $encryptionFlags.Keys | Sort-Object) {
                            if ($encTypeValue -band $flag) {
                                $enabledEncTypes += $encryptionFlags[$flag]
                            }
                        }
                    }

                    # Create result object
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
                catch {
                    Write-Verbose "Could not analyze encryption for $($spn.SamAccountName): $($_.Exception.Message)"
                    # Continue processing other accounts
                }
            }
        }
        catch {
            Write-Warning "Error processing encryption types: $($_.Exception.Message)"
        }
    }

    end {
        return $spnList
    }
}

#endregion

#region Account Settings Analysis

<#
.SYNOPSIS
    Analyzes account settings for SPN accounts
.PARAMETER servicePrincipalName
    Array of service principal name objects to analyze
.DESCRIPTION
    Checks password and security settings for SPN accounts including:
    - Password expiration, age, and related settings
    - Delegation settings (unconstrained/constrained)
    - Kerberos pre-authentication
    - DES key usage and reversible encryption
.OUTPUTS
    Array of objects containing detailed account settings for each SPN
#>
function Get-SPNAccountSettings {
    [CmdletBinding()]
    [OutputType([Object[]])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [Object[]]$servicePrincipalName
    )

    begin {
        $pswSettings = @()
    }

    process {
        try {
            foreach ($spn in $servicePrincipalName) {
                try {
                    # Skip disabled state check for krbtgt account
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

                    $pswSettings += $passwordDetailsSPN
                }
                catch {
                    Write-Verbose "Could not get settings for $($spn.SamAccountName): $($_.Exception.Message)"
                    # Continue processing other accounts
                }
            }
        }
        catch {
            Write-Warning "Error processing SPN account settings: $($_.Exception.Message)"
        }
    }

    end {
        return $pswSettings
    }
}

#endregion

#region Password Policy Analysis

<#
.SYNOPSIS
    Retrieves Fine-Grained Password Policies (FGPP) for SPN accounts
.DESCRIPTION
    Uses functions from passwordSettings.ps1 to analyze password policies.
    Dot-sources the passwordSettings.ps1 file from module1dangerousAccounts.
.OUTPUTS
    Password policy analysis results for SPN accounts
#>
function Get-PasswordPoliciesSPN {
    [CmdletBinding()]
    [OutputType([Object])]
    param()

    try {
        # Dot-source password settings functions from module 1
        $passwordSettingsPath = "$PSScriptRoot\..\module1dangerousAccounts\passwordSettings.ps1"

        if (-not (Test-Path $passwordSettingsPath)) {
            Write-Error "Password settings file not found at: $passwordSettingsPath"
            return $null
        }

        . $passwordSettingsPath

        $passwordPoliciesSPN = Get-PasswordPolicyAnalysis -isSPNCK $true -ErrorAction Stop

        return $passwordPoliciesSPN
    }
    catch {
        Write-Error "Failed to retrieve password policies for SPNs: $($_.Exception.Message)"
        return $null
    }
}

#endregion
