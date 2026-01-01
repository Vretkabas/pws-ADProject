<#
.SYNOPSIS
    Pester tests for remediationFix.ps1 from Module 2 (Kerberos/SPN)

.DESCRIPTION
    Tests for Module 2 remediation fix functions.
    Includes unit tests for Kerberos and SPN-related fixes.
#>

BeforeAll {
    # Create stub functions for ActiveDirectory cmdlets
    function Set-ADUser {
        param($Identity, $PasswordNotRequired, $PasswordNeverExpires, $AllowReversiblePasswordEncryption, $Clear, $Replace, $ErrorAction)
    }
    function Set-ADAccountControl {
        param($Identity, $CannotChangePassword, $UseDESKeyOnly, $DoesNotRequirePreAuth, $TrustedForDelegation, $TrustedToAuthForDelegation, $ErrorAction)
    }
    function Disable-ADAccount {
        param($Identity, $ErrorAction)
    }

    # Load the functions
    $ModulePath = "$PSScriptRoot\..\Modules\module2Kerberos\remediationFix.ps1"
    . $ModulePath

    # Helper function to create mock accounts
    function New-MockAccount {
        param(
            [string]$Name = "TestUser",
            [string]$SamAccountName = "testuser"
        )
        return [PSCustomObject]@{
            Name           = $Name
            SamAccountName = $SamAccountName
        }
    }
}

Describe "Set-PasswordNeverExpiresFix" {
    Context "Successful Remediation" {
        BeforeEach {
            Mock Set-ADUser { }
            Mock Write-Host { }
            Mock Write-Warning { }
        }

        It "Should call Set-ADUser with correct parameters" {
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Set-PasswordNeverExpiresFix -Accounts @($account)

            Should -Invoke Set-ADUser -Times 1 -ParameterFilter {
                $Identity -eq "user1" -and
                $PasswordNeverExpires -eq $false
            }
        }

        It "Should process multiple accounts" {
            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            Set-PasswordNeverExpiresFix -Accounts $accounts

            Should -Invoke Set-ADUser -Times 2
        }
    }

    Context "Error Handling" {
        BeforeEach {
            Mock Write-Host { }
            Mock Write-Warning { }
        }

        It "Should continue processing after individual account failure" {
            Mock Set-ADUser {
                if ($Identity -eq "user1") { throw "AD Error" }
            }

            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            { Set-PasswordNeverExpiresFix -Accounts $accounts } | Should -Not -Throw
            Should -Invoke Set-ADUser -Times 2
            Should -Invoke Write-Warning -Times 1
        }
    }

    Context "Parameter Validation" {
        It "Should reject null Accounts" {
            { Set-PasswordNeverExpiresFix -Accounts $null } | Should -Throw
        }
    }
}

Describe "Set-PasswordNotRequiredFix" {
    Context "Successful Remediation" {
        BeforeEach {
            Mock Set-ADUser { }
            Mock Write-Host { }
            Mock Write-Warning { }
        }

        It "Should call Set-ADUser with correct parameters" {
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Set-PasswordNotRequiredFix -Accounts @($account)

            Should -Invoke Set-ADUser -Times 1 -ParameterFilter {
                $Identity -eq "user1" -and
                $PasswordNotRequired -eq $false
            }
        }

        It "Should process multiple accounts" {
            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            Set-PasswordNotRequiredFix -Accounts $accounts

            Should -Invoke Set-ADUser -Times 2
        }
    }

    Context "Error Handling" {
        BeforeEach {
            Mock Write-Host { }
            Mock Write-Warning { }
        }

        It "Should continue processing after individual account failure" {
            Mock Set-ADUser {
                if ($Identity -eq "user1") { throw "AD Error" }
            }

            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            { Set-PasswordNotRequiredFix -Accounts $accounts } | Should -Not -Throw
            Should -Invoke Set-ADUser -Times 2
            Should -Invoke Write-Warning -Times 1
        }
    }

    Context "Parameter Validation" {
        It "Should reject null Accounts" {
            { Set-PasswordNotRequiredFix -Accounts $null } | Should -Throw
        }
    }
}

Describe "Set-CannotChangePasswordFix" {
    Context "Successful Remediation" {
        BeforeEach {
            Mock Set-ADAccountControl { }
            Mock Write-Host { }
            Mock Write-Warning { }
        }

        It "Should call Set-ADAccountControl with correct parameters" {
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Set-CannotChangePasswordFix -Accounts @($account)

            Should -Invoke Set-ADAccountControl -Times 1 -ParameterFilter {
                $Identity -eq "user1" -and
                $CannotChangePassword -eq $false
            }
        }

        It "Should process multiple accounts" {
            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            Set-CannotChangePasswordFix -Accounts $accounts

            Should -Invoke Set-ADAccountControl -Times 2
        }
    }

    Context "Error Handling" {
        BeforeEach {
            Mock Write-Host { }
            Mock Write-Warning { }
        }

        It "Should continue processing after individual account failure" {
            Mock Set-ADAccountControl {
                if ($Identity -eq "user1") { throw "AD Error" }
            }

            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            { Set-CannotChangePasswordFix -Accounts $accounts } | Should -Not -Throw
            Should -Invoke Set-ADAccountControl -Times 2
            Should -Invoke Write-Warning -Times 1
        }
    }

    Context "Parameter Validation" {
        It "Should reject null Accounts" {
            { Set-CannotChangePasswordFix -Accounts $null } | Should -Throw
        }
    }
}

Describe "Set-UseDESKeyOnlyFix" {
    Context "Successful Remediation" {
        BeforeEach {
            Mock Set-ADAccountControl { }
            Mock Write-Host { }
            Mock Write-Warning { }
        }

        It "Should call Set-ADAccountControl with correct parameters" {
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Set-UseDESKeyOnlyFix -Accounts @($account)

            Should -Invoke Set-ADAccountControl -Times 1 -ParameterFilter {
                $Identity -eq "user1" -and
                $UseDESKeyOnly -eq $false
            }
        }

        It "Should process multiple accounts" {
            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            Set-UseDESKeyOnlyFix -Accounts $accounts

            Should -Invoke Set-ADAccountControl -Times 2
        }
    }

    Context "Error Handling" {
        BeforeEach {
            Mock Write-Host { }
            Mock Write-Warning { }
        }

        It "Should continue processing after individual account failure" {
            Mock Set-ADAccountControl {
                if ($Identity -eq "user1") { throw "AD Error" }
            }

            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            { Set-UseDESKeyOnlyFix -Accounts $accounts } | Should -Not -Throw
            Should -Invoke Set-ADAccountControl -Times 2
            Should -Invoke Write-Warning -Times 1
        }
    }

    Context "Parameter Validation" {
        It "Should reject null Accounts" {
            { Set-UseDESKeyOnlyFix -Accounts $null } | Should -Throw
        }
    }
}

Describe "Set-ReversiblePasswordEncryptionFix" {
    Context "Successful Remediation" {
        BeforeEach {
            Mock Set-ADUser { }
            Mock Write-Host { }
            Mock Write-Warning { }
        }

        It "Should call Set-ADUser with correct parameters" {
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Set-ReversiblePasswordEncryptionFix -Accounts @($account)

            Should -Invoke Set-ADUser -Times 1 -ParameterFilter {
                $Identity -eq "user1" -and
                $AllowReversiblePasswordEncryption -eq $false
            }
        }

        It "Should process multiple accounts" {
            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            Set-ReversiblePasswordEncryptionFix -Accounts $accounts

            Should -Invoke Set-ADUser -Times 2
        }
    }

    Context "Error Handling" {
        BeforeEach {
            Mock Write-Host { }
            Mock Write-Warning { }
        }

        It "Should continue processing after individual account failure" {
            Mock Set-ADUser {
                if ($Identity -eq "user1") { throw "AD Error" }
            }

            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            { Set-ReversiblePasswordEncryptionFix -Accounts $accounts } | Should -Not -Throw
            Should -Invoke Set-ADUser -Times 2
            Should -Invoke Write-Warning -Times 1
        }
    }

    Context "Parameter Validation" {
        It "Should reject null Accounts" {
            { Set-ReversiblePasswordEncryptionFix -Accounts $null } | Should -Throw
        }
    }
}

Describe "Set-RequirePreAuthFix" {
    Context "Successful Remediation" {
        BeforeEach {
            Mock Set-ADAccountControl { }
            Mock Write-Host { }
            Mock Write-Warning { }
        }

        It "Should call Set-ADAccountControl with correct parameters" {
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Set-RequirePreAuthFix -Accounts @($account)

            Should -Invoke Set-ADAccountControl -Times 1 -ParameterFilter {
                $Identity -eq "user1" -and
                $DoesNotRequirePreAuth -eq $false
            }
        }

        It "Should process multiple accounts" {
            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            Set-RequirePreAuthFix -Accounts $accounts

            Should -Invoke Set-ADAccountControl -Times 2
        }
    }

    Context "Error Handling" {
        BeforeEach {
            Mock Write-Host { }
            Mock Write-Warning { }
        }

        It "Should continue processing after individual account failure" {
            Mock Set-ADAccountControl {
                if ($Identity -eq "user1") { throw "AD Error" }
            }

            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            { Set-RequirePreAuthFix -Accounts $accounts } | Should -Not -Throw
            Should -Invoke Set-ADAccountControl -Times 2
            Should -Invoke Write-Warning -Times 1
        }
    }

    Context "Parameter Validation" {
        It "Should reject null Accounts" {
            { Set-RequirePreAuthFix -Accounts $null } | Should -Throw
        }
    }
}

Describe "Set-TrustedForDelegationFix" {
    Context "Successful Remediation" {
        BeforeEach {
            Mock Set-ADAccountControl { }
            Mock Write-Host { }
            Mock Write-Warning { }
        }

        It "Should call Set-ADAccountControl with correct parameters" {
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Set-TrustedForDelegationFix -Accounts @($account)

            Should -Invoke Set-ADAccountControl -Times 1 -ParameterFilter {
                $Identity -eq "user1" -and
                $TrustedForDelegation -eq $false
            }
        }

        It "Should display warning about breaking services" {
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Set-TrustedForDelegationFix -Accounts @($account)

            Should -Invoke Write-Host -Times 1 -ParameterFilter {
                $Object -like "*WARNING*delegation*"
            }
        }

        It "Should process multiple accounts" {
            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            Set-TrustedForDelegationFix -Accounts $accounts

            Should -Invoke Set-ADAccountControl -Times 2
        }
    }

    Context "Error Handling" {
        BeforeEach {
            Mock Write-Host { }
            Mock Write-Warning { }
        }

        It "Should continue processing after individual account failure" {
            Mock Set-ADAccountControl {
                if ($Identity -eq "user1") { throw "AD Error" }
            }

            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            { Set-TrustedForDelegationFix -Accounts $accounts } | Should -Not -Throw
            Should -Invoke Set-ADAccountControl -Times 2
            Should -Invoke Write-Warning -Times 1
        }
    }

    Context "Parameter Validation" {
        It "Should reject null Accounts" {
            { Set-TrustedForDelegationFix -Accounts $null } | Should -Throw
        }
    }
}

Describe "Set-TrustedToAuthForDelegationFix" {
    Context "Successful Remediation" {
        BeforeEach {
            Mock Set-ADUser { }
            Mock Set-ADAccountControl { }
            Mock Write-Host { }
            Mock Write-Warning { }
        }

        It "Should clear msDS-AllowedToDelegateTo attribute" {
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Set-TrustedToAuthForDelegationFix -Accounts @($account)

            Should -Invoke Set-ADUser -Times 1 -ParameterFilter {
                $Identity -eq "user1" -and
                $Clear -eq 'msDS-AllowedToDelegateTo'
            }
        }

        It "Should disable TrustedToAuthForDelegation flag" {
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Set-TrustedToAuthForDelegationFix -Accounts @($account)

            Should -Invoke Set-ADAccountControl -Times 1 -ParameterFilter {
                $Identity -eq "user1" -and
                $TrustedToAuthForDelegation -eq $false
            }
        }

        It "Should display warning about breaking services" {
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Set-TrustedToAuthForDelegationFix -Accounts @($account)

            Should -Invoke Write-Host -Times 1 -ParameterFilter {
                $Object -like "*WARNING*delegation*"
            }
        }

        It "Should process multiple accounts" {
            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            Set-TrustedToAuthForDelegationFix -Accounts $accounts

            Should -Invoke Set-ADUser -Times 2
            Should -Invoke Set-ADAccountControl -Times 2
        }
    }

    Context "Error Handling" {
        BeforeEach {
            Mock Write-Host { }
            Mock Write-Warning { }
        }

        It "Should continue processing after individual account failure" {
            Mock Set-ADUser {
                if ($Identity -eq "user1") { throw "AD Error" }
            }
            Mock Set-ADAccountControl { }

            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            { Set-TrustedToAuthForDelegationFix -Accounts $accounts } | Should -Not -Throw
            Should -Invoke Set-ADUser -Times 2
            Should -Invoke Write-Warning -Times 1
        }
    }

    Context "Parameter Validation" {
        It "Should reject null Accounts" {
            { Set-TrustedToAuthForDelegationFix -Accounts $null } | Should -Throw
        }
    }
}

Describe "Disable-SPNAccountsFix" {
    Context "Successful Remediation" {
        BeforeEach {
            Mock Disable-ADAccount { }
            Mock Write-Host { }
            Mock Write-Warning { }
        }

        It "Should call Disable-ADAccount with correct parameters" {
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Disable-SPNAccountsFix -Accounts @($account)

            Should -Invoke Disable-ADAccount -Times 1 -ParameterFilter {
                $Identity -eq "user1"
            }
        }

        It "Should display warning about disabling accounts" {
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Disable-SPNAccountsFix -Accounts @($account)

            Should -Invoke Write-Host -Times 1 -ParameterFilter {
                $Object -like "*WARNING*disable*"
            }
        }

        It "Should process multiple accounts" {
            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            Disable-SPNAccountsFix -Accounts $accounts

            Should -Invoke Disable-ADAccount -Times 2
        }
    }

    Context "Error Handling" {
        BeforeEach {
            Mock Write-Host { }
            Mock Write-Warning { }
        }

        It "Should continue processing after individual account failure" {
            Mock Disable-ADAccount {
                if ($Identity -eq "user1") { throw "AD Error" }
            }

            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            { Disable-SPNAccountsFix -Accounts $accounts } | Should -Not -Throw
            Should -Invoke Disable-ADAccount -Times 2
            Should -Invoke Write-Warning -Times 1
        }
    }

    Context "Parameter Validation" {
        It "Should reject null Accounts" {
            { Disable-SPNAccountsFix -Accounts $null } | Should -Throw
        }
    }
}

Describe "Set-EncryptionToAESFix" {
    Context "Successful Remediation" {
        BeforeEach {
            Mock Set-ADUser { }
            Mock Write-Host { }
            Mock Write-Warning { }
        }

        It "Should call Set-ADUser with correct encryption value (24 = AES128 + AES256)" {
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Set-EncryptionToAESFix -Accounts @($account)

            Should -Invoke Set-ADUser -Times 1 -ParameterFilter {
                $Identity -eq "user1" -and
                $Replace['msDS-SupportedEncryptionTypes'] -eq 24
            }
        }

        It "Should display information about encryption settings" {
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Set-EncryptionToAESFix -Accounts @($account)

            Should -Invoke Write-Host -ParameterFilter {
                $Object -like "*AES128*AES256*"
            }
        }

        It "Should display warning about service restarts" {
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Set-EncryptionToAESFix -Accounts @($account)

            Should -Invoke Write-Host -ParameterFilter {
                $Object -like "*WARNING*restart*"
            }
        }

        It "Should process multiple accounts" {
            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            Set-EncryptionToAESFix -Accounts $accounts

            Should -Invoke Set-ADUser -Times 2
        }
    }

    Context "Error Handling" {
        BeforeEach {
            Mock Write-Host { }
            Mock Write-Warning { }
        }

        It "Should continue processing after individual account failure" {
            Mock Set-ADUser {
                if ($Identity -eq "user1") { throw "AD Error" }
            }

            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            { Set-EncryptionToAESFix -Accounts $accounts } | Should -Not -Throw
            Should -Invoke Set-ADUser -Times 2
            Should -Invoke Write-Warning -Times 1
        }
    }

    Context "Parameter Validation" {
        It "Should reject null Accounts" {
            { Set-EncryptionToAESFix -Accounts $null } | Should -Throw
        }
    }
}

# Summary test to verify all functions exist
Describe "Module 2 Remediation Functions - Completeness Check" {
    It "Should have Set-PasswordNeverExpiresFix function" {
        Get-Command Set-PasswordNeverExpiresFix | Should -Not -BeNullOrEmpty
    }

    It "Should have Set-PasswordNotRequiredFix function" {
        Get-Command Set-PasswordNotRequiredFix | Should -Not -BeNullOrEmpty
    }

    It "Should have Set-CannotChangePasswordFix function" {
        Get-Command Set-CannotChangePasswordFix | Should -Not -BeNullOrEmpty
    }

    It "Should have Set-UseDESKeyOnlyFix function" {
        Get-Command Set-UseDESKeyOnlyFix | Should -Not -BeNullOrEmpty
    }

    It "Should have Set-ReversiblePasswordEncryptionFix function" {
        Get-Command Set-ReversiblePasswordEncryptionFix | Should -Not -BeNullOrEmpty
    }

    It "Should have Set-RequirePreAuthFix function" {
        Get-Command Set-RequirePreAuthFix | Should -Not -BeNullOrEmpty
    }

    It "Should have Set-TrustedForDelegationFix function" {
        Get-Command Set-TrustedForDelegationFix | Should -Not -BeNullOrEmpty
    }

    It "Should have Set-TrustedToAuthForDelegationFix function" {
        Get-Command Set-TrustedToAuthForDelegationFix | Should -Not -BeNullOrEmpty
    }

    It "Should have Disable-SPNAccountsFix function" {
        Get-Command Disable-SPNAccountsFix | Should -Not -BeNullOrEmpty
    }

    It "Should have Set-EncryptionToAESFix function" {
        Get-Command Set-EncryptionToAESFix | Should -Not -BeNullOrEmpty
    }
}