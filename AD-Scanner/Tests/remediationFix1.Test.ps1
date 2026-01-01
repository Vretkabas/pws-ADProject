<#
.SYNOPSIS
    Pester tests for remediationFix.ps1 from module 1

.DESCRIPTION
    Tests for Module 1 remediation fixs.
    Includes unit tests and integration tests for Active Directory queries.
#>

BeforeAll {
    # Maak stub functies voor ActiveDirectory cmdlets
    # Deze worden later gemockt in de tests
    function Set-ADUser {
        param($Identity, $PasswordNotRequired, $PasswordNeverExpires, $CannotChangePassword, $Clear, $ErrorAction)
    }
    function Get-ADUser {
        param($Identity, $ErrorAction)
    }
    function Remove-ADUser {
        param($Identity, $Confirm, $ErrorAction)
    }
    function Get-Acl {
        param($Path, $ErrorAction)
    }
    function Set-Acl {
        param($Path, $AclObject, $ErrorAction)
    }

    # Laad de functies
    $ModulePath = "$PSScriptRoot\..\Modules\module1dangerousAccounts\remediationFix.ps1"
    . $ModulePath

    # Helper functie om mock accounts te maken
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

Describe "Set-PasswordNotRequiredFix" {
    Context "Successful Remediation" {
        BeforeEach {
            Mock Set-ADUser { }
            Mock Write-Host { }
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
        }

        It "Should continue processing after individual account failure" {
            Mock Set-ADUser {
                if ($Identity -eq "user1") { throw "AD Error" }
            }
            Mock Write-Warning { }

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
        It "Should reject empty array for Accounts" {
            { Set-PasswordNotRequiredFix -Accounts @() } | Should -Throw
        }

        It "Should reject null Accounts" {
            { Set-PasswordNotRequiredFix -Accounts $null } | Should -Throw
        }
    }
}

Describe "Set-PasswordNeverExpiresFix" {
    Context "Successful Remediation" {
        BeforeEach {
            Mock Set-ADUser { }
            Mock Write-Host { }
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
        }

        It "Should continue processing after individual account failure" {
            Mock Set-ADUser {
                if ($Identity -eq "user1") { throw "AD Error" }
            }
            Mock Write-Warning { }

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
        It "Should reject empty array for Accounts" {
            { Set-PasswordNeverExpiresFix -Accounts @() } | Should -Throw
        }

        It "Should reject null Accounts" {
            { Set-PasswordNeverExpiresFix -Accounts $null } | Should -Throw
        }
    }
}

Describe "Set-CannotChangePasswordFix" {
    Context "Successful Remediation" {
        BeforeEach {
            Mock Set-ADUser { }
            Mock Write-Host { }
        }

        It "Should call Set-ADUser with correct parameters" {
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Set-CannotChangePasswordFix -Accounts @($account)

            Should -Invoke Set-ADUser -Times 1 -ParameterFilter {
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

            Should -Invoke Set-ADUser -Times 2
        }
    }

    Context "Error Handling" {
        BeforeEach {
            Mock Write-Host { }
        }

        It "Should continue processing after individual account failure" {
            Mock Set-ADUser {
                if ($Identity -eq "user1") { throw "AD Error" }
            }
            Mock Write-Warning { }

            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            { Set-CannotChangePasswordFix -Accounts $accounts } | Should -Not -Throw
            Should -Invoke Set-ADUser -Times 2
            Should -Invoke Write-Warning -Times 1
        }
    }

    Context "Parameter Validation" {
        It "Should reject empty array for Accounts" {
            { Set-CannotChangePasswordFix -Accounts @() } | Should -Throw
        }

        It "Should reject null Accounts" {
            { Set-CannotChangePasswordFix -Accounts $null } | Should -Throw
        }
    }
}

Describe "Remove-DisabledAccountsFix" {
    Context "Successful Remediation with User Confirmation" {
        BeforeEach {
            Mock Remove-ADUser { }
            Mock Write-Host { }
            Mock Read-Host { return "DELETE" }
        }

        It "Should call Remove-ADUser when user confirms with DELETE" {
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Remove-DisabledAccountsFix -Accounts @($account)

            Should -Invoke Remove-ADUser -Times 1 -ParameterFilter {
                $Identity -eq "user1" -and
                $Confirm -eq $false
            }
        }

        It "Should process multiple accounts when confirmed" {
            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            Remove-DisabledAccountsFix -Accounts $accounts

            Should -Invoke Remove-ADUser -Times 2
        }
    }

    Context "User Cancellation" {
        BeforeEach {
            Mock Remove-ADUser { }
            Mock Write-Host { }
        }

        It "Should NOT delete when user types anything other than DELETE" {
            Mock Read-Host { return "NO" }
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Remove-DisabledAccountsFix -Accounts @($account)

            Should -Invoke Remove-ADUser -Times 0
        }

        It "Should NOT delete when user presses Enter" {
            Mock Read-Host { return "" }
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Remove-DisabledAccountsFix -Accounts @($account)

            Should -Invoke Remove-ADUser -Times 0
        }
    }

    Context "Error Handling" {
        BeforeEach {
            Mock Write-Host { }
        }

        It "Should continue processing after individual account deletion failure" {
            Mock Read-Host { return "DELETE" }
            Mock Remove-ADUser {
                if ($Identity -eq "user1") { throw "AD Error - Cannot delete" }
            }
            Mock Write-Warning { }

            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            { Remove-DisabledAccountsFix -Accounts $accounts } | Should -Not -Throw
            Should -Invoke Remove-ADUser -Times 2
            Should -Invoke Write-Warning -Times 1
        }
    }

    Context "Parameter Validation" {
        It "Should reject empty array for Accounts" {
            { Remove-DisabledAccountsFix -Accounts @() } | Should -Throw
        }

        It "Should reject null Accounts" {
            { Remove-DisabledAccountsFix -Accounts $null } | Should -Throw
        }
    }
}

Describe "Clear-AdminCountFix" {
    Context "Successful Remediation" {
        BeforeEach {
            Mock Set-ADUser { }
            Mock Get-ADUser {
                return [PSCustomObject]@{
                    DistinguishedName = "CN=TestUser,CN=Users,DC=domain,DC=com"
                    SamAccountName = "testuser"
                }
            }
            Mock Get-Acl {
                $acl = New-Object System.DirectoryServices.ActiveDirectorySecurity
                return $acl
            }
            Mock Set-Acl { }
            Mock Write-Host { }
        }

        It "Should clear adminCount attribute" {
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Clear-AdminCountFix -Accounts @($account)

            Should -Invoke Set-ADUser -Times 1 -ParameterFilter {
                $Identity -eq "user1" -and
                $Clear -eq "adminCount"
            }
        }

        It "Should restore ACL inheritance" {
            $account = New-MockAccount -Name "User1" -SamAccountName "user1"

            Clear-AdminCountFix -Accounts @($account)

            Should -Invoke Get-Acl -Times 1
            Should -Invoke Set-Acl -Times 1
        }

        It "Should process multiple accounts" {
            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            Clear-AdminCountFix -Accounts $accounts

            Should -Invoke Set-ADUser -Times 2
            Should -Invoke Get-ADUser -Times 2
            Should -Invoke Set-Acl -Times 2
        }
    }

    Context "Error Handling" {
        BeforeEach {
            Mock Write-Host { }
            Mock Get-ADUser {
                return [PSCustomObject]@{
                    DistinguishedName = "CN=TestUser,CN=Users,DC=domain,DC=com"
                    SamAccountName    = $Identity
                }
            }
            Mock Get-Acl {
                $acl = New-Object System.DirectoryServices.ActiveDirectorySecurity
                return $acl
            }
            Mock Set-Acl { }
        }

        It "Should continue processing after individual account failure" {
            Mock Set-ADUser {
                if ($Identity -eq "user1") { throw "AD Error" }
            }
            Mock Write-Warning { }

            $accounts = @(
                (New-MockAccount -Name "User1" -SamAccountName "user1"),
                (New-MockAccount -Name "User2" -SamAccountName "user2")
            )

            { Clear-AdminCountFix -Accounts $accounts } | Should -Not -Throw
            Should -Invoke Set-ADUser -Times 2
            Should -Invoke Write-Warning -Times 1
        }
    }

    Context "Parameter Validation" {
        It "Should reject empty array for Accounts" {
            { Clear-AdminCountFix -Accounts @() } | Should -Throw
        }

        It "Should reject null Accounts" {
            { Clear-AdminCountFix -Accounts $null } | Should -Throw
        }
    }
}