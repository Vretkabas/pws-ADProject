<#
.SYNOPSIS
    Pester tests for aclAudit.ps1 from Module 4 (ACL Permissions)

.DESCRIPTION
    Tests for Module 4 ACL permission audit functions.
    Includes unit tests for all ACL audit functions.
#>

BeforeAll {
    # Create stub functions for ActiveDirectory cmdlets
    function Get-ADDomain {
        param($ErrorAction)
    }
    function Get-ADObject {
        param($Identity, $Filter, $SearchBase, $Properties, $ErrorAction)
    }
    function Get-ADGroup {
        param($Identity, $Filter, $Properties, $ErrorAction)
    }
    function Get-ADGroupMember {
        param($Identity, $Recursive, $ErrorAction)
    }
    function Get-ADUser {
        param($Identity, $Filter, $Properties, $ErrorAction)
    }
    function Get-ADOrganizationalUnit {
        param($Filter, $SearchBase, $SearchScope, $Properties, $ErrorAction)
    }
    function Get-GPO {
        param($All, $ErrorAction)
    }

    # Load the functions (skip #Requires check by executing content)
    $ModulePath = "$PSScriptRoot\..\Modules\module4DangerousACLs\aclAudit.ps1"
    $scriptContent = Get-Content -Path $ModulePath -Raw
    # Remove the #Requires statement to allow testing without ActiveDirectory module
    $scriptContent = $scriptContent -replace '#Requires -Modules ActiveDirectory', ''
    Invoke-Expression $scriptContent

    # Helper function to create mock ACE (Access Control Entry)
    function New-MockACE {
        param(
            [string]$IdentityReference = "S-1-5-21-1234567890-1234567890-1234567890-1001",
            [string]$ActiveDirectoryRights = "GenericAll",
            [string]$AccessControlType = "Allow",
            [bool]$IsInherited = $false,
            [string]$ObjectType = $null
        )

        # Create a proper mock object with ScriptMethod for ToString
        $ace = New-Object PSObject
        $ace | Add-Member -MemberType NoteProperty -Name "IdentityReference" -Value ([PSCustomObject]@{ Value = $IdentityReference })
        $ace | Add-Member -MemberType NoteProperty -Name "IsInherited" -Value $IsInherited
        $ace | Add-Member -MemberType NoteProperty -Name "ObjectType" -Value $ObjectType
        
        # Create ActiveDirectoryRights as object with ToString method
        $rightsObj = New-Object PSObject
        $rightsObj | Add-Member -MemberType ScriptMethod -Name "ToString" -Value { $ActiveDirectoryRights }.GetNewClosure() -Force
        $ace | Add-Member -MemberType NoteProperty -Name "ActiveDirectoryRights" -Value $rightsObj

        # Create AccessControlType as object with ToString method
        $accessTypeObj = New-Object PSObject
        $accessTypeObj | Add-Member -MemberType ScriptMethod -Name "ToString" -Value { $AccessControlType }.GetNewClosure() -Force
        $ace | Add-Member -MemberType NoteProperty -Name "AccessControlType" -Value $accessTypeObj

        return $ace
    }

    # Helper function to create mock security descriptor
    function New-MockSecurityDescriptor {
        param(
            [array]$AccessList = @()
        )

        return [PSCustomObject]@{
            Access = $AccessList
        }
    }
}

#region Helper Function Tests

Describe "Get-DangerousRights" {
    Context "Return Values" {
        It "Should return an array of dangerous rights" {
            $result = Get-DangerousRights
            $result | Should -BeOfType [string]
        }

        It "Should include GenericAll" {
            $result = Get-DangerousRights
            $result | Should -Contain "GenericAll"
        }

        It "Should include GenericWrite" {
            $result = Get-DangerousRights
            $result | Should -Contain "GenericWrite"
        }

        It "Should include WriteDacl" {
            $result = Get-DangerousRights
            $result | Should -Contain "WriteDacl"
        }

        It "Should include WriteOwner" {
            $result = Get-DangerousRights
            $result | Should -Contain "WriteOwner"
        }

        It "Should include WriteProperty" {
            $result = Get-DangerousRights
            $result | Should -Contain "WriteProperty"
        }
    }
}

Describe "Get-InterestingExtendedRights" {
    Context "Return Values" {
        It "Should return a hashtable" {
            $result = Get-InterestingExtendedRights
            $result | Should -BeOfType [hashtable]
        }

        It "Should contain DCSync rights GUIDs" {
            $result = Get-InterestingExtendedRights
            $result['DS-Replication-Get-Changes'] | Should -Be '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
            $result['DS-Replication-Get-Changes-All'] | Should -Be '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
        }

        It "Should contain User-Force-Change-Password GUID" {
            $result = Get-InterestingExtendedRights
            $result['User-Force-Change-Password'] | Should -Be '00299570-246d-11d0-a768-00aa006e0529'
        }
    }
}

Describe "Test-IsBuiltInAdminGroup" {
    Context "Built-in Groups" {
        It "Should return true for BUILTIN\Administrators" {
            $result = Test-IsBuiltInAdminGroup -Identity "BUILTIN\Administrators"
            $result | Should -Be $true
        }

        It "Should return true for NT AUTHORITY\SYSTEM" {
            $result = Test-IsBuiltInAdminGroup -Identity "NT AUTHORITY\SYSTEM"
            $result | Should -Be $true
        }

        It "Should return true for Domain Admins" {
            $result = Test-IsBuiltInAdminGroup -Identity "DOMAIN\Domain Admins"
            $result | Should -Be $true
        }

        It "Should return true for Enterprise Admins" {
            $result = Test-IsBuiltInAdminGroup -Identity "DOMAIN\Enterprise Admins"
            $result | Should -Be $true
        }

        It "Should return true for Schema Admins" {
            $result = Test-IsBuiltInAdminGroup -Identity "DOMAIN\Schema Admins"
            $result | Should -Be $true
        }
    }

    Context "Non-Built-in Groups" {
        It "Should return false for regular user" {
            $result = Test-IsBuiltInAdminGroup -Identity "DOMAIN\RegularUser"
            $result | Should -Be $false
        }

        It "Should return false for custom group" {
            $result = Test-IsBuiltInAdminGroup -Identity "DOMAIN\CustomSecurityGroup"
            $result | Should -Be $false
        }

        It "Should return false for service account" {
            $result = Test-IsBuiltInAdminGroup -Identity "DOMAIN\svc_sqlserver"
            $result | Should -Be $false
        }
    }

    Context "Parameter Validation" {
        It "Should reject empty string" {
            { Test-IsBuiltInAdminGroup -Identity "" } | Should -Throw
        }

        It "Should reject null" {
            { Test-IsBuiltInAdminGroup -Identity $null } | Should -Throw
        }
    }
}

Describe "ConvertFrom-SID" {
    Context "SID Conversion" {
        BeforeEach {
            Mock Write-Verbose { }
        }

        It "Should return original SID when conversion fails" {
            $fakeSID = "S-1-5-21-9999999999-9999999999-9999999999-9999"
            $result = ConvertFrom-SID -SID $fakeSID
            # Should return something (either converted or original)
            $result | Should -Not -BeNullOrEmpty
        }
    }

    Context "Parameter Validation" {
        It "Should reject empty string" {
            { ConvertFrom-SID -SID "" } | Should -Throw
        }

        It "Should reject null" {
            { ConvertFrom-SID -SID $null } | Should -Throw
        }
    }
}

Describe "Remove-DuplicateACLEntries" {
    Context "Deduplication Logic" {
        BeforeEach {
            Mock Write-Warning { }
        }

        It "Should return empty array for null input" {
            $result = Remove-DuplicateACLEntries -Entries $null
            @($result).Count | Should -Be 0
        }

        It "Should return empty array for empty input" {
            $result = Remove-DuplicateACLEntries -Entries @()
            @($result).Count | Should -Be 0
        }

        It "Should remove duplicate entries" {
            $entries = @(
                [PSCustomObject]@{ Trustee = "User1"; ObjectPath = "CN=Test"; Rights = "GenericAll" },
                [PSCustomObject]@{ Trustee = "User1"; ObjectPath = "CN=Test"; Rights = "GenericAll" },
                [PSCustomObject]@{ Trustee = "User2"; ObjectPath = "CN=Test"; Rights = "GenericWrite" }
            )

            $result = Remove-DuplicateACLEntries -Entries $entries
            @($result).Count | Should -Be 2
        }

        It "Should keep unique entries" {
            $entries = @(
                [PSCustomObject]@{ Trustee = "User1"; ObjectPath = "CN=Test1"; Rights = "GenericAll" },
                [PSCustomObject]@{ Trustee = "User1"; ObjectPath = "CN=Test2"; Rights = "GenericAll" },
                [PSCustomObject]@{ Trustee = "User2"; ObjectPath = "CN=Test1"; Rights = "GenericAll" }
            )

            $result = Remove-DuplicateACLEntries -Entries $entries
            @($result).Count | Should -Be 3
        }
    }
}

#endregion

#region ACL Check Function Tests

Describe "Get-AdminSDHolderACL" {
    Context "Successful Audit" {
        BeforeEach {
            Mock Get-ADDomain {
                return [PSCustomObject]@{
                    DistinguishedName = "DC=test,DC=local"
                }
            }

            Mock Get-ADObject {
                $ace = New-MockACE -IdentityReference "S-1-5-21-1234567890-1234567890-1234567890-5001" -ActiveDirectoryRights "GenericAll"
                return [PSCustomObject]@{
                    DistinguishedName    = "CN=AdminSDHolder,CN=System,DC=test,DC=local"
                    ntSecurityDescriptor = New-MockSecurityDescriptor -AccessList @($ace)
                }
            }

            # Mock ConvertFrom-SID to return the identity as-is
            Mock ConvertFrom-SID { return "DOMAIN\SuspiciousUser" }

            Mock Write-Error { }
            Mock Write-Warning { }
            Mock Write-Verbose { }
        }

        It "Should return array of results" {
            $result = Get-AdminSDHolderACL
            $result | Should -Not -BeNullOrEmpty
        }

        It "Should include Object property" {
            $result = Get-AdminSDHolderACL
            $result[0].Object | Should -Be "AdminSDHolder"
        }

        It "Should include Trustee property" {
            $result = Get-AdminSDHolderACL
            $result[0].Trustee | Should -Not -BeNullOrEmpty
        }

        It "Should include Rights property" {
            $result = Get-AdminSDHolderACL
            $result[0].Rights | Should -Not -BeNullOrEmpty
        }
    }

    Context "Filtering Built-in Groups" {
        BeforeEach {
            Mock Get-ADDomain {
                return [PSCustomObject]@{
                    DistinguishedName = "DC=test,DC=local"
                }
            }

            Mock Get-ADObject {
                $builtInAce = New-MockACE -IdentityReference "BUILTIN\Administrators" -ActiveDirectoryRights "GenericAll"
                return [PSCustomObject]@{
                    DistinguishedName    = "CN=AdminSDHolder,CN=System,DC=test,DC=local"
                    ntSecurityDescriptor = New-MockSecurityDescriptor -AccessList @($builtInAce)
                }
            }

            Mock ConvertFrom-SID { return $SID }
            Mock Write-Error { }
            Mock Write-Warning { }
            Mock Write-Verbose { }
        }

        It "Should filter out built-in admin groups" {
            $result = Get-AdminSDHolderACL
            @($result).Count | Should -Be 0
        }
    }

    Context "Filtering Inherited Permissions" {
        BeforeEach {
            Mock Get-ADDomain {
                return [PSCustomObject]@{
                    DistinguishedName = "DC=test,DC=local"
                }
            }

            Mock Get-ADObject {
                $inheritedAce = New-MockACE -IdentityReference "S-1-5-21-1234567890-1234567890-1234567890-5001" -ActiveDirectoryRights "GenericAll" -IsInherited $true
                return [PSCustomObject]@{
                    DistinguishedName    = "CN=AdminSDHolder,CN=System,DC=test,DC=local"
                    ntSecurityDescriptor = New-MockSecurityDescriptor -AccessList @($inheritedAce)
                }
            }

            Mock ConvertFrom-SID { return "DOMAIN\SuspiciousUser" }
            Mock Write-Error { }
            Mock Write-Warning { }
            Mock Write-Verbose { }
        }

        It "Should filter out inherited permissions" {
            $result = Get-AdminSDHolderACL
            @($result).Count | Should -Be 0
        }
    }

    Context "Error Handling" {
        BeforeEach {
            Mock Get-ADDomain { throw "AD connection failed" }
            Mock Write-Error { }
            Mock Write-Verbose { }
        }

        It "Should handle errors gracefully" {
            { Get-AdminSDHolderACL } | Should -Not -Throw
        }

        It "Should return empty array on error" {
            $result = Get-AdminSDHolderACL
            @($result).Count | Should -Be 0
        }
    }
}

Describe "Get-DomainObjectACL" {
    Context "DCSync Detection" {
        BeforeEach {
            Mock Get-ADDomain {
                return [PSCustomObject]@{
                    DistinguishedName = "DC=test,DC=local"
                }
            }

            Mock Get-ADObject {
                # DCSync right GUID
                $dcsyncAce = New-MockACE -IdentityReference "S-1-5-21-1234567890-1234567890-1234567890-5001" -ActiveDirectoryRights "ExtendedRight" -ObjectType "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
                return [PSCustomObject]@{
                    DistinguishedName    = "DC=test,DC=local"
                    ntSecurityDescriptor = New-MockSecurityDescriptor -AccessList @($dcsyncAce)
                }
            }

            Mock ConvertFrom-SID { return "DOMAIN\SuspiciousUser" }
            Mock Write-Error { }
            Mock Write-Warning { }
            Mock Write-Verbose { }
        }

        It "Should detect DCSync rights" {
            $result = Get-DomainObjectACL
            $result | Where-Object { $_.Object -like "*DCSync*" } | Should -Not -BeNullOrEmpty
        }
    }

    Context "Error Handling" {
        BeforeEach {
            Mock Get-ADDomain { throw "AD connection failed" }
            Mock Write-Error { }
            Mock Write-Verbose { }
        }

        It "Should handle errors gracefully" {
            { Get-DomainObjectACL } | Should -Not -Throw
        }

        It "Should return empty array on error" {
            $result = Get-DomainObjectACL
            @($result).Count | Should -Be 0
        }
    }
}

Describe "Get-PrivilegedGroupACL" {
    Context "Successful Audit" {
        BeforeEach {
            Mock Get-ADGroup {
                param($Filter)
                $ace = New-MockACE -IdentityReference "S-1-5-21-1234567890-1234567890-1234567890-5001" -ActiveDirectoryRights "WriteProperty"
                return [PSCustomObject]@{
                    Name                 = "Domain Admins"
                    DistinguishedName    = "CN=Domain Admins,CN=Users,DC=test,DC=local"
                    ntSecurityDescriptor = New-MockSecurityDescriptor -AccessList @($ace)
                }
            }

            Mock ConvertFrom-SID { return "DOMAIN\SuspiciousUser" }
            Mock Write-Warning { }
            Mock Write-Verbose { }
        }

        It "Should return array of results" {
            $result = Get-PrivilegedGroupACL
            $result | Should -Not -BeNullOrEmpty
        }

        It "Should include GroupName property" {
            $result = Get-PrivilegedGroupACL
            $result[0].GroupName | Should -Not -BeNullOrEmpty
        }
    }

    Context "Group Not Found" {
        BeforeEach {
            Mock Get-ADGroup { return $null }
            Mock Write-Warning { }
            Mock Write-Verbose { }
        }

        It "Should handle missing groups gracefully" {
            { Get-PrivilegedGroupACL } | Should -Not -Throw
        }

        It "Should return empty array when no groups found" {
            $result = Get-PrivilegedGroupACL
            @($result).Count | Should -Be 0
        }
    }
}

Describe "Get-GPOObjectACL" {
    Context "Successful Audit" {
        BeforeEach {
            Mock Get-GPO {
                return @(
                    [PSCustomObject]@{
                        Id          = "12345678-1234-1234-1234-123456789012"
                        DisplayName = "Default Domain Policy"
                    }
                )
            }

            Mock Get-ADDomain {
                return [PSCustomObject]@{
                    DistinguishedName = "DC=test,DC=local"
                }
            }

            Mock Get-ADObject {
                $ace = New-MockACE -IdentityReference "S-1-5-21-1234567890-1234567890-1234567890-5001" -ActiveDirectoryRights "GenericAll"
                return [PSCustomObject]@{
                    DistinguishedName    = "CN={12345678-1234-1234-1234-123456789012},CN=Policies,CN=System,DC=test,DC=local"
                    ntSecurityDescriptor = New-MockSecurityDescriptor -AccessList @($ace)
                }
            }

            Mock ConvertFrom-SID { return "DOMAIN\SuspiciousUser" }
            Mock Write-Error { }
            Mock Write-Warning { }
            Mock Write-Verbose { }
        }

        It "Should return array of results" {
            $result = Get-GPOObjectACL
            $result | Should -Not -BeNullOrEmpty
        }

        It "Should include GPOName property" {
            $result = Get-GPOObjectACL
            $result[0].GPOName | Should -Be "Default Domain Policy"
        }
    }

    Context "Error Handling" {
        BeforeEach {
            Mock Get-GPO { throw "GPO enumeration failed" }
            Mock Write-Error { }
            Mock Write-Verbose { }
        }

        It "Should handle errors gracefully" {
            { Get-GPOObjectACL } | Should -Not -Throw
        }

        It "Should return empty array on error" {
            $result = Get-GPOObjectACL
            @($result).Count | Should -Be 0
        }
    }
}

Describe "Get-PrivilegedUserACL" {
    Context "Successful Audit" {
        BeforeEach {
            Mock Get-ADGroupMember {
                return @(
                    [PSCustomObject]@{
                        SamAccountName    = "AdminUser1"
                        DistinguishedName = "CN=AdminUser1,CN=Users,DC=test,DC=local"
                        objectClass       = "user"
                    }
                )
            }

            Mock Get-ADUser {
                $ace = New-MockACE -IdentityReference "S-1-5-21-1234567890-1234567890-1234567890-5001" -ActiveDirectoryRights "GenericAll"
                return [PSCustomObject]@{
                    SamAccountName       = "AdminUser1"
                    DistinguishedName    = "CN=AdminUser1,CN=Users,DC=test,DC=local"
                    SID                  = [PSCustomObject]@{ Value = "S-1-5-21-1234-5678-9012-1001" }
                    ntSecurityDescriptor = New-MockSecurityDescriptor -AccessList @($ace)
                }
            }

            Mock ConvertFrom-SID { return "DOMAIN\SuspiciousUser" }
            Mock Write-Warning { }
            Mock Write-Verbose { }
        }

        It "Should return array of results" {
            $result = Get-PrivilegedUserACL
            $result | Should -Not -BeNullOrEmpty
        }

        It "Should include UserName property" {
            $result = Get-PrivilegedUserACL
            $result[0].UserName | Should -Be "AdminUser1"
        }
    }

    Context "Password Reset Detection" {
        BeforeEach {
            Mock Get-ADGroupMember {
                return @(
                    [PSCustomObject]@{
                        SamAccountName    = "AdminUser1"
                        DistinguishedName = "CN=AdminUser1,CN=Users,DC=test,DC=local"
                        objectClass       = "user"
                    }
                )
            }

            Mock Get-ADUser {
                # Password reset GUID
                $pwdResetAce = New-MockACE -IdentityReference "S-1-5-21-1234567890-1234567890-1234567890-5001" -ActiveDirectoryRights "ExtendedRight" -ObjectType "00299570-246d-11d0-a768-00aa006e0529"
                return [PSCustomObject]@{
                    SamAccountName       = "AdminUser1"
                    DistinguishedName    = "CN=AdminUser1,CN=Users,DC=test,DC=local"
                    SID                  = [PSCustomObject]@{ Value = "S-1-5-21-1234-5678-9012-1001" }
                    ntSecurityDescriptor = New-MockSecurityDescriptor -AccessList @($pwdResetAce)
                }
            }

            Mock ConvertFrom-SID { return "DOMAIN\SuspiciousUser" }
            Mock Write-Warning { }
            Mock Write-Verbose { }
        }

        It "Should detect password reset rights" {
            $result = Get-PrivilegedUserACL
            $result | Where-Object { $_.Rights -like "*Password*" } | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Get-OUObjectACL" {
    Context "Successful Audit" {
        BeforeEach {
            Mock Get-ADDomain {
                return [PSCustomObject]@{
                    DistinguishedName = "DC=test,DC=local"
                }
            }

            Mock Get-ADOrganizationalUnit {
                $ace = New-MockACE -IdentityReference "S-1-5-21-1234567890-1234567890-1234567890-5001" -ActiveDirectoryRights "GenericAll"
                return @(
                    [PSCustomObject]@{
                        Name                 = "Users"
                        DistinguishedName    = "OU=Users,DC=test,DC=local"
                        ntSecurityDescriptor = New-MockSecurityDescriptor -AccessList @($ace)
                    }
                )
            }

            Mock ConvertFrom-SID { return "DOMAIN\SuspiciousUser" }
            Mock Write-Error { }
            Mock Write-Warning { }
            Mock Write-Verbose { }
        }

        It "Should return array of results" {
            $result = Get-OUObjectACL
            $result | Should -Not -BeNullOrEmpty
        }

        It "Should include OUName property" {
            $result = Get-OUObjectACL
            $result[0].OUName | Should -Be "Users"
        }
    }

    Context "Error Handling" {
        BeforeEach {
            Mock Get-ADDomain { throw "AD connection failed" }
            Mock Write-Error { }
            Mock Write-Verbose { }
        }

        It "Should handle errors gracefully" {
            { Get-OUObjectACL } | Should -Not -Throw
        }

        It "Should return empty array on error" {
            $result = Get-OUObjectACL
            @($result).Count | Should -Be 0
        }
    }
}

#endregion

#region Main Audit Function Tests

Describe "Invoke-ACLAudit" {
    Context "Successful Audit" {
        BeforeEach {
            # Mock all sub-functions
            Mock Get-AdminSDHolderACL { return @() }
            Mock Get-DomainObjectACL { return @() }
            Mock Get-PrivilegedGroupACL { return @() }
            Mock Get-GPOObjectACL { return @() }
            Mock Get-PrivilegedUserACL { return @() }
            Mock Get-OUObjectACL { return @() }
            Mock Remove-DuplicateACLEntries { param($Entries) return $Entries }
            Mock Write-Verbose { }
            Mock Write-Error { }
        }

        It "Should return a hashtable" {
            $result = Invoke-ACLAudit
            $result | Should -BeOfType [hashtable]
        }

        It "Should include AdminSDHolder key" {
            $result = Invoke-ACLAudit
            $result.ContainsKey('AdminSDHolder') | Should -Be $true
        }

        It "Should include DomainObject key" {
            $result = Invoke-ACLAudit
            $result.ContainsKey('DomainObject') | Should -Be $true
        }

        It "Should include PrivilegedGroups key" {
            $result = Invoke-ACLAudit
            $result.ContainsKey('PrivilegedGroups') | Should -Be $true
        }

        It "Should include GPOs key" {
            $result = Invoke-ACLAudit
            $result.ContainsKey('GPOs') | Should -Be $true
        }

        It "Should include PrivilegedUsers key" {
            $result = Invoke-ACLAudit
            $result.ContainsKey('PrivilegedUsers') | Should -Be $true
        }

        It "Should include OrganizationalUnits key" {
            $result = Invoke-ACLAudit
            $result.ContainsKey('OrganizationalUnits') | Should -Be $true
        }

        It "Should call all audit functions" {
            Invoke-ACLAudit

            Should -Invoke Get-AdminSDHolderACL -Times 1
            Should -Invoke Get-DomainObjectACL -Times 1
            Should -Invoke Get-PrivilegedGroupACL -Times 1
            Should -Invoke Get-GPOObjectACL -Times 1
            Should -Invoke Get-PrivilegedUserACL -Times 1
            Should -Invoke Get-OUObjectACL -Times 1
        }
    }

    Context "Result Structure" {
        BeforeEach {
            Mock Get-AdminSDHolderACL { return @() }
            Mock Get-DomainObjectACL {
                return @(
                    [PSCustomObject]@{ Object = "Domain Root - DCSync"; Trustee = "User1" },
                    [PSCustomObject]@{ Object = "Domain Root"; Trustee = "User2" }
                )
            }
            Mock Get-PrivilegedGroupACL {
                return @(
                    [PSCustomObject]@{ GroupName = "Domain Admins"; Trustee = "User1" },
                    [PSCustomObject]@{ GroupName = "Enterprise Admins"; Trustee = "User2" },
                    [PSCustomObject]@{ GroupName = "Backup Operators"; Trustee = "User3" }
                )
            }
            Mock Get-GPOObjectACL { return @() }
            Mock Get-PrivilegedUserACL {
                return @(
                    [PSCustomObject]@{ UserName = "Admin1"; Rights = "User-Force-Change-Password" },
                    [PSCustomObject]@{ UserName = "Admin2"; Rights = "GenericAll" }
                )
            }
            Mock Get-OUObjectACL { return @() }
            Mock Remove-DuplicateACLEntries { param($Entries) return $Entries }
            Mock Write-Verbose { }
        }

        It "Should split DomainObject results by DCSync" {
            $result = Invoke-ACLAudit
            $result.DomainObject.DCSync | Should -Not -BeNullOrEmpty
            $result.DomainObject.Other | Should -Not -BeNullOrEmpty
        }

        It "Should split PrivilegedGroups by group type" {
            $result = Invoke-ACLAudit
            $result.PrivilegedGroups.DomainAdmins | Should -Not -BeNullOrEmpty
            $result.PrivilegedGroups.EnterpriseAdmins | Should -Not -BeNullOrEmpty
            $result.PrivilegedGroups.Other | Should -Not -BeNullOrEmpty
        }

        It "Should split PrivilegedUsers by password reset" {
            $result = Invoke-ACLAudit
            $result.PrivilegedUsers.PasswordReset | Should -Not -BeNullOrEmpty
            $result.PrivilegedUsers.Other | Should -Not -BeNullOrEmpty
        }
    }

    Context "Error Handling" {
        BeforeEach {
            Mock Get-AdminSDHolderACL { throw "Audit failed" }
            Mock Write-Error { }
            Mock Write-Verbose { }
        }

        It "Should handle errors gracefully" {
            { Invoke-ACLAudit } | Should -Not -Throw
        }

        It "Should return empty hashtable on error" {
            $result = Invoke-ACLAudit
            $result.Count | Should -Be 0
        }
    }
}

#endregion

#region Completeness Check

Describe "Module 4 ACL Audit Functions - Completeness Check" {
    It "Should have Get-DangerousRights function" {
        Get-Command Get-DangerousRights | Should -Not -BeNullOrEmpty
    }

    It "Should have Get-InterestingExtendedRights function" {
        Get-Command Get-InterestingExtendedRights | Should -Not -BeNullOrEmpty
    }

    It "Should have ConvertFrom-SID function" {
        Get-Command ConvertFrom-SID | Should -Not -BeNullOrEmpty
    }

    It "Should have Test-IsBuiltInAdminGroup function" {
        Get-Command Test-IsBuiltInAdminGroup | Should -Not -BeNullOrEmpty
    }

    It "Should have Remove-DuplicateACLEntries function" {
        Get-Command Remove-DuplicateACLEntries | Should -Not -BeNullOrEmpty
    }

    It "Should have Get-AdminSDHolderACL function" {
        Get-Command Get-AdminSDHolderACL | Should -Not -BeNullOrEmpty
    }

    It "Should have Get-DomainObjectACL function" {
        Get-Command Get-DomainObjectACL | Should -Not -BeNullOrEmpty
    }

    It "Should have Get-PrivilegedGroupACL function" {
        Get-Command Get-PrivilegedGroupACL | Should -Not -BeNullOrEmpty
    }

    It "Should have Get-GPOObjectACL function" {
        Get-Command Get-GPOObjectACL | Should -Not -BeNullOrEmpty
    }

    It "Should have Get-PrivilegedUserACL function" {
        Get-Command Get-PrivilegedUserACL | Should -Not -BeNullOrEmpty
    }

    It "Should have Get-OUObjectACL function" {
        Get-Command Get-OUObjectACL | Should -Not -BeNullOrEmpty
    }

    It "Should have Invoke-ACLAudit function" {
        Get-Command Invoke-ACLAudit | Should -Not -BeNullOrEmpty
    }
}

#endregion