<#
.SYNOPSIS
    ACL permission audit functions for Module 4

.DESCRIPTION
    Contains functions to audit dangerous ACL permissions on sensitive AD objects.
    Includes parameter validation and comprehensive error handling.

    Audited objects include:
    - AdminSDHolder
    - Domain Object (including DCSync rights)
    - Privileged Groups
    - GPO Objects
    - Privileged User Objects
    - Organizational Units

#>

#Requires -Modules ActiveDirectory

#region Helper Functions

<#
.SYNOPSIS
    Returns a list of dangerous Active Directory rights
.OUTPUTS
    Array of dangerous right names
#>
function Get-DangerousRights {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    return @(
        'GenericAll',
        'GenericWrite',
        'WriteDacl',
        'WriteOwner',
        'WriteProperty'
    )
}

<#
.SYNOPSIS
    Returns a hashtable of interesting extended rights and their GUIDs
.DESCRIPTION
    These extended rights can be abused for privilege escalation or persistence
.OUTPUTS
    Hashtable with right names and their corresponding GUIDs
#>
function Get-InterestingExtendedRights {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return @{
        'User-Force-Change-Password'                 = '00299570-246d-11d0-a768-00aa006e0529'
        'DS-Replication-Get-Changes'                 = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
        'DS-Replication-Get-Changes-All'             = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
        'DS-Replication-Get-Changes-In-Filtered-Set' = '89e95b76-444d-4c62-991a-0facbeda640c'
        'User-Account-Restrictions'                  = '4c164200-20c0-11d0-a768-00aa006e0529'
        'Validated-SPN'                              = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
    }
}

<#
.SYNOPSIS
    Converts a SID to a friendly account name
.PARAMETER SID
    Security Identifier to convert
.OUTPUTS
    Friendly account name or original SID if conversion fails
#>
function ConvertFrom-SID {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SID
    )

    try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
        $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
        return $objUser.Value
    }
    catch {
        Write-Verbose "Could not convert SID '$SID': $($_.Exception.Message)"
        return $SID
    }
}

<#
.SYNOPSIS
    Tests if an identity is a built-in administrator group
.PARAMETER Identity
    Account or group name to test
.OUTPUTS
    Boolean indicating if identity is a built-in admin group
#>
function Test-IsBuiltInAdminGroup {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Identity
    )

    # Built-in and well-known administrative groups and accounts
    $builtInAdmins = @(
        'BUILTIN\Administrators',
        'NT AUTHORITY\SYSTEM',
        'NT AUTHORITY\Authenticated Users',
        'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS',
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Administrators',
        'CREATOR OWNER',
        'SELF',
        'Everyone',
        'Domain Controllers',
        'Enterprise Domain Controllers',
        'Key Admins',
        'Enterprise Key Admins',
        'Group Policy Creator Owners',
        'Cert Publishers',
        'RAS and IAS Servers',
        'Terminal Server License Servers',
        'Windows Authorization Access Group',
        'Allowed RODC Password Replication Group',
        'Denied RODC Password Replication Group',
        'Pre-Windows 2000 Compatible Access',
        'Incoming Forest Trust Builders',
        'Network Configuration Operators',
        'Performance Monitor Users',
        'Performance Log Users',
        'Distributed COM Users',
        'IIS_IUSRS',
        'Cryptographic Operators',
        'Event Log Readers',
        'Certificate Service DCOM Access',
        'RDS Remote Access Servers',
        'RDS Endpoint Servers',
        'RDS Management Servers',
        'Hyper-V Administrators',
        'Access Control Assistance Operators',
        'Remote Management Users',
        'Storage Replica Administrators'
    )

    foreach ($admin in $builtInAdmins) {
        if ($Identity -like "*$admin*") {
            return $true
        }
    }

    return $false
}

<#
.SYNOPSIS
    Removes duplicate ACL entries based on Trustee, ObjectPath, and Rights
.PARAMETER Entries
    Array of ACL entry objects to deduplicate
.OUTPUTS
    Array of unique ACL entries
#>
function Remove-DuplicateACLEntries {
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [array]$Entries
    )

    if (-not $Entries -or $Entries.Count -eq 0) {
        return @()
    }

    try {
        # Group by unique combination of Trustee + ObjectPath + Rights
        $uniqueEntries = $Entries | Group-Object -Property @{Expression = {
                "$($_.Trustee)|$($_.ObjectPath)|$($_.Rights)"
            }
        } | ForEach-Object { $_.Group | Select-Object -First 1 }

        return $uniqueEntries
    }
    catch {
        Write-Warning "Failed to remove duplicate ACL entries: $($_.Exception.Message)"
        return $Entries
    }
}

#endregion

#region ACL Check Functions

<#
.SYNOPSIS
    Audits ACL permissions on the AdminSDHolder object
.DESCRIPTION
    AdminSDHolder is a special container that acts as a security template for privileged accounts.
    Non-standard permissions can indicate security issues.
.OUTPUTS
    Array of ACL entries with dangerous permissions
#>
function Get-AdminSDHolderACL {
    [CmdletBinding()]
    [OutputType([array])]
    param()

    $results = @()
    $dangerousRights = Get-DangerousRights

    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $adminSDHolder = Get-ADObject -Identity "CN=AdminSDHolder,CN=System,$($domain.DistinguishedName)" -Properties ntSecurityDescriptor -ErrorAction Stop

        $acl = $adminSDHolder.ntSecurityDescriptor.Access

        foreach ($ace in $acl) {
            # Skip inherited permissions
            if ($ace.IsInherited) { continue }

            $identity = ConvertFrom-SID -SID $ace.IdentityReference.Value

            # Skip built-in admin groups (expected to have permissions)
            if (Test-IsBuiltInAdminGroup -Identity $identity) { continue }

            $rightName = $ace.ActiveDirectoryRights.ToString()

            # Check for dangerous rights
            if ($rightName -in $dangerousRights -or $rightName -like '*All*' -or $rightName -like '*Write*') {
                $results += [PSCustomObject]@{
                    Object     = 'AdminSDHolder'
                    ObjectPath = $adminSDHolder.DistinguishedName
                    Trustee    = $identity
                    TrusteeSID = $ace.IdentityReference.Value
                    Rights     = $rightName
                    AccessType = $ace.AccessControlType.ToString()
                    ObjectType = if ($ace.ObjectType) { $ace.ObjectType.ToString() } else { "All" }
                }
            }
        }
    }
    catch {
        Write-Error "Failed to audit AdminSDHolder: $($_.Exception.Message)"
    }

    return $results
}

<#
.SYNOPSIS
    Audits ACL permissions on the Domain root object
.DESCRIPTION
    Checks for dangerous permissions on the domain root, including DCSync rights
    which can be used to replicate password hashes from domain controllers.
.OUTPUTS
    Array of ACL entries with dangerous permissions
#>
function Get-DomainObjectACL {
    [CmdletBinding()]
    [OutputType([array])]
    param()

    $results = @()
    $dangerousRights = Get-DangerousRights
    $extendedRights = Get-InterestingExtendedRights

    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $domainObj = Get-ADObject -Identity $domain.DistinguishedName -Properties ntSecurityDescriptor -ErrorAction Stop

        $acl = $domainObj.ntSecurityDescriptor.Access

        foreach ($ace in $acl) {
            # Skip inherited permissions
            if ($ace.IsInherited) { continue }

            $identity = ConvertFrom-SID -SID $ace.IdentityReference.Value

            # Skip built-in admin groups
            if (Test-IsBuiltInAdminGroup -Identity $identity) { continue }

            $rightName = $ace.ActiveDirectoryRights.ToString()

            # Check for DCSync rights (critical for security)
            if ($ace.ObjectType -eq $extendedRights['DS-Replication-Get-Changes'] -or
                $ace.ObjectType -eq $extendedRights['DS-Replication-Get-Changes-All']) {

                $results += [PSCustomObject]@{
                    Object     = 'Domain Root - DCSync'
                    ObjectPath = $domainObj.DistinguishedName
                    Trustee    = $identity
                    TrusteeSID = $ace.IdentityReference.Value
                    Rights     = "DCSync Rights ($rightName)"
                    AccessType = $ace.AccessControlType.ToString()
                    ObjectType = $ace.ObjectType.ToString()
                }
            }

            # Check for other dangerous rights
            if ($rightName -in $dangerousRights) {
                $results += [PSCustomObject]@{
                    Object     = 'Domain Root'
                    ObjectPath = $domainObj.DistinguishedName
                    Trustee    = $identity
                    TrusteeSID = $ace.IdentityReference.Value
                    Rights     = $rightName
                    AccessType = $ace.AccessControlType.ToString()
                    ObjectType = if ($ace.ObjectType) { $ace.ObjectType.ToString() } else { "All" }
                }
            }
        }
    }
    catch {
        Write-Error "Failed to audit Domain Object: $($_.Exception.Message)"
    }

    return $results
}

<#
.SYNOPSIS
    Audits ACL permissions on privileged groups
.DESCRIPTION
    Checks who has permissions to modify membership or properties of privileged groups.
    Unexpected permissions can allow privilege escalation.
.OUTPUTS
    Array of ACL entries with dangerous permissions on privileged groups
#>
function Get-PrivilegedGroupACL {
    [CmdletBinding()]
    [OutputType([array])]
    param()

    $results = @()
    $dangerousRights = Get-DangerousRights

    # List of privileged groups to audit
    $privilegedGroups = @(
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Administrators',
        'Account Operators',
        'Backup Operators',
        'Server Operators',
        'Print Operators',
        'DnsAdmins'
    )

    foreach ($groupName in $privilegedGroups) {
        try {
            $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Properties ntSecurityDescriptor -ErrorAction SilentlyContinue
            if (-not $group) {
                Write-Verbose "Group '$groupName' not found in domain"
                continue
            }

            $acl = $group.ntSecurityDescriptor.Access

            foreach ($ace in $acl) {
                # Skip inherited permissions
                if ($ace.IsInherited) { continue }

                $identity = ConvertFrom-SID -SID $ace.IdentityReference.Value

                # Skip built-in admin groups
                if (Test-IsBuiltInAdminGroup -Identity $identity) { continue }

                $rightName = $ace.ActiveDirectoryRights.ToString()

                # Check for permissions that allow group modification
                if ($rightName -like '*WriteProperty*' -or
                    $rightName -like '*Self*' -or
                    $rightName -in $dangerousRights) {

                    $results += [PSCustomObject]@{
                        GroupName  = $groupName
                        ObjectPath = $group.DistinguishedName
                        Trustee    = $identity
                        TrusteeSID = $ace.IdentityReference.Value
                        Rights     = $rightName
                        AccessType = $ace.AccessControlType.ToString()
                        ObjectType = if ($ace.ObjectType) { $ace.ObjectType.ToString() } else { "All" }
                    }
                }
            }
        }
        catch {
            Write-Warning "Could not audit group '$groupName': $($_.Exception.Message)"
        }
    }

    return $results
}

<#
.SYNOPSIS
    Audits ACL permissions on Group Policy Objects
.DESCRIPTION
    Checks who has permissions to modify GPOs.
    Unauthorized GPO modification can be used for privilege escalation and persistence.
.OUTPUTS
    Array of ACL entries with dangerous permissions on GPOs
#>
function Get-GPOObjectACL {
    [CmdletBinding()]
    [OutputType([array])]
    param()

    $results = @()
    $dangerousRights = Get-DangerousRights

    try {
        $gpos = Get-GPO -All -ErrorAction Stop

        foreach ($gpo in $gpos) {
            try {
                $gpoObj = Get-ADObject -Filter "Name -eq '$($gpo.Id)'" -SearchBase "CN=Policies,CN=System,$((Get-ADDomain).DistinguishedName)" -Properties ntSecurityDescriptor -ErrorAction SilentlyContinue

                if (-not $gpoObj) {
                    Write-Verbose "Could not find AD object for GPO: $($gpo.DisplayName)"
                    continue
                }

                $acl = $gpoObj.ntSecurityDescriptor.Access

                foreach ($ace in $acl) {
                    # Skip inherited permissions
                    if ($ace.IsInherited) { continue }

                    $identity = ConvertFrom-SID -SID $ace.IdentityReference.Value

                    # Skip built-in admin groups
                    if (Test-IsBuiltInAdminGroup -Identity $identity) { continue }

                    $rightName = $ace.ActiveDirectoryRights.ToString()

                    # Check for dangerous rights
                    if ($rightName -in $dangerousRights) {
                        $results += [PSCustomObject]@{
                            GPOName    = $gpo.DisplayName
                            ObjectPath = $gpoObj.DistinguishedName
                            Trustee    = $identity
                            TrusteeSID = $ace.IdentityReference.Value
                            Rights     = $rightName
                            AccessType = $ace.AccessControlType.ToString()
                            ObjectType = if ($ace.ObjectType) { $ace.ObjectType.ToString() } else { "All" }
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Could not audit GPO '$($gpo.DisplayName)': $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Failed to enumerate GPOs: $($_.Exception.Message)"
    }

    return $results
}

<#
.SYNOPSIS
    Audits ACL permissions on privileged user accounts
.DESCRIPTION
    Checks who has permissions to modify privileged user accounts.
    Focuses on members of Domain Admins, Enterprise Admins, Schema Admins, and Administrators.
.OUTPUTS
    Array of ACL entries with dangerous permissions on privileged users
#>
function Get-PrivilegedUserACL {
    [CmdletBinding()]
    [OutputType([array])]
    param()

    $results = @()
    $dangerousRights = Get-DangerousRights
    $extendedRights = Get-InterestingExtendedRights

    # Get privileged users from admin groups
    $adminGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')
    $privilegedUsers = @()

    foreach ($groupName in $adminGroups) {
        try {
            $members = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction SilentlyContinue |
                Where-Object { $_.objectClass -eq 'user' }
            $privilegedUsers += $members
        }
        catch {
            Write-Verbose "Could not get members of '$groupName': $($_.Exception.Message)"
        }
    }

    # Remove duplicates (users can be in multiple admin groups)
    $privilegedUsers = $privilegedUsers | Select-Object -Unique -Property SamAccountName, DistinguishedName

    foreach ($user in $privilegedUsers) {
        try {
            $userObj = Get-ADUser -Identity $user.SamAccountName -Properties ntSecurityDescriptor -ErrorAction SilentlyContinue
            if (-not $userObj) {
                Write-Verbose "Could not retrieve user: $($user.SamAccountName)"
                continue
            }

            $acl = $userObj.ntSecurityDescriptor.Access

            foreach ($ace in $acl) {
                # Skip inherited permissions
                if ($ace.IsInherited) { continue }

                $identity = ConvertFrom-SID -SID $ace.IdentityReference.Value

                # Skip built-in admin groups
                if (Test-IsBuiltInAdminGroup -Identity $identity) { continue }

                # Skip SELF (user has permission on their own account)
                if ($ace.IdentityReference.Value -eq $userObj.SID.Value) { continue }

                $rightName = $ace.ActiveDirectoryRights.ToString()

                # Check for Password Reset permission (critical)
                if ($ace.ObjectType -eq $extendedRights['User-Force-Change-Password']) {
                    $results += [PSCustomObject]@{
                        UserName   = $userObj.SamAccountName
                        ObjectPath = $userObj.DistinguishedName
                        Trustee    = $identity
                        TrusteeSID = $ace.IdentityReference.Value
                        Rights     = "User-Force-Change-Password"
                        AccessType = $ace.AccessControlType.ToString()
                        ObjectType = $ace.ObjectType.ToString()
                    }
                }

                # Check for other dangerous rights
                if ($rightName -in $dangerousRights) {
                    $results += [PSCustomObject]@{
                        UserName   = $userObj.SamAccountName
                        ObjectPath = $userObj.DistinguishedName
                        Trustee    = $identity
                        TrusteeSID = $ace.IdentityReference.Value
                        Rights     = $rightName
                        AccessType = $ace.AccessControlType.ToString()
                        ObjectType = if ($ace.ObjectType) { $ace.ObjectType.ToString() } else { "All" }
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not audit user '$($user.SamAccountName)': $($_.Exception.Message)"
        }
    }

    return $results
}

<#
.SYNOPSIS
    Audits ACL permissions on Organizational Units
.DESCRIPTION
    Checks who has permissions to modify top-level OUs.
    OU permissions can affect all objects within the OU.
.OUTPUTS
    Array of ACL entries with dangerous permissions on OUs
#>
function Get-OUObjectACL {
    [CmdletBinding()]
    [OutputType([array])]
    param()

    $results = @()
    $dangerousRights = Get-DangerousRights

    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $ous = Get-ADOrganizationalUnit -Filter * -SearchBase $domain.DistinguishedName -SearchScope OneLevel -Properties ntSecurityDescriptor -ErrorAction Stop

        foreach ($ou in $ous) {
            try {
                $acl = $ou.ntSecurityDescriptor.Access

                foreach ($ace in $acl) {
                    # Skip inherited permissions
                    if ($ace.IsInherited) { continue }

                    $identity = ConvertFrom-SID -SID $ace.IdentityReference.Value

                    # Skip built-in admin groups
                    if (Test-IsBuiltInAdminGroup -Identity $identity) { continue }

                    $rightName = $ace.ActiveDirectoryRights.ToString()

                    # Check for dangerous rights
                    if ($rightName -in $dangerousRights) {
                        $results += [PSCustomObject]@{
                            OUName     = $ou.Name
                            ObjectPath = $ou.DistinguishedName
                            Trustee    = $identity
                            TrusteeSID = $ace.IdentityReference.Value
                            Rights     = $rightName
                            AccessType = $ace.AccessControlType.ToString()
                            ObjectType = if ($ace.ObjectType) { $ace.ObjectType.ToString() } else { "All" }
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Could not audit OU '$($ou.Name)': $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Failed to enumerate OUs: $($_.Exception.Message)"
    }

    return $results
}

#endregion

#region Main Audit Function

<#
.SYNOPSIS
    Performs a comprehensive ACL permission audit
.DESCRIPTION
    Coordinates all ACL audit checks and organizes results by object type.
    Removes duplicates and categorizes findings for easier analysis.
.OUTPUTS
    Hashtable containing categorized ACL audit results
#>
function Invoke-ACLAudit {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    try {
        Write-Verbose "Starting ACL Permission Audit..."

        # 1. AdminSDHolder
        Write-Verbose "Collecting AdminSDHolder ACL data..."
        $allAdminSDHolder = Remove-DuplicateACLEntries -Entries (Get-AdminSDHolderACL)

        # 2. Domain Object
        Write-Verbose "Collecting Domain Object ACL data..."
        $allDomainObject = Remove-DuplicateACLEntries -Entries (Get-DomainObjectACL)

        # Split by type
        $domainObject_DCSync = $allDomainObject | Where-Object { $_.Object -like '*DCSync*' }
        $domainObject_Other = $allDomainObject | Where-Object { $_.Object -notlike '*DCSync*' }

        # 3. Privileged Groups
        Write-Verbose "Collecting Privileged Group ACL data..."
        $allPrivilegedGroups = Remove-DuplicateACLEntries -Entries (Get-PrivilegedGroupACL)

        # Split by group
        $privGroups_DomainAdmins = $allPrivilegedGroups | Where-Object { $_.GroupName -eq 'Domain Admins' }
        $privGroups_EnterpriseAdmins = $allPrivilegedGroups | Where-Object { $_.GroupName -eq 'Enterprise Admins' }
        $privGroups_Other = $allPrivilegedGroups | Where-Object { $_.GroupName -notin @('Domain Admins', 'Enterprise Admins') }

        # 4. GPO Objects
        Write-Verbose "Collecting GPO ACL data..."
        $allGPOs = Remove-DuplicateACLEntries -Entries (Get-GPOObjectACL)

        # 5. Privileged Users
        Write-Verbose "Collecting Privileged User ACL data..."
        $allPrivilegedUsers = Remove-DuplicateACLEntries -Entries (Get-PrivilegedUserACL)

        # Split by right type
        $privUsers_PasswordReset = $allPrivilegedUsers | Where-Object { $_.Rights -like '*Password*' }
        $privUsers_Other = $allPrivilegedUsers | Where-Object { $_.Rights -notlike '*Password*' }

        # 6. OU Objects
        Write-Verbose "Collecting OU ACL data..."
        $allOUs = Remove-DuplicateACLEntries -Entries (Get-OUObjectACL)

        # Organize results into structured output
        $results = @{
            # AdminSDHolder
            AdminSDHolder       = @{
                All = $allAdminSDHolder
            }

            # Domain Object
            DomainObject        = @{
                All    = $allDomainObject
                DCSync = $domainObject_DCSync
                Other  = $domainObject_Other
            }

            # Privileged Groups
            PrivilegedGroups    = @{
                All              = $allPrivilegedGroups
                DomainAdmins     = $privGroups_DomainAdmins
                EnterpriseAdmins = $privGroups_EnterpriseAdmins
                Other            = $privGroups_Other
            }

            # GPOs
            GPOs                = @{
                All = $allGPOs
            }

            # Privileged Users
            PrivilegedUsers     = @{
                All           = $allPrivilegedUsers
                PasswordReset = $privUsers_PasswordReset
                Other         = $privUsers_Other
            }

            # OUs
            OrganizationalUnits = @{
                All = $allOUs
            }
        }

        Write-Verbose "ACL Permission Audit completed successfully."
        return $results
    }
    catch {
        Write-Error "Failed to complete ACL audit: $($_.Exception.Message)"
        return @{}
    }
}

#endregion

# Run audit when script is executed directly (not dot-sourced)
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-ACLAudit
}
