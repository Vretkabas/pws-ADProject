#Requires -Modules ActiveDirectory

#region Helper Functions

function Get-DangerousRights {
    return @(
        'GenericAll',
        'GenericWrite',
        'WriteDacl',
        'WriteOwner',
        'WriteProperty'
    )
}

function Get-InterestingExtendedRights {
    return @{
        'User-Force-Change-Password'                     = '00299570-246d-11d0-a768-00aa006e0529'
        'DS-Replication-Get-Changes'                     = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
        'DS-Replication-Get-Changes-All'                 = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
        'DS-Replication-Get-Changes-In-Filtered-Set'     = '89e95b76-444d-4c62-991a-0facbeda640c'
        'User-Account-Restrictions'                      = '4c164200-20c0-11d0-a768-00aa006e0529'
        'Validated-SPN'                                  = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
    }
}

function ConvertFrom-SID {
    param([string]$SID)

    try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
        $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
        return $objUser.Value
    }
    catch {
        return $SID
    }
}

function Test-IsBuiltInAdminGroup {
    param([string]$Identity)

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

function Remove-DuplicateACLEntries {
    param([array]$Entries)

    if (-not $Entries -or $Entries.Count -eq 0) {
        return @()
    }

    # Group by unique combination van Trustee + ObjectPath + Rights
    $uniqueEntries = $Entries | Group-Object -Property @{Expression={
        "$($_.Trustee)|$($_.ObjectPath)|$($_.Rights)"
    }} | ForEach-Object { $_.Group | Select-Object -First 1 }

    return $uniqueEntries
}

#endregion

#region ACL Check Functions

# 1. AdminSDHolder ACL Audit
function Get-AdminSDHolderACL {
    [CmdletBinding()]
    param()

    $results = @()
    $dangerousRights = Get-DangerousRights

    try {
        $domain = Get-ADDomain
        $adminSDHolder = Get-ADObject -Identity "CN=AdminSDHolder,CN=System,$($domain.DistinguishedName)" -Properties ntSecurityDescriptor

        $acl = $adminSDHolder.ntSecurityDescriptor.Access

        foreach ($ace in $acl) {
            if ($ace.IsInherited) { continue }

            $identity = ConvertFrom-SID -SID $ace.IdentityReference.Value
            if (Test-IsBuiltInAdminGroup -Identity $identity) { continue }

            $rightName = $ace.ActiveDirectoryRights.ToString()

            if ($rightName -in $dangerousRights -or $rightName -like '*All*' -or $rightName -like '*Write*') {
                $results += [PSCustomObject]@{
                    Object       = 'AdminSDHolder'
                    ObjectPath   = $adminSDHolder.DistinguishedName
                    Trustee      = $identity
                    TrusteeSID   = $ace.IdentityReference.Value
                    Rights       = $rightName
                    AccessType   = $ace.AccessControlType.ToString()
                    ObjectType   = if ($ace.ObjectType) { $ace.ObjectType.ToString() } else { "All" }
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to audit AdminSDHolder: $_"
    }

    return $results
}

# 2. Domain Object ACL Audit
function Get-DomainObjectACL {
    [CmdletBinding()]
    param()

    $results = @()
    $dangerousRights = Get-DangerousRights
    $extendedRights = Get-InterestingExtendedRights

    try {
        $domain = Get-ADDomain
        $domainObj = Get-ADObject -Identity $domain.DistinguishedName -Properties ntSecurityDescriptor

        $acl = $domainObj.ntSecurityDescriptor.Access

        foreach ($ace in $acl) {
            if ($ace.IsInherited) { continue }

            $identity = ConvertFrom-SID -SID $ace.IdentityReference.Value
            if (Test-IsBuiltInAdminGroup -Identity $identity) { continue }

            $rightName = $ace.ActiveDirectoryRights.ToString()

            # Check voor DCSync rights
            if ($ace.ObjectType -eq $extendedRights['DS-Replication-Get-Changes'] -or
                $ace.ObjectType -eq $extendedRights['DS-Replication-Get-Changes-All']) {

                $results += [PSCustomObject]@{
                    Object       = 'Domain Root - DCSync'
                    ObjectPath   = $domainObj.DistinguishedName
                    Trustee      = $identity
                    TrusteeSID   = $ace.IdentityReference.Value
                    Rights       = "DCSync Rights ($rightName)"
                    AccessType   = $ace.AccessControlType.ToString()
                    ObjectType   = $ace.ObjectType.ToString()
                }
            }

            # Check voor andere dangerous rights
            if ($rightName -in $dangerousRights) {
                $results += [PSCustomObject]@{
                    Object       = 'Domain Root'
                    ObjectPath   = $domainObj.DistinguishedName
                    Trustee      = $identity
                    TrusteeSID   = $ace.IdentityReference.Value
                    Rights       = $rightName
                    AccessType   = $ace.AccessControlType.ToString()
                    ObjectType   = if ($ace.ObjectType) { $ace.ObjectType.ToString() } else { "All" }
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to audit Domain Object: $_"
    }

    return $results
}

# 3. Privileged Group ACL Audit
function Get-PrivilegedGroupACL {
    [CmdletBinding()]
    param()

    $results = @()
    $dangerousRights = Get-DangerousRights

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
            if (-not $group) { continue }

            $acl = $group.ntSecurityDescriptor.Access

            foreach ($ace in $acl) {
                if ($ace.IsInherited) { continue }

                $identity = ConvertFrom-SID -SID $ace.IdentityReference.Value
                if (Test-IsBuiltInAdminGroup -Identity $identity) { continue }

                $rightName = $ace.ActiveDirectoryRights.ToString()

                if ($rightName -like '*WriteProperty*' -or
                    $rightName -like '*Self*' -or
                    $rightName -in $dangerousRights) {

                    $results += [PSCustomObject]@{
                        GroupName    = $groupName
                        ObjectPath   = $group.DistinguishedName
                        Trustee      = $identity
                        TrusteeSID   = $ace.IdentityReference.Value
                        Rights       = $rightName
                        AccessType   = $ace.AccessControlType.ToString()
                        ObjectType   = if ($ace.ObjectType) { $ace.ObjectType.ToString() } else { "All" }
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not audit group $groupName : $_"
        }
    }

    return $results
}

# 4. GPO Object ACL Audit
function Get-GPOObjectACL {
    [CmdletBinding()]
    param()

    $results = @()
    $dangerousRights = Get-DangerousRights

    try {
        $gpos = Get-GPO -All -ErrorAction Stop

        foreach ($gpo in $gpos) {
            try {
                $gpoObj = Get-ADObject -Filter "Name -eq '$($gpo.Id)'" -SearchBase "CN=Policies,CN=System,$((Get-ADDomain).DistinguishedName)" -Properties ntSecurityDescriptor -ErrorAction SilentlyContinue

                if (-not $gpoObj) { continue }

                $acl = $gpoObj.ntSecurityDescriptor.Access

                foreach ($ace in $acl) {
                    if ($ace.IsInherited) { continue }

                    $identity = ConvertFrom-SID -SID $ace.IdentityReference.Value
                    if (Test-IsBuiltInAdminGroup -Identity $identity) { continue }

                    $rightName = $ace.ActiveDirectoryRights.ToString()

                    if ($rightName -in $dangerousRights) {
                        $results += [PSCustomObject]@{
                            GPOName      = $gpo.DisplayName
                            ObjectPath   = $gpoObj.DistinguishedName
                            Trustee      = $identity
                            TrusteeSID   = $ace.IdentityReference.Value
                            Rights       = $rightName
                            AccessType   = $ace.AccessControlType.ToString()
                            ObjectType   = if ($ace.ObjectType) { $ace.ObjectType.ToString() } else { "All" }
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Could not audit GPO $($gpo.DisplayName): $_"
            }
        }
    }
    catch {
        Write-Warning "Failed to enumerate GPOs: $_"
    }

    return $results
}

# 5. Privileged User Object ACL Audit
function Get-PrivilegedUserACL {
    [CmdletBinding()]
    param()

    $results = @()
    $dangerousRights = Get-DangerousRights
    $extendedRights = Get-InterestingExtendedRights

    # Haal privileged users op
    $adminGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')
    $privilegedUsers = @()

    foreach ($groupName in $adminGroups) {
        try {
            $members = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction SilentlyContinue |
            Where-Object { $_.objectClass -eq 'user' }
            $privilegedUsers += $members
        }
        catch {
            Write-Verbose "Could not get members of $groupName"
        }
    }

    $privilegedUsers = $privilegedUsers | Select-Object -Unique -Property SamAccountName, DistinguishedName

    foreach ($user in $privilegedUsers) {
        try {
            $userObj = Get-ADUser -Identity $user.SamAccountName -Properties ntSecurityDescriptor -ErrorAction SilentlyContinue
            if (-not $userObj) { continue }

            $acl = $userObj.ntSecurityDescriptor.Access

            foreach ($ace in $acl) {
                if ($ace.IsInherited) { continue }

                $identity = ConvertFrom-SID -SID $ace.IdentityReference.Value
                if (Test-IsBuiltInAdminGroup -Identity $identity) { continue }

                # Skip SELF
                if ($ace.IdentityReference.Value -eq $userObj.SID.Value) { continue }

                $rightName = $ace.ActiveDirectoryRights.ToString()

                # Check voor Password Reset
                if ($ace.ObjectType -eq $extendedRights['User-Force-Change-Password']) {
                    $results += [PSCustomObject]@{
                        UserName     = $userObj.SamAccountName
                        ObjectPath   = $userObj.DistinguishedName
                        Trustee      = $identity
                        TrusteeSID   = $ace.IdentityReference.Value
                        Rights       = "User-Force-Change-Password"
                        AccessType   = $ace.AccessControlType.ToString()
                        ObjectType   = $ace.ObjectType.ToString()
                    }
                }

                # Check voor andere dangerous rights
                if ($rightName -in $dangerousRights) {
                    $results += [PSCustomObject]@{
                        UserName     = $userObj.SamAccountName
                        ObjectPath   = $userObj.DistinguishedName
                        Trustee      = $identity
                        TrusteeSID   = $ace.IdentityReference.Value
                        Rights       = $rightName
                        AccessType   = $ace.AccessControlType.ToString()
                        ObjectType   = if ($ace.ObjectType) { $ace.ObjectType.ToString() } else { "All" }
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not audit user $($user.SamAccountName): $_"
        }
    }

    return $results
}

# 6. OU Object ACL Audit
function Get-OUObjectACL {
    [CmdletBinding()]
    param()

    $results = @()
    $dangerousRights = Get-DangerousRights

    try {
        $domain = Get-ADDomain
        $ous = Get-ADOrganizationalUnit -Filter * -SearchBase $domain.DistinguishedName -SearchScope OneLevel -Properties ntSecurityDescriptor

        foreach ($ou in $ous) {
            $acl = $ou.ntSecurityDescriptor.Access

            foreach ($ace in $acl) {
                if ($ace.IsInherited) { continue }

                $identity = ConvertFrom-SID -SID $ace.IdentityReference.Value
                if (Test-IsBuiltInAdminGroup -Identity $identity) { continue }

                $rightName = $ace.ActiveDirectoryRights.ToString()

                if ($rightName -in $dangerousRights) {
                    $results += [PSCustomObject]@{
                        OUName       = $ou.Name
                        ObjectPath   = $ou.DistinguishedName
                        Trustee      = $identity
                        TrusteeSID   = $ace.IdentityReference.Value
                        Rights       = $rightName
                        AccessType   = $ace.AccessControlType.ToString()
                        ObjectType   = if ($ace.ObjectType) { $ace.ObjectType.ToString() } else { "All" }
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to audit OUs: $_"
    }

    return $results
}

#endregion

#region Main Audit Function

function Invoke-ACLAudit {
    [CmdletBinding()]
    param()

    Write-Verbose "Starting ACL Permission Audit..."

    # 1. ADMINSDHOLDER
    Write-Verbose "Collecting AdminSDHolder ACL data..."
    $allAdminSDHolder = Remove-DuplicateACLEntries -Entries (Get-AdminSDHolderACL)

    # DOMAIN OBJECT
    Write-Verbose "Collecting Domain Object ACL data..."
    $allDomainObject = Remove-DuplicateACLEntries -Entries (Get-DomainObjectACL)

    # Split by type
    $domainObject_DCSync = $allDomainObject | Where-Object { $_.Object -like '*DCSync*' }
    $domainObject_Other = $allDomainObject | Where-Object { $_.Object -notlike '*DCSync*' }

    # PRIVILEGED GROUPS
    Write-Verbose "Collecting Privileged Group ACL data..."
    $allPrivilegedGroups = Remove-DuplicateACLEntries -Entries (Get-PrivilegedGroupACL)

    # Split by group
    $privGroups_DomainAdmins = $allPrivilegedGroups | Where-Object { $_.GroupName -eq 'Domain Admins' }
    $privGroups_EnterpriseAdmins = $allPrivilegedGroups | Where-Object { $_.GroupName -eq 'Enterprise Admins' }
    $privGroups_Other = $allPrivilegedGroups | Where-Object { $_.GroupName -notin @('Domain Admins', 'Enterprise Admins') }

    # GPO OBJECTS
    Write-Verbose "Collecting GPO ACL data..."
    $allGPOs = Remove-DuplicateACLEntries -Entries (Get-GPOObjectACL)

    # PRIVILEGED USERS
    Write-Verbose "Collecting Privileged User ACL data..."
    $allPrivilegedUsers = Remove-DuplicateACLEntries -Entries (Get-PrivilegedUserACL)

    # Split by right type
    $privUsers_PasswordReset = $allPrivilegedUsers | Where-Object { $_.Rights -like '*Password*' }
    $privUsers_Other = $allPrivilegedUsers | Where-Object { $_.Rights -notlike '*Password*' }

    # OU OBJECTS
    Write-Verbose "Collecting OU ACL data..."
    $allOUs = Remove-DuplicateACLEntries -Entries (Get-OUObjectACL)

    $results = @{
        # AdminSDHolder
        AdminSDHolder      = @{
            All = $allAdminSDHolder
        }

        # Domain Object
        DomainObject       = @{
            All    = $allDomainObject
            DCSync = $domainObject_DCSync
            Other  = $domainObject_Other
        }

        # Privileged Groups
        PrivilegedGroups   = @{
            All               = $allPrivilegedGroups
            DomainAdmins      = $privGroups_DomainAdmins
            EnterpriseAdmins  = $privGroups_EnterpriseAdmins
            Other             = $privGroups_Other
        }

        # GPOs
        GPOs               = @{
            All = $allGPOs
        }

        # Privileged Users
        PrivilegedUsers    = @{
            All           = $allPrivilegedUsers
            PasswordReset = $privUsers_PasswordReset
            Other         = $privUsers_Other
        }

        # OUs
        OrganizationalUnits = @{
            All = $allOUs
        }
    }

    Write-Verbose "ACL Permission Audit completed."
    return $results
}

#endregion

# Run audit when script is executed directly
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-ACLAudit
}
