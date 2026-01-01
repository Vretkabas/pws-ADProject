<#
.SYNOPSIS
    Delegation abuse audit functions for Module 3

.DESCRIPTION
    Contains functions to audit various types of Kerberos delegation configurations in Active Directory.
    Includes parameter validation and comprehensive error handling.

    Audited delegation types:
    - Unconstrained Delegation
    - Constrained Delegation (with/without Protocol Transition)
    - Resource-Based Constrained Delegation (RBCD)
    - Dangerous SPN Delegation
    - Delegation to Domain Controllers
    - Sensitive Accounts Not Protected
    - Admins Not in Protected Users Group
    - Pre-Windows 2000 Compatible Access
    - Service Account Delegation

#>

#Requires -Modules ActiveDirectory

#region Helper Functions

<#
.SYNOPSIS
    Retrieves list of domain controller names
.OUTPUTS
    Array of domain controller names
#>
function Get-DomainControllerNames {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    try {
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop |
            Select-Object -ExpandProperty Name
        return $dcs
    }
    catch {
        Write-Error "Failed to retrieve domain controller names: $($_.Exception.Message)"
        return @()
    }
}

#endregion

#region Delegation Check Functions

<#
.SYNOPSIS
    Finds accounts configured for unconstrained delegation
.DESCRIPTION
    Unconstrained delegation allows an account to impersonate any user to any service.
    This is a high-risk configuration that can lead to credential theft.
    Domain controllers normally have this by design; others should be reviewed.
.OUTPUTS
    Array of accounts with unconstrained delegation
#>
function Get-UnconstrainedDelegation {
    [CmdletBinding()]
    [OutputType([array])]
    param()

    try {
        $domainControllers = Get-DomainControllerNames
        $results = @()

        # Check Users
        try {
            Get-ADUser -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation, ServicePrincipalName, Enabled, Description -ErrorAction Stop |
                ForEach-Object {
                    $results += [PSCustomObject]@{
                        Name               = $_.Name
                        SamAccountName     = $_.SamAccountName
                        ObjectClass        = "user"
                        IsDomainController = $false
                        SPNs               = ($_.ServicePrincipalName -join "; ")
                        Enabled            = $_.Enabled
                        Description        = $_.Description
                    }
                }
        }
        catch {
            Write-Warning "Failed to query users with unconstrained delegation: $($_.Exception.Message)"
        }

        # Check Computers
        try {
            Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation, ServicePrincipalName, Enabled, Description -ErrorAction Stop |
                ForEach-Object {
                    $isDC = $_.Name -in $domainControllers
                    $results += [PSCustomObject]@{
                        Name               = $_.Name
                        SamAccountName     = $_.SamAccountName
                        ObjectClass        = "computer"
                        IsDomainController = $isDC
                        SPNs               = ($_.ServicePrincipalName -join "; ")
                        Enabled            = $_.Enabled
                        Description        = $_.Description
                    }
                }
        }
        catch {
            Write-Warning "Failed to query computers with unconstrained delegation: $($_.Exception.Message)"
        }

        # Check gMSAs (Group Managed Service Accounts)
        try {
            Get-ADServiceAccount -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation, ServicePrincipalName, Enabled, Description -ErrorAction Stop |
                ForEach-Object {
                    $results += [PSCustomObject]@{
                        Name               = $_.Name
                        SamAccountName     = $_.SamAccountName
                        ObjectClass        = "msDS-GroupManagedServiceAccount"
                        IsDomainController = $false
                        SPNs               = ($_.ServicePrincipalName -join "; ")
                        Enabled            = $_.Enabled
                        Description        = $_.Description
                    }
                }
        }
        catch {
            Write-Verbose "No gMSAs found with unconstrained delegation or unable to query: $($_.Exception.Message)"
        }

        return $results
    }
    catch {
        Write-Error "Failed to enumerate unconstrained delegation: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Finds accounts configured for constrained delegation
.DESCRIPTION
    Constrained delegation restricts which services an account can delegate to.
    Protocol Transition allows delegation without requiring Kerberos authentication from the client.
    This increases risk as the service can impersonate users without their knowledge.
.OUTPUTS
    Array of accounts with constrained delegation
#>
function Get-ConstrainedDelegation {
    [CmdletBinding()]
    [OutputType([array])]
    param()

    try {
        $results = @()

        # Check Users
        try {
            Get-ADUser -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties `
                msDS-AllowedToDelegateTo,
                TrustedToAuthForDelegation,
                ServicePrincipalName,
                Enabled,
                Description -ErrorAction Stop |
                ForEach-Object {
                    $results += [PSCustomObject]@{
                        Name                = $_.Name
                        SamAccountName      = $_.SamAccountName
                        ObjectClass         = "user"
                        AllowedToDelegateTo = ($_.'msDS-AllowedToDelegateTo' -join "; ")
                        AllowedToCount      = @($_.'msDS-AllowedToDelegateTo').Count
                        ProtocolTransition  = $_.TrustedToAuthForDelegation
                        DelegationType      = if ($_.TrustedToAuthForDelegation) { "ProtocolTransition" } else { "ConstrainedOnly" }
                        SPNs                = ($_.ServicePrincipalName -join "; ")
                        Enabled             = $_.Enabled
                        Description         = $_.Description
                    }
                }
        }
        catch {
            Write-Warning "Failed to query users with constrained delegation: $($_.Exception.Message)"
        }

        # Check Computers
        try {
            Get-ADComputer -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties `
                msDS-AllowedToDelegateTo,
                TrustedToAuthForDelegation,
                ServicePrincipalName,
                Enabled,
                Description -ErrorAction Stop |
                ForEach-Object {
                    $results += [PSCustomObject]@{
                        Name                = $_.Name
                        SamAccountName      = $_.SamAccountName
                        ObjectClass         = "computer"
                        AllowedToDelegateTo = ($_.'msDS-AllowedToDelegateTo' -join "; ")
                        AllowedToCount      = @($_.'msDS-AllowedToDelegateTo').Count
                        ProtocolTransition  = $_.TrustedToAuthForDelegation
                        DelegationType      = if ($_.TrustedToAuthForDelegation) { "ProtocolTransition" } else { "ConstrainedOnly" }
                        SPNs                = ($_.ServicePrincipalName -join "; ")
                        Enabled             = $_.Enabled
                        Description         = $_.Description
                    }
                }
        }
        catch {
            Write-Warning "Failed to query computers with constrained delegation: $($_.Exception.Message)"
        }

        # Check gMSAs
        try {
            Get-ADServiceAccount -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties `
                msDS-AllowedToDelegateTo,
                TrustedToAuthForDelegation,
                ServicePrincipalName,
                Enabled,
                Description -ErrorAction Stop |
                ForEach-Object {
                    $results += [PSCustomObject]@{
                        Name                = $_.Name
                        SamAccountName      = $_.SamAccountName
                        ObjectClass         = "msDS-GroupManagedServiceAccount"
                        AllowedToDelegateTo = ($_.'msDS-AllowedToDelegateTo' -join "; ")
                        AllowedToCount      = @($_.'msDS-AllowedToDelegateTo').Count
                        ProtocolTransition  = $_.TrustedToAuthForDelegation
                        DelegationType      = if ($_.TrustedToAuthForDelegation) { "ProtocolTransition" } else { "ConstrainedOnly" }
                        SPNs                = ($_.ServicePrincipalName -join "; ")
                        Enabled             = $_.Enabled
                        Description         = $_.Description
                    }
                }
        }
        catch {
            Write-Verbose "No gMSAs found with constrained delegation or unable to query: $($_.Exception.Message)"
        }

        return $results
    }
    catch {
        Write-Error "Failed to enumerate constrained delegation: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Finds accounts configured as targets for Resource-Based Constrained Delegation (RBCD)
.DESCRIPTION
    RBCD allows target resources to specify which accounts can delegate to them.
    This can be abused if an attacker gains write access to the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.
.OUTPUTS
    Array of accounts configured for RBCD
#>
function Get-ResourceBasedConstrainedDelegation {
    [CmdletBinding()]
    [OutputType([array])]
    param()

    try {
        $results = @()

        # Check Computers
        try {
            Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity, Name, SamAccountName, Enabled -ErrorAction Stop |
                Where-Object { $null -ne $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' } |
                ForEach-Object {
                    $securityDescriptor = $_.'msDS-AllowedToActOnBehalfOfOtherIdentity'
                    $allowedPrincipals = @()

                    if ($securityDescriptor) {
                        try {
                            # Parse the security descriptor to see who can delegate
                            $sd = New-Object Security.AccessControl.RawSecurityDescriptor($securityDescriptor, 0)
                            foreach ($ace in $sd.DiscretionaryAcl) {
                                try {
                                    $sid = $ace.SecurityIdentifier
                                    $identity = $sid.Translate([System.Security.Principal.NTAccount]).Value
                                    $allowedPrincipals += $identity
                                }
                                catch {
                                    $allowedPrincipals += $sid.Value
                                }
                            }
                        }
                        catch {
                            $allowedPrincipals += "[Unable to parse]"
                            Write-Verbose "Failed to parse security descriptor for $($_.Name): $($_.Exception.Message)"
                        }
                    }

                    $results += [PSCustomObject]@{
                        TargetName             = $_.Name
                        TargetSamAccountName   = $_.SamAccountName
                        TargetObjectClass      = "computer"
                        AllowedToActOnBehalf   = ($allowedPrincipals -join "; ")
                        AllowedPrincipalsCount = $allowedPrincipals.Count
                        Enabled                = $_.Enabled
                    }
                }
        }
        catch {
            Write-Warning "Failed to query computers for RBCD: $($_.Exception.Message)"
        }

        # Check Users (less common but possible)
        try {
            Get-ADUser -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity, Name, SamAccountName, Enabled -ErrorAction Stop |
                Where-Object { $null -ne $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' } |
                ForEach-Object {
                    $securityDescriptor = $_.'msDS-AllowedToActOnBehalfOfOtherIdentity'
                    $allowedPrincipals = @()

                    if ($securityDescriptor) {
                        try {
                            $sd = New-Object Security.AccessControl.RawSecurityDescriptor($securityDescriptor, 0)
                            foreach ($ace in $sd.DiscretionaryAcl) {
                                try {
                                    $sid = $ace.SecurityIdentifier
                                    $identity = $sid.Translate([System.Security.Principal.NTAccount]).Value
                                    $allowedPrincipals += $identity
                                }
                                catch {
                                    $allowedPrincipals += $sid.Value
                                }
                            }
                        }
                        catch {
                            $allowedPrincipals += "[Unable to parse]"
                            Write-Verbose "Failed to parse security descriptor for $($_.Name): $($_.Exception.Message)"
                        }
                    }

                    $results += [PSCustomObject]@{
                        TargetName             = $_.Name
                        TargetSamAccountName   = $_.SamAccountName
                        TargetObjectClass      = "user"
                        AllowedToActOnBehalf   = ($allowedPrincipals -join "; ")
                        AllowedPrincipalsCount = $allowedPrincipals.Count
                        Enabled                = $_.Enabled
                    }
                }
        }
        catch {
            Write-Warning "Failed to query users for RBCD: $($_.Exception.Message)"
        }

        # Check gMSAs (Group Managed Service Accounts)
        try {
            Get-ADServiceAccount -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity, Name, SamAccountName, Enabled -ErrorAction Stop |
                Where-Object { $null -ne $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' } |
                ForEach-Object {
                    $securityDescriptor = $_.'msDS-AllowedToActOnBehalfOfOtherIdentity'
                    $allowedPrincipals = @()

                    if ($securityDescriptor) {
                        try {
                            $sd = New-Object Security.AccessControl.RawSecurityDescriptor($securityDescriptor, 0)
                            foreach ($ace in $sd.DiscretionaryAcl) {
                                try {
                                    $sid = $ace.SecurityIdentifier
                                    $identity = $sid.Translate([System.Security.Principal.NTAccount]).Value
                                    $allowedPrincipals += $identity
                                }
                                catch {
                                    $allowedPrincipals += $sid.Value
                                }
                            }
                        }
                        catch {
                            $allowedPrincipals += "[Unable to parse]"
                            Write-Verbose "Failed to parse security descriptor for $($_.Name): $($_.Exception.Message)"
                        }
                    }

                    $results += [PSCustomObject]@{
                        TargetName             = $_.Name
                        TargetSamAccountName   = $_.SamAccountName
                        TargetObjectClass      = "msDS-GroupManagedServiceAccount"
                        AllowedToActOnBehalf   = ($allowedPrincipals -join "; ")
                        AllowedPrincipalsCount = $allowedPrincipals.Count
                        Enabled                = $_.Enabled
                    }
                }
        }
        catch {
            Write-Verbose "No gMSAs found with RBCD or unable to query: $($_.Exception.Message)"
        }

        return $results
    }
    catch {
        Write-Error "Failed to enumerate RBCD: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Finds sensitive/privileged accounts not protected against delegation
.DESCRIPTION
    Privileged accounts should have the "Account is sensitive and cannot be delegated" flag set.
    Without this protection, their credentials can be captured through delegation attacks.
.OUTPUTS
    Array of sensitive accounts not protected against delegation
#>
function Get-SensitiveAccountsNotProtected {
    [CmdletBinding()]
    [OutputType([array])]
    param()

    try {
        # List of privileged groups to check
        $privilegedGroups = @(
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators",
            "Account Operators",
            "Backup Operators",
            "Server Operators"
        )

        $results = @()
        $processedUsers = @{}

        foreach ($group in $privilegedGroups) {
            try {
                Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue |
                    Where-Object { $_.objectClass -eq 'user' } |
                    ForEach-Object {
                        # Avoid processing same user multiple times
                        if (-not $processedUsers.ContainsKey($_.SamAccountName)) {
                            try {
                                $user = Get-ADUser -Identity $_.SamAccountName -Properties AccountNotDelegated, Enabled, MemberOf -ErrorAction Stop

                                # Check if NOT protected (flag is false or not set)
                                if ($user.AccountNotDelegated -eq $false) {
                                    $processedUsers[$_.SamAccountName] = $true

                                    $results += [PSCustomObject]@{
                                        Name                = $user.Name
                                        SamAccountName      = $user.SamAccountName
                                        Enabled             = $user.Enabled
                                        AccountNotDelegated = $user.AccountNotDelegated
                                        PrivilegedGroup     = $group
                                    }
                                }
                            }
                            catch {
                                Write-Verbose "Could not process user $($_.SamAccountName): $($_.Exception.Message)"
                            }
                        }
                    }
            }
            catch {
                Write-Warning "Could not process group '$group': $($_.Exception.Message)"
            }
        }

        return $results
    }
    catch {
        Write-Error "Failed to enumerate sensitive accounts not protected: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Finds admin accounts not in Protected Users group
.DESCRIPTION
    The Protected Users group provides additional protections against credential theft.
    High-privilege accounts should be members of this group when possible.
.OUTPUTS
    Array of admin accounts not in Protected Users group
#>
function Get-AdminsNotInProtectedUsers {
    [CmdletBinding()]
    [OutputType([array])]
    param()

    try {
        $results = @()

        # Get members of Protected Users group
        try {
            $protectedUsers = Get-ADGroupMember -Identity "Protected Users" -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty SamAccountName
        }
        catch {
            $protectedUsers = @()
            Write-Warning "Could not retrieve Protected Users group members: $($_.Exception.Message)"
        }

        # List of highly privileged groups
        $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
        $processedUsers = @{}

        foreach ($group in $privilegedGroups) {
            try {
                Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue |
                    Where-Object { $_.objectClass -eq 'user' } |
                    ForEach-Object {
                        # Avoid processing same user multiple times
                        if (-not $processedUsers.ContainsKey($_.SamAccountName)) {
                            $processedUsers[$_.SamAccountName] = $true

                            # Check if NOT in Protected Users
                            if ($_.SamAccountName -notin $protectedUsers) {
                                try {
                                    $user = Get-ADUser -Identity $_.SamAccountName -Properties Enabled -ErrorAction Stop

                                    $results += [PSCustomObject]@{
                                        Name             = $user.Name
                                        SamAccountName   = $user.SamAccountName
                                        Enabled          = $user.Enabled
                                        PrivilegedGroup  = $group
                                        InProtectedUsers = $false
                                    }
                                }
                                catch {
                                    Write-Verbose "Could not process user $($_.SamAccountName): $($_.Exception.Message)"
                                }
                            }
                        }
                    }
            }
            catch {
                Write-Warning "Could not process group '$group': $($_.Exception.Message)"
            }
        }

        return $results
    }
    catch {
        Write-Error "Failed to enumerate admins not in Protected Users: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Finds accounts with constrained delegation to dangerous SPNs
.DESCRIPTION
    Certain SPNs are more dangerous than others when used with delegation.
    LDAP and KRBTGT are critical; CIFS, HOST, and MSSQL are high risk.
.OUTPUTS
    Array of accounts with dangerous SPN delegation
#>
function Get-DangerousSPNDelegation {
    [CmdletBinding()]
    [OutputType([array])]
    param()

    try {
        # Map of dangerous SPN types and their risk levels
        $dangerousSPNPatterns = @{
            "ldap"   = "CRITICAL"  # Can be used for DCSync
            "cifs"   = "HIGH"      # File share access
            "host"   = "HIGH"      # Multiple services
            "http"   = "MEDIUM"    # Web services
            "https"  = "MEDIUM"    # Secure web services
            "mssql"  = "HIGH"      # Database access
            "wsman"  = "HIGH"      # PowerShell remoting
            "rpcss"  = "HIGH"      # RPC services
            "krbtgt" = "CRITICAL"  # Kerberos ticket granting
            "gc"     = "HIGH"      # Global catalog
        }

        $results = @()

        # Check Users
        try {
            Get-ADUser -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties `
                msDS-AllowedToDelegateTo,
                Name,
                SamAccountName,
                Enabled -ErrorAction Stop |
                ForEach-Object {
                    $allowedTo = $_.'msDS-AllowedToDelegateTo'

                    if ($null -ne $allowedTo) {
                        foreach ($spn in $allowedTo) {
                            $serviceType = ($spn -split '/')[0].ToLower()

                            if ($dangerousSPNPatterns.ContainsKey($serviceType)) {
                                $results += [PSCustomObject]@{
                                    Account        = $_.Name
                                    SamAccountName = $_.SamAccountName
                                    ObjectClass    = "user"
                                    DelegatedToSPN = $spn
                                    ServiceType    = $serviceType
                                    RiskLevel      = $dangerousSPNPatterns[$serviceType]
                                    Enabled        = $_.Enabled
                                }
                            }
                        }
                    }
                }
        }
        catch {
            Write-Warning "Failed to query users for dangerous SPN delegation: $($_.Exception.Message)"
        }

        # Check Computers
        try {
            Get-ADComputer -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties `
                msDS-AllowedToDelegateTo,
                Name,
                SamAccountName,
                Enabled -ErrorAction Stop |
                ForEach-Object {
                    $allowedTo = $_.'msDS-AllowedToDelegateTo'

                    if ($null -ne $allowedTo) {
                        foreach ($spn in $allowedTo) {
                            $serviceType = ($spn -split '/')[0].ToLower()

                            if ($dangerousSPNPatterns.ContainsKey($serviceType)) {
                                $results += [PSCustomObject]@{
                                    Account        = $_.Name
                                    SamAccountName = $_.SamAccountName
                                    ObjectClass    = "computer"
                                    DelegatedToSPN = $spn
                                    ServiceType    = $serviceType
                                    RiskLevel      = $dangerousSPNPatterns[$serviceType]
                                    Enabled        = $_.Enabled
                                }
                            }
                        }
                    }
                }
        }
        catch {
            Write-Warning "Failed to query computers for dangerous SPN delegation: $($_.Exception.Message)"
        }

        # Check gMSAs
        try {
            Get-ADServiceAccount -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties `
                msDS-AllowedToDelegateTo,
                Name,
                SamAccountName,
                Enabled -ErrorAction Stop |
                ForEach-Object {
                    $allowedTo = $_.'msDS-AllowedToDelegateTo'

                    if ($null -ne $allowedTo) {
                        foreach ($spn in $allowedTo) {
                            $serviceType = ($spn -split '/')[0].ToLower()

                            if ($dangerousSPNPatterns.ContainsKey($serviceType)) {
                                $results += [PSCustomObject]@{
                                    Account        = $_.Name
                                    SamAccountName = $_.SamAccountName
                                    ObjectClass    = "msDS-GroupManagedServiceAccount"
                                    DelegatedToSPN = $spn
                                    ServiceType    = $serviceType
                                    RiskLevel      = $dangerousSPNPatterns[$serviceType]
                                    Enabled        = $_.Enabled
                                }
                            }
                        }
                    }
                }
        }
        catch {
            Write-Verbose "No gMSAs found with dangerous SPN delegation or unable to query: $($_.Exception.Message)"
        }

        return $results
    }
    catch {
        Write-Error "Failed to enumerate dangerous SPN delegation: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Finds accounts with delegation to domain controllers
.DESCRIPTION
    Delegation to domain controllers is highly sensitive.
    LDAP delegation can enable DCSync attacks; HOST and CIFS also pose significant risks.
.OUTPUTS
    Array of accounts with delegation to domain controllers
#>
function Get-DelegationToDomainControllers {
    [CmdletBinding()]
    [OutputType([array])]
    param()

    try {
        $domainControllers = Get-DomainControllerNames
        $results = @()

        # Check Users
        try {
            Get-ADUser -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties `
                msDS-AllowedToDelegateTo,
                Name,
                SamAccountName,
                Enabled -ErrorAction Stop |
                ForEach-Object {
                    $allowedTo = $_.'msDS-AllowedToDelegateTo'

                    if ($null -ne $allowedTo) {
                        foreach ($spn in $allowedTo) {
                            $targetHost = ($spn -split '/')[1]
                            if ($targetHost) {
                                $targetHost = ($targetHost -split ':')[0]  # Remove port if present
                                $targetHost = ($targetHost -split '\.')[0]  # Get hostname part

                                if ($targetHost -in $domainControllers) {
                                    $serviceType = ($spn -split '/')[0].ToLower()
                                    $results += [PSCustomObject]@{
                                        Account        = $_.Name
                                        SamAccountName = $_.SamAccountName
                                        ObjectClass    = "user"
                                        DelegatedToSPN = $spn
                                        ServiceType    = $serviceType
                                        TargetDC       = $targetHost
                                        Enabled        = $_.Enabled
                                    }
                                }
                            }
                        }
                    }
                }
        }
        catch {
            Write-Warning "Failed to query users for delegation to DCs: $($_.Exception.Message)"
        }

        # Check Computers
        try {
            Get-ADComputer -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties `
                msDS-AllowedToDelegateTo,
                Name,
                SamAccountName,
                Enabled -ErrorAction Stop |
                ForEach-Object {
                    $allowedTo = $_.'msDS-AllowedToDelegateTo'

                    if ($null -ne $allowedTo) {
                        foreach ($spn in $allowedTo) {
                            $targetHost = ($spn -split '/')[1]
                            if ($targetHost) {
                                $targetHost = ($targetHost -split ':')[0]  # Remove port if present
                                $targetHost = ($targetHost -split '\.')[0]  # Get hostname part

                                if ($targetHost -in $domainControllers) {
                                    $serviceType = ($spn -split '/')[0].ToLower()
                                    $results += [PSCustomObject]@{
                                        Account        = $_.Name
                                        SamAccountName = $_.SamAccountName
                                        ObjectClass    = "computer"
                                        DelegatedToSPN = $spn
                                        ServiceType    = $serviceType
                                        TargetDC       = $targetHost
                                        Enabled        = $_.Enabled
                                    }
                                }
                            }
                        }
                    }
                }
        }
        catch {
            Write-Warning "Failed to query computers for delegation to DCs: $($_.Exception.Message)"
        }

        # Check gMSAs
        try {
            Get-ADServiceAccount -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties `
                msDS-AllowedToDelegateTo,
                Name,
                SamAccountName,
                Enabled -ErrorAction Stop |
                ForEach-Object {
                    $allowedTo = $_.'msDS-AllowedToDelegateTo'

                    if ($null -ne $allowedTo) {
                        foreach ($spn in $allowedTo) {
                            $targetHost = ($spn -split '/')[1]
                            if ($targetHost) {
                                $targetHost = ($targetHost -split ':')[0]  # Remove port if present
                                $targetHost = ($targetHost -split '\.')[0]  # Get hostname part

                                if ($targetHost -in $domainControllers) {
                                    $serviceType = ($spn -split '/')[0].ToLower()
                                    $results += [PSCustomObject]@{
                                        Account        = $_.Name
                                        SamAccountName = $_.SamAccountName
                                        ObjectClass    = "msDS-GroupManagedServiceAccount"
                                        DelegatedToSPN = $spn
                                        ServiceType    = $serviceType
                                        TargetDC       = $targetHost
                                        Enabled        = $_.Enabled
                                    }
                                }
                            }
                        }
                    }
                }
        }
        catch {
            Write-Verbose "No gMSAs found with delegation to DCs or unable to query: $($_.Exception.Message)"
        }

        return $results
    }
    catch {
        Write-Error "Failed to enumerate delegation to DCs: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Checks Pre-Windows 2000 Compatible Access group membership
.DESCRIPTION
    This group should not contain dangerous principals like Everyone, Anonymous Logon, or Authenticated Users.
    These memberships can allow unauthorized access to user information.
.OUTPUTS
    Array of Pre-Windows 2000 Compatible Access group members
#>
function Get-PreWindows2000CompatibleAccess {
    [CmdletBinding()]
    [OutputType([array])]
    param()

    try {
        $results = @()

        # Dangerous well-known SIDs and names
        $dangerousMembers = @("S-1-5-7", "S-1-1-0", "S-1-5-11")  # Anonymous Logon, Everyone, Authenticated Users
        $dangerousNames = @("Anonymous Logon", "Everyone", "Authenticated Users", "ANONYMOUS LOGON")

        try {
            $members = Get-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" -ErrorAction Stop

            foreach ($member in $members) {
                $isDangerous = $member.Name -in $dangerousNames -or $member.SID.Value -in $dangerousMembers

                $results += [PSCustomObject]@{
                    MemberName  = $member.Name
                    MemberSID   = $member.SID.Value
                    ObjectClass = $member.objectClass
                    IsDangerous = $isDangerous
                }
            }
        }
        catch {
            Write-Warning "Could not retrieve Pre-Windows 2000 Compatible Access group: $($_.Exception.Message)"
        }

        return $results
    }
    catch {
        Write-Error "Failed to enumerate Pre-Windows 2000 Compatible Access: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Finds Group Managed Service Accounts (gMSAs) with delegation configured
.DESCRIPTION
    Audits gMSAs for all types of delegation configurations.
    gMSAs are designed for service accounts and may legitimately have delegation,
    but should still be reviewed.
.OUTPUTS
    Array of gMSAs with delegation configured
#>
function Get-ServiceAccountDelegation {
    [CmdletBinding()]
    [OutputType([array])]
    param()

    try {
        $results = @()

        # Check gMSAs for any delegation configuration
        try {
            Get-ADServiceAccount -Filter * -Properties `
                TrustedForDelegation,
                TrustedToAuthForDelegation,
                msDS-AllowedToDelegateTo,
                msDS-AllowedToActOnBehalfOfOtherIdentity,
                ServicePrincipalName -ErrorAction Stop |
                ForEach-Object {
                    $issues = @()

                    # Identify all delegation types configured
                    if ($_.TrustedForDelegation) { $issues += "Unconstrained Delegation" }
                    if ($_.TrustedToAuthForDelegation) { $issues += "Protocol Transition" }
                    if ($_.'msDS-AllowedToDelegateTo') { $issues += "Constrained Delegation" }
                    if ($_.'msDS-AllowedToActOnBehalfOfOtherIdentity') { $issues += "RBCD Target" }

                    # Only include if at least one delegation type is configured
                    if ($issues.Count -gt 0) {
                        $results += [PSCustomObject]@{
                            Name                = $_.Name
                            SamAccountName      = $_.SamAccountName
                            ObjectClass         = "msDS-GroupManagedServiceAccount"
                            DelegationTypes     = ($issues -join ", ")
                            AllowedToDelegateTo = ($_.'msDS-AllowedToDelegateTo' -join "; ")
                            SPNs                = ($_.ServicePrincipalName -join "; ")
                        }
                    }
                }
        }
        catch {
            Write-Verbose "No gMSAs found or unable to query: $($_.Exception.Message)"
        }

        return $results
    }
    catch {
        Write-Error "Failed to enumerate service account delegation: $($_.Exception.Message)"
        return @()
    }
}

#endregion

#region Main Audit Function

<#
.SYNOPSIS
    Performs a comprehensive delegation abuse audit
.DESCRIPTION
    Coordinates all delegation checks and organizes results by type and risk level.
    Returns a structured hashtable with categorized findings.
.OUTPUTS
    Hashtable containing categorized delegation audit results
#>
function Invoke-DelegationAudit {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    try {
        Write-Verbose "Starting Delegation Audit..."

        # 1. UNCONSTRAINED DELEGATION
        Write-Verbose "Collecting Unconstrained Delegation data..."
        $allUnconstrainedDelegation = Get-UnconstrainedDelegation

        # Split by object type and risk level
        $unconstrainedDelegationU = $allUnconstrainedDelegation | Where-Object { $_.ObjectClass -eq "user" }                                                                    # CRITICAL
        $unconstrainedDelegationC = $allUnconstrainedDelegation | Where-Object { $_.ObjectClass -eq "computer" -and $_.IsDomainController -eq $false }                        # HIGH
        $unconstrainedDelegationS = $allUnconstrainedDelegation | Where-Object { $_.ObjectClass -eq "msDS-GroupManagedServiceAccount" }                                       # HIGH
        $unconstrainedDelegationDC = $allUnconstrainedDelegation | Where-Object { $_.ObjectClass -eq "computer" -and $_.IsDomainController -eq $true }                        # EXPECTED (informational)

        # 2. CONSTRAINED DELEGATION
        Write-Verbose "Collecting Constrained Delegation data..."
        $allConstrainedDelegation = Get-ConstrainedDelegation

        # Split by object type and protocol transition
        # Users
        $constrainedDelegationU_KerbOnly = $allConstrainedDelegation | Where-Object { $_.ObjectClass -eq "user" -and $_.ProtocolTransition -eq $false }                      # MEDIUM
        $constrainedDelegationU_WithPT = $allConstrainedDelegation | Where-Object { $_.ObjectClass -eq "user" -and $_.ProtocolTransition -eq $true }                         # HIGH

        # Computers
        $constrainedDelegationC_KerbOnly = $allConstrainedDelegation | Where-Object { $_.ObjectClass -eq "computer" -and $_.ProtocolTransition -eq $false }                  # LOW
        $constrainedDelegationC_WithPT = $allConstrainedDelegation | Where-Object { $_.ObjectClass -eq "computer" -and $_.ProtocolTransition -eq $true }                     # MEDIUM

        # Service Accounts (gMSA)
        $constrainedDelegationS_KerbOnly = $allConstrainedDelegation | Where-Object { $_.ObjectClass -eq "msDS-GroupManagedServiceAccount" -and $_.ProtocolTransition -eq $false }  # LOW
        $constrainedDelegationS_WithPT = $allConstrainedDelegation | Where-Object { $_.ObjectClass -eq "msDS-GroupManagedServiceAccount" -and $_.ProtocolTransition -eq $true }    # MEDIUM

        # 3. RESOURCE-BASED CONSTRAINED DELEGATION (RBCD)
        Write-Verbose "Collecting RBCD data..."
        $allRBCD = Get-ResourceBasedConstrainedDelegation

        # Split by target object type
        $rbcdTargetComputers = $allRBCD | Where-Object { $_.TargetObjectClass -eq "computer" }                                                                                # MEDIUM-CRITICAL (depends on principals)
        $rbcdTargetUsers = $allRBCD | Where-Object { $_.TargetObjectClass -eq "user" }                                                                                        # CRITICAL (very unusual)
        $rbcdTargetGMSA = $allRBCD | Where-Object { $_.TargetObjectClass -eq "msDS-GroupManagedServiceAccount" }                                                              # MEDIUM

        # 4. SENSITIVE ACCOUNTS NOT PROTECTED
        Write-Verbose "Collecting Sensitive Accounts Not Protected data..."
        $allSensitiveNotProtected = Get-SensitiveAccountsNotProtected

        # Split by enabled/disabled and privileged group
        $sensitiveNotProtected_Enabled = $allSensitiveNotProtected | Where-Object { $_.Enabled -eq $true }                                                                    # HIGH
        $sensitiveNotProtected_Disabled = $allSensitiveNotProtected | Where-Object { $_.Enabled -eq $false }                                                                  # MEDIUM

        # Group by privileged group for better reporting
        $sensitiveByGroup = $allSensitiveNotProtected | Group-Object -Property PrivilegedGroup

        # 5. ADMINS NOT IN PROTECTED USERS
        Write-Verbose "Collecting Admins Not in Protected Users data..."
        $allAdminsNotProtected = Get-AdminsNotInProtectedUsers

        # Split by enabled/disabled
        $adminsNotProtected_Enabled = $allAdminsNotProtected | Where-Object { $_.Enabled -eq $true }                                                                          # MEDIUM
        $adminsNotProtected_Disabled = $allAdminsNotProtected | Where-Object { $_.Enabled -eq $false }                                                                        # LOW

        # Group by privileged group
        $adminsNotProtectedByGroup = $allAdminsNotProtected | Group-Object -Property PrivilegedGroup

        # 6. DANGEROUS SPN DELEGATION
        Write-Verbose "Collecting Dangerous SPN Delegation data..."
        $allDangerousSPN = Get-DangerousSPNDelegation

        # Split by risk level
        $dangerousSPN_Critical = $allDangerousSPN | Where-Object { $_.RiskLevel -eq "CRITICAL" }                                                                              # ldap, krbtgt
        $dangerousSPN_High = $allDangerousSPN | Where-Object { $_.RiskLevel -eq "HIGH" }                                                                                      # cifs, host, wsman, mssql, gc, rpcss
        $dangerousSPN_Medium = $allDangerousSPN | Where-Object { $_.RiskLevel -eq "MEDIUM" }                                                                                  # http, https

        # Split by object type
        $dangerousSPN_Users = $allDangerousSPN | Where-Object { $_.ObjectClass -eq "user" }
        $dangerousSPN_Computers = $allDangerousSPN | Where-Object { $_.ObjectClass -eq "computer" }
        $dangerousSPN_ServiceAccounts = $allDangerousSPN | Where-Object { $_.ObjectClass -eq "msDS-GroupManagedServiceAccount" }

        # 7. DELEGATION TO DOMAIN CONTROLLERS
        Write-Verbose "Collecting Delegation to Domain Controllers data..."
        $allDelegationToDCs = Get-DelegationToDomainControllers

        # Split by service type
        $delegationToDC_LDAP = $allDelegationToDCs | Where-Object { $_.ServiceType -eq "ldap" }                                                                               # CRITICAL (DCSync!)
        $delegationToDC_CIFS = $allDelegationToDCs | Where-Object { $_.ServiceType -eq "cifs" }                                                                               # CRITICAL
        $delegationToDC_HOST = $allDelegationToDCs | Where-Object { $_.ServiceType -eq "host" }                                                                               # CRITICAL
        $delegationToDC_Other = $allDelegationToDCs | Where-Object { $_.ServiceType -notin @("ldap", "cifs", "host") }                                                       # HIGH

        # 8. PRE-WINDOWS 2000 COMPATIBLE ACCESS
        Write-Verbose "Collecting Pre-Windows 2000 Compatible Access data..."
        $allPreWin2000 = Get-PreWindows2000CompatibleAccess

        # Split by dangerous members
        $preWin2000_Dangerous = $allPreWin2000 | Where-Object { $_.IsDangerous -eq $true }                                                                                    # HIGH (Anonymous, Everyone, Auth Users)
        $preWin2000_Other = $allPreWin2000 | Where-Object { $_.IsDangerous -eq $false }                                                                                       # LOW

        # 9. SERVICE ACCOUNT (gMSA) DELEGATION
        Write-Verbose "Collecting Service Account Delegation data..."
        $allServiceAccountDelegation = Get-ServiceAccountDelegation

        # Split by delegation type
        $serviceAcctDelegation_Unconstrained = $allServiceAccountDelegation | Where-Object { $_.DelegationTypes -like "*Unconstrained*" }                                     # HIGH
        $serviceAcctDelegation_ProtocolTransition = $allServiceAccountDelegation | Where-Object { $_.DelegationTypes -like "*Protocol Transition*" }                         # MEDIUM
        $serviceAcctDelegation_Constrained = $allServiceAccountDelegation | Where-Object { $_.DelegationTypes -like "*Constrained Delegation*" -and $_.DelegationTypes -notlike "*Protocol*" } # LOW
        $serviceAcctDelegation_RBCD = $allServiceAccountDelegation | Where-Object { $_.DelegationTypes -like "*RBCD*" }                                                       # MEDIUM

        # Organize results into structured output
        $results = @{
            # Section 1: Unconstrained Delegation
            UnconstrainedDelegation       = @{
                All               = $allUnconstrainedDelegation
                Users             = $unconstrainedDelegationU
                Computers         = $unconstrainedDelegationC
                ServiceAccounts   = $unconstrainedDelegationS
                DomainControllers = $unconstrainedDelegationDC
            }

            # Section 2: Constrained Delegation
            ConstrainedDelegation         = @{
                All                                    = $allConstrainedDelegation
                Users_KerberosOnly                     = $constrainedDelegationU_KerbOnly
                Users_WithProtocolTransition           = $constrainedDelegationU_WithPT
                Computers_KerberosOnly                 = $constrainedDelegationC_KerbOnly
                Computers_WithProtocolTransition       = $constrainedDelegationC_WithPT
                ServiceAccounts_KerberosOnly           = $constrainedDelegationS_KerbOnly
                ServiceAccounts_WithProtocolTransition = $constrainedDelegationS_WithPT
            }

            # Section 3: RBCD
            RBCD                          = @{
                All             = $allRBCD
                TargetComputers = $rbcdTargetComputers
                TargetUsers     = $rbcdTargetUsers
                TargetGMSA      = $rbcdTargetGMSA
            }

            # Section 4: Sensitive Accounts Not Protected
            SensitiveAccountsNotProtected = @{
                All      = $allSensitiveNotProtected
                Enabled  = $sensitiveNotProtected_Enabled
                Disabled = $sensitiveNotProtected_Disabled
                ByGroup  = $sensitiveByGroup
            }

            # Section 5: Admins Not in Protected Users
            AdminsNotInProtectedUsers     = @{
                All      = $allAdminsNotProtected
                Enabled  = $adminsNotProtected_Enabled
                Disabled = $adminsNotProtected_Disabled
                ByGroup  = $adminsNotProtectedByGroup
            }

            # Section 6: Dangerous SPN Delegation
            DangerousSPNDelegation        = @{
                All             = $allDangerousSPN
                Critical        = $dangerousSPN_Critical
                High            = $dangerousSPN_High
                Medium          = $dangerousSPN_Medium
                Users           = $dangerousSPN_Users
                Computers       = $dangerousSPN_Computers
                ServiceAccounts = $dangerousSPN_ServiceAccounts
            }

            # Section 7: Delegation to Domain Controllers
            DelegationToDCs               = @{
                All   = $allDelegationToDCs
                LDAP  = $delegationToDC_LDAP
                CIFS  = $delegationToDC_CIFS
                HOST  = $delegationToDC_HOST
                Other = $delegationToDC_Other
            }

            # Section 8: Pre-Windows 2000 Compatible Access
            PreWindows2000                = @{
                All       = $allPreWin2000
                Dangerous = $preWin2000_Dangerous
                Other     = $preWin2000_Other
            }

            # Section 9: Service Account Delegation
            ServiceAccountDelegation      = @{
                All                = $allServiceAccountDelegation
                Unconstrained      = $serviceAcctDelegation_Unconstrained
                ProtocolTransition = $serviceAcctDelegation_ProtocolTransition
                Constrained        = $serviceAcctDelegation_Constrained
                RBCD               = $serviceAcctDelegation_RBCD
            }
        }

        Write-Verbose "Delegation Audit completed successfully."
        return $results
    }
    catch {
        Write-Error "Failed to complete delegation audit: $($_.Exception.Message)"
        return @{}
    }
}

#endregion

# Run audit when script is executed directly (not dot-sourced)
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-DelegationAudit
}
