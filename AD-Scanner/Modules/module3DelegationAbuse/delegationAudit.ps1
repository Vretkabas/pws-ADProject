#Requires -Modules ActiveDirectory

#region Helper Functions
function Get-DomainControllerNames {
    return Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name
}

#endregion

#region Delegation Check Functions

# 1. Unconstrained Delegation (excluding DCs)
function Get-UnconstrainedDelegation {
    [CmdletBinding()]
    param()

    $domainControllers = Get-DomainControllerNames
    $results = @()

    # Users
    Get-ADUser -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation, ServicePrincipalName, Enabled, Description |
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

    # Computers
    Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation, ServicePrincipalName, Enabled, Description |
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

    # gMSAs (Group Managed Service Accounts)
    try {
        Get-ADServiceAccount -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation, ServicePrincipalName, Enabled, Description |
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
        Write-Verbose "No gMSAs found with unconstrained delegation or unable to query: $_"
    }

    return $results
}

# 2. Constrained Delegation met Protocol Transition detail
function Get-ConstrainedDelegation {
    [CmdletBinding()]
    param()

    $results = @()

    # Users
    Get-ADUser -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties `
        msDS-AllowedToDelegateTo,
    TrustedToAuthForDelegation,
    ServicePrincipalName,
    Enabled,
    Description |
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

    # Computers
    Get-ADComputer -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties `
        msDS-AllowedToDelegateTo,
    TrustedToAuthForDelegation,
    ServicePrincipalName,
    Enabled,
    Description |
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

    # gMSAs
    try {
        Get-ADServiceAccount -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties `
            msDS-AllowedToDelegateTo,
        TrustedToAuthForDelegation,
        ServicePrincipalName,
        Enabled,
        Description |
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
        Write-Verbose "No gMSAs found with constrained delegation or unable to query: $_"
    }

    return $results
}

# 3. Resource-Based Constrained Delegation (RBCD)
function Get-ResourceBasedConstrainedDelegation {
    [CmdletBinding()]
    param()

    $results = @()

    # Check computers
    Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity, Name, SamAccountName, Enabled |
    Where-Object { $null -ne $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' } |
    ForEach-Object {
        $securityDescriptor = $_.'msDS-AllowedToActOnBehalfOfOtherIdentity'
        $allowedPrincipals = @()

        if ($securityDescriptor) {
            try {
                # Parse de security descriptor om te zien wie mag delegeren
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

    # Check users (less common but possible)
    Get-ADUser -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity, Name, SamAccountName, Enabled |
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

    # Check gMSAs (Group Managed Service Accounts)
    try {
        Get-ADServiceAccount -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity, Name, SamAccountName, Enabled |
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
        Write-Verbose "No gMSAs found with RBCD or unable to query: $_"
    }

    return $results
}

# 4. Sensitive Accounts Not Protected Against Delegation
function Get-SensitiveAccountsNotProtected {
    [CmdletBinding()]
    param()
    
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
                if (-not $processedUsers.ContainsKey($_.SamAccountName)) {
                    $user = Get-ADUser -Identity $_.SamAccountName -Properties AccountNotDelegated, Enabled, MemberOf
                    
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
            }
        }
        catch {
            Write-Warning "Could not process group: $group - $_"
        }
    }
    
    return $results
}

# 5. Admins Not in Protected Users Group
function Get-AdminsNotInProtectedUsers {
    [CmdletBinding()]
    param()
    
    $results = @()
    
    try {
        $protectedUsers = Get-ADGroupMember -Identity "Protected Users" -ErrorAction SilentlyContinue | 
        Select-Object -ExpandProperty SamAccountName
    }
    catch {
        $protectedUsers = @()
        Write-Warning "Could not retrieve Protected Users group members"
    }
    
    $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
    $processedUsers = @{}
    
    foreach ($group in $privilegedGroups) {
        try {
            Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue |
            Where-Object { $_.objectClass -eq 'user' } |
            ForEach-Object {
                if (-not $processedUsers.ContainsKey($_.SamAccountName)) {
                    $processedUsers[$_.SamAccountName] = $true
                    
                    if ($_.SamAccountName -notin $protectedUsers) {
                        $user = Get-ADUser -Identity $_.SamAccountName -Properties Enabled
                        
                        $results += [PSCustomObject]@{
                            Name             = $user.Name
                            SamAccountName   = $user.SamAccountName
                            Enabled          = $user.Enabled
                            PrivilegedGroup  = $group
                            InProtectedUsers = $false
                        }
                    }
                }
            }
        }
        catch {
            Write-Warning "Could not process group: $group"
        }
    }
    
    return $results
}

# 6. Dangerous SPN Delegation
function Get-DangerousSPNDelegation {
    [CmdletBinding()]
    param()

    $dangerousSPNPatterns = @{
        "ldap"   = "CRITICAL"
        "cifs"   = "HIGH"
        "host"   = "HIGH"
        "http"   = "MEDIUM"
        "https"  = "MEDIUM"
        "mssql"  = "HIGH"
        "wsman"  = "HIGH"
        "rpcss"  = "HIGH"
        "krbtgt" = "CRITICAL"
        "gc"     = "HIGH"
    }

    $results = @()

    # Users
    Get-ADUser -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties `
        msDS-AllowedToDelegateTo,
    Name,
    SamAccountName,
    Enabled |
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

    # Computers
    Get-ADComputer -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties `
        msDS-AllowedToDelegateTo,
    Name,
    SamAccountName,
    Enabled |
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

    # gMSAs
    try {
        Get-ADServiceAccount -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties `
            msDS-AllowedToDelegateTo,
        Name,
        SamAccountName,
        Enabled |
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
        Write-Verbose "No gMSAs found with dangerous SPN delegation or unable to query: $_"
    }

    return $results
}

# 7. Delegation to Domain Controllers
function Get-DelegationToDomainControllers {
    [CmdletBinding()]
    param()

    $domainControllers = Get-DomainControllerNames
    $results = @()

    # Users
    Get-ADUser -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties `
        msDS-AllowedToDelegateTo,
    Name,
    SamAccountName,
    Enabled |
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

    # Computers
    Get-ADComputer -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties `
        msDS-AllowedToDelegateTo,
    Name,
    SamAccountName,
    Enabled |
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

    # gMSAs
    try {
        Get-ADServiceAccount -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties `
            msDS-AllowedToDelegateTo,
        Name,
        SamAccountName,
        Enabled |
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
        Write-Verbose "No gMSAs found with delegation to DCs or unable to query: $_"
    }

    return $results
}

# 8. Pre-Windows 2000 Compatible Access Check
function Get-PreWindows2000CompatibleAccess {
    [CmdletBinding()]
    param()
    
    $results = @()
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
        Write-Warning "Could not retrieve Pre-Windows 2000 Compatible Access group: $_"
    }
    
    return $results
}

# 9. Service Accounts with Delegation (gMSA and regular)
function Get-ServiceAccountDelegation {
    [CmdletBinding()]
    param()
    
    $results = @()
    
    # Check gMSAs
    try {
        Get-ADServiceAccount -Filter * -Properties `
            TrustedForDelegation,
        TrustedToAuthForDelegation,
        msDS-AllowedToDelegateTo,
        msDS-AllowedToActOnBehalfOfOtherIdentity,
        ServicePrincipalName |
        ForEach-Object {
            $issues = @()
            
            if ($_.TrustedForDelegation) { $issues += "Unconstrained Delegation" }
            if ($_.TrustedToAuthForDelegation) { $issues += "Protocol Transition" }
            if ($_.'msDS-AllowedToDelegateTo') { $issues += "Constrained Delegation" }
            if ($_.'msDS-AllowedToActOnBehalfOfOtherIdentity') { $issues += "RBCD Target" }
            
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
        Write-Verbose "No gMSAs found or unable to query: $_"
    }
    
    return $results
}

#endregion

#region Main Audit Function

function Invoke-DelegationAudit {
    [CmdletBinding()]
    param()

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
    $rbcdTargetUsers = $allRBCD | Where-Object { $_.TargetObjectClass -eq "user" }                                                                                        # CRITICAL (zeer ongebruikelijk)
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

    Write-Verbose "Delegation Audit completed."
    return $results
}

#endregion



# Run audit when script is executed directly
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-DelegationAudit
}
