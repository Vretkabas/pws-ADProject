# Setup-VulnerableAD.ps1
# Creates vulnerable AD environment for testing scanner
# Run this ON DC01 as Domain Admin

<#
.SYNOPSIS
Creates a vulnerable AD test environment with:
- Multiple OUs with users
- Bad FGPPs (weak settings)
- Good FGPPs (strong settings)
- Privileged accounts with issues
- Multiple GPOs with conflicting password policies

.NOTES
Run on DC01 as CORP\Administrator
This intentionally creates VULNERABLE configurations for testing!
#>

param(
    [string]$Domain = "corp.testlab.local",
    [string]$DomainDN = "DC=corp,DC=testlab,DC=local"
)

Write-Host @"
╔═══════════════════════════════════════════════════════╗
║  Creating Vulnerable AD Test Environment             ║
║  ⚠️  FOR TESTING ONLY - INTENTIONALLY INSECURE! ⚠️   ║
╚═══════════════════════════════════════════════════════╝
"@ -ForegroundColor Red

Import-Module ActiveDirectory

# ═══════════════════════════════════════════════════════
# PART 1: CREATE ORGANIZATIONAL UNITS
# ═══════════════════════════════════════════════════════

Write-Host "`n[1/7] Creating Organizational Units..." -ForegroundColor Cyan

$ous = @(
    @{Name="TestUsers"; Description="Test users for scanner"},
    @{Name="Admins"; Description="Administrative accounts"},
    @{Name="ServiceAccounts"; Description="Service accounts"},
    @{Name="Finance"; Description="Finance department"},
    @{Name="IT"; Description="IT department"},
    @{Name="HR"; Description="HR department"}
)

foreach ($ou in $ous) {
    try {
        $ouPath = "OU=$($ou.Name),$DomainDN"
        if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouPath'" -ErrorAction SilentlyContinue)) {
            New-ADOrganizationalUnit -Name $ou.Name -Path $DomainDN -Description $ou.Description -ProtectedFromAccidentalDeletion $false
            Write-Host "  ✓ Created OU: $($ou.Name)" -ForegroundColor Green
        } else {
            Write-Host "  - OU already exists: $($ou.Name)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Warning "Could not create OU: $($ou.Name) - $_"
    }
}

# ═══════════════════════════════════════════════════════
# PART 2: CREATE TEST USERS
# ═══════════════════════════════════════════════════════

Write-Host "`n[2/7] Creating Test Users..." -ForegroundColor Cyan

$testUsers = @(
    # Regular users
    @{Name="John Doe"; SamAccountName="john.doe"; OU="TestUsers"; Password="Password123!"; Description="Regular user"},
    @{Name="Jane Smith"; SamAccountName="jane.smith"; OU="TestUsers"; Password="Summer2024!"; Description="Regular user"},
    @{Name="Bob Johnson"; SamAccountName="bob.johnson"; OU="TestUsers"; Password="Winter2024!"; Description="Regular user"},
    
    # Finance users
    @{Name="Alice Finance"; SamAccountName="alice.finance"; OU="Finance"; Password="Finance123!"; Description="Finance department"},
    @{Name="Charlie Finance"; SamAccountName="charlie.finance"; OU="Finance"; Password="Money2024!"; Description="Finance department"},
    
    # IT users
    @{Name="Dave ITGuy"; SamAccountName="dave.it"; OU="IT"; Password="Support123!"; Description="IT support"},
    @{Name="Eve ITGal"; SamAccountName="eve.it"; OU="IT"; Password="Helpdesk1!"; Description="IT support"},
    
    # BAD ADMINS (vulnerable configurations)
    @{Name="Old Admin"; SamAccountName="admin.old"; OU="Admins"; Password="Admin123!"; Description="Inactive admin - VULNERABLE"; PasswordNeverExpires=$true},
    @{Name="Weak Admin"; SamAccountName="admin.weak"; OU="Admins"; Password="Pass1!"; Description="Weak password admin - VULNERABLE"},
    @{Name="Test Admin"; SamAccountName="admin.test"; OU="Admins"; Password="Testing123!"; Description="Test admin account"},
    
    # Service Accounts
    @{Name="SQL Service"; SamAccountName="svc_sql"; OU="ServiceAccounts"; Password="SuperSecretSQLPass123!"; Description="SQL Server service account"},
    @{Name="Web Service"; SamAccountName="svc_web"; OU="ServiceAccounts"; Password="WebServicePassword2024!"; Description="IIS service account"},
    @{Name="Backup Service"; SamAccountName="svc_backup"; OU="ServiceAccounts"; Password="BackupService123!"; Description="Backup service account"}
)

foreach ($user in $testUsers) {
    try {
        $ouPath = "OU=$($user.OU),$DomainDN"
        $userPath = "CN=$($user.Name),$ouPath"
        
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$($user.SamAccountName)'" -ErrorAction SilentlyContinue)) {
            $securePassword = ConvertTo-SecureString $user.Password -AsPlainText -Force
            
            $params = @{
                Name = $user.Name
                SamAccountName = $user.SamAccountName
                UserPrincipalName = "$($user.SamAccountName)@$Domain"
                Path = $ouPath
                AccountPassword = $securePassword
                Enabled = $true
                Description = $user.Description
                ChangePasswordAtLogon = $false
            }
            
            if ($user.PasswordNeverExpires) {
                $params.PasswordNeverExpires = $true
            }
            
            New-ADUser @params
            Write-Host "  ✓ Created user: $($user.SamAccountName)" -ForegroundColor Green
        } else {
            Write-Host "  - User already exists: $($user.SamAccountName)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Warning "Could not create user: $($user.SamAccountName) - $_"
    }
}

# ═══════════════════════════════════════════════════════
# PART 3: ADD USERS TO GROUPS
# ═══════════════════════════════════════════════════════

Write-Host "`n[3/7] Adding users to groups..." -ForegroundColor Cyan

# Add admins to Domain Admins (VULNERABLE!)
$adminUsers = @("admin.old", "admin.weak", "admin.test")
foreach ($admin in $adminUsers) {
    try {
        Add-ADGroupMember -Identity "Domain Admins" -Members $admin -ErrorAction Stop
        Write-Host "  ✓ Added $admin to Domain Admins" -ForegroundColor Green
    }
    catch {
        Write-Host "  - $admin already in Domain Admins or error" -ForegroundColor Gray
    }
}

# Create custom groups
$customGroups = @(
    @{Name="Finance-Users"; Description="Finance department users"; Members=@("alice.finance", "charlie.finance")},
    @{Name="IT-Support"; Description="IT support team"; Members=@("dave.it", "eve.it")},
    @{Name="Service-Accounts"; Description="Service accounts group"; Members=@("svc_sql", "svc_web", "svc_backup")}
)

foreach ($group in $customGroups) {
    try {
        if (-not (Get-ADGroup -Filter "Name -eq '$($group.Name)'" -ErrorAction SilentlyContinue)) {
            New-ADGroup -Name $group.Name -GroupScope Global -Path "OU=TestUsers,$DomainDN" -Description $group.Description
            Write-Host "  ✓ Created group: $($group.Name)" -ForegroundColor Green
        }
        
        foreach ($member in $group.Members) {
            try {
                Add-ADGroupMember -Identity $group.Name -Members $member -ErrorAction SilentlyContinue
                Write-Host "    ✓ Added $member to $($group.Name)" -ForegroundColor Green
            } catch {}
        }
    }
    catch {
        Write-Warning "Could not create group: $($group.Name)"
    }
}

# ═══════════════════════════════════════════════════════
# PART 4: CREATE VULNERABLE FGPPs (BAD POLICIES)
# ═══════════════════════════════════════════════════════

Write-Host "`n[4/7] Creating VULNERABLE Fine-Grained Password Policies..." -ForegroundColor Cyan

$badFGPPs = @(
    @{
        Name = "Weak-Finance-Policy"
        Precedence = 50
        MinPasswordLength = 6  # TOO SHORT!
        MaxPasswordAge = (New-TimeSpan -Days 30)  # TOO FREQUENT!
        ComplexityEnabled = $false  # NO COMPLEXITY!
        LockoutThreshold = 0  # NO LOCKOUT!
        Description = "VULNERABLE: Weak policy for testing"
        ApplyTo = "Finance-Users"
    },
    @{
        Name = "Bad-Service-Account-Policy"
        Precedence = 60
        MinPasswordLength = 8
        MaxPasswordAge = (New-TimeSpan -Days 365)
        ComplexityEnabled = $true
        ReversibleEncryptionEnabled = $true  # CRITICAL VULNERABILITY!
        LockoutThreshold = 3
        LockoutDuration = (New-TimeSpan -Minutes 15)
        LockoutObservationWindow = (New-TimeSpan -Minutes 15)
        Description = "VULNERABLE: Has reversible encryption!"
        ApplyTo = "Service-Accounts"
    }
)

foreach ($fgpp in $badFGPPs) {
    try {
        if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$($fgpp.Name)'" -ErrorAction SilentlyContinue)) {
            $params = @{
                Name = $fgpp.Name
                Precedence = $fgpp.Precedence
                MinPasswordLength = $fgpp.MinPasswordLength
                MaxPasswordAge = $fgpp.MaxPasswordAge
                MinPasswordAge = (New-TimeSpan -Days 1)
                PasswordHistoryCount = 5
                ComplexityEnabled = $fgpp.ComplexityEnabled
                LockoutThreshold = $fgpp.LockoutThreshold
                ReversibleEncryptionEnabled = if($fgpp.ReversibleEncryptionEnabled) { $true } else { $false }
                Description = $fgpp.Description
            }
            
            if ($fgpp.LockoutDuration) {
                $params.LockoutDuration = $fgpp.LockoutDuration
                $params.LockoutObservationWindow = $fgpp.LockoutObservationWindow
            }
            
            New-ADFineGrainedPasswordPolicy @params
            Write-Host "  ✓ Created BAD FGPP: $($fgpp.Name)" -ForegroundColor Yellow
            
            # Apply to group
            Add-ADFineGrainedPasswordPolicySubject -Identity $fgpp.Name -Subjects $fgpp.ApplyTo
            Write-Host "    → Applied to: $($fgpp.ApplyTo)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Warning "Could not create FGPP: $($fgpp.Name) - $_"
    }
}

# ═══════════════════════════════════════════════════════
# PART 5: CREATE GOOD FGPPs (BEST PRACTICE)
# ═══════════════════════════════════════════════════════

Write-Host "`n[5/7] Creating GOOD Fine-Grained Password Policies..." -ForegroundColor Cyan

$goodFGPPs = @(
    @{
        Name = "Strong-IT-Policy"
        Precedence = 20
        MinPasswordLength = 14
        MaxPasswordAge = (New-TimeSpan -Days 180)
        ComplexityEnabled = $true
        LockoutThreshold = 5
        LockoutDuration = (New-TimeSpan -Minutes 30)
        LockoutObservationWindow = (New-TimeSpan -Minutes 30)
        Description = "GOOD: Strong policy for IT staff"
        ApplyTo = "IT-Support"
    }
)

foreach ($fgpp in $goodFGPPs) {
    try {
        if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$($fgpp.Name)'" -ErrorAction SilentlyContinue)) {
            New-ADFineGrainedPasswordPolicy `
                -Name $fgpp.Name `
                -Precedence $fgpp.Precedence `
                -MinPasswordLength $fgpp.MinPasswordLength `
                -MaxPasswordAge $fgpp.MaxPasswordAge `
                -MinPasswordAge (New-TimeSpan -Days 1) `
                -PasswordHistoryCount 24 `
                -ComplexityEnabled $fgpp.ComplexityEnabled `
                -LockoutThreshold $fgpp.LockoutThreshold `
                -LockoutDuration $fgpp.LockoutDuration `
                -LockoutObservationWindow $fgpp.LockoutObservationWindow `
                -ReversibleEncryptionEnabled $false `
                -Description $fgpp.Description
            
            Write-Host "  ✓ Created GOOD FGPP: $($fgpp.Name)" -ForegroundColor Green
            
            Add-ADFineGrainedPasswordPolicySubject -Identity $fgpp.Name -Subjects $fgpp.ApplyTo
            Write-Host "    → Applied to: $($fgpp.ApplyTo)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Warning "Could not create FGPP: $($fgpp.Name) - $_"
    }
}

# ═══════════════════════════════════════════════════════
# PART 6: MODIFY DEFAULT DOMAIN PASSWORD POLICY (WEAK!)
# ═══════════════════════════════════════════════════════

Write-Host "`n[6/7] Setting WEAK Default Domain Password Policy..." -ForegroundColor Cyan

try {
    Set-ADDefaultDomainPasswordPolicy `
        -Identity $Domain `
        -MinPasswordLength 8 `
        -MaxPasswordAge (New-TimeSpan -Days 90) `
        -MinPasswordAge (New-TimeSpan -Days 1) `
        -PasswordHistoryCount 6 `
        -ComplexityEnabled $true `
        -LockoutThreshold 5 `
        -LockoutDuration (New-TimeSpan -Minutes 30) `
        -LockoutObservationWindow (New-TimeSpan -Minutes 30) `
        -ReversibleEncryptionEnabled $false
    
    Write-Host "  ✓ Default Domain Policy set to WEAK settings (8 chars minimum)" -ForegroundColor Yellow
}
catch {
    Write-Warning "Could not modify default domain password policy: $_"
}

# ═══════════════════════════════════════════════════════
# PART 7: CREATE ADDITIONAL GPOs WITH PASSWORD SETTINGS
# ═══════════════════════════════════════════════════════

Write-Host "`n[7/7] Creating additional GPOs with password policies (CONFLICT!)..." -ForegroundColor Cyan

# Note: Creating GPOs with password settings via PowerShell is complex
# We'll create the GPO and document that it should have password settings

$additionalGPOs = @(
    @{Name="Security-Baseline-GPO"; Comment="Should contain password policy - creates confusion with Default Domain Policy"},
    @{Name="Compliance-GPO"; Comment="Another GPO with password settings - only one will win!"}
)

foreach ($gpoData in $additionalGPOs) {
    try {
        if (-not (Get-GPO -Name $gpoData.Name -ErrorAction SilentlyContinue)) {
            $gpo = New-GPO -Name $gpoData.Name -Comment $gpoData.Comment
            Write-Host "  ✓ Created GPO: $($gpoData.Name)" -ForegroundColor Yellow
            Write-Host "    ⚠️  Manually configure password settings in this GPO via GPMC" -ForegroundColor Gray
        }
    }
    catch {
        Write-Warning "Could not create GPO: $($gpoData.Name)"
    }
}

# ═══════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════

Write-Host "`n" -NoNewline
Write-Host @"
╔═══════════════════════════════════════════════════════╗
║  Vulnerable AD Environment Created!                   ║
╚═══════════════════════════════════════════════════════╝
"@ -ForegroundColor Green

Write-Host "`n📊 SUMMARY:" -ForegroundColor Cyan
Write-Host ""

# Count objects
$ouCount = (Get-ADOrganizationalUnit -Filter * -SearchBase $DomainDN).Count
$userCount = (Get-ADUser -Filter * -SearchBase $DomainDN | Where-Object {$_.DistinguishedName -notlike "*CN=Users,*"}).Count
$fgppCount = (Get-ADFineGrainedPasswordPolicy -Filter *).Count
$domainAdminsCount = (Get-ADGroupMember -Identity "Domain Admins").Count

Write-Host "  OUs Created: $ouCount" -ForegroundColor White
Write-Host "  Test Users: $userCount" -ForegroundColor White
Write-Host "  FGPPs: $fgppCount (Mix of good and bad)" -ForegroundColor White
Write-Host "  Domain Admins: $domainAdminsCount (some VULNERABLE!)" -ForegroundColor White

Write-Host "`n🔴 VULNERABILITIES INTRODUCED:" -ForegroundColor Red
Write-Host "  ✗ Domain Admins group has NO dedicated FGPP (uses weak domain default)" -ForegroundColor Yellow
Write-Host "  ✗ Enterprise Admins has NO FGPP" -ForegroundColor Yellow
Write-Host "  ✗ admin.old has PasswordNeverExpires enabled" -ForegroundColor Yellow
Write-Host "  ✗ Finance-Users FGPP: Only 6 chars, no complexity, no lockout!" -ForegroundColor Yellow
Write-Host "  ✗ Service-Accounts FGPP: Reversible encryption ENABLED!" -ForegroundColor Yellow
Write-Host "  ✗ Default Domain Policy: Only 8 char minimum" -ForegroundColor Yellow
Write-Host "  ✗ Multiple GPOs may have conflicting password policies" -ForegroundColor Yellow

Write-Host "`n✅ GOOD CONFIGURATIONS:" -ForegroundColor Green
Write-Host "  ✓ IT-Support has strong FGPP (14 chars, proper settings)" -ForegroundColor Green

Write-Host "`n🎯 TEST YOUR SCANNER:" -ForegroundColor Cyan
Write-Host @"
Your scanner should detect:
1. Domain Admins without FGPP (HIGH severity)
2. Weak Default Domain Policy (MEDIUM severity)
3. FGPP with reversible encryption (CRITICAL severity)
4. FGPP with no complexity/lockout (HIGH severity)
5. admin.old with PasswordNeverExpires (HIGH severity)
6. Multiple GPOs with password policies (MEDIUM severity)
"@

Write-Host "`n📝 VERIFICATION COMMANDS:" -ForegroundColor Cyan
Write-Host @"
# Check default policy
Get-ADDefaultDomainPasswordPolicy

# Check all FGPPs
Get-ADFineGrainedPasswordPolicy -Filter * | Format-Table Name, Precedence, MinPasswordLength, ComplexityEnabled

# Check Domain Admins FGPP
Get-ADGroup "Domain Admins" | Get-ADFineGrainedPasswordPolicy

# Check specific user's policy
Get-ADUserResultantPasswordPolicy -Identity "Administrator"
Get-ADUserResultantPasswordPolicy -Identity "alice.finance"
Get-ADUserResultantPasswordPolicy -Identity "dave.it"

# Check vulnerable user
Get-ADUser admin.old -Properties PasswordNeverExpires
"@

Write-Host "`n✅ Setup complete! Ready for scanning!" -ForegroundColor Green