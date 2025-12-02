#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Creates test accounts with bad configurations for Module 1 testing

.DESCRIPTION
    This script creates multiple AD accounts with various security issues:
    - Password never expires enabled
    - Inactive administrative accounts
    - Privileged accounts with weak configurations
    - Old passwords that should be changed
    - Disabled accounts in administrative groups

.NOTES
    Author: Lab Setup Script
    Purpose: Testing Privileged Account Management Scanner (Module 1)
    WARNING: Only use in test environments!
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$DomainDN = (Get-ADDomain).DistinguishedName,

    [Parameter()]
    [string]$OUPath = "OU=TestAccounts,$DomainDN",

    [Parameter()]
    [switch]$CleanupFirst
)

# Error handling
$ErrorActionPreference = "Stop"

# Function to create OU if it doesn't exist
function Ensure-TestOU {
    param([string]$Path)

    try {
        Get-ADOrganizationalUnit -Identity $Path -ErrorAction Stop | Out-Null
        Write-Host "OU already exists: $Path" -ForegroundColor Yellow
    }
    catch {
        $ouName = ($Path -split ',')[0] -replace 'OU=', ''
        $parentPath = ($Path -split ',', 2)[1]
        New-ADOrganizationalUnit -Name $ouName -Path $parentPath
        Write-Host "Created OU: $Path" -ForegroundColor Green
    }
}

# Function to create a test user
function New-TestUser {
    param(
        [string]$Username,
        [string]$DisplayName,
        [string]$Description,
        [string]$Path,
        [bool]$PasswordNeverExpires = $false,
        [bool]$Enabled = $true,
        [string[]]$Groups = @()
    )

    $password = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force

    try {
        # Check if user already exists
        $existingUser = Get-ADUser -Filter "SamAccountName -eq '$Username'" -ErrorAction SilentlyContinue
        if ($existingUser) {
            Write-Host "User already exists: $Username - Removing..." -ForegroundColor Yellow
            Remove-ADUser -Identity $Username -Confirm:$false
        }

        # Create user
        $userParams = @{
            SamAccountName = $Username
            Name = $DisplayName
            DisplayName = $DisplayName
            Description = $Description
            Path = $Path
            AccountPassword = $password
            Enabled = $Enabled
            PasswordNeverExpires = $PasswordNeverExpires
            ChangePasswordAtLogon = $false
        }

        New-ADUser @userParams
        Write-Host "Created user: $Username" -ForegroundColor Green

        # Add to groups
        foreach ($group in $Groups) {
            try {
                Add-ADGroupMember -Identity $group -Members $Username
                Write-Host "  Added to group: $group" -ForegroundColor Cyan
            }
            catch {
                Write-Host "  Failed to add to group ${group}: $_" -ForegroundColor Red
            }
        }

        return Get-ADUser -Identity $Username
    }
    catch {
        Write-Host "Failed to create user ${Username}: $_" -ForegroundColor Red
        return $null
    }
}

# Function to set last logon date
# NOTE: Requires Domain Admin or special permissions to modify replication metadata
function Set-LastLogonDate {
    param(
        [string]$Username,
        [int]$DaysAgo
    )

    try {
        $user = Get-ADUser -Identity $Username
        $date = (Get-Date).AddDays(-$DaysAgo)

        # Set lastLogonTimestamp (replicated attribute)
        # This requires special permissions and may fail without Domain Admin rights
        $lastLogonTimestamp = $date.ToFileTime()
        Set-ADUser -Identity $Username -Replace @{lastLogonTimestamp = $lastLogonTimestamp} -ErrorAction Stop

        Write-Host "  Set last logon to $DaysAgo days ago" -ForegroundColor Gray
    }
    catch [System.UnauthorizedAccessException] {
        Write-Host "  Warning: Insufficient permissions to set last logon timestamp (requires elevated rights)" -ForegroundColor Yellow
    }
    catch {
        Write-Host "  Warning: Could not set last logon: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Function to set password last set date
# NOTE: pwdLastSet is a protected attribute - alternative method using description field
function Set-PasswordLastSet {
    param(
        [string]$Username,
        [int]$DaysAgo
    )

    try {
        # Method 1: Try direct manipulation (requires special permissions)
        $date = (Get-Date).AddDays(-$DaysAgo)
        $pwdLastSetTimestamp = $date.ToFileTime()
        Set-ADUser -Identity $Username -Replace @{pwdLastSet = $pwdLastSetTimestamp} -ErrorAction Stop

        Write-Host "  Set password age to $DaysAgo days ago" -ForegroundColor Gray
    }
    catch [System.UnauthorizedAccessException] {
        # Method 2: Use description to mark it instead
        Write-Host "  Warning: Cannot directly set pwdLastSet (SAM protected)" -ForegroundColor Yellow
        Write-Host "  Adding note to description field instead..." -ForegroundColor Yellow

        try {
            $user = Get-ADUser -Identity $Username -Properties Description
            $currentDesc = $user.Description
            $newDesc = "$currentDesc [SIMULATED: Password $DaysAgo days old]"
            Set-ADUser -Identity $Username -Description $newDesc
            Write-Host "  Description updated to indicate old password" -ForegroundColor Gray
        }
        catch {
            Write-Host "  Could not update description: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  Warning: Could not set password age: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Main script
Write-Host "`n=== Module 1 Test Account Creation ===" -ForegroundColor Cyan
Write-Host "Creating accounts with bad configurations for testing...`n" -ForegroundColor Cyan

# Cleanup if requested
if ($CleanupFirst) {
    Write-Host "Cleaning up existing test accounts..." -ForegroundColor Yellow
    try {
        Get-ADUser -Filter * -SearchBase $OUPath | Remove-ADUser -Confirm:$false
        Write-Host "Cleanup completed`n" -ForegroundColor Green
    }
    catch {
        Write-Host "Cleanup warning: $_`n" -ForegroundColor Yellow
    }
}

# Ensure OU exists
Ensure-TestOU -Path $OUPath

Write-Host "`n--- Creating Bad Practice Accounts ---`n" -ForegroundColor Yellow

# 1. Admin account with Password Never Expires
New-TestUser -Username "admin_neverexpire" `
    -DisplayName "Admin Never Expire" `
    -Description "Admin account with password never expires - BAD PRACTICE" `
    -Path $OUPath `
    -PasswordNeverExpires $true `
    -Groups @("Domain Admins")

# 2. Inactive Domain Admin account
$user = New-TestUser -Username "admin_inactive" `
    -DisplayName "Inactive Admin" `
    -Description "Inactive domain admin account - BAD PRACTICE" `
    -Path $OUPath `
    -Groups @("Domain Admins")

if ($user) {
    Set-LastLogonDate -Username "admin_inactive" -DaysAgo 180
}

# 3. Service account in Domain Admins with password never expires
New-TestUser -Username "svc_oldadmin" `
    -DisplayName "Old Service Admin" `
    -Description "Service account in Domain Admins - BAD PRACTICE" `
    -Path $OUPath `
    -PasswordNeverExpires $true `
    -Groups @("Domain Admins")

# 4. Account Operators member with old password
$user = New-TestUser -Username "accountop_oldpwd" `
    -DisplayName "Account Operator Old Password" `
    -Description "Account Operators member with old password - BAD PRACTICE" `
    -Path $OUPath `
    -Groups @("Account Operators")

if ($user) {
    Set-PasswordLastSet -Username "accountop_oldpwd" -DaysAgo 400
}

# 5. Backup Operators member with password never expires
New-TestUser -Username "backup_neverexpire" `
    -DisplayName "Backup Never Expire" `
    -Description "Backup Operators with password never expires - BAD PRACTICE" `
    -Path $OUPath `
    -PasswordNeverExpires $true `
    -Groups @("Backup Operators")

# 6. Disabled account in Domain Admins
New-TestUser -Username "admin_disabled" `
    -DisplayName "Disabled Admin" `
    -Description "Disabled account in Domain Admins - BAD PRACTICE" `
    -Path $OUPath `
    -Enabled $false `
    -Groups @("Domain Admins")

# 7. Enterprise Admin with password never expires
New-TestUser -Username "entadmin_neverexpire" `
    -DisplayName "Enterprise Admin Never Expire" `
    -Description "Enterprise Admin with password never expires - BAD PRACTICE" `
    -Path $OUPath `
    -PasswordNeverExpires $true `
    -Groups @("Enterprise Admins")

# 8. Schema Admin that's inactive
$user = New-TestUser -Username "schemaadmin_inactive" `
    -DisplayName "Schema Admin Inactive" `
    -Description "Inactive Schema Admin - BAD PRACTICE" `
    -Path $OUPath `
    -Groups @("Schema Admins")

if ($user) {
    Set-LastLogonDate -Username "schemaadmin_inactive" -DaysAgo 365
}

# 9. Server Operators with old password and never expires
$user = New-TestUser -Username "srvop_combo" `
    -DisplayName "Server Operator Combined Issues" `
    -Description "Server Operator with multiple issues - BAD PRACTICE" `
    -Path $OUPath `
    -PasswordNeverExpires $true `
    -Groups @("Server Operators")

if ($user) {
    Set-PasswordLastSet -Username "srvop_combo" -DaysAgo 500
    Set-LastLogonDate -Username "srvop_combo" -DaysAgo 200
}

# 10. Print Operators inactive
$user = New-TestUser -Username "printop_inactive" `
    -DisplayName "Print Operator Inactive" `
    -Description "Inactive Print Operator - BAD PRACTICE" `
    -Path $OUPath `
    -Groups @("Print Operators")

if ($user) {
    Set-LastLogonDate -Username "printop_inactive" -DaysAgo 150
}

# 11. Regular admin with very old password
$user = New-TestUser -Username "admin_oldpassword" `
    -DisplayName "Admin Old Password" `
    -Description "Admin with very old password - BAD PRACTICE" `
    -Path $OUPath `
    -Groups @("Domain Admins")

if ($user) {
    Set-PasswordLastSet -Username "admin_oldpassword" -DaysAgo 730
}

# 12. Multiple privileged groups membership
New-TestUser -Username "admin_multigroup" `
    -DisplayName "Admin Multiple Groups" `
    -Description "Account in multiple privileged groups - BAD PRACTICE" `
    -Path $OUPath `
    -PasswordNeverExpires $true `
    -Groups @("Domain Admins", "Account Operators", "Server Operators")

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Test accounts created successfully!" -ForegroundColor Green
Write-Host "`nBad practices included:" -ForegroundColor Yellow
Write-Host "  - Password Never Expires on privileged accounts" -ForegroundColor Gray
Write-Host "  - Inactive administrative accounts (90+ days)" -ForegroundColor Gray
Write-Host "  - Old passwords on privileged accounts (365+ days)" -ForegroundColor Gray
Write-Host "  - Disabled accounts in administrative groups" -ForegroundColor Gray
Write-Host "  - Service accounts with excessive privileges" -ForegroundColor Gray
Write-Host "  - Accounts with multiple privileged group memberships" -ForegroundColor Gray

Write-Host "`nOU Location: $OUPath" -ForegroundColor Cyan
Write-Host "`nYou can now run Module 1 scanner to detect these issues!" -ForegroundColor Green
Write-Host "`nTo cleanup: .\module1_accounts.ps1 -CleanupFirst`n" -ForegroundColor Yellow

Write-Host "Note: Timestamp manipulation requires Domain Admin rights or special permissions." -ForegroundColor Cyan
Write-Host "If you see warnings about 'SAM protected' or 'Insufficient permissions'," -ForegroundColor Cyan
Write-Host "run this script with elevated Domain Admin privileges.`n" -ForegroundColor Cyan
