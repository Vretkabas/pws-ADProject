# Remediation Menu - Interactive menu for fixing SPN account issues
# This displays a dynamic menu that updates after each fix

param(
    [hashtable]$Module2Results,
    [Parameter(Mandatory=$false)]
    [ref]$IssuesFixedRef
)

. "$PSScriptRoot\remediation.ps1"
. "$PSScriptRoot\remediationFix.ps1"

Write-Host "`n=== Remediation Options ===" -ForegroundColor Cyan
Write-Host "The following SPN account issues can be automatically fixed:`n" -ForegroundColor Yellow

# Build menu van remediation functies
$fixableIssues = @{
    "1" = @{
        Name = "Weak Encryption (Upgrade to AES)"
        Accounts = Get-WeakEncryptionAccounts
        FixFunction = "Set-EncryptionToAESFix"
    }
    "2" = @{
        Name = "Password Never Expires"
        Accounts = Get-PasswordNeverExpiresAccounts
        FixFunction = "Set-PasswordNeverExpiresFix"
    }
    "3" = @{
        Name = "Password Not Required"
        Accounts = Get-PasswordNotRequiredAccounts
        FixFunction = "Set-PasswordNotRequiredFix"
    }
    "4" = @{
        Name = "Cannot Change Password"
        Accounts = Get-CannotChangePasswordAccounts
        FixFunction = "Set-CannotChangePasswordFix"
    }
    "5" = @{
        Name = "Use DES Key Only"
        Accounts = Get-UseDESKeyOnlyAccounts
        FixFunction = "Set-UseDESKeyOnlyFix"
    }
    "6" = @{
        Name = "Reversible Password Encryption"
        Accounts = Get-ReversiblePasswordEncryptionAccounts
        FixFunction = "Set-ReversiblePasswordEncryptionFix"
    }
    "7" = @{
        Name = "Does Not Require PreAuth (AS-REP Roasting)"
        Accounts = Get-DoesNotRequirePreAuthAccounts
        FixFunction = "Set-RequirePreAuthFix"
    }
    "8" = @{
        Name = "Trusted For Delegation (Unconstrained)"
        Accounts = Get-TrustedForDelegationAccounts
        FixFunction = "Set-TrustedForDelegationFix"
    }
    "9" = @{
        Name = "Trusted To Auth For Delegation"
        Accounts = Get-TrustedToAuthForDelegationAccounts
        FixFunction = "Set-TrustedToAuthForDelegationFix"
    }
    "10" = @{
        Name = "Disabled SPN Accounts (DISABLE)"
        Accounts = Get-DisabledSPNAccounts
        FixFunction = "Disable-SPNAccountsFix"
    }
}

# Build availableOptions (alleen issues met accounts)
$availableOptions = @{}
$menuIndex = 1

foreach ($key in ($fixableIssues.Keys | Sort-Object)) {
    $issue = $fixableIssues[$key]
    $count = if ($issue.Accounts -and $issue.Accounts.Accounts) { ($issue.Accounts.Accounts | Measure-Object).Count } else { 0 }

    if ($count -gt 0) {
        $availableOptions[$menuIndex.ToString()] = @{
            Name = $issue.Name
            Accounts = $issue.Accounts.Accounts
            FixFunction = $issue.FixFunction
        }
        $menuIndex++
    }
}

if ($availableOptions.Count -eq 0) {
    Write-Host "No fixable issues found!" -ForegroundColor Green
    Write-Host "Skipping remediation...`n" -ForegroundColor Cyan
    return $false  # No issues fixed
}

# ============================================
# Remediation Loop
# ============================================
$issuesFixed = $false
$fixedIssues = @{}  # Track which issues have been fixed

while ($true) {
    # Re-display menu showing current status
    Write-Host "`n=== Available Remediation Options ===" -ForegroundColor Cyan

    $hasUnfixedIssues = $false
    foreach ($key in ($availableOptions.Keys | Sort-Object)) {
        $issue = $availableOptions[$key]

        if ($fixedIssues.ContainsKey($key)) {
            # Issue was fixed - show as completed
            Write-Host "$key. $($issue.Name): ✓ FIXED" -ForegroundColor Green
        } else {
            # Issue not yet fixed - show count
            $count = if ($issue.Accounts) { ($issue.Accounts | Measure-Object).Count } else { 0 }
            Write-Host "$key. $($issue.Name): $count account(s)" -ForegroundColor Yellow
            $hasUnfixedIssues = $true
        }
    }

    Write-Host "0. Exit remediation" -ForegroundColor Cyan

    # If all issues are fixed, auto-exit
    if (-not $hasUnfixedIssues) {
        Write-Host "`n✓ All fixable issues have been resolved!" -ForegroundColor Green
        break
    }

    $selection = Read-Host "`nSelect option (0 to exit)"

    if ($selection -eq "0") {
        Write-Host "Exiting remediation.`n" -ForegroundColor Cyan
        break
    }

    # Check if already fixed
    if ($fixedIssues.ContainsKey($selection)) {
        Write-Host "This issue has already been fixed! Please select another option.`n" -ForegroundColor Yellow
        continue
    }

    if ($availableOptions.ContainsKey($selection)) {
        $selectedIssue = $availableOptions[$selection]

        Write-Host "`n--- $($selectedIssue.Name) ---" -ForegroundColor Yellow

        # Check if accounts exist
        $accountCount = if ($selectedIssue.Accounts) { ($selectedIssue.Accounts | Measure-Object).Count } else { 0 }
        Write-Host "Found $accountCount account(s) to fix`n" -ForegroundColor Cyan

        if ($accountCount -gt 0) {
            # Show accounts in Out-GridView for better visibility
            Write-Host "Opening account list in grid view..." -ForegroundColor Yellow
            $selectedIssue.Accounts | Out-GridView -Title "Accounts to fix: $($selectedIssue.Name)" -Wait
        } else {
            Write-Host "ERROR: No accounts found for this issue!" -ForegroundColor Red
            Write-Host "This should not happen - skipping this option.`n" -ForegroundColor Red
            continue
        }

        $confirm = Read-Host "`nProceed with fix? (Y/N)"

        if ($confirm -eq "Y" -or $confirm -eq "y") {
            # Voer fix uit
            & $selectedIssue.FixFunction -Accounts $selectedIssue.Accounts
            $issuesFixed = $true

            # Mark this issue as fixed
            $fixedIssues[$selection] = $true

            Write-Host "`n✓ Fix completed!" -ForegroundColor Green
            Write-Host "Returning to menu...`n" -ForegroundColor Cyan
            Start-Sleep -Seconds 1
        }
        else {
            Write-Host "Fix cancelled.`n" -ForegroundColor Red
        }
    }
    else {
        Write-Host "Invalid selection!`n" -ForegroundColor Red
    }
}

# Update the reference if provided
if ($IssuesFixedRef) {
    $IssuesFixedRef.Value = $issuesFixed
}

# Return whether any issues were fixed
return $issuesFixed
