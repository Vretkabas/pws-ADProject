# in this script we will check if the password settings objects are compliant with best practices

. "$PSScriptRoot\passwordSettings.ps1"

# function to decide if a password policy is compliant
function Get-PasswordPolicyCompliant {
    param (
        [PSCustomObject]$policy
    )

    $compliant = $true
    $issues = @()

    # Check if policy has users applied
    if ($policy.AppliedUserCount -eq 0) {
        $issues += "Policy is not applied to any users"
        $compliant = $false
    }

    # Check MinPasswordLength (minimum 12 characters)
    if ($policy.MinPasswordLength -lt 12) {
        $issues += "MinPasswordLength is $($policy.MinPasswordLength) (should be >= 12)"
        $compliant = $false
    }

    # Check ComplexityEnabled (must be enabled)
    if ($policy.ComplexityEnabled -ne $true) {
        $issues += "ComplexityEnabled is disabled (should be enabled)"
        $compliant = $false
    }

    # Check MaxPasswordAge (maximum 90 days)
    if ($policy.MaxPasswordAge -gt 90) {
        $issues += "MaxPasswordAge is $($policy.MaxPasswordAge) days (should be <= 90)"
        $compliant = $false
    }

    # Check PasswordHistoryCount (minimum 24 passwords remembered)
    if ($policy.PasswordHistoryCount -lt 24) {
        $issues += "PasswordHistoryCount is $($policy.PasswordHistoryCount) (should be >= 24)"
        $compliant = $false
    }

    # Check MinPasswordAge (minimum 1 day to prevent rapid password changes)
    if ($policy.MinPasswordAge -lt 1) {
        $issues += "MinPasswordAge is $($policy.MinPasswordAge) days (should be >= 1)"
        $compliant = $false
    }

    # Check ReversibleEncryptionEnabled (must be disabled for security)
    if ($policy.ReversibleEncryptionEnabled -eq $true) {
        $issues += "ReversibleEncryptionEnabled is enabled (should be disabled)"
        $compliant = $false
    }

    # Check LockoutThreshold (should be set to prevent brute force attacks)
    if ($policy.LockoutThreshold -eq 0) {
        $issues += "LockoutThreshold is disabled (should be 3-10 failed attempts)"
        $compliant = $false
    }
    elseif ($policy.LockoutThreshold -gt 10) {
        $issues += "LockoutThreshold is $($policy.LockoutThreshold) (should be <= 10)"
        $compliant = $false
    }

    # Check LockoutDuration (should be at least 15 minutes)
    if ($policy.LockoutThreshold -gt 0 -and $policy.LockoutDuration -lt 15) {
        $issues += "LockoutDuration is $($policy.LockoutDuration) minutes (should be >= 15)"
        $compliant = $false
    }

    # Check LockoutObservationWindow (should be at least 15 minutes)
    if ($policy.LockoutThreshold -gt 0 -and $policy.LockoutObservationWindow -lt 15) {
        $issues += "LockoutObservationWindow is $($policy.LockoutObservationWindow) minutes (should be >= 15)"
        $compliant = $false
    }

    return [PSCustomObject]@{
        Compliant = $compliant
        Issues = $issues
    }
}

# Main script execution
# Importeer de functies uit passwordSettings.ps1
. "$PSScriptRoot\passwordSettings.ps1"

# Haal alle password policies op
$policies = Get-AllPasswordPolicies

$results = @()

foreach ($policyName in $policies.Keys) {
    $policy = $policies[$policyName]

    # Add PolicyName back to the policy object for checking
    $policyWithName = $policy | Select-Object -Property *
    $policyWithName | Add-Member -MemberType NoteProperty -Name "PolicyName" -Value $policyName -Force

    $complianceCheck = Get-PasswordPolicyCompliant -policy $policyWithName

    $results += [PSCustomObject]@{
        PolicyName = $policyName
        PolicyType = $policy.PolicyType
        AppliedUserCount = $policy.AppliedUserCount
        Compliant = $complianceCheck.Compliant
        Issues = ($complianceCheck.Issues -join '; ')
    }
}

return $results