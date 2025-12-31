#region Helper Functions

function Write-CheckResult {
    param(
        [string]$CheckName,
        [bool]$Passed,
        [string]$Message = "",
        [string]$Severity = "Critical"  # Critical, Warning, Info
    )

    $status = if ($Passed) { "PASS" } else { "FAIL" }
    $color = if ($Passed) { "Green" } else {
        switch ($Severity) {
            "Critical" { "Red" }
            "Warning"  { "Yellow" }
            default    { "Gray" }
        }
    }

    Write-Host "  [$status] " -NoNewline -ForegroundColor $color
    Write-Host "$CheckName" -NoNewline
    if ($Message) {
        Write-Host " - $Message" -ForegroundColor Gray
    } else {
        Write-Host ""
    }

    return [PSCustomObject]@{
        Check = $CheckName
        Passed = $Passed
        Severity = $Severity
        Message = $Message
    }
}


#region Individual Checks

function Test-AdminRights {
    param([switch]$Quiet)

    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $Quiet) {
        Write-CheckResult -CheckName "Administrator rechten" -Passed $isAdmin -Severity "Critical" | Out-Null
    }

    return $isAdmin
}

function Test-DomainConnectivity {
    param([switch]$Quiet)

    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $passed = $true
        $message = "Verbonden met: $($domain.DNSRoot)"
    }
    catch {
        $passed = $false
        $message = "Geen AD connectie: $($_.Exception.Message)"
    }

    if (-not $Quiet) {
        Write-CheckResult -CheckName "Domain connectiviteit" -Passed $passed -Message $message -Severity "Critical" | Out-Null
    }

    return $passed
}

function Test-DomainAdminRights {
    param([switch]$Quiet)

    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        $domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive -ErrorAction Stop
        $isDomainAdmin = $domainAdmins.SamAccountName -contains $currentUser.Split('\')[-1]

        $message = if ($isDomainAdmin) {
            "User: $currentUser"
        } else {
            "User: $currentUser (niet in Domain Admins - sommige checks kunnen falen)"
        }

        if (-not $Quiet) {
            Write-CheckResult -CheckName "Domain Admin rechten" -Passed $isDomainAdmin -Message $message -Severity "Warning" | Out-Null
        }

        return $isDomainAdmin
    }
    catch {
        if (-not $Quiet) {
            Write-CheckResult -CheckName "Domain Admin rechten" -Passed $false -Message "Kan niet controleren: $_" -Severity "Warning" | Out-Null
        }
        return $false
    }
}

function Test-RequiredModules {
    param([switch]$Quiet)

    $requiredModules = @(
        @{ Name = "ActiveDirectory"; Critical = $true },
        @{ Name = "GroupPolicy"; Critical = $true },
        @{ Name = "Microsoft.PowerShell.Security"; Critical = $false }
    )

    $allPassed = $true
    $results = @()

    foreach ($module in $requiredModules) {
        $available = Get-Module -ListAvailable -Name $module.Name -ErrorAction SilentlyContinue
        $passed = $null -ne $available

        if (-not $passed) {
            $allPassed = $false
        }

        if (-not $Quiet) {
            $severity = if ($module.Critical) { "Critical" } else { "Warning" }
            $message = if ($passed) {
                "Versie: $($available[0].Version)"
            } else {
                "NIET GEVONDEN - installeer RSAT tools"
            }
            Write-CheckResult -CheckName "Module: $($module.Name)" -Passed $passed -Message $message -Severity $severity | Out-Null
        }

        $results += [PSCustomObject]@{
            Module = $module.Name
            Available = $passed
            Critical = $module.Critical
        }
    }

    return $allPassed
}

function Test-DomainController {
    param([switch]$Quiet)

    try {
        $dc = Get-ADDomainController -Discover -ErrorAction Stop
        $passed = $true
        $message = "DC: $($dc.HostName) ($($dc.Site))"
    }
    catch {
        $passed = $false
        $message = "Geen DC gevonden: $_"
    }

    if (-not $Quiet) {
        Write-CheckResult -CheckName "Domain Controller bereikbaar" -Passed $passed -Message $message -Severity "Critical" | Out-Null
    }

    return $passed
}

function Test-ADWebServices {
    param([switch]$Quiet)

    try {
        # Test door een eenvoudige AD query uit te voeren
        $null = Get-ADDomain -ErrorAction Stop
        $passed = $true
        $message = "ADWS reageert"
    }
    catch {
        $passed = $false
        $message = "ADWS probleem: $_"
    }

    if (-not $Quiet) {
        Write-CheckResult -CheckName "AD Web Services (ADWS)" -Passed $passed -Message $message -Severity "Critical" | Out-Null
    }

    return $passed
}

function Test-RSATInstalled {
    param([switch]$Quiet)

    # Check of de ActiveDirectory module beschikbaar is - dit is de beste indicator voor RSAT
    # Anders checken we voor Windows Capabilities
    $adModuleAvailable = Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue

    if ($adModuleAvailable) {
        # AD module is beschikbaar, dus RSAT is correct geïnstalleerd
        $passed = $true
        $message = "RSAT geïnstalleerd (ActiveDirectory module beschikbaar)"
    } else {
        # Fallback: Check voor Windows Capabilities
        $rsatCapabilities = @(
            "Rsat.ActiveDirectory.DS-LDS.Tools*",
            "RSAT-AD-PowerShell*",
            "RSAT-AD-Tools*"
        )

        $passed = $false
        foreach ($capability in $rsatCapabilities) {
            $installed = Get-WindowsCapability -Online -Name $capability -ErrorAction SilentlyContinue |
                         Where-Object { $_.State -eq "Installed" }

            if ($installed) {
                $passed = $true
                break
            }
        }

        $message = if ($passed) {
            "RSAT geïnstalleerd"
        } else {
            "RSAT ontbreekt - installeer met: Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'"
        }
    }

    if (-not $Quiet) {
        Write-CheckResult -CheckName "RSAT Tools" -Passed $passed -Message $message -Severity "Critical" | Out-Null
    }

    return $passed
}

function Test-PowerShellVersion {
    param([switch]$Quiet)

    $version = $PSVersionTable.PSVersion
    $passed = $version.Major -ge 5 -and $version.Minor -ge 1

    $message = "Versie: $($version.Major).$($version.Minor)"

    if (-not $Quiet) {
        Write-CheckResult -CheckName "PowerShell versie (min 5.1)" -Passed $passed -Message $message -Severity "Critical" | Out-Null
    }

    return $passed
}

function Test-ExecutionPolicy {
    param([switch]$Quiet)

    $policy = Get-ExecutionPolicy
    $passed = $policy -ne "Restricted" -and $policy -ne "AllSigned"

    $message = "Policy: $policy"

    if (-not $Quiet) {
        Write-CheckResult -CheckName "Execution Policy" -Passed $passed -Message $message -Severity "Warning" | Out-Null
    }

    return $passed
}

# region Main Check Function

function Test-Prerequisites {
    [CmdletBinding()]
    param(
        [switch]$StopOnFailure
    )

    Write-Host "`n=== AD Scanner - Prerequisite Checks ===" -ForegroundColor Cyan
    Write-Host ""

    $results = @()

    # Voer alle checks uit en sla de resultaten op
    $psVersionPassed = Test-PowerShellVersion
    $results += [PSCustomObject]@{ Check = "PowerShell Version"; Passed = $psVersionPassed; Critical = $true }

    $execPolicyPassed = Test-ExecutionPolicy
    $results += [PSCustomObject]@{ Check = "Execution Policy"; Passed = $execPolicyPassed; Critical = $false }

    $adminRightsPassed = Test-AdminRights
    $results += [PSCustomObject]@{ Check = "Administrator Rights"; Passed = $adminRightsPassed; Critical = $true }

    $modulesPassed = Test-RequiredModules
    $results += [PSCustomObject]@{ Check = "Required Modules"; Passed = $modulesPassed; Critical = $true }

    $rsatPassed = Test-RSATInstalled
    $results += [PSCustomObject]@{ Check = "RSAT Tools"; Passed = $rsatPassed; Critical = $true }

    $domainConnPassed = Test-DomainConnectivity
    $results += [PSCustomObject]@{ Check = "Domain Connectivity"; Passed = $domainConnPassed; Critical = $true }

    $dcPassed = Test-DomainController
    $results += [PSCustomObject]@{ Check = "Domain Controller"; Passed = $dcPassed; Critical = $true }

    $adwsPassed = Test-ADWebServices
    $results += [PSCustomObject]@{ Check = "AD Web Services"; Passed = $adwsPassed; Critical = $true }

    $daRightsPassed = Test-DomainAdminRights
    $results += [PSCustomObject]@{ Check = "Domain Admin Rights"; Passed = $daRightsPassed; Critical = $false }

    # Samenvatting
    Write-Host "`n=== Samenvatting ===" -ForegroundColor Cyan

    $criticalFailed = $results | Where-Object { $_.Critical -and -not $_.Passed }
    $warningFailed = $results | Where-Object { -not $_.Critical -and -not $_.Passed }
    $totalPassed = ($results | Where-Object { $_.Passed }).Count
    $totalChecks = $results.Count

    Write-Host "Geslaagd: $totalPassed/$totalChecks checks" -ForegroundColor $(if ($totalPassed -eq $totalChecks) { "Green" } else { "Yellow" })

    if ($criticalFailed.Count -gt 0) {
        Write-Host "KRITIEKE FOUTEN: $($criticalFailed.Count)" -ForegroundColor Red
        $criticalFailed | ForEach-Object {
            Write-Host "  - $($_.Check)" -ForegroundColor Red
        }

        if ($StopOnFailure) {
            Write-Host "`nKritieke checks gefaald. Scan wordt afgebroken.`n" -ForegroundColor Red
            exit 1
        }
    }

    if ($warningFailed.Count -gt 0) {
        Write-Host "WAARSCHUWINGEN: $($warningFailed.Count)" -ForegroundColor Yellow
        $warningFailed | ForEach-Object {
            Write-Host "  - $($_.Check)" -ForegroundColor Yellow
        }
    }

    if ($criticalFailed.Count -eq 0) {
        Write-Host "`nAlle kritieke checks geslaagd. Klaar om te scannen!`n" -ForegroundColor Green
        return $true
    } else {
        Write-Host "`nKritieke checks gefaald. Los de problemen op voordat je de scan start.`n" -ForegroundColor Red
        return $false
    }
}

#endregion

# Als het script direct wordt uitgevoerd (niet dot-sourced), run dan de checks automatisch
if ($MyInvocation.InvocationName -ne '.') {
    Test-Prerequisites -StopOnFailure
}
