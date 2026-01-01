<#
.SYNOPSIS
    HTML report export functions for AD Security Scanner

.DESCRIPTION
    Contains functions to export scan results to a comprehensive HTML report.
    Includes parameter validation and comprehensive error handling.

#>

#region Main Export Function

<#
.SYNOPSIS
    Exports scan results to a formatted HTML report
.PARAMETER Results
    Hashtable containing scan results from all modules
.PARAMETER OutputPath
    Path where the HTML report will be saved (default: "AD-Security-Report.html")
.EXAMPLE
    Export-ToHTML -Results $scanResults -OutputPath "C:\Reports\AD-Report.html"
#>
function Export-ToHTML {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [hashtable]$Results,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = "AD-Security-Report.html"
    )

    try {
        # Load check information metadata
        $checkInfo = & "$PSScriptRoot\checkInfo.ps1"
        if (-not $checkInfo) {
            Write-Warning "Could not load check information. Report will have limited details."
            $checkInfo = @{}
        }

        # Generate HTML template with CSS styling
        $html = Get-HTMLTemplate

        # Pre-process: Calculate statistics per module
        $moduleStats = Get-ModuleStatistics -Results $Results -CheckInfo $checkInfo

        # Generate dashboard cards
        $dashboardCards = Get-DashboardCards -Results $Results -ModuleStats $moduleStats

        # Insert dashboard cards into HTML
        $html = $html -replace "<!-- Dashboard cards will be inserted here -->", $dashboardCards

        # Generate detail views for each module
        $html += Get-DetailViews -Results $Results -CheckInfo $checkInfo

        # Add footer with JavaScript
        $html += Get-HTMLFooter -TotalChecks $moduleStats.TotalChecks -TotalIssues $moduleStats.TotalIssues

        # Ensure output directory exists
        $reportDir = Split-Path $OutputPath -Parent
        if ($reportDir -and -not (Test-Path $reportDir)) {
            try {
                New-Item -ItemType Directory -Path $reportDir -Force -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Error "Failed to create report directory: $($_.Exception.Message)"
                return
            }
        }

        # Write to file
        try {
            $html | Out-File -FilePath $OutputPath -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to write HTML report: $($_.Exception.Message)"
            return
        }

        Write-Host "`nHTML report successfully generated!" -ForegroundColor Green
        Write-Host "Location: $OutputPath" -ForegroundColor Cyan
    }
    catch {
        Write-Error "Failed to generate HTML report: $($_.Exception.Message)"
    }
}

#endregion

#region HTML Generation Helper Functions

<#
.SYNOPSIS
    Generates the HTML template with CSS styling
.OUTPUTS
    String containing the HTML template
#>
function Get-HTMLTemplate {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    try {
        $currentDate = Get-Date -Format 'dd-MM-yyyy HH:mm:ss'

        return @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD Security Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { font-size: 1.1em; opacity: 0.9; }
        .content { padding: 30px; }
        .module {
            margin-bottom: 40px;
            border-left: 4px solid #667eea;
            padding-left: 20px;
        }
        .module-title {
            font-size: 1.8em;
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e0e0e0;
        }
        .check {
            margin-bottom: 30px;
            background: #f9f9f9;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #e0e0e0;
        }
        .check-title {
            font-size: 1.3em;
            color: #333;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
        }
        .badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            margin-left: 10px;
        }
        .badge-warning { background: #fff3cd; color: #856404; }
        .badge-success { background: #d4edda; color: #155724; }
        .badge-danger { background: #f8d7da; color: #721c24; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            background: white;
        }
        th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        td {
            padding: 10px 12px;
            border-bottom: 1px solid #e0e0e0;
        }
        tr:hover { background: #f5f5f5; }
        .no-data {
            color: #28a745;
            font-style: italic;
            padding: 10px;
        }
        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
            border-top: 1px solid #e0e0e0;
        }
        /* Dashboard Cards */
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
            margin-bottom: 40px;
        }
        .dashboard-card {
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            border-left: 5px solid #667eea;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        .dashboard-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 6px 20px rgba(0,0,0,0.15);
        }
        .dashboard-card.critical { border-left-color: #dc3545; }
        .dashboard-card.high { border-left-color: #fd7e14; }
        .dashboard-card.medium { border-left-color: #ffc107; }
        .dashboard-card.low { border-left-color: #28a745; }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .card-title {
            font-size: 1.4em;
            color: #333;
            font-weight: 600;
        }
        .card-icon {
            font-size: 2.5em;
            opacity: 0.2;
        }
        .card-stats {
            margin: 15px 0;
        }
        .stat-row {
            display: flex;
            justify-content: space-between;
            margin: 10px 0;
            padding: 8px 0;
            border-bottom: 1px solid #f0f0f0;
        }
        .stat-label {
            color: #666;
            font-size: 0.95em;
        }
        .stat-value {
            font-weight: bold;
            font-size: 1.1em;
        }
        .stat-value.critical { color: #dc3545; }
        .stat-value.high { color: #fd7e14; }
        .stat-value.medium { color: #ffc107; }
        .stat-value.low { color: #28a745; }
        .card-footer {
            margin-top: 15px;
            padding-top: 15px;
            border-top: 2px solid #f0f0f0;
            text-align: center;
            color: #667eea;
            font-weight: 600;
        }

        /* View Sections (hidden by default) */
        .view-section {
            display: none;
            animation: fadeIn 0.3s ease;
        }
        .view-section.active {
            display: block;
        }
        .back-button {
            background: #6c757d;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            font-size: 1em;
            cursor: pointer;
            margin-bottom: 20px;
            transition: background 0.2s ease;
        }
        .back-button:hover {
            background: #5a6268;
        }

        /* Collapsible styling */
        .check-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            cursor: pointer;
            user-select: none;
        }
        .check-header:hover {
            background: rgba(102, 126, 234, 0.05);
            border-radius: 5px;
            padding: 5px;
            margin: -5px;
        }
        .check-title-left {
            display: flex;
            align-items: center;
            flex: 1;
        }
        .check-title-text {
            font-size: 1.3em;
            color: #333;
        }
        .collapse-icon {
            font-size: 1.2em;
            margin-right: 10px;
            transition: transform 0.3s ease;
            color: #667eea;
        }
        .collapsed .collapse-icon {
            transform: rotate(-90deg);
        }
        .check-content {
            margin-top: 15px;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }
        .collapsed .check-content {
            display: none;
        }

        /* More Info button */
        .btn-info {
            background: #17a2b8;
            color: white;
            border: none;
            padding: 6px 14px;
            border-radius: 5px;
            font-size: 0.85em;
            cursor: pointer;
            margin-left: 10px;
            transition: background 0.2s ease;
        }
        .btn-info:hover {
            background: #138496;
        }

        /* Modal styling */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            animation: fadeIn 0.2s ease;
        }
        .modal.show {
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .modal-content {
            background: white;
            padding: 30px;
            border-radius: 10px;
            max-width: 600px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            animation: slideIn 0.3s ease;
        }
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #667eea;
        }
        .modal-title {
            font-size: 1.5em;
            color: #667eea;
            margin: 0;
        }
        .close-modal {
            font-size: 2em;
            color: #999;
            cursor: pointer;
            border: none;
            background: none;
            line-height: 1;
        }
        .close-modal:hover {
            color: #333;
        }
        .modal-body {
            color: #555;
            line-height: 1.6;
        }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        @keyframes slideIn {
            from { transform: translateY(-50px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AD Security Report</h1>
            <p>Generated: $currentDate</p>
        </div>
        <div class="content">
            <!-- Dashboard View -->
            <div id="dashboard-view" class="view-section active">
                <h2 style="margin-bottom: 25px; color: #333;">Security Dashboard</h2>
                <div class="dashboard" id="dashboard-cards">
                    <!-- Dashboard cards will be inserted here -->
                </div>
            </div>

            <!-- Detail Views (hidden by default) -->
"@
    }
    catch {
        Write-Error "Failed to generate HTML template: $($_.Exception.Message)"
        return ""
    }
}

<#
.SYNOPSIS
    Calculates statistics for all modules
.PARAMETER Results
    Scan results hashtable
.PARAMETER CheckInfo
    Check information metadata
.OUTPUTS
    Hashtable containing statistics per module
#>
function Get-ModuleStatistics {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Results,

        [Parameter(Mandatory = $true)]
        [hashtable]$CheckInfo
    )

    try {
        $moduleStats = @{}
        $totalIssues = 0
        $totalChecks = 0

        foreach ($moduleName in $Results.Keys) {
            $moduleData = $Results[$moduleName]
            $moduleIssueCount = 0
            $moduleCheckCount = 0
            $highestModuleRisk = "Low"
            $criticalCount = 0
            $highCount = 0
            $mediumCount = 0
            $lowCount = 0

            foreach ($checkName in $moduleData.Keys) {
                $data = $moduleData[$checkName]

                # Check for Module 3 or Module 4 nested structure (hashtable containing hashtables)
                $isModule3Nested = ($moduleName -match "Module 3" -and $data -is [hashtable])
                $isModule4Nested = ($moduleName -match "Module 4" -and $data -is [hashtable])

                if ($isModule3Nested -or $isModule4Nested) {
                    # Module 3 or Module 4: Nested structure - loop through sub-categories
                    foreach ($subCheckName in $data.Keys) {
                        $subData = $data[$subCheckName]
                        $moduleCheckCount++
                        $totalChecks++

                        # Count accounts in this sub-check
                        if ($subData -and $subData.Count -gt 0) {
                            $count = ($subData | Measure-Object).Count
                            $moduleIssueCount += $count
                            $totalIssues += $count

                            # Get risk level from checkInfo for this sub-check
                            $info = $CheckInfo[$subCheckName]
                            if ($info) {
                                $risk = $info.RiskLevel

                                # Update highest risk level for the module
                                $highestModuleRisk = Update-HighestRiskLevel -CurrentHighest $highestModuleRisk -NewRisk $risk

                                # All accounts in this check have the same severity
                                switch ($risk) {
                                    "Critical" { $criticalCount += $count }
                                    "High" { $highCount += $count }
                                    "Medium" { $mediumCount += $count }
                                    "Low" { $lowCount += $count }
                                }
                            }
                        }
                    }
                }
                else {
                    # Regular modules (Module 1 & 2)
                    $moduleCheckCount++
                    $totalChecks++

                    # Check if password policy or regular check
                    $isPasswordPolicy = ($data -is [PSCustomObject] -and $data.PSObject.Properties.Name -contains 'PolicyType')

                    if ($isPasswordPolicy) {
                        # Password policy - count affected users, not number of settings
                        $issues = $data.Issues
                        $userCount = $data.AppliedUserCount
                        $moduleIssueCount += $userCount
                        $totalIssues += $userCount

                        foreach ($issue in $issues) {
                            $settingName = $issue.Setting
                            $info = $CheckInfo[$settingName]
                            if ($info) {
                                $risk = $info.RiskLevel

                                # Update highest risk level for the module
                                $highestModuleRisk = Update-HighestRiskLevel -CurrentHighest $highestModuleRisk -NewRisk $risk

                                # Count each issue by severity
                                switch ($risk) {
                                    "Critical" { $criticalCount++ }
                                    "High" { $highCount++ }
                                    "Medium" { $mediumCount++ }
                                    "Low" { $lowCount++ }
                                }
                            }
                        }
                    }
                    else {
                        # Regular account check - each found account is an issue with same severity
                        if ($data -and $data.Count -gt 0) {
                            $count = ($data | Measure-Object).Count
                            $moduleIssueCount += $count
                            $totalIssues += $count

                            # Get risk level from checkInfo for this check type
                            $info = $CheckInfo[$checkName]
                            if ($info) {
                                $risk = $info.RiskLevel

                                # Update highest risk level for the module
                                $highestModuleRisk = Update-HighestRiskLevel -CurrentHighest $highestModuleRisk -NewRisk $risk

                                # All accounts in this check have the same severity
                                switch ($risk) {
                                    "Critical" { $criticalCount += $count }
                                    "High" { $highCount += $count }
                                    "Medium" { $mediumCount += $count }
                                    "Low" { $lowCount += $count }
                                }
                            }
                        }
                    }
                }
            }

            $moduleStats[$moduleName] = @{
                IssueCount   = $moduleIssueCount
                CheckCount   = $moduleCheckCount
                HighestRisk  = $highestModuleRisk
                Critical     = $criticalCount
                High         = $highCount
                Medium       = $mediumCount
                Low          = $lowCount
            }
        }

        # Add totals to stats
        $moduleStats.TotalIssues = $totalIssues
        $moduleStats.TotalChecks = $totalChecks

        return $moduleStats
    }
    catch {
        Write-Error "Failed to calculate module statistics: $($_.Exception.Message)"
        return @{
            TotalIssues = 0
            TotalChecks = 0
        }
    }
}

<#
.SYNOPSIS
    Updates the highest risk level based on new risk
.PARAMETER CurrentHighest
    Current highest risk level
.PARAMETER NewRisk
    New risk level to compare
.OUTPUTS
    Updated highest risk level
#>
function Update-HighestRiskLevel {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CurrentHighest,

        [Parameter(Mandatory = $true)]
        [string]$NewRisk
    )

    # Priority: Critical > High > Medium > Low
    if ($NewRisk -eq "Critical") {
        return "Critical"
    }
    elseif ($NewRisk -eq "High" -and $CurrentHighest -ne "Critical") {
        return "High"
    }
    elseif ($NewRisk -eq "Medium" -and $CurrentHighest -notin @("Critical", "High")) {
        return "Medium"
    }
    else {
        return $CurrentHighest
    }
}

<#
.SYNOPSIS
    Generates dashboard cards HTML
.PARAMETER Results
    Scan results hashtable
.PARAMETER ModuleStats
    Module statistics hashtable
.OUTPUTS
    String containing dashboard cards HTML
#>
function Get-DashboardCards {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Results,

        [Parameter(Mandatory = $true)]
        [hashtable]$ModuleStats
    )

    try {
        $dashboardCards = ""

        # Sort modules by name to ensure consistent order (Module 1, Module 2, Module 3, Module 4)
        $sortedModules = $Results.Keys | Sort-Object {
            if ($_ -match "Module (\d+)") {
                [int]$matches[1]
            } else {
                999  # Put non-numbered modules at the end
            }
        }

        foreach ($moduleName in $sortedModules) {
            $stats = $ModuleStats[$moduleName]
            if (-not $stats) {
                Write-Verbose "No stats found for module: $moduleName"
                continue
            }

            $moduleId = $moduleName -replace '[^a-zA-Z0-9]', ''
            $riskClass = $stats.HighestRisk.ToLower()

            # Select icon based on module name
            $icon = switch -Regex ($moduleName) {
                "Password" { "&#128273;" }
                "Module 3" { "&#128272;" }
                "Module 4" { "&#128274;" }
                default { "&#9888;" }
            }

            $dashboardCards += @"
        <div class="dashboard-card $riskClass" onclick="showView('$moduleId')">
            <div class="card-header">
                <div class="card-title">$moduleName</div>
                <div class="card-icon">$icon</div>
            </div>
            <div class="card-stats">
                <div class="stat-row">
                    <span class="stat-label">Total Issues</span>
                    <span class="stat-value $riskClass">$($stats.IssueCount)</span>
                </div>
"@
            # Add severity breakdowns if present
            if ($stats.Critical -gt 0) {
                $dashboardCards += @"
                <div class="stat-row">
                    <span class="stat-label">Critical</span>
                    <span class="stat-value critical">$($stats.Critical)</span>
                </div>
"@
            }
            if ($stats.High -gt 0) {
                $dashboardCards += @"
                <div class="stat-row">
                    <span class="stat-label">High</span>
                    <span class="stat-value high">$($stats.High)</span>
                </div>
"@
            }
            if ($stats.Medium -gt 0) {
                $dashboardCards += @"
                <div class="stat-row">
                    <span class="stat-label">Medium</span>
                    <span class="stat-value medium">$($stats.Medium)</span>
                </div>
"@
            }
            $dashboardCards += @"
            </div>
            <div class="card-footer">Click to view details &#8594;</div>
        </div>

"@
        }

        return $dashboardCards
    }
    catch {
        Write-Error "Failed to generate dashboard cards: $($_.Exception.Message)"
        return ""
    }
}

<#
.SYNOPSIS
    Generates detail view HTML for all modules
.PARAMETER Results
    Scan results hashtable
.PARAMETER CheckInfo
    Check information metadata
.OUTPUTS
    String containing detail views HTML
#>
function Get-DetailViews {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Results,

        [Parameter(Mandatory = $true)]
        [hashtable]$CheckInfo
    )

    try {
        $html = ""

        # Sort modules by name to ensure consistent order (Module 1, Module 2, Module 3, Module 4)
        $sortedModules = $Results.Keys | Sort-Object {
            if ($_ -match "Module (\d+)") {
                [int]$matches[1]
            } else {
                999  # Put non-numbered modules at the end
            }
        }

        foreach ($moduleName in $sortedModules) {
            $moduleData = $Results[$moduleName]
            $moduleId = $moduleName -replace '[^a-zA-Z0-9]', ''

            $html += "<div id='view-$moduleId' class='view-section'>`n"
            $html += "<button class='back-button' onclick='showDashboard()'>&#8592; Back to Dashboard</button>`n"
            $html += "<div class='module'>`n"
            $html += "<h2 class='module-title'>$moduleName</h2>`n"

            # Check if this is Module 3 or Module 4 with nested structure
            $isModule3 = ($moduleName -match "Module 3")
            $isModule4 = ($moduleName -match "Module 4")

            if ($isModule3 -or $isModule4) {
                # Module 3 or 4: Nested structure (3-layer)
                $html += Get-NestedModuleHTML -ModuleName $moduleName -ModuleData $moduleData -ModuleId $moduleId -CheckInfo $CheckInfo -IsModule4 $isModule4
            }
            else {
                # Regular modules (Module 1 & 2)
                $html += Get-RegularModuleHTML -ModuleName $moduleName -ModuleData $moduleData -ModuleId $moduleId -CheckInfo $CheckInfo
            }

            $html += "</div>`n" # close module
            $html += "</div>`n" # close view-section
        }

        return $html
    }
    catch {
        Write-Error "Failed to generate detail views: $($_.Exception.Message)"
        return ""
    }
}

<#
.SYNOPSIS
    Generates HTML for nested modules (Module 3 & 4)
.PARAMETER ModuleName
    Name of the module
.PARAMETER ModuleData
    Module data hashtable
.PARAMETER ModuleId
    Sanitized module ID
.PARAMETER CheckInfo
    Check information metadata
.PARAMETER IsModule4
    Whether this is Module 4 (for disclaimer)
.OUTPUTS
    String containing nested module HTML
#>
function Get-NestedModuleHTML {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [Parameter(Mandatory = $true)]
        [hashtable]$ModuleData,

        [Parameter(Mandatory = $true)]
        [string]$ModuleId,

        [Parameter(Mandatory = $true)]
        [hashtable]$CheckInfo,

        [Parameter(Mandatory = $false)]
        [bool]$IsModule4 = $false
    )

    try {
        $html = ""

        # Module 4 disclaimer
        if ($IsModule4) {
            $html += @"
<div style='background: #fff3cd; border-left: 5px solid #ffc107; padding: 20px; margin-bottom: 25px; border-radius: 5px;'>
    <h3 style='color: #856404; margin: 0 0 10px 0;'>&#9432; Important: ACL Audit Overview</h3>
    <p style='margin: 0; color: #856404; line-height: 1.6;'>
        <strong>These are not necessarily security issues</strong>, but an overview of who has which ACL permissions on sensitive objects
        such as AdminSDHolder, Domain Object, privileged groups, GPOs, privileged users, and OUs.<br><br>
        <strong>Review each result</strong> to determine if the ACL permissions are legitimate (e.g., a delegated admin)
        or if they pose a security risk (e.g., a regular user with excessive permissions).
    </p>
</div>
`n
"@
        }

        foreach ($categoryName in $ModuleData.Keys) {
            $categoryData = $ModuleData[$categoryName]
            $categoryId = "$ModuleId-" + ($categoryName -replace '[^a-zA-Z0-9]', '')

            # Render sub-card for this category
            $html += "<div class='check' style='margin-bottom: 30px; background: #ffffff; border: 2px solid #667eea; padding: 25px;'>`n"
            $html += "<h3 style='color: #667eea; margin-bottom: 20px; font-size: 1.5em;'>$categoryName</h3>`n"

            # Loop through all issues within this category
            foreach ($issueName in $categoryData.Keys) {
                $issueData = $categoryData[$issueName]
                $html += Get-IssueHTML -IssueName $issueName -IssueData $issueData -CategoryId $categoryId -CheckInfo $CheckInfo
            }

            $html += "</div>`n" # close category card
        }

        return $html
    }
    catch {
        Write-Error "Failed to generate nested module HTML: $($_.Exception.Message)"
        return ""
    }
}

<#
.SYNOPSIS
    Generates HTML for regular modules (Module 1 & 2)
.PARAMETER ModuleName
    Name of the module
.PARAMETER ModuleData
    Module data hashtable
.PARAMETER ModuleId
    Sanitized module ID
.PARAMETER CheckInfo
    Check information metadata
.OUTPUTS
    String containing regular module HTML
#>
function Get-RegularModuleHTML {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [Parameter(Mandatory = $true)]
        [hashtable]$ModuleData,

        [Parameter(Mandatory = $true)]
        [string]$ModuleId,

        [Parameter(Mandatory = $true)]
        [hashtable]$CheckInfo
    )

    try {
        $html = ""
        $checkIndex = 0

        foreach ($checkName in $ModuleData.Keys) {
            $data = $ModuleData[$checkName]
            $checkId = "check-$ModuleId-$checkIndex"
            $modalId = "modal-$checkId"
            $checkIndex++

            # Check if this is a FGPP policy object or regular account array
            $isPasswordPolicy = ($data -is [PSCustomObject] -and $data.PSObject.Properties.Name -contains 'PolicyType')

            if ($isPasswordPolicy) {
                # FGPP / Password Policy rendering
                $html += Get-PasswordPolicyHTML -CheckName $checkName -Data $data -CheckId $checkId -ModalId $modalId -CheckInfo $CheckInfo
            }
            else {
                # Regular account checks rendering
                $html += Get-RegularCheckHTML -CheckName $checkName -Data $data -CheckId $checkId -ModalId $modalId -CheckInfo $CheckInfo
            }
        }

        return $html
    }
    catch {
        Write-Error "Failed to generate regular module HTML: $($_.Exception.Message)"
        return ""
    }
}

<#
.SYNOPSIS
    Generates HTML for an individual issue (Module 3/4)
.PARAMETER IssueName
    Name of the issue
.PARAMETER IssueData
    Issue data (array or single object)
.PARAMETER CategoryId
    Sanitized category ID
.PARAMETER CheckInfo
    Check information metadata
.OUTPUTS
    String containing issue HTML
#>
function Get-IssueHTML {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IssueName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $IssueData,

        [Parameter(Mandatory = $true)]
        [string]$CategoryId,

        [Parameter(Mandatory = $true)]
        [hashtable]$CheckInfo
    )

    try {
        $issueId = "$CategoryId-" + ($IssueName -replace '[^a-zA-Z0-9]', '')
        $modalId = "modal-$issueId"

        $html = "<div class='check' style='margin: 15px 0; background: #f9f9f9;'>`n"
        $html += "<div class='check-header' onclick='toggleCheck(""$issueId"")'>`n"
        $html += "<div class='check-title-left'>`n"
        $html += "<span class='collapse-icon' style='transform: rotate(-90deg);'>&#9660;</span>`n"
        $html += "<span class='check-title-text'>$IssueName</span>`n"

        # Check if issueData exists and has items (handle both single object and arrays)
        $hasData = $false
        $count = 0
        if ($IssueData) {
            if ($IssueData -is [Array]) {
                $count = $IssueData.Count
                $hasData = $count -gt 0
            }
            else {
                # Single object
                $count = 1
                $hasData = $true
            }
        }

        # Add badge with count and risk level
        if ($hasData) {
            $info = $CheckInfo[$IssueName]
            if ($info) {
                $riskLevel = $info.RiskLevel
                $riskScore = $info.RiskScore
                $badgeClass = switch ($riskLevel) {
                    "Critical" { "badge-danger" }
                    "High" { "badge-danger" }
                    "Medium" { "badge-warning" }
                    "Low" { "badge-success" }
                    default { "badge-warning" }
                }
                $html += "<span class='badge $badgeClass'>$count account(s) - $riskLevel Risk (Score: $riskScore)</span>`n"
            }
            else {
                $html += "<span class='badge badge-warning'>$count account(s)</span>`n"
            }
        }
        else {
            $html += "<span class='badge badge-success'>No issues found</span>`n"
        }

        $html += "</div>`n" # close check-title-left

        # More Info button
        if ($CheckInfo[$IssueName]) {
            $html += "<button class='btn-info' onclick='event.stopPropagation(); showModal(""$modalId"")'>More Info</button>`n"
        }

        $html += "</div>`n" # close check-header

        # Collapsible content: Accounts table (starts collapsed)
        $html += "<div id='$issueId' class='check-content' style='display: none;'>`n"

        if ($hasData) {
            # Ensure issueData is always treated as an array
            $dataArray = @()
            if ($IssueData -is [Array]) {
                $dataArray = $IssueData
            }
            else {
                $dataArray = @($IssueData)
            }

            # Get first object to determine properties
            $firstItem = $dataArray[0]
            $properties = $firstItem.PSObject.Properties.Name

            $html += "<table>`n<thead><tr>`n"
            foreach ($prop in $properties) {
                $html += "<th>$prop</th>`n"
            }
            $html += "</tr></thead>`n<tbody>`n"

            foreach ($item in $dataArray) {
                $html += "<tr>`n"
                foreach ($prop in $properties) {
                    $value = $item.$prop
                    if ($null -eq $value) { $value = "" }
                    $html += "<td>$value</td>`n"
                }
                $html += "</tr>`n"
            }
            $html += "</tbody></table>`n"
        }
        else {
            $html += "<p class='no-data'>No accounts found for this issue.</p>`n"
        }

        $html += "</div>`n" # close check-content

        # Modal for More Info
        if ($CheckInfo[$IssueName]) {
            $html += Get-ModalHTML -ModalId $modalId -CheckName $IssueName -CheckInfo $CheckInfo
        }

        $html += "</div>`n" # close issue check

        return $html
    }
    catch {
        Write-Error "Failed to generate issue HTML for '$IssueName': $($_.Exception.Message)"
        return ""
    }
}

<#
.SYNOPSIS
    Generates HTML for password policy checks
.PARAMETER CheckName
    Name of the check
.PARAMETER Data
    Password policy data
.PARAMETER CheckId
    Sanitized check ID
.PARAMETER ModalId
    Modal ID
.PARAMETER CheckInfo
    Check information metadata
.OUTPUTS
    String containing password policy HTML
#>
function Get-PasswordPolicyHTML {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CheckName,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Data,

        [Parameter(Mandatory = $true)]
        [string]$CheckId,

        [Parameter(Mandatory = $true)]
        [string]$ModalId,

        [Parameter(Mandatory = $true)]
        [hashtable]$CheckInfo
    )

    try {
        $policyData = $Data
        $issues = $policyData.Issues
        $users = $policyData.AppliedUsers
        $userCount = $policyData.AppliedUserCount
        $issueCount = ($issues | Measure-Object).Count

        # Determine highest severity level of all issues
        $highestRisk = "Low"
        $highestRiskColor = "#28a745"

        foreach ($issue in $issues) {
            $settingName = $issue.Setting
            $info = $CheckInfo[$settingName]
            if ($info) {
                $risk = $info.RiskLevel
                $highestRisk = Update-HighestRiskLevel -CurrentHighest $highestRisk -NewRisk $risk
                if ($highestRisk -eq $risk) {
                    $highestRiskColor = $info.RiskColor
                }
            }
        }

        $html = "<div class='check'>`n"
        $html += "<div class='check-header' onclick='toggleCheck(""$CheckId"")'>`n"
        $html += "<div class='check-title-left'>`n"
        $html += "<span class='collapse-icon' style='transform: rotate(-90deg);'>&#9660;</span>`n"
        $html += "<span class='check-title-text'>$CheckName</span>`n"

        # Badge with user count for password policies
        $badgeClass = switch ($highestRisk) {
            "Critical" { "badge-danger" }
            "High" { "badge-danger" }
            "Medium" { "badge-warning" }
            default { "badge-warning" }
        }
        $html += "<span class='badge $badgeClass'>$userCount user(s) affected - $highestRisk Risk</span>`n"

        $html += "</div>`n" # close check-title-left

        # More Info button
        $html += "<button class='btn-info' onclick='event.stopPropagation(); showModal(""$ModalId"")'>More Info</button>`n"

        $html += "</div>`n" # close check-header

        # Collapsible content: Users table (starts collapsed)
        $html += "<div id='$CheckId' class='check-content' style='display: none;'>`n"
        $html += "<p style='margin-bottom: 10px;'><strong>Affected Users:</strong> $userCount user(s)</p>`n"

        if ($users -and $users.Count -gt 0) {
            $html += "<table>`n<thead><tr><th>Username</th></tr></thead>`n<tbody>`n"
            foreach ($user in $users) {
                $html += "<tr><td>$user</td></tr>`n"
            }
            $html += "</tbody></table>`n"
        }
        else {
            $html += "<p class='no-data'>No users affected by this policy.</p>`n"
        }

        $html += "</div>`n" # close check-content

        # Modal for More Info: Show all policy issues with details
        $html += Get-PasswordPolicyModalHTML -ModalId $ModalId -CheckName $CheckName -Issues $issues -UserCount $userCount -IssueCount $issueCount -HighestRisk $highestRisk -HighestRiskColor $highestRiskColor -CheckInfo $CheckInfo

        $html += "</div>`n" # close check

        return $html
    }
    catch {
        Write-Error "Failed to generate password policy HTML for '$CheckName': $($_.Exception.Message)"
        return ""
    }
}

<#
.SYNOPSIS
    Generates HTML for regular account checks
.PARAMETER CheckName
    Name of the check
.PARAMETER Data
    Check data (array of accounts)
.PARAMETER CheckId
    Sanitized check ID
.PARAMETER ModalId
    Modal ID
.PARAMETER CheckInfo
    Check information metadata
.OUTPUTS
    String containing regular check HTML
#>
function Get-RegularCheckHTML {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CheckName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Data,

        [Parameter(Mandatory = $true)]
        [string]$CheckId,

        [Parameter(Mandatory = $true)]
        [string]$ModalId,

        [Parameter(Mandatory = $true)]
        [hashtable]$CheckInfo
    )

    try {
        $accounts = $Data

        $html = "<div class='check'>`n"
        $html += "<div class='check-header' onclick='toggleCheck(""$CheckId"")'>`n"
        $html += "<div class='check-title-left'>`n"
        $html += "<span class='collapse-icon' style='transform: rotate(-90deg);'>&#9660;</span>`n"
        $html += "<span class='check-title-text'>$CheckName</span>`n"

        if ($accounts -and $accounts.Count -gt 0) {
            $count = ($accounts | Measure-Object).Count

            # Get risk level for this check
            $info = $CheckInfo[$CheckName]
            if ($info) {
                $riskLevel = $info.RiskLevel
                $riskScore = $info.RiskScore
                # Badge color based on risk level
                $badgeClass = switch ($riskLevel) {
                    "Critical" { "badge-danger" }
                    "High" { "badge-danger" }
                    "Medium" { "badge-warning" }
                    "Low" { "badge-success" }
                    default { "badge-warning" }
                }
                $html += "<span class='badge $badgeClass'>$count found - $riskLevel Risk (Score: $riskScore)</span>`n"
            }
            else {
                # Fallback if no info available
                $badgeClass = if ($count -gt 10) { "badge-danger" } elseif ($count -gt 5) { "badge-warning" } else { "badge-warning" }
                $html += "<span class='badge $badgeClass'>$count found</span>`n"
            }
        }
        else {
            $html += "<span class='badge badge-success'>0 found</span>`n"
        }

        $html += "</div>`n" # close check-title-left

        # More Info button (only if there is data)
        if ($accounts -and $accounts.Count -gt 0) {
            $html += "<button class='btn-info' onclick='event.stopPropagation(); showModal(""$ModalId"")'>More Info</button>`n"
        }

        $html += "</div>`n" # close check-header

        # Check content (starts collapsed)
        $html += "<div id='$CheckId' class='check-content' style='display: none;'>`n"

        if ($accounts -and $accounts.Count -gt 0) {
            # Create table with accounts
            $html += "<table>`n<thead><tr>"

            # Dynamic columns based on properties
            $properties = $accounts[0].PSObject.Properties.Name
            foreach ($prop in $properties) {
                $html += "<th>$prop</th>"
            }
            $html += "</tr></thead>`n<tbody>`n"

            # Rows with data
            foreach ($account in $accounts) {
                $html += "<tr>"
                foreach ($prop in $properties) {
                    $value = $account.$prop
                    if ($value -is [DateTime]) {
                        $value = $value.ToString('dd-MM-yyyy HH:mm:ss')
                    }
                    $html += "<td>$value</td>"
                }
                $html += "</tr>`n"
            }
            $html += "</tbody></table>`n"
        }
        else {
            $html += "<p class='no-data'>No issues found for this check.</p>`n"
        }

        $html += "</div>`n" # close check-content

        # Modal for More Info (only if there is data)
        if ($accounts -and $accounts.Count -gt 0) {
            $html += Get-ModalHTML -ModalId $ModalId -CheckName $CheckName -CheckInfo $CheckInfo
        }

        $html += "</div>`n" # close check

        return $html
    }
    catch {
        Write-Error "Failed to generate regular check HTML for '$CheckName': $($_.Exception.Message)"
        return ""
    }
}

<#
.SYNOPSIS
    Generates HTML for information modal
.PARAMETER ModalId
    Modal ID
.PARAMETER CheckName
    Name of the check
.PARAMETER CheckInfo
    Check information metadata
.OUTPUTS
    String containing modal HTML
#>
function Get-ModalHTML {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModalId,

        [Parameter(Mandatory = $true)]
        [string]$CheckName,

        [Parameter(Mandatory = $true)]
        [hashtable]$CheckInfo
    )

    try {
        # Get check info from the checkInfo hashtable
        $info = $CheckInfo[$CheckName]

        if ($info) {
            $riskLevel = $info.RiskLevel
            $riskColor = $info.RiskColor
            $description = $info.Description
            $remediation = $info.Remediation -replace "`n", "<br>"
            $references = $info.References
            $severity = $info.Severity
            $exploitability = $info.Exploitability
            $exposure = $info.Exposure
            $riskScore = $info.RiskScore
            $mitre = $info.MITRETechnique
        }
        else {
            # Fallback if there is no info for this check
            $riskLevel = "Unknown"
            $riskColor = "#6c757d"
            $description = "No detailed information available for this check yet."
            $remediation = "Please consult your security team or documentation."
            $references = "N/A"
            $severity = $null
            $exploitability = $null
            $exposure = $null
            $riskScore = $null
            $mitre = $null
        }

        $html = "<div id='$ModalId' class='modal' onclick='closeModal(""$ModalId"")'>`n"
        $html += "    <div class='modal-content' onclick='event.stopPropagation()'>`n"
        $html += "        <div class='modal-header'>`n"
        $html += "            <h2 class='modal-title'>$CheckName</h2>`n"
        $html += "            <button class='close-modal' onclick='event.stopPropagation(); closeModal(""$ModalId"")'>&times;</button>`n"
        $html += "        </div>`n"
        $html += "        <div class='modal-body'>`n"
        $html += "            <p><strong>Risk Level:</strong> <span style='color: $riskColor; font-weight: bold;'>$riskLevel</span></p>`n"

        # Show risk score and breakdown
        if ($riskScore) {
            $html += "            <p><strong>Risk Score:</strong> $riskScore (Severity: $severity &times; Exploitability: $exploitability &times; Exposure: $exposure)</p>`n"
        }

        # Show MITRE ATT&CK technique (if present)
        if ($mitre) {
            $html += "            <p><strong>MITRE ATT&CK:</strong> $mitre</p>`n"
        }

        $html += "            <hr style='margin: 15px 0; border: none; border-top: 1px solid #e0e0e0;'>`n"
        $html += "            <p><strong>Description:</strong><br>$description</p>`n"
        $html += "            <hr style='margin: 15px 0; border: none; border-top: 1px solid #e0e0e0;'>`n"
        $html += "            <p><strong>Remediation:</strong><br>$remediation</p>`n"
        if ($references) {
            $html += "            <hr style='margin: 15px 0; border: none; border-top: 1px solid #e0e0e0;'>`n"
            $html += "            <p><strong>References:</strong><br>$references</p>`n"
        }
        $html += "        </div>`n"
        $html += "    </div>`n"
        $html += "</div>`n"

        return $html
    }
    catch {
        Write-Error "Failed to generate modal HTML for '$CheckName': $($_.Exception.Message)"
        return ""
    }
}

<#
.SYNOPSIS
    Generates HTML for password policy modal
.PARAMETER ModalId
    Modal ID
.PARAMETER CheckName
    Name of the check
.PARAMETER Issues
    Array of policy issues
.PARAMETER UserCount
    Number of affected users
.PARAMETER IssueCount
    Number of issues
.PARAMETER HighestRisk
    Highest risk level
.PARAMETER HighestRiskColor
    Color for highest risk level
.PARAMETER CheckInfo
    Check information metadata
.OUTPUTS
    String containing password policy modal HTML
#>
function Get-PasswordPolicyModalHTML {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModalId,

        [Parameter(Mandatory = $true)]
        [string]$CheckName,

        [Parameter(Mandatory = $true)]
        [array]$Issues,

        [Parameter(Mandatory = $true)]
        [int]$UserCount,

        [Parameter(Mandatory = $true)]
        [int]$IssueCount,

        [Parameter(Mandatory = $true)]
        [string]$HighestRisk,

        [Parameter(Mandatory = $true)]
        [string]$HighestRiskColor,

        [Parameter(Mandatory = $true)]
        [hashtable]$CheckInfo
    )

    try {
        $html = "<div id='$ModalId' class='modal' onclick='closeModal(""$ModalId"")'>`n"
        $html += "    <div class='modal-content' onclick='event.stopPropagation()'>`n"
        $html += "        <div class='modal-header'>`n"
        $html += "            <h2 class='modal-title'>$CheckName - Policy Issues</h2>`n"
        $html += "            <button class='close-modal' onclick='event.stopPropagation(); closeModal(""$ModalId"")'>&times;</button>`n"
        $html += "        </div>`n"
        $html += "        <div class='modal-body'>`n"
        $html += "            <p><strong>Highest Risk Level:</strong> <span style='color: $HighestRiskColor; font-weight: bold;'>$HighestRisk</span></p>`n"
        $html += "            <p><strong>Total Issues:</strong> $IssueCount</p>`n"
        $html += "            <p><strong>Affected Users:</strong> $UserCount</p>`n"
        $html += "            <hr style='margin: 15px 0; border: none; border-top: 1px solid #e0e0e0;'>`n"

        # Loop through all issues and show details
        foreach ($issue in $Issues) {
            $settingName = $issue.Setting
            $currentValue = $issue.CurrentValue
            $info = $CheckInfo[$settingName]

            if ($info) {
                $riskLevel = $info.RiskLevel
                $riskColor = $info.RiskColor
                $description = $info.Description
                $remediation = $info.Remediation -replace "`n", "<br>"
                $references = $info.References
                $severity = $info.Severity
                $exploitability = $info.Exploitability
                $exposure = $info.Exposure
                $riskScore = $info.RiskScore
                $mitre = $info.MITRETechnique
            }
            else {
                $riskLevel = "Unknown"
                $riskColor = "#6c757d"
                $description = "No detailed information available."
                $remediation = "Please consult documentation."
                $references = "N/A"
                $severity = $null
                $exploitability = $null
                $exposure = $null
                $riskScore = $null
                $mitre = $null
            }

            $html += "<div style='margin-bottom: 25px; padding: 15px; background: #f9f9f9; border-left: 4px solid $riskColor; border-radius: 5px;'>`n"
            $html += "    <h3 style='color: $riskColor; margin-bottom: 10px;'>$settingName</h3>`n"
            $html += "    <p><strong>Current Value:</strong> $currentValue</p>`n"
            $html += "    <p><strong>Risk Level:</strong> <span style='color: $riskColor; font-weight: bold;'>$riskLevel</span></p>`n"
            if ($riskScore) {
                $html += "    <p><strong>Risk Score:</strong> $riskScore (Severity: $severity &times; Exploitability: $exploitability &times; Exposure: $exposure)</p>`n"
            }
            if ($mitre) {
                $html += "    <p><strong>MITRE ATT&CK:</strong> $mitre</p>`n"
            }
            $html += "    <hr style='margin: 10px 0; border: none; border-top: 1px solid #e0e0e0;'>`n"
            $html += "    <p><strong>Description:</strong><br>$description</p>`n"
            $html += "    <hr style='margin: 10px 0; border: none; border-top: 1px solid #e0e0e0;'>`n"
            $html += "    <p><strong>Remediation:</strong><br>$remediation</p>`n"
            if ($references) {
                $html += "    <hr style='margin: 10px 0; border: none; border-top: 1px solid #e0e0e0;'>`n"
                $html += "    <p><strong>References:</strong><br>$references</p>`n"
            }
            $html += "</div>`n"
        }

        $html += "        </div>`n"
        $html += "    </div>`n"
        $html += "</div>`n"

        return $html
    }
    catch {
        Write-Error "Failed to generate password policy modal HTML: $($_.Exception.Message)"
        return ""
    }
}

<#
.SYNOPSIS
    Generates HTML footer with JavaScript
.PARAMETER TotalChecks
    Total number of checks performed
.PARAMETER TotalIssues
    Total number of issues found
.OUTPUTS
    String containing footer HTML
#>
function Get-HTMLFooter {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$TotalChecks,

        [Parameter(Mandatory = $true)]
        [int]$TotalIssues
    )

    try {
        return @"
        </div>
        <div class="footer">
            <p>Total checks performed: $TotalChecks | Total issues found: $TotalIssues</p>
            <p>AD Security Scanner | Generated by PowerShell</p>
        </div>
    </div>

    <script>
        // Dashboard Navigation
        function showDashboard() {
            // Hide all detail views
            document.querySelectorAll('.view-section').forEach(view => {
                view.classList.remove('active');
            });
            // Show dashboard
            document.getElementById('dashboard-view').classList.add('active');
        }

        function showView(moduleId) {
            // Hide all views
            document.querySelectorAll('.view-section').forEach(view => {
                view.classList.remove('active');
            });
            // Show selected view
            document.getElementById('view-' + moduleId).classList.add('active');
        }

        // Toggle collapse of check sections
        function toggleCheck(checkId) {
            const contentElement = document.getElementById(checkId);
            const checkElement = contentElement.parentElement;
            const icon = checkElement.querySelector('.collapse-icon');

            if (contentElement.style.display === 'none') {
                contentElement.style.display = 'block';
                icon.style.transform = 'rotate(0deg)';
            } else {
                contentElement.style.display = 'none';
                icon.style.transform = 'rotate(-90deg)';
            }
        }

        // Open modal
        function showModal(modalId) {
            const modal = document.getElementById(modalId);
            modal.classList.add('show');
        }

        // Close modal
        function closeModal(modalId) {
            const modal = document.getElementById(modalId);
            modal.classList.remove('show');
        }

        // Close modal with ESC key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                document.querySelectorAll('.modal.show').forEach(modal => {
                    modal.classList.remove('show');
                });
            }
        });

        // Collapse all functionality
        function collapseAll() {
            document.querySelectorAll('.check-content').forEach(content => {
                content.style.display = 'none';
            });
            document.querySelectorAll('.collapse-icon').forEach(icon => {
                icon.style.transform = 'rotate(-90deg)';
            });
        }

        // Expand all functionality
        function expandAll() {
            document.querySelectorAll('.check-content').forEach(content => {
                content.style.display = 'block';
            });
            document.querySelectorAll('.collapse-icon').forEach(icon => {
                icon.style.transform = 'rotate(0deg)';
            });
        }
    </script>
</body>
</html>
"@
    }
    catch {
        Write-Error "Failed to generate HTML footer: $($_.Exception.Message)"
        return ""
    }
}

#endregion
