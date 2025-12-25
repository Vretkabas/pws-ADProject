function Export-ToHTML {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$Results,

        [string]$OutputPath = "AD-Security-Report.html"
    )

    # alle info over de checks
    $checkInfo = & "$PSScriptRoot\checkInfo.ps1"

    # HTML / CSS template
    $html = @"
<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD Security Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            padding: 20px;§
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
            <p>Generated: $(Get-Date -Format 'dd-MM-yyyy HH:mm:ss')</p>
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

    # Pre-process: Calculate stats per module
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
                        $info = $checkInfo[$subCheckName]
                        if ($info) {
                            $risk = $info.RiskLevel
                            # Update highest risk level for the module
                            if ($risk -eq "Critical" -and $highestModuleRisk -ne "Critical") {
                                $highestModuleRisk = "Critical"
                            }
                            elseif ($risk -eq "High" -and $highestModuleRisk -notin @("Critical")) {
                                $highestModuleRisk = "High"
                            }
                            elseif ($risk -eq "Medium" -and $highestModuleRisk -notin @("Critical", "High")) {
                                $highestModuleRisk = "Medium"
                            }

                            # All accounts in this check have the same severity
                            if ($risk -eq "Critical") { $criticalCount += $count }
                            elseif ($risk -eq "High") { $highCount += $count }
                            elseif ($risk -eq "Medium") { $mediumCount += $count }
                            elseif ($risk -eq "Low") { $lowCount += $count }
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
                        $info = $checkInfo[$settingName]
                        if ($info) {
                            $risk = $info.RiskLevel
                            # Update highest risk level for the module
                            if ($risk -eq "Critical" -and $highestModuleRisk -ne "Critical") {
                                $highestModuleRisk = "Critical"
                            }
                            elseif ($risk -eq "High" -and $highestModuleRisk -notin @("Critical")) {
                                $highestModuleRisk = "High"
                            }
                            elseif ($risk -eq "Medium" -and $highestModuleRisk -notin @("Critical", "High")) {
                                $highestModuleRisk = "Medium"
                            }

                            # Count each issue by severity
                            if ($risk -eq "Critical") { $criticalCount++ }
                            elseif ($risk -eq "High") { $highCount++ }
                            elseif ($risk -eq "Medium") { $mediumCount++ }
                            elseif ($risk -eq "Low") { $lowCount++ }
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
                        $info = $checkInfo[$checkName]
                        if ($info) {
                            $risk = $info.RiskLevel
                            # Update highest risk level for the module
                            if ($risk -eq "Critical" -and $highestModuleRisk -ne "Critical") {
                                $highestModuleRisk = "Critical"
                            }
                            elseif ($risk -eq "High" -and $highestModuleRisk -notin @("Critical")) {
                                $highestModuleRisk = "High"
                            }
                            elseif ($risk -eq "Medium" -and $highestModuleRisk -notin @("Critical", "High")) {
                                $highestModuleRisk = "Medium"
                            }

                            # All accounts in this check have the same severity
                            if ($risk -eq "Critical") { $criticalCount += $count }
                            elseif ($risk -eq "High") { $highCount += $count }
                            elseif ($risk -eq "Medium") { $mediumCount += $count }
                            elseif ($risk -eq "Low") { $lowCount += $count }
                        }
                    }
                }
            }
        }

        $moduleStats[$moduleName] = @{
            IssueCount = $moduleIssueCount
            CheckCount = $moduleCheckCount
            HighestRisk = $highestModuleRisk
            Critical = $criticalCount
            High = $highCount
            Medium = $mediumCount
            Low = $lowCount
        }
    }

    # Generate Dashboard Cards
    $dashboardCards = ""
    foreach ($moduleName in $Results.Keys) {
        $stats = $moduleStats[$moduleName]
        $moduleId = $moduleName -replace '[^a-zA-Z0-9]', ''
        $riskClass = $stats.HighestRisk.ToLower()
        $icon = if ($moduleName -match "Password") { "🔑" } elseif ($moduleName -match "Module 3") { "🔐" } elseif ($moduleName -match "Module 4") { "🔒" } else { "⚠️" }

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
            <div class="card-footer">Click to view details →</div>
        </div>

"@
    }

    # Insert dashboard cards into HTML
    $html = $html -replace "<!-- Dashboard cards will be inserted here -->", $dashboardCards

    # Generate Detail Views
    foreach ($moduleName in $Results.Keys) {
        $moduleData = $Results[$moduleName]
        $moduleId = $moduleName -replace '[^a-zA-Z0-9]', ''

        $html += "<div id='view-$moduleId' class='view-section'>`n"
        $html += "<button class='back-button' onclick='showDashboard()'>← Back to Dashboard</button>`n"
        $html += "<div class='module'>`n"
        $html += "<h2 class='module-title'>$moduleName</h2>`n"

        # Check if this is Module 3 or Module 4 with nested structure
        $isModule3 = ($moduleName -match "Module 3")
        $isModule4 = ($moduleName -match "Module 4")

        if ($isModule3 -or $isModule4) {
            # === MODULE 3 or MODULE 4: 3-Laag structuur ===
            # Laag 1: Module kaart (al op dashboard)
            # Laag 2: Controle types (sub-kaarten) - we tonen deze nu
            # Laag 3: Issues per object type binnen elke controle

            # Module 4 disclaimer
            if ($isModule4) {
                $html += @"
<div style='background: #fff3cd; border-left: 5px solid #ffc107; padding: 20px; margin-bottom: 25px; border-radius: 5px;'>
    <h3 style='color: #856404; margin: 0 0 10px 0;'>ℹ️ Belangrijk: ACL Audit Overzicht</h3>
    <p style='margin: 0; color: #856404; line-height: 1.6;'>
        <strong>Dit zijn niet persé security issues</strong>, maar een overzicht van wie welke ACL rechten heeft op gevoelige objecten
        zoals AdminSDHolder, Domain Object, privileged groups, GPOs, privileged users en OUs.<br><br>
        <strong>Review elk resultaat</strong> om te bepalen of de ACL rechten legitiem zijn (bijv. een delegated admin)
        of dat ze een security risk vormen (bijv. een gewone gebruiker met te veel rechten).
    </p>
</div>
`n
"@
            }

            foreach ($categoryName in $moduleData.Keys) {
                $categoryData = $moduleData[$categoryName]
                $categoryId = "$moduleId-" + ($categoryName -replace '[^a-zA-Z0-9]', '')

                # Render sub-card voor deze categorie (bijv. "Unconstrained Delegation")
                $html += "<div class='check' style='margin-bottom: 30px; background: #ffffff; border: 2px solid #667eea; padding: 25px;'>`n"
                $html += "<h3 style='color: #667eea; margin-bottom: 20px; font-size: 1.5em;'>$categoryName</h3>`n"

                # Loop door alle issues binnen deze categorie
                foreach ($issueName in $categoryData.Keys) {
                    $issueData = $categoryData[$issueName]
                    $issueId = "$categoryId-" + ($issueName -replace '[^a-zA-Z0-9]', '')
                    $modalId = "modal-$issueId"

                    # Render issue (bijv. "Users (CRITICAL)")
                    $html += "<div class='check' style='margin: 15px 0; background: #f9f9f9;'>`n"
                    $html += "<div class='check-header' onclick='toggleCheck(""$issueId"")'>`n"
                    $html += "<div class='check-title-left'>`n"
                    $html += "<span class='collapse-icon'>▼</span>`n"
                    $html += "<span class='check-title-text'>$issueName</span>`n"

                    # Check if issueData exists and has items (handle both single object and arrays)
                    $hasData = $false
                    $count = 0
                    if ($issueData) {
                        if ($issueData -is [Array]) {
                            $count = $issueData.Count
                            $hasData = $count -gt 0
                        } else {
                            # Single object
                            $count = 1
                            $hasData = $true
                        }
                    }

                    if ($hasData) {
                        $info = $checkInfo[$issueName]
                        $badgeClass = if ($info -and $info.RiskLevel -eq "Critical") { "badge-danger" } elseif ($info -and $info.RiskLevel -eq "High") { "badge-danger" } elseif ($info -and $info.RiskLevel -eq "Medium") { "badge-warning" } else { "badge-warning" }
                        $html += "<span class='badge $badgeClass'>$count account(s)</span>`n"
                    } else {
                        $html += "<span class='badge badge-success'>No issues found</span>`n"
                    }

                    $html += "</div>`n" # close check-title-left

                    # More Info button
                    if ($checkInfo[$issueName]) {
                        $html += "<button class='btn-info' onclick='event.stopPropagation(); showModal(""$modalId"")'>More Info</button>`n"
                    }

                    $html += "</div>`n" # close check-header

                    # Collapsible content: Accounts tabel
                    $html += "<div id='$issueId' class='check-content'>`n"

                    if ($hasData) {
                        # Ensure issueData is always treated as an array
                        $dataArray = @()
                        if ($issueData -is [Array]) {
                            $dataArray = $issueData
                        } else {
                            $dataArray = @($issueData)
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
                    } else {
                        $html += "<p class='no-data'>No accounts found for this issue.</p>`n"
                    }

                    $html += "</div>`n" # close check-content

                    # Modal voor More Info
                    if ($checkInfo[$issueName]) {
                        $info = $checkInfo[$issueName]
                        $riskLevel = $info.RiskLevel
                        $riskColor = $info.RiskColor
                        $description = $info.Description
                        $remediation = $info.Remediation -replace "`n", "<br>"
                        $references = $info.References

                        $html += "<div id='$modalId' class='modal' onclick='closeModal(""$modalId"")'>`n"
                        $html += "    <div class='modal-content' onclick='event.stopPropagation()'>`n"
                        $html += "        <div class='modal-header'>`n"
                        $html += "            <h2 class='modal-title'>$issueName</h2>`n"
                        $html += "            <button class='close-modal' onclick='event.stopPropagation(); closeModal(""$modalId"")'>&times;</button>`n"
                        $html += "        </div>`n"
                        $html += "        <div class='modal-body'>`n"
                        $html += "            <p><strong>Risk Level:</strong> <span style='color: $riskColor; font-weight: bold;'>$riskLevel</span></p>`n"
                        $html += "            <hr style='margin: 15px 0; border: none; border-top: 1px solid #e0e0e0;'>`n"
                        $html += "            <p><strong>Description:</strong><br>$description</p>`n"
                        $html += "            <hr style='margin: 15px 0; border: none; border-top: 1px solid #e0e0e0;'>`n"
                        $html += "            <p><strong>Remediation:</strong><br>$remediation</p>`n"
                        if ($references) {
                            $html += "            <hr style='margin: 15px 0; border: none; border-top: 1px solid #e0e0e0;'>`n"
                            $html += "            <p><strong>References:</strong><br><a href='$references' target='_blank'>$references</a></p>`n"
                        }
                        $html += "        </div>`n"
                        $html += "    </div>`n"
                        $html += "</div>`n"
                    }

                    $html += "</div>`n" # close issue check
                }

                $html += "</div>`n" # close category card
            }
        }
        else {
            # === REGULAR MODULES (Module 1 & 2) ===
            # Loop door alle checks binnen de module
            $checkIndex = 0
            foreach ($checkName in $moduleData.Keys) {
                $data = $moduleData[$checkName]
                $checkId = "check-$($moduleName -replace '[^a-zA-Z0-9]', '')-$checkIndex"
                $modalId = "modal-$checkId"
                $checkIndex++

                # Check of dit een FGPP policy object is of gewone account array
                $isPasswordPolicy = ($data -is [PSCustomObject] -and $data.PSObject.Properties.Name -contains 'PolicyType')

                if ($isPasswordPolicy) {
                # === FGPP / Password Policy rendering ===
                $policyData = $data
                $issues = $policyData.Issues
                $users = $policyData.AppliedUsers
                $userCount = $policyData.AppliedUserCount

                # Bepaal hoogste severity level van alle issues
                $highestRisk = "Low"
                $highestRiskColor = "#28a745"

                foreach ($issue in $issues) {
                    $settingName = $issue.Setting
                    $info = $checkInfo[$settingName]
                    if ($info) {
                        $risk = $info.RiskLevel
                        # Priority: Critical > High > Medium > Low
                        if ($risk -eq "Critical" -and $highestRisk -ne "Critical") {
                            $highestRisk = "Critical"
                            $highestRiskColor = $info.RiskColor
                        }
                        elseif ($risk -eq "High" -and $highestRisk -notin @("Critical", "High")) {
                            $highestRisk = "High"
                            $highestRiskColor = $info.RiskColor
                        }
                        elseif ($risk -eq "Medium" -and $highestRisk -notin @("Critical", "High", "Medium")) {
                            $highestRisk = "Medium"
                            $highestRiskColor = $info.RiskColor
                        }
                    }
                }

                $html += "<div class='check'>`n"
                $html += "<div class='check-header' onclick='toggleCheck(""$checkId"")'>`n"
                $html += "<div class='check-title-left'>`n"
                $html += "<span class='collapse-icon'>▼</span>`n"
                $html += "<span class='check-title-text'>$checkName</span>`n"

                # Badge met user count (niet issue count) voor password policies
                $userCount = $data.AppliedUserCount
                $badgeClass = if ($highestRisk -eq "Critical") { "badge-danger" } elseif ($highestRisk -eq "High") { "badge-danger" } elseif ($highestRisk -eq "Medium") { "badge-warning" } else { "badge-warning" }
                $html += "<span class='badge $badgeClass'>$userCount user(s) affected - $highestRisk Risk</span>`n"

                $html += "</div>`n" # close check-title-left

                # More Info button
                $html += "<button class='btn-info' onclick='event.stopPropagation(); showModal(""$modalId"")'>More Info</button>`n"

                $html += "</div>`n" # close check-header

                # Collapsible content: Users tabel
                $html += "<div id='$checkId' class='check-content'>`n"
                $html += "<p style='margin-bottom: 10px;'><strong>Affected Users:</strong> $userCount user(s)</p>`n"

                if ($users -and $users.Count -gt 0) {
                    $html += "<table>`n<thead><tr><th>Username</th></tr></thead>`n<tbody>`n"
                    foreach ($user in $users) {
                        $html += "<tr><td>$user</td></tr>`n"
                    }
                    $html += "</tbody></table>`n"
                } else {
                    $html += "<p class='no-data'>No users affected by this policy.</p>`n"
                }

                $html += "</div>`n" # close check-content

                # Modal voor More Info: Toon alle policy issues met details
                $html += "<div id='$modalId' class='modal' onclick='closeModal(""$modalId"")'>`n"
                $html += "    <div class='modal-content' onclick='event.stopPropagation()'>`n"
                $html += "        <div class='modal-header'>`n"
                $html += "            <h2 class='modal-title'>$checkName - Policy Issues</h2>`n"
                $html += "            <button class='close-modal' onclick='event.stopPropagation(); closeModal(""$modalId"")'>&times;</button>`n"
                $html += "        </div>`n"
                $html += "        <div class='modal-body'>`n"
                $html += "            <p><strong>Highest Risk Level:</strong> <span style='color: $highestRiskColor; font-weight: bold;'>$highestRisk</span></p>`n"
                $html += "            <p><strong>Total Issues:</strong> $issueCount</p>`n"
                $html += "            <p><strong>Affected Users:</strong> $userCount</p>`n"
                $html += "            <hr style='margin: 15px 0; border: none; border-top: 1px solid #e0e0e0;'>`n"

                # Loop door alle issues en toon details
                foreach ($issue in $issues) {
                    $settingName = $issue.Setting
                    $currentValue = $issue.CurrentValue
                    $info = $checkInfo[$settingName]

                    if ($info) {
                        $riskLevel = $info.RiskLevel
                        $riskColor = $info.RiskColor
                        $description = $info.Description
                        $remediation = $info.Remediation -replace "`n", "<br>"
                        $references = $info.References
                    } else {
                        $riskLevel = "Unknown"
                        $riskColor = "#6c757d"
                        $description = "No detailed information available."
                        $remediation = "Please consult documentation."
                        $references = "N/A"
                    }

                    $html += "<div style='margin-bottom: 25px; padding: 15px; background: #f9f9f9; border-left: 4px solid $riskColor; border-radius: 5px;'>`n"
                    $html += "    <h3 style='color: $riskColor; margin-bottom: 10px;'>$settingName</h3>`n"
                    $html += "    <p><strong>Current Value:</strong> $currentValue</p>`n"
                    $html += "    <p><strong>Risk Level:</strong> <span style='color: $riskColor; font-weight: bold;'>$riskLevel</span></p>`n"
                    $html += "    <p><strong>Description:</strong><br>$description</p>`n"
                    $html += "    <p><strong>Remediation:</strong><br>$remediation</p>`n"
                    if ($references) {
                        $html += "    <p><strong>References:</strong><br>$references</p>`n"
                    }
                    $html += "</div>`n"
                }

                $html += "        </div>`n"
                $html += "    </div>`n"
                $html += "</div>`n"

                $html += "</div>`n" # close check
            }
            else {
                # === Regular account checks rendering ===
                $accounts = $data

                $html += "<div class='check'>`n"
                $html += "<div class='check-header' onclick='toggleCheck(""$checkId"")'>`n"
                $html += "<div class='check-title-left'>`n"
                $html += "<span class='collapse-icon'>▼</span>`n"
                $html += "<span class='check-title-text'>$checkName</span>`n"

                if ($accounts -and $accounts.Count -gt 0) {
                    $count = ($accounts | Measure-Object).Count

                    # Haal risk level op voor deze check
                    $info = $checkInfo[$checkName]
                    if ($info) {
                        $riskLevel = $info.RiskLevel
                        # Badge kleur gebaseerd op risk level
                        $badgeClass = switch ($riskLevel) {
                            "Critical" { "badge-danger" }
                            "High" { "badge-danger" }
                            "Medium" { "badge-warning" }
                            "Low" { "badge-success" }
                            default { "badge-warning" }
                        }
                        $html += "<span class='badge $badgeClass'>$count found - $riskLevel Risk</span>`n"
                    } else {
                        # Fallback als geen info beschikbaar
                        $badgeClass = if ($count -gt 10) { "badge-danger" } elseif ($count -gt 5) { "badge-warning" } else { "badge-warning" }
                        $html += "<span class='badge $badgeClass'>$count found</span>`n"
                    }
                } else {
                    $html += "<span class='badge badge-success'>0 found</span>`n"
                }

                $html += "</div>`n" # close check-title-left

                # More Info button (alleen als er data is)
                if ($accounts -and $accounts.Count -gt 0) {
                    $html += "<button class='btn-info' onclick='event.stopPropagation(); showModal(""$modalId"")'>More Info</button>`n"
                }

                $html += "</div>`n" # close check-header

                # gegevens van de check
                $html += "<div id='$checkId' class='check-content'>`n"

                if ($accounts -and $accounts.Count -gt 0) {
                    # Maak tabel met accounts
                    $html += "<table>`n<thead><tr>"

                    # Dynamische kolommen obv properties
                    $properties = $accounts[0].PSObject.Properties.Name
                    foreach ($prop in $properties) {
                        $html += "<th>$prop</th>"
                    }
                    $html += "</tr></thead>`n<tbody>`n"

                    # Rijen met data
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
                } else {
                    $html += "<p class='no-data'>No issues found for this check.</p>`n"
                }

                $html += "</div>`n" # close check-content

                # Modal voor More Info (alleen als er data is)
                if ($accounts -and $accounts.Count -gt 0) {
                    # Haal check info op uit de checkInfo hashtable
                    $info = $checkInfo[$checkName]

                    if ($info) {
                        $riskLevel = $info.RiskLevel
                        $riskColor = $info.RiskColor
                        $description = $info.Description
                        $remediation = $info.Remediation -replace "`n", "<br>"
                        $references = $info.References
                    } else {
                        # Fallback als er geen info is voor deze check
                        $riskLevel = "Unknown"
                        $riskColor = "#6c757d"
                        $description = "No detailed information available for this check yet."
                        $remediation = "Please consult your security team or documentation."
                        $references = "N/A"
                    }

                    $html += "<div id='$modalId' class='modal' onclick='closeModal(""$modalId"")'>`n"
                    $html += "    <div class='modal-content' onclick='event.stopPropagation()'>`n"
                    $html += "        <div class='modal-header'>`n"
                    $html += "            <h2 class='modal-title'>$checkName</h2>`n"
                    $html += "            <button class='close-modal' onclick='event.stopPropagation(); closeModal(""$modalId"")'>&times;</button>`n"
                    $html += "        </div>`n"
                    $html += "        <div class='modal-body'>`n"
                    $html += "            <p><strong>Risk Level:</strong> <span style='color: $riskColor; font-weight: bold;'>$riskLevel</span></p>`n"
                    $html += "            <p><strong>Description:</strong><br>$description</p>`n"
                    $html += "            <p><strong>Remediation:</strong><br>$remediation</p>`n"
                    $html += "            <p><strong>References:</strong><br>$references</p>`n"
                    $html += "        </div>`n"
                    $html += "    </div>`n"
                    $html += "</div>`n"
                }

                    $html += "</div>`n" # close check
                }
            }
        } # end else (regular modules)

        $html += "</div>`n" # close module
        $html += "</div>`n" # close view-section
    }

    # Footer met JavaScript + popup
    $html += @"
        </div>
        <div class="footer">
            <p>Total checks performed: $totalChecks | Total issues found: $totalIssues</p>
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

        // Toggle collapse van check sections
        function toggleCheck(checkId) {
            const checkElement = document.getElementById(checkId).parentElement;
            checkElement.classList.toggle('collapsed');
        }

        // Open modal
        function showModal(modalId) {
            const modal = document.getElementById(modalId);
            modal.classList.add('show');
        }

        // Sluit modal
        function closeModal(modalId) {
            const modal = document.getElementById(modalId);
            modal.classList.remove('show');
        }

        // Sluit modal met ESC toets
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                document.querySelectorAll('.modal.show').forEach(modal => {
                    modal.classList.remove('show');
                });
            }
        });

        // Collapse all functionaliteit
        function collapseAll() {
            document.querySelectorAll('.check').forEach(check => {
                check.classList.add('collapsed');
            });
        }

        // Expand all functionaliteit
        function expandAll() {
            document.querySelectorAll('.check').forEach(check => {
                check.classList.remove('collapsed');
            });
        }
    </script>
</body>
</html>
"@

    # Zorgt dat de Reports directory bestaat
    $reportDir = Split-Path $OutputPath -Parent
    if ($reportDir -and -not (Test-Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    }

    # Schrijf naar bestand
    $html | Out-File -FilePath $OutputPath -Encoding UTF8

    Write-Host "`nHTML report successfully generated!" -ForegroundColor Green
    Write-Host "Location: $OutputPath" -ForegroundColor Cyan
}
