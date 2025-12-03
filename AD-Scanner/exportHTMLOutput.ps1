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
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .summary-card h3 { font-size: 2em; margin-bottom: 5px; }
        .summary-card p { font-size: 0.9em; opacity: 0.9; }

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
"@

    # Tel totaal aantal issues
    $totalIssues = 0
    $totalChecks = 0

    # Loop door alle modules
    foreach ($moduleName in $Results.Keys) {
        $moduleData = $Results[$moduleName]

        $html += "<div class='module'>`n"
        $html += "<h2 class='module-title'>$moduleName</h2>`n"

        # Loop door alle checks binnen de module
        $checkIndex = 0
        foreach ($checkName in $moduleData.Keys) {
            $accounts = $moduleData[$checkName]
            $totalChecks++
            $checkId = "check-$($moduleName -replace '[^a-zA-Z0-9]', '')-$checkIndex"
            $modalId = "modal-$checkId"
            $checkIndex++

            $html += "<div class='check'>`n"
            $html += "<div class='check-header' onclick='toggleCheck(""$checkId"")'>`n"
            $html += "<div class='check-title-left'>`n"
            $html += "<span class='collapse-icon'>▼</span>`n"
            $html += "<span class='check-title-text'>$checkName</span>`n"

            if ($accounts -and $accounts.Count -gt 0) {
                $count = ($accounts | Measure-Object).Count
                $totalIssues += $count
                $badgeClass = if ($count -gt 10) { "badge-danger" } elseif ($count -gt 5) { "badge-warning" } else { "badge-warning" }
                $html += "<span class='badge $badgeClass'>$count found</span>`n"
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

        $html += "</div>`n"
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
