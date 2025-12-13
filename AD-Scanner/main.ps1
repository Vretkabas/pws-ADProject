# ============================================
# AD Security Scanner - Master Script
# ============================================
# Dit script verzamelt resultaten van alle modules en genereert een HTML rapport.

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("All", "1", "2", "3", "4")]
    [string[]]$Modules = @("All"),

    [switch]$SkipHTML,

    [switch]$Force  # force om controle checks over te slaan
)

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   AD Security Scanner - Starting Analysis" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "Scan started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host ""

# Voer prerequisite checks uit (tenzij -Force is gebruikt)
if (-not $Force) {
    . "$PSScriptRoot\Modules\Checks.ps1"
    $checksPass = Test-Prerequisites -StopOnFailure:$false

    if (-not $checksPass) {
        Write-Host "`nKritieke prerequisite checks gefaald." -ForegroundColor Red
        Write-Host "De scan kan niet worden uitgevoerd." -ForegroundColor Red
        Write-Host "`nOpties:" -ForegroundColor Yellow
        Write-Host "  1. Los de bovenstaande problemen op en probeer opnieuw" -ForegroundColor Gray
        Write-Host "  2. Gebruik -Force om de checks te negeren (NIET AANBEVOLEN)" -ForegroundColor Gray
        Write-Host ""
        exit 1
    }
} else {
    Write-Host "WARNING: Prerequisite checks worden overgeslagen (-Force gebruikt)" -ForegroundColor Yellow
    Write-Host "De resultaten kunnen onbetrouwbaar zijn!`n" -ForegroundColor Yellow
}

# Bepaal welke modules te runnen
$runAll = $Modules -contains "All"

# Import de HTML export functie
. "$PSScriptRoot\exportHTMLOutput.ps1"

# Verzamel resultaten van alle modules
$allModuleResults = [ordered]@{}

# Module 1: Dangerous Accounts
if (($runAll -or $Modules -contains "1") -and (Test-Path "$PSScriptRoot\Modules\module1dangerousAccounts\main.ps1")) {
    Write-Host "`nRunning Module 1: Dangerous Accounts..." -ForegroundColor Yellow
    $module1Results = & "$PSScriptRoot\Modules\module1dangerousAccounts\main.ps1"
    $allModuleResults["Module 1 - Dangerous Accounts"] = $module1Results
}

Write-Host "`n==================================================" -ForegroundColor Cyan
Write-Host "   All modules completed - Generating report..." -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# Genereer het complete HTML rapport (tenzij -SkipHTML is opgegeven)
if (-not $SkipHTML) {
    $reportPath = "Reports\AD-Security-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    Export-ToHTML -Results $allModuleResults -OutputPath $reportPath

    Write-Host "`nReport generated: $reportPath" -ForegroundColor Green
} else {
    Write-Host "`nHTML report skipped (use -SkipHTML:$false to generate)" -ForegroundColor Yellow
}

Write-Host "Scan completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray