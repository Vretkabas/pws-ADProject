<#
.SYNOPSIS
    Test runner script for AD Scanner Pester tests

.DESCRIPTION
    Runs all Pester tests with optional code coverage and detailed reporting.

.PARAMETER IncludeIntegration
    Include integration tests that require real AD connection

.PARAMETER CodeCoverage
    Generate code coverage report

.PARAMETER OutputXml
    Generate NUnit XML output for CI/CD integration

.EXAMPLE
    .\RunAllTests.ps1
    Runs all unit tests

.EXAMPLE
    .\RunAllTests.ps1 -IncludeIntegration
    Runs all tests including integration tests

.EXAMPLE
    .\RunAllTests.ps1 -CodeCoverage
    Runs tests with code coverage analysis
#>

[CmdletBinding()]
param(
    [switch]$IncludeIntegration,
    [switch]$CodeCoverage,
    [switch]$OutputXml
)

# Ensure Pester is installed
$pesterModule = Get-Module -Name Pester -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1

if (-not $pesterModule) {
    Write-Host "Pester is not installed. Installing..." -ForegroundColor Yellow
    Install-Module -Name Pester -Force -SkipPublisherCheck -Scope CurrentUser
}
elseif ($pesterModule.Version -lt [version]"5.0.0") {
    Write-Host "Pester version $($pesterModule.Version) found. Version 5.0+ recommended." -ForegroundColor Yellow
    Write-Host "Consider upgrading: Install-Module -Name Pester -Force -SkipPublisherCheck" -ForegroundColor Yellow
}

# Import Pester
Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop

# Configuration
$testPath = $PSScriptRoot
$modulePath = Join-Path (Split-Path $PSScriptRoot -Parent) "Modules"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  AD Scanner Pester Test Suite" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Test Path: $testPath" -ForegroundColor Gray
Write-Host "Module Path: $modulePath" -ForegroundColor Gray

# Build Pester configuration
$config = New-PesterConfiguration

# Set test path - include all test files
$testFiles = Get-ChildItem -Path $testPath -Filter "*.Test.ps1" -Recurse
if ($testFiles.Count -eq 0) {
    Write-Host "No test files found matching pattern *.Test.ps1" -ForegroundColor Red
    exit 1
}

Write-Host "Found $($testFiles.Count) test file(s):" -ForegroundColor Gray
$testFiles | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor Gray }
Write-Host ""

$config.Run.Path = $testFiles.FullName

# Exclude integration tests unless specified
if (-not $IncludeIntegration) {
    $config.Filter.ExcludeTag = "Integration"
    Write-Host "Mode: Unit Tests Only (use -IncludeIntegration to include AD integration tests)" -ForegroundColor Yellow
}
else {
    Write-Host "Mode: Unit + Integration Tests" -ForegroundColor Green

    # Verify AD access
    try {
        Get-ADDomain -ErrorAction Stop | Out-Null
        Write-Host "AD Access: OK" -ForegroundColor Green
    }
    catch {
        Write-Warning "No AD access detected - integration tests may fail"
    }
}

# Code coverage
if ($CodeCoverage) {
    $config.CodeCoverage.Enabled = $true
    $config.CodeCoverage.Path = Get-ChildItem -Path $modulePath -Filter "*.ps1" -Recurse | Select-Object -ExpandProperty FullName
    $config.CodeCoverage.OutputPath = Join-Path $PSScriptRoot "CodeCoverage.xml"
    Write-Host "Code Coverage: Enabled" -ForegroundColor Green
}

# XML output
if ($OutputXml) {
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputPath = Join-Path $PSScriptRoot "TestResults.xml"
    Write-Host "XML Output: TestResults.xml" -ForegroundColor Green
}

# Verbosity
$config.Output.Verbosity = "Detailed"

Write-Host "`nStarting tests...`n" -ForegroundColor Cyan

# Run tests
$testResults = Invoke-Pester -Configuration $config

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Test Results Summary" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

if ($null -eq $testResults) {
    Write-Host "No test results returned" -ForegroundColor Red
    exit 1
}

$totalCount = if ($testResults.TotalCount) { $testResults.TotalCount } else { 0 }
$passedCount = if ($testResults.PassedCount) { $testResults.PassedCount } else { 0 }
$failedCount = if ($testResults.FailedCount) { $testResults.FailedCount } else { 0 }
$skippedCount = if ($testResults.SkippedCount) { $testResults.SkippedCount } else { 0 }

Write-Host "Total Tests:  " -NoNewline -ForegroundColor Gray
Write-Host $totalCount -ForegroundColor White

Write-Host "Passed:       " -NoNewline -ForegroundColor Gray
Write-Host $passedCount -ForegroundColor Green

if ($failedCount -gt 0) {
    Write-Host "Failed:       " -NoNewline -ForegroundColor Gray
    Write-Host $failedCount -ForegroundColor Red
}

if ($skippedCount -gt 0) {
    Write-Host "Skipped:      " -NoNewline -ForegroundColor Gray
    Write-Host $skippedCount -ForegroundColor Yellow
}

if ($testResults.Duration) {
    Write-Host "Duration:     " -NoNewline -ForegroundColor Gray
    Write-Host "$($testResults.Duration.TotalSeconds.ToString('F2')) seconds" -ForegroundColor White
}

# Code coverage summary
if ($CodeCoverage -and $testResults.CodeCoverage) {
    Write-Host "`nCode Coverage:" -ForegroundColor Cyan
    $coverage = $testResults.CodeCoverage
    $coveragePercent = if ($coverage.NumberOfCommandsAnalyzed -gt 0) {
        [math]::Round(($coverage.NumberOfCommandsExecuted / $coverage.NumberOfCommandsAnalyzed) * 100, 2)
    } else { 0 }

    Write-Host "  Commands Analyzed: $($coverage.NumberOfCommandsAnalyzed)" -ForegroundColor Gray
    Write-Host "  Commands Executed: $($coverage.NumberOfCommandsExecuted)" -ForegroundColor Gray
    Write-Host "  Coverage:          " -NoNewline -ForegroundColor Gray

    $color = if ($coveragePercent -ge 80) { "Green" } elseif ($coveragePercent -ge 60) { "Yellow" } else { "Red" }
    Write-Host "$coveragePercent%" -ForegroundColor $color

    if ($coverage.MissedCommands.Count -gt 0) {
        Write-Host "`n  Top 5 files with missed coverage:" -ForegroundColor Yellow
        $coverage.MissedCommands |
            Group-Object File |
            Sort-Object Count -Descending |
            Select-Object -First 5 |
            ForEach-Object {
                $fileName = Split-Path $_.Name -Leaf
                Write-Host "    $fileName : $($_.Count) commands missed" -ForegroundColor Gray
            }
    }
}

Write-Host "`n========================================`n" -ForegroundColor Cyan

# Exit with error code if tests failed
if ($failedCount -gt 0) {
    Write-Host "TESTS FAILED - Please review failures above" -ForegroundColor Red
    exit 1
}
else {
    Write-Host "ALL TESTS PASSED" -ForegroundColor Green
    exit 0
}
