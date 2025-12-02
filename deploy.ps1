# deploy.ps1 - to deploy code to remote PC

param(
    [switch]$Run
)

# Vraag IP-adres
# Read-Host "Enter IP adress for remote PC" ==> voor nu zelf ip in code ==> sneller
$ipAddress = '10.0.0.1'
# if (-not $ipAddress) {
#     Write-Error "IP address is required!"
#     exit 1
# }

Write-Host "=== Deploying AD Scanner to $ipAddress ===" -ForegroundColor Cyan

# Lab PC is volledig afgescheiden van internet ==> geef alleen hardcode credentials als dit kan zoals bij mij!!!
# anders ==> $cred = Get-Credential -Message "Login for $ipAddress"
$username = "Administrator"
$password = ConvertTo-SecureString "Lucas1234!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username, $password)
$session = New-PSSession -ComputerName $ipAddress -Credential $cred

if (-not $session) {
    Write-Error "Could not connect to $ipAddress!"
    exit 1
}

Write-Host "Copying files to $ipAddress..." -ForegroundColor Yellow

# Maak eerst de folder structuur aan op de remote PC
Invoke-Command -Session $session -ScriptBlock {
    if (-not (Test-Path "C:\Scanner")) {
        New-Item -Path "C:\Scanner" -ItemType Directory -Force | Out-Null
    }
}

# Kopieer alle files en folders recursief
$scriptRoot = $PSScriptRoot
$foldersToSync = @("AD-Scanner", "Lab-Setup")

foreach ($folderName in $foldersToSync) {
    $sourcePath = Join-Path $scriptRoot $folderName

    if (-not (Test-Path $sourcePath)) {
        Write-Host "Warning: Folder $folderName not found, skipping..." -ForegroundColor Yellow
        continue
    }

    Write-Host "Syncing $folderName..." -ForegroundColor Cyan

    Get-ChildItem $sourcePath -Recurse | ForEach-Object {
        $relativePath = $_.FullName.Substring($scriptRoot.Length).TrimStart('\')

        if ($_.PSIsContainer) {
            # Maak folder aan op remote PC
            Write-Host "  Creating folder $relativePath..." -ForegroundColor Gray
            Invoke-Command -Session $session -ArgumentList $relativePath -ScriptBlock {
                param($folderPath)
                $fullPath = "C:\Scanner\$folderPath"
                if (-not (Test-Path $fullPath)) {
                    New-Item -Path $fullPath -ItemType Directory -Force | Out-Null
                }
            }
        } else {
            # Kopieer file met encoding fix anders worden "" slecht gekopieerd en failt script
            Write-Host "  Copying $relativePath..." -ForegroundColor Gray
            $content = Get-Content $_.FullName -Raw

            Invoke-Command -Session $session -ArgumentList $relativePath, $content -ScriptBlock {
                param($filePath, $fileContent)
                $fullPath = "C:\Scanner\$filePath"

                # Maak parent folder aan als die niet bestaat
                $parentFolder = Split-Path $fullPath -Parent
                if (-not (Test-Path $parentFolder)) {
                    New-Item -Path $parentFolder -ItemType Directory -Force | Out-Null
                }

                $fileContent | Out-File -FilePath $fullPath -Encoding ASCII -Force
            }
        }
    }
}

Write-Host "Files copied successfully!" -ForegroundColor Green

# voor nu niks automatisch runnen alleen deployen
# if ($Run) {
#     Write-Host "Running scanner on PC1..." -ForegroundColor Yellow
#     Invoke-Command -Session $session -ScriptBlock {
#         cd C:\Scanner
#         Get-ChildItem *.ps1
#     }
# }

Remove-PSSession $session
Write-Host "`n=== Deploy complete! ===" -ForegroundColor Green