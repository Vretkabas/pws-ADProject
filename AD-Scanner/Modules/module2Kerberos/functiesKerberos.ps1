# File functies voor Kerberos module

#helper functie
# function Show-AccountResults {
#     param(
#         [Object[]]$Accounts,
#         [string]$MessageFound,
#         [string]$MessageNotFound
#     )

#     if ($Accounts) {
#         $count = ($Accounts | Measure-Object).Count
#         Write-Host "$count $MessageFound" -ForegroundColor Yellow
#     } else {
#         Write-Host $MessageNotFound -ForegroundColor Green
#     }
# }