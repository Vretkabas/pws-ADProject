# deze script verzamelt alle gegevens dat we nodig hebben in module 2
. "$PSScriptRoot\SPNAudit.ps1"


$encryptionSettingsSPN = Get-EncryptionType -servicePrincipalName $(Get-ServiceAccounts)

# $encryptionSettingsSPN
# #1 verzamel encrryption type
$module2Results = @{
    "Weak Encryption (DES or RC4 without AES)" = $encryptionSettingsSPN | Where-Object { $_.HasWeakEncryption -eq $true } | Select-Object SamAccountName
    "DES Encryption (Critical)" = $encryptionSettingsSPN | Where-Object { $_.HasDES -eq $true } | Select-Object SamAccountName
    "RC4 Only (No AES)" = $encryptionSettingsSPN | Where-Object { $_.HasRC4Only -eq $true } | Select-Object SamAccountName
    "AES Only (Best Practice)" = $encryptionSettingsSPN | Where-Object { $_.HasAESOnly -eq $true } | Select-Object SamAccountName
    "AES with RC4 (Acceptable)" = $encryptionSettingsSPN | Where-Object { $_.HasAES -eq $true -and $_.HasRC4 -eq $true -and $_.HasDES -eq $false } | Select-Object SamAccountName
}

$module2Results