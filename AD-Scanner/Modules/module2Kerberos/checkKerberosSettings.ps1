# deze file zal kerberos gerelateerde instellingen controleren


# Zoek alle service accounts in de AD
function Get-ServiceAccounts {
    $serviceAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName
    return $serviceAccounts
}

# #1 encyrptie controleren op service accounts