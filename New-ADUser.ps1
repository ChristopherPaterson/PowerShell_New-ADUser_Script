Import-Module ActiveDirectory
$Users = Import-Csv -Delimiter "," -Path 'C:\Support\New-ADUsers.csv'
foreach ($User in $Users)
{
    ## Update $OU Varialbe with OU distinguishedName  ##

    $OU = 'OU=Melbourne,OU=JBA Users,DC=jbasyd,DC=int'
    $Proxy1 = $User.ProxyAddress1
    $Proxy2 = $user.ProxyAddress2
    $Proxy2 = $user.ProxyAddress3
    $Password = $User.Password

  New-ADUser `
  -Name $User.DisplayName `
  -SamAccountName $User.SamAccountName `
  -UserPrincipalName $User.UserPrincipalName `
  -DisplayName $User.DisplayName `
  -GivenName $User.GivenName `
  -Surname $User.Surname `
  -EmailAddress $User.EmailAddress `
  -Office $User.OfficeName `
  -Description $User.Description `
  -StreetAddress $User.StreetAddress `
  -City $User.City `
  -PostalCode $User.PostalCode `
  -State $User.State `
  -Country $User.Country `
  -Company $User.Company `
  -Title $User.Title `
  -OfficePhone  $User.Phone `
  -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) `
  -Enabled $true `
  -PasswordNeverExpires $true `
  -Path $OU`
  

    ##  Add Proxy Addresses  ##
    
    if ($Proxy1 -ne '') {
        Set-ADUser -Identity $User.SamAccountName -Add @{proxyAddresses=$Proxy1}
        }

    if ($Proxy2 -ne '') {
        Set-ADUser -Identity $User.SamAccountName -Add @{proxyAddresses=$Proxy2}
        }

    if ($Proxy3 -ne '') {
        Set-ADUser -Identity $User.SamAccountName -Add @{proxyAddresses=$Proxy2}
        }
}