
Write-Host Joining PC to Domain

# Edit domain name and credentials
    
$hostname = Read-Host "Enter your New Computer Name WITHOUT "" "" ..."
$Domain = Read-Host "Enter your domain name WITHOUT "" "" ..."
$Credential = Get-Credential

Rename-Computer $hostname
Add-Computer -Domain $Domain -NewName $hostname -Credential $Credential -Restart -Force
