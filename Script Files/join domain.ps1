    Clear-Host
    Write-Host Joining PC to Domain

    # Edit domain name and credentials
    
$hostname = 'hostname'  ## put New Hostname here
$Domain = 'domain.com' ## put domain name here
$Credential = Get-Credential

Rename-Computer $hostname
Add-Computer -Domain $Domain -NewName $hostname -Credential $Credential -Restart -Force
