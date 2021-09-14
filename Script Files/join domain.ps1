    Write-Host Join PC to Domain
    add-computer –domainname "example.com" -Credential example\username -restart –force
