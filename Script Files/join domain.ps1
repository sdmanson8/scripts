    Clear-Host
    Write-Host Join PC to Domain

    # Edit domain name and credentials
    add-computer –domainname "example.com" -Credential example\username -restart –force
