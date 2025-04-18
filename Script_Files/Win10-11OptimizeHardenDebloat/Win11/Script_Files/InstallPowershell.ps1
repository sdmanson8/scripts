Function CheckPowershellVersion {
    if (-Not (Get-Command pwsh -ErrorAction SilentlyContinue)) {
        try {
            # Define the URL for downloading the PowerShell 7 installation script
            $installScriptUrl = "https://aka.ms/install-powershell.ps1"
            
            # Specify a temporary path to save the installation script
            $tempScriptPath = Join-Path $env:TEMP "InstallPowershell.ps1"
            
            # Display progress for downloading the script
            Write-Progress -Activity "Downloading PowerShell 7 Installation Script" -Status "Initializing..." -PercentComplete 0

            # Simulate progress while downloading
            for ($i = 10; $i -le 100; $i += 10) {
                Start-Sleep -Milliseconds 200
                Write-Progress -Activity "Downloading PowerShell 7 Installation Script" -Status "$i% Complete" -PercentComplete $i
            }

            # Download the installation script to the temporary location
            Invoke-RestMethod -Uri $installScriptUrl -OutFile $tempScriptPath -ErrorAction Stop
            
            # Clear the progress bar
            Write-Progress -Activity "Downloading PowerShell 7 Installation Script" -Completed

            # Display progress for installing PowerShell 7
            Write-Progress -Activity "Installing PowerShell 7" -Status "Installing..." -PercentComplete 0

            # Simulate progress during installation
            for ($i = 20; $i -le 100; $i += 20) {
                Start-Sleep -Milliseconds 300
                Write-Progress -Activity "Installing PowerShell 7" -Status "$i% Complete" -PercentComplete $i
            }

            # Execute the installation script
            & $tempScriptPath -UseMSI

            # Clear the progress bar
            Write-Progress -Activity "Installing PowerShell 7" -Completed

            # Remove the temporary installation script after installation
            Remove-Item -Path $tempScriptPath -Force
        } catch {
            # Display an error message if installation fails
            Write-Error "Failed to install PowerShell 7: $_"
        }
    }
}