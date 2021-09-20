# Windows Tweaks

Run "Set-ExecutionPolicy Unrestricted" if you get an error

Depending on the options selected you might require editing the script which will automatically download and open on your system

Requires Powershell 5.0 and later in an elavated Powershell Window
        
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Script.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)


Preview of Script Menu

![image](https://user-images.githubusercontent.com/90516190/133616494-4aebb632-bf58-4e71-b72c-2c1c7d38208d.png)

