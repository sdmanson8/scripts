Invoke-WebRequest -URI https://patchmypc.com/freeupdater/PatchMyPC.exe -OutFile $env:SystemDrive\PatchMyPC.exe
& $env:SystemDrive\PatchMyPC.exe