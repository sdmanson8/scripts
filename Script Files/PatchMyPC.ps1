Invoke-WebRequest -URI https://patchmypc.com/freeupdater/PatchMyPC.exe -OutFile $env:SystemDrive\PatchMyPC.exe -UseBasicParsing
& $env:SystemDrive\PatchMyPC.exe