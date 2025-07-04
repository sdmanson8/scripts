$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
Invoke-WebRequest -URI "https://homeupdater.patchmypc.com/public/PatchMyPC-HomeUpdater.msi?_gl=1*1gxmdjs*_gcl_au*MTg3OTQ2MTQ2Ny4xNzM1MDM1MjQ5" -OutFile $downloads\PatchMyPC.msi -UseBasicParsing
& $downloads\PatchMyPC.msi
