ConvertFrom-StringData -StringData @'
UnsupportedOSBuild                        = El script es compatible con Windows 11 23H2+.
UpdateWarning                             = Su build de Windows 11: {0}.{1}. Compilaciones compatibles: {2}+. Ejecute Windows Update y vuelva a intentarlo.
UnsupportedLanguageMode                   = Sesión de PowerShell ejecutada en modo de lenguaje limitado.
LoggedInUserNotAdmin                      = El usuario que inició sesión no tiene derechos de administrador.
UnsupportedPowerShell                     = Estás intentando ejecutar el script a través de PowerShell {0}.{1}. Ejecute el script en la versión apropiada de PowerShell.
UnsupportedHost                           = El script no es compatible con la ejecución a través de {0}.
Win10TweakerWarning                       = Probablemente su sistema operativo fue infectado a través del backdoor Win 10 Tweaker.
TweakerWarning                            = La estabilidad del sistema operativo Windows puede haberse visto comprometida al utilizar el {0}. Reinstale Windows utilizando sólo una imagen ISO original.\nhttps://www.microsoft.com/software-download/windows11
Bin                                       = No hay archivos en la carpeta bin. Por favor, vuelva a descargar el archivo.
RebootPending                             = El PC está esperando a ser reiniciado.
UnsupportedRelease                        = Una nueva versión encontrada.
KeyboardArrows                            = Utilice las flechas {0} y {1} de su teclado para seleccionar la respuesta
CustomizationWarning                      = ¿Ha personalizado todas las funciones del archivo predeterminado {0} antes de ejecutar Sophia Script?
WindowsComponentBroken                    = {0} dañado o eliminado del sistema operativo.
UpdateDefender                            = Las definiciones de Microsoft Defender no están actualizadas. Ejecute Windows Update y vuelva a intentarlo.
ControlledFolderAccessDisabled            = Acceso a la carpeta controlada deshabilitado.
InitialActionsCheckFailed                 = La función "InitialActions" no se puede cargar desde el archivo de preajuste {0}.
ScheduledTasks                            = Tareas programadas
OneDriveUninstalling                      = Desinstalar OneDrive...
OneDriveInstalling                        = Instalación de OneDrive...
OneDriveDownloading                       = Descargando OneDrive...
OneDriveWarning                           = La función "{0}" se aplicará sólo si el preajuste está configurado para eliminar OneDrive (o la aplicación ya fue eliminada), de lo contrario la funcionalidad de copia de seguridad para las carpetas "Escritorio" e "Imágenes" en OneDrive se rompe.
WindowsFeaturesTitle                      = Características de Windows
OptionalFeaturesTitle                     = Características opcionales
EnableHardwareVT                          = Habilitar la virtualización en UEFI.
UserShellFolderNotEmpty                   = Algunos archivos quedan en la carpeta "{0}". Moverlos manualmente a una nueva ubicación.
UserFolderLocationMove                    = No deberías cambiar la ubicación de la carpeta de usuario a la raíz de la unidad C.
RetrievingDrivesList                      = Recuperando lista de unidades...
DriveSelect                               = Seleccione la unidad dentro de la raíz de la cual se creó la carpeta "{0}".
CurrentUserFolderLocation                 = La ubicación actual de la carpeta "{0}": "{1}".
UserFolderRequest                         = ¿Le gustaría cambiar la ubicación de la "{0}" carpeta?
UserDefaultFolder                         = ¿Le gustaría cambiar la ubicación de la carpeta "{0}" para el valor por defecto?
ReservedStorageIsInUse                    = Esta operación no es compatible cuando el almacenamiento reservada está en uso\nPor favor, vuelva a ejecutar la función "{0}" después de reiniciar el PC.
ShortcutPinning                           = El acceso directo "{0}" está siendo clavado en Start...
SSDRequired                               = Para utilizar Windows Subsystem for Android™ en su dispositivo, su PC debe tener instalada una unidad de estado sólido (SSD).
UninstallUWPForAll                        = Para todos los usuarios
UWPAppsTitle                              = Aplicaciones UWP
GraphicsPerformanceTitle                  = ¿Le gustaría establecer la configuración de rendimiento gráfico de una aplicación de su elección a "alto rendimiento"?
ActionCenter                              = Um die Funktion "{0}" nutzen zu können, müssen Sie das Action Center aktivieren.
WindowsScriptHost                         = Acceso a Windows Script Host deshabilitado en este equipo. Um die Funktion "{0}" nutzen zu können, müssen Sie den Windows Script Host aktivieren.
ScheduledTaskPresented                    = La función "{0}" ya fue creada como "{1}".
CleanupTaskNotificationTitle              = Limpieza de Windows
CleanupTaskNotificationEvent              = ¿Ejecutar la tarea de limpiar los archivos no utilizados y actualizaciones de Windows?
CleanupTaskDescription                    = La limpieza de Windows los archivos no utilizados y actualizaciones utilizando una función de aplicación de limpieza de discos.
CleanupNotificationTaskDescription        = Pop-up recordatorio de notificaciones sobre la limpieza de archivos no utilizados de Windows y actualizaciones.
SoftwareDistributionTaskNotificationEvent = La caché de actualización de Windows eliminado correctamente.
TempTaskNotificationEvent                 = Los archivos de la carpeta Temp limpiados con éxito.
FolderTaskDescription                     = La limpieza de la carpeta "{0}".
EventViewerCustomViewName                 = Creación de proceso
EventViewerCustomViewDescription          = Eventos de auditoría de línea de comandos y creación de procesos.
RestartWarning                            = Asegúrese de reiniciar su PC.
ErrorsLine                                = Línea
ErrorsMessage                             = Errores/Advertencias
DialogBoxOpening                          = Viendo el cuadro de diálogo...
Disable                                   = Desactivar
Enable                                    = Habilitar
AllFilesFilter                            = Todos los Archivos
FolderSelect                              = Seleccione una carpeta
FilesWontBeMoved                          = Los archivos no se transferirán.
Install                                   = Instalar
NoData                                    = Nada que mostrar.
RestartFunction                           = Por favor, reinicie la función "{0}".
NoResponse                                = No se pudo establecer una conexión con {0}.
Restore                                   = Restaurar
Run                                       = Iniciar
Skipped                                   = Función "{0}" omitida.
GPOUpdate                                 = Actualización de GPO...
TelegramGroupTitle                        = Únete a nuestro grupo oficial de Telegram.
TelegramChannelTitle                      = Únete a nuestro canal oficial de Telegram.
DiscordChannelTitle                       = Únete a nuestro canal oficial de Discord.
Uninstall                                 = Desinstalar
'@

# SIG # Begin signature block
# MIIbrQYJKoZIhvcNAQcCoIIbnjCCG5oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBzcdlRycC2f4gW
# c3+HQReqOlbfAqhC+SIWR0/LBBk2QqCCFgMwggL8MIIB5KADAgECAhBFDx8e2txW
# r0C9Cp8ZKhRTMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNVBAMMC1RlYW0gU29waGlh
# MB4XDTI0MTEyODExNTU1MloXDTI2MTEyODEyMDU1MFowFjEUMBIGA1UEAwwLVGVh
# bSBTb3BoaWEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6Hwl+UALX
# w8CtVZZSc9DRB6T0HMCy+knzr3kGeAf2HijH/gCH2cQWpqiBjxNWabcRbYBwwoGK
# saGesiidoLXwWavZHx/tMZ7XbZxoV3C1Xb2miG3lHLqTryJQEtV8sMwtNuVhcrya
# VyLMbclG19HOMMcQ3ADrF1OEG9f16hJ/YPGTSBBb6pL/kAWP6KITmuXU+tylml+E
# uYaNCZRBXbFIvT6cOTRKTUadRbM1QdpYBTx3LgkeQ67DO1tT8Nm8egB2ljW8Lbix
# mXHDDS2de4aARzksEYdpfpbXQpYsVs1o1gcXUs3/MKSKSzkxXho4pil0+eDNIImn
# c0uRtc5KnKnVAgMBAAGjRjBEMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggr
# BgEFBQcDAzAdBgNVHQ4EFgQUD69SpSVFP5am4c21foB5/iYrRoMwDQYJKoZIhvcN
# AQELBQADggEBAD3nnS9xzUe3Y3WcphwEbXlR9prQNqlBybyjaY6n8JfU/QhkCK1h
# S5YQgPi3CvosE9jrqVE9tsbQEPT3qyloZYDp3fFlJD8D7P2OfMQ61kTGT8XbfZ+x
# 1p5VD39vNCr64DK/izISI3LRv3tHv5TIc4Ou0v8ucNtT0fed+NrDDlEHLRiMTjhn
# LA9qamVvOYswGUSyxx6vk9kk32F7GsF97Dc+/PKYUBhFiu/fXrivDdQ3X+vbKYRv
# 0xAlWd4OAduTZqvO5pDnS6vEX579OC4ZitLVR74F31foyt03DxOcjLCNEtE4KyHR
# v348h9jkafC5Z0lwvYKIRXyQ5D+A1PEA0vgwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggauMIIElqADAgECAhAHNje3JFR82Ees/ShmKl5bMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMy
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGhjUGSbPBPXJJUVXH
# JQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6ffOciQt/nR+eDzMf
# UBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/qxkrPkLcZ47qUT3w
# 1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL6IRk
# tFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYb
# qMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcplicu9Yemj052FVUm
# cJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+onP6
# 5x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZGs506o9UD4L/wojzK
# QtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo
# 80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjB
# Jgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJASgADoRU7s7pXche
# MBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB
# /wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8wHwYDVR0jBBgwFoAU
# 7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDig
# NqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZI
# hvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd
# 4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfNthKWb8RQTGIdDAiC
# qBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl
# /Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw1YpxdmXazPByoyP6wCeC
# RK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/umnXKvxMfBwWpx2cYT
# gAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/
# a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhzq6YBT70/O3itTK37
# xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11LB4nLCbbbxV7HhmL
# NriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCYoCvtlUG3OtUVmDG0
# YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJ
# RyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8MIIG
# vDCCBKSgAwIBAgIQC65mvFq6f5WHxvnpBOMzBDANBgkqhkiG9w0BAQsFADBjMQsw
# CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRp
# Z2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENB
# MB4XDTI0MDkyNjAwMDAwMFoXDTM1MTEyNTIzNTk1OVowQjELMAkGA1UEBhMCVVMx
# ETAPBgNVBAoTCERpZ2lDZXJ0MSAwHgYDVQQDExdEaWdpQ2VydCBUaW1lc3RhbXAg
# MjAyNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL5qc5/2lSGrljC6
# W23mWaO16P2RHxjEiDtqmeOlwf0KMCBDEr4IxHRGd7+L660x5XltSVhhK64zi9Ce
# C9B6lUdXM0s71EOcRe8+CEJp+3R2O8oo76EO7o5tLuslxdr9Qq82aKcpA9O//X6Q
# E+AcaU/byaCagLD/GLoUb35SfWHh43rOH3bpLEx7pZ7avVnpUVmPvkxT8c2a2yC0
# WMp8hMu60tZR0ChaV76Nhnj37DEYTX9ReNZ8hIOYe4jl7/r419CvEYVIrH6sN00y
# x49boUuumF9i2T8UuKGn9966fR5X6kgXj3o5WHhHVO+NBikDO0mlUh902wS/Eeh8
# F/UFaRp1z5SnROHwSJ+QQRZ1fisD8UTVDSupWJNstVkiqLq+ISTdEjJKGjVfIcsg
# A4l9cbk8Smlzddh4EfvFrpVNnes4c16Jidj5XiPVdsn5n10jxmGpxoMc6iPkoaDh
# i6JjHd5ibfdp5uzIXp4P0wXkgNs+CO/CacBqU0R4k+8h6gYldp4FCMgrXdKWfM4N
# 0u25OEAuEa3JyidxW48jwBqIJqImd93NRxvd1aepSeNeREXAu2xUDEW8aqzFQDYm
# r9ZONuc2MhTMizchNULpUEoA6Vva7b1XCB+1rxvbKmLqfY/M/SdV6mwWTyeVy5Z/
# JkvMFpnQy5wR14GJcv6dQ4aEKOX5AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMC
# B4AwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAE
# GTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3Mp
# dpovdYxqII+eyG8wHQYDVR0OBBYEFJ9XLAN3DigVkGalY17uT5IfdqBbMFoGA1Ud
# HwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUF
# BwEBBIGDMIGAMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20w
# WAYIKwYBBQUHMAKGTGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZI
# hvcNAQELBQADggIBAD2tHh92mVvjOIQSR9lDkfYR25tOCB3RKE/P09x7gUsmXqt4
# 0ouRl3lj+8QioVYq3igpwrPvBmZdrlWBb0HvqT00nFSXgmUrDKNSQqGTdpjHsPy+
# LaalTW0qVjvUBhcHzBMutB6HzeledbDCzFzUy34VarPnvIWrqVogK0qM8gJhh/+q
# DEAIdO/KkYesLyTVOoJ4eTq7gj9UFAL1UruJKlTnCVaM2UeUUW/8z3fvjxhN6hdT
# 98Vr2FYlCS7Mbb4Hv5swO+aAXxWUm3WpByXtgVQxiBlTVYzqfLDbe9PpBKDBfk+r
# abTFDZXoUke7zPgtd7/fvWTlCs30VAGEsshJmLbJ6ZbQ/xll/HjO9JbNVekBv2Tg
# em+mLptR7yIrpaidRJXrI+UzB6vAlk/8a1u7cIqV0yef4uaZFORNekUgQHTqddms
# PCEIYQP7xGxZBIhdmm4bhYsVA6G2WgNFYagLDBzpmk9104WQzYuVNsxyoVLObhx3
# RugaEGru+SojW4dHPoWrUhftNpFC5H7QEY7MhKRyrBe7ucykW7eaCuWBsBb4HOKR
# FVDcrZgdwaSIqMDiCLg4D+TPVgKx2EgEdeoHNHT9l3ZDBD+XgbF+23/zBjeCtxz+
# dL/9NWR6P2eZRi7zcEO1xwcdcqJsyz/JceENc2Sg8h3KeFUCS7tpFk7CrDqkMYIF
# ADCCBPwCAQEwKjAWMRQwEgYDVQQDDAtUZWFtIFNvcGhpYQIQRQ8fHtrcVq9AvQqf
# GSoUUzANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAA
# MBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgor
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDUisWImSZhQSoDmAqEsdkqVyoNP+wi
# ENphA/kt91uVNDANBgkqhkiG9w0BAQEFAASCAQB/pNIdL3yWOOEANUppqtpdXYd7
# yo/V4wGryEI8eybfuwNfNW74wj/Xq7exo5Y7iFcQsLTFkBNNrRC0hYJ0mhPG0e6/
# AQPJpXNuWTNvaqeQebVc/0NfqPsFcF6PJjAk/JN4t1ddFTctz3ny7lI7NKFn3qJa
# IlOf1cAPF7ojQMMSu4NxJstrdF0njJKHPbCUhm6TyxZJ6m3LF+gxBwdRFN0rPsGB
# FH1r2bCC/4VbefYGrkqoRtk0kvb066tY296VgpipWt6p4Y/mZZu8uxD0vKkNh9SL
# Q+8e1ihvkyZa3mfJ+ZAdmsLe3Uwd3IXDinIKRZW3bg3WPaUhGF82fPGowgqgoYID
# IDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVk
# IEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQC65mvFq6f5WHxvnp
# BOMzBDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEw
# HAYJKoZIhvcNAQkFMQ8XDTI0MTEyODEyMDYwMVowLwYJKoZIhvcNAQkEMSIEIBSy
# 1RvyN/FGju0GOooNv+2EIFTlS6Y2iZaFk+LsEe4kMA0GCSqGSIb3DQEBAQUABIIC
# AB26U65CgT6pqTmUkdD/MHFr6gHBPCzkMCz89SCp206PknyEE3uRNtGra66vtoZ+
# Rlmwtz21VyHYQBpFZUkBNmHqm+XA9K1GN7QzbvngkWNR2CPe1ZoUJUGbss81gviw
# 6CcD3A3791+dOoQkXumpXTf+2cbQ/PZUThptIJeYlmlwi4CUl4Qy/MEdCjBSk/jV
# tmkCa+/53rOxV+YBDm6LWFmwYPMki+xtt/OIMI4MjeTYC6eGlU7nHAk+u2K8kweO
# JMMY8EB/ZnJ8Im+3GQxPTfPTei0XcwcMtrDXTiYx2Z/cD82pRXNvzmq9UXH0WHlg
# q4dGmMUILqNvQlBK5kHUGpwg6HqMoftV849YTHQidpD/dj/BMWkcE3KZ2f0mWGUL
# cOu7Y47rx7jqSAqmhpFXuZ1ZCbiaBYEJ0ED30D8YLNVtC6KIur831A4hL4GPoeKq
# FcSP6OueNi36iFEutPu7DazBQI4o2jbDpv69xYJ74T0Fdwf7Z4tpsm8EyZP25UlZ
# REjS0W4LpFRpLaizJnCA9s7JoWo5XmHR3SxXL4k9dM0DtiixvoNmV8sxqMdqOHZI
# aFlAZSd7q3/+W5aaYrT6rV0h+FZ+XXR570FrvIRsyXj6BmaCRSjkjMc/YvWSh/lM
# ljBGU9FjdLryVhQQBCdAdUzZ8X0wb3SVevluuZ4IDULI
# SIG # End signature block
