$AppList = "Microsoft.3DBuilder",
           "Microsoft.Appconnector",
           "Microsoft.BingFinance",
           "Microsoft.BingNews",
           "Microsoft.BingSports",
           "Microsoft.BingTranslator",
           "Microsoft.BingWeather",
           "Microsoft.FreshPaint",
           "Microsoft.DesktopAppInstaller",
           "Microsoft.Getstarted",
           "Microsoft.GetHelp",
           "Microsoft.Messaging",
           "Microsoft.Microsoft3DViewer",
           "Microsoft.MicrosoftOfficeHub",
           "Microsoft.MicrosoftPowerBIForWindows",
           "Microsoft.MicrosoftSolitaireCollection",
           "Microsoft.MicrosoftStickyNotes",
           "Microsoft.MinecraftUWP",
           "Microsoft.NetworkSpeedTest",
           "Microsoft.WindowsPhone",
           "Microsoft.CommsPhone",
           "Microsoft.ConnectivityStore",
           "Microsoft.Office.Sway",
           "Microsoft.BingFoodAndDrink",
           "Microsoft.BingTravel",
           "Microsoft.BingHealthAndFitness",
           "9E2F88E3.Twitter",
           "PandoraMediaInc.29680B314EFC2",
           "Flipboard.Flipboard",
           "ShazamEntertainmentLtd.Shazam",
           "king.com.CandyCrushSaga",
           "king.com.CandyCrushSodaSaga",
           "king.com.",
           "ClearChannelRadioDigital.iHeartRadio",
           "4DF9E0F8.Netflix",
           "6Wunderkinder.Wunderlist",
           "Drawboard.DrawboardPDF",
           "22StokedOnIt.NotebookPro",
           "2FE3CB00.PicsArt-PhotoStudio",
           "41038Axilesoft.ACGMediaPlayer",
           "5CB722CC.SeekersNotesMysteriesofDarkwood",
           "7458BE2C.WorldofTanksBlitz",
           "D52A8D61.FarmVille2CountryEscape",
           "TuneIn.TuneInRadio",
           "GAMELOFTSA.Asphalt8Airborne",
           "TheNewYorkTimes.NYTCrossword",
           "DB6EA5DB.CyberLinkMediaSuiteEssentials",
           "Facebook.Facebook",
           "flaregamesGmbH.RoyalRevolt2",
           "Playtika.CaesarsSlotsFreeCasino",
           "A278AB0D.MarchofEmpires",
           "KeeperSecurityInc.Keeper",
           "ThumbmunkeysLtd.PhototasticCollage",
           "INGAG.XING",
           "89006A2E.AutodeskSketchBook",
           "D5EA27B7.Duolingo-LearnLanguagesforFree",
           "46928bounde.EclipseManager",
           "ActiproSoftwareLLC.562882FEEB49",
           "DolbyLaboratories.DolbyAccess",
           "SpotifyAB.SpotifyMusic",
           "A278AB0D.DisneyMagicKingdoms",
           "WinZipComputing.WinZipUniversal",
           "Microsoft.MSPaint",
           "Microsoft.Office.OneNote",
           "Microsoft.OneConnect",
           "Microsoft.People",
           "Microsoft.Print3D",
           "Microsoft.SkypeApp",
           "Microsoft.Wallet",
           "Microsoft.Windows.Photos",
           "Microsoft.WindowsAlarms",
           "Microsoft.WindowsCamera",
           "Microsoft.windowscommunicationsapps",
           "Microsoft.WindowsFeedbackHub",
           "Microsoft.WindowsMaps",
           "Microsoft.WindowsSoundRecorder",
           "Microsoft.XboxApp",
           "Microsoft.Xbox.TCUI",
           "Microsoft.ZuneMusic",
           "Microsoft.ZuneVideo",
           "828B5831.HiddenCityMysteryofShadows",
           "king.com.BubbleWitch3Saga",
           "Fitbit.FitbitCoach",
           "Facebook.InstagramBeta",
           "Facebook.317180B0BB486",
           "Expedia.ExpediaHotelsFlightsCarsActivities",
           "CAF9E577.Plex",
           "AdobeSystemsIncorporated.PhotoshopElements2018",
           "A278AB0D.DragonManiaLegends",
           "A278AB0D.AsphaltStreetStormRacing",
           "828B5831.TheSecretSociety-HiddenMystery",
           "USATODAY.USATODAY",
           "SiliconBendersLLC.Sketchable",
           "Nordcurrent.CookingFever",
           "NAVER.LINEwin8",
           "microsoft.microsoftskydrive",
           "Microsoft.AgeCastles",
           "Microsoft.ScreenSketch",
           "Microsoft.YourPhone",
           "Microsoft.WebMediaExtensions",
           "Microsoft.MixedReality.Portal"
ForEach ($App in $AppList)
{
 $PackageFullName = (Get-AppxPackage $App).PackageFullName
 $ProPackageFullName = (Get-AppxProvisionedPackage -online | where {$_.Displayname -eq $App}).PackageName
 write-host $PackageFullName
 Write-Host $ProPackageFullName
 if ($PackageFullName)
 	{
 	Write-Host "Removing Package: $App"
 	Remove-AppxPackage -package $PackageFullName
	 }
 	else
	 {
 	Write-Host "Unable to find package: $App"
	 }
 	if ($ProPackageFullName)
 	{
	 Write-Host "Removing Provisioned Package: $ProPackageFullName"
	 Remove-AppxProvisionedPackage -online -packagename $ProPackageFullName
 	}
	 else
 	{
	 Write-Host "Unable to find provisioned package: $App"
	 }
 }
