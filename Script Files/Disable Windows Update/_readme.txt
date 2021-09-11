Sledgehammer - Windows 10 update control readme 2.7.2
This script allows fully manual updates with Windows 10 including Home. Windows 10 only!
The script now allows the option of using Windows Update Manager (WuMgr).
Project page:
https://forums.mydigitallife.net/threads/wumt-wrapper-script-controls-windows-update-service.72203/

;tldr Sledgehammer as-is provides manual updating. Use the Configurator in the script
if you want to use the Store. Don't change any settings in lower left of WUMT while running the script.
You don't have to worry about messing with options in WuMgr as they are greyed out while using the script.

The wrapper script causes sfc errors, so if you want to run sfc, uninstall the
script first or read the logs for errors with EOSNotify.exe,
WaaSMedic.exe, WaasMedicSvc.dll, WaaSMedicPS.dll, WaaSAssessment.dll,
UsoClient.exe, SIHClient.exe, MusNotificationUx.exe, MusNotification.exe,
osrss.dll, %ProgramFiles%\rempl, %systemroot%\UpdateAssistant and
%systemroot%\UpdateAssistantV2, and %systemdrive%\Windows10Upgrade
which is normal. This command in the command prompt will show if the above files
are the problem:
findstr /c:"[SR] Cannot" %windir%\logs\cbs\cbs.log|more

"Uninstaller - undo script changes" in start menu or "Uninstaller_undo-all-script-changes.cmd"
in script folder is the only way to completely uninstall the script.

How it works: The script first checks if the OS is older than Windows 10 and if so
it notifies you, then exits. Windows 10 only!
This script disables and locks all "\Microsoft\Windows\WindowsUpdate\" tasks,
disables all "\Microsoft\Windows\LanguageComponentsInstaller\" tasks,
creates a smart Windows Defender Update task "\Microsoft\Sledgehammer\WDU" that updates Windows
Defender every 6 hours if it's running and enabled, and doesn't update it if it's
not running and disabled, saving resources; auto-elevates, uninstalls and removes
the Windows 10 Update Assistant, locks every file in the %programfiles%\rempl* folder,
resets and locks (removes permissions from) and disables these Update Hijackers
(they're renamed if they can't be locked for whatever reason):
EOSNotify.exe
osrss.dll
UsoClient.exe
WaaSMedic.exe
WaasMedicSvc.dll
WaaSMedicPS.dll
WaaSAssessment.dll
MusNotification.exe
MusNotificationUx.exe
SIHClient.exe
makes sure the task "wub_task" is installed that runs wub at boot (to stop updates from turning
updates back on), runs wub.exe and enables and starts the windows update service (wuauserv) if
disabled, then runs the correct version of the Windows Update MiniTool in "auto search for updates"
mode for your OS version's architecture (x86 or x64), then disables and stops wuauserv giving you
full control. No more forced automatic updates or surprise reboots. This was written for Windows 10
Pro and Home, but works with all versions of Windows 10. Don't change any settings in lower left of
WUMT while running the script.

I also included an "Uninstaller_undo-all-script-changes.cmd" that deletes the "\Microsoft\Sledgehammer\WDU" and "\Microsoft\Sledgehammer\wub_task" tasks,
deletes the WDU.cmd file used by WDU task, restores the rempl folder, resets Update Hijacker permissions
to how they were originally, and turns off wub (if enabled) which turns the windows update service on automatic
again, undoing everything done by the script. If you uninstall after having used the installer the
files in the script folder are removed also.

Configurator in script leaves the Update Hijackers disabled, but gives you the option of turning on
the windows update service temporarily to use Store.

Installation:

*Installer:
Run WUMTWrapperScript.exe. Menu shortcuts in the start menu can be optionally not installed. There
is no uninstall in control panel. Only uninstall from the shortcut in the start menu or using
Uninstaller.cmd in the Sledgehammer folder.

*Portable:
Extract the contents of the portable folder to a folder of your choosing or use the scripts in the
link at the top of the page.
Then make a shortcut to the files "WUMTWrapperScript.cmd",
"Uninstaller_undo-all-script-changes.cmd", "_readme.txt", and "Project Page.url".
Now use the script shortcut to run manual Windows Updates.
Use the Configurator in the script to enable using the Store any time.
WUMT is available here: https://forums.mydigitallife.net/threads/64939-Windows-Update-MiniTool
Windows Update Manager (WuMgr) is available here: https://github.com/DavidXanatos/wumgr/releases/
Windows Update Blocker v1.0 is available here: http://sordum.org/files/windows-update-blocker/old/Wub_v1.0.zip
Only use Windows Update Blocker v1.0 with this script, not v1.1.
NSudo 6.1 is available here: https://github.com/M2Team/NSudo/releases/tag/6.1

Frequently Asked Questions (FAQ)
Sledgehammer
Updated 9/28/18

GENERAL (Section A)
INSTALLATION (Section B)
USE (Section C)
ADVANCED (Section D)

-----
GENERAL.
-----

A1.  Isn't WUMT, which the Wrapper Script runs, too old to be effective? It hasn't had an update since 2016.

While it's true that the Windows Update MiniTool (WUMT) itself hasn't been updated recently, it's still a very effective tool for manually selecting which Windows updates to install. And the Wrapper Script is being refined continually to "wrap" WUMT and WuMgr in processes that restrict Microsoft's attempts to force Windows updates in new ways. Additionally, the Wrapper Script now provides the option to use Windows Update Manager (WuMgr), a great replacement that is stable and is currently maintained. https://forums.mydigitallife.net/threads/windows-update-manager.77736/.
-----
A2. When the script runs WUMT or WuMgr, is the native Windows Update Service also able to run in parallel and install something unexpectedly? What keeps the built-in Windows Update from doing its own thing while WUMT is running? When the Wrapper Script starts WUMT, apparently WUMT (a "black box") blocks the regular Windows Update from operating. Is that true, and if so, how does it do that?

Using the script, it doesn't block anything from installing, rather it prevents Windows from checking for updates on its own. While WUMT is running using the script, you can also check for updates in the Settings app, but the Settings app won't check for updates by itself. The script handles that by disabling all update hijacker files, and windows can't update by itself while WUMT or WuMgr is running, the mechanism of which I'm unsure.
-----
A3. How can I be sure that installing the Wrapper Script won't mess up my system? I've read comments that it makes changes that cause errors in the System File Checker (SFC) results.

SFC errors are caused by locking update hijacker files. The included uninstaller undoes script changes and leaves everything like it was before you ever used the script. (Use the "Uninstaller_undo-all-script-changes.cmd" to undo all script changes whether you run the script in the portable folder or install the script into your Windows start menu (it's the "Uninstaller-undo script changes" shortcut in the start menu.))  The wrapper script causes SFC errors because it makes update hijacker files unreadable. The errors go away after uninstalling the script. So if you want to run SFC, uninstall the script first. Or when you read the logs produced by SFC, recognize that there should be errors for osrss.dll, UsoClient.exe, WaaSMedic.exe, WaasMedicSvc.dll, WaasMedicPS.dll, WaaSAssessment.dll, MusNotificationUx.exe, and SIHClient.exe. 
-----
A4. Is the Wrapper Script "peer reviewed"?

Yes. The full script is available for anyone to download, use, modify, or fork. The operation and effects of the script and any changes are discussed on the MDL Forum thread and tested by multiple users. Improvements are incorporated whenever feedback shows a need.
-----
A5. After installing the script, what are the default effects?

The default configuration of the script disables the Windows Update Service and Microsoft “Update Hijackers”. If you choose to (C)ontinue to WUMT to check for updates, the script enables the update service, keeping the update hijackers disabled, then after running and closing WUMT, turns off windows updates. The Configurator will also let you (E)nable the Windows Update service, keeping update hijackers disabled, so you can use the Store. The update service will be disabled when WUMT is closed no matter what you choose in the Configurator. If Windows Defender is enabled, it will update every 6 hours no matter what setting you make. If Windows Defender is disabled, it will not be updated.
The script has never disabled any triggers that force updates; instead, it disables the files the triggers try to run.  Without the script, every time you start Windows Update Service (wuauserv), you’re rolling the dice on a forced update.  WaasMedic(SVC), Update Orchestrator, Remediation Service, and other “Update Hijackers” are ready and waiting for you to enable wuauserv to start unwanted Update downloads and installations. And even if you don’t enable wuauserv, Microsoft will enable it for you!  And then there’s Update Assistant that doesn’t even need wuauserv enabled to force an update.
The purpose of the script is not to stop updates permanently, even though that's possible with the script. The purpose of the script is to allow you to choose to update when updates are available and at a time convenient to you. The script gives you complete control, like it used to be in Windows 7 when you set Windows Updates to check manually. I only want manual update checks. My script is the closest thing I've found to that.
-----
A6. Where is the location of wsusscn.cab downloaded with the script?

It's in the script's "bin/Updates" folder.
-----
INSTALLATION.
-----

B1. Do I need to uninstall the Wrapper Script before installing a new version of it?

Yes, uninstall the previous version before installing a new one.  The Uninstaller gives you the option to disable your network connection before uninstalling the script so that you can be 100 percent certain that Microsoft won’t be updating your computer in between versions.  Or you can run WUB 1.0 and disable the update service right after you uninstall the Wrapper Script you’re currently using (WUB.exe will be deleted from the wrapper script folder if you used the script installer, so make sure you put a copy in a different folder). If you pin WUB to the taskbar from this different folder, it will be instantly available at your mouse click.
-----
B2. Does the same version of the Wrapper Script work for all Windows versions? (I've seen there are specific script versions for different Windows versions in the past.)

As of version 2.5.3, the script only supports Windows 10. Keeping up with previous versions is better handled using other methods since I can't and don't keep up with update hijackers in all versions of Windows.

-----
USE.
-----

C1. Should the settings under Update Service in WUMT be changed while the script is running?

No. If you want to change the WUMT settings manually, you should run WUMT separately after exiting the script.  The script sets WUMT to “Automatically” check for updates.  You need only choose the updates it finds and offers to either hide or install.  If you want to run WUMT independently of the script (for example, if you wish to update offline with wsusscn2.cab https://go.microsoft.com/fwlink/?LinkID=74689), you should select (E)nable Windows Update Service in the Configurator or run WUB.exe manually to enable the update service. You may then use WUMT with other options.  For further information on those options, you can visit the WUMT MDL thread at https://forums.mydigitallife.net/threads/windows-update-minitool.64939/.
-----
C2. What will happen if you do change the option in the lower left corner of WUMT from “Automatic” while running it in the script?  Will that cause the native Windows Update to download and install updates simultaneously with WUMT?

It can cause problems while running WUMT using the script, but only for the current update session. Better to leave all options alone while running the script. And no, it won't cause Windows to install updates on its own.
-----
C3. Does the Windows update service stay disabled after reboot?

Yes. The "wub_task" task created by the script disables the update service at reboot and at logon. However, if you update using WUMT in the script, and the update requires a reboot, you should re-run the script after the reboot, then close the first screen after confirming that it shows the Windows Update Service is disabled and stopped. This action will ensure that all the “Update Hijackers” that force updates stay off.
-----
C4. Will the script keep protecting against new and unexpected Windows updates after the next Feature Update (aka, Windows 10.x, 10.y, 10.z)?

Most of the time yes, but I can't always predict what Microsoft will do. The intention for the script is to keep discovering the new methods that Microsoft deploys to facilitate or force updates and to develop and provide protection against such Microsoft exploits. So always use the latest version of the script. However, script countermeasures can't always be written and incorporated until after feature updates are released. So remember that MS gives you only 30 days (or less) to roll back or uninstall a feature update to the previous version of Windows. Consequently, it's advisable to have regular image backups of your Windows system drive that you can rely on for restoration in worst case scenarios. In addition, the negative effects of some Windows updates aren’t discovered by the community of Windows users until days, or in some case weeks, after deployment by MS. Please consult your favorite websites to monitor feedback and consensus on new updates found to be problems for other users. One such site is AskWoody, where you can find an overall rating of comfort level with current updates (https://www.askwoody.com/ms-defcon-system) and a master list of updates (https://www.askwoody.com/patch-list-master). 
Please note that some updates other than feature updates are also designed by MS to change the behavior of Windows Update, and some of those cannot be uninstalled after installation (another good reason to have an image backup). The Wrapper Script is continually being revised to deal with the existence of those types of updates after MS introduces them.
-----
C5. Why don't updates that are "Hidden" in WUMT stay hidden? Sometimes they show up in available updates again.

The problem of having updates that have been hidden by WUMT or by wushowhide.diagcab suddenly reappear as available is a perplexing issue. It’s suspected that clearing the "Windows\SoftwareDistribution" folder may unhide updates, and also some updates, like KB4023057, periodically have newer revisions, which in effect create a new update, making the hidden update invalid and superseded by the re-release.  At least, using the Wrapper Script with WUMT, you can simply re-hide the updates without concern that they will automatically be installed.
-----
C6. How can I be sure that the Windows Update Service is still disabled after running the script?

You can verify that the update service is off by opening Services (%windir%\system32\services.msc) and scrolling down to Windows Update to see that it is Disabled and not running, and you can run the Wrapper Script at any time just to check the status. Additionally, you can pin Windows Update Blocker (WUB) 1.0 to the taskbar to make it readily available, then when you run it, it should show the update service as disabled. But make sure you copy WUB.exe into a different folder because if you used the installer, then the uninstaller, it deletes all files in the script folder including WUB.exe. If you would like to install an automatic indicator that shows when the Windows Update Service starts and stops, two free alternatives are: 
(1) "ServiceTray" by Core Technologies (https://www.coretechnologies.com/products/ServiceTray/) will show a red icon in the notification area (system tray) when Windows update service is disabled (which should be the normal state of using the script) and alert you when the update service has started again, both with a green icon and a Windows notification. Whenever the status changes, it will create a Windows notification. (To stay visible in the notification area, you need to go to Taskbar settings and check ServiceTray in Select which icons appear on the taskbar. Otherwise, it will be in the hidden group and not be as useful for this monitoring purpose.) After installation, to start ServiceTray with Windows, you can use task scheduler to schedule a task to run with highest privileges at log on of any user. When creating the task, if you just browse to the shortcut on the desktop as the program to run under the Actions tab, Task Scheduler will automatically parse the program to start as "C:\Program Files\ServiceTray\ServiceTray.exe" with argument = "wuauserv" -icon 1. After that, the shortcut is no longer needed. 
(2) A second monitoring program called Windows Service Monitor (http://www.softpedia.com/get/System/System-Miscellaneous/Windows-Service-Monitor.shtml) is similar to ServiceTray.  Although it doesn't give notifications, the tray icon changes from green when the service is running, to gray when it's not. It doesn't need admin rights and autostarts with windows if you set it to.
-----
C7. Windows Defender is the only antivirus program I use. Do I have to run the Wrapper Script every time I want to get new malware signatures and updates for it?

No. One of the script’s features is that Windows Defender, if enabled, is automatically updated with the script every 6 hours through the Windows Update service using the "WDU" (Windows Defender Update) task. This task will not update Defender if it's disabled.
-----
C8. Can the script be run automatically rather than manually, maybe even silently, for the computers of family members who aren't very technically minded to block updates completely, except for Windows Defender updates?

The script could be modified to do so, but in its present form, not silently. The reason is that the script requires user input, so if the parts requiring user input are bypassed, then the script could be run silently, either through a task or putting the script in the startup folder. But then WUMT would have to pop up. You could even bypass WUMT by modifying the script, but if you did that you might as well uninstall the script and let Windows update whenever it wants to.
-----
C9. Does the Wrapper Script let me use the Windows Store?

Yes, but it's a little restrictive because the Windows Store can't work without the Windows Update Service. You can use the store by selecting (E)nable in the Configurator, then use the Store either by leaving the Configurator window open, or (C)ontinue while checking for updates. The update service will be stopped when you choose to do so in the Configurator, or after an update check if you close WUMT or WuMgr. When WUMT or WuMgr is closed, the update service is disabled and the Store won't work.
-----
C10.  After updating with WUMT or WuMgr, a pop-up box asks if I want to reboot now. Is it better to say “yes” and let it reboot, or to close the pop-up, then the main WUMT window and reboot manually, or does it matter to the script?

It doesn’t matter. You can reboot either way and the update service will stay disabled.
-----
C11. How do I know which Windows updates are risky to install when I'm looking at what's available with WUMT? For example, I've learned that kbxxxxxxx and kbyyyyyyyy are actually update facilitators or "hijackers" and that MS keeps redistributing them so they become available for downloading again even after I've hidden them. Is there a simple list of bad KBs maintained that I can refer so I can hide them when they show up?

First, google the KB numbers to see if they are harmful.
"Simple" is a relative term. Here is a list of bad patches that facilitate telemetry (MS collecting data from you) for Windows 7 and 8.1: https://www.askwoody.com/forums/topic/2000003-ongoing-list-of-group-b-monthly-updates-for-win7-and-8-1/. 
For Windows 10:  Bad: KB4023057, KB4295110, KB4056254, KB4023814, . . . . ???
The negative effects of some Windows updates aren’t discovered by the community of Windows users until days, or in some case weeks, after deployment by MS.  Please consult your favorite websites to monitor feedback and consensus on new updates found to be problems for other users. One such site is AskWoody, where you can find an overall rating of comfort level with current updates ( https://www.askwoody.com/ms-defcon-system) and a master list of updates (https://www.askwoody.com/patch-list-master). However, a definitive blacklist of Windows updates does not yet seem to be available. To complicate this issue further, because of variable hardware characteristics and software configurations, an update can break one computer but not another.  So there is not a one-size-fits-all for any list.
It appears reasonable that updates contained in the offline Microsoft Update Catalog file, wsusscn2.cab https://go.microsoft.com/fwlink/?LinkID=74689, are bona fide updates and do not include update hijackers. But there is always the possibility that any update could be problematic for your specific, unique computer.
-----
C12.  Does the script create tasks in Task Scheduler?

Yes. The script creates "wub_task" which forces off the update service at reboot and at logon. It also creates a "WDU" task to update Windows Defender every 6 hours (but only if Defender is enabled). Both wub_task and WDU task are deleted and recreated every time you run the script. The WDU task waits 5 minutes to reduce resource hogging while booting, starts the windows update service, updates defender, then disables the windows update service. The varying length of time the update service stays on only depends on the type of Windows Defender update needed, engine (takes most time) or definition (usually pretty quick), but never stays on longer than needed to update defender, so you should be in no actual danger of a forced update during that time.  

-----
ADVANCED.
-----

D1. Can cumulative updates be selected and installed?

Yes, it almost always works, but not every time. Since Windows 10 version 1709 (Fall Creators Update), Cumulative Updates are processed by Microsoft's new delivery technology, Unified Update Platform (UUP), and WUMT and WuMgr can’t always handle UUP correctly. UUP was intended to significantly reduce the size of large feature updates by allowing them to be differential downloads that contain only the changes that have been made since the last time you updated Windows, rather than having to download a full build. Cumulative Updates were already differential updates, but were not previously processed by UUP. Microsoft’s use of UUP is one of the many challenges being addressed in the continuing development of the Wrapper Script. 
If you can’t install a Cumulative Update with WUMT or WuMgt under the script but WUMT or WuMgr does identify it, you can leave WUMT or WuMgr open with only that update shown as available (others either hidden or previously installed). Then you can open the Windows Update in Windows 10 Settings to install it. Follow the Wrapper Script instructions carefully to do this.
If you are having serious problems you can put the update's KB number in the search box here: https://www.catalog.update.microsoft.com/Home.aspx and download it from Microsoft after having tried using Updates in the Settings app while WUMT or WuMgr is running.
Another option for installing Cumulative Updates is to do it offline with WUMT or WuMgr by downloading the Microsoft Update Catalog file, wsusscn2.cab, which contains all updates and is itself updated periodically, from Microsoft at https://go.microsoft.com/fwlink/?LinkID=74689. 
(Note: Full build download packages, called "canonical" packages by MS, are self-contained updates that contain all files for the update, and don't rely on any files on your computer. Much smaller differential download packages reuse files on your current OS to reconstruct the newer OS by copying files as-is that have not changed between builds and by applying binary deltas to old files to generate newer ones.) 
-----
D2. Windows Update Blocker has an updated version 1.1. Shouldn't I use that instead of the version 1.0 that's included with the Wrapper Script installation?

No! Only use WUB version 1.0 with script, available here http://sordum.org/files/windows-update-blocker/old/Wub_v1.0.zip. WUB v1.1 can enable and disable a whole list of stuff that you specify in the Wub.ini file. That's great except for when you enable the update service, it'll also enable all the update hijackers that you want to stay disabled. For example, DoSvc, (Delivery Optimization Service) is in the ini file by default. If you don't re-enable the update service with v1.1, then v1.0 in the script won't re-enable whatever's in the v1.1 ini file (i.e. DoSvc).  In other words, always let enable be the last thing you do with v1.1 before you use v1.0 (included with the script) unless you want Delivery Optimization Service disabled permanently until you enable with v.1.1 again. Or better, remove DoSvc from Wub.ini (but not after disabling it or you can't reenable it!). Better yet, just use WUB v1.0 in conjunction with the Wrapper Script and forget that WUB v1.1 exists while using this script. Of course, there are exceptions to this, but you'd better know exactly what you're doing if you decide to use WUB v1.1!
-----
D3. I’m getting an error updating with the script and WUMT or WuMgr. How can I tell if the script is the problem?

If you're getting an error updating and you want to make sure the script isn't the problem, uninstall the script, then run Updates from the Settings app, or wumt_64.exe (or wumt_x86.exe) or WuMgr.exe and see what happens. If you get an 0x80072EE2 error code, that is a Windows Update error code (and not a script error code).
-----
D4. Why doesn't the script set the network connection to metered? Doesn't that stop Windows updates?

Enabling metering interferes with some apps. For example, a while back there was a problem with the Netflix app and metering. Plus, it doesn't stop updates. Windows still checks for updates with the connection metered and eventually forces updates anyway. Setting connections to metered is not a solution and can cause problems, so that method will not be added to the script. I'm only concerned with manual updating and the script is doing that. I don't want to interfere with anything except forced updates. People who truly need a metered connection can do this themselves and deal with any consequences.
-----
D5. Why doesn’t the script use the Windows firewall or the hosts file to restrict or block Windows update?

The firewall is unreliable since the update hijacker files will change over time, and then there are third party firewalls which will override any settings in the Windows firewall, and since it isn't necessary to block anything in the firewall to prevent unwanted updates with the script, using the firewall to block updates is a waste of time. Anything you might want to manually block in the firewall would only be redundant since the script takes care of update hijackers.
And the hosts file is easily bypassed by Windows, so using the hosts file is not an option.
-----
D6. Is it safe to use Windows 10 Fast Startup option when you're using the script?

Yes. Windows Update Blocker will be executed after you reboot, and logon, whether or not you have Fast Startup enabled.
-----
D7. Why are WaaSMedic, Update Orchestrator, and other update hijacker services allowed to run with the script?

Because there's no need to disable them. The script disables the parts of those services that initiate an update (system32\WaasMedic*.* and osrss.dll for example), and if the services were completely disabled, it could potentially cause serious problems with Windows in general (the Store, App updates, etc.), plus you wouldn't be able to update at all. There's no reason to be concerned about these services running. The methods I'm using have been well tested over time.
-----
D8. Why can't I enable the Windows Update Service?

It's been disabled by wub.exe on purpose. Just run wub.exe it and enable it if needed. The script will turn it back off when run, and when WUMT or WuMgr is closed.