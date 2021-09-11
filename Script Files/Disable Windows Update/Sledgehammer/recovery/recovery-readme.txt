Emergency recovery script v2.7.2

For emergency uninstall,
If you can get to Troubleshoot > Advanced options > Command Prompt in Windows 10 Recovery Environment go to step "3".
You may can force it by holding power button until it forces a shutdown enough times or if it boot-loops enough times. If not, make a windows 10 install flash drive or DVD on another computer and go to step "1".
1) Boot to normal Windows 10 install media. Make sure to use x64 media on an x64 windows install or x86 media on an x86 install.
2) When you get to the first screen to install, press shift+F10 to open command prompt.
3) locate and run the included recovery.cmd script* (see below)
4) reboot
5) run script uninstaller to reverse all changes made by script

===============================================================

*To find "recovery.cmd" file in command prompt:

3A) type command below and hit "enter" and you should see similar text on the screen as shown.
dir c:\w*

C:\>dir c:\w*

 Volume in drive C is 400GB
 Volume Serial Number is 7B90-AF21

 Directory of c:\

04/26/2019  03:58 PM    <DIR>          Windows

3B) If you see a Windows folder as shown above, good, if not, try replacing "c:" in step 3A with "d:", then "e:", etc. until you find it. Then, enter the drive letter you found the Windows folder on like this (if it's c drive), then "enter".
c:

3C) Run this command
dir \recovery.cmd /s

The result:

C:\>dir \recovery.cmd /s
 Volume in drive C is 400GB
 Volume Serial Number is 7B90-AF21

 Directory of C:\Sledgehammer\recovery script

01/06/2019  04:31 PM               3,957 recovery.cmd
               1 File(s)            3,957 bytes
 
     Total Files Listed:
               1 File(s)          3,957 bytes
               0 Dir(s)  253,928,378,368 bytes free


3D) Now you have the full path to the recovery script. In the command prompt, type the filename including the complete path, in this case C:\Sledgehammer\recovery script\recovery.cmd.
(or cd to the folder and run recovery.cmd from there).

3E) After the script successfully finishes, click the "X" in command prompt window, and then in installation menu box, to "cancel installation" which will reboot you into Windows 10.

3F) Uninstall Sledgehammer by, a) clicking "Uninstaller_undo-all-script-changes" from Sledgehammer folder in start menu if you installed with script installer, or, b) run "Uninstaller_undo-all-script-changes.cmd" in Sledgehammer folder if you didn't install it. Either way will work. Make sure you're using the correct uninstaller version, it'll say so in the uninstaller window title. Make sure to disable internet during uninstallation if you don't want to do updates yet. If you do "b" and the script was installed from the installer, you could possibly have "ghost" start menu entries that don't go anywhere, so to fix that, right click and delete Sledgehammer from the start menu.