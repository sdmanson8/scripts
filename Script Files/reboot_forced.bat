:: Countdown
cls
for %%r in (35 34 33 32 31 30 29 28 26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1) do (
cls
echo Restarting in %%r seconds...
timeout 1 >nul
cls
)

:: Force restart
shutdown /r /f /t 00
