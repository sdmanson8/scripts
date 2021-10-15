:: Countdown
cls
for %%r in (30 29 28 27 26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1) do (
echo Restarting in %%r...
timeout 1
cls
timeout 5 >nul
)

:: Force restart
shutdown /r /f /t 00
