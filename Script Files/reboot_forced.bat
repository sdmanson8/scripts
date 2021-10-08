:: Countdown
cls
for %%r in (10 9 8 7 6 5 4 3 2 1) do (
echo Restarting in %%r...
timeout 1
cls
)

:: Force restart
shutdown /r /f /t 00
