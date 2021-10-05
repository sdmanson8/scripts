:: Countdown
cls
for %%r in (5 4 3 2 1) do (
echo Restarting in %%r...
timeout 1 1>NUL 2>NUL
cls
)

:: Force restart
:: shutdown /r /f /t 00
