@echo off
REM LitterBox Service Wrapper ? launched by Task Scheduler
REM Logs to C:\LitterBox\logs\litterbox.log

cd /d "C:\LitterBox"

:loop
echo [%date% %time%] Starting LitterBox... >> "C:\LitterBox\logs\litterbox.log"
"C:\LitterBox\venv\Scripts\python.exe" "C:\LitterBox\litterbox.py" --ip 0.0.0.0 >> "C:\LitterBox\logs\litterbox.log" 2>&1

echo [%date% %time%] LitterBox exited (code %errorlevel%). Restarting in 5 seconds... >> "C:\LitterBox\logs\litterbox.log"
timeout /t 5 /nobreak > nul
goto loop
