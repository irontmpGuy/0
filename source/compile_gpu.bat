@echo off
setlocal enabledelayedexpansion

:: Force oneAPI to look into your Visual Studio Insider folder
set "VS2026INSTALLDIR=C:\Program Files\Microsoft Visual Studio\18\Insiders"

:: Check if icpx is available. If not, initialize the oneAPI environment.
where icpx >nul 2>nul
if %errorlevel% neq 0 (
    echo Initializing oneAPI environment...
    if exist "C:\Program Files (x86)\Intel\oneAPI\setvars.bat" (
        call "C:\Program Files (x86)\Intel\oneAPI\setvars.bat" intel64
    ) else (
        echo Error: setvars.bat not found. Please verify your Intel oneAPI installation path.
        exit /b 1
    )
)

:: Create build directory if it doesn't exist
if not exist "..\build" mkdir "..\build"

:: 1. Gather all subdirectories to include for headers (-I)
set "INCLUDES="
for /r /d %%d in (*) do (
    set "INCLUDES=!INCLUDES! -I"%%d""
)

:: 2. Gather all .cpp files from current and all subfolders
set "SOURCES="
for /r %%f in (*.cpp) do (
    set "SOURCES=!SOURCES! "%%f""
)

:: 3. Compile using Intel oneAPI SYCL compiler (icpx)
echo Compiling...
icx-cl -w /DNOMINMAX /EHsc -fsycl -std=c++17 -O3 !INCLUDES! !SOURCES! -Xlinker user32.lib -Xlinker gdi32.lib -Xlinker /SUBSYSTEM:WINDOWS -o ../build/raycaster.exe

:: Clean up temporary object files (if any are left over)
if exist *.obj del *.obj