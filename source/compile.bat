@echo off
setlocal enabledelayedexpansion

:: Create build directory if it doesn't exist
if not exist "..\build" mkdir "..\build"

:: 1. Gather all subdirectories to include for headers (/I)
set "INCLUDES="
for /r /d %%d in (*) do (
    set "INCLUDES=!INCLUDES! /I"%%d""
)

:: 2. Gather all .cpp files from current and all subfolders
set "SOURCES="
for /r %%f in (*.cpp) do (
    set "SOURCES=!SOURCES! "%%f""
)

:: 3. Compile using gathered sources and includes
cl /TP /std:c++17 /O2 /W4 /D NOMINMAX /EHsc ^
/I"%VULKAN_SDK%\Include" ^
!INCLUDES! !SOURCES! ^
/link ^
/LIBPATH:"%VULKAN_SDK%\Lib" ^
vulkan-1.lib ^
user32.lib gdi32.lib ^
/SUBSYSTEM:WINDOWS ^
/OUT:../build/raycaster.exe | findstr error

:: Clean up temporary object files
del *.obj