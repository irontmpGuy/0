#include <windows.h>
#include <iostream>

typedef BOOL (WINAPI* MainFuncType)();   // no parameters now

int main(const char* dllPath, const char* mainFuncName)
{
    HMODULE hMod = LoadLibraryA(dllPath);
    if (!hMod) {
        std::cout << "LoadLibrary failed: " << GetLastError() << "\n";
        return 1;
    }

    std::cout << "DLL loaded at: 0x" << std::hex << (uintptr_t)hMod << std::dec << "\n";

    FARPROC proc = GetProcAddress(hMod, mainFuncName);
    if (!proc) {
        std::cout << "GetProcAddress failed: " << GetLastError() << "\n";
        FreeLibrary(hMod);
        return 1;
    }

    MainFuncType main_func = reinterpret_cast<MainFuncType>(proc);

    std::cout << "Calling main_func()...\n";

    BOOL result = main_func();

    std::cout << "main_func returned: " << result << "\n";

    FreeLibrary(hMod);
    return 0;
}
