#include <windows.h>
#include <string>
#include <vector>

extern "C" __declspec(dllexport) bool __cdecl main_func(const char* file, bool bat = true, const char* exeArgs = nullptr)
{
    auto expandVars = [](const char* input) -> std::string {
        if (!input) return "";
        DWORD need = ExpandEnvironmentStringsA(input, nullptr, 0);
        if (!need) return "";
        std::vector<char> buf(need);
        ExpandEnvironmentStringsA(input, buf.data(), need);
        return std::string(buf.data());
    };

    std::string scriptPath = expandVars(file);
    if (scriptPath.empty()) return false;

    std::vector<char> cmdMutableData;
    char* cmdPtr = nullptr;

    if (bat) {
        std::string cmdLine = std::string("/C \"") + scriptPath + "\"";
        cmdMutableData.assign(cmdLine.begin(), cmdLine.end());
        cmdMutableData.push_back('\0');
        cmdPtr = cmdMutableData.data();
    } else {
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

    std::string processName = bat ? "C:\\Windows\\System32\\cmd.exe" : scriptPath;

    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    BOOL ok = CreateProcessA(
        processName.c_str(),
        cmdPtr,
        nullptr, nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si, &pi);

    if (!ok) return false;

    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

BOOL APIENTRY DllMain(HMODULE hModuleCall, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    return TRUE;
}