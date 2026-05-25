#include "Engine.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow)
{
    // 1. Parse command line for "-v"
    std::string cmdLine = lpCmdLine;
    std::string ip;
    bool verbose = (cmdLine.find("-v") != std::string::npos);
    bool server = (cmdLine.find("-l") != std::string::npos);

    std::string target = "-ip";
    size_t pos = cmdLine.find(target);

    if (pos != std::string::npos) {
        // Move the position to the end of "-ip"
        size_t startOfIp = pos + target.length();

        // Skip any extra spaces between "-ip" and the actual IP address
        startOfIp = cmdLine.find_first_not_of(" ", startOfIp);

        if (startOfIp != std::string::npos) {
            // Find where the IP address ends (the next space)
            size_t endOfIp = cmdLine.find(" ", startOfIp);

            // Extract the substring
            if (endOfIp == std::string::npos) {
                // If there's no space after the IP, it's at the very end of the string
                ip = cmdLine.substr(startOfIp);
            } else {
                ip = cmdLine.substr(startOfIp, endOfIp - startOfIp);
            }
        }
    }

    // 2. If verbose, spawn a console window
    if (verbose)
    {
        if (!AttachConsole(ATTACH_PARENT_PROCESS))
        {
            // Fallback if no parent console exists (e.g. double-clicked exe)
            AllocConsole();
        }

        FILE* fDummy;
        freopen_s(&fDummy, "CONOUT$", "w", stdout);
        freopen_s(&fDummy, "CONOUT$", "w", stderr);
        freopen_s(&fDummy, "CONIN$",  "r", stdin);

        std::cout << "[Debug] Verbose mode enabled..." << std::endl;
    }

    if (ip.empty()) ip = "127.0.0.1";
    try {
        Engine engine("Raycaster Engine", server, ip);
        engine.run();
    }
    catch (const std::exception& e) {
        if (verbose) std::cerr << "CRITICAL ERROR: " << e.what() << std::endl;
        MessageBoxA(NULL, e.what(), "Engine Error", MB_ICONERROR);
    }

    return 0;
}