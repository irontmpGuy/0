#pragma once

#include <iostream>

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

using socket_t = SOCKET;

static constexpr socket_t INVALID_SOCKET_VALUE = INVALID_SOCKET;
static constexpr int SOCKET_ERROR_VALUE = SOCKET_ERROR;

inline void closeSocket(socket_t socketHandle)
{
    closesocket(socketHandle);
}

inline bool initNetwork()
{
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
}

inline void shutdownNetwork()
{
    WSACleanup();
}

#else

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>

using socket_t = int;

static constexpr socket_t INVALID_SOCKET_VALUE = -1;
static constexpr int SOCKET_ERROR_VALUE = -1;

inline void closeSocket(socket_t socketHandle)
{
    close(socketHandle);
}

inline bool initNetwork()
{
    return true;
}

inline void shutdownNetwork()
{
}

#endif