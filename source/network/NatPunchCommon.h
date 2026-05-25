#pragma once

#include "NetworkPlatform.h"
#include "Packet.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>

// PacketType values used by NAT punchthrough.
// They are intentionally high so they do not collide with normal gameplay packets.
static constexpr PacketType PACKET_RENDEZVOUS_REGISTER_HOST = static_cast<PacketType>(100);
static constexpr PacketType PACKET_RENDEZVOUS_JOIN_HOST     = static_cast<PacketType>(101);
static constexpr PacketType PACKET_RENDEZVOUS_PEER_INFO     = static_cast<PacketType>(102);
static constexpr PacketType PACKET_RENDEZVOUS_ERROR         = static_cast<PacketType>(103);
static constexpr PacketType PACKET_NAT_PUNCH                = static_cast<PacketType>(104);
static constexpr PacketType PACKET_NAT_PUNCH_ACK            = static_cast<PacketType>(105);
static constexpr PacketType PACKET_RENDEZVOUS_KEEPALIVE     = static_cast<PacketType>(106);

struct RendezvousRegisterHostPacket {
    PacketHeader header;
    uint32_t roomCodeNetworkOrder;
};

struct RendezvousJoinHostPacket {
    PacketHeader header;
    uint32_t roomCodeNetworkOrder;
};

struct RendezvousPeerInfoPacket {
    PacketHeader header;
    uint32_t roomCodeNetworkOrder;

    // Network byte order, copied directly from sockaddr_in.
    uint32_t peerAddressNetworkOrder;
    uint16_t peerPortNetworkOrder;

    uint8_t youAreHost;
    uint8_t reserved;
};

struct RendezvousErrorPacket {
    PacketHeader header;
    uint32_t roomCodeNetworkOrder;
    uint32_t errorCodeNetworkOrder;
    char message[96];
};

struct NatPunchPacket {
    PacketHeader header;
    uint32_t roomCodeNetworkOrder;
    uint8_t fromHost;
    uint8_t reserved[3];
};

inline uint32_t makeRoomCode(uint32_t value)
{
    return value == 0 ? 1u : value;
}

inline const char* natPacketName(PacketType type)
{
    if (type == PACKET_RENDEZVOUS_REGISTER_HOST) return "RendezvousRegisterHost";
    if (type == PACKET_RENDEZVOUS_JOIN_HOST)     return "RendezvousJoinHost";
    if (type == PACKET_RENDEZVOUS_PEER_INFO)     return "RendezvousPeerInfo";
    if (type == PACKET_RENDEZVOUS_ERROR)         return "RendezvousError";
    if (type == PACKET_NAT_PUNCH)                return "NatPunch";
    if (type == PACKET_NAT_PUNCH_ACK)            return "NatPunchAck";
    if (type == PACKET_RENDEZVOUS_KEEPALIVE)     return "RendezvousKeepAlive";
    return "Unknown";
}

inline std::string endpointToString(const sockaddr_in& address)
{
    char ip[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &address.sin_addr, ip, sizeof(ip));
    return std::string(ip) + ":" + std::to_string(ntohs(address.sin_port));
}

inline bool parseIpv4Endpoint(const std::string& ip, uint16_t port, sockaddr_in& out)
{
    std::memset(&out, 0, sizeof(out));
    out.sin_family = AF_INET;
    out.sin_port = htons(port);

    if (inet_pton(AF_INET, ip.c_str(), &out.sin_addr) != 1) {
        std::cerr << "[NatPunch] Invalid IPv4 address: " << ip << "\n";
        return false;
    }

    return true;
}

inline bool sameEndpointNat(const sockaddr_in& a, const sockaddr_in& b)
{
    return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
}

inline bool setSocketNonBlockingNat(socket_t socketHandle, const char* ownerName)
{
#ifdef _WIN32
    u_long nonBlocking = 1;
    if (ioctlsocket(socketHandle, FIONBIO, &nonBlocking) != 0) {
        std::cerr << "[" << ownerName << "] Failed to set non-blocking mode. WSA error: "
                  << WSAGetLastError() << "\n";
        return false;
    }
#else
    int flags = fcntl(socketHandle, F_GETFL, 0);
    if (flags == -1) {
        std::cerr << "[" << ownerName << "] fcntl(F_GETFL) failed. errno: " << errno << "\n";
        return false;
    }
    if (fcntl(socketHandle, F_SETFL, flags | O_NONBLOCK) == -1) {
        std::cerr << "[" << ownerName << "] fcntl(F_SETFL) failed. errno: " << errno << "\n";
        return false;
    }
#endif
    return true;
}

inline bool sendUdpPacketNat(socket_t socketHandle, const sockaddr_in& to, const void* data, int size, const char* ownerName)
{
    if (socketHandle == INVALID_SOCKET_VALUE) {
        std::cerr << "[" << ownerName << "] Cannot send: invalid socket.\n";
        return false;
    }

    int bytesSent = sendto(
        socketHandle,
        reinterpret_cast<const char*>(data),
        size,
        0,
        reinterpret_cast<const sockaddr*>(&to),
        sizeof(to)
    );

    if (bytesSent == SOCKET_ERROR_VALUE) {
#ifdef _WIN32
        std::cerr << "[" << ownerName << "] sendto(" << endpointToString(to)
                  << ") failed. WSA error: " << WSAGetLastError() << "\n";
#else
        std::cerr << "[" << ownerName << "] sendto(" << endpointToString(to)
                  << ") failed. errno: " << errno << "\n";
#endif
        return false;
    }

    if (bytesSent != size) {
        std::cerr << "[" << ownerName << "] Partial UDP send to " << endpointToString(to)
                  << ": " << bytesSent << "/" << size << " bytes.\n";
        return false;
    }

    return true;
}

inline bool validatePacketHeaderNat(const char* data, int size, const char* ownerName)
{
    if (size < static_cast<int>(sizeof(PacketHeader))) {
        std::cerr << "[" << ownerName << "] Dropped packet: too small (" << size << " bytes).\n";
        return false;
    }

    const PacketHeader* header = reinterpret_cast<const PacketHeader*>(data);
    if (header->size != size) {
        std::cerr << "[" << ownerName << "] Dropped " << natPacketName(header->type)
                  << ": size mismatch, header=" << header->size
                  << ", actual=" << size << ".\n";
        return false;
    }

    return true;
}
