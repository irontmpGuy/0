#pragma once

#include "NetworkPlatform.h"
#include "Packet.h"
#include "NatPunchCommon.h"
#include "Player.h"
#include "MapEditProtocol.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>
#include <string>

// ---------------------------------------------------------------------------
// ClientEndpoint — one entry per connected peer.
// ---------------------------------------------------------------------------
struct ClientEndpoint {
    sockaddr_in        address{};
    uint32_t           playerId = 0;
    uint32_t lastSequenceNumber = 0;
    PlayerStatePacket  lastState{};
    std::chrono::steady_clock::time_point lastSeen = std::chrono::steady_clock::now();

    bool mapTransferActive = false;
    uint32_t mapTransferId = 0;
    uint32_t mapChunkCount = 0;
    bool mapChunkAcked[MAP_TRANSFER_MAX_CHUNKS]{};
    std::chrono::steady_clock::time_point lastMapSend{};
};

// ---------------------------------------------------------------------------
// UdpServer
//
// Feature 1 (listen-server architecture):
//   • The host-player's state is no longer injected here — it arrives via the
//     normal UdpClient → server → broadcast path like any other player.
//   • HOST_PLAYER_ID and broadcastHostState() have been removed.
//   • update() is non-blocking (sockets are O_NONBLOCK); call it once per
//     frame, before UdpClient::update().
// ---------------------------------------------------------------------------
class UdpServer {
public:
    UdpServer();
    ~UdpServer();

    bool start(uint16_t port = 54000);
    void update();
    void stop();

    // Host-side NAT punchthrough. Call after start().
    // This registers THIS local game-server socket with the public rendezvous server.
    bool registerWithRendezvous(const std::string& rendezvousIp, uint16_t rendezvousPort, uint32_t roomCode);
    bool hasNatPeer() const { return m_natHasPeer; }
    bool isNatDirectReady() const { return m_natDirectReady; }

    bool isRunning() const;

    // Read-only snapshot for the renderer (or debugging).
    const ClientEndpoint* getClients() const { return m_clients; }

    static constexpr int MAX_PLAYERS = 4;

    int m_clientCount = 0;

private:
    void handlePacket(const char* data, int size, const sockaddr_in& from);
    void handleHello(const sockaddr_in& from);
    void handlePlayerState(const PlayerStatePacket& packet, const sockaddr_in& from);
    void handleDisconnect(const sockaddr_in& from);
    void handleMapRequest(const sockaddr_in& from);
    void handleMapChunkAck(const MapChunkAckPacket& packet, const sockaddr_in& from);
    void handleMapAdd(const MapAddPacket& packet, const sockaddr_in& from);
    void handleMapRemove(const MapRemovePacket& packet, const sockaddr_in& from);

    bool handleNatPacket(const char* data, int size, const sockaddr_in& from);
    void handleRendezvousPeerInfo(const RendezvousPeerInfoPacket& packet);
    void handleNatPunch(const NatPunchPacket& packet, const sockaddr_in& from);
    void handleNatPunchAck(const NatPunchPacket& packet, const sockaddr_in& from);
    void handleRendezvousError(const RendezvousErrorPacket& packet, const sockaddr_in& from);
    void updateRendezvousRegistration();
    void updateNatPunching();
    void sendRendezvousRegister(PacketType type);
    void sendNatPunch(PacketType type);

    void evictTimedOutClients();
    void removeClientAt(size_t index, const char* reason);
    void broadcastLeave(uint32_t playerId);

    bool loadMapJson();
    void startMapTransfer(ClientEndpoint& client);
    void sendMapChunk(ClientEndpoint& client, uint32_t chunkIndex);
    void updateMapTransfers();

    bool isValidEndpoint(const sockaddr_in& a) const;

    void sendPacket(const sockaddr_in& to, const void* data, int size);
    void broadcastExcept(const sockaddr_in& except, const void* data, int size);
    void broadcastAll(const void* data, int size);

    bool sameEndpoint(const sockaddr_in& a, const sockaddr_in& b) const;
    ClientEndpoint* findClient(const sockaddr_in& from);

private:
    socket_t m_socket  = INVALID_SOCKET_VALUE;
    bool     m_running = false;

    uint32_t                    m_nextPlayerId = 1;
    ClientEndpoint m_clients[MAX_PLAYERS];

    std::string m_mapJson;
    uint32_t m_nextMapTransferId = 1;

    static constexpr float TIMEOUT_SECONDS = 5.0f;

    bool m_rendezvousEnabled = false;
    sockaddr_in m_rendezvousAddress{};
    uint32_t m_natRoomCode = 0;
    std::chrono::steady_clock::time_point m_lastRendezvousRegister{};

    bool m_natHasPeer = false;
    bool m_natDirectReady = false;
    sockaddr_in m_natPeerAddress{};
    std::chrono::steady_clock::time_point m_lastNatPunch{};
    std::chrono::steady_clock::time_point m_natPunchUntil{};

    static constexpr float RENDEZVOUS_REGISTER_INTERVAL_SECONDS = 1.0f;
    static constexpr float NAT_PUNCH_INTERVAL_SECONDS = 0.10f;
    static constexpr float NAT_PUNCH_DURATION_SECONDS = 5.0f;
};