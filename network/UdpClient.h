#pragma once

#include "NetworkPlatform.h"
#include "Packet.h"
#include "NatPunchCommon.h"
#include "Player.h"
#include "MapEditProtocol.h"

#include <cstdint>
#include <chrono>
#include <string>
#include <vector>
#include <mutex>

#include "UdpServer.h"

struct MapData;

class UdpClient {

public:
    UdpClient();
    ~UdpClient();

    bool connect(std::string ip = "127.0.0.1", uint16_t port = 54000);

    // Join-side NAT punchthrough. This creates the UDP client socket, asks the
    // public rendezvous server for the host endpoint, punches, then sends Hello
    // to the host's local UdpServer once a direct path is likely open.
    bool connectViaRendezvous(const std::string& rendezvousIp, uint16_t rendezvousPort, uint32_t roomCode);

    void update();
    void stop();

    void sendHello();
    void sendPlayerState(const Player& player);
    void requestMap();

    // Client-authored map edits. The server only relays these; the sender should
    // apply the edit locally before sending. Remote clients consume and apply
    // queued edits from Engine::update().
    void sendMapAdd(const MapObjectEdit& object);
    void sendMapRemove(const std::string& objectId, bool persistToJson = true);
    bool addMapObject(MapData& mapData, MapObjectEdit& object, const std::string& jsonPath = "assets/map.json");
    bool removeMapObject(MapData& mapData, const std::string& objectId, const std::string& jsonPath = "assets/map.json");
    bool consumeMapEdits(std::vector<MapObjectEdit>& adds, std::vector<std::string>& removes);

    bool hasReceivedMapJson() const;
    const std::string& getReceivedMapJson() const { return m_receivedMapJson; }
    bool consumeReceivedMapJson(std::string& out);

    bool isRunning() const;
    bool isConnected() const;
    bool hasNatPeer() const { return m_natHasPeer; }
    bool isNatDirectReady() const { return m_natDirectReady; }

    uint32_t getPlayerId() const;

    PlayerStatePacket* getRemotePlayers();
    void predictRemotePlayers();

    static constexpr int MAX_PLAYERS = UdpServer::MAX_PLAYERS;

    int getClientNum() { return m_clientNum; };

private:
    void handlePacket(const char* data, int size, const sockaddr_in& from);
    void handleWelcome(const WelcomePacket& packet);
    void handlePlayerState(const PlayerStatePacket& packet);
    void handleMapChunk(const MapChunkPacket& packet);
    void handleMapDone(const MapDonePacket& packet);
    void handleMapAdd(const MapAddPacket& packet);
    void handleMapRemove(const MapRemovePacket& packet);
    void sendMapChunkAck(uint32_t transferId, uint32_t chunkIndex);

    bool handleNatPacket(const char* data, int size, const sockaddr_in& from);
    void handleRendezvousPeerInfo(const RendezvousPeerInfoPacket& packet);
    void handleNatPunch(const NatPunchPacket& packet, const sockaddr_in& from);
    void handleNatPunchAck(const NatPunchPacket& packet, const sockaddr_in& from);
    void handleRendezvousError(const RendezvousErrorPacket& packet, const sockaddr_in& from);
    void handleDisconnect(const DisconnectPacket& packet);
    void sendDisconnect();

    void updateRendezvousJoin();
    void updateNatPunching();
    void sendRendezvousJoin();
    void sendNatPunch(PacketType type);

    void sendPacket(const void* data, int size);

private:
    socket_t m_socket = INVALID_SOCKET_VALUE;

    sockaddr_in m_serverAddress{};

    bool m_running = false;
    bool m_connected = false;

    uint32_t m_playerId = 0;

    static constexpr int REMOTE_HISTORY_SIZE = 8;

    struct RemotePlayerHistory {
        PlayerStatePacket states[REMOTE_HISTORY_SIZE]{};
        std::chrono::steady_clock::time_point times[REMOTE_HISTORY_SIZE]{};
        int count = 0;
        uint32_t lastSequenceNumber = 0;
    };

    PlayerStatePacket m_remotePlayers[MAX_PLAYERS]{};
    RemotePlayerHistory m_remotePlayerHistory[MAX_PLAYERS]{};
    int m_clientNum = 0;

    uint32_t m_mapTransferId = 0;
    uint32_t m_mapChunkCount = 0;
    uint32_t m_mapTotalSize = 0;
    std::vector<std::string> m_mapChunks;
    std::vector<bool> m_mapChunkReceived;
    std::string m_receivedMapJson;
    bool m_hasReceivedMapJson = false;
    bool m_mapTransferComplete = false;
    mutable std::mutex m_mapMutex;

    std::vector<MapObjectEdit> m_pendingMapAdds;
    std::vector<std::string> m_pendingMapRemoves;
    std::mutex m_mapEditMutex;
    uint32_t m_nextMapEditSequence = 1;

    bool m_rendezvousMode = false;
    sockaddr_in m_rendezvousAddress{};
    uint32_t m_natRoomCode = 0;
    std::chrono::steady_clock::time_point m_lastRendezvousJoin{};

    bool m_natHasPeer = false;
    bool m_natDirectReady = false;
    bool m_sentHelloToNatPeer = false;
    sockaddr_in m_natPeerAddress{};
    std::chrono::steady_clock::time_point m_lastNatPunch{};
    std::chrono::steady_clock::time_point m_natPunchUntil{};

    static constexpr float RENDEZVOUS_JOIN_INTERVAL_SECONDS = 1.0f;
    static constexpr float NAT_PUNCH_INTERVAL_SECONDS = 0.10f;
    static constexpr float NAT_PUNCH_DURATION_SECONDS = 5.0f;
};