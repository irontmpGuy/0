#include "UdpClient.h"
#include "MapData.h"

#include <iostream>
#include <cstring>
#include <cerrno>
#include <algorithm>

#ifdef _WIN32
#include <io.h>
#else
#include <fcntl.h>
#endif

UdpClient::UdpClient()
{
}

UdpClient::~UdpClient()
{
    stop();
}

bool UdpClient::connect(std::string ip, uint16_t port)
{
    if (!initNetwork()) {
        std::cerr << "[UdpClient] Failed to initialize network.\n";
        return false;
    }

    m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (m_socket == INVALID_SOCKET_VALUE) {
        std::cerr << "[UdpClient] Failed to create UDP socket.\n";
        shutdownNetwork();
        return false;
    }

    std::memset(&m_serverAddress, 0, sizeof(m_serverAddress));

    m_serverAddress.sin_family = AF_INET;
    m_serverAddress.sin_port = htons(port);

    if (inet_pton(AF_INET, ip.c_str(), &m_serverAddress.sin_addr) != 1) { // ip
        std::cerr << "[UdpClient] Failed to parse server address.\n";
        closeSocket(m_socket);
        m_socket = INVALID_SOCKET_VALUE;
        shutdownNetwork();
        return false;
    }

#ifdef _WIN32
    u_long nonBlocking = 1;
    ioctlsocket(m_socket, FIONBIO, &nonBlocking);
#else
    int flags = fcntl(m_socket, F_GETFL, 0);
    fcntl(m_socket, F_SETFL, flags | O_NONBLOCK);
#endif

    m_running = true;

    sendHello();

    return true;
}


bool UdpClient::connectViaRendezvous(const std::string& rendezvousIp, uint16_t rendezvousPort, uint32_t roomCode)
{
    if (!initNetwork()) {
        std::cerr << "[UdpClient/NAT] Failed to initialize network.\n";
        return false;
    }

    m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (m_socket == INVALID_SOCKET_VALUE) {
        std::cerr << "[UdpClient/NAT] Failed to create UDP socket.\n";
        shutdownNetwork();
        return false;
    }

    if (!parseIpv4Endpoint(rendezvousIp, rendezvousPort, m_rendezvousAddress)) {
        closeSocket(m_socket);
        m_socket = INVALID_SOCKET_VALUE;
        shutdownNetwork();
        return false;
    }

    if (!setSocketNonBlockingNat(m_socket, "UdpClient/NAT")) {
        closeSocket(m_socket);
        m_socket = INVALID_SOCKET_VALUE;
        shutdownNetwork();
        return false;
    }

    m_running = true;
    m_connected = false;
    m_rendezvousMode = true;
    m_natRoomCode = makeRoomCode(roomCode);
    m_natHasPeer = false;
    m_natDirectReady = false;
    m_sentHelloToNatPeer = false;
    m_lastRendezvousJoin = std::chrono::steady_clock::now() - std::chrono::seconds(10);

    std::cout << "[UdpClient/NAT] Joining room=" << m_natRoomCode
              << " through rendezvous " << endpointToString(m_rendezvousAddress) << "\n";

    sendRendezvousJoin();
    return true;
}

void UdpClient::sendHello()
{
    HelloPacket packet{};
    packet.header.type = PacketType::Hello;
    packet.header.size = sizeof(HelloPacket);

    sendPacket(&packet, sizeof(packet));
}

void UdpClient::update()
{
    if (!m_running) {
        return;
    }

    char buffer[1024];

    while (true) {
        sockaddr_in from{};

#ifdef _WIN32
        int fromLength = sizeof(from);
#else
        socklen_t fromLength = sizeof(from);
#endif

        int bytesReceived = recvfrom(
            m_socket,
            buffer,
            sizeof(buffer),
            0,
            (sockaddr*)&from,
            &fromLength
        );

        if (bytesReceived <= 0) {
            break;
        }

        handlePacket(buffer, bytesReceived, from);
    }

    updateRendezvousJoin();
    updateNatPunching();
}

void UdpClient::handlePacket(const char* data, int size, const sockaddr_in& from)
{
    if (size < static_cast<int>(sizeof(PacketHeader))) {
        return;
    }

    const PacketHeader* header = reinterpret_cast<const PacketHeader*>(data);

    if (header->size != size) {
        return;
    }

    if (handleNatPacket(data, size, from)) {
        return;
    }

    switch (header->type) {
        case PacketType::Welcome:
            if (size == sizeof(WelcomePacket)) {
                const WelcomePacket& packet =
                    *(const WelcomePacket*)data;

                handleWelcome(packet);
            }
            break;

        case PacketType::PlayerState:
            if (size == sizeof(PlayerStatePacket)) {
                const PlayerStatePacket& packet =
                    *(const PlayerStatePacket*)data;

                handlePlayerState(packet);
            }
            break;
        case PacketType::Disconnect:
            if (size == sizeof(DisconnectPacket)) {
                const DisconnectPacket& packet =
                    *(const DisconnectPacket*)data;

                handleDisconnect(packet);
            }
            break;

        case PacketType::MapChunk:
            if (size == sizeof(MapChunkPacket)) {
                const MapChunkPacket& packet =
                    *(const MapChunkPacket*)data;

                handleMapChunk(packet);
            }
            break;

        case PacketType::MapDone:
            if (size == sizeof(MapDonePacket)) {
                const MapDonePacket& packet =
                    *(const MapDonePacket*)data;

                handleMapDone(packet);
            }
            break;

        case PacketType::MapAdd:
            if (size == sizeof(MapAddPacket)) {
                handleMapAdd(*(const MapAddPacket*)data);
            }
            break;

        case PacketType::MapRemove:
            if (size == sizeof(MapRemovePacket)) {
                handleMapRemove(*(const MapRemovePacket*)data);
            }
            break;

        default:
            break;
    }
}

void UdpClient::handleWelcome(const WelcomePacket& packet)
{
    m_playerId = packet.playerId;
    m_connected = true;

    std::cout << "[UdpClient] Connected. Assigned playerId "
              << m_playerId
              << "\n";

    requestMap();
}


void UdpClient::requestMap()
{
    if (!m_running)
        return;

    {
        std::lock_guard<std::mutex> lock(m_mapMutex);
        m_mapTransferId = 0;
        m_mapChunkCount = 0;
        m_mapTotalSize = 0;
        m_mapChunks.clear();
        m_mapChunkReceived.clear();
        m_mapTransferComplete = false;
        m_hasReceivedMapJson = false;
        m_receivedMapJson.clear();
    }

    MapRequestPacket packet{};
    packet.header.type = PacketType::MapRequest;
    packet.header.size = sizeof(packet);

    sendPacket(&packet, sizeof(packet));
}

void UdpClient::sendMapChunkAck(uint32_t transferId, uint32_t chunkIndex)
{
    MapChunkAckPacket packet{};
    packet.header.type = PacketType::MapChunkAck;
    packet.header.size = sizeof(packet);
    packet.transferId = transferId;
    packet.chunkIndex = chunkIndex;

    sendPacket(&packet, sizeof(packet));
}

void UdpClient::handleMapChunk(const MapChunkPacket& packet)
{
    if (packet.chunkCount == 0 ||
        packet.chunkCount > MAP_TRANSFER_MAX_CHUNKS ||
        packet.chunkIndex >= packet.chunkCount ||
        packet.payloadSize > MAP_TRANSFER_CHUNK_SIZE) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_mapMutex);

        // After completion, duplicate chunks can still arrive because UDP ACKs/Done
        // race each other. ACK them, but do not rebuild/overwrite the JSON string.
        if (m_mapTransferComplete && packet.transferId == m_mapTransferId) {
            sendMapChunkAck(packet.transferId, packet.chunkIndex);
            return;
        }

        if (m_mapTransferId == 0) {
            m_mapTransferId = packet.transferId;
            m_mapChunkCount = packet.chunkCount;
            m_mapTotalSize = packet.totalSize;
            m_mapChunks.assign(packet.chunkCount, std::string());
            m_mapChunkReceived.assign(packet.chunkCount, false);
            m_receivedMapJson.clear();
            m_hasReceivedMapJson = false;
            m_mapTransferComplete = false;
        } else if (m_mapTransferId != packet.transferId) {
            // Ignore stale/overlapping map chunks. The old code accepted any
            // different transferId and rebuilt the receive buffer, so two
            // concurrent map transfers could corrupt/oscillate map loading.
            return;
        }

        if (packet.chunkCount != m_mapChunkCount || packet.totalSize != m_mapTotalSize)
            return;

        if (!m_mapChunkReceived[packet.chunkIndex]) {
            m_mapChunks[packet.chunkIndex].assign(packet.payload, packet.payload + packet.payloadSize);
            m_mapChunkReceived[packet.chunkIndex] = true;
        }

        // ACK duplicates too. If the ACK was lost, this stops server resends.
        sendMapChunkAck(packet.transferId, packet.chunkIndex);

        bool complete = true;
        for (bool received : m_mapChunkReceived) {
            if (!received) {
                complete = false;
                break;
            }
        }

        if (!complete)
            return;

        std::string json;
        json.reserve(m_mapTotalSize);
        for (const std::string& chunk : m_mapChunks)
            json += chunk;

        if (json.size() != m_mapTotalSize)
            return;

        m_receivedMapJson = std::move(json);
        m_hasReceivedMapJson = true;
        m_mapTransferComplete = true;
    }
}

void UdpClient::handleMapDone(const MapDonePacket& packet)
{
    bool transferComplete = false;
    bool totalSizeMatches = false;

    {
        std::lock_guard<std::mutex> lock(m_mapMutex);

        if (packet.transferId != m_mapTransferId)
            return;

        transferComplete = m_mapTransferComplete;
        totalSizeMatches = packet.totalSize == m_mapTotalSize;
    }

    if (!transferComplete || !totalSizeMatches) {
        requestMap();
        return;
    }

    std::cout << "[UdpClient] Map received. bytes=" << packet.totalSize << "\n";
}

bool UdpClient::hasReceivedMapJson() const
{
    std::lock_guard<std::mutex> lock(m_mapMutex);
    return m_hasReceivedMapJson;
}

bool UdpClient::consumeReceivedMapJson(std::string& out)
{
    std::lock_guard<std::mutex> lock(m_mapMutex);
    if (!m_hasReceivedMapJson)
        return false;

    m_hasReceivedMapJson = false;
    out = m_receivedMapJson;
    return true;
}

void UdpClient::sendMapAdd(const MapObjectEdit& object)
{
    if (!m_running || !m_connected)
        return;

    MapAddPacket packet{};
    packet.header.type = PacketType::MapAdd;
    packet.header.size = sizeof(packet);
    packet.sourcePlayerId = m_playerId;
    packet.sequenceNumber = m_nextMapEditSequence++;
    packet.object = object;

    sendPacket(&packet, sizeof(packet));
}

void UdpClient::sendMapRemove(const std::string& objectId, bool persistToJson)
{
    if (!m_running || !m_connected || objectId.empty())
        return;

    MapRemovePacket packet{};
    packet.header.type = PacketType::MapRemove;
    packet.header.size = sizeof(packet);
    packet.sourcePlayerId = m_playerId;
    packet.sequenceNumber = m_nextMapEditSequence++;
    packet.persistToJson = persistToJson ? 1 : 0;
    mapEditSetString(packet.objectId, sizeof(packet.objectId), objectId);

    sendPacket(&packet, sizeof(packet));
}

bool UdpClient::addMapObject(MapData& mapData, MapObjectEdit& object, const std::string& jsonPath)
{
    if (!mapData.addObjectAndPersist(object, jsonPath, true))
        return false;

    sendMapAdd(object);
    return true;
}

bool UdpClient::removeMapObject(MapData& mapData, const std::string& objectId, const std::string& jsonPath)
{
    if (objectId.empty())
        return false;

    const bool removed = mapData.removeObjectAndPersist(objectId, jsonPath);
    if (removed) {
        sendMapRemove(objectId, true);
    }
    return removed;
}

bool UdpClient::consumeMapEdits(std::vector<MapObjectEdit>& adds, std::vector<std::string>& removes)
{
    std::lock_guard<std::mutex> lock(m_mapEditMutex);
    if (m_pendingMapAdds.empty() && m_pendingMapRemoves.empty())
        return false;

    adds.insert(adds.end(), m_pendingMapAdds.begin(), m_pendingMapAdds.end());
    removes.insert(removes.end(), m_pendingMapRemoves.begin(), m_pendingMapRemoves.end());
    m_pendingMapAdds.clear();
    m_pendingMapRemoves.clear();
    return true;
}

void UdpClient::handleMapAdd(const MapAddPacket& packet)
{
    if (packet.sourcePlayerId == m_playerId)
        return;

    const std::string id = mapEditGetString(packet.object.id, sizeof(packet.object.id));
    if (id.empty())
        return;

    std::lock_guard<std::mutex> lock(m_mapEditMutex);
    m_pendingMapAdds.push_back(packet.object);
}

void UdpClient::handleMapRemove(const MapRemovePacket& packet)
{
    if (packet.sourcePlayerId == m_playerId)
        return;

    const std::string id = mapEditGetString(packet.objectId, sizeof(packet.objectId));
    if (id.empty())
        return;

    std::lock_guard<std::mutex> lock(m_mapEditMutex);
    m_pendingMapRemoves.push_back(id);
}


void UdpClient::handleDisconnect(const DisconnectPacket& packet)
{
    for (int i = 0; i < m_clientNum; ++i) {
        if (m_remotePlayers[i].playerId == packet.playerId) {
            for (int j = i + 1; j < m_clientNum; ++j) {
                m_remotePlayers[j - 1] = m_remotePlayers[j];
                m_remotePlayerHistory[j - 1] = m_remotePlayerHistory[j];
            }

            --m_clientNum;

            std::cout << "[UdpClient] Remote player " << packet.playerId << " left\n";
            return;
        }
    }
}

void UdpClient::sendDisconnect()
{
    if (!m_running || !m_connected)
        return;

    DisconnectPacket packet{};
    packet.header.type = PacketType::Disconnect;
    packet.header.size = sizeof(packet);
    packet.playerId = m_playerId;

    sendPacket(&packet, sizeof(packet));
}

void UdpClient::handlePlayerState(const PlayerStatePacket& packet)
{
    if (packet.playerId == m_playerId) {
        return;
    }

    auto now = std::chrono::steady_clock::now();

    for (int i = 0; i < m_clientNum; i++) {
        if (m_remotePlayers[i].playerId == packet.playerId) {
            RemotePlayerHistory& history = m_remotePlayerHistory[i];

            if (packet.sequenceNumber <= history.lastSequenceNumber) {
                return;
            }

            history.lastSequenceNumber = packet.sequenceNumber;

            if (history.count < REMOTE_HISTORY_SIZE) {
                history.states[history.count] = packet;
                history.times[history.count] = now;
                history.count++;
            } else {
                for (int j = 1; j < REMOTE_HISTORY_SIZE; j++) {
                    history.states[j - 1] = history.states[j];
                    history.times[j - 1] = history.times[j];
                }

                history.states[REMOTE_HISTORY_SIZE - 1] = packet;
                history.times[REMOTE_HISTORY_SIZE - 1] = now;
            }

            return;
        }
    }

    if (m_clientNum < MAX_PLAYERS) {
        int index = m_clientNum++;

        m_remotePlayers[index] = packet;

        RemotePlayerHistory& history = m_remotePlayerHistory[index];
        history.states[0] = packet;
        history.times[0] = now;
        history.count = 1;
        history.lastSequenceNumber = packet.sequenceNumber;
    }
}


bool UdpClient::handleNatPacket(const char* data, int size, const sockaddr_in& from)
{
    const PacketHeader* header = reinterpret_cast<const PacketHeader*>(data);

    if (header->type == PACKET_RENDEZVOUS_PEER_INFO) {
        if (size != static_cast<int>(sizeof(RendezvousPeerInfoPacket))) {
            std::cerr << "[UdpClient/NAT] Bad PeerInfo size from " << endpointToString(from) << "\n";
            return true;
        }
        handleRendezvousPeerInfo(*reinterpret_cast<const RendezvousPeerInfoPacket*>(data));
        return true;
    }

    if (header->type == PACKET_NAT_PUNCH) {
        if (size != static_cast<int>(sizeof(NatPunchPacket))) {
            std::cerr << "[UdpClient/NAT] Bad Punch size from " << endpointToString(from) << "\n";
            return true;
        }
        handleNatPunch(*reinterpret_cast<const NatPunchPacket*>(data), from);
        return true;
    }

    if (header->type == PACKET_NAT_PUNCH_ACK) {
        if (size != static_cast<int>(sizeof(NatPunchPacket))) {
            std::cerr << "[UdpClient/NAT] Bad PunchAck size from " << endpointToString(from) << "\n";
            return true;
        }
        handleNatPunchAck(*reinterpret_cast<const NatPunchPacket*>(data), from);
        return true;
    }

    if (header->type == PACKET_RENDEZVOUS_ERROR) {
        if (size != static_cast<int>(sizeof(RendezvousErrorPacket))) {
            std::cerr << "[UdpClient/NAT] Bad RendezvousError size from " << endpointToString(from) << "\n";
            return true;
        }
        handleRendezvousError(*reinterpret_cast<const RendezvousErrorPacket*>(data), from);
        return true;
    }

    return false;
}

void UdpClient::handleRendezvousPeerInfo(const RendezvousPeerInfoPacket& packet)
{
    uint32_t roomCode = ntohl(packet.roomCodeNetworkOrder);
    if (!m_rendezvousMode || roomCode != m_natRoomCode) {
        std::cerr << "[UdpClient/NAT] Ignored PeerInfo for wrong room. got="
                  << roomCode << ", expected=" << m_natRoomCode << "\n";
        return;
    }

    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_addr.s_addr = packet.peerAddressNetworkOrder;
    peer.sin_port = packet.peerPortNetworkOrder;

    if (m_natDirectReady && m_natHasPeer && sameEndpointNat(m_natPeerAddress, peer)) {
        return;
    }

    m_natPeerAddress = peer;
    m_serverAddress = peer;
    m_natHasPeer = true;
    m_natDirectReady = false;
    m_sentHelloToNatPeer = false;

    auto now = std::chrono::steady_clock::now();
    m_lastNatPunch = now - std::chrono::seconds(10);
    m_natPunchUntil = now + std::chrono::milliseconds(static_cast<int>(NAT_PUNCH_DURATION_SECONDS * 1000.0f));

    sendNatPunch(PACKET_NAT_PUNCH);
}

void UdpClient::handleNatPunch(const NatPunchPacket& packet, const sockaddr_in& from)
{
    uint32_t roomCode = ntohl(packet.roomCodeNetworkOrder);
    if (!m_rendezvousMode || roomCode != m_natRoomCode) {
        std::cerr << "[UdpClient/NAT] Ignored Punch for wrong room from "
                  << endpointToString(from) << "\n";
        return;
    }

    m_natPeerAddress = from;
    m_serverAddress = from;
    m_natHasPeer = true;
    m_natDirectReady = true;

    sendNatPunch(PACKET_NAT_PUNCH_ACK);

    if (!m_sentHelloToNatPeer) {
        m_sentHelloToNatPeer = true;
        sendHello();
    }
}

void UdpClient::handleNatPunchAck(const NatPunchPacket& packet, const sockaddr_in& from)
{
    uint32_t roomCode = ntohl(packet.roomCodeNetworkOrder);
    if (!m_rendezvousMode || roomCode != m_natRoomCode) {
        std::cerr << "[UdpClient/NAT] Ignored PunchAck for wrong room from "
                  << endpointToString(from) << "\n";
        return;
    }

    m_natPeerAddress = from;
    m_serverAddress = from;
    m_natHasPeer = true;
    m_natDirectReady = true;

    if (!m_sentHelloToNatPeer) {
        m_sentHelloToNatPeer = true;
        sendHello();
    }
}

void UdpClient::handleRendezvousError(const RendezvousErrorPacket& packet, const sockaddr_in& from)
{
    uint32_t roomCode = ntohl(packet.roomCodeNetworkOrder);
    uint32_t errorCode = ntohl(packet.errorCodeNetworkOrder);
    std::cerr << "[UdpClient/NAT] Rendezvous error from " << endpointToString(from)
              << ". room=" << roomCode
              << ", code=" << errorCode
              << ", message=" << packet.message << "\n";
}

void UdpClient::updateRendezvousJoin()
{
    if (!m_rendezvousMode || m_natHasPeer)
        return;

    auto now = std::chrono::steady_clock::now();
    float elapsed = std::chrono::duration<float>(now - m_lastRendezvousJoin).count();
    if (elapsed >= RENDEZVOUS_JOIN_INTERVAL_SECONDS) {
        sendRendezvousJoin();
        m_lastRendezvousJoin = now;
    }
}

void UdpClient::updateNatPunching()
{
    if (!m_natHasPeer || m_natDirectReady)
        return;

    auto now = std::chrono::steady_clock::now();
    if (now > m_natPunchUntil) {
        std::cerr << "[UdpClient/NAT] Punch timeout. Could not open direct path to "
                  << endpointToString(m_natPeerAddress) << "\n";
        m_natHasPeer = false;
        return;
    }

    float elapsed = std::chrono::duration<float>(now - m_lastNatPunch).count();
    if (elapsed >= NAT_PUNCH_INTERVAL_SECONDS) {
        sendNatPunch(PACKET_NAT_PUNCH);
        m_lastNatPunch = now;
    }
}

void UdpClient::sendRendezvousJoin()
{
    RendezvousJoinHostPacket packet{};
    packet.header.type = PACKET_RENDEZVOUS_JOIN_HOST;
    packet.header.size = sizeof(packet);
    packet.roomCodeNetworkOrder = htonl(m_natRoomCode);

    sendUdpPacketNat(m_socket, m_rendezvousAddress, &packet, sizeof(packet), "UdpClient/NAT");
}

void UdpClient::sendNatPunch(PacketType type)
{
    if (!m_natHasPeer)
        return;

    NatPunchPacket packet{};
    packet.header.type = type;
    packet.header.size = sizeof(packet);
    packet.roomCodeNetworkOrder = htonl(m_natRoomCode);
    packet.fromHost = 0;

    sendUdpPacketNat(m_socket, m_natPeerAddress, &packet, sizeof(packet), "UdpClient/NAT");
}

static float lerpFloat(float a, float b, float t)
{
    return a + (b - a) * t;
}

static PlayerStatePacket lerpPlayerState(const PlayerStatePacket& a,
                                         const PlayerStatePacket& b,
                                         float t)
{
    PlayerStatePacket out = b;

    out.x = lerpFloat(a.x, b.x, t);
    out.y = lerpFloat(a.y, b.y, t);
    out.z = lerpFloat(a.z, b.z, t);

    out.dirX = lerpFloat(a.dirX, b.dirX, t);
    out.dirY = lerpFloat(a.dirY, b.dirY, t);
    out.dirZ = lerpFloat(a.dirZ, b.dirZ, t);

    out.vX = lerpFloat(a.vX, b.vX, t);
    out.vY = lerpFloat(a.vY, b.vY, t);
    out.vZ = lerpFloat(a.vZ, b.vZ, t);

    out.pitch = lerpFloat(a.pitch, b.pitch, t);
    out.height = lerpFloat(a.height, b.height, t);
    out.speedFactor = lerpFloat(a.speedFactor, b.speedFactor, t);

    return out;
}

void UdpClient::predictRemotePlayers()
{
    constexpr float INTERPOLATION_DELAY_PACKETS = 3.0f;

    for (int i = 0; i < m_clientNum; i++) {
        const RemotePlayerHistory& history = m_remotePlayerHistory[i];

        if (history.count <= 0)
            continue;

        if (history.count == 1) {
            m_remotePlayers[i] = history.states[0];
            continue;
        }

        const int newestIndex = history.count - 1;
        const uint32_t newestSeq = history.states[newestIndex].sequenceNumber;

        const float renderSeq = static_cast<float>(newestSeq) - INTERPOLATION_DELAY_PACKETS;

        if (renderSeq <= static_cast<float>(history.states[0].sequenceNumber)) {
            m_remotePlayers[i] = history.states[0];
            continue;
        }

        if (renderSeq >= static_cast<float>(newestSeq)) {
            m_remotePlayers[i] = history.states[newestIndex];
            continue;
        }

        bool found = false;

        for (int j = 1; j < history.count; j++) {
            const PlayerStatePacket& a = history.states[j - 1];
            const PlayerStatePacket& b = history.states[j];

            const float seqA = static_cast<float>(a.sequenceNumber);
            const float seqB = static_cast<float>(b.sequenceNumber);

            if (renderSeq >= seqA && renderSeq <= seqB) {
                float alpha = 0.0f;

                if (seqB > seqA) {
                    alpha = (renderSeq - seqA) / (seqB - seqA);
                }

                if (alpha < 0.0f) alpha = 0.0f;
                if (alpha > 1.0f) alpha = 1.0f;

                m_remotePlayers[i] = lerpPlayerState(a, b, alpha);
                found = true;
                break;
            }
        }

        if (!found) {
            m_remotePlayers[i] = history.states[newestIndex];
        }
    }
}

void UdpClient::sendPlayerState(const Player& player)
{
    static uint32_t sequenceNumber = 0;
    sequenceNumber++;
    if (!m_running || !m_connected) {
        return;
    }

    Vec3f pos = player.getPos();
    Vec3f dir = player.getDir();
    Vec3f velocity = player.m_velocity;

    PlayerStatePacket packet{};
    packet.header.type = PacketType::PlayerState;
    packet.header.size = sizeof(PlayerStatePacket);

    packet.playerId = m_playerId;
    packet.sequenceNumber = sequenceNumber;

    packet.x = pos.x;
    packet.y = pos.y;
    packet.z = pos.z;

    packet.dirX = dir.x;
    packet.dirY = dir.y;
    packet.dirZ = dir.z;

    packet.vX = velocity.x;
    packet.vY = velocity.y;
    packet.vZ = velocity.z;

    packet.pitch = 0.0f;       // We can expose Player::getPitch() later.
    packet.height = player.height;

    packet.speedFactor = player.speedFactor;

    packet.light_on = player.light_on;

    sendPacket(&packet, sizeof(packet));
}

void UdpClient::sendPacket(const void* data, int size)
{
    if (m_socket == INVALID_SOCKET_VALUE) {
        std::cerr << "[UdpClient] Cannot send: invalid socket\n";
        return;
    }

    int bytesSent = sendto(
        m_socket,
        reinterpret_cast<const char*>(data),
        size,
        0,
        reinterpret_cast<const sockaddr*>(&m_serverAddress),
        sizeof(m_serverAddress)
    );

    if (bytesSent == SOCKET_ERROR_VALUE) {
#ifdef _WIN32
        std::cerr << "[UdpClient] sendto failed. WSA error: "
                  << WSAGetLastError()
                  << "\n";
#else
        std::cerr << "[UdpClient] sendto failed. errno: "
                  << errno
                  << "\n";
#endif
        return;
    }
}

void UdpClient::stop()
{
    sendDisconnect();
    if (m_socket != INVALID_SOCKET_VALUE) {
        closeSocket(m_socket);
        m_socket = INVALID_SOCKET_VALUE;
    }

    if (m_running) {
        shutdownNetwork();
    }

    m_running = false;
    m_connected = false;
    m_playerId = 0;
    
    m_clientNum = 0;
    m_rendezvousMode = false;
    m_natRoomCode = 0;
    m_natHasPeer = false;
    m_natDirectReady = false;
    m_sentHelloToNatPeer = false;

    m_mapTransferId = 0;
    m_mapChunkCount = 0;
    m_mapTotalSize = 0;
    m_mapChunks.clear();
    m_mapChunkReceived.clear();
    m_receivedMapJson.clear();
    m_hasReceivedMapJson = false;
    m_mapTransferComplete = false;
}

bool UdpClient::isRunning() const
{
    return m_running;
}

bool UdpClient::isConnected() const
{
    return m_connected;
}

uint32_t UdpClient::getPlayerId() const
{
    return m_playerId;
}

PlayerStatePacket* UdpClient::getRemotePlayers()
{
    return m_remotePlayers;
}