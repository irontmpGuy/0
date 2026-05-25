#include "UdpServer.h"

#include <algorithm>
#include <iostream>
#include <cstring>
#include <cmath>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#include <io.h>
#else
#include <fcntl.h>
#endif

UdpServer::UdpServer()
{
}

UdpServer::~UdpServer()
{
    stop();
}

bool UdpServer::isValidEndpoint(const sockaddr_in& a) const
{
    return a.sin_family == AF_INET &&
           a.sin_port != 0 &&
           a.sin_addr.s_addr != 0;
}

bool UdpServer::start(uint16_t port)
{
    if (!initNetwork()) {
        std::cerr << "[UdpServer] Failed to initialize network.\n";
        return false;
    }

    m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (m_socket == INVALID_SOCKET_VALUE) {
        std::cerr << "[UdpServer] Failed to create UDP socket.\n";
        shutdownNetwork();
        return false;
    }

    sockaddr_in serverAddress{};
    serverAddress.sin_family      = AF_INET;
    serverAddress.sin_port        = htons(port);
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(m_socket, (sockaddr*)(&serverAddress), sizeof(serverAddress)) == SOCKET_ERROR_VALUE) {
        std::cerr << "[UdpServer] Bind failed.\n";
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
    return true;
}

void UdpServer::update()
{
    if (!m_running)
        return;

    char buffer[1024];

    while (true) {
        sockaddr_in from{};

#ifdef _WIN32
        int fromLength = sizeof(from);
#else
        socklen_t fromLength = sizeof(from);
#endif

        int bytesReceived = recvfrom(
            m_socket, buffer, sizeof(buffer), 0,
            reinterpret_cast<sockaddr*>(&from), &fromLength
        );

        if (bytesReceived == SOCKET_ERROR_VALUE) {
#ifdef _WIN32
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK)
                std::cerr << "[UdpServer] recvfrom failed. WSA error: " << error << "\n";
#else
            if (errno != EWOULDBLOCK && errno != EAGAIN)
                std::cerr << "[UdpServer] recvfrom failed. errno: " << errno << "\n";
#endif
            break;
        }

        if (bytesReceived == 0)
            break;

        handlePacket(buffer, bytesReceived, from);
    }

    updateRendezvousRegistration();
    updateNatPunching();
    updateMapTransfers();
    evictTimedOutClients();
}

void UdpServer::handlePacket(const char* data, int size, const sockaddr_in& from)
{
    if (size < static_cast<int>(sizeof(PacketHeader)))
        return;

    const PacketHeader* header = reinterpret_cast<const PacketHeader*>(data);

    if (header->size != size)
        return;

    if (handleNatPacket(data, size, from))
        return;

    switch (header->type) {
        case PacketType::Hello:
            handleHello(from);
            break;

        case PacketType::PlayerState:
            if (size == sizeof(PlayerStatePacket))
                handlePlayerState(*reinterpret_cast<const PlayerStatePacket*>(data), from);
            break;

        case PacketType::Disconnect:
            handleDisconnect(from);
            break;

        case PacketType::MapRequest:
            if (size == sizeof(MapRequestPacket))
                handleMapRequest(from);
            break;

        case PacketType::MapChunkAck:
            if (size == sizeof(MapChunkAckPacket))
                handleMapChunkAck(*(const MapChunkAckPacket*)data, from);
            break;

        case PacketType::MapAdd:
            if (size == sizeof(MapAddPacket))
                handleMapAdd(*(const MapAddPacket*)data, from);
            break;

        case PacketType::MapRemove:
            if (size == sizeof(MapRemovePacket))
                handleMapRemove(*(const MapRemovePacket*)data, from);
            break;

        default:
            break;
    }
}

void UdpServer::handleHello(const sockaddr_in& from)
{
    if (findClient(from))
        return;

    ClientEndpoint client;
    client.address  = from;
    client.lastSequenceNumber = 0;
    client.playerId = m_nextPlayerId++;
    client.lastSeen = std::chrono::steady_clock::now();
    
    if (m_clientCount < MAX_PLAYERS) {
        m_clients[m_clientCount] = client;
        m_clientCount++;
    } else {
        std::cerr << "[UdpServer] Server is full! Cannot add client.\n";
    }

    WelcomePacket welcome{};
    welcome.header.type = PacketType::Welcome;
    welcome.header.size = sizeof(WelcomePacket);
    welcome.playerId    = client.playerId;
    sendPacket(from, &welcome, sizeof(welcome));

    // Do NOT start the map transfer here. The client explicitly sends
    // MapRequest after Welcome. Starting here as well creates two overlapping
    // transferIds; out-of-order UDP chunks can then reset the client map
    // receiver back and forth during join.

    char ip[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
}

void UdpServer::handlePlayerState(const PlayerStatePacket& packet, const sockaddr_in& from)
{
    ClientEndpoint* client = findClient(from);
    if (!client)
        return;

    if (packet.sequenceNumber <= client->lastSequenceNumber) {
        return;
    }
    client->lastSequenceNumber = packet.sequenceNumber;
    
    client->lastSeen = std::chrono::steady_clock::now();

    PlayerStatePacket outgoing = packet;
    outgoing.playerId          = client->playerId;
    client->lastState          = outgoing;

    // broadcastExcept already guarantees the sender does NOT receive its own state.
    broadcastExcept(from, &outgoing, sizeof(outgoing));
}

void UdpServer::handleDisconnect(const sockaddr_in& from)
{
    for (size_t i = 0; i < static_cast<size_t>(m_clientCount); ++i) {
        if (sameEndpoint(m_clients[i].address, from)) {
            removeClientAt(i, "disconnected");
            return;
        }
    }
}

void UdpServer::handleMapAdd(const MapAddPacket& packet, const sockaddr_in& from)
{
    ClientEndpoint* client = findClient(from);
    if (!client)
        return;

    client->lastSeen = std::chrono::steady_clock::now();

    MapAddPacket outgoing = packet;
    outgoing.sourcePlayerId = client->playerId;

    // The server has no gameplay map. It only relays client-authored edits.
    // Clear the cached JSON so future MapRequest transfers re-read the host
    // client's updated assets/map.json from disk.
    m_mapJson.clear();

    broadcastExcept(from, &outgoing, sizeof(outgoing));
}

void UdpServer::handleMapRemove(const MapRemovePacket& packet, const sockaddr_in& from)
{
    ClientEndpoint* client = findClient(from);
    if (!client)
        return;

    client->lastSeen = std::chrono::steady_clock::now();

    MapRemovePacket outgoing = packet;
    outgoing.sourcePlayerId = client->playerId;

    m_mapJson.clear();

    broadcastExcept(from, &outgoing, sizeof(outgoing));
}


bool UdpServer::loadMapJson()
{
    if (!m_mapJson.empty())
        return true;

    std::ifstream file("assets/map.json", std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[UdpServer] Could not open assets/map.json for map transfer.\n";
        return false;
    }

    std::ostringstream ss;
    ss << file.rdbuf();
    m_mapJson = ss.str();

    if (m_mapJson.empty()) {
        std::cerr << "[UdpServer] assets/map.json is empty.\n";
        return false;
    }

    return true;
}

void UdpServer::handleMapRequest(const sockaddr_in& from)
{
    ClientEndpoint* client = findClient(from);
    if (!client)
        return;

    client->lastSeen = std::chrono::steady_clock::now();
    startMapTransfer(*client);
}

void UdpServer::startMapTransfer(ClientEndpoint& client)
{
    if (!loadMapJson())
        return;

    const uint32_t chunkCount =
        static_cast<uint32_t>((m_mapJson.size() + MAP_TRANSFER_CHUNK_SIZE - 1) / MAP_TRANSFER_CHUNK_SIZE);

    if (chunkCount == 0 || chunkCount > MAP_TRANSFER_MAX_CHUNKS) {
        std::cerr << "[UdpServer] map.json too large for transfer. chunks=" << chunkCount
                  << ", max=" << MAP_TRANSFER_MAX_CHUNKS << "\n";
        return;
    }

    client.mapTransferActive = true;
    client.mapTransferId = m_nextMapTransferId++;
    if (m_nextMapTransferId == 0)
        m_nextMapTransferId = 1;
    client.mapChunkCount = chunkCount;

    for (uint32_t i = 0; i < MAP_TRANSFER_MAX_CHUNKS; ++i)
        client.mapChunkAcked[i] = false;

    client.lastMapSend = std::chrono::steady_clock::now() - std::chrono::seconds(1);

    for (uint32_t i = 0; i < chunkCount; ++i)
        sendMapChunk(client, i);
}

void UdpServer::sendMapChunk(ClientEndpoint& client, uint32_t chunkIndex)
{
    if (!client.mapTransferActive || chunkIndex >= client.mapChunkCount)
        return;

    const uint32_t offset = chunkIndex * MAP_TRANSFER_CHUNK_SIZE;
    const uint32_t remaining = static_cast<uint32_t>(m_mapJson.size()) - offset;
    const uint16_t payloadSize = static_cast<uint16_t>((std::min)(remaining, MAP_TRANSFER_CHUNK_SIZE));

    MapChunkPacket packet{};
    packet.header.type = PacketType::MapChunk;
    packet.header.size = sizeof(MapChunkPacket);
    packet.transferId = client.mapTransferId;
    packet.chunkIndex = chunkIndex;
    packet.chunkCount = client.mapChunkCount;
    packet.totalSize = static_cast<uint32_t>(m_mapJson.size());
    packet.payloadSize = payloadSize;
    std::memcpy(packet.payload, m_mapJson.data() + offset, payloadSize);

    sendPacket(client.address, &packet, sizeof(packet));
}

void UdpServer::handleMapChunkAck(const MapChunkAckPacket& packet, const sockaddr_in& from)
{
    ClientEndpoint* client = findClient(from);
    if (!client || !client->mapTransferActive)
        return;

    client->lastSeen = std::chrono::steady_clock::now();

    if (packet.transferId != client->mapTransferId)
        return;

    if (packet.chunkIndex >= client->mapChunkCount)
        return;

    client->mapChunkAcked[packet.chunkIndex] = true;

    bool allAcked = true;
    for (uint32_t i = 0; i < client->mapChunkCount; ++i) {
        if (!client->mapChunkAcked[i]) {
            allAcked = false;
            break;
        }
    }

    if (allAcked) {
        MapDonePacket done{};
        done.header.type = PacketType::MapDone;
        done.header.size = sizeof(done);
        done.transferId = client->mapTransferId;
        done.totalSize = static_cast<uint32_t>(m_mapJson.size());

        sendPacket(client->address, &done, sizeof(done));
        client->mapTransferActive = false;
    }
}

void UdpServer::updateMapTransfers()
{
    auto now = std::chrono::steady_clock::now();

    for (ClientEndpoint& client : m_clients) {
        if (!client.mapTransferActive)
            continue;

        float elapsed = std::chrono::duration<float>(now - client.lastMapSend).count();
        if (elapsed < 0.10f)
            continue;

        client.lastMapSend = now;

        for (uint32_t i = 0; i < client.mapChunkCount; ++i) {
            if (!client.mapChunkAcked[i])
                sendMapChunk(client, i);
        }
    }
}


void UdpServer::evictTimedOutClients()
{
    auto now = std::chrono::steady_clock::now();

    size_t i = 0;
    while (i < static_cast<size_t>(m_clientCount)) {
        float elapsed = std::chrono::duration<float>(now - m_clients[i].lastSeen).count();

        if (elapsed > TIMEOUT_SECONDS) {
            removeClientAt(i, "timed out");
            continue;
        }

        ++i;
    }
}

void UdpServer::removeClientAt(size_t index, const char* reason)
{
    if (index >= static_cast<size_t>(m_clientCount))
        return;

    const uint32_t leftPlayerId = m_clients[index].playerId;

    std::cerr << "[UdpServer] Client " << leftPlayerId << " " << reason << "\n";

    for (size_t i = index + 1; i < static_cast<size_t>(m_clientCount); ++i) {
        m_clients[i - 1] = m_clients[i];
    }

    --m_clientCount;

    broadcastLeave(leftPlayerId);
}

void UdpServer::broadcastLeave(uint32_t playerId)
{
    DisconnectPacket packet{};
    packet.header.type = PacketType::Disconnect;
    packet.header.size = sizeof(packet);
    packet.playerId = playerId;

    broadcastAll(&packet, sizeof(packet));
}

void UdpServer::sendPacket(const sockaddr_in& to, const void* data, int size)
{
    if (!isValidEndpoint(to)) return;

    sendUdpPacketNat(m_socket, to, data, size, "UdpServer");
}


void UdpServer::broadcastExcept(const sockaddr_in& except, const void* data, int size)
{
    for (const ClientEndpoint& c : m_clients) {
        if (!sameEndpoint(c.address, except))
            sendPacket(c.address, data, size);
    }
}

void UdpServer::broadcastAll(const void* data, int size)
{
    for (const ClientEndpoint& c : m_clients)
        sendPacket(c.address, data, size);
}

bool UdpServer::sameEndpoint(const sockaddr_in& a, const sockaddr_in& b) const
{
    return a.sin_addr.s_addr == b.sin_addr.s_addr &&
           a.sin_port        == b.sin_port;
}

ClientEndpoint* UdpServer::findClient(const sockaddr_in& from)
{
    for (ClientEndpoint& c : m_clients)
        if (sameEndpoint(c.address, from))
            return &c;
    return nullptr;
}


bool UdpServer::registerWithRendezvous(const std::string& rendezvousIp, uint16_t rendezvousPort, uint32_t roomCode)
{
    if (!m_running || m_socket == INVALID_SOCKET_VALUE) {
        std::cerr << "[UdpServer/NAT] Cannot register with rendezvous before start().\n";
        return false;
    }

    roomCode = makeRoomCode(roomCode);

    if (!parseIpv4Endpoint(rendezvousIp, rendezvousPort, m_rendezvousAddress)) {
        std::cerr << "[UdpServer/NAT] Invalid rendezvous endpoint.\n";
        return false;
    }

    m_rendezvousEnabled = true;
    m_natRoomCode = roomCode;
    m_natHasPeer = false;
    m_natDirectReady = false;
    m_lastRendezvousRegister = std::chrono::steady_clock::now() - std::chrono::seconds(10);

    sendRendezvousRegister(PACKET_RENDEZVOUS_REGISTER_HOST);
    return true;
}

bool UdpServer::handleNatPacket(const char* data, int size, const sockaddr_in& from)
{
    const PacketHeader* header = reinterpret_cast<const PacketHeader*>(data);

    if (header->type == PACKET_RENDEZVOUS_PEER_INFO) {
        if (size != static_cast<int>(sizeof(RendezvousPeerInfoPacket))) {
            std::cerr << "[UdpServer/NAT] Bad PeerInfo size from " << endpointToString(from) << "\n";
            return true;
        }
        handleRendezvousPeerInfo(*reinterpret_cast<const RendezvousPeerInfoPacket*>(data));
        return true;
    }

    if (header->type == PACKET_NAT_PUNCH) {
        if (size != static_cast<int>(sizeof(NatPunchPacket))) {
            std::cerr << "[UdpServer/NAT] Bad Punch size from " << endpointToString(from) << "\n";
            return true;
        }
        handleNatPunch(*reinterpret_cast<const NatPunchPacket*>(data), from);
        return true;
    }

    if (header->type == PACKET_NAT_PUNCH_ACK) {
        if (size != static_cast<int>(sizeof(NatPunchPacket))) {
            std::cerr << "[UdpServer/NAT] Bad PunchAck size from " << endpointToString(from) << "\n";
            return true;
        }
        handleNatPunchAck(*reinterpret_cast<const NatPunchPacket*>(data), from);
        return true;
    }

    if (header->type == PACKET_RENDEZVOUS_ERROR) {
        if (size != static_cast<int>(sizeof(RendezvousErrorPacket))) {
            std::cerr << "[UdpServer/NAT] Bad RendezvousError size from " << endpointToString(from) << "\n";
            return true;
        }
        handleRendezvousError(*reinterpret_cast<const RendezvousErrorPacket*>(data), from);
        return true;
    }

    return false;
}

void UdpServer::handleRendezvousPeerInfo(const RendezvousPeerInfoPacket& packet)
{
    uint32_t roomCode = ntohl(packet.roomCodeNetworkOrder);
    if (!m_rendezvousEnabled || roomCode != m_natRoomCode) {
        std::cerr << "[UdpServer/NAT] Ignored PeerInfo for wrong room. got="
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
    m_natHasPeer = true;
    m_natDirectReady = false;

    auto now = std::chrono::steady_clock::now();
    m_lastNatPunch = now - std::chrono::seconds(10);
    m_natPunchUntil = now + std::chrono::milliseconds(static_cast<int>(NAT_PUNCH_DURATION_SECONDS * 1000.0f));

    sendNatPunch(PACKET_NAT_PUNCH);
}

void UdpServer::handleNatPunch(const NatPunchPacket& packet, const sockaddr_in& from)
{
    uint32_t roomCode = ntohl(packet.roomCodeNetworkOrder);
    if (!m_rendezvousEnabled || roomCode != m_natRoomCode) {
        std::cerr << "[UdpServer/NAT] Ignored Punch for wrong room from "
                  << endpointToString(from) << "\n";
        return;
    }

    if (!m_natHasPeer || !sameEndpointNat(m_natPeerAddress, from)) {
        m_natPeerAddress = from;
        m_natHasPeer = true;
    }

    m_natDirectReady = true;
    sendNatPunch(PACKET_NAT_PUNCH_ACK);
}

void UdpServer::handleNatPunchAck(const NatPunchPacket& packet, const sockaddr_in& from)
{
    uint32_t roomCode = ntohl(packet.roomCodeNetworkOrder);
    if (!m_rendezvousEnabled || roomCode != m_natRoomCode) {
        std::cerr << "[UdpServer/NAT] Ignored PunchAck for wrong room from "
                  << endpointToString(from) << "\n";
        return;
    }

    m_natPeerAddress = from;
    m_natHasPeer = true;
    m_natDirectReady = true;
}

void UdpServer::handleRendezvousError(const RendezvousErrorPacket& packet, const sockaddr_in& from)
{
    uint32_t roomCode = ntohl(packet.roomCodeNetworkOrder);
    uint32_t errorCode = ntohl(packet.errorCodeNetworkOrder);
    std::cerr << "[UdpServer/NAT] Rendezvous error from " << endpointToString(from)
              << ". room=" << roomCode
              << ", code=" << errorCode
              << ", message=" << packet.message << "\n";
}

void UdpServer::updateRendezvousRegistration()
{
    if (!m_rendezvousEnabled || m_socket == INVALID_SOCKET_VALUE)
        return;

    auto now = std::chrono::steady_clock::now();
    float elapsed = std::chrono::duration<float>(now - m_lastRendezvousRegister).count();

    if (elapsed >= RENDEZVOUS_REGISTER_INTERVAL_SECONDS) {
        sendRendezvousRegister(PACKET_RENDEZVOUS_KEEPALIVE);
        m_lastRendezvousRegister = now;
    }
}

void UdpServer::updateNatPunching()
{
    if (!m_natHasPeer || m_natDirectReady)
        return;

    auto now = std::chrono::steady_clock::now();
    if (now > m_natPunchUntil) {
        std::cerr << "[UdpServer/NAT] Punch timeout. Could not open direct path to "
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

void UdpServer::sendRendezvousRegister(PacketType type)
{
    RendezvousRegisterHostPacket packet{};
    packet.header.type = type;
    packet.header.size = sizeof(packet);
    packet.roomCodeNetworkOrder = htonl(m_natRoomCode);

    sendUdpPacketNat(m_socket, m_rendezvousAddress, &packet, sizeof(packet), "UdpServer/NAT");
}

void UdpServer::sendNatPunch(PacketType type)
{
    if (!m_natHasPeer)
        return;

    NatPunchPacket packet{};
    packet.header.type = type;
    packet.header.size = sizeof(packet);
    packet.roomCodeNetworkOrder = htonl(m_natRoomCode);
    packet.fromHost = 1;

    sendUdpPacketNat(m_socket, m_natPeerAddress, &packet, sizeof(packet), "UdpServer/NAT");
}

void UdpServer::stop()
{
    if (m_socket != INVALID_SOCKET_VALUE) {
        closeSocket(m_socket);
        m_socket = INVALID_SOCKET_VALUE;
    }

    if (m_running)
        shutdownNetwork();

    m_running = false;
}

bool UdpServer::isRunning() const
{
    return m_running;
}