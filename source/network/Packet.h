#pragma once

#include <cstdint>

enum class PacketType : uint8_t {
    Hello = 1,
    Welcome = 2,
    PlayerState = 3,
    Disconnect = 4,

    MapRequest = 20,
    MapChunk = 21,
    MapChunkAck = 22,
    MapDone = 23,

    MapAdd = 100,
    MapRemove = 101
};

struct PacketHeader {
    PacketType type;
    uint16_t size;
};

struct HelloPacket {
    PacketHeader header;
};

struct WelcomePacket {
    PacketHeader header;
    uint32_t playerId;
};

struct DisconnectPacket {
    PacketHeader header;
    uint32_t playerId;
};

struct PlayerStatePacket {
    PacketHeader header;

    uint32_t playerId;

    uint32_t sequenceNumber;

    float x;
    float y;
    float z;

    float dirX;
    float dirY;
    float dirZ;

    float vX;
    float vY;
    float vZ;

    float pitch;
    float height;

    float speedFactor;

    bool light_on;
};

static constexpr uint32_t MAP_TRANSFER_CHUNK_SIZE = 900;
static constexpr uint32_t MAP_TRANSFER_MAX_CHUNKS = 256;

struct MapRequestPacket {
    PacketHeader header;
};

struct MapChunkPacket {
    PacketHeader header;
    uint32_t transferId;
    uint32_t chunkIndex;
    uint32_t chunkCount;
    uint32_t totalSize;
    uint16_t payloadSize;
    char payload[MAP_TRANSFER_CHUNK_SIZE];
};

struct MapChunkAckPacket {
    PacketHeader header;
    uint32_t transferId;
    uint32_t chunkIndex;
};

struct MapDonePacket {
    PacketHeader header;
    uint32_t transferId;
    uint32_t totalSize;
};
