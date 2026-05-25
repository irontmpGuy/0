#pragma once

#include "Packet.h"

#include <cstdint>
#include <cstring>
#include <string>

static constexpr int MAP_EDIT_ID_SIZE        = 64;
static constexpr int MAP_EDIT_PATH_SIZE      = 192;
static constexpr int MAP_EDIT_TEXTURE_SIZE   = 192;
static constexpr int MAP_EDIT_COLLISION_SIZE = 16;

enum class MapEditObjectType : uint8_t {
    Aabb       = 0,
    Plane      = 1,
    Mesh       = 2,
    Light = 3
};

struct MapObjectEdit {
    uint8_t objectType = static_cast<uint8_t>(MapEditObjectType::Aabb);
    uint8_t persistToJson = 1;
    uint16_t reserved = 0;

    char id[MAP_EDIT_ID_SIZE]{};
    char path[MAP_EDIT_PATH_SIZE]{};
    char texture[MAP_EDIT_TEXTURE_SIZE]{};
    char collision[MAP_EDIT_COLLISION_SIZE]{};

    float corner0[3]  = {0.f, 0.f, 0.f};
    float corner1[3]  = {0.f, 0.f, 0.f};
    float normal[3]   = {0.f, 1.f, 0.f};
    float position[3] = {0.f, 0.f, 0.f};
    float color[3]    = {1.f, 1.f, 1.f};
    float rotation[3] = {0.f, 0.f, 0.f};
    float scale[3]    = {0.f, 0.f, 0.f};

    float intensity = 1.f;
    float radius    = 8.f;
    float angle     = 0.f;
};

struct MapAddPacket {
    PacketHeader header{};
    uint32_t sourcePlayerId = 0;
    uint32_t sequenceNumber = 0;
    MapObjectEdit object{};
};

struct MapRemovePacket {
    PacketHeader header{};
    uint32_t sourcePlayerId = 0;
    uint32_t sequenceNumber = 0;
    char objectId[MAP_EDIT_ID_SIZE]{};
    uint8_t persistToJson = 1;
};

inline void mapEditSetString(char* dst, size_t dstSize, const std::string& value) {
    if (!dst || dstSize == 0) return;
    std::memset(dst, 0, dstSize);
    std::strncpy(dst, value.c_str(), dstSize - 1);
}

inline std::string mapEditGetString(const char* src, size_t srcSize) {
    if (!src || srcSize == 0) return {};
    size_t n = 0;
    while (n < srcSize && src[n] != '\0') ++n;
    return std::string(src, n);
}

static_assert(sizeof(MapAddPacket) <= 1024, "MapAddPacket must fit UdpClient/UdpServer receive buffers.");
static_assert(sizeof(MapRemovePacket) <= 1024, "MapRemovePacket must fit UdpClient/UdpServer receive buffers.");
