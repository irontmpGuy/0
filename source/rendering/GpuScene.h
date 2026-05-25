#pragma once

#include <cstdint>

struct GpuVec4 {
    float x = 0.f, y = 0.f, z = 0.f, w = 0.f;
};

struct GpuVec3 {
    float x = 0.f, y = 0.f, z = 0.f;
};


struct GpuUVec4 {
    uint32_t x = 0, y = 0, z = 0, w = 0;
};


struct GpuLight {
    // xyz = local grid-space position, w = visibility range derived from intensity
    GpuVec4 position;
    // rgb = linear light color, w = intensity
    GpuVec4 color;
    // normal and angle for spotlight
    GpuVec3 normal;
    uint32_t angle;
};

struct GpuRtSettings {
    // x = raytracing enabled, y = quality percent, z = frame index, w = light count
    GpuUVec4 flags;
    // x = RT lighting samples per 8x8 tile: 0 off, 1 = 1/64, 64 = full
    // y = temporal history valid, z = debug mode, w = reserved
    GpuUVec4 modes;
    // x = max lights, y = normal bias, z = ambient, w = temporal alpha
    GpuVec4 params;
};

struct GpuCamera {
    GpuVec4 pos;       // local grid-space camera position
    GpuVec4 dir;
    GpuVec4 plane;
    GpuVec4 upPlane;
    GpuVec4 fog;       // renderDistance, fogMax, fogFactor, minFog
    GpuVec4 gridMin;   // xyz = world-space map minimum; w = fogStart
    GpuUVec4 screen;   // width, height, unused, unused
    GpuUVec4 gridSize; // sizeX, sizeY, sizeZ, cellCount
};

struct GpuCell {
    uint32_t firstItem = 0;
    uint32_t itemCount = 0;
    uint32_t pad0 = 0;
    uint32_t pad1 = 0;
};

struct GpuCellItem {
    uint32_t type = 0;   // 0 box, 1 plane, 2 mesh
    uint32_t index = 0;  // box/plane index or mesh-cell index
    uint32_t aux = 0;
    uint32_t pad = 0;
};

struct GpuBox {
    uint32_t textureIndex = 0xFFFFFFFFu;
    uint32_t pad0 = 0;
    uint32_t pad1 = 0;
    uint32_t pad2 = 0;
};

struct GpuPlane {
    GpuVec4 position;
    GpuVec4 normal;
    uint32_t textureIndex = 0xFFFFFFFFu;
    uint32_t pad0 = 0;
    uint32_t pad1 = 0;
    uint32_t pad2 = 0;
};

struct GpuTextureInfo {
    uint32_t offset = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t pad = 0;
};

struct GpuTriangle {
    GpuVec4 p1;       // xyz position, w unused
    GpuVec4 p2;
    GpuVec4 p3;
    GpuVec4 uv12;     // u1, v1, u2, v2
    GpuVec4 uv3;      // u3, v3, unused, unused
    GpuUVec4 meta;    // textureIndex, unused, unused, unused
};

struct GpuBVHNode {
    GpuVec4 aabbMin;
    GpuVec4 aabbMax;
    GpuUVec4 data;    // leftFirst, triCount, unused, unused
};

struct GpuMesh {
    GpuVec4 modelMin;
    GpuVec4 scale;
    GpuVec4 offset;
    GpuVec4 modelCenter;
    GpuVec4 pivot;
    GpuVec4 rot0;
    GpuVec4 rot1;
    GpuVec4 rot2;
    GpuUVec4 ranges;  // triBase, triCount, unused, unused
};

struct GpuMeshCell {
    uint32_t meshIndex = 0;
    uint32_t nodeRoot = 0;
    uint32_t triIdxBase = 0;
    uint32_t pad = 0;
};


struct GpuRemotePlayer {
    GpuVec4 aabbMin;
    GpuVec4 aabbMax;
    GpuVec4 offset;
    GpuVec4 scale;
    GpuVec4 pivot;
    GpuVec4 rot0;
    GpuVec4 rot1;
    GpuVec4 rot2;

    // Per-remote-player animated mesh data. This lets different remote players
    // use different skinned triangle/BVH ranges instead of all sharing the
    // local player's current animation pose.
    GpuVec4 modelMin;
    GpuVec4 modelCenter;
    GpuUVec4 ranges; // x triBase, y triCount, z nodeRoot, w triIdxBase

    GpuUVec4 meta; // x = active, yzw unused

    GpuUVec4 light;
};

struct GpuPlayerMesh {
    GpuVec4 modelMin;
    GpuVec4 modelCenter;
    GpuUVec4 ranges; // x triBase, y triCount, z nodeRoot, w triIdxBase
};
