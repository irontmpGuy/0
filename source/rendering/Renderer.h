#pragma once

#include <cstdint>
#include <memory>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "Framebuffer.h"
#include "Player.h"
#include "Map.h"
#include "Packet.h"
#include "Mat3.h"
#include "Vec3f.h"
#include "UdpServer.h"
#include "GpuScene.h"
#include "VulkanOverlay.h"

class VulkanComputeRenderer;

struct RemotePlayerGPUData {
    Mat3  rot;
    Vec3f offset;
    Vec3f scale;
    Vec3f pivot;

    Vec3f aabbMin;
    Vec3f aabbMax;
    bool  active = false;
};

struct FogConfig {
    float renderDistance;
    float fogMax;
    float fogFactor;
    float minFog;
    float fogStart;
};

static constexpr float RENDER_DISTANCE = 50.f;
static constexpr float FOGMAX          = 50.f;
static constexpr float FOGFACTOR       = 0.f;
static constexpr float MINFOG          = 0.f;
static constexpr float FOGSTART        = 0.f;

class Renderer {
public:
    Renderer(int screenW, int screenH, HWND hwnd);
    ~Renderer();

    bool renderFrame(Framebuffer& fb, const Player& player, const Map& map,
                     PlayerStatePacket* remotePlayers, int numRemotePlayers, float dt,
                     bool menuOverlayEnabled = false,
                     const MenuOverlayRect* menuOverlayRects = nullptr,
                     uint32_t menuOverlayRectCount = 0,
                     uint32_t menuOverlayWindowW = 1,
                     uint32_t menuOverlayWindowH = 1);

    // New raster path. renderFrame() remains the old raytracing/compute path.
    // Switch the caller to rasterizeFrame(...) when you want hardware rasterisation.
    bool rasterizeFrame(Framebuffer& fb, const Player& player, const Map& map,
                        PlayerStatePacket* remotePlayers, int numRemotePlayers, float dt,
                        bool menuOverlayEnabled = false,
                        const MenuOverlayRect* menuOverlayRects = nullptr,
                        uint32_t menuOverlayRectCount = 0,
                        uint32_t menuOverlayWindowW = 1,
                        uint32_t menuOverlayWindowH = 1);

    void renderBg(Framebuffer& fb, const Texture& texture);

    static constexpr int MAX_PLAYERS = UdpServer::MAX_PLAYERS;

    void resize(int width, int height);

    void setRaytracingEnabled(bool enabled);
    void setRaytracingQualityPercent(int percent);
    void setDustDensityPercent(int percent);
    void setDustBrightnessPercent(int percent);
    void setEditorMode(bool enabled);
    bool isRaytracingEnabled() const { return m_raytracingEnabled; }
    int  getRaytracingQualityPercent() const { return m_raytracingQualityPercent; }
    int  getDustDensityPercent() const { return m_dustDensityPercent; }
    int  getDustBrightnessPercent() const { return m_dustBrightnessPercent; }

private:
    bool renderAll(Framebuffer& fb, const Player& player, const Map& map,
                   bool menuOverlayEnabled,
                   const MenuOverlayRect* menuOverlayRects,
                   uint32_t menuOverlayRectCount,
                   uint32_t menuOverlayWindowW,
                   uint32_t menuOverlayWindowH);

    bool rasterizeAll(Framebuffer& fb, const Player& player, const Map& map,
                      bool menuOverlayEnabled,
                      const MenuOverlayRect* menuOverlayRects,
                      uint32_t menuOverlayRectCount,
                      uint32_t menuOverlayWindowW,
                      uint32_t menuOverlayWindowH);

    void updateRemotePlayerAnimations(const Mesh* sourceMesh,
                                      PlayerStatePacket* packets, int count, float dt);

    Mesh* ensureRemoteMeshForSlot(int slot, uint32_t playerId, const Mesh* sourceMesh);

    void updateGpuPlayers(const Player& player, const Map& map,
                          PlayerStatePacket* packets, int count);

    int       m_screenW = 0;
    int       m_screenH = 0;
    GpuRemotePlayer* m_gpuPlayers = nullptr;
    int                  m_numRemotePlayers = 0;

    Mesh*    m_remoteMeshes[MAX_PLAYERS] = {};
    uint32_t m_remotePlayerIds[MAX_PLAYERS] = {};
    Vec3f    m_remotePrevPos[MAX_PLAYERS] = {};
    bool     m_remotePrevValid[MAX_PLAYERS] = {};
    const Mesh* m_remoteMeshPtrs[MAX_PLAYERS] = {};

    std::unique_ptr<VulkanComputeRenderer> m_vkRenderer;
    bool m_vkReady = false;

    // UI-controlled flags only for now. They do not change the render path yet.
    bool m_raytracingEnabled = false;
    int  m_raytracingQualityPercent = 100;
    int  m_dustDensityPercent = 100;
    int  m_dustBrightnessPercent = 35;
    bool m_editorMode = false;
};
