#include "Renderer.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <new>

#include "Mesh.h"
#include "Triangle.h"
#include "Mat3.h"
#include "VulkanComputeRenderer.h"
#include "GpuScene.h"

static GpuVec4 gv4r(float x, float y, float z, float w = 0.f) { return {x,y,z,w}; }
static GpuUVec4 guv4r(uint32_t x, uint32_t y, uint32_t z, uint32_t w) { return {x,y,z,w}; }

Renderer::Renderer(int screenW, int screenH, HWND hwnd)
    : m_screenW(screenW)
    , m_screenH(screenH)
    , m_vkRenderer(std::make_unique<VulkanComputeRenderer>())
{
    m_gpuPlayers = new (std::nothrow) GpuRemotePlayer[MAX_PLAYERS];
    if (!m_gpuPlayers) {
        std::cerr << "CRITICAL: gpuPlayers host alloc failed!\n";
        std::exit(EXIT_FAILURE);
    }
    m_vkReady = m_vkRenderer->init(hwnd, m_screenW, m_screenH);
    if (!m_vkReady) {
        std::cerr << "[Renderer] Vulkan compute renderer failed: "
                  << m_vkRenderer->lastError() << "\n";
        std::cerr << "[Renderer] No CPU raycast fallback is used in this Vulkan-transition build.\n";
    } else {
        std::cout << "[Renderer] Vulkan compute renderer ready ("
                  << m_screenW << "x" << m_screenH << ")\n";
    }
}

Renderer::~Renderer()
{
    for (int i = 0; i < MAX_PLAYERS; ++i) {
        delete m_remoteMeshes[i];
        m_remoteMeshes[i] = nullptr;
    }
    delete[] m_gpuPlayers;
}

void Renderer::resize(int width, int height)
{
    if (width == m_screenW && height == m_screenH) return;

    m_screenW = width;
    m_screenH = height;

    if (m_vkRenderer && m_vkReady) {
        m_vkReady = m_vkRenderer->resize(width, height);
        if (!m_vkReady) {
            std::cerr << "[Renderer] Vulkan resize failed: " << m_vkRenderer->lastError() << "\n";
        }
    }
}

void Renderer::setRaytracingEnabled(bool enabled)
{
    if (m_raytracingEnabled == enabled) return;
    m_raytracingEnabled = enabled;
    if (m_vkRenderer) m_vkRenderer->setRaytracingSettings(m_raytracingEnabled, m_raytracingQualityPercent, m_dustDensityPercent, m_dustBrightnessPercent);
}

void Renderer::setRaytracingQualityPercent(int percent)
{
    percent = std::clamp(percent, 0, 100);
    if (m_raytracingQualityPercent == percent) return;
    m_raytracingQualityPercent = percent;
    if (m_vkRenderer) m_vkRenderer->setRaytracingSettings(m_raytracingEnabled, m_raytracingQualityPercent, m_dustDensityPercent, m_dustBrightnessPercent);
}

void Renderer::setDustDensityPercent(int percent)
{
    percent = std::clamp(percent, 0, 100);
    if (m_dustDensityPercent == percent) return;
    m_dustDensityPercent = percent;
    if (m_vkRenderer) m_vkRenderer->setRaytracingSettings(m_raytracingEnabled, m_raytracingQualityPercent, m_dustDensityPercent, m_dustBrightnessPercent);
}

void Renderer::setDustBrightnessPercent(int percent)
{
    percent = std::clamp(percent, 0, 100);
    if (m_dustBrightnessPercent == percent) return;
    m_dustBrightnessPercent = percent;
    if (m_vkRenderer) m_vkRenderer->setRaytracingSettings(m_raytracingEnabled, m_raytracingQualityPercent, m_dustDensityPercent, m_dustBrightnessPercent);
}

void Renderer::setEditorMode(bool enabled)
{
    if (m_editorMode == enabled) return;
    m_editorMode = enabled;
    if (m_vkRenderer) m_vkRenderer->setEditorMode(m_editorMode);
}

bool Renderer::renderFrame(Framebuffer& fb, const Player& player, const Map& map,
                           PlayerStatePacket* remotePlayers, int numRemotePlayers, float dt,
                           bool menuOverlayEnabled,
                           const MenuOverlayRect* menuOverlayRects,
                           uint32_t menuOverlayRectCount,
                           uint32_t menuOverlayWindowW,
                           uint32_t menuOverlayWindowH)
{
    static int  frames = 1;
    static auto start  = std::chrono::high_resolution_clock::now();

    if (player.mesh) player.mesh->tickAnimation(dt);

    if (map.mapData) {
        for (int i = 0; i < map.mapData->numObjects; i++) {
            if (!map.mapData->pageMem[i]) continue;
            int type = *(int*)map.mapData->pageMem[i];
            if (type == 2) {
                Mesh* mesh = (Mesh*)map.mapData->pageMem[i];
                if (mesh->skeleton && mesh->skinCtx) mesh->tickAnimation(dt);
            }
        }
    }

    updateRemotePlayerAnimations(player.mesh, remotePlayers, numRemotePlayers, dt);
    updateGpuPlayers(player, map, remotePlayers, numRemotePlayers);
    const bool presented = renderAll(
        fb, player, map,
        menuOverlayEnabled,
        menuOverlayRects,
        menuOverlayRectCount,
        menuOverlayWindowW,
        menuOverlayWindowH
    );

    auto  end = std::chrono::high_resolution_clock::now();
    float ms  = std::chrono::duration<float, std::milli>(end - start).count();
    if (ms > 5000.f) {
        std::cout << "[FPS] " << frames / (ms / 1000.f) << "\n";
        frames = 0;
        start  = std::chrono::high_resolution_clock::now();
    }
    ++frames;
    return presented;
}


bool Renderer::rasterizeFrame(Framebuffer& fb, const Player& player, const Map& map,
                              PlayerStatePacket* remotePlayers, int numRemotePlayers, float dt,
                              bool menuOverlayEnabled,
                              const MenuOverlayRect* menuOverlayRects,
                              uint32_t menuOverlayRectCount,
                              uint32_t menuOverlayWindowW,
                              uint32_t menuOverlayWindowH)
{
    static int  frames = 1;
    static auto start  = std::chrono::high_resolution_clock::now();

    if (player.mesh) player.mesh->tickAnimation(dt);

    if (map.mapData) {
        for (int i = 0; i < map.mapData->numObjects; i++) {
            if (!map.mapData->pageMem[i]) continue;
            int type = *(int*)map.mapData->pageMem[i];
            if (type == 2) {
                Mesh* mesh = (Mesh*)map.mapData->pageMem[i];
                if (mesh->skeleton && mesh->skinCtx) mesh->tickAnimation(dt);
            }
        }
    }

    updateRemotePlayerAnimations(player.mesh, remotePlayers, numRemotePlayers, dt);
    updateGpuPlayers(player, map, remotePlayers, numRemotePlayers);
    const bool presented = rasterizeAll(
        fb, player, map,
        menuOverlayEnabled,
        menuOverlayRects,
        menuOverlayRectCount,
        menuOverlayWindowW,
        menuOverlayWindowH
    );

    auto  end = std::chrono::high_resolution_clock::now();
    float ms  = std::chrono::duration<float, std::milli>(end - start).count();
    if (ms > 5000.f) {
        std::cout << "[FPS raster] " << frames / (ms / 1000.f) << "\n";
        frames = 0;
        start  = std::chrono::high_resolution_clock::now();
    }
    ++frames;
    return presented;
}

static bool meshBlendOrPlay(Mesh* mesh, const char* lower, const char* upper, float fade, float speed = 1.f)
{
    if (!mesh) return false;
    if (mesh->hasAnimation(lower)) return mesh->blendToAnimation(lower, fade, true, speed);
    if (mesh->hasAnimation(upper)) return mesh->blendToAnimation(upper, fade, true, speed);
    return false;
}

Mesh* Renderer::ensureRemoteMeshForSlot(int slot, uint32_t playerId, const Mesh* sourceMesh)
{
    if (slot < 0 || slot >= MAX_PLAYERS || playerId == 0 || !sourceMesh) return nullptr;

    if (m_remoteMeshes[slot] && m_remotePlayerIds[slot] == playerId) {
        return m_remoteMeshes[slot];
    }

    delete m_remoteMeshes[slot];
    m_remoteMeshes[slot] = sourceMesh->cloneInstance();

    if (m_remoteMeshes[slot] && m_remoteMeshes[slot]->skeleton) {
        std::cout << "[RemoteAnim] animations:";
        for (const auto& a : m_remoteMeshes[slot]->skeleton->animations) {
            std::cout << " [" << a.name << " dur=" << a.duration << "]";
        }
        std::cout << "\n";
    }

    m_remotePlayerIds[slot] = playerId;
    m_remotePrevValid[slot] = false;

    if (m_remoteMeshes[slot]) {
        if (!meshBlendOrPlay(m_remoteMeshes[slot], "idle", "Idle", 0.0f)) {
            if (m_remoteMeshes[slot]->skeleton && !m_remoteMeshes[slot]->skeleton->animations.empty()) {
                m_remoteMeshes[slot]->playAnimation(m_remoteMeshes[slot]->skeleton->animations[0].name);
            }
        }
    }

    return m_remoteMeshes[slot];
}

void Renderer::updateRemotePlayerAnimations(const Mesh* sourceMesh,
                                            PlayerStatePacket* packets, int count, float dt)
{

    static float walkSpeed;

    for (int i = 0; i < MAX_PLAYERS; ++i) m_remoteMeshPtrs[i] = nullptr;
    if (!sourceMesh || !packets || count <= 0) return;

    const int n = count < MAX_PLAYERS ? count : MAX_PLAYERS;
    for (int i = 0; i < n; ++i) {
        const PlayerStatePacket& pkt = packets[i];
        if (pkt.playerId == 0) {
            m_remotePrevValid[i] = false;
            continue;
        }

        Mesh* mesh = ensureRemoteMeshForSlot(i, (uint32_t)pkt.playerId, sourceMesh);
        if (!mesh) continue;

        const Vec3f pos = {pkt.x, pkt.y, pkt.z};
        float speedSq = 0.f;
        if (m_remotePrevValid[i] && dt > 1e-6f) {
            Vec3f d = {pos.x - m_remotePrevPos[i].x, pos.y - m_remotePrevPos[i].y, pos.z - m_remotePrevPos[i].z};
            // Only horizontal movement drives walk. Pure vertical velocity keeps idle.
            speedSq = (d.x*d.x + d.z*d.z) / (dt * dt);
        }
        m_remotePrevPos[i] = pos;
        m_remotePrevValid[i] = true;

        float speed = std::sqrt(pkt.vX * pkt.vX + pkt.vZ * pkt.vZ);
        if (speed > 1e-4f) {
            walkSpeed = speed;
        }

        if (speed > 0.05f) {
            meshBlendOrPlay(mesh, "walk", "Walk", 0.1f, walkSpeed); // 2 * speed
        } else {
            meshBlendOrPlay(mesh, "idle", "Idle", 1.0f - 0.2 * walkSpeed, 0.8f); // 0.82x speed
        }

        mesh->tickAnimation(dt);
        m_remoteMeshPtrs[i] = mesh;
    }
}

void Renderer::updateGpuPlayers(const Player& player, const Map& map,
                                PlayerStatePacket* packets, int count)
{
    m_numRemotePlayers = 0;
    if (!map.mapData || count <= 0) return;

    const float mapMinX = map.mapData->minX;
    const float mapMinY = map.mapData->minY;
    const float mapMinZ = map.mapData->minZ;

    int n = count < MAX_PLAYERS ? count : MAX_PLAYERS;
    for (int i = 0; i < n; i++) {
        const PlayerStatePacket& pkt = packets[i];
        //if (pkt.playerId == 0) {
        //    m_gpuPlayers[i].meta = guv4r(0u, 0u, 0u, 0u);
        //    m_gpuPlayers[i].light = guv4r(0u, 0u, 0u, 0u);
        //    continue;
        //}

        const Mesh* mesh = m_remoteMeshPtrs[i] ? m_remoteMeshPtrs[i] : player.mesh;
        if (!mesh || !mesh->d_fullNodes || mesh->numFullNodes == 0) {
            m_gpuPlayers[i].meta = guv4r(0u, 0u, 0u, 0u);
            m_gpuPlayers[i].light = guv4r(0u, 0u, 0u, 0u);
            continue;
        }

        const Vec3f& sc = mesh->scale;
        const Vec3f& mn = mesh->modelMin;
        const Vec3f& mc = mesh->modelCenter;
        const Vec3f mMin = mesh->d_fullNodes[0].aabbMin;
        const Vec3f mMax = mesh->d_fullNodes[0].aabbMax;

        Mat3 rot = Mat3::fromYawDirection({pkt.dirX, pkt.dirY, pkt.dirZ});

        const Vec3f& ms = player.MESH_SCALE;
        Vec3f effSc = { sc.x * ms.x, sc.y * ms.y, sc.z * ms.z };

        Vec3f pv = {
            effSc.x * (mc.x - mn.x),
            effSc.y * (mc.y - mn.y),
            effSc.z * (mc.z - mn.z)
        };

        const Vec3f& mo = player.MESH_OFFSET;
        Vec3f off = {
            (pkt.x - mapMinX) - pv.x + mo.x,
            (pkt.y - mapMinY)        + mo.y,
            (pkt.z - mapMinZ) - pv.z + mo.z
        };

        m_gpuPlayers[i].rot0   = gv4r(rot.m[0], rot.m[1], rot.m[2], 0.f);
        m_gpuPlayers[i].rot1   = gv4r(rot.m[3], rot.m[4], rot.m[5], 0.f);
        m_gpuPlayers[i].rot2   = gv4r(rot.m[6], rot.m[7], rot.m[8], 0.f);
        m_gpuPlayers[i].offset = gv4r(off.x, off.y, off.z, 0.f);
        m_gpuPlayers[i].scale  = gv4r(effSc.x, effSc.y, effSc.z, 0.f);
        m_gpuPlayers[i].pivot  = gv4r(pv.x, pv.y, pv.z, 0.f);
        m_gpuPlayers[i].meta   = guv4r(1u, 0u, 0u, 0u);

        m_gpuPlayers[i].light = guv4r(pkt.light_on ? 1u : 0u, 0u, 0u, 0u);

        Vec3f wMin = {1e30f,1e30f,1e30f}, wMax = {-1e30f,-1e30f,-1e30f};
        for (int j = 0; j < 8; j++) {
            Vec3f c = { j&1 ? mMax.x : mMin.x,
                        j&2 ? mMax.y : mMin.y,
                        j&4 ? mMax.z : mMin.z };
            Vec3f s = { (c.x-mn.x)*effSc.x - pv.x,
                        (c.y-mn.y)*effSc.y - pv.y,
                        (c.z-mn.z)*effSc.z - pv.z };
            Vec3f r = rot.mul(s);
            Vec3f w = { r.x + pv.x + off.x,
                        r.y + pv.y + off.y,
                        r.z + pv.z + off.z };
            if (w.x<wMin.x) wMin.x=w.x; if (w.x>wMax.x) wMax.x=w.x;
            if (w.y<wMin.y) wMin.y=w.y; if (w.y>wMax.y) wMax.y=w.y;
            if (w.z<wMin.z) wMin.z=w.z; if (w.z>wMax.z) wMax.z=w.z;
        }
        constexpr float PAD = 0.15f;
        m_gpuPlayers[i].aabbMin = gv4r(wMin.x-PAD, wMin.y-PAD, wMin.z-PAD, 0.f);
        m_gpuPlayers[i].aabbMax = gv4r(wMax.x+PAD, wMax.y+PAD, wMax.z+PAD, 0.f);
        m_gpuPlayers[i].modelMin = gv4r(mesh->modelMin.x, mesh->modelMin.y, mesh->modelMin.z, 0.f);
        m_gpuPlayers[i].modelCenter = gv4r(mesh->modelCenter.x, mesh->modelCenter.y, mesh->modelCenter.z, 0.f);
    }
    m_numRemotePlayers = n;
}

void Renderer::renderBg(Framebuffer& fb, const Texture& texture)
{
    for (int y = 0; y < m_screenH; ++y) {
        for (int x = 0; x < m_screenW; ++x) {
            int tx = (x * texture.width)  / m_screenW;
            int ty = (y * texture.height) / m_screenH;
            fb.setPixel(x, y, texture.getPixel(tx, ty));
        }
    }
}

bool Renderer::renderAll(Framebuffer& fb, const Player& player, const Map& map,
                         bool menuOverlayEnabled,
                         const MenuOverlayRect* menuOverlayRects,
                         uint32_t menuOverlayRectCount,
                         uint32_t menuOverlayWindowW,
                         uint32_t menuOverlayWindowH)
{
    (void)fb;
    if (!m_vkReady || !m_vkRenderer) {
        std::cerr << "Vulkan Shaders not ready!\n";
        return false;
    }
    if (!m_vkRenderer->render(
            player, map,
            m_gpuPlayers, m_remoteMeshPtrs, m_numRemotePlayers,
            nullptr,
            menuOverlayRects, menuOverlayRectCount,
            menuOverlayEnabled,
            menuOverlayWindowW, menuOverlayWindowH)) {
        std::cerr << "[Renderer] Vulkan render failed: " << m_vkRenderer->lastError() << "\n";
        return false;
    }
    return true;
}


bool Renderer::rasterizeAll(Framebuffer& fb, const Player& player, const Map& map,
                            bool menuOverlayEnabled,
                            const MenuOverlayRect* menuOverlayRects,
                            uint32_t menuOverlayRectCount,
                            uint32_t menuOverlayWindowW,
                            uint32_t menuOverlayWindowH)
{
    (void)fb;
    if (!m_vkReady || !m_vkRenderer) {
        std::cerr << "Vulkan rasterizer not ready!\n";
        return false;
    }
    m_vkRenderer->setRaytracingSettings(m_raytracingEnabled, m_raytracingQualityPercent, m_dustDensityPercent, m_dustBrightnessPercent);
    if (!m_vkRenderer->rasterize(
            player, map,
            m_gpuPlayers, m_remoteMeshPtrs, m_numRemotePlayers,
            nullptr,
            menuOverlayRects, menuOverlayRectCount,
            menuOverlayEnabled,
            menuOverlayWindowW, menuOverlayWindowH)) {
        std::cerr << "[Renderer] Vulkan rasterize failed: " << m_vkRenderer->lastError() << "\n";
        return false;
    }
    return true;
}
