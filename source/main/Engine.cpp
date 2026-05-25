#include "Engine.h"
#include "MapEditProtocol.h"
#include "MapEditorOverlay.h"
#include "MapData.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <chrono>
#include <thread>
#include <iostream>
#include <vector>
#include <algorithm>
#include <string>

namespace {
MapEditorOverlay g_mapEditorOverlay;

void processMapBuilder(MapData* mapData, UdpClient& client, Player& player)
{
    if (!mapData) return;

    g_mapEditorOverlay.setCurrentPlayerPosition(player.getPos());

    std::string checkId;
    if (g_mapEditorOverlay.consumeCheckRequest(checkId)) {
        MapObjectEdit existing{};
        if (mapData->getRuntimeObjectEdit(checkId, existing)) {
            g_mapEditorOverlay.setCheckedObjectFound(existing);
            player.setPosition(MapData::focusPositionForEdit(existing));
        } else {
            g_mapEditorOverlay.setCheckedObjectAvailable(checkId);
        }
    }

    const std::string requestedId = g_mapEditorOverlay.getRequestedObjectId();
    g_mapEditorOverlay.setObjectIdTaken(
        !requestedId.empty() && mapData->hasRuntimeObjectId(requestedId)
    );

    std::string previewRemoveId;
    if (g_mapEditorOverlay.consumePreviewRemove(previewRemoveId)) {
        mapData->removeObjectById(previewRemoveId);
        g_mapEditorOverlay.notePreviewRemoved();
    }

    MapObjectEdit previewEdit{};
    std::string previewReplaceId;
    if (g_mapEditorOverlay.consumePreviewUpdate(previewEdit, previewReplaceId)) {
        mapData->removeObjectById(previewReplaceId);
        previewEdit.persistToJson = 0;
        mapData->addObject(previewEdit, false);
    }

    MapObjectEdit createEdit{};
    if (g_mapEditorOverlay.consumeAddRequest(createEdit, player.getPos())) {
        mapData->removeObjectById(g_mapEditorOverlay.previewObjectId());
        g_mapEditorOverlay.notePreviewRemoved();
        createEdit.persistToJson = 1;
        if (client.addMapObject(*mapData, createEdit, "assets/map.json")) {
            const std::string createdId = mapEditGetString(createEdit.id, sizeof(createEdit.id));
            g_mapEditorOverlay.setObjectIdTaken(!createdId.empty() && mapData->hasRuntimeObjectId(createdId));
        }
    }

    std::string removeId;
    if (g_mapEditorOverlay.consumeRemoveRequest(removeId)) {
        mapData->removeObjectById(g_mapEditorOverlay.previewObjectId());
        g_mapEditorOverlay.notePreviewRemoved();
        client.removeMapObject(*mapData, removeId, "assets/map.json");
        if (removeId == g_mapEditorOverlay.getRequestedObjectId()) {
            g_mapEditorOverlay.setObjectIdTaken(false);
        }
    }
}
}


Engine::Engine(const std::string& title, bool isServer, std::string ip)
    : m_window(0, 0, title),
      m_fb(RENDER_W, RENDER_H),
      m_input(),
      m_player({0.0f, 0.0f, 0.0f}, {0.0f, 0.0f, 0.0f}, 0.66f),
      m_renderer(RENDER_W, RENDER_H, m_window.getHWND()),
      m_running(true),
      isServer(isServer)
{

    m_menu.setResolutionChangedCallback([this](int width, int height) {
        setResolution(width, height);
    });

    m_menu.setQuitCallback([this]() {
        m_running = false;
    });

    m_menu.setRaytracingChangedCallback([this](bool enabled, int qualityPercent, int dustDensityPercent, int dustBrightnessPercent) {
        m_renderer.setRaytracingEnabled(enabled);
        m_renderer.setRaytracingQualityPercent(qualityPercent);
        m_renderer.setDustDensityPercent(dustDensityPercent);
        m_renderer.setDustBrightnessPercent(dustBrightnessPercent);
    });

    g_mapEditorOverlay.create(m_window.getHWND());

    std::cout << "[Engine] All subsystems initialized via initializer list." << std::endl;

    if (isServer) {
        std::cout << "[+] Starting Server...\n";
        if (!server.start(54000)) {
            std::cout << "[!] Server start failed\n";
            return;
        } else std::thread([this]{ ServerLoop(); }).detach();

        std::cout << "[+] Starting Client...\n";
        if (!client.connect("127.0.0.1", 54000)) {
            std::cout << "[!] Client start failed\n";
            return;
        }
        std::thread([this]{ ClientLoop(); }).detach();

        server.registerWithRendezvous(SERVER_IP, 55000, ROOM_ID);
        return;
    }

    std::cout << "[+] Starting Client...\n";
    if (!client.connectViaRendezvous(SERVER_IP, 55000, ROOM_ID)) {
        std::cout << "[!] Client start failed\n";
        return;
    }
    std::thread([this]{ ClientLoop(); }).detach();
}

void Engine::ServerLoop() {
    
    while (server.isRunning())
    {
        server.update();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

void Engine::ClientLoop() {
    
    using Clock = std::chrono::high_resolution_clock;
    auto lastTime = Clock::now();

    float sendAccumulator = 0.0f;

    while (client.isRunning())
    {
        auto now = Clock::now();
        float dt = std::chrono::duration<float>(now - lastTime).count();
        lastTime = now;

        sendAccumulator += dt;

        if (sendAccumulator >= PLAYERSTATE_UPDATE_FREQUENZY) {
            client.sendPlayerState(m_player);
            sendAccumulator = 0.0f;
        }

        client.update();

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

void Engine::setResolution(int width, int height)
{
    if (width < 1) width = 1;
    if (height < 1) height = 1;

    // This is an internal render-resolution slider, not a window/framebuffer
    // resize. The CPU framebuffer stays at its normal size for fallback/menu
    // paths; Vulkan renders offscreen at width/height and blits to the window.
    m_renderer.resize(width, height);
}

bool Engine::checkPause() {
    if (m_input.isPressed(InputHandler::Action::Escape)) {
        pause = !pause;
    }

    g_mapEditorOverlay.setPauseVisible(pause, m_window.getHWND());
    m_player.setFlyEnabled(g_mapEditorOverlay.isEditEnabled());

    if (pause) {
        m_menu.update(
            m_window.getHWND(),
            m_window.getWidth(),
            m_window.getHeight(),
            m_fb
        );

        // Handle the in-game Edit checkbox; the full builder UI is the
        // separate native popup owned by MapEditorOverlay.
        g_mapEditorOverlay.handleOverlayInput(
            m_window.getHWND(),
            m_window.getWidth(),
            m_window.getHeight()
        );

        // While paused the normal update() path is skipped, so still process
        // the builder popup here. Preview is local-only; Create/Remove are
        // persisted and replicated through the client map-edit packets.
        if (hasMap && m_map.mapData) {
            processMapBuilder(m_map.mapData, client, m_player);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        return true;
    }

    return false;
}

void Engine::run()
{
    using Clock = std::chrono::high_resolution_clock;
    auto lastTime = Clock::now();

    while (m_running)
    {
        handleEvents();
        if (!m_running) break;

        auto  now = Clock::now();
        float dt  = std::chrono::duration<float>(now - lastTime).count();
        lastTime  = now;
        
        if (checkPause()) {
            lastTime = Clock::now();
            render(dt);
            m_player.update(dt, m_input, m_map, false);
            continue;
        }

        if (dt > MAX_DT) dt = MAX_DT;

        update(dt);
        render(dt);
    }
}

bool Engine::isRunning() const { return m_running; }

// ---------------------------------------------------------------------------
// Private
// ---------------------------------------------------------------------------

void Engine::handleEvents()
{
    if (!m_window.processMessages()) {
        m_running = false;
        return;
    }

    m_input.update(m_window.getHWND(), pause, g_mapEditorOverlay.isEditEnabled());
    g_mapEditorOverlay.pumpMessages();
}

void Engine::update(float dt)
{
    std::string receivedMapJson; // handle initial/full map transfer
    if (client.consumeReceivedMapJson(receivedMapJson)) {
        m_map.loadFromJsonString(receivedMapJson, &m_player);
        hasMap = true;
    }

    if (!hasMap) {
        m_player.setFlyEnabled(g_mapEditorOverlay.isEditEnabled());
        return;
    }

    g_mapEditorOverlay.keepOnTop(m_window.getHWND());
    m_player.setFlyEnabled(g_mapEditorOverlay.isEditEnabled());

    // Client-authored map edits are relayed by the server, then applied here by
    // every receiving client to both the live map and the local assets/map.json.
    std::vector<MapObjectEdit> mapAdds;
    std::vector<std::string> mapRemoves;
    if (client.consumeMapEdits(mapAdds, mapRemoves) && m_map.mapData) {
        for (MapObjectEdit& edit : mapAdds) {
            m_map.mapData->addObjectAndPersist(edit, "assets/map.json", true);
        }

        for (const std::string& objectId : mapRemoves) {
            m_map.mapData->removeObjectAndPersist(objectId, "assets/map.json");
        }
    }

    // Builder popup: field changes still use a local-only preview. Create and
    // Remove commit to assets/map.json locally and are sent to the server for
    // relay to all other clients.
    if (m_map.mapData) {
        processMapBuilder(m_map.mapData, client, m_player);
    }

    m_player.update(dt, m_input, m_map);
}



void Engine::render(float dt)
{
    if (!hasMap) return;

    std::vector<MenuOverlayRect> menuRects;
    if (pause) {
        m_menu.buildOverlay(menuRects, m_window.getWidth(), m_window.getHeight());
        g_mapEditorOverlay.appendOverlay(menuRects, m_window.getWidth(), m_window.getHeight());
    }

    client.predictRemotePlayers();

    m_renderer.setEditorMode(g_mapEditorOverlay.isEditEnabled());

    const bool gpuPresented = m_renderer.rasterizeFrame(
        m_fb,
        m_player,
        m_map,
        client.getRemotePlayers(),
        client.getClientNum(),
        dt,
        pause,
        menuRects.empty() ? nullptr : menuRects.data(),
        static_cast<uint32_t>(menuRects.size()),
        static_cast<uint32_t>(std::max(1, m_window.getWidth())),
        static_cast<uint32_t>(std::max(1, m_window.getHeight()))
    );

    // In Vulkan mode, rendering + pause menu presentation are both done by Vulkan.
    // GDI/Framebuffer presentation is now only a fallback if Vulkan fails.
    if (!gpuPresented) {
        m_fb.clear(0);
        if (pause) {
            m_menu.draw(m_fb, m_window.getWidth(), m_window.getHeight());
        }
        m_window.present(m_fb);
    }
}

