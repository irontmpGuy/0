#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <string>
#include <unordered_map>

#include "Window.h"
#include "Framebuffer.h"
#include "InputHandler.h"
#include "Map.h"
#include "Player.h"
#include "Renderer.h"
#include "Menu.h"

#include "UdpServer.h"
#include "UdpClient.h"

class Engine
{
public:
    static constexpr int RENDER_W = 2560;
    static constexpr int RENDER_H = 1440;

    Engine(const std::string& title, bool isServer, std::string ip);
    ~Engine() = default;

    void run();
    bool isRunning() const;


    //Networking
    bool      isServer = false;
    UdpServer server;
    UdpClient client;

    // timings
    static constexpr float PLAYERSTATE_UPDATE_FREQUENZY = 1/50; //40Hz

    int ROOM_ID = 3123;

    std::string SERVER_IP = "158.180.49.41";

private:
    void ClientLoop();
    void ServerLoop();
    void handleEvents();
    void update(float dt);
    void render(float dt);
    bool checkPause();
    void setResolution(int width, int height);

    Window       m_window;
    Framebuffer  m_fb;
    Player       m_player;
    Renderer     m_renderer;
    InputHandler m_input;
    Map          m_map;
    bool hasMap = false;

    Menu m_menu;
    

    float m_resolutionScale = 1.0f;

    bool m_running = true;
    bool pause = false;

    static constexpr float MAX_DT = 0.05f;

    // Reused every frame by the server path in render() to avoid allocation.
    std::unordered_map<uint32_t, PlayerStatePacket> m_remoteSnapshot;
};