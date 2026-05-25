#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>

class Framebuffer;

// ---------------------------------------------------------------------------
// Window
// Normal resizable Win32 game window.
// Blits a Framebuffer to screen each frame via StretchDIBits (GDI).
// ---------------------------------------------------------------------------
class Window
{
public:
    Window() : m_hwnd(nullptr), m_hdc(nullptr), m_width(0), m_height(0) {}
    Window(int width, int height, const std::string& title);
    ~Window();

    Window& operator=(Window&& other) noexcept {
        if (this != &other) {
            // Clean up existing resources if they exist
            if (m_hdc && m_hwnd) ReleaseDC(m_hwnd, m_hdc);
            if (m_hwnd) DestroyWindow(m_hwnd);

            // Steal the guts from the temporary object
            m_hwnd         = other.m_hwnd;
            m_hdc          = other.m_hdc;
            m_width        = other.m_width;
            m_height       = other.m_height;
            m_isFullscreen = other.m_isFullscreen;
            m_windowedRect = other.m_windowedRect;

            // Null out the temporary so its destructor doesn't kill our window
            other.m_hwnd = nullptr;
            other.m_hdc  = nullptr;
        }
        return *this;
    }

    // Drain the Win32 message queue. Returns false when the window closes.
    bool processMessages();

    // Blit framebuffer pixels to the window client area.
    void present(const Framebuffer& fb);

    void toggleFullscreen();

    int getWidth()  const;
    int getHeight() const;

    Window(const Window&)            = delete;
    Window& operator=(const Window&) = delete;

    HWND getHWND() const { return m_hwnd; }

private:
    HWND m_hwnd  = nullptr;
    HDC  m_hdc   = nullptr;
    int  m_width  = 0;
    int  m_height = 0;
    bool m_isFullscreen = false;
    RECT m_windowedRect = {};

    static LRESULT CALLBACK wndProc(HWND hwnd, UINT msg,
                                    WPARAM wParam, LPARAM lParam);
};
