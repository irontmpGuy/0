#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "Framebuffer.h"
#include "VulkanOverlay.h"

class Menu
{
public:
    using ResolutionChangedCallback = std::function<void(int, int)>;
    using RaytracingChangedCallback = std::function<void(bool, int, int, int)>;
    using QuitCallback = std::function<void()>;

    void setResolutionChangedCallback(ResolutionChangedCallback cb) { m_onResolutionChanged = cb; }
    void setRaytracingChangedCallback(RaytracingChangedCallback cb) { m_onRaytracingChanged = cb; }
    void setQuitCallback(QuitCallback cb) { m_onQuit = cb; }

    void update(HWND hwnd, int windowW, int windowH, Framebuffer& fb)
    {
        (void)fb;
        if (windowW <= 0 || windowH <= 0) return;

        POINT mouse;
        GetCursorPos(&mouse);
        ScreenToClient(hwnd, &mouse);

        const bool mouseDown = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
        const bool clicked = mouseDown && !m_mouseWasDown;

        int sliderX, sliderY, sliderW, sliderH;
        getSliderRect(windowW, windowH, sliderX, sliderY, sliderW, sliderH);

        int rtSliderX, rtSliderY, rtSliderW, rtSliderH;
        getRaytracingQualitySliderRect(windowW, windowH, rtSliderX, rtSliderY, rtSliderW, rtSliderH);

        int dustSliderX, dustSliderY, dustSliderW, dustSliderH;
        getDustDensitySliderRect(windowW, windowH, dustSliderX, dustSliderY, dustSliderW, dustSliderH);

        int densitySliderX, densitySliderY, densitySliderW, densitySliderH;
        getDustBrightnessSliderRect(windowW, windowH, densitySliderX, densitySliderY, densitySliderW, densitySliderH);

        int rtButtonX, rtButtonY, rtButtonW, rtButtonH;
        getRaytracingToggleRect(windowW, windowH, rtButtonX, rtButtonY, rtButtonW, rtButtonH);

        int quitX, quitY, quitW, quitH;
        getQuitRect(windowW, windowH, quitX, quitY, quitW, quitH);

        const bool overSlider = inSlider(mouse, sliderX, sliderY, sliderW, sliderH);
        const bool overRtSlider = inSlider(mouse, rtSliderX, rtSliderY, rtSliderW, rtSliderH);
        const bool overDustSlider = inSlider(mouse, dustSliderX, dustSliderY, dustSliderW, dustSliderH);
        const bool overDensitySlider = inSlider(mouse, densitySliderX, densitySliderY, densitySliderW, densitySliderH);
        const bool overRtButton = inRect(mouse, rtButtonX, rtButtonY, rtButtonW, rtButtonH);
        const bool overQuit = inRect(mouse, quitX, quitY, quitW, quitH);

        if (clicked && overQuit) {
            if (m_onQuit) m_onQuit();
        }

        if (clicked && overRtButton) {
            m_raytracingEnabled = !m_raytracingEnabled;
            emitRaytracingChanged();
        }

        if (mouseDown && overSlider) m_draggingResolutionSlider = true;
        if (mouseDown && overRtSlider) m_draggingRaytracingQualitySlider = true;
        if (mouseDown && overDustSlider) m_draggingDustDensitySlider = true;
        if (mouseDown && overDensitySlider) m_draggingDustBrightnessSlider = true;

        if (!mouseDown) {
            m_draggingResolutionSlider = false;
            m_draggingRaytracingQualitySlider = false;
            m_draggingDustDensitySlider = false;
            m_draggingDustBrightnessSlider = false;
        }

        if (m_draggingResolutionSlider) {
            float t = static_cast<float>(mouse.x - sliderX) / static_cast<float>(sliderW);
            t = std::clamp(t, 0.0f, 1.0f);

            const int newW = 1 + static_cast<int>(t * (3840 - 1));
            const int newH = 1 + static_cast<int>(t * (2160 - 1));
            if (newW != m_resolutionW || newH != m_resolutionH) {
                m_resolutionW = newW;
                m_resolutionH = newH;
                if (m_onResolutionChanged) m_onResolutionChanged(m_resolutionW, m_resolutionH);
            }
        }

        if (m_draggingRaytracingQualitySlider) {
            const int newQuality = sliderPercent(mouse.x, rtSliderX, rtSliderW);
            if (newQuality != m_raytracingQualityPercent) {
                m_raytracingQualityPercent = newQuality;
                emitRaytracingChanged();
            }
        }

        if (m_draggingDustDensitySlider) {
            const int newDustDensity = sliderPercent(mouse.x, dustSliderX, dustSliderW);
            if (newDustDensity != m_dustDensityPercent) {
                m_dustDensityPercent = newDustDensity;
                emitRaytracingChanged();
            }
        }

        if (m_draggingDustBrightnessSlider) {
            const int newDustBrightness = sliderPercent(mouse.x, densitySliderX, densitySliderW);
            if (newDustBrightness != m_dustBrightnessPercent) {
                m_dustBrightnessPercent = newDustBrightness;
                emitRaytracingChanged();
            }
        }

        m_mouseWasDown = mouseDown;
    }

    void draw(Framebuffer& fb, int windowW, int windowH)
    {
        if (windowW <= 0 || windowH <= 0) return;
        darken(fb);

        int sliderX, sliderY, sliderW, sliderH;
        getSliderRect(windowW, windowH, sliderX, sliderY, sliderW, sliderH);

        int rtSliderX, rtSliderY, rtSliderW, rtSliderH;
        getRaytracingQualitySliderRect(windowW, windowH, rtSliderX, rtSliderY, rtSliderW, rtSliderH);

        int dustSliderX, dustSliderY, dustSliderW, dustSliderH;
        getDustDensitySliderRect(windowW, windowH, dustSliderX, dustSliderY, dustSliderW, dustSliderH);

        int densitySliderX, densitySliderY, densitySliderW, densitySliderH;
        getDustBrightnessSliderRect(windowW, windowH, densitySliderX, densitySliderY, densitySliderW, densitySliderH);

        int rtButtonX, rtButtonY, rtButtonW, rtButtonH;
        getRaytracingToggleRect(windowW, windowH, rtButtonX, rtButtonY, rtButtonW, rtButtonH);

        int quitX, quitY, quitW, quitH;
        getQuitRect(windowW, windowH, quitX, quitY, quitW, quitH);

        fillRectWindow(fb, windowW, windowH, sliderX - 50, sliderY - 80, sliderW + 250, 455, 0x202020);
        drawSlider(fb, windowW, windowH, sliderX, sliderY, sliderW, sliderH,
                   static_cast<float>(m_resolutionW - 1) / static_cast<float>(3840 - 1),
                   std::to_string(m_resolutionW) + "x" + std::to_string(m_resolutionH));
        drawSlider(fb, windowW, windowH, rtSliderX, rtSliderY, rtSliderW, rtSliderH,
                   static_cast<float>(m_raytracingQualityPercent) / 100.0f,
                   "RT " + std::to_string(m_raytracingQualityPercent) + "%");
        drawSlider(fb, windowW, windowH, dustSliderX, dustSliderY, dustSliderW, dustSliderH,
                   static_cast<float>(m_dustDensityPercent) / 100.0f,
                   dustDensityLabel());
        drawSlider(fb, windowW, windowH, densitySliderX, densitySliderY, densitySliderW, densitySliderH,
                   static_cast<float>(m_dustBrightnessPercent) / 100.0f,
                   dustBrightnessLabel());

        fillRectWindow(fb, windowW, windowH, rtButtonX, rtButtonY, rtButtonW, rtButtonH,
                       m_raytracingEnabled ? 0x306030 : 0x604030);
        drawTextWindow(fb, windowW, windowH, rtButtonX + 18, rtButtonY + 10,
                       m_raytracingEnabled ? "RT ON" : "RT OFF", 3, 0xFFFFFF);

        fillRectWindow(fb, windowW, windowH, quitX, quitY, quitW, quitH, 0x803030);
        drawTextWindow(fb, windowW, windowH, quitX + 18, quitY + 10, "QUIT", 3, 0xFFFFFF);
    }

    void buildOverlay(std::vector<MenuOverlayRect>& out, int windowW, int windowH) const
    {
        if (windowW <= 0 || windowH <= 0) return;

        int sliderX, sliderY, sliderW, sliderH;
        getSliderRect(windowW, windowH, sliderX, sliderY, sliderW, sliderH);

        int rtSliderX, rtSliderY, rtSliderW, rtSliderH;
        getRaytracingQualitySliderRect(windowW, windowH, rtSliderX, rtSliderY, rtSliderW, rtSliderH);

        int dustSliderX, dustSliderY, dustSliderW, dustSliderH;
        getDustDensitySliderRect(windowW, windowH, dustSliderX, dustSliderY, dustSliderW, dustSliderH);

        int densitySliderX, densitySliderY, densitySliderW, densitySliderH;
        getDustBrightnessSliderRect(windowW, windowH, densitySliderX, densitySliderY, densitySliderW, densitySliderH);

        int rtButtonX, rtButtonY, rtButtonW, rtButtonH;
        getRaytracingToggleRect(windowW, windowH, rtButtonX, rtButtonY, rtButtonW, rtButtonH);

        int quitX, quitY, quitW, quitH;
        getQuitRect(windowW, windowH, quitX, quitY, quitW, quitH);

        addRect(out, sliderX - 50, sliderY - 80, sliderW + 250, 455, 0x202020);
        addSlider(out, sliderX, sliderY, sliderW, sliderH,
                  static_cast<float>(m_resolutionW - 1) / static_cast<float>(3840 - 1),
                  std::to_string(m_resolutionW) + "x" + std::to_string(m_resolutionH));
        addSlider(out, rtSliderX, rtSliderY, rtSliderW, rtSliderH,
                  static_cast<float>(m_raytracingQualityPercent) / 100.0f,
                  "RT " + std::to_string(m_raytracingQualityPercent) + "%");
        addSlider(out, dustSliderX, dustSliderY, dustSliderW, dustSliderH,
                  static_cast<float>(m_dustDensityPercent) / 100.0f,
                  dustDensityLabel());
        addSlider(out, densitySliderX, densitySliderY, densitySliderW, densitySliderH,
                  static_cast<float>(m_dustBrightnessPercent) / 100.0f,
                  dustBrightnessLabel());

        addRect(out, rtButtonX, rtButtonY, rtButtonW, rtButtonH,
                m_raytracingEnabled ? 0x306030 : 0x604030);
        addText(out, rtButtonX + 18, rtButtonY + 10,
                m_raytracingEnabled ? "RT ON" : "RT OFF", 3, 0xFFFFFF);

        addRect(out, quitX, quitY, quitW, quitH, 0x803030);
        addText(out, quitX + 18, quitY + 10, "QUIT", 3, 0xFFFFFF);
    }

    int getResolutionW() const { return m_resolutionW; }
    int getResolutionH() const { return m_resolutionH; }
    bool isRaytracingEnabled() const { return m_raytracingEnabled; }
    int getRaytracingQualityPercent() const { return m_raytracingQualityPercent; }
    std::string dustDensityLabel() const
    {
        // UI density is intentionally compressed: 100% now equals the previous over-strong 1% setting.
        // Internally this maps to 0..20 effective particles per cubic meter.
        const int particlesPerM3Times10 = static_cast<int>(std::lround(static_cast<float>(m_dustDensityPercent) * 2.0f));
        const int whole = particlesPerM3Times10 / 10;
        const int frac = particlesPerM3Times10 % 10;
        return "DUST DENSITY " + std::to_string(whole) + "." + std::to_string(frac) + "/m3";
    }

    std::string dustBrightnessLabel() const
    {
        return "DUST BRIGHTNESS " + std::to_string(m_dustBrightnessPercent) + "%";
    }

    int getDustDensityPercent() const { return m_dustDensityPercent; }
    int getDustBrightnessPercent() const { return m_dustBrightnessPercent; }

private:
    int  m_resolutionW = 3840;
    int  m_resolutionH = 2160;

    bool m_draggingResolutionSlider = false;
    bool m_draggingRaytracingQualitySlider = false;
    bool m_draggingDustDensitySlider = false;
    bool m_draggingDustBrightnessSlider = false;
    bool m_mouseWasDown = false;

    bool m_raytracingEnabled = false;
    int  m_raytracingQualityPercent = 100;
    int  m_dustDensityPercent = 100;
    int  m_dustBrightnessPercent = 35;

    ResolutionChangedCallback m_onResolutionChanged;
    RaytracingChangedCallback m_onRaytracingChanged;
    QuitCallback m_onQuit;

    static bool inRect(POINT mouse, int x, int y, int w, int h)
    {
        return mouse.x >= x && mouse.x <= x + w && mouse.y >= y && mouse.y <= y + h;
    }

    static bool inSlider(POINT mouse, int x, int y, int w, int h)
    {
        return mouse.x >= x && mouse.x <= x + w && mouse.y >= y - 18 && mouse.y <= y + h + 18;
    }

    static int sliderPercent(int mouseX, int x, int w)
    {
        float t = static_cast<float>(mouseX - x) / static_cast<float>(w);
        t = std::clamp(t, 0.0f, 1.0f);
        return std::clamp(static_cast<int>(std::round(t * 100.0f)), 0, 100);
    }

    void getSliderRect(int windowW, int windowH, int& x, int& y, int& w, int& h) const
    {
        w = 420;
        h = 12;
        x = windowW / 2 - w / 2 - 80;
        y = windowH / 2 - 70;
    }

    void getRaytracingQualitySliderRect(int windowW, int windowH, int& x, int& y, int& w, int& h) const
    {
        w = 420;
        h = 12;
        x = windowW / 2 - w / 2 - 80;
        y = windowH / 2 + 5;
    }

    void getDustDensitySliderRect(int windowW, int windowH, int& x, int& y, int& w, int& h) const
    {
        w = 420;
        h = 12;
        x = windowW / 2 - w / 2 - 80;
        y = windowH / 2 + 80;
    }

    void getDustBrightnessSliderRect(int windowW, int windowH, int& x, int& y, int& w, int& h) const
    {
        w = 420;
        h = 12;
        x = windowW / 2 - w / 2 - 80;
        y = windowH / 2 + 155;
    }

    void getRaytracingToggleRect(int windowW, int windowH, int& x, int& y, int& w, int& h) const
    {
        w = 150;
        h = 45;
        x = windowW / 2 - w / 2;
        y = windowH / 2 + 200;
    }

    void getQuitRect(int windowW, int windowH, int& x, int& y, int& w, int& h) const
    {
        w = 110;
        h = 45;
        x = windowW / 2 - w / 2;
        y = windowH / 2 + 260;
    }

    void emitRaytracingChanged()
    {
        if (m_onRaytracingChanged) {
            m_onRaytracingChanged(m_raytracingEnabled, m_raytracingQualityPercent, m_dustDensityPercent, m_dustBrightnessPercent);
        }
    }

    void darken(Framebuffer& fb)
    {
        const int fbW = fb.getWidth();
        const int fbH = fb.getHeight();

        for (int y = 0; y < fbH; ++y) {
            for (int x = 0; x < fbW; ++x) {
                const uint32_t c = fb.getPixel(x, y);
                uint8_t r = (c >> 16) & 0xFF;
                uint8_t g = (c >> 8)  & 0xFF;
                uint8_t b =  c        & 0xFF;
                r = static_cast<uint8_t>(r * 0.35f);
                g = static_cast<uint8_t>(g * 0.35f);
                b = static_cast<uint8_t>(b * 0.35f);
                fb.setPixel(x, y, (r << 16) | (g << 8) | b);
            }
        }
    }

    static int toFbX(int windowX, int windowW, int fbW) { return windowX * fbW / windowW; }
    static int toFbY(int windowY, int windowH, int fbH) { return windowY * fbH / windowH; }

    void fillRectWindow(Framebuffer& fb, int windowW, int windowH,
                        int x, int y, int w, int h, uint32_t color)
    {
        const int fbW = fb.getWidth();
        const int fbH = fb.getHeight();
        int x0 = toFbX(x, windowW, fbW);
        int y0 = toFbY(y, windowH, fbH);
        int x1 = toFbX(x + w, windowW, fbW);
        int y1 = toFbY(y + h, windowH, fbH);
        if (x1 <= x0) x1 = x0 + 1;
        if (y1 <= y0) y1 = y0 + 1;

        for (int yy = y0; yy < y1; ++yy) {
            for (int xx = x0; xx < x1; ++xx) {
                fb.setPixel(xx, yy, color);
            }
        }
    }

    void drawSlider(Framebuffer& fb, int windowW, int windowH,
                    int x, int y, int w, int h, float t, const std::string& text)
    {
        t = std::clamp(t, 0.0f, 1.0f);
        const int filledW = static_cast<int>(w * t);
        fillRectWindow(fb, windowW, windowH, x, y, w, h, 0x606060);
        fillRectWindow(fb, windowW, windowH, x, y, filledW, h, 0xFFFFFF);
        fillRectWindow(fb, windowW, windowH, x + filledW - 6, y - 9, 12, 30, 0xFFCC00);
        drawTextWindow(fb, windowW, windowH, x + w + 25, y - 8, text, 3, 0xFFFFFF);
    }

    void drawTextWindow(Framebuffer& fb, int windowW, int windowH,
                        int x, int y, const std::string& text, int scale, uint32_t color)
    {
        int cursorX = x;
        for (char c : text) {
            drawCharWindow(fb, windowW, windowH, cursorX, y, c, scale, color);
            cursorX += 6 * scale;
        }
    }

    void drawCharWindow(Framebuffer& fb, int windowW, int windowH,
                        int x, int y, char c, int scale, uint32_t color)
    {
        const char* glyph = getGlyph(c);
        if (!glyph) return;
        for (int row = 0; row < 7; ++row) {
            for (int col = 0; col < 5; ++col) {
                if (glyph[row * 5 + col] == '1') {
                    fillRectWindow(fb, windowW, windowH,
                                   x + col * scale, y + row * scale,
                                   scale, scale, color);
                }
            }
        }
    }

    void addSlider(std::vector<MenuOverlayRect>& out, int x, int y, int w, int h,
                   float t, const std::string& text) const
    {
        t = std::clamp(t, 0.0f, 1.0f);
        const int filledW = static_cast<int>(w * t);
        addRect(out, x, y, w, h, 0x606060);
        addRect(out, x, y, filledW, h, 0xFFFFFF);
        addRect(out, x + filledW - 6, y - 9, 12, 30, 0xFFCC00);
        addText(out, x + w + 25, y - 8, text, 3, 0xFFFFFF);
    }

    void addRect(std::vector<MenuOverlayRect>& out, int x, int y, int w, int h, uint32_t color) const
    {
        if (w <= 0 || h <= 0) return;
        MenuOverlayRect r;
        r.x = x;
        r.y = y;
        r.w = w;
        r.h = h;
        r.color = color;
        out.push_back(r);
    }

    void addText(std::vector<MenuOverlayRect>& out, int x, int y,
                 const std::string& text, int scale, uint32_t color) const
    {
        int cursorX = x;
        for (char c : text) {
            addChar(out, cursorX, y, c, scale, color);
            cursorX += 6 * scale;
        }
    }

    void addChar(std::vector<MenuOverlayRect>& out, int x, int y,
                 char c, int scale, uint32_t color) const
    {
        const char* glyph = getGlyph(c);
        if (!glyph) return;
        for (int row = 0; row < 7; ++row) {
            for (int col = 0; col < 5; ++col) {
                if (glyph[row * 5 + col] == '1') {
                    addRect(out, x + col * scale, y + row * scale, scale, scale, color);
                }
            }
        }
    }

    const char* getGlyph(char c) const
    {
        switch (c) {
        case ' ': return "00000000000000000000000000000000000";
        case '0': return "11111100011001110101110011000111111";
        case '1': return "00100011000010000100001000010001110";
        case '2': return "11111000010000111111100001000011111";
        case '3': return "11111000010000111111000010000111111";
        case '4': return "10001100011000111111000010000100001";
        case '5': return "11111100001000011111000010000111111";
        case '6': return "11111100001000011111100011000111111";
        case '7': return "11111000010001000100010000100001000";
        case '8': return "11111100011000111111100011000111111";
        case '9': return "11111100011000111111000010000111111";
        case '%': return "10001000100010001000100010000000000";
        case 'D': return "11110100011000110001100011000111110";
        case 'F': return "11111100001000011110100001000010000";
        case 'I': return "11111001000010000100001000010011111";
        case 'N': return "10001110011010110011100011000110001";
        case 'O': return "01110100011000110001100011000101110";
        case 'Q': return "11110100011000110001101011001011101";
        case 'R': return "11110100011000111110101001001010001";
        case 'S': return "11111100001000011111000010000111111";
        case 'T': return "11111001000010000100001000010000100";
        case 'U': return "10001100011000110001100011000111111";
        case 'x':
        case 'X': return "10001010100010000100001000101010001";
        default: return nullptr;
        }
    }
};
