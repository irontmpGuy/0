#pragma once
#include <vector>
#include <cstdint>

// ---------------------------------------------------------------------------
// Framebuffer
// CPU-side pixel buffer in 0xAARRGGBB format (Windows ARGB / BGRA DIB).
// The raycaster writes here; Window blits it to screen via StretchDIBits.
// ---------------------------------------------------------------------------
class Framebuffer
{
public:
    Framebuffer() : m_width(0), m_height(0) {}
    Framebuffer(int width, int height);

    inline void setPixel(int x, int y, uint32_t color) {
        if (x < 0 || x >= m_width || y < 0 || y >= m_height) return;
        m_pixels[y * m_width + x] = color;
    }

    inline uint32_t getPixel(int x, int y) const {
        if (x < 0 || x >= m_width || y < 0 || y >= m_height) return 0;
        return m_pixels[y * m_width + x];
    }

    // Fill the entire buffer with one color (0 = black).
    void clear(uint32_t color = 0);
    void resize(int width, int height);

    // Raw pointer passed to StretchDIBits in Window::present().
    const uint32_t* getData() const;

    int getWidth()  const;
    int getHeight() const;

private:
    int                   m_width;
    int                   m_height;
    std::vector<uint32_t> m_pixels;     // row-major, top-left origin
};
