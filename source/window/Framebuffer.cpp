#include "Framebuffer.h"
#include <cassert>

Framebuffer::Framebuffer(int width, int height)
    : m_width(width), m_height(height), m_pixels(width * height, 0)
{}


void Framebuffer::clear(uint32_t color)
{
    std::fill(m_pixels.begin(), m_pixels.end(), color);
}

void Framebuffer::resize(int width, int height)
{
    if (width == m_width && height == m_height) return;

    m_width = width;
    m_height = height;
    m_pixels.assign(width * height, 0);
}

const uint32_t* Framebuffer::getData()   const { return m_pixels.data(); }
int             Framebuffer::getWidth()  const { return m_width;          }
int             Framebuffer::getHeight() const { return m_height;         }
