#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <utility>

#include "stb_image.h"

struct Texture {
    int width = 0;
    int height = 0;
    int channels = 0;
    uint32_t* pixels = nullptr;
    bool valid = false;

    Texture() = default;

    explicit Texture(const char* filename) {
        load(filename);
    }

    Texture(const Texture&) = delete;
    Texture& operator=(const Texture&) = delete;

    Texture(Texture&& other) noexcept {
        *this = std::move(other);
    }

    Texture& operator=(Texture&& other) noexcept {
        if (this == &other) return *this;
        delete[] pixels;
        width = other.width;
        height = other.height;
        channels = other.channels;
        pixels = other.pixels;
        valid = other.valid;
        other.width = 0;
        other.height = 0;
        other.channels = 0;
        other.pixels = nullptr;
        other.valid = false;
        return *this;
    }

    ~Texture() {
        delete[] pixels;
    }

    bool load(const char* filename) {
        delete[] pixels;
        pixels = nullptr;
        width = height = channels = 0;
        valid = false;

        int w = 0, h = 0, c = 0;
        unsigned char* data = stbi_load(filename, &w, &h, &c, 4);
        if (!data || w <= 0 || h <= 0) {
            std::cerr << "[Texture] Failed to load: " << (filename ? filename : "<null>") << "\n";
            if (data) stbi_image_free(data);
            return false;
        }

        width = w;
        height = h;
        channels = 4;
        pixels = new uint32_t[(size_t)width * (size_t)height];

        for (int y = 0; y < height; ++y) {
            for (int x = 0; x < width; ++x) {
                const size_t i = ((size_t)y * (size_t)width + (size_t)x) * 4u;
                const uint8_t r = data[i + 0];
                const uint8_t g = data[i + 1];
                const uint8_t b = data[i + 2];
                pixels[(size_t)y * (size_t)width + (size_t)x] =
                    ((uint32_t)r << 16) | ((uint32_t)g << 8) | (uint32_t)b;
            }
        }

        stbi_image_free(data);
        valid = true;
        return true;
    }

    uint32_t getPixel(int x, int y) const {
        if (!pixels || width <= 0 || height <= 0) return 0;
        x = std::clamp(x, 0, width - 1);
        y = std::clamp(y, 0, height - 1);
        return pixels[(size_t)y * (size_t)width + (size_t)x];
    }
};
