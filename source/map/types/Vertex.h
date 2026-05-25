#pragma once
#include "Vec3f.h"
#include <cstdint>

struct Vertex {
    Vec3f pos;
    Vec2f uv;
    uint32_t skinIndex = 0;
};