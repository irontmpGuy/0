#pragma once
#include "Vec3f.h"
#include "Vertex.h"
#include <cstdint>

struct Triangle {
    Vertex v1, v2, v3;
    int textureID = -1;
};