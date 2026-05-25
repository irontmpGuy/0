#pragma once
#include "Texture.h"
#include "Vec3f.h"

struct Plane {
    int type = 1;
    Vec3f position;
    Vec3f normal;
    Texture* texture;
};