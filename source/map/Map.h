#pragma once
#include <vector>
#include <map>
#include "Texture.h"
#include "MapData.h"
#include "Triangle.h"
#include <string>
#include "Box.h"
#include "Cell.h"

struct GridCell {
    std::vector<const Triangle*> triangles;
};

class Map
{
public:
    Map() = default;
    Map(Player* player);

    bool collides(Vec3f diff, Vec3f pos, float* distance = nullptr, float* planeY = nullptr, Plane** plane = nullptr) const;
    
    bool isWall(int x, int y, int z) const;
    bool inBounds(float x, float y, float z) const;
    Cell* getObj(float x, float y, float z) const;

    bool getSurfaceY(float x, float z, float nearY, float& outY) const;

    bool isWallRaw(int x, int y, int z) const;
    bool inBoundsRaw(int x, int y, int z) const;
    Cell* getObjRaw(int x, int y, int z) const;

    int getWidth()  const;
    int getHeight() const;
    int getDepth() const;

    bool loadOBJ(const std::string& filename);

    bool loadFromJsonFile(const std::string& path, Player* player);
    bool loadFromJsonString(const std::string& content, Player* player);

    MapData* mapData = nullptr;

    void Map::worldToGrid(float wx, float wy, float wz, int& gx, int& gy, int& gz) const;

private:
    int              m_width  = 0;
    int              m_height = 0;
    int              m_depth = 0;

    std::vector<std::vector<std::vector<void*>>> map;
};
