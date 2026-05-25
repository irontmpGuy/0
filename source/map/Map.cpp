#include "Map.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cmath>
#include <limits>

// for tiny_gltf.h to work, must be defined in one .cpp file
#define TINYGLTF_IMPLEMENTATION
#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_WRITE_IMPLEMENTATION

#include "tiny_gltf.h"


namespace {
    Vec3f meshWorldToModel(const MapData* data, const Mesh* mesh, const Vec3f& worldPoint) {
        Vec3f gridPoint = {
            worldPoint.x - data->minX,
            worldPoint.y - data->minY,
            worldPoint.z - data->minZ
        };

        Vec3f centered = {
            gridPoint.x - mesh->pivot.x - mesh->offset.x,
            gridPoint.y - mesh->pivot.y - mesh->offset.y,
            gridPoint.z - mesh->pivot.z - mesh->offset.z
        };

        // Inverse of meshModelToWorld():
        //   grid = rot * (((model - modelMin) * scale) - pivot) + pivot + offset
        // This keeps collision in the exact same transform space as rendering,
        // especially for rotated meshes.
        Vec3f r = mesh->rot.mulT(centered);
        return {
            (r.x + mesh->pivot.x) / mesh->scale.x + mesh->modelMin.x,
            (r.y + mesh->pivot.y) / mesh->scale.y + mesh->modelMin.y,
            (r.z + mesh->pivot.z) / mesh->scale.z + mesh->modelMin.z
        };
    }

    Vec3f meshModelToWorld(const MapData* data, const Mesh* mesh, const Vec3f& modelPoint) {
        Vec3f scaled = {
            (modelPoint.x - mesh->modelMin.x) * mesh->scale.x - mesh->pivot.x,
            (modelPoint.y - mesh->modelMin.y) * mesh->scale.y - mesh->pivot.y,
            (modelPoint.z - mesh->modelMin.z) * mesh->scale.z - mesh->pivot.z
        };

        Vec3f r = mesh->rot.mul(scaled);
        Vec3f gridPoint = {
            r.x + mesh->pivot.x + mesh->offset.x,
            r.y + mesh->pivot.y + mesh->offset.y,
            r.z + mesh->pivot.z + mesh->offset.z
        };

        return {
            gridPoint.x + data->minX,
            gridPoint.y + data->minY,
            gridPoint.z + data->minZ
        };
    }

    bool meshHitBoxContainsPoint(const MapData* data,
                                 const Mesh* mesh,
                                 const Vec3f& worldPoint,
                                 float* planeY) {
        if (!data || !mesh || !data->isMeshCollisionEnabled(mesh)) return false;

        const HitBox* hitBox = data->getHitBoxForMesh(mesh);
        if (!hitBox || hitBox->boxes.empty()) return false;

        Vec3f local = meshWorldToModel(data, mesh, worldPoint);
        const float EPS = 1e-4f;
        bool hit = false;

        for (const CollisionAABB& box : hitBox->boxes) {
            if (local.x < box.min.x - EPS || local.x > box.max.x + EPS ||
                local.y < box.min.y - EPS || local.y > box.max.y + EPS ||
                local.z < box.min.z - EPS || local.z > box.max.z + EPS) {
                continue;
            }

            hit = true;

            if (planeY) {
                Vec3f topLocal = local;
                topLocal.y = box.max.y;
                Vec3f topWorld = meshModelToWorld(data, mesh, topLocal);
                if (std::isnan(*planeY) || topWorld.y > *planeY) {
                    *planeY = topWorld.y;
                }
            }
        }

        return hit;
    }
}

void Map::worldToGrid(float wx, float wy, float wz, int& gx, int& gy, int& gz) const {
    gx = (int)std::floor(wx - mapData->minX);
    gy = (int)std::floor(wy - mapData->minY);
    gz = (int)std::floor(wz - mapData->minZ);
}

Map::Map(Player* player)
{
    loadFromJsonFile("assets/map.json", player);
}

bool Map::loadFromJsonFile(const std::string& path, Player* player)
{
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open())
        return false;

    std::stringstream buffer;
    buffer << file.rdbuf();
    return loadFromJsonString(buffer.str(), player);
}

bool Map::loadFromJsonString(const std::string& content, Player* player)
{
    std::cout << "loading map from JSON string... size=" << content.size() << " bytes\n";
    if (mapData)
        delete mapData;

    mapData = new MapData;
    mapData->generateFromString(content, player);

    m_width = mapData->sizeX;
    m_height = mapData->sizeY;
    m_depth = mapData->sizeZ;

    std::cout << "map dimensions: " << m_width << " x "
              << (m_height > 0 ? m_height : 0) << " x "
              << (m_depth > 0 ? m_depth : 0)
              << std::endl;

    return m_width > 0 && m_height > 0 && m_depth > 0;
}

bool Map::inBounds(float x, float y, float z) const {
    int gx, gy, gz;
    worldToGrid(x, y, z, gx, gy, gz);
    return gx >= 0 && gx < m_width &&
           gy >= 0 && gy < m_height &&
           gz >= 0 && gz < m_depth;
}

bool Map::inBoundsRaw(int x, int y, int z) const {
    return x >= 0 && x < m_width &&
           y >= 0 && y < m_height &&
           z >= 0 && z < m_depth;
}

Cell* Map::getObj(float x, float y, float z) const {
    int gx, gy, gz;
    worldToGrid(x, y, z, gx, gy, gz);
    if (!inBounds(x, y, z)) return nullptr;
    return mapData->getCell(gx, gy, gz);
}

bool Map::isWall(int x, int y, int z) const {
    int gx, gy, gz;
    worldToGrid(x, y, z, gx, gy, gz);
    int* type = (int*)getObjRaw(gx, gy, gz);
    return type != nullptr;
}

bool Map::collides(Vec3f diff, Vec3f pos, float* distance, float* planeY, Plane** plane) const {
    Vec3f start = pos;
    Vec3f end = pos + diff;

    int gx1, gy1, gz1, gx2, gy2, gz2;
    worldToGrid(start.x, start.y, start.z, gx1, gy1, gz1);
    worldToGrid(end.x,   end.y,   end.z,   gx2, gy2, gz2);

    // Standard min/max logic is infinitely safer than "!=" loops
    int xStart = std::min(gx1, gx2);
    int xEnd   = std::max(gx1, gx2);
    int yStart = std::min(gy1, gy2);
    int yEnd   = std::max(gy1, gy2);
    int zStart = std::min(gz1, gz2);
    int zEnd   = std::max(gz1, gz2);

    bool collided = false;
    float closestDistance = std::numeric_limits<float>::max();

    for (int x = xStart; x <= xEnd; ++x) {
        for (int y = yStart; y <= yEnd; ++y) {
            for (int z = zStart; z <= zEnd; ++z) {
                Cell* cell = getObjRaw(x, y, z);
                if (!cell) continue;
                for (int i = 0; i < cell->count; i++) {
                    void* obj = cell->items[i];
                    if (!obj) continue;

                    int type = *(int*)obj;

                    if (type == 0) { // Block
                        // Your vertical stacking logic
                        int topY = y;
                        while (isWallRaw(x, topY + 1, z) && inBoundsRaw(x, topY + 1, z)) {
                            topY++;
                        }
                        if (planeY) *planeY = (float)topY + 1 + mapData->minY;
                        return true;
                    }

                    if (type == 1) { // Plane
                        Plane* p = (Plane*)obj;
                        Vec3f currLoc = { end.x - mapData->minX, end.y - mapData->minY, end.z - mapData->minZ };
                        Vec3f prevLoc = { start.x - mapData->minX, start.y - mapData->minY, start.z - mapData->minZ };

                        float dCurr = (currLoc - p->position).dot(p->normal);
                        float dPrev = (prevLoc - p->position).dot(p->normal);

                        if ((dPrev >= -0.01f && dCurr <= 0.01f) || (dPrev <= 0.01f && dCurr >= -0.01f)) {
                            if (planeY && std::abs(p->normal.y) > 1e-6f) {
                                float newPlaneY = p->position.y - (p->normal.x * (currLoc.x - p->position.x) + 
                                        p->normal.z * (currLoc.z - p->position.z)) / p->normal.y + mapData->minY;
                            
                                if (std::isnan(*planeY) || newPlaneY > *planeY) {
                                    *planeY = newPlaneY;
                                }
                            }
                            collided =  true;
                            if (distance && std::abs(dCurr) < closestDistance) {
                                closestDistance = std::abs(dCurr);//get distance from pos to plane hit
                                if (plane) *plane = p;
                            }
                        }
                    }


                    if (type == 2) { // Mesh auto-hitbox collision
                        Mesh* mesh = (Mesh*)obj;
                        if (meshHitBoxContainsPoint(mapData, mesh, end, planeY)) {
                            collided = true;
                            if (distance && 0.f < closestDistance) {
                                closestDistance = 0.f;
                            }
                        }
                    }
                }
            }
        }
    }
    if (distance) *distance = closestDistance;
    return collided;
}

bool Map::getSurfaceY(float x, float z, float nearY, float& outY) const {
    int gx, gy, gz;
    worldToGrid(x, nearY, z, gx, gy, gz);

    void* obj = getObjRaw(gx, gy, gz);
    if (obj == nullptr) return false;
    if (*(int*)obj != 1) return false;

    Plane* p = (Plane*)obj;
    if (std::abs(p->normal.y) < 1e-6f) return false; // vertical plane, no Y solution

    float localX = x - mapData->minX;
    float localZ = z - mapData->minZ;

    // solve plane equation for Y
    float localY = p->position.y 
                 - (p->normal.x * (localX - p->position.x) 
                 +  p->normal.z * (localZ - p->position.z)) 
                 / p->normal.y;

    outY = localY + mapData->minY;
    return true;
}

Cell* Map::getObjRaw(int x, int y, int z) const {
    if (!inBoundsRaw(x, y, z)) return nullptr;
    return mapData->getCell(x, y, z);
}

bool Map::isWallRaw(int x, int y, int z) const {
    Cell* cell = (Cell*)getObjRaw(x, y, z);
    if (!cell) return false;
    for (int i = 0; i < cell->count; i++)
        if (cell->items[i] && *(int*)cell->items[i] == 0) return true;
    return false;
}