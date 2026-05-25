#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <fstream>
#include <sstream>
#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <cmath>
#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <cstdio>
#include <cctype>
#include <cstddef>

#include "Box.h"
#include "Plane.h"
#include "Mesh.h"
#include "Player.h"
#include "Texture.h"
#include "Cell.h"
#include "BVH.h"
#include "Mat3.h"
#include "MapEditProtocol.h"
#include "tiny_gltf.h"

// ---------------------------------------------------------------------------
// MAP DATA
// ---------------------------------------------------------------------------

struct CollisionAABB {
    Vec3f min = {0.f, 0.f, 0.f};
    Vec3f max = {0.f, 0.f, 0.f};
};

struct HitBox {
    // Mesh/model-space boxes. They are shared by all instances of the same GLB.
    std::vector<CollisionAABB> boxes;
};

struct Light {
    int type = 3;

    // worldPosition is the value from map.json.
    // position is grid-local, matching the coordinate space used by the renderer.
    Vec3f worldPosition = {0.f, 0.f, 0.f};
    Vec3f position      = {0.f, 0.f, 0.f};

    Vec3f color = {1.f, 1.f, 1.f};
    float intensity = 1.f;
    float radius    = 8.f;

    Vec3f normal = {0.f, -1.f, 0.f};
    float angle = 0.f;
};

struct MapData {
    std::map<std::string, Texture*> textures;

    // Type 3 objects from map.json. They are render data only, not collision/grid objects.
    std::vector<Light> lights;

    // GLB triangle cache: maps file path → shared, immutable triangle list.
    // Triangles are in raw model space. Mesh instances point into this cache
    // and must NOT delete these pointers (ownsTris = false for shared copies).
    std::map<std::string, std::vector<Texture*>> meshTextureCache;
    std::map<std::string, std::vector<Triangle>*> meshCache;

    // Animated GLB cache. Triangle data is shared, but each Mesh instance gets
    // its own Skeleton copy so animation time and crossfades stay independent.
    std::map<std::string, Skeleton*> meshSkeletonCache;
    std::map<std::string, std::vector<SkinVertex>> meshSkinVertexCache;

    // Runtime/editor change counter. Renderer re-uploads the scene when this changes.
    uint64_t version = 1;
    void markDirty() { ++version; if (version == 0) version = 1; }

    struct MeshAsset {
        std::vector<Triangle>* tris = nullptr;     // owned by meshCache
        std::vector<Texture*>  textures;           // non-owning texture pointers

        Vec3f modelMin    = {0,0,0};
        Vec3f modelMax    = {0,0,0};
        Vec3f modelCenter = {0,0,0};
        Vec3f modelSize   = {0,0,0};

        HitBox hitBox;                              // shared local/model-space collision data

        Skeleton* skeleton = nullptr;              // owned by meshSkeletonCache
        std::vector<SkinVertex>* skinVertices = nullptr; // owned by meshSkinVertexCache
    };

    std::map<std::string, MeshAsset> meshAssets;
    std::map<const std::vector<Triangle>*, const HitBox*> hitBoxByTris;
    std::map<const Mesh*, bool> meshCollisionEnabled;

    struct RuntimeObjectRef {
        int type = -1;
        void* object = nullptr;
        size_t lightIndex = 0;
    };

    // Stable IDs are required for replicated add/remove operations. Objects
    // loaded from JSON are registered here only when their JSON block contains
    // an "id" field. Runtime-created objects always get/keep an ID.
    std::map<std::string, RuntimeObjectRef> runtimeObjectIds;
    std::map<std::string, MapObjectEdit> runtimeObjectEdits;

    Skeleton*              _lastParsedSkeleton  = nullptr;
    std::vector<SkinVertex> _lastParsedSkinVerts;

    Cell* grid = nullptr;

    void** pageMem = nullptr;
    int numObjects = 0;

    float minX = 0, minY = 0, minZ = 0;
    int sizeX = 0, sizeY = 0, sizeZ = 0;

    ~MapData() {
        if (pageMem) {
            for (int i = 0; i < numObjects; i++) {
                if (!pageMem[i]) continue;
                int type = *(int*)(pageMem[i]);
                if (type == 0) {
                    delete (Box*)pageMem[i];
                } else if (type == 1) {
                    delete (Plane*)pageMem[i];
                } else if (type == 2) {
                    delete (Mesh*)pageMem[i];
                }
            }
            delete[] pageMem;
        }

        // -------------------------------------------------------------------
        // 2. FREE GRID (NO OBJECT DELETION HERE)
        // -------------------------------------------------------------------
        delete[] grid;

        // -------------------------------------------------------------------
        // 3. FREE MESH CACHE (single owner of all triangle data)
        // -------------------------------------------------------------------
        for (auto& [k, v] : meshCache) {
            delete v;
        }
        meshCache.clear();

        for (auto& [k, v] : meshSkeletonCache) {
            delete v;
        }
        meshSkeletonCache.clear();
        meshSkinVertexCache.clear();

        delete _lastParsedSkeleton;
        _lastParsedSkeleton = nullptr;

        // -------------------------------------------------------------------
        // 4. TEXTURES (if you own them)
        // -------------------------------------------------------------------
        for (auto& [k, v] : textures) {
            delete v;
        }
        textures.clear();
    }

    Cell* getCell(int x, int y, int z) {
        if (x < 0 || x >= sizeX || y < 0 || y >= sizeY || z < 0 || z >= sizeZ)
            return nullptr;
        return &grid[index(x, y, z)];
    }

    // -----------------------------------------------------------------------
    inline int index(int x, int y, int z) const {
        return x + y * sizeX + z * sizeX * sizeY;
    }

    // -----------------------------------------------------------------------
    std::string findValue(const std::string& block, std::string key) {
        size_t keyPos = block.find(key);
        if (keyPos == std::string::npos) return "";

        size_t colonPos = block.find(':', keyPos);
        size_t start = block.find_first_not_of(" \t\n\r", colonPos + 1);

        if (block[start] == '"') {
            size_t end = block.find('"', start + 1);
            return block.substr(start + 1, end - start - 1);
        }

        if (block[start] == '[') {
            size_t end = block.find(']', start + 1);
            return block.substr(start, end - start + 1);
        }

        size_t end = block.find_first_of(", \n\r}", start);
        return block.substr(start, end - start);
    }

    std::string findDirectValue(const std::string& block, std::string key) {
        // Like findValue(), but ignores keys that only appear inside a nested
        // child object. This lets us scan JSON maps such as
        // "objects": { "light": { ... } } without accidentally treating the
        // container as the light object.
        size_t searchEnd = block.size();
        size_t child = block.find('{', 1);
        if (child != std::string::npos) searchEnd = child;
        std::string head = block.substr(0, searchEnd);
        return findValue(head, key);
    }

    Vec3f parseVec(std::string data) {
        if (data.empty()) return {0,0,0};
        for (char& c : data)
            if (c == ',' || c == '[' || c == ']')
                c = ' ';

        std::stringstream ss(data);
        Vec3f v;
        ss >> v.x >> v.y >> v.z;
        return v;
    }

    float parseFloat(const std::string& data, float fallback = 0.f) {
        if (data.empty()) return fallback;
        try {
            return std::stof(data);
        } catch (...) {
            return fallback;
        }
    }

bool loadGLB(const std::string& filename,
             std::vector<Triangle>& out_triangles, std::vector<Texture**>& ret_textures)
{
    tinygltf::Model model;
    tinygltf::TinyGLTF loader;
    std::string err, warn;

    loader.SetPreserveImageChannels(false);
    if (!loader.LoadBinaryFromFile(&model, &err, &warn, filename)) {
        std::cerr << "GLB LOAD FAILED: " << err << "\n";
        return false;
    }

    std::cout << "Meshes: " << model.meshes.size()
              << " Materials: " << model.materials.size()
              << " Textures: " << model.textures.size()
              << " Images: " << model.images.size() << "\n";

    struct Mat4f {
        // glTF matrices are column-major.
        float m[16];
    };

    auto identity = []() -> Mat4f {
        Mat4f r{};
        r.m[0] = r.m[5] = r.m[10] = r.m[15] = 1.f;
        return r;
    };

    auto multiply = [](const Mat4f& a, const Mat4f& b) -> Mat4f {
        Mat4f r{};
        for (int c = 0; c < 4; ++c) {
            for (int row = 0; row < 4; ++row) {
                r.m[c * 4 + row] =
                    a.m[0 * 4 + row] * b.m[c * 4 + 0] +
                    a.m[1 * 4 + row] * b.m[c * 4 + 1] +
                    a.m[2 * 4 + row] * b.m[c * 4 + 2] +
                    a.m[3 * 4 + row] * b.m[c * 4 + 3];
            }
        }
        return r;
    };

    auto transformPoint = [](const Mat4f& m, const Vec3f& p) -> Vec3f {
        return {
            m.m[0] * p.x + m.m[4] * p.y + m.m[8]  * p.z + m.m[12],
            m.m[1] * p.x + m.m[5] * p.y + m.m[9]  * p.z + m.m[13],
            m.m[2] * p.x + m.m[6] * p.y + m.m[10] * p.z + m.m[14]
        };
    };

    auto nodeLocalMatrix = [&](const tinygltf::Node& node) -> Mat4f {
        if (node.matrix.size() == 16) {
            Mat4f r{};
            for (int i = 0; i < 16; ++i) r.m[i] = (float)node.matrix[i];
            return r;
        }

        Mat4f t = identity();
        if (node.translation.size() == 3) {
            t.m[12] = (float)node.translation[0];
            t.m[13] = (float)node.translation[1];
            t.m[14] = (float)node.translation[2];
        }

        Mat4f r = identity();
        if (node.rotation.size() == 4) {
            const float x = (float)node.rotation[0];
            const float y = (float)node.rotation[1];
            const float z = (float)node.rotation[2];
            const float w = (float)node.rotation[3];
            const float xx = x * x, yy = y * y, zz = z * z;
            const float xy = x * y, xz = x * z, yz = y * z;
            const float wx = w * x, wy = w * y, wz = w * z;

            r.m[0]  = 1.f - 2.f * (yy + zz);
            r.m[1]  = 2.f * (xy + wz);
            r.m[2]  = 2.f * (xz - wy);
            r.m[4]  = 2.f * (xy - wz);
            r.m[5]  = 1.f - 2.f * (xx + zz);
            r.m[6]  = 2.f * (yz + wx);
            r.m[8]  = 2.f * (xz + wy);
            r.m[9]  = 2.f * (yz - wx);
            r.m[10] = 1.f - 2.f * (xx + yy);
        }

        Mat4f s = identity();
        if (node.scale.size() == 3) {
            s.m[0]  = (float)node.scale[0];
            s.m[5]  = (float)node.scale[1];
            s.m[10] = (float)node.scale[2];
        }

        return multiply(multiply(t, r), s);
    };

    auto clampByte = [](double v) -> uint8_t {
        if (v < 0.0) return 0;
        if (v > 255.0) return 255;
        return (uint8_t)(v + 0.5);
    };

    auto pushTextureRef = [&](const std::string& texKey, Texture* tex) -> int {
        if (!textures.count(texKey)) textures[texKey] = tex;
        int localTexIndex = (int)ret_textures.size();
        ret_textures.push_back(&textures[texKey]);
        return localTexIndex;
    };

    auto addImageTexture = [&](int texIndex) -> int {
        if (texIndex < 0 || texIndex >= (int)model.textures.size()) return -1;
        const auto& tex = model.textures[texIndex];
        if (tex.source < 0 || tex.source >= (int)model.images.size()) return -1;

        const auto& img = model.images[tex.source];
        if (img.width <= 0 || img.height <= 0 || img.image.empty()) return -1;

        std::string texKey = filename + "_img_" + std::to_string(tex.source);
        if (textures.count(texKey)) {
            return pushTextureRef(texKey, textures[texKey]);
        }

        Texture* newTex = new Texture();
        newTex->width = img.width;
        newTex->height = img.height;
        newTex->channels = 4;

        size_t totalPixels = (size_t)img.width * (size_t)img.height;
        newTex->pixels = new uint32_t[totalPixels];

        const int comp = (std::max)(1, img.component);
        for (size_t i = 0; i < totalPixels; i++) {
            const size_t base = i * (size_t)comp;
            uint8_t r = img.image[base + 0];
            uint8_t g = comp > 1 ? img.image[base + 1] : r;
            uint8_t b = comp > 2 ? img.image[base + 2] : r;
            newTex->pixels[i] = ((uint32_t)r << 16) | ((uint32_t)g << 8) | (uint32_t)b;
        }

        newTex->valid = true;
        return pushTextureRef(texKey, newTex);
    };

    auto addMaterialColorTexture = [&](int materialIndex, const tinygltf::Material& mat) -> int {
        double r = 1.0, g = 1.0, b = 1.0;
        if (mat.pbrMetallicRoughness.baseColorFactor.size() >= 3) {
            r = mat.pbrMetallicRoughness.baseColorFactor[0];
            g = mat.pbrMetallicRoughness.baseColorFactor[1];
            b = mat.pbrMetallicRoughness.baseColorFactor[2];
        }
        if (mat.extensions.count("KHR_materials_pbrSpecularGlossiness")) {
            const auto& ext = mat.extensions.at("KHR_materials_pbrSpecularGlossiness");
            if (ext.Has("diffuseFactor") && ext.Get("diffuseFactor").IsArray() && ext.Get("diffuseFactor").ArrayLen() >= 3) {
                r = ext.Get("diffuseFactor").Get(0).Get<double>();
                g = ext.Get("diffuseFactor").Get(1).Get<double>();
                b = ext.Get("diffuseFactor").Get(2).Get<double>();
            }
        }

        const uint8_t rb = clampByte(r * 255.0);
        const uint8_t gb = clampByte(g * 255.0);
        const uint8_t bb = clampByte(b * 255.0);
        std::string texKey = filename + "_mat_" + std::to_string(materialIndex) +
                             "_" + std::to_string(rb) + "_" + std::to_string(gb) + "_" + std::to_string(bb);

        if (textures.count(texKey)) {
            return pushTextureRef(texKey, textures[texKey]);
        }

        Texture* newTex = new Texture();
        newTex->width = 1;
        newTex->height = 1;
        newTex->channels = 4;
        newTex->pixels = new uint32_t[1];
        newTex->pixels[0] = ((uint32_t)rb << 16) | ((uint32_t)gb << 8) | (uint32_t)bb;
        newTex->valid = true;
        return pushTextureRef(texKey, newTex);
    };

    uint32_t skinVertexOffset = 0;
    const bool applyNodeTransforms = model.skins.empty();

    auto processMesh = [&](int meshIndex, const Mat4f& nodeMatrix) {
        if (meshIndex < 0 || meshIndex >= (int)model.meshes.size()) return;
        const auto& mesh = model.meshes[meshIndex];

        std::cout << "\n[Mesh " << meshIndex << "] Primitives: "
                  << mesh.primitives.size() << "\n";

        for (size_t pi = 0; pi < mesh.primitives.size(); pi++) {
            const auto& primitive = mesh.primitives[pi];

            std::cout << "\n  [Primitive " << pi << "]\n";

            if (primitive.mode != TINYGLTF_MODE_TRIANGLES) {
                std::cout << "   SKIP (not triangles)\n";
                continue;
            }

            bool hasMaterial = primitive.material >= 0 && primitive.material < (int)model.materials.size();
            int localTexIndex = -1;

            if (hasMaterial) {
                const auto& mat = model.materials[primitive.material];
                int texIndex = mat.pbrMetallicRoughness.baseColorTexture.index;

                if (mat.extensions.count("KHR_materials_pbrSpecularGlossiness")) {
                    const auto& ext = mat.extensions.at("KHR_materials_pbrSpecularGlossiness");
                    if (ext.Has("diffuseTexture")) {
                        texIndex = ext.Get("diffuseTexture").Get("index").Get<int>();
                    }
                }

                localTexIndex = addImageTexture(texIndex);
                if (localTexIndex < 0) {
                    // GLBs such as wall.glb can have materials but no embedded images.
                    // Use the material base color as a tiny texture so the mesh is not untextured.
                    localTexIndex = addMaterialColorTexture(primitive.material, mat);
                }
            } else {
                std::cout << "   NO MATERIAL\n";
            }

            auto itPos = primitive.attributes.find("POSITION");
            if (itPos == primitive.attributes.end()) {
                std::cout << "   NO POSITION (skip)\n";
                continue;
            }

            const auto& posAccessor = model.accessors[itPos->second];
            const auto& posView = model.bufferViews[posAccessor.bufferView];
            const auto& posBuffer = model.buffers[posView.buffer];

            uint32_t thisPrimitiveSkinOffset = skinVertexOffset;

            const unsigned char* posData =
                posBuffer.data.data() + posView.byteOffset + posAccessor.byteOffset;

            size_t posStride = posAccessor.ByteStride(posView);
            if (posStride == 0) posStride = sizeof(float) * 3;

            const unsigned char* uvData = nullptr;
            size_t uvStride = 0;

            const unsigned char* colData = nullptr;
            size_t colStride = 0;

            if (primitive.attributes.count("TEXCOORD_0")) {
                const auto& uvAccessor = model.accessors.at(primitive.attributes.at("TEXCOORD_0"));
                const auto& uvView = model.bufferViews[uvAccessor.bufferView];
                const auto& uvBuffer = model.buffers[uvView.buffer];

                uvData = uvBuffer.data.data() + uvView.byteOffset + uvAccessor.byteOffset;
                uvStride = uvAccessor.ByteStride(uvView);
                if (uvStride == 0) uvStride = sizeof(float) * 2;

                std::cout << "   HAS UVs\n";
            } else {
                std::cout << "   NO UVs\n";
                if (primitive.attributes.count("COLOR_0")) {
                    const auto& cAccessor = model.accessors.at(primitive.attributes.at("COLOR_0"));
                    const auto& cView = model.bufferViews[cAccessor.bufferView];
                    const auto& cBuffer = model.buffers[cView.buffer];

                    colData = cBuffer.data.data() + cView.byteOffset + cAccessor.byteOffset;
                    colStride = cAccessor.ByteStride(cView);
                    std::cout << "   HAS VERTEX COLORS\n";
                } else {
                    std::cout << "   NO VERTEX COLORS\n";
                }
            }

            bool indexed = primitive.indices >= 0;
            const tinygltf::Accessor* idxAccessor = nullptr;
            const unsigned char* idxData = nullptr;
            size_t idxStride = 0;

            if (indexed) {
                idxAccessor = &model.accessors[primitive.indices];
                const auto& idxView = model.bufferViews[idxAccessor->bufferView];
                const auto& idxBuffer = model.buffers[idxView.buffer];

                idxData = idxBuffer.data.data() + idxView.byteOffset + idxAccessor->byteOffset;
                idxStride = idxAccessor->ByteStride(idxView);
                if (idxStride == 0) {
                    switch (idxAccessor->componentType) {
                        case TINYGLTF_COMPONENT_TYPE_UNSIGNED_INT:   idxStride = sizeof(uint32_t); break;
                        case TINYGLTF_COMPONENT_TYPE_UNSIGNED_SHORT: idxStride = sizeof(uint16_t); break;
                        default:                                    idxStride = sizeof(uint8_t);  break;
                    }
                }

                std::cout << "   INDEXED: " << idxAccessor->count << "\n";
            } else {
                std::cout << "   NON-INDEXED\n";
            }

            auto getIndex = [&](size_t i) -> unsigned int {
                if (!indexed) return (unsigned int)i;
                const unsigned char* p = idxData + i * idxStride;
                switch (idxAccessor->componentType) {
                    case TINYGLTF_COMPONENT_TYPE_UNSIGNED_SHORT: return *(const uint16_t*)p;
                    case TINYGLTF_COMPONENT_TYPE_UNSIGNED_INT:   return *(const uint32_t*)p;
                    default:                                    return *p;
                }
            };

            auto getPos = [&](size_t i) -> Vec3f {
                const float* f = reinterpret_cast<const float*>(posData + i * posStride);
                Vec3f p = { f[0], f[1], f[2] };
                return applyNodeTransforms ? transformPoint(nodeMatrix, p) : p;
            };

            auto getUV = [&](size_t i) -> Vec2f {
                if (!uvData) return {0,0};
                const float* f = reinterpret_cast<const float*>(uvData + i * uvStride);
                return { f[0], 1.0f - f[1] };
            };

            size_t count = indexed ? idxAccessor->count : posAccessor.count;
            int usedVertexColor = colData ? 1 : 0;
            int usedTexture = localTexIndex >= 0 ? 1 : 0;

            for (size_t i = 0; i + 2 < count; i += 3) {
                unsigned int i0 = getIndex(i);
                unsigned int i1 = getIndex(i + 1);
                unsigned int i2 = getIndex(i + 2);

                Triangle tri;
                tri.textureID = localTexIndex;

                tri.v1.pos = getPos(i0);
                tri.v1.uv  = getUV(i0);
                tri.v1.skinIndex = thisPrimitiveSkinOffset + i0;

                tri.v2.pos = getPos(i1);
                tri.v2.uv  = getUV(i1);
                tri.v2.skinIndex = thisPrimitiveSkinOffset + i1;

                tri.v3.pos = getPos(i2);
                tri.v3.uv  = getUV(i2);
                tri.v3.skinIndex = thisPrimitiveSkinOffset + i2;

                out_triangles.push_back(tri);
            }

            skinVertexOffset += (uint32_t)posAccessor.count;

            std::cout << "   Color usage: vertex="
                      << usedVertexColor
                      << " texture="
                      << usedTexture;
        }
    };

    bool processedSceneNodes = false;
    auto traverseNode = [&](auto&& self, int nodeIndex, const Mat4f& parentMatrix) -> void {
        if (nodeIndex < 0 || nodeIndex >= (int)model.nodes.size()) return;
        const tinygltf::Node& node = model.nodes[nodeIndex];
        Mat4f worldMatrix = multiply(parentMatrix, nodeLocalMatrix(node));

        if (node.mesh >= 0) {
            processedSceneNodes = true;
            processMesh(node.mesh, worldMatrix);
        }

        for (int child : node.children) {
            self(self, child, worldMatrix);
        }
    };

    if (!model.scenes.empty()) {
        int sceneIndex = model.defaultScene >= 0 ? model.defaultScene : 0;
        if (sceneIndex >= 0 && sceneIndex < (int)model.scenes.size()) {
            Mat4f root = identity();
            for (int nodeIndex : model.scenes[sceneIndex].nodes) {
                traverseNode(traverseNode, nodeIndex, root);
            }
        }
    }

    if (!processedSceneNodes) {
        Mat4f root = identity();
        for (size_t mi = 0; mi < model.meshes.size(); ++mi) {
            processMesh((int)mi, root);
        }
    }

    delete _lastParsedSkeleton;
    _lastParsedSkeleton = new Skeleton();
    _lastParsedSkinVerts.clear();
    if (!AnimParser::parse(model, *_lastParsedSkeleton, _lastParsedSkinVerts)) {
        delete _lastParsedSkeleton;
        _lastParsedSkeleton = nullptr;
    }

    return true;
}


    HitBox buildAutoHitBox(const std::vector<Triangle>& tris,
                           const Vec3f& modelMin,
                           const Vec3f& modelMax,
                           const Vec3f& modelSize) const {
        HitBox hitBox;
        if (tris.empty()) return hitBox;

        const float sxAbs = std::abs(modelSize.x);
        const float syAbs = std::abs(modelSize.y);
        const float szAbs = std::abs(modelSize.z);
        const float maxAxis = (std::max)({sxAbs, syAbs, szAbs});
        if (maxAxis < 1e-6f) {
            hitBox.boxes.push_back({modelMin, modelMax});
            return hitBox;
        }

        const int MAX_AXIS_CELLS = 10;
        const int MAX_AUTO_BOXES = 64;

        auto axisCells = [&](float axisSize) -> int {
            int c = (int)std::ceil((axisSize / maxAxis) * (float)MAX_AXIS_CELLS);
            if (c < 1) c = 1;
            if (c > MAX_AXIS_CELLS) c = MAX_AXIS_CELLS;
            return c;
        };

        const int nx = axisCells(sxAbs);
        const int ny = axisCells(syAbs);
        const int nz = axisCells(szAbs);

        const Vec3f cellSize = {
            sxAbs > 1e-6f ? sxAbs / (float)nx : 1.f,
            syAbs > 1e-6f ? syAbs / (float)ny : 1.f,
            szAbs > 1e-6f ? szAbs / (float)nz : 1.f
        };

        auto idx = [&](int x, int y, int z) -> int {
            return x + y * nx + z * nx * ny;
        };

        auto clampIndex = [](int v, int maxV) -> int {
            if (v < 0) return 0;
            if (v >= maxV) return maxV - 1;
            return v;
        };

        std::vector<uint8_t> filled((size_t)nx * (size_t)ny * (size_t)nz, 0);

        for (const Triangle& tri : tris) {
            const float tMinX = (std::min)({tri.v1.pos.x, tri.v2.pos.x, tri.v3.pos.x});
            const float tMaxX = (std::max)({tri.v1.pos.x, tri.v2.pos.x, tri.v3.pos.x});
            const float tMinY = (std::min)({tri.v1.pos.y, tri.v2.pos.y, tri.v3.pos.y});
            const float tMaxY = (std::max)({tri.v1.pos.y, tri.v2.pos.y, tri.v3.pos.y});
            const float tMinZ = (std::min)({tri.v1.pos.z, tri.v2.pos.z, tri.v3.pos.z});
            const float tMaxZ = (std::max)({tri.v1.pos.z, tri.v2.pos.z, tri.v3.pos.z});

            const int x0 = clampIndex((int)std::floor((tMinX - modelMin.x) / cellSize.x), nx);
            const int x1 = clampIndex((int)std::floor((tMaxX - modelMin.x) / cellSize.x), nx);
            const int y0 = clampIndex((int)std::floor((tMinY - modelMin.y) / cellSize.y), ny);
            const int y1 = clampIndex((int)std::floor((tMaxY - modelMin.y) / cellSize.y), ny);
            const int z0 = clampIndex((int)std::floor((tMinZ - modelMin.z) / cellSize.z), nz);
            const int z1 = clampIndex((int)std::floor((tMaxZ - modelMin.z) / cellSize.z), nz);

            for (int z = z0; z <= z1; ++z)
            for (int y = y0; y <= y1; ++y)
            for (int x = x0; x <= x1; ++x) {
                filled[(size_t)idx(x, y, z)] = 1;
            }
        }

        // Make common closed shapes solid enough for point-based player collision:
        // for every occupied X/Z column, fill between the lowest and highest marked voxel.
        for (int z = 0; z < nz; ++z) {
            for (int x = 0; x < nx; ++x) {
                int minY = ny;
                int maxY = -1;
                for (int y = 0; y < ny; ++y) {
                    if (filled[(size_t)idx(x, y, z)]) {
                        if (y < minY) minY = y;
                        if (y > maxY) maxY = y;
                    }
                }
                if (maxY >= minY) {
                    for (int y = minY; y <= maxY; ++y) {
                        filled[(size_t)idx(x, y, z)] = 1;
                    }
                }
            }
        }

        std::vector<uint8_t> used(filled.size(), 0);
        auto isFreeFilled = [&](int x, int y, int z) -> bool {
            const size_t i = (size_t)idx(x, y, z);
            return filled[i] && !used[i];
        };

        for (int y = 0; y < ny; ++y) {
            for (int z = 0; z < nz; ++z) {
                for (int x = 0; x < nx; ++x) {
                    if (!isFreeFilled(x, y, z)) continue;

                    int x1 = x;
                    while (x1 + 1 < nx && isFreeFilled(x1 + 1, y, z)) ++x1;

                    int z1 = z;
                    bool canGrowZ = true;
                    while (canGrowZ && z1 + 1 < nz) {
                        for (int xx = x; xx <= x1; ++xx) {
                            if (!isFreeFilled(xx, y, z1 + 1)) {
                                canGrowZ = false;
                                break;
                            }
                        }
                        if (canGrowZ) ++z1;
                    }

                    int y1 = y;
                    bool canGrowY = true;
                    while (canGrowY && y1 + 1 < ny) {
                        for (int zz = z; zz <= z1 && canGrowY; ++zz) {
                            for (int xx = x; xx <= x1; ++xx) {
                                if (!isFreeFilled(xx, y1 + 1, zz)) {
                                    canGrowY = false;
                                    break;
                                }
                            }
                        }
                        if (canGrowY) ++y1;
                    }

                    for (int yy = y; yy <= y1; ++yy)
                    for (int zz = z; zz <= z1; ++zz)
                    for (int xx = x; xx <= x1; ++xx) {
                        used[(size_t)idx(xx, yy, zz)] = 1;
                    }

                    CollisionAABB box;
                    box.min = {
                        modelMin.x + (float)x * cellSize.x,
                        modelMin.y + (float)y * cellSize.y,
                        modelMin.z + (float)z * cellSize.z
                    };
                    box.max = {
                        modelMin.x + (float)(x1 + 1) * cellSize.x,
                        modelMin.y + (float)(y1 + 1) * cellSize.y,
                        modelMin.z + (float)(z1 + 1) * cellSize.z
                    };

                    if (box.max.x > modelMax.x) box.max.x = modelMax.x;
                    if (box.max.y > modelMax.y) box.max.y = modelMax.y;
                    if (box.max.z > modelMax.z) box.max.z = modelMax.z;

                    hitBox.boxes.push_back(box);
                }
            }
        }

        // If an irregular mesh produced too many boxes, keep collision cheap and safe.
        if (hitBox.boxes.empty() || hitBox.boxes.size() > (size_t)MAX_AUTO_BOXES) {
            hitBox.boxes.clear();
            hitBox.boxes.push_back({modelMin, modelMax});
        }

        return hitBox;
    }

    const HitBox* getHitBoxForMesh(const Mesh* mesh) const {
        if (!mesh || !mesh->tris) return nullptr;
        auto it = hitBoxByTris.find(mesh->tris);
        if (it == hitBoxByTris.end()) return nullptr;
        return it->second;
    }

    bool isMeshCollisionEnabled(const Mesh* mesh) const {
        if (!mesh) return false;
        auto it = meshCollisionEnabled.find(mesh);
        if (it == meshCollisionEnabled.end()) return true;
        return it->second;
    }

    MeshAsset* getOrLoadMeshAsset(const std::string& path) {
        auto assetIt = meshAssets.find(path);
        if (assetIt != meshAssets.end()) return &assetIt->second;

        std::vector<Triangle>* tris = nullptr;
        std::vector<Texture*> meshTextures;

        auto cacheIt = meshCache.find(path);
        if (cacheIt != meshCache.end()) {
            tris = cacheIt->second;

            auto texCacheIt = meshTextureCache.find(path);
            if (texCacheIt != meshTextureCache.end()) {
                meshTextures = texCacheIt->second;
            }

            std::cout << "[MeshCache] HIT \"" << path << "\" ("
                      << tris->size() << " tris, "
                      << meshTextures.size() << " textures)\n";
        } else {
            std::vector<Texture**> loadedTextureRefs;
            tris = new std::vector<Triangle>();

            if (!loadGLB(path, *tris, loadedTextureRefs)) {
                delete tris;
                return nullptr;
            }

            meshCache[path] = tris;

            for (Texture** texRef : loadedTextureRefs) {
                meshTextures.push_back(*texRef);
            }
            meshTextureCache[path] = meshTextures;

            if (_lastParsedSkeleton && !_lastParsedSkinVerts.empty()) {
                delete meshSkeletonCache[path];
                meshSkeletonCache[path] = new Skeleton(*_lastParsedSkeleton);
                meshSkinVertexCache[path] = _lastParsedSkinVerts;

                delete _lastParsedSkeleton;
                _lastParsedSkeleton = nullptr;
                _lastParsedSkinVerts.clear();
            }

            std::cout << "[MeshCache] LOAD \"" << path << "\" ("
                      << tris->size() << " tris, "
                      << meshTextures.size() << " textures)\n";
        }

        if (!tris || tris->empty()) return nullptr;

        MeshAsset asset;
        asset.tris = tris;
        asset.textures = meshTextures;

        float mX = (*tris)[0].v1.pos.x, mY = (*tris)[0].v1.pos.y, mZ = (*tris)[0].v1.pos.z;
        float MX = mX, MY = mY, MZ = mZ;
        for (const auto& tri : *tris) {
            const Vec3f pts[3] = {tri.v1.pos, tri.v2.pos, tri.v3.pos};
            for (int i = 0; i < 3; i++) {
                if (pts[i].x < mX) mX = pts[i].x; if (pts[i].x > MX) MX = pts[i].x;
                if (pts[i].y < mY) mY = pts[i].y; if (pts[i].y > MY) MY = pts[i].y;
                if (pts[i].z < mZ) mZ = pts[i].z; if (pts[i].z > MZ) MZ = pts[i].z;
            }
        }

        asset.modelMin    = {mX, mY, mZ};
        asset.modelMax    = {MX, MY, MZ};
        asset.modelCenter = {(mX + MX) * 0.5f, (mY + MY) * 0.5f, (mZ + MZ) * 0.5f};
        asset.modelSize   = {MX - mX, MY - mY, MZ - mZ};
        asset.hitBox      = buildAutoHitBox(*tris, asset.modelMin, asset.modelMax, asset.modelSize);

        std::cout << "[Collision] \"" << path << "\" -> "
                  << asset.hitBox.boxes.size() << " AABBs\n";

        auto skelIt = meshSkeletonCache.find(path);
        auto skinIt = meshSkinVertexCache.find(path);
        if (skelIt != meshSkeletonCache.end() && skelIt->second &&
            skinIt != meshSkinVertexCache.end() && !skinIt->second.empty()) {
            asset.skeleton = skelIt->second;
            asset.skinVertices = &skinIt->second;
        }

        auto [it, inserted] = meshAssets.emplace(path, asset);
        hitBoxByTris[it->second.tris] = &it->second.hitBox;
        return &it->second;
    }

    void attachMeshTexturesAndAnimation(Mesh* mesh, const MeshAsset& asset) {
        mesh->textures = new std::vector<Texture*>();
        for (Texture* tex : asset.textures) {
            mesh->textures->push_back(tex);
        }

        mesh->flattenForGPU();

        if (asset.skeleton && asset.skinVertices && !asset.skinVertices->empty()) {
            mesh->skeleton = new Skeleton(*asset.skeleton);
            mesh->anim.skeleton = mesh->skeleton;
            mesh->skinVertices = *asset.skinVertices;

            mesh->skinCtx = new SkinningContext();
            buildSkinningContext(
                *mesh->skinCtx,
                *asset.tris,
                *asset.skinVertices,
                (uint32_t)mesh->skeleton->bones.size(),
                mesh->d_tris,
                mesh->d_fullNodes,  mesh->numFullNodes,
                mesh->d_fullTriIdx, mesh->numFullTriIdx
            );

            if (mesh->hasAnimation("idle")) {
                mesh->playAnimation("idle");
            } else if (mesh->hasAnimation("Idle")) {
                mesh->playAnimation("Idle");
            } else if (!mesh->skeleton->animations.empty()) {
                mesh->playAnimation(mesh->skeleton->animations[0].name);
            }
        }
    }

    void applyMeshTextureOverride(Mesh* mesh, Texture* texture) {
        if (!mesh || !texture) return;
        if (!mesh->textures) mesh->textures = new std::vector<Texture*>();

        // Only use the JSON texture as a fallback. Embedded GLB image/material
        // textures stay authoritative when they exist.
        if (mesh->textures->empty()) {
            mesh->textures->push_back(texture);
            mesh->flattenForGPU();
        }
    }

    Mesh* createMesh(const std::string& path,
                     Vec3f targetC0,
                     Vec3f targetC1,
                     const Mat3& meshRot = Mat3::identity(),
                     Vec3f scaleOverride = {0,0,0},
                     Vec3f* outWorldC0 = nullptr,
                     Vec3f* outWorldC1 = nullptr) {
        MeshAsset* asset = getOrLoadMeshAsset(path);
        if (!asset || !asset->tris || asset->tris->empty()) return nullptr;

        const float targetMinX = (std::min)(targetC0.x, targetC1.x);
        const float targetMinY = (std::min)(targetC0.y, targetC1.y);
        const float targetMinZ = (std::min)(targetC0.z, targetC1.z);

        const float targetSizeX = std::abs(targetC1.x - targetC0.x);
        const float targetSizeY = std::abs(targetC1.y - targetC0.y);
        const float targetSizeZ = std::abs(targetC1.z - targetC0.z);

        float sx = scaleOverride.x;
        float sy = scaleOverride.y;
        float sz = scaleOverride.z;

        if (sx > 1e-6f && sy < 1e-6f && sz < 1e-6f) {
            sy = sz = sx;
        }

        if (sx < 1e-6f || sy < 1e-6f || sz < 1e-6f) {
            sx = asset->modelSize.x > 1e-6f ? targetSizeX / asset->modelSize.x : 1.f;
            sy = asset->modelSize.y > 1e-6f ? targetSizeY / asset->modelSize.y : 1.f;
            sz = asset->modelSize.z > 1e-6f ? targetSizeZ / asset->modelSize.z : 1.f;
        }

        Mesh* mesh = new Mesh();
        mesh->type     = 2;
        mesh->tris     = asset->tris;
        mesh->ownsTris = false;

        mesh->modelMin    = asset->modelMin;
        mesh->modelCenter = asset->modelCenter;
        mesh->scale       = {sx, sy, sz};

        Vec3f pv = {
            sx * asset->modelSize.x * 0.5f,
            sy * asset->modelSize.y * 0.5f,
            sz * asset->modelSize.z * 0.5f
        };
        mesh->pivot = pv;

        const float tcX = (targetMinX + targetMinX + targetSizeX) * 0.5f;
        const float tcY = (targetMinY + targetMinY + targetSizeY) * 0.5f;
        const float tcZ = (targetMinZ + targetMinZ + targetSizeZ) * 0.5f;

        mesh->offset = {
            tcX - minX - pv.x,
            tcY - minY - pv.y,
            tcZ - minZ - pv.z
        };
        mesh->rot = meshRot;

        attachMeshTexturesAndAnimation(mesh, *asset);

        if (outWorldC0 || outWorldC1) {
            const float worldSizeX = asset->modelSize.x * sx;
            const float worldSizeY = asset->modelSize.y * sy;
            const float worldSizeZ = asset->modelSize.z * sz;

            Vec3f rMin = {1e30f,1e30f,1e30f};
            Vec3f rMax = {-1e30f,-1e30f,-1e30f};
            for (int ci = 0; ci < 8; ci++) {
                Vec3f corner = {
                    ci & 1 ? worldSizeX : 0.f,
                    ci & 2 ? worldSizeY : 0.f,
                    ci & 4 ? worldSizeZ : 0.f
                };
                Vec3f rc = meshRot.mul(corner);
                if (rc.x < rMin.x) rMin.x = rc.x; if (rc.x > rMax.x) rMax.x = rc.x;
                if (rc.y < rMin.y) rMin.y = rc.y; if (rc.y > rMax.y) rMax.y = rc.y;
                if (rc.z < rMin.z) rMin.z = rc.z; if (rc.z > rMax.z) rMax.z = rc.z;
            }

            if (outWorldC0) *outWorldC0 = {targetMinX + rMin.x, targetMinY + rMin.y, targetMinZ + rMin.z};
            if (outWorldC1) *outWorldC1 = {targetMinX + rMax.x, targetMinY + rMax.y, targetMinZ + rMax.z};
        }

        return mesh;
    }

    Mesh* loadMesh(const std::string& path) {
        MeshAsset* asset = getOrLoadMeshAsset(path);
        if (!asset || !asset->tris || asset->tris->empty()) return nullptr;

        const Vec3f& sz = asset->modelSize;
        Vec3f nrm = {
            sz.x > 1e-6f ? 1.f / sz.x : 1.f,
            sz.y > 1e-6f ? 1.f / sz.y : 1.f,
            sz.z > 1e-6f ? 1.f / sz.z : 1.f
        };

        Mesh* mesh = new Mesh();
        mesh->type = 2;
        mesh->tris = asset->tris;
        mesh->ownsTris = false;

        mesh->modelMin    = asset->modelMin;
        mesh->modelCenter = asset->modelCenter;
        mesh->scale       = nrm;
        mesh->pivot       = { nrm.x * sz.x * 0.5f, nrm.y * sz.y * 0.5f, nrm.z * sz.z * 0.5f };
        mesh->offset      = { 0.f, 0.f, 0.f };

        attachMeshTexturesAndAnimation(mesh, *asset);
        return mesh;
    }


    static Vec3f editVec3(const float v[3]) {
        return {v[0], v[1], v[2]};
    }

    static bool nearlyZeroVec3(const float v[3]) {
        return std::abs(v[0]) < 1e-6f && std::abs(v[1]) < 1e-6f && std::abs(v[2]) < 1e-6f;
    }

    static std::string jsonEscape(const std::string& in) {
        std::string out;
        out.reserve(in.size());
        for (char c : in) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default: out += c; break;
            }
        }
        return out;
    }

    static std::string unescapeJsonKey(const std::string& in) {
        std::string out;
        out.reserve(in.size());
        bool escaped = false;
        for (char c : in) {
            if (escaped) { out.push_back(c); escaped = false; }
            else if (c == '\\') escaped = true;
            else out.push_back(c);
        }
        return out;
    }

    static std::string findObjectKeyBeforeBlock(const std::string& content, size_t blockStart) {
        if (blockStart == std::string::npos || blockStart == 0) return {};
        size_t i = blockStart;
        while (i > 0 && std::isspace((unsigned char)content[i - 1])) --i;
        if (i == 0 || content[i - 1] != ':') return {};
        --i;
        while (i > 0 && std::isspace((unsigned char)content[i - 1])) --i;
        if (i == 0 || content[i - 1] != '"') return {};

        size_t quoteEnd = i - 1;
        size_t quoteStart = quoteEnd;
        while (quoteStart > 0) {
            --quoteStart;
            if (content[quoteStart] != '"') continue;
            size_t slashCount = 0;
            size_t k = quoteStart;
            while (k > 0 && content[k - 1] == '\\') { ++slashCount; --k; }
            if ((slashCount & 1u) == 0u) break;
        }
        if (content[quoteStart] != '"' || quoteStart >= quoteEnd) return {};
        return unescapeJsonKey(content.substr(quoteStart + 1, quoteEnd - quoteStart - 1));
    }

    static size_t findMatchingCurlyBrace(const std::string& text, size_t openPos) {
        bool inString = false;
        bool escaped = false;
        int depth = 0;
        for (size_t i = openPos; i < text.size(); ++i) {
            char c = text[i];
            if (inString) {
                if (escaped) escaped = false;
                else if (c == '\\') escaped = true;
                else if (c == '"') inString = false;
                continue;
            }
            if (c == '"') inString = true;
            else if (c == '{') ++depth;
            else if (c == '}') {
                --depth;
                if (depth == 0) return i;
            }
        }
        return std::string::npos;
    }

    static std::string formatJsonVec3(const float v[3]) {
        std::ostringstream ss;
        ss << "[" << v[0] << ", " << v[1] << ", " << v[2] << "]";
        return ss.str();
    }

    static std::string makeRuntimeObjectId() {
        static uint64_t counter = 1;
        char buf[MAP_EDIT_ID_SIZE]{};
        std::snprintf(buf, sizeof(buf), "obj_%llu", (unsigned long long)counter++);
        return std::string(buf);
    }

    void ensureObjectId(MapObjectEdit& edit) const {
        if (!mapEditGetString(edit.id, sizeof(edit.id)).empty()) return;
        mapEditSetString(edit.id, sizeof(edit.id), makeRuntimeObjectId());
    }

    bool hasRuntimeObjectId(const std::string& id) const {
        return !id.empty() && runtimeObjectIds.find(id) != runtimeObjectIds.end();
    }

    bool getRuntimeObjectEdit(const std::string& id, MapObjectEdit& out) const {
        auto it = runtimeObjectEdits.find(id);
        if (it == runtimeObjectEdits.end()) return false;
        out = it->second;
        return true;
    }

    static Vec3f focusPositionForEdit(const MapObjectEdit& edit) {
        const int type = (int)edit.objectType;
        if (type == (int)MapEditObjectType::Light) {
            return editVec3(edit.position);
        }
        if (type == (int)MapEditObjectType::Plane) {
            Vec3f p = editVec3(edit.position);
            if (std::abs(p.x) > 1e-6f || std::abs(p.y) > 1e-6f || std::abs(p.z) > 1e-6f) {
                return p;
            }
        }
        Vec3f c0 = editVec3(edit.corner0);
        Vec3f c1 = editVec3(edit.corner1);
        return {(c0.x + c1.x) * 0.5f, (c0.y + c1.y) * 0.5f, (c0.z + c1.z) * 0.5f};
    }

    void registerRuntimeObjectId(const std::string& id, int type, void* object, size_t lightIndex = 0) {
        if (id.empty()) return;
        RuntimeObjectRef ref;
        ref.type = type;
        ref.object = object;
        ref.lightIndex = lightIndex;
        runtimeObjectIds[id] = ref;
    }

    void registerRuntimeObjectEdit(const std::string& id, const MapObjectEdit& edit) {
        if (id.empty()) return;
        runtimeObjectEdits[id] = edit;
    }

    void unregisterRuntimeObjectId(const std::string& id) {
        if (id.empty()) return;
        runtimeObjectIds.erase(id);
        runtimeObjectEdits.erase(id);
    }

    Texture* getOrLoadTexture(const std::string& texPath) {
        if (texPath.empty()) return nullptr;
        auto it = textures.find(texPath);
        if (it != textures.end()) return it->second;
        Texture* t = new Texture(texPath.c_str());
        textures[texPath] = t;
        return t;
    }

    MapObjectEdit objectEditFromJsonBlock(const std::string& block, int type, const std::string& objectId) {
        MapObjectEdit edit{};
        edit.objectType = (uint8_t)type;
        edit.persistToJson = 1;
        mapEditSetString(edit.id, sizeof(edit.id), objectId);

        const std::string texPath = findValue(block, "\"texture\"");
        const std::string meshPath = findValue(block, "\"path\"");
        const std::string collision = findValue(block, "\"collision\"");
        mapEditSetString(edit.texture, sizeof(edit.texture), texPath);
        mapEditSetString(edit.path, sizeof(edit.path), meshPath);
        mapEditSetString(edit.collision, sizeof(edit.collision), collision.empty() ? "true" : collision);

        Vec3f c0 = parseVec(findValue(block, "\"corner0\""));
        Vec3f c1 = parseVec(findValue(block, "\"corner1\""));
        edit.corner0[0] = c0.x; edit.corner0[1] = c0.y; edit.corner0[2] = c0.z;
        edit.corner1[0] = c1.x; edit.corner1[1] = c1.y; edit.corner1[2] = c1.z;

        Vec3f normal = parseVec(findValue(block, "\"normal\""));
        if (std::abs(normal.x) < 1e-6f && std::abs(normal.y) < 1e-6f && std::abs(normal.z) < 1e-6f) {
            normal = (type == (int)MapEditObjectType::Light) ? Vec3f{0.f, -1.f, 0.f} : Vec3f{0.f, 1.f, 0.f};
        }
        edit.normal[0] = normal.x; edit.normal[1] = normal.y; edit.normal[2] = normal.z;

        Vec3f pos = parseVec(findValue(block, "\"position\""));
        if (findValue(block, "\"position\"").empty()) {
            pos = (type == (int)MapEditObjectType::Plane)
                ? Vec3f{(c0.x + c1.x) * 0.5f, (c0.y + c1.y) * 0.5f, (c0.z + c1.z) * 0.5f}
                : c0;
        }
        edit.position[0] = pos.x; edit.position[1] = pos.y; edit.position[2] = pos.z;

        Vec3f color = parseVec(findValue(block, "\"color\""));
        if (findValue(block, "\"color\"").empty()) color = {1.f, 1.f, 1.f};
        edit.color[0] = color.x; edit.color[1] = color.y; edit.color[2] = color.z;

        Vec3f rotation = parseVec(findValue(block, "\"rotation\""));
        edit.rotation[0] = rotation.x; edit.rotation[1] = rotation.y; edit.rotation[2] = rotation.z;

        Vec3f scale = parseVec(findValue(block, "\"scale\""));
        edit.scale[0] = scale.x; edit.scale[1] = scale.y; edit.scale[2] = scale.z;

        edit.intensity = parseFloat(findValue(block, "\"intensity\""), 1.f);
        edit.radius = parseFloat(findValue(block, "\"radius\""), 8.f);
        edit.angle = parseFloat(findValue(block, "\"angle\""), 0.f);
        return edit;
    }

    std::string objectEditToJson(const MapObjectEdit& edit, bool includeId = true) const {
        const int type = (int)edit.objectType;
        const std::string id = mapEditGetString(edit.id, sizeof(edit.id));
        const std::string texPath = mapEditGetString(edit.texture, sizeof(edit.texture));
        const std::string meshPath = mapEditGetString(edit.path, sizeof(edit.path));
        const std::string collision = mapEditGetString(edit.collision, sizeof(edit.collision));

        std::ostringstream ss;
        ss << "    {\n";
        if (includeId && !id.empty()) ss << "      \"id\": \"" << jsonEscape(id) << "\",\n";
        ss << "      \"type\": " << type;

        if (!texPath.empty()) ss << ",\n      \"texture\": \"" << jsonEscape(texPath) << "\"";

        if (type == 0) {
            ss << ",\n      \"corner0\": " << formatJsonVec3(edit.corner0)
               << ",\n      \"corner1\": " << formatJsonVec3(edit.corner1);
        } else if (type == 1) {
            ss << ",\n      \"corner0\": " << formatJsonVec3(edit.corner0)
               << ",\n      \"corner1\": " << formatJsonVec3(edit.corner1)
               << ",\n      \"position\": " << formatJsonVec3(edit.position)
               << ",\n      \"normal\": " << formatJsonVec3(edit.normal);
        } else if (type == 2) {
            ss << ",\n      \"path\": \"" << jsonEscape(meshPath) << "\""
               << ",\n      \"corner0\": " << formatJsonVec3(edit.corner0)
               << ",\n      \"corner1\": " << formatJsonVec3(edit.corner1);
            if (!nearlyZeroVec3(edit.rotation)) {
                ss << ",\n      \"rotation\": " << formatJsonVec3(edit.rotation);
            }
            if (!nearlyZeroVec3(edit.scale)) {
                ss << ",\n      \"scale\": " << formatJsonVec3(edit.scale);
            }
            if (!collision.empty()) {
                ss << ",\n      \"collision\": \"" << jsonEscape(collision) << "\"";
            }
        } else if (type == 3) {
            ss << ",\n      \"position\": " << formatJsonVec3(edit.position)
               << ",\n      \"color\": " << formatJsonVec3(edit.color)
               << ",\n      \"intensity\": " << edit.intensity
               << ",\n      \"radius\": " << edit.radius
               << ",\n      \"normal\": " << formatJsonVec3(edit.normal)
               << ",\n      \"angle\": " << edit.angle;
        }

        ss << "\n    }";
        return ss.str();
    }

    bool jsonContainsObjectId(const std::string& content, const std::string& id) {
        if (id.empty()) return false;
        size_t pos = 0;
        while ((pos = content.find('{', pos)) != std::string::npos) {
            size_t end = findMatchingCurlyBrace(content, pos);
            if (end == std::string::npos) break;
            std::string block = content.substr(pos, end - pos + 1);
            if (findValue(block, "\"id\"") == id) return true;
            if (findObjectKeyBeforeBlock(content, pos) == id && !findValue(block, "\"type\"").empty()) return true;
            ++pos;
        }
        return false;
    }

    static size_t findMatchingSquareBracket(const std::string& text, size_t openPos) {
        bool inString = false;
        bool escaped = false;
        int depth = 0;
        for (size_t i = openPos; i < text.size(); ++i) {
            char c = text[i];
            if (inString) {
                if (escaped) escaped = false;
                else if (c == '\\') escaped = true;
                else if (c == '"') inString = false;
                continue;
            }
            if (c == '"') inString = true;
            else if (c == '[') ++depth;
            else if (c == ']') {
                --depth;
                if (depth == 0) return i;
            }
        }
        return std::string::npos;
    }

    bool appendObjectToJsonFile(const std::string& jsonPath, const MapObjectEdit& edit, bool skipIfPresent = true) {
        const std::string id = mapEditGetString(edit.id, sizeof(edit.id));

        std::ifstream in(jsonPath, std::ios::binary);
        if (!in.is_open()) return false;
        std::stringstream buffer;
        buffer << in.rdbuf();
        std::string content = buffer.str();
        in.close();

        if (skipIfPresent && jsonContainsObjectId(content, id)) {
            return true;
        }

        size_t objectsPos = content.find("\"objects\"");
        if (objectsPos == std::string::npos) {
            size_t close = content.rfind('}');
            if (close == std::string::npos) return false;
            size_t before = close;
            while (before > 0 && std::isspace((unsigned char)content[before - 1])) --before;
            bool needsComma = before > 0 && content[before - 1] != '{' && content[before - 1] != ',';

            std::string objectJson;
            if (!id.empty()) {
                std::string body = objectEditToJson(edit, false);
                if (body.rfind("    ", 0) == 0) body.erase(0, 4);
                objectJson = "    \"" + jsonEscape(id) + "\": " + body;
            } else {
                objectJson = objectEditToJson(edit, true);
            }

            std::string field = std::string(needsComma ? ",\n" : "\n") +
                "  \"objects\": {\n" + objectJson + "\n  }\n";
            content.insert(close, field);
        } else {
            size_t colon = content.find(':', objectsPos);
            if (colon == std::string::npos) return false;
            size_t containerStart = content.find_first_not_of(" \t\n\r", colon + 1);
            if (containerStart == std::string::npos) return false;

            if (content[containerStart] == '[') {
                size_t arrayStart = containerStart;
                size_t arrayEnd = findMatchingSquareBracket(content, arrayStart);
                if (arrayEnd == std::string::npos) return false;

                bool hasAnyObject = false;
                for (size_t i = arrayStart + 1; i < arrayEnd; ++i) {
                    if (!std::isspace((unsigned char)content[i])) { hasAnyObject = true; break; }
                }

                std::string insertion = std::string(hasAnyObject ? ",\n" : "\n") + objectEditToJson(edit, true) + "\n  ";
                content.insert(arrayEnd, insertion);
            } else if (content[containerStart] == '{') {
                if (id.empty()) return false;
                size_t objectEnd = findMatchingCurlyBrace(content, containerStart);
                if (objectEnd == std::string::npos) return false;

                bool hasAnyObject = false;
                for (size_t i = containerStart + 1; i < objectEnd; ++i) {
                    if (!std::isspace((unsigned char)content[i])) { hasAnyObject = true; break; }
                }

                std::string body = objectEditToJson(edit, false);
                if (body.rfind("    ", 0) == 0) body.erase(0, 4);
                std::string keyed = "    \"" + jsonEscape(id) + "\": " + body;
                std::string insertion = std::string(hasAnyObject ? ",\n" : "\n") + keyed + "\n  ";
                content.insert(objectEnd, insertion);
            } else {
                return false;
            }
        }

        std::ofstream out(jsonPath, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) return false;
        out << content;
        return true;
    }

    bool removeJsonRange(std::string& content, size_t eraseStart, size_t eraseEnd, size_t containerStart, size_t containerEnd) {
        size_t before = eraseStart;
        while (before > containerStart && std::isspace((unsigned char)content[before - 1])) --before;
        if (before > containerStart && content[before - 1] == ',') {
            eraseStart = before - 1;
        } else {
            size_t after = eraseEnd;
            while (after < containerEnd && std::isspace((unsigned char)content[after])) ++after;
            if (after < containerEnd && content[after] == ',') eraseEnd = after + 1;
        }
        content.erase(eraseStart, eraseEnd - eraseStart);
        return true;
    }

    bool removeObjectFromJsonFile(const std::string& jsonPath, const std::string& objectId) {
        if (objectId.empty()) return false;

        std::ifstream in(jsonPath, std::ios::binary);
        if (!in.is_open()) return false;
        std::stringstream buffer;
        buffer << in.rdbuf();
        std::string content = buffer.str();
        in.close();

        size_t objectsPos = content.find("\"objects\"");
        if (objectsPos == std::string::npos) return false;
        size_t colon = content.find(':', objectsPos);
        if (colon == std::string::npos) return false;
        size_t containerStart = content.find_first_not_of(" \t\n\r", colon + 1);
        if (containerStart == std::string::npos) return false;

        bool changed = false;
        if (content[containerStart] == '[') {
            size_t arrayEnd = findMatchingSquareBracket(content, containerStart);
            if (arrayEnd == std::string::npos) return false;

            size_t pos = containerStart + 1;
            while (pos < arrayEnd) {
                size_t objStart = content.find('{', pos);
                if (objStart == std::string::npos || objStart >= arrayEnd) break;
                size_t objEnd = findMatchingCurlyBrace(content, objStart);
                if (objEnd == std::string::npos || objEnd >= arrayEnd) break;

                std::string block = content.substr(objStart, objEnd - objStart + 1);
                const std::string blockId = findValue(block, "\"id\"");
                if (blockId == objectId) {
                    removeJsonRange(content, objStart, objEnd + 1, containerStart, arrayEnd);
                    changed = true;
                    break;
                }

                pos = objEnd + 1;
            }
        } else if (content[containerStart] == '{') {
            size_t objectEnd = findMatchingCurlyBrace(content, containerStart);
            if (objectEnd == std::string::npos) return false;

            size_t pos = containerStart + 1;
            while (pos < objectEnd) {
                size_t keyPos = content.find('"', pos);
                if (keyPos == std::string::npos || keyPos >= objectEnd) break;
                size_t keyEnd = keyPos + 1;
                bool escaped = false;
                for (; keyEnd < objectEnd; ++keyEnd) {
                    char c = content[keyEnd];
                    if (escaped) { escaped = false; continue; }
                    if (c == '\\') { escaped = true; continue; }
                    if (c == '"') break;
                }
                if (keyEnd >= objectEnd) break;
                std::string key = unescapeJsonKey(content.substr(keyPos + 1, keyEnd - keyPos - 1));
                size_t keyColon = content.find(':', keyEnd + 1);
                if (keyColon == std::string::npos || keyColon >= objectEnd) break;
                size_t objStart = content.find_first_not_of(" \t\n\r", keyColon + 1);
                if (objStart == std::string::npos || objStart >= objectEnd) break;
                if (content[objStart] != '{') { pos = objStart + 1; continue; }
                size_t objEnd = findMatchingCurlyBrace(content, objStart);
                if (objEnd == std::string::npos || objEnd > objectEnd) break;

                std::string block = content.substr(objStart, objEnd - objStart + 1);
                if (key == objectId || findValue(block, "\"id\"") == objectId) {
                    removeJsonRange(content, keyPos, objEnd + 1, containerStart, objectEnd);
                    changed = true;
                    break;
                }
                pos = objEnd + 1;
            }
        }

        if (!changed) return false;
        std::ofstream out(jsonPath, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) return false;
        out << content;
        return true;
    }

    void removeObjectFromAllGridCells(void* obj) {
        if (!obj || !grid) return;
        const int cellCount = sizeX * sizeY * sizeZ;
        for (int ci = 0; ci < cellCount; ++ci) {
            Cell& cell = grid[ci];
            for (int i = 0; i < cell.count; ) {
                if (cell.items[i] == obj) {
                    for (int j = i + 1; j < cell.count; ++j) {
                        cell.items[j - 1] = cell.items[j];
                    }
                    --cell.count;
                    continue;
                }
                ++i;
            }
        }
    }

    void removeObjectFromPageMem(void* obj) {
        if (!obj || !pageMem) return;
        for (int i = 0; i < numObjects; ++i) {
            if (pageMem[i] != obj) continue;
            for (int j = i + 1; j < numObjects; ++j) {
                pageMem[j - 1] = pageMem[j];
            }
            --numObjects;
            if (numObjects >= 0 && pageMem) pageMem[numObjects] = nullptr;
            return;
        }
    }

    void rebuildLightIdIndices() {
        for (auto& kv : runtimeObjectIds) {
            if (kv.second.type != 3) continue;
            // lightIndex is repaired by matching object pointer-sized sentinel values are not used;
            // callers update erased light IDs separately, and newly added lights are registered directly.
            if (kv.second.lightIndex >= lights.size()) kv.second.lightIndex = 0;
        }
    }

    void appendObject(void* obj) {
        void** next = new void*[numObjects + 1];
        for (int i = 0; i < numObjects; ++i) next[i] = pageMem ? pageMem[i] : nullptr;
        next[numObjects] = obj;
        delete[] pageMem;
        pageMem = next;
        ++numObjects;
    }

    void insertObjectIntoGrid(void* obj, int type, Vec3f c0, Vec3f c1) {
        if (!obj || !grid) return;

        int startX = (int)std::floor((std::min)(c0.x, c1.x) - minX);
        int endX   = (int)std::ceil ((std::max)(c0.x, c1.x) - minX);
        if (endX <= startX) endX = startX + 1;

        int startY = (int)std::floor((std::min)(c0.y, c1.y) - minY);
        int endY   = (int)std::ceil ((std::max)(c0.y, c1.y) - minY);
        if (endY <= startY) endY = startY + 1;

        int startZ = (int)std::floor((std::min)(c0.z, c1.z) - minZ);
        int endZ   = (int)std::ceil ((std::max)(c0.z, c1.z) - minZ);
        if (endZ <= startZ) endZ = startZ + 1;

        for (int x = startX; x < endX; x++)
        for (int y = startY; y < endY; y++)
        for (int z = startZ; z < endZ; z++) {
            if (x < 0 || x >= sizeX ||
                y < 0 || y >= sizeY ||
                z < 0 || z >= sizeZ) continue;

            grid[index(x,y,z)].add(obj);

            if (type == 2) {
                Mesh* mesh = (Mesh*)obj;

                const Vec3f& sc  = mesh->scale;
                const Vec3f& off = mesh->offset;
                const float CELL_EPS = 1e-4f;

                Vec3f cellMn = { 1e30f,  1e30f,  1e30f};
                Vec3f cellMx = {-1e30f, -1e30f, -1e30f};
                for (int cx = 0; cx <= 1; ++cx)
                for (int cy = 0; cy <= 1; ++cy)
                for (int cz = 0; cz <= 1; ++cz) {
                    const Vec3f& pv2 = mesh->pivot;
                    const Vec3f& mc  = mesh->modelCenter;
                    Vec3f corner = { (float)(x + cx) - pv2.x - off.x,
                                     (float)(y + cy) - pv2.y - off.y,
                                     (float)(z + cz) - pv2.z - off.z };
                    Vec3f r = mesh->rot.mulT(corner);
                    Vec3f mp = { r.x / sc.x + mc.x,
                                 r.y / sc.y + mc.y,
                                 r.z / sc.z + mc.z };
                    if (mp.x < cellMn.x) cellMn.x = mp.x;
                    if (mp.y < cellMn.y) cellMn.y = mp.y;
                    if (mp.z < cellMn.z) cellMn.z = mp.z;
                    if (mp.x > cellMx.x) cellMx.x = mp.x;
                    if (mp.y > cellMx.y) cellMx.y = mp.y;
                    if (mp.z > cellMx.z) cellMx.z = mp.z;
                }
                cellMn = { cellMn.x - CELL_EPS, cellMn.y - CELL_EPS, cellMn.z - CELL_EPS };
                cellMx = { cellMx.x + CELL_EPS, cellMx.y + CELL_EPS, cellMx.z + CELL_EPS };

                std::vector<uint32_t> cellTris;
                const uint32_t numTris = (uint32_t)mesh->tris->size();
                for (uint32_t ti = 0; ti < numTris; ti++) {
                    const Triangle& tri = (*mesh->tris)[ti];
                    float tMinX = (std::min)({tri.v1.pos.x, tri.v2.pos.x, tri.v3.pos.x});
                    float tMaxX = (std::max)({tri.v1.pos.x, tri.v2.pos.x, tri.v3.pos.x});
                    float tMinY = (std::min)({tri.v1.pos.y, tri.v2.pos.y, tri.v3.pos.y});
                    float tMaxY = (std::max)({tri.v1.pos.y, tri.v2.pos.y, tri.v3.pos.y});
                    float tMinZ = (std::min)({tri.v1.pos.z, tri.v2.pos.z, tri.v3.pos.z});
                    float tMaxZ = (std::max)({tri.v1.pos.z, tri.v2.pos.z, tri.v3.pos.z});

                    if (tMaxX >= cellMn.x && tMinX <= cellMx.x &&
                        tMaxY >= cellMn.y && tMinY <= cellMx.y &&
                        tMaxZ >= cellMn.z && tMinZ <= cellMx.z) {
                        cellTris.push_back(ti);
                    }
                }

                if (!cellTris.empty()) {
                    BVH* cellBvh = new BVH();
                    cellBvh->build(*mesh->tris, cellTris);
                    mesh->cellBVHs[index(x, y, z)] = cellBvh;
                }
            }
        }

        if (type == 2) {
            ((Mesh*)obj)->flattenForGPU();
        }
    }

    Box* addAabbObject(Vec3f c0,
                       Vec3f c1,
                       const std::string& texturePath = "",
                       const std::string& objectId = "") {
        Box* box = new Box();
        box->type = 0;
        box->texture = getOrLoadTexture(texturePath);

        appendObject(box);
        insertObjectIntoGrid(box, 0, c0, c1);
        registerRuntimeObjectId(objectId, 0, box);
        markDirty();
        return box;
    }

    Plane* addPlaneObject(Vec3f c0,
                          Vec3f c1,
                          Vec3f normal,
                          const std::string& texturePath = "",
                          const std::string& objectId = "",
                          Vec3f worldPosition = {0.f, 0.f, 0.f}) {
        Plane* plane = new Plane();
        plane->type = 1;
        plane->texture = getOrLoadTexture(texturePath);
        plane->position = {worldPosition.x - minX, worldPosition.y - minY, worldPosition.z - minZ};
        plane->normal = normal;

        appendObject(plane);
        insertObjectIntoGrid(plane, 1, c0, c1);
        registerRuntimeObjectId(objectId, 1, plane);
        markDirty();
        return plane;
    }

    Light* addLightObject(Vec3f worldPosition,
                                    Vec3f color = {1.f, 1.f, 1.f},
                                    float intensity = 1.f,
                                    float radius = 8.f,
                                    const std::string& objectId = "", Vec3f normal = {0.f, -1.f, 0.f}, float angle = 0.f) {
        Light light;
        light.type = 3;
        light.worldPosition = worldPosition;
        light.position = {
            worldPosition.x - minX,
            worldPosition.y - minY,
            worldPosition.z - minZ
        };
        light.color = color;
        light.intensity = intensity;
        light.radius = radius;

        light.normal = normal;
        light.angle = angle;

        lights.push_back(light);
        const size_t idx = lights.size() - 1;
        registerRuntimeObjectId(objectId, 3, nullptr, idx);
        markDirty();
        return &lights.back();
    }

    Mesh* addMeshObject(const std::string& path,
                        Vec3f targetC0,
                        Vec3f targetC1,
                        const Mat3& meshRot = Mat3::identity(),
                        Vec3f scaleOverride = {0,0,0},
                        const std::string& texturePath = "",
                        bool collisionEnabled = true,
                        const std::string& objectId = "") {
        Vec3f worldC0, worldC1;
        Mesh* mesh = createMesh(path, targetC0, targetC1, meshRot, scaleOverride, &worldC0, &worldC1);
        if (!mesh) return nullptr;

        if (!texturePath.empty()) {
            applyMeshTextureOverride(mesh, getOrLoadTexture(texturePath));
        }
        meshCollisionEnabled[mesh] = collisionEnabled;

        appendObject(mesh);
        insertObjectIntoGrid(mesh, 2, worldC0, worldC1);
        registerRuntimeObjectId(objectId, 2, mesh);
        markDirty();
        return mesh;
    }

    bool addObject(const MapObjectEdit& edit, bool skipIfPresent = true) {
        const std::string id = mapEditGetString(edit.id, sizeof(edit.id));
        if (skipIfPresent && hasRuntimeObjectId(id)) return true;

        const int type = (int)edit.objectType;
        const std::string texPath = mapEditGetString(edit.texture, sizeof(edit.texture));
        bool added = false;

        if (type == 0) {
            added = addAabbObject(editVec3(edit.corner0), editVec3(edit.corner1), texPath, id) != nullptr;
        } else if (type == 1) {
            added = addPlaneObject(editVec3(edit.corner0),
                                   editVec3(edit.corner1),
                                   editVec3(edit.normal),
                                   texPath,
                                   id,
                                   editVec3(edit.position)) != nullptr;
        } else if (type == 2) {
            const std::string meshPath = mapEditGetString(edit.path, sizeof(edit.path));
            const std::string collision = mapEditGetString(edit.collision, sizeof(edit.collision));
            const bool collisionEnabled = !(collision == "none" || collision == "false" || collision == "0");
            Mat3 rot = Mat3::fromEulerDeg(edit.rotation[0], edit.rotation[1], edit.rotation[2]);
            added = addMeshObject(meshPath,
                                  editVec3(edit.corner0),
                                  editVec3(edit.corner1),
                                  rot,
                                  editVec3(edit.scale),
                                  texPath,
                                  collisionEnabled,
                                  id) != nullptr;
        } else if (type == 3) {
            added = addLightObject(editVec3(edit.position),
                                        editVec3(edit.color),
                                        edit.intensity,
                                        edit.radius,
                                        id,
                                        editVec3(edit.normal),
                                        edit.angle) != nullptr;
        }

        if (added) {
            registerRuntimeObjectEdit(id, edit);
        }
        return added;
    }

    bool addObjectAndPersist(MapObjectEdit& edit,
                             const std::string& jsonPath = "assets/map.json",
                             bool skipIfPresent = true) {
        ensureObjectId(edit);
        if (!addObject(edit, skipIfPresent)) return false;
        if (!edit.persistToJson) return true;
        return appendObjectToJsonFile(jsonPath, edit, skipIfPresent);
    }

    bool removeObjectById(const std::string& objectId) {
        if (objectId.empty()) return false;

        auto it = runtimeObjectIds.find(objectId);
        if (it == runtimeObjectIds.end()) return false;

        const int type = it->second.type;

        if (type == 3) {
            const size_t idx = it->second.lightIndex;
            if (idx < lights.size()) {
                lights.erase(lights.begin() + (ptrdiff_t)idx);
            }
            unregisterRuntimeObjectId(objectId);

            // Rebuild light indices for the remaining registered point lights.
            for (auto& kv : runtimeObjectIds) {
                if (kv.second.type != 3) continue;
                if (kv.second.lightIndex > idx) --kv.second.lightIndex;
            }

            markDirty();
            return true;
        }

        void* obj = it->second.object;
        if (!obj) {
            unregisterRuntimeObjectId(objectId);
            return false;
        }

        removeObjectFromAllGridCells(obj);
        removeObjectFromPageMem(obj);

        if (type == 0) {
            delete (Box*)obj;
        } else if (type == 1) {
            delete (Plane*)obj;
        } else if (type == 2) {
            Mesh* mesh = (Mesh*)obj;
            meshCollisionEnabled.erase(mesh);
            delete mesh;
        }

        unregisterRuntimeObjectId(objectId);
        markDirty();
        return true;
    }

    bool removeObjectAndPersist(const std::string& objectId,
                                const std::string& jsonPath = "assets/map.json") {
        const bool removedRuntime = removeObjectById(objectId);
        const bool removedJson = removeObjectFromJsonFile(jsonPath, objectId);
        return removedRuntime || removedJson;
    }

    // -----------------------------------------------------------------------
    void generate(Player* player) {
        std::ifstream file("assets/map.json");
        if (!file.is_open()) return;

        std::stringstream buffer;
        buffer << file.rdbuf();
        generateFromString(buffer.str(), player);
    }

    void generateFromString(const std::string& content, Player* player) {

        std::cout << "loading map...\n";
        runtimeObjectIds.clear();
        runtimeObjectEdits.clear();

        size_t pos = 0;

        float max_x = 0, max_y = 0, max_z = 0;

        int numBoxes = 0, numPlanes = 0, numMeshes = 0, numLights = 0;

        // -------------------------------------------------------------------
        // PLAYER
        // -------------------------------------------------------------------
        size_t playerPos = content.find("\"player\"");
        if (playerPos != std::string::npos && player) {
            size_t blockStart = content.find('{', playerPos);
            size_t blockEnd = content.find('}', blockStart);

            std::string block = content.substr(blockStart, blockEnd - blockStart);

            Vec3f spawnPos = parseVec(findValue(block, "\"position\""));
            Vec3f spawnDir = parseVec(findValue(block, "\"direction\""));

            std::string asset = findValue(block, "\"mesh\"");


            player->setSpawn(spawnPos, spawnDir);

            if (!asset.empty()) {
                Mesh* playerMesh = loadMesh(asset);

                if (playerMesh) {
                    player->mesh = playerMesh; // or player->setMesh(playerMesh);
                } else {
                    std::cout << "[Player] Failed to load mesh: " << asset << "\n";
                }
            }
        }

        // -------------------------------------------------------------------
        // PASS 1: BOUNDS
        // -------------------------------------------------------------------
        while ((pos = content.find('{', pos + 1)) != std::string::npos) {
            size_t end = findMatchingCurlyBrace(content, pos);
            if (end == std::string::npos) break;

            std::string block = content.substr(pos, end - pos + 1);
            std::string typeStr = findDirectValue(block, "\"type\"");
            if (typeStr.empty()) {
                continue;
            }

            int type = std::stoi(typeStr);
            Vec3f c0 = parseVec(findDirectValue(block, "\"corner0\""));
            Vec3f c1 = parseVec(findDirectValue(block, "\"corner1\""));

            max_x = (std::max)({max_x, c0.x, c1.x});
            max_y = (std::max)({max_y, c0.y, c1.y});
            max_z = (std::max)({max_z, c0.z, c1.z});

            minX = (std::min)({minX, c0.x, c1.x});
            minY = (std::min)({minY, c0.y, c1.y});
            minZ = (std::min)({minZ, c0.z, c1.z});

            if (type == 0) numBoxes++;
            else if (type == 1) numPlanes++;
            else if (type == 2) numMeshes++;
            else if (type == 3) numLights++;
        }

        sizeX = (int)std::ceil(max_x - minX) + 1;
        sizeY = (int)std::ceil(max_y - minY) + 1;
        sizeZ = (int)std::ceil(max_z - minZ) + 1;

        // -------------------------------------------------------------------
        // GRID
        // -------------------------------------------------------------------
        grid = new Cell[sizeX * sizeY * sizeZ];

        // -------------------------------------------------------------------
        // OBJECT POOL (IMPORTANT)
        // -------------------------------------------------------------------
        // Lights are intentionally not added to pageMem/grid: they do not collide
        // and they should not be hit by the raycaster as geometry.
        numObjects = numBoxes + numPlanes + numMeshes;
        lights.reserve(numLights);
        pageMem = new void*[numObjects];

        for (int i = 0; i < numObjects; i++)
            pageMem[i] = nullptr;

        int pageMemIndex = 0;

        // -------------------------------------------------------------------
        // PASS 2: BUILD WORLD
        // -------------------------------------------------------------------
        pos = 0;

        while ((pos = content.find('{', pos + 1)) != std::string::npos) {

            size_t end = findMatchingCurlyBrace(content, pos);
            if (end == std::string::npos) break;

            std::string block = content.substr(pos, end - pos + 1);

            std::string typeStr = findDirectValue(block, "\"type\"");
            if (typeStr.empty()) continue;
            int type = std::stoi(typeStr);
            std::string objectId = findDirectValue(block, "\"id\"");
            if (objectId.empty()) objectId = findObjectKeyBeforeBlock(content, pos);
            MapObjectEdit loadedEdit = objectEditFromJsonBlock(block, type, objectId);

            std::string texPath = findDirectValue(block, "\"texture\"");
            if (!texPath.empty() && !textures.count(texPath)) {
                Texture* t = new Texture(texPath.c_str());
                textures[texPath] = t;
            }
            Vec3f c0 = parseVec(findDirectValue(block, "\"corner0\""));
            Vec3f c1 = parseVec(findDirectValue(block, "\"corner1\""));

            void* obj = nullptr;
            // ---------------------------------------------------------------
            // OBJECT CREATION
            // ---------------------------------------------------------------
            if (type == 0) { // AABB
                Box* b = new Box();

                b->type = 0;
                b->texture = textures[texPath];

                obj = b;
                pageMem[pageMemIndex++] = obj;
            }
            else if (type == 1) { // Plane
                Plane* p = new Plane();
                p->type = 1;
                p->texture = textures[texPath];

                Vec3f planePosition = c0;
                std::string planePositionStr = findDirectValue(block, "\"position\"");
                if (!planePositionStr.empty()) {
                    planePosition = parseVec(planePositionStr);
                }

                p->position = {planePosition.x - minX, planePosition.y - minY, planePosition.z - minZ};
                p->normal = parseVec(findDirectValue(block, "\"normal\""));

                obj = p;
                pageMem[pageMemIndex++] = obj;
            }
            else if (type == 2) { // Mesh
                std::string path = findDirectValue(block, "\"path\"");

                // Target bounding box from JSON (world space)
                Vec3f targetC0 = parseVec(findDirectValue(block, "\"corner0\""));
                Vec3f targetC1 = parseVec(findDirectValue(block, "\"corner1\""));
                

                float targetMinX = (std::min)(targetC0.x, targetC1.x);
                float targetMinY = (std::min)(targetC0.y, targetC1.y);
                float targetMinZ = (std::min)(targetC0.z, targetC1.z);

                float targetSizeX = std::abs(targetC1.x - targetC0.x);
                float targetSizeY = std::abs(targetC1.y - targetC0.y);
                float targetSizeZ = std::abs(targetC1.z - targetC0.z);

                // Static rotation (Euler angles in degrees) from JSON.
                // Format:  "rotation": [rx, ry, rz]
                // Applied as Ry * Rx * Rz.  Omit the key for no rotation.
                Mat3 meshRot = Mat3::identity();
                {
                    std::string rotStr = findDirectValue(block, "\"rotation\"");
                    if (!rotStr.empty()) {
                        Vec3f euler = parseVec(rotStr); // reuse the [x,y,z] parser
                        meshRot = Mat3::fromEulerDeg(euler.x, euler.y, euler.z);
                    }
                }

                Vec3f scaleOverride = {0,0,0};
                {
                    std::string scStr = findDirectValue(block, "\"scale\"");
                    if (!scStr.empty()) {
                        scaleOverride = parseVec(scStr);
                    }
                }

                Mesh* mesh = createMesh(path, targetC0, targetC1, meshRot, scaleOverride, &c0, &c1);
                if (mesh) {
                    std::string collisionMode = findDirectValue(block, "\"collision\"");
                    bool collisionEnabled = !(collisionMode == "none" ||
                                              collisionMode == "false" ||
                                              collisionMode == "0");
                    meshCollisionEnabled[mesh] = collisionEnabled;

                    if (!texPath.empty()) {
                        applyMeshTextureOverride(mesh, textures[texPath]);
                    }
                    obj = mesh;
                    pageMem[pageMemIndex++] = obj;
                }
            }
            else if (type == 3) { // Point light, render data only
                Light light;

                Vec3f worldPos = parseVec(findDirectValue(block, "\"position\""));
                if (findDirectValue(block, "\"position\"").empty()) {
                    // Optional fallback so older test maps can use corner0 as position.
                    worldPos = c0;
                }

                light.worldPosition = worldPos;
                light.position = {
                    worldPos.x - minX,
                    worldPos.y - minY,
                    worldPos.z - minZ
                };

                std::string colorStr = findDirectValue(block, "\"color\"");
                if (!colorStr.empty()) {
                    light.color = parseVec(colorStr);
                }

                light.intensity = parseFloat(findDirectValue(block, "\"intensity\""), 1.f);
                light.radius    = parseFloat(findDirectValue(block, "\"radius\""), 8.f);
                light.angle    = parseFloat(findDirectValue(block, "\"angle\""), 0.f);

                light.normal = parseVec(findDirectValue(block, "\"normal\""));
                if (std::abs(light.normal.x) < 1e-6f &&
                    std::abs(light.normal.y) < 1e-6f &&
                    std::abs(light.normal.z) < 1e-6f) {
                    light.normal = {0.f, -1.f, 0.f};
                }

                lights.push_back(light);
                registerRuntimeObjectId(objectId, 3, nullptr, lights.size() - 1);
                registerRuntimeObjectEdit(objectId, loadedEdit);
            }
            // ---------------------------------------------------------------
            // GRID INSERT + PER-CELL BVH BUILD
            // ---------------------------------------------------------------
            if (obj) {

                registerRuntimeObjectId(objectId, type, obj);
                registerRuntimeObjectEdit(objectId, loadedEdit);

                // Use parentheses to bypass the Windows min/max macros
                int startX = (int)std::floor((std::min)(c0.x, c1.x) - minX);
                int endX   = (int)std::ceil ((std::max)(c0.x, c1.x) - minX);
                // Fix: Ensure the range is at least 1 cell wide for thin planes
                if (endX <= startX) endX = startX + 1;

                int startY = (int)std::floor((std::min)(c0.y, c1.y) - minY);
                int endY   = (int)std::ceil ((std::max)(c0.y, c1.y) - minY);
                if (endY <= startY) endY = startY + 1;

                int startZ = (int)std::floor((std::min)(c0.z, c1.z) - minZ);
                int endZ   = (int)std::ceil ((std::max)(c0.z, c1.z) - minZ);
                if (endZ <= startZ) endZ = startZ + 1;

                for (int x = startX; x < endX; x++)
                for (int y = startY; y < endY; y++)
                for (int z = startZ; z < endZ; z++) {

                    if (x < 0 || x >= sizeX ||
                        y < 0 || y >= sizeY ||
                        z < 0 || z >= sizeZ) continue;

                    grid[index(x,y,z)].add(obj);

                    // ---------------------------------------------------------
                    // PER-CELL BVH: only for meshes.
                    // Compute this cell's AABB in model space, collect all
                    // triangles whose AABB overlaps it, then build a small BVH
                    // containing only those triangles.
                    //
                    // At render time the DDA gives us (mapX,mapY,mapZ) directly,
                    // so we just look up cellBVHs[index(mapX,mapY,mapZ)] — no
                    // cell-boundary slab test is needed at all.
                    // ---------------------------------------------------------
                    if (type == 2) {
                        Mesh* mesh = (Mesh*)obj;

                        const Vec3f& sc  = mesh->scale;
                        const Vec3f& off = mesh->offset;
                        const Vec3f& mn  = mesh->modelMin;

                        // Grid cell [x, x+1]³ → model space.
                        // scale > 0 always, so min maps to min, max maps to max.
                        // A small epsilon catches triangles right on the boundary.
                        const float CELL_EPS = 1e-4f;

                        // When the mesh has a rotation we can no longer map the
                        // cell's axis-aligned box to model space with simple
                        // per-component arithmetic.  Instead transform all 8
                        // corners of the grid cell through the full inverse
                        //   model = rot^T * ((corner - offset) / scale) + modelMin
                        // and take their AABB — this is always correct regardless
                        // of whether rot is identity or not.
                        Vec3f cellMn = { 1e30f,  1e30f,  1e30f};
                        Vec3f cellMx = {-1e30f, -1e30f, -1e30f};
                        for (int cx = 0; cx <= 1; ++cx)
                        for (int cy = 0; cy <= 1; ++cy)
                        for (int cz = 0; cz <= 1; ++cz) {
                            const Vec3f& pv2 = mesh->pivot;
                            const Vec3f& mc  = mesh->modelCenter;
                            Vec3f corner = { (float)(x + cx) - pv2.x - off.x,
                                            (float)(y + cy) - pv2.y - off.y,
                                            (float)(z + cz) - pv2.z - off.z };
                            Vec3f r = mesh->rot.mulT(corner);
                            Vec3f mp = { r.x / sc.x + mc.x,
                                        r.y / sc.y + mc.y,
                                        r.z / sc.z + mc.z };
                            if (mp.x < cellMn.x) cellMn.x = mp.x;
                            if (mp.y < cellMn.y) cellMn.y = mp.y;
                            if (mp.z < cellMn.z) cellMn.z = mp.z;
                            if (mp.x > cellMx.x) cellMx.x = mp.x;
                            if (mp.y > cellMx.y) cellMx.y = mp.y;
                            if (mp.z > cellMx.z) cellMx.z = mp.z;
                        }
                        cellMn = { cellMn.x - CELL_EPS, cellMn.y - CELL_EPS, cellMn.z - CELL_EPS };
                        cellMx = { cellMx.x + CELL_EPS, cellMx.y + CELL_EPS, cellMx.z + CELL_EPS };

                        // Collect triangles overlapping this cell's model-space AABB.
                        // Conservative AABB-vs-AABB test: a false positive just means
                        // one extra triangle in the leaf; a false negative would miss a hit.
                        std::vector<uint32_t> cellTris;
                        const uint32_t numTris = (uint32_t)mesh->tris->size();
                        for (uint32_t ti = 0; ti < numTris; ti++) {
                            const Triangle& tri = (*mesh->tris)[ti];
                            float tMinX = (std::min)({tri.v1.pos.x, tri.v2.pos.x, tri.v3.pos.x});
                            float tMaxX = (std::max)({tri.v1.pos.x, tri.v2.pos.x, tri.v3.pos.x});
                            float tMinY = (std::min)({tri.v1.pos.y, tri.v2.pos.y, tri.v3.pos.y});
                            float tMaxY = (std::max)({tri.v1.pos.y, tri.v2.pos.y, tri.v3.pos.y});
                            float tMinZ = (std::min)({tri.v1.pos.z, tri.v2.pos.z, tri.v3.pos.z});
                            float tMaxZ = (std::max)({tri.v1.pos.z, tri.v2.pos.z, tri.v3.pos.z});

                            if (tMaxX >= cellMn.x && tMinX <= cellMx.x &&
                                tMaxY >= cellMn.y && tMinY <= cellMx.y &&
                                tMaxZ >= cellMn.z && tMinZ <= cellMx.z) {
                                cellTris.push_back(ti);
                            }
                        }

                        if (!cellTris.empty()) {
                            BVH* cellBvh = new BVH();
                            cellBvh->build(*mesh->tris, cellTris);
                            mesh->cellBVHs[index(x, y, z)] = cellBvh;
                        }
                    }
                }
            }

            if (type == 2 && obj) { // Get it flat-buffer ready
                ((Mesh*)obj)->flattenForGPU();
            }

            // Do not jump to end here; continuing from pos+1 lets the scanner
            // also visit named object blocks inside an "objects" JSON object.
        }

        markDirty();
        std::cout << "loaded point lights: " << lights.size() << "\n";
        std::cout << "loading map done\n";
    }
};