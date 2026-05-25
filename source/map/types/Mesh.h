#pragma once
#include <cstdint>
#include "Triangle.h"
#include "Vec3f.h"
#include "BVH.h"
#include "Texture.h"
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <string>
#include "Mat3.h"
#include "Animation.h"
#include "Skinning.h"

// Matches the lookup expected in Renderer.cpp
struct FlatCellBVH {
    int key;
    uint32_t nodeOffset;
    uint32_t triIdxOffset;
};

struct Mesh {
    int type = 2;

    std::vector<Triangle>* tris = nullptr;
    bool ownsTris = true;

    Vec3f modelMin = {0.f, 0.f, 0.f};
    Vec3f scale = {1.f, 1.f, 1.f};
    Vec3f offset = {0.f, 0.f, 0.f};
    Vec3f modelCenter = {0.f, 0.f, 0.f};
    Vec3f pivot = {0.f, 0.f, 0.f};

    std::unordered_map<int, BVH*> cellBVHs;
    std::vector<Texture*>* textures = nullptr;

    Skeleton* skeleton = nullptr;
    AnimationController anim;
    SkinningContext* skinCtx = nullptr;
    std::vector<SkinVertex> skinVertices;

    uint32_t numFullTriIdx = 0;

    Triangle* d_tris = nullptr;
    FlatCellBVH* d_cellBVHIndex = nullptr;
    BVHNode* d_flatNodes = nullptr;
    uint32_t* d_flatTriIdx = nullptr;
    uint32_t numFlatNodes = 0;
    uint32_t numFlatTriIdx = 0;
    uint32_t numCellBVHs = 0;

    BVHNode* d_fullNodes = nullptr;
    uint32_t* d_fullTriIdx = nullptr;
    uint32_t numFullNodes = 0;

    Texture** d_textures = nullptr;
    uint32_t numTextures = 0;

    Mat3 rot;

    ~Mesh() {
        for (auto& [k, v] : cellBVHs) {
            delete v;
        }

        if (ownsTris && tris) {
            delete tris;
        }

        if (textures) {
            delete textures;
        }

        delete skeleton;
        delete skinCtx;

        delete[] d_tris;
        delete[] d_cellBVHIndex;
        delete[] d_flatNodes;
        delete[] d_flatTriIdx;
        delete[] d_fullNodes;
        delete[] d_fullTriIdx;
        delete[] d_textures;
    }

    bool hasAnimation(const std::string& name) const {
        return skeleton && skeleton->hasAnimation(name);
    }

    bool playAnimation(const std::string& name, bool loop = true, float speed = 1.f) {
        if (!skeleton) {
            return false;
        }

        anim.skeleton = skeleton;
        return anim.play(name, loop, speed);
    }

    bool blendToAnimation(const std::string& name,
                          float fadeSeconds = 0.15f,
                          bool loop = true,
                          float speed = 1.f) {
        if (!skeleton) {
            return false;
        }

        anim.skeleton = skeleton;
        return anim.crossFade(name, fadeSeconds, loop, speed);
    }

    void stopAnimation() {
        anim.stop();
    }

    void tickAnimation(float dt, float speed = 1.f) {
        if (!skeleton || !skeleton->valid()) {
            return;
        }

        anim.skeleton = skeleton;
        anim.update(dt, speed);

        if (skinCtx) {
            skinAndRefit(*skinCtx, *skeleton);
        }
    }

    void flattenForGPU() {
        if (tris && !tris->empty() && !d_tris) {
            d_tris = new Triangle[tris->size()];
            std::copy(tris->begin(), tris->end(), d_tris);
        }

        numCellBVHs = static_cast<uint32_t>(cellBVHs.size());

        if (numCellBVHs > 0 && !d_cellBVHIndex) {
            std::vector<FlatCellBVH> cpuIndex;
            std::vector<BVHNode> cpuNodes;
            std::vector<uint32_t> cpuTriIdx;

            cpuIndex.reserve(numCellBVHs);

            std::vector<std::pair<int, BVH*>> sortedBVHs(cellBVHs.begin(), cellBVHs.end());

            std::sort(sortedBVHs.begin(), sortedBVHs.end(),
                [](const auto& a, const auto& b) {
                    return a.first < b.first;
                }
            );

            for (const auto& pair : sortedBVHs) {
                FlatCellBVH entry;
                entry.key = pair.first;
                entry.nodeOffset = static_cast<uint32_t>(cpuNodes.size());
                entry.triIdxOffset = static_cast<uint32_t>(cpuTriIdx.size());

                uint32_t localNodeOffset = static_cast<uint32_t>(cpuNodes.size());

                for (const auto& node : pair.second->nodes) {
                    BVHNode flatNode = node;

                    if (!flatNode.isLeaf()) {
                        flatNode.leftFirst += localNodeOffset;
                    }

                    cpuNodes.push_back(flatNode);
                }

                cpuTriIdx.insert(
                    cpuTriIdx.end(),
                    pair.second->triIdx.begin(),
                    pair.second->triIdx.end()
                );

                cpuIndex.push_back(entry);
            }

            d_cellBVHIndex = new FlatCellBVH[cpuIndex.size()];
            std::copy(cpuIndex.begin(), cpuIndex.end(), d_cellBVHIndex);

            numFlatNodes = static_cast<uint32_t>(cpuNodes.size());

            if (numFlatNodes > 0) {
                d_flatNodes = new BVHNode[numFlatNodes];
                std::copy(cpuNodes.begin(), cpuNodes.end(), d_flatNodes);
            }

            numFlatTriIdx = static_cast<uint32_t>(cpuTriIdx.size());

            if (numFlatTriIdx > 0) {
                d_flatTriIdx = new uint32_t[numFlatTriIdx];
                std::copy(cpuTriIdx.begin(), cpuTriIdx.end(), d_flatTriIdx);
            }
        }

        if (textures && !textures->empty() && !d_textures) {
            numTextures = static_cast<uint32_t>(textures->size());
            d_textures = new Texture*[numTextures];
            std::copy(textures->begin(), textures->end(), d_textures);
        }

        if (tris && !tris->empty() && !d_fullNodes) {
            BVH fullBvh;
            fullBvh.build(*tris);

            numFullNodes = static_cast<uint32_t>(fullBvh.nodes.size());

            if (numFullNodes > 0) {
                d_fullNodes = new BVHNode[numFullNodes];
                std::copy(fullBvh.nodes.begin(), fullBvh.nodes.end(), d_fullNodes);
            }

            numFullTriIdx = static_cast<uint32_t>(fullBvh.triIdx.size());

            if (numFullTriIdx > 0) {
                d_fullTriIdx = new uint32_t[numFullTriIdx];
                std::copy(fullBvh.triIdx.begin(), fullBvh.triIdx.end(), d_fullTriIdx);
            }
        }
    }

    void clearFlatArrays() {
        delete[] d_tris;
        delete[] d_cellBVHIndex;
        delete[] d_flatNodes;
        delete[] d_flatTriIdx;
        delete[] d_fullNodes;
        delete[] d_fullTriIdx;
        delete[] d_textures;

        d_tris = nullptr;
        d_cellBVHIndex = nullptr;
        d_flatNodes = nullptr;
        d_flatTriIdx = nullptr;
        d_fullNodes = nullptr;
        d_fullTriIdx = nullptr;
        d_textures = nullptr;

        numFlatNodes = 0;
        numFlatTriIdx = 0;
        numCellBVHs = 0;
        numFullNodes = 0;
        numFullTriIdx = 0;
        numTextures = 0;
    }

    Mesh* cloneInstance() const {
        Mesh* m = new Mesh();

        m->type      = type;
        m->tris      = tris;
        m->ownsTris  = false;

        m->modelMin    = modelMin;
        m->scale       = scale;
        m->offset      = offset;
        m->modelCenter = modelCenter;
        m->pivot       = pivot;
        m->rot         = rot;

        // KRITISCH: skinVertices muss aus dem Source übernommen werden.
        // Wenn das Source ein Clone ist, muss es seine skinVertices behalten.
        m->skinVertices = skinVertices;

        if (textures)
            m->textures = new std::vector<Texture*>(*textures);

        if (skeleton) {
            m->skeleton = new Skeleton(*skeleton);
            m->skeleton->skinMatrices.clear();
            m->anim.skeleton = m->skeleton;
        }

        m->flattenForGPU();

        // GUARD: alle drei Voraussetzungen prüfen + Logging
        if (m->skeleton && !m->skinVertices.empty() && m->d_tris && m->d_fullNodes) {
            m->skinCtx = new SkinningContext();
            buildSkinningContext(
                *m->skinCtx,
                *m->tris,
                m->skinVertices,
                static_cast<uint32_t>(m->skeleton->bones.size()),
                m->d_tris,
                m->d_fullNodes,  m->numFullNodes,
                m->d_fullTriIdx, m->numFullTriIdx
            );
        } else {
            std::cerr << "[cloneInstance] skinCtx NOT built:"
                    << " skeleton=" << m->skeleton
                    << " skinVerts=" << m->skinVertices.size()
                    << " d_tris="   << m->d_tris
                    << " d_fullNodes=" << m->d_fullNodes
                    << "\n";
        }

        return m;
    }
};