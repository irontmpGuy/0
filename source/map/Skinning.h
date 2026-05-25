#pragma once
#include "Triangle.h"
#include "BVH.h"
#include "Animation.h"
#include "Vec3f.h"
#include <vector>
#include <cstring>
#include <algorithm>

// Flat 4x4 matrix for transfer-friendly storage (row-major floats[16]).
// The name is kept because these buffers should later become Vulkan SSBO data.
struct GpuMat4 { float v[16]; };

inline GpuMat4 toGpu(const Mat4& m) {
    GpuMat4 g{};
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            g.v[r * 4 + c] = m.m[r][c];
    return g;
}

struct GpuSkinVertex {
    uint16_t joints[4];
    float    weights[4];
};

struct SkinningContext {
    Vec3f*    d_restPositions = nullptr;
    uint32_t  numVerts = 0;

    GpuSkinVertex* d_skinVerts = nullptr;
    GpuMat4*       d_skinMatrices = nullptr;
    uint32_t       numBones = 0;

    Triangle* d_tris = nullptr;      // owned by Mesh
    uint32_t  numTris = 0;

    uint32_t* d_vertIndex = nullptr;

    BVHNode*  d_flatNodes = nullptr; // owned by Mesh
    uint32_t  numNodes = 0;

    uint32_t* d_flatTriIdx = nullptr; // owned by Mesh
    uint32_t  numTriIdx = 0;

    ~SkinningContext() {
        delete[] d_restPositions;
        delete[] d_skinVerts;
        delete[] d_skinMatrices;
        delete[] d_vertIndex;
    }
};

inline void buildSkinningContext(
    SkinningContext& ctx,
    const std::vector<Triangle>& restTris,
    const std::vector<SkinVertex>& skinVerts,
    uint32_t numBones,
    Triangle* d_tris,
    BVHNode* d_flatNodes, uint32_t numNodes,
    uint32_t* d_flatTriIdx, uint32_t numTriIdx)
{
    ctx.d_tris = d_tris;
    ctx.numTris = (uint32_t)restTris.size();
    ctx.numBones = numBones;
    ctx.d_flatNodes = d_flatNodes;
    ctx.numNodes = numNodes;
    ctx.d_flatTriIdx = d_flatTriIdx;
    ctx.numTriIdx = numTriIdx;

    const uint32_t N = ctx.numTris * 3;
    ctx.numVerts = N;
    ctx.d_restPositions = new Vec3f[N];
    ctx.d_vertIndex     = new uint32_t[N];
    ctx.d_skinVerts     = new GpuSkinVertex[N];
    ctx.d_skinMatrices  = new GpuMat4[numBones ? numBones : 1];

    for (uint32_t ti = 0; ti < ctx.numTris; ti++) {
        const Triangle& t = restTris[ti];
        const Vec3f* vp[3] = { &t.v1.pos, &t.v2.pos, &t.v3.pos };
        for (int c = 0; c < 3; c++) {
            const uint32_t vi = ti * 3 + (uint32_t)c;
            ctx.d_restPositions[vi] = *vp[c];
            ctx.d_vertIndex[vi] = vi;

            uint32_t si = 0;
            if      (c == 0) si = t.v1.skinIndex;
            else if (c == 1) si = t.v2.skinIndex;
            else             si = t.v3.skinIndex;
            if (si >= skinVerts.size()) si = 0;

            const SkinVertex& sv = skinVerts[si];
            for (int k = 0; k < 4; k++) {
                ctx.d_skinVerts[vi].joints[k]  = sv.joints[k];
                ctx.d_skinVerts[vi].weights[k] = sv.weights[k];
            }
        }
    }
}

inline void skinAndRefit(SkinningContext& ctx, const Skeleton& skel)
{
    if (!skel.valid() || skel.skinMatrices.empty() || !ctx.d_tris) return;

    uint32_t nb = (uint32_t)skel.skinMatrices.size();
    nb = std::min(nb, ctx.numBones);
    for (uint32_t i = 0; i < nb; i++) ctx.d_skinMatrices[i] = toGpu(skel.skinMatrices[i]);

    for (uint32_t vi = 0; vi < ctx.numVerts; vi++) {
        Vec3f rp = ctx.d_restPositions[vi];
        const GpuSkinVertex& sv = ctx.d_skinVerts[vi];

        Vec3f out = {0,0,0};
        for (int k = 0; k < 4; k++) {
            const float w = sv.weights[k];
            const uint16_t joint = sv.joints[k];
            if (w < 1e-6f || joint >= ctx.numBones) continue;

            const float* M = ctx.d_skinMatrices[joint].v;
            out.x += w * (M[0] * rp.x + M[1] * rp.y + M[2]  * rp.z + M[3]);
            out.y += w * (M[4] * rp.x + M[5] * rp.y + M[6]  * rp.z + M[7]);
            out.z += w * (M[8] * rp.x + M[9] * rp.y + M[10] * rp.z + M[11]);
        }

        const uint32_t ti = vi / 3;
        const uint32_t ci = vi % 3;
        if      (ci == 0) ctx.d_tris[ti].v1.pos = out;
        else if (ci == 1) ctx.d_tris[ti].v2.pos = out;
        else              ctx.d_tris[ti].v3.pos = out;
    }

    BVHNode*  dN   = ctx.d_flatNodes;
    uint32_t* dIdx = ctx.d_flatTriIdx;
    const uint32_t nN = ctx.numNodes;
    if (!dN || !dIdx || nN == 0) return;

    for (uint32_t ni = 0; ni < nN; ni++) {
        BVHNode& nd = dN[ni];
        if (!nd.isLeaf()) continue;

        Vec3f mn = { 1e30f, 1e30f, 1e30f };
        Vec3f mx = {-1e30f,-1e30f,-1e30f };
        for (uint32_t li = 0; li < nd.triCount; li++) {
            const uint32_t gi = dIdx[nd.leftFirst + li];
            const Triangle& t = ctx.d_tris[gi];
            const Vec3f* v[3] = { &t.v1.pos, &t.v2.pos, &t.v3.pos };
            for (int c = 0; c < 3; c++) {
                if (v[c]->x < mn.x) mn.x = v[c]->x; if (v[c]->x > mx.x) mx.x = v[c]->x;
                if (v[c]->y < mn.y) mn.y = v[c]->y; if (v[c]->y > mx.y) mx.y = v[c]->y;
                if (v[c]->z < mn.z) mn.z = v[c]->z; if (v[c]->z > mx.z) mx.z = v[c]->z;
            }
        }
        nd.aabbMin = mn;
        nd.aabbMax = mx;
    }

    for (uint32_t rev = 0; rev < nN; rev++) {
        const uint32_t ni = nN - 1 - rev;
        BVHNode& nd = dN[ni];
        if (nd.isLeaf()) continue;
        const BVHNode& L = dN[nd.leftFirst];
        const BVHNode& R = dN[nd.leftFirst + 1];
        nd.aabbMin = {
            L.aabbMin.x < R.aabbMin.x ? L.aabbMin.x : R.aabbMin.x,
            L.aabbMin.y < R.aabbMin.y ? L.aabbMin.y : R.aabbMin.y,
            L.aabbMin.z < R.aabbMin.z ? L.aabbMin.z : R.aabbMin.z
        };
        nd.aabbMax = {
            L.aabbMax.x > R.aabbMax.x ? L.aabbMax.x : R.aabbMax.x,
            L.aabbMax.y > R.aabbMax.y ? L.aabbMax.y : R.aabbMax.y,
            L.aabbMax.z > R.aabbMax.z ? L.aabbMax.z : R.aabbMax.z
        };
    }
}
