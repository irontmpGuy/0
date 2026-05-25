#pragma once
#define NOMINMAX
#include "Triangle.h"
#include "Vec3f.h"
#include <vector>
#include <algorithm>
#include <limits>
#include <cmath>
#include <iostream>

// ---------------------------------------------------------------------------
// AABB — used during build only; not stored in the final node layout
// ---------------------------------------------------------------------------
struct AABB {
    Vec3f mn = {  1e30f,  1e30f,  1e30f };
    Vec3f mx = { -1e30f, -1e30f, -1e30f };

    void grow(const Vec3f& p) {
        if (p.x < mn.x) mn.x = p.x;  if (p.x > mx.x) mx.x = p.x;
        if (p.y < mn.y) mn.y = p.y;  if (p.y > mx.y) mx.y = p.y;
        if (p.z < mn.z) mn.z = p.z;  if (p.z > mx.z) mx.z = p.z;
    }
    void grow(const AABB& b) {
        if (b.mn.x > 1e29f) return; // empty guard
        grow(b.mn); grow(b.mx);
    }
    float area() const {
        float ex = mx.x - mn.x, ey = mx.y - mn.y, ez = mx.z - mn.z;
        if (ex < 0.f || ey < 0.f || ez < 0.f) return 0.f;
        return 2.f * (ex * ey + ey * ez + ez * ex);
    }
    bool valid() const { return mn.x <= mx.x; }
};

// ---------------------------------------------------------------------------
// Flat BVH node — 32 bytes, two per cache line
//
//   isLeaf() == true:
//       leftFirst = first index in BVH::triIdx[]
//       triCount  = number of triangles in leaf
//
//   isLeaf() == false (internal):
//       leftFirst = index of LEFT child in BVH::nodes[]
//                   RIGHT child is always at leftFirst + 1
//       triCount  = 0
// ---------------------------------------------------------------------------
struct BVHNode {
    Vec3f    aabbMin;
    uint32_t leftFirst = 0;
    Vec3f    aabbMax;
    uint32_t triCount  = 0;

    bool isLeaf() const { return triCount > 0; }
};

// ---------------------------------------------------------------------------
// BVH — one instance per DDA cell per mesh instance.
// Each cell BVH contains only the triangles whose AABB overlaps that cell,
// so traversal never tests triangles from neighbouring cells.
// ---------------------------------------------------------------------------
struct BVH {

    std::vector<BVHNode>  nodes;   // flat node pool, index 0 = root
    std::vector<uint32_t> triIdx;  // permuted subset of GLOBAL triangle indices into tris[]

    // -----------------------------------------------------------------------
    // Build SAH BVH over a specific SUBSET of triangles, identified by their
    // global indices into the shared tris[] list.
    //
    // bounds[] and centroids[] are allocated at global size (tris.size()) so
    // that triIdx values can index them directly — the same way subdivide()
    // and refreshBounds() already do. Only entries in initialIndices are
    // populated; all others are left at their zero-initialised defaults.
    //
    // This is a load-time-only call: the temporary arrays are freed on return.
    // -----------------------------------------------------------------------
    void build(const std::vector<Triangle>& tris,
               const std::vector<uint32_t>& initialIndices)
    {
        const uint32_t N       = (uint32_t)initialIndices.size();
        const uint32_t globalN = (uint32_t)tris.size();
        if (N == 0) return;

        // triIdx starts as the caller-supplied subset; subdivide() will
        // permute it in-place but never adds or removes elements.
        triIdx = initialIndices;

        // Allocate at global size so bounds[triIdx[i]] is always valid.
        // Only entries listed in initialIndices are written; the rest remain
        // at their default-constructed (empty AABB / zero centroid) values,
        // which subdivide() will never touch because they are not in triIdx.
        std::vector<Vec3f> centroids(globalN);
        std::vector<AABB>  bounds(globalN);

        for (uint32_t i = 0; i < N; i++) {
            const uint32_t  gi = initialIndices[i];
            const Triangle&  t = tris[gi];
            bounds[gi].grow(t.v1.pos);
            bounds[gi].grow(t.v2.pos);
            bounds[gi].grow(t.v3.pos);
            centroids[gi] = {
                (t.v1.pos.x + t.v2.pos.x + t.v3.pos.x) * (1.f / 3.f),
                (t.v1.pos.y + t.v2.pos.y + t.v3.pos.y) * (1.f / 3.f),
                (t.v1.pos.z + t.v2.pos.z + t.v3.pos.z) * (1.f / 3.f)
            };
        }

        nodes.reserve(2 * N);
        nodes.push_back(BVHNode{});
        nodes[0].leftFirst = 0;
        nodes[0].triCount  = N;
        refreshBounds(0, bounds);
        subdivide(0, centroids, bounds);
    }

    // -----------------------------------------------------------------------
    // Convenience: build over ALL triangles (full-mesh BVH).
    // Logs the result — use this path only for debugging or non-cell builds.
    // -----------------------------------------------------------------------
    void build(const std::vector<Triangle>& tris) {
        const uint32_t N = (uint32_t)tris.size();
        std::vector<uint32_t> all(N);
        for (uint32_t i = 0; i < N; i++) all[i] = i;
        build(tris, all);
        std::cout << "[BVH] " << N << " tris  →  "
                  << nodes.size() << " nodes\n";
    }

    // -----------------------------------------------------------------------
    // Traverse the BVH for a single ray in model space.
    //
    //   origin / dir   — ray in model space (dir need NOT be normalised;
    //                    t is in the same parameterisation as dir)
    //   tris           — the shared, immutable GLOBAL triangle list for this mesh;
    //                    triIdx[] stores indices into this list
    //   tMin / tMax    — depth window; pass 0 and 1e30f for a full search.
    //                    Because each BVH contains only triangles that overlap
    //                    the DDA cell it was built for, no extra cell-boundary
    //                    clamping is required here.
    //   outNormal      — model-space surface normal of the closest hit
    //   outColor       — vertex / material color of the closest hit
    //
    // Returns the t of the closest hit within [tMin, tMax], or -1 if none.
    // -----------------------------------------------------------------------
    float intersect(Vec3f origin, Vec3f dir,
                    const std::vector<Triangle>& tris,
                    float tMin, float tMax,
                    Vec3f& outNormal, float& outHitU, float& outHitV, uint32_t& triIdxOut) const
    {
        if (nodes.empty()) return -1.f;

        // Precompute reciprocals for slab tests.
        // Sign-correct large value for zero-direction components.
        Vec3f invDir = {
            (std::abs(dir.x) > 1e-9f) ? 1.f / dir.x : (dir.x >= 0.f ?  1e30f : -1e30f),
            (std::abs(dir.y) > 1e-9f) ? 1.f / dir.y : (dir.y >= 0.f ?  1e30f : -1e30f),
            (std::abs(dir.z) > 1e-9f) ? 1.f / dir.z : (dir.z >= 0.f ?  1e30f : -1e30f)
        };

        float bestT  = tMax;
        bool  anyHit = false;

        // Iterative stack-based traversal (depth 128 is safe for any mesh)
        uint32_t stack[128];
        int      sPtr = 0;
        stack[sPtr++] = 0; // start at root

        while (sPtr > 0) {
            const BVHNode& node = nodes[stack[--sPtr]];

            // Cheap AABB reject: skip if node box not hit within [tMin, bestT]
            if (!slabTest(origin, invDir, node.aabbMin, node.aabbMax, tMin, bestT))
                continue;

            if (node.isLeaf()) {
                // Test every triangle in the leaf
                for (uint32_t i = 0; i < node.triCount; i++) {
                    uint32_t currentTriIdx = triIdx[node.leftFirst + i];
                    const Triangle& tri = tris[triIdx[node.leftFirst + i]];
                    Vec3f n;
                    float u, v;
                    float t = mollerTrumbore(origin, dir, tri, n, u, v);
                    // Accept only if inside [tMin, bestT] — tMin enforces the
                    // near cell boundary, bestT shrinks as we find closer hits
                    if (t > tMin && t < bestT) {
                        bestT     = t;
                        outNormal = n;
                        outHitU = u;
                        outHitV = v;
                        triIdxOut = currentTriIdx;
                        anyHit    = true;
                    }
                }
            } else {
                // Internal: push both children.
                // Far child first → near child is on top of stack → tested first.
                stack[sPtr++] = node.leftFirst;
                stack[sPtr++] = node.leftFirst + 1;
            }
        }

        return anyHit ? bestT : -1.f;
    }

private:

    // SAH binning resolution: 8 bins is a good quality/build-time tradeoff
    static constexpr int      BINS     = 8;
    // Stop subdividing when a node holds at most this many triangles
    static constexpr uint32_t LEAF_MAX = 4;

    // -----------------------------------------------------------------------
    // Recompute the AABB of node[nodeIdx] from the triangle bounds it spans.
    // -----------------------------------------------------------------------
    void refreshBounds(uint32_t nodeIdx, const std::vector<AABB>& bounds) {
        BVHNode& node = nodes[nodeIdx];
        AABB box;
        for (uint32_t i = 0; i < node.triCount; i++)
            box.grow(bounds[triIdx[node.leftFirst + i]]);
        node.aabbMin = box.mn;
        node.aabbMax = box.mx;
    }

    // -----------------------------------------------------------------------
    // Recursively split node[nodeIdx] using SAH binning.
    // Reads nodes[nodeIdx] by index every time (never keeps a reference across
    // push_back calls that might reallocate the vector).
    // -----------------------------------------------------------------------
    void subdivide(uint32_t nodeIdx,
                   const std::vector<Vec3f>& centroids,
                   const std::vector<AABB>&  bounds)
    {
        if (nodes[nodeIdx].triCount <= LEAF_MAX) return;

        // --- Node surface area (SAH denominator) ----------------------------
        float nodeArea;
        {
            float ex = nodes[nodeIdx].aabbMax.x - nodes[nodeIdx].aabbMin.x;
            float ey = nodes[nodeIdx].aabbMax.y - nodes[nodeIdx].aabbMin.y;
            float ez = nodes[nodeIdx].aabbMax.z - nodes[nodeIdx].aabbMin.z;
            nodeArea = 2.f * (ex * ey + ey * ez + ez * ex);
        }
        if (nodeArea < 1e-10f) return; // degenerate, stay as leaf

        // --- Centroid AABB (defines the binning range on each axis) ---------
        AABB centBox;
        for (uint32_t i = 0; i < nodes[nodeIdx].triCount; i++)
            centBox.grow(centroids[triIdx[nodes[nodeIdx].leftFirst + i]]);

        // --- SAH sweep over 3 axes × (BINS-1) split planes -----------------
        int   bestAxis = -1, bestBin = -1;
        float bestCost = std::numeric_limits<float>::max();

        for (int axis = 0; axis < 3; axis++) {
            float cMin = (&centBox.mn.x)[axis];
            float cMax = (&centBox.mx.x)[axis];
            if (cMax - cMin < 1e-6f) continue; // all centroids coplanar on this axis

            struct Bin { AABB bounds; uint32_t cnt = 0; };
            Bin bins[BINS] = {};

            // Bin each triangle by its centroid
            float bScale = (float)BINS / (cMax - cMin);
            for (uint32_t i = 0; i < nodes[nodeIdx].triCount; i++) {
                uint32_t ti  = triIdx[nodes[nodeIdx].leftFirst + i];
                int      b   = (int)(((&centroids[ti].x)[axis] - cMin) * bScale);
                b = std::min(b, BINS - 1);
                bins[b].cnt++;
                bins[b].bounds.grow(bounds[ti]);
            }

            // Left-to-right prefix (cumulative count + surface area)
            float    lArea[BINS - 1]; uint32_t lCnt[BINS - 1];
            AABB     lBox; uint32_t lc = 0;
            for (int i = 0; i < BINS - 1; i++) {
                lBox.grow(bins[i].bounds); lc += bins[i].cnt;
                lArea[i] = lBox.area(); lCnt[i] = lc;
            }

            // Right-to-left suffix (cumulative count + surface area)
            float    rArea[BINS - 1]; uint32_t rCnt[BINS - 1];
            AABB     rBox; uint32_t rc = 0;
            for (int i = BINS - 2; i >= 0; i--) {
                rBox.grow(bins[i + 1].bounds); rc += bins[i + 1].cnt;
                rArea[i] = rBox.area(); rCnt[i] = rc;
            }

            // Evaluate each candidate split (7 planes for 8 bins)
            for (int i = 0; i < BINS - 1; i++) {
                if (lCnt[i] == 0 || rCnt[i] == 0) continue;
                float cost = (lCnt[i] * lArea[i] + rCnt[i] * rArea[i]) / nodeArea;
                if (cost < bestCost) {
                    bestCost = cost; bestAxis = axis; bestBin = i;
                }
            }
        }

        // Leaf cost = just testing all triangles (no traversal overhead)
        float leafCost = (float)nodes[nodeIdx].triCount;
        if (bestAxis < 0 || bestCost >= leafCost) return; // no beneficial split

        // --- Partition triIdx around the chosen split in-place --------------
        float cMin  = (&centBox.mn.x)[bestAxis];
        float cMax  = (&centBox.mx.x)[bestAxis];
        float bScale2 = (float)BINS / (cMax - cMin);

        uint32_t  first = nodes[nodeIdx].leftFirst;
        uint32_t  count = nodes[nodeIdx].triCount;
        uint32_t* pFirst = triIdx.data() + first;
        uint32_t* pLast  = pFirst + count;

        uint32_t* pMid = std::partition(pFirst, pLast, [&](uint32_t ti) {
            int b = (int)(((&centroids[ti].x)[bestAxis] - cMin) * bScale2);
            return std::min(b, BINS - 1) <= bestBin;
        });

        uint32_t leftCount  = (uint32_t)(pMid - pFirst);
        uint32_t rightCount = count - leftCount;
        if (leftCount == 0 || rightCount == 0) return; // degenerate, leave as leaf

        // --- Allocate two child nodes ----------------------------------------
        // IMPORTANT: copy values from parent BEFORE push_back, which may
        // reallocate nodes[] and invalidate any reference into it.
        uint32_t myFirst = first;

        uint32_t leftIdx = (uint32_t)nodes.size();
        nodes.push_back(BVHNode{});  // left child  — may reallocate
        nodes.push_back(BVHNode{});  // right child — may reallocate

        nodes[leftIdx    ].leftFirst = myFirst;
        nodes[leftIdx    ].triCount  = leftCount;
        nodes[leftIdx + 1].leftFirst = myFirst + leftCount;
        nodes[leftIdx + 1].triCount  = rightCount;

        // Convert parent from leaf to internal node
        nodes[nodeIdx].leftFirst = leftIdx;
        nodes[nodeIdx].triCount  = 0;

        refreshBounds(leftIdx,     bounds);
        refreshBounds(leftIdx + 1, bounds);

        subdivide(leftIdx,     centroids, bounds);
        subdivide(leftIdx + 1, centroids, bounds);
    }

    // -----------------------------------------------------------------------
    // Ray–AABB slab test.
    // Returns true if the ray hits [bMin, bMax] within the window (tMin, tMax).
    // -----------------------------------------------------------------------
    static inline bool slabTest(Vec3f o, Vec3f invD,
                                 Vec3f bMin, Vec3f bMax,
                                 float tMin, float tMax)
    {
        float tx0 = (bMin.x - o.x) * invD.x,  tx1 = (bMax.x - o.x) * invD.x;
        float ty0 = (bMin.y - o.y) * invD.y,  ty1 = (bMax.y - o.y) * invD.y;
        float tz0 = (bMin.z - o.z) * invD.z,  tz1 = (bMax.z - o.z) * invD.z;

        float tNear = std::max({ std::min(tx0,tx1), std::min(ty0,ty1), std::min(tz0,tz1), tMin });
        float tFar  = std::min({ std::max(tx0,tx1), std::max(ty0,ty1), std::max(tz0,tz1), tMax });

        return tNear <= tFar;
    }

    // -----------------------------------------------------------------------
    // Möller–Trumbore ray–triangle intersection.
    // Returns t > 0 on hit; -1 otherwise. Sets n to the face normal on hit.
    // dir need not be normalised; t is in the same parameterisation as dir.
    // -----------------------------------------------------------------------
    static inline float mollerTrumbore(Vec3f o, Vec3f d, const Triangle& tri, Vec3f& n, float& outU, float& outV) // MAth intersection
    {
        const float EPS = 1e-6f;
        Vec3f e1 = tri.v2.pos - tri.v1.pos;
        Vec3f e2 = tri.v3.pos - tri.v1.pos;
        Vec3f h  = d.cross(e2);
        float a  = e1.dot(h);
        if (a > -EPS && a < EPS) return -1.f;
        
        float f = 1.f / a;
        Vec3f s = o - tri.v1.pos;
        outU = f * s.dot(h); // Barycentric U
        if (outU < 0.f || outU > 1.f) return -1.f;
        
        Vec3f q = s.cross(e1);
        outV = f * d.dot(q); // Barycentric V
        if (outV < 0.f || outU + outV > 1.f) return -1.f;
        
        float t = f * e2.dot(q);
        if (t > EPS) { 
            n = e1.cross(e2).normalized(); 
            return t; 
        }
        return -1.f;
    }
};