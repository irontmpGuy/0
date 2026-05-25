#pragma once
#include "Vec3f.h"

// ============================================================================
// Mat3  —  row-major 3×3 rotation matrix
//
// Layout:  m[row * 3 + col]
//
//   [ m[0]  m[1]  m[2] ]
//   [ m[3]  m[4]  m[5] ]
//   [ m[6]  m[7]  m[8] ]
//
// All arithmetic methods (mul / mulT / operator*) use only float operations
// so they are trivially portable to CPU code and GLSL/HLSL shader code.
//
// Construction helpers (rotationX/Y/Z, fromEulerDeg, fromYawDirection) call
// std::cos / std::atan2 and are therefore CPU-only; call them at load time or
// on the host side of a per-frame update, never inside a kernel.
// ============================================================================

struct Mat3 {

    float m[9];

    // Default-construct as identity
    Mat3() {
        m[0]=1.f; m[1]=0.f; m[2]=0.f;
        m[3]=0.f; m[4]=1.f; m[5]=0.f;
        m[6]=0.f; m[7]=0.f; m[8]=1.f;
    }

    // ---- Arithmetic (GPU-safe) ----------------------------------------

    // M * v
    inline Vec3f mul(Vec3f v) const {
        return { m[0]*v.x + m[1]*v.y + m[2]*v.z,
                 m[3]*v.x + m[4]*v.y + m[5]*v.z,
                 m[6]*v.x + m[7]*v.y + m[8]*v.z };
    }

    // M^T * v  (= M^-1 * v for orthogonal rotation matrices)
    inline Vec3f mulT(Vec3f v) const {
        return { m[0]*v.x + m[3]*v.y + m[6]*v.z,
                 m[1]*v.x + m[4]*v.y + m[7]*v.z,
                 m[2]*v.x + m[5]*v.y + m[8]*v.z };
    }

    // Matrix multiplication  (A * B)
    Mat3 operator*(const Mat3& o) const {
        Mat3 r;
        r.m[0] = m[0]*o.m[0] + m[1]*o.m[3] + m[2]*o.m[6];
        r.m[1] = m[0]*o.m[1] + m[1]*o.m[4] + m[2]*o.m[7];
        r.m[2] = m[0]*o.m[2] + m[1]*o.m[5] + m[2]*o.m[8];

        r.m[3] = m[3]*o.m[0] + m[4]*o.m[3] + m[5]*o.m[6];
        r.m[4] = m[3]*o.m[1] + m[4]*o.m[4] + m[5]*o.m[7];
        r.m[5] = m[3]*o.m[2] + m[4]*o.m[5] + m[5]*o.m[8];

        r.m[6] = m[6]*o.m[0] + m[7]*o.m[3] + m[8]*o.m[6];
        r.m[7] = m[6]*o.m[1] + m[7]*o.m[4] + m[8]*o.m[7];
        r.m[8] = m[6]*o.m[2] + m[7]*o.m[5] + m[8]*o.m[8];
        return r;
    }

    // ---- CPU-only construction helpers --------------------------------
    // (call std::cos / std::sin / std::atan2 — host side only)

    static Mat3 identity() { return Mat3{}; }

    // Rotation around X axis (pitch): right-hand, radians
    static Mat3 rotationX(float rad) {
        float c = std::cos(rad), s = std::sin(rad);
        Mat3 r{};
        // row 0 unchanged:  [1, 0, 0]
        r.m[4] =  c;  r.m[5] = -s;   // row 1: [0, c, -s]
        r.m[7] =  s;  r.m[8] =  c;   // row 2: [0, s,  c]
        return r;
    }

    // Rotation around Y axis (yaw): right-hand, radians
    //   +angle rotates +Z toward +X
    static Mat3 rotationY(float rad) {
        float c = std::cos(rad), s = std::sin(rad);
        Mat3 r{};
        r.m[0] =  c;  r.m[2] =  s;   // row 0: [ c, 0, s]
        // row 1 unchanged:  [0, 1, 0]
        r.m[6] = -s;  r.m[8] =  c;   // row 2: [-s, 0, c]
        return r;
    }

    // Rotation around Z axis (roll): right-hand, radians
    static Mat3 rotationZ(float rad) {
        float c = std::cos(rad), s = std::sin(rad);
        Mat3 r{};
        r.m[0] =  c;  r.m[1] = -s;   // row 0: [c, -s, 0]
        r.m[3] =  s;  r.m[4] =  c;   // row 1: [s,  c, 0]
        // row 2 unchanged:  [0, 0, 1]
        return r;
    }

    // Euler angles in degrees, applied as  Ry * Rx * Rz
    // (standard "YXZ" / Tait-Bryan convention, Y-up world)
    static Mat3 fromEulerDeg(float dx, float dy, float dz) {
        constexpr float toRad = 3.14159265f / 180.f;
        return rotationY(dy * toRad) * rotationX(dx * toRad) * rotationZ(dz * toRad);
    }

    // Yaw-only rotation that aligns `modelForward` (default +Z) with `dir`.
    //
    // Strips the Y component of both vectors so the result is always a
    // pure horizontal turn around the world Y axis.  Safe to call every
    // frame to keep a player mesh facing its movement direction.
    //
    // If your model faces -Z in its GLB, pass modelForward = {0,0,-1}.
    // If it faces +X,  pass modelForward = {1,0,0}.  Etc.
    static Mat3 fromYawDirection(Vec3f dir,
                                 Vec3f modelForward = {0.f, 0.f, 1.f})
    {
        // Flatten to XZ plane
        dir.y = 0.f;
        float dl = dir.length();
        if (dl < 1e-6f) return identity();
        dir = { dir.x / dl, 0.f, dir.z / dl };

        modelForward.y = 0.f;
        float fl = modelForward.length();
        if (fl < 1e-6f) return identity();
        modelForward = { modelForward.x / fl, 0.f, modelForward.z / fl };

        float yawTarget = std::atan2(dir.x,          dir.z);
        float yawFwd    = std::atan2(modelForward.x, modelForward.z);
        return rotationY(yawTarget - yawFwd);
    }
};