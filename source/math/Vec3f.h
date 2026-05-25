#pragma once
#include <cmath>
#include "Vec2f.h"

struct Vec3f
{
    float x = 0.f;
    float y = 0.f;
    float z = 0.f;

    // -----------------------------------------------------------------------
    // Construction helpers
    // -----------------------------------------------------------------------
    static Vec3f from2D(Vec2f xy, float z = 0.f) { return { xy.x, xy.y, z }; }

    Vec2f xy() const { return { x, y }; }

    // -----------------------------------------------------------------------
    // Arithmetic
    // -----------------------------------------------------------------------
    Vec3f operator+(const Vec3f& r) const { return { x+r.x, y+r.y, z+r.z }; }
    Vec3f operator-(const Vec3f& r) const { return { x-r.x, y-r.y, z-r.z }; }
    Vec3f operator*(float s)        const { return { x*s,   y*s,   z*s   }; }
    Vec3f operator/(float s)        const { return { x/s,   y/s,   z/s   }; }
    bool operator==(const Vec3f& r) const { return x==r.x && y==r.y && z==r.z; }

    Vec3f& operator+=(const Vec3f& r) { x+=r.x; y+=r.y; z+=r.z; return *this; }
    Vec3f& operator-=(const Vec3f& r) { x-=r.x; y-=r.y; z-=r.z; return *this; }
    Vec3f& operator*=(float s)        { x*=s;   y*=s;   z*=s;   return *this; }

    // -----------------------------------------------------------------------
    // Geometry
    // -----------------------------------------------------------------------
    float dot(const Vec3f& r)  const { return x*r.x + y*r.y + z*r.z; }
    float dot2D(const Vec3f& r)  const { return x*r.x + z*r.z; }
    float lengthSq()           const { return dot(*this); }
    float length()             const { return std::sqrt(lengthSq()); }

    Vec3f normalized() const
    {
        float len = length();
        return (len > 1e-8f) ? (*this / len) : Vec3f{};
    }

    Vec3f rotatedAroundAxis(const Vec3f& axis, float angle) const {
        // axis must be normalized
        float cosTheta = std::cos(angle);
        float sinTheta = std::sin(angle);

        // Rodrigues' Rotation Formula:
        // v_rot = v*cosTheta + (axis x v)*sinTheta + axis*(axis . v)*(1 - cosTheta)
        
        Vec3f crossProd = axis.cross(*this);
        float dotProd = axis.dot(*this);

        return (*this * cosTheta) + 
            (crossProd * sinTheta) + 
            (axis * dotProd * (1.0f - cosTheta));
    }

    Vec3f cross(const Vec3f& r) const
    {
        return { y*r.z - z*r.y,
                 z*r.x - x*r.z,
                 x*r.y - y*r.x };
    }

    // Rotate around the Z axis (same semantics as Vec2f::rotated)
    Vec3f rotatedZ(float angle) const
    {
        float c = std::cos(angle), s = std::sin(angle);
        return { x*c - y*s, x*s + y*c, z };
    }

    // Rotate around the X axis (pitch)
    Vec3f rotatedX(float angle) const
    {
        float c = std::cos(angle), s = std::sin(angle);
        return { x, y*c - z*s, y*s + z*c };
    }

    Vec3f rotatedY(float angle) const
    {
        float c = std::cos(angle), s = std::sin(angle);
        return { x*c + z*s, y, -x*s + z*c };
    }

    Vec3f rotatedEuler(const Vec3f& r) {
        Vec3f out = this->rotatedX(r.x);
        out = out.rotatedY(r.y);
        out = out.rotatedZ(r.z);

        return out;
    }

    Vec3f inverseRotatedEuler(const Vec3f& r) {
        // Reverse order, negative angles
        Vec3f out = this->rotatedZ(-r.z);
        out = rotatedY(-r.y);
        out = rotatedX(-r.x);

        return out;
    }

};

// Allow  scalar * Vec3f
inline Vec3f operator*(float s, const Vec3f& v) { return v * s; }
