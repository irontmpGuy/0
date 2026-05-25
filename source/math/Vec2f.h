#pragma once
#include <cmath>

struct Vec2f
{
    float x;
    float y;

    Vec2f operator+(const Vec2f& rhs) const
    {
        return { x + rhs.x, y + rhs.y };
    }
    Vec2f operator-(const Vec2f& rhs) const
    {
        return { x - rhs.x, y - rhs.y };
    }
    Vec2f operator*(float scalar) const
    {
        return { x * scalar, y * scalar };
    }
    Vec2f operator/(float scalar) const
    {
        return { x / scalar, y / scalar };
    }
    float dot(const Vec2f& rhs) const
    {
        return x * rhs.x + y * rhs.y;
    }
    float length() const
    {
        return std::sqrt(x * x + y * y);
    }
    Vec2f normalized() const
    {
        float len = length();
        return { x / len, y / len };
    }
    Vec2f rotated(float angle) const
    {
        float cosA = std::cos(angle);
        float sinA = std::sin(angle);
        return { x * cosA - y * sinA, x * sinA + y * cosA };
    }
};