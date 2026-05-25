#version 450

struct GpuCamera {
    vec4 pos;
    vec4 dir;
    vec4 plane;
    vec4 upPlane;
    vec4 fog;
    vec4 gridMin;
    uvec4 screen;
    uvec4 gridSize;
};
struct GpuTextureInfo { uint offset; uint width; uint height; uint pad; };

layout(std430, binding = 1) readonly buffer CameraBuf { GpuCamera cam; };
layout(std430, binding = 6) readonly buffer TexInfos { GpuTextureInfo texInfos[]; };
layout(std430, binding = 7) readonly buffer TexPixels { uint texPixels[]; };

layout(location = 0) in vec2 vUV;
layout(location = 1) in vec3 vWorldPos;
layout(location = 2) flat in uint vTextureIndex;
layout(location = 3) flat in uint vColor;
layout(location = 4) flat in uint vMode;

layout(location = 0) out vec4 outColor;

vec3 unpackRgb(uint color)
{
    return vec3(float((color >> 16) & 255u),
                float((color >>  8) & 255u),
                float( color        & 255u)) / 255.0;
}

vec4 unpackArgb(uint color)
{
    uint ai = (color >> 24) & 255u;
    float a = (ai == 0u) ? 1.0 : float(ai) / 255.0;
    return vec4(unpackRgb(color), a);
}

uint rgbToPacked(vec3 c)
{
    c = clamp(c * 255.0, 0.0, 255.0);
    return (uint(c.r) << 16) | (uint(c.g) << 8) | uint(c.b);
}

uint applyFog(uint color, float dist)
{
    if (cam.screen.w != 0u) return color;

    float fogMax = cam.fog.y;
    float fogFactor = cam.fog.z;
    float minFog = cam.fog.w;
    float fogStart = cam.gridMin.w;

    float minI = clamp(1.0 - minFog / 100.0, 0.0, 1.0);
    vec3 rgb = unpackRgb(color) * minI;

    if (dist >= fogStart) {
        if (dist >= fogMax) return 0u;
        float normD = (dist - fogStart) / max(fogMax - fogStart, 0.0001);
        float f = clamp(fogFactor / 100.0, 0.01, 1.0);
        float intensity = pow(1.0 - normD, 1.0 / f);
        rgb *= intensity;
    }
    return rgbToPacked(rgb);
}

uint sampleTexture(uint texIndex, vec2 uv, float dist)
{
    if (texIndex == 0xFFFFFFFFu) return applyFog(0xFF00FFu, dist);
    GpuTextureInfo t = texInfos[texIndex];
    if (t.width == 0u || t.height == 0u) return applyFog(0xFF00FFu, dist);

    vec2 fuv = fract(uv);
    uint tx = min(uint(fuv.x * float(t.width)),  t.width - 1u);
    uint ty = min(uint(fuv.y * float(t.height)), t.height - 1u);
    return applyFog(texPixels[t.offset + ty * t.width + tx], dist);
}

void main()
{
    if (vMode == 1u || vMode == 2u) {
        outColor = unpackArgb(vColor);
        return;
    }

    float dist = length(vWorldPos - cam.pos.xyz);
    uint packed = sampleTexture(vTextureIndex, vUV, dist);
    outColor = vec4(unpackRgb(packed), 1.0);
}
