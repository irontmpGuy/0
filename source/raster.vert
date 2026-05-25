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

layout(std430, binding = 1) readonly buffer CameraBuf { GpuCamera cam; };

layout(location = 0) in vec3 inPos;
layout(location = 1) in vec2 inUV;
layout(location = 2) in uint inTextureIndex;
layout(location = 3) in uint inColor;
layout(location = 4) in uint inMode; // 0 world, 1 screen overlay, 2 world dust
layout(location = 5) in vec3 inNormal;

layout(location = 0) out vec2 vUV;
layout(location = 1) out vec3 vWorldPos;
layout(location = 2) flat out uint vTextureIndex;
layout(location = 3) flat out uint vColor;
layout(location = 4) flat out uint vMode;
layout(location = 5) out vec3 vNormal;

vec3 safeNormalize(vec3 v, vec3 fallback)
{
    float l2 = dot(v, v);
    if (l2 <= 1e-12 || any(isnan(v)) || any(isinf(v))) return fallback;
    return v * inversesqrt(l2);
}

void buildCameraBasis(out vec3 forward, out vec3 right, out vec3 up,
                      out float rightLen, out float upLen)
{
    forward = safeNormalize(cam.dir.xyz, vec3(0.0, 0.0, 1.0));

    vec3 rawRight = cam.plane.xyz;
    vec3 rawUp = cam.upPlane.xyz;
    rightLen = max(length(rawRight), 1e-6);
    upLen = max(length(rawUp), 1e-6);

    right = rawRight - forward * dot(rawRight, forward);
    if (dot(right, right) <= 1e-12) {
        right = cross(rawUp, forward);
        if (dot(right, right) <= 1e-12) right = cross(vec3(0.0, 1.0, 0.0), forward);
        if (dot(right, right) <= 1e-12) right = vec3(1.0, 0.0, 0.0);
    }
    right = safeNormalize(right, vec3(1.0, 0.0, 0.0));
    if (dot(rawRight, rawRight) > 1e-12 && dot(right, rawRight) < 0.0) right = -right;

    // Preserve the sign of cam.upPlane. The previous "idealUp = cross(...)"
    // correction could silently invert the vertical axis for one camera
    // handedness, which makes floor/ceiling appear swapped.
    up = rawUp - forward * dot(rawUp, forward) - right * dot(rawUp, right);
    if (dot(up, up) <= 1e-12) {
        up = rawUp - forward * dot(rawUp, forward);
    }
    if (dot(up, up) <= 1e-12) {
        up = vec3(0.0, 1.0, 0.0) - forward * dot(vec3(0.0, 1.0, 0.0), forward);
    }
    if (dot(up, up) <= 1e-12) up = cross(forward, right);
    up = safeNormalize(up, vec3(0.0, 1.0, 0.0));
    if (dot(rawUp, rawUp) > 1e-12 && dot(up, rawUp) < 0.0) up = -up;
}

void main()
{
    vUV = inUV;
    vWorldPos = inPos;
    vTextureIndex = inTextureIndex;
    vColor = inColor;
    vMode = inMode;
    vNormal = inNormal;

    if (inMode == 1u) {
        // Screen-space overlay vertex. inPos.xy is already Vulkan NDC.
        gl_Position = vec4(inPos.xy, 0.0, 1.0);
        return;
    }

    vec3 forward, right, up;
    float rightLen, upLen;
    buildCameraBasis(forward, right, up, rightLen, upLen);

    vec3 d = inPos - cam.pos.xyz;
    float z = dot(d, forward);

    // Match the raycaster camera: ray = dir + plane * cx + upPlane * -cy.
    // Therefore projected NDC is:
    //   x = dot(d,right) / (z * |plane|)
    //   y = -dot(d,up) / (z * |upPlane|)
    float clipX = dot(d, right) / rightLen;
    float clipY = -dot(d, up) / upLen;

    float nearZ = 0.03;
    float farZ = max(cam.fog.x, nearZ + 1.0);
    float ndcZ = (z - nearZ) / (farZ - nearZ);

    // Tiny world-space dust motes are depth-tested against the G-buffer. Pull
    // them only a very small amount toward the camera to avoid depth precision
    // flicker without making them obviously float through surfaces.
    if (inMode == 2u) {
        ndcZ = max(ndcZ - 0.0007, 0.0);
    }

    gl_Position = vec4(clipX, clipY, ndcZ * z, z);
}
