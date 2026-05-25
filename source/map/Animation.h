#pragma once
#include "Vec3f.h"
#include "Mat3.h"
#include <vector>
#include <string>
#include <cstdint>
#include <cmath>
#include <unordered_map>
#include <algorithm>
#include <iostream>
#include "tiny_gltf.h"

// ── Quaternion (minimal, CPU-only) ──────────────────────────────────────────
struct Quat {
    float x=0,y=0,z=0,w=1;
    static Quat identity() { return {0,0,0,1}; }
    Quat operator*(const Quat& b) const {
        return { w*b.x + x*b.w + y*b.z - z*b.y,
                 w*b.y - x*b.z + y*b.w + z*b.x,
                 w*b.z + x*b.y - y*b.x + z*b.w,
                 w*b.w - x*b.x - y*b.y - z*b.z };
    }
    Quat normalized() const {
        float n = sqrtf(x*x+y*y+z*z+w*w);
        if (n<1e-9f) return identity();
        float inv=1.f/n; return {x*inv,y*inv,z*inv,w*inv};
    }
    // Slerp
    static Quat slerp(Quat a, Quat b, float t) {
        float dot = a.x*b.x+a.y*b.y+a.z*b.z+a.w*b.w;
        if (dot < 0.f) { b={-b.x,-b.y,-b.z,-b.w}; dot=-dot; }
        if (dot > 0.9995f) {
            Quat r={a.x+t*(b.x-a.x),a.y+t*(b.y-a.y),a.z+t*(b.z-a.z),a.w+t*(b.w-a.w)};
            return r.normalized();
        }
        float th0=acosf(dot), th=th0*t;
        float s0=cosf(th)-dot*sinf(th)/sinf(th0);
        float s1=sinf(th)/sinf(th0);
        return {s0*a.x+s1*b.x,s0*a.y+s1*b.y,s0*a.z+s1*b.z,s0*a.w+s1*b.w};
    }
    // Convert to 3x3 rotation matrix (no scale)
    Mat3 toMat3() const {
        float x2=x+x,y2=y+y,z2=z+z;
        float xx=x*x2,xy=x*y2,xz=x*z2;
        float yy=y*y2,yz=y*z2,zz=z*z2;
        float wx=w*x2,wy=w*y2,wz=w*z2;
        Mat3 mat;
        // row 0
        mat.m[0]=1.f-(yy+zz); mat.m[1]=xy-wz;       mat.m[2]=xz+wy;
        // row 1
        mat.m[3]=xy+wz;       mat.m[4]=1.f-(xx+zz); mat.m[5]=yz-wx;
        // row 2
        mat.m[6]=xz-wy;       mat.m[7]=yz+wx;       mat.m[8]=1.f-(xx+yy);
        return mat;
    }
};

// ── 4x4 matrix (column-major), CPU-only ─────────────────────────────────────
struct Mat4 {
    float m[4][4] = {};
    static Mat4 identity() {
        Mat4 r; r.m[0][0]=r.m[1][1]=r.m[2][2]=r.m[3][3]=1.f; return r;
    }
    Mat4 operator*(const Mat4& b) const {
        Mat4 r;
        for (int i=0;i<4;i++) for (int j=0;j<4;j++) for (int k=0;k<4;k++)
            r.m[i][j]+=m[i][k]*b.m[k][j];
        return r;
    }
    Vec3f mulPoint(Vec3f p) const {
        float x=m[0][0]*p.x+m[0][1]*p.y+m[0][2]*p.z+m[0][3];
        float y=m[1][0]*p.x+m[1][1]*p.y+m[1][2]*p.z+m[1][3];
        float z=m[2][0]*p.x+m[2][1]*p.y+m[2][2]*p.z+m[2][3];
        return {x,y,z};
    }
    static Mat4 fromTRS(Vec3f t, Quat r, Vec3f s) {
        Mat3 rot = r.toMat3();
        Mat4 mat = identity();
        // row 0: rot.m[0..2] scaled by s.x, s.y, s.z + translation
        mat.m[0][0]=rot.m[0]*s.x; mat.m[0][1]=rot.m[1]*s.y; mat.m[0][2]=rot.m[2]*s.z; mat.m[0][3]=t.x;
        // row 1
        mat.m[1][0]=rot.m[3]*s.x; mat.m[1][1]=rot.m[4]*s.y; mat.m[1][2]=rot.m[5]*s.z; mat.m[1][3]=t.y;
        // row 2
        mat.m[2][0]=rot.m[6]*s.x; mat.m[2][1]=rot.m[7]*s.y; mat.m[2][2]=rot.m[8]*s.z; mat.m[2][3]=t.z;
        return mat;
    }
};

// ── Per-vertex skin data (up to 4 influences) ───────────────────────────────
struct SkinVertex {
    uint16_t joints[4] = {0,0,0,0};
    float    weights[4]= {1,0,0,0};
};

// ── Animation channel types ─────────────────────────────────────────────────
enum class AnimTarget { Translation, Rotation, Scale };
enum class AnimInterpolation { Linear, Step };

struct AnimChannel {
    int                boneIndex     = -1;
    AnimTarget         target        = AnimTarget::Translation;
    AnimInterpolation  interpolation = AnimInterpolation::Linear;
    std::vector<float> times;      // keyframe times (seconds)
    std::vector<float> values;     // 3 floats (TXS) or 4 floats (rot) per key
};

struct Animation {
    std::string          name;
    float                duration = 0.f;
    std::vector<AnimChannel> channels;
};

// ── Bone ────────────────────────────────────────────────────────────────────
struct Bone {
    std::string name;
    int         parent = -1;
    Mat4        invBindMatrix = Mat4::identity();   // from skin.inverseBindMatrices
    // Local rest pose (used as default when no channel overrides)
    Vec3f       restT = {0,0,0};
    Quat        restR = Quat::identity();
    Vec3f       restS = {1,1,1};
};

// ── Local pose ────────────────────────────────────────────────────────────────
struct LocalPose {
    std::vector<Vec3f> T;
    std::vector<Quat>  R;
    std::vector<Vec3f> S;

    void resize(size_t n) {
        T.resize(n);
        R.resize(n);
        S.resize(n);
    }
};

// ── Runtime playback state ──────────────────────────────────────────────────
struct AnimPlayback {
    int   clip  = -1;
    float time  = 0.f;
    float speed = 1.f;
    bool  loop  = true;
};

// ── Skeleton: rig + named animation clips + current skin matrices ───────────
struct Skeleton {
    std::vector<Bone>       bones;
    std::vector<Animation>  animations;
    std::unordered_map<std::string, int> animationByName;

    // Kept for backward compatibility with old code that may still set these.
    int   activeAnim = 0;
    float time       = 0.f;

    // Computed this frame (CPU): world-space skinning matrix per bone.
    // skinMatrix[i] = globalTransform[i] * invBind[i]
    std::vector<Mat4> skinMatrices;

    bool valid() const { return !bones.empty(); }

    int findAnimation(const std::string& name) const {
        auto it = animationByName.find(name);
        return it == animationByName.end() ? -1 : it->second;
    }

    bool hasAnimation(const std::string& name) const {
        return findAnimation(name) >= 0;
    }

    std::string animationName(int index) const {
        if (index < 0 || index >= (int)animations.size()) return {};
        return animations[index].name;
    }

    void makeRestPose(LocalPose& out) const {
        const int nb = (int)bones.size();
        out.resize(nb);
        for (int i = 0; i < nb; i++) {
            out.T[i] = bones[i].restT;
            out.R[i] = bones[i].restR;
            out.S[i] = bones[i].restS;
        }
    }

    static float wrappedTime(float t, float duration, bool loop) {
        if (duration <= 1e-5f) return 0.f;
        if (loop) {
            t = fmodf(t, duration);
            if (t < 0.f) t += duration;
            return t;
        }
        if (t < 0.f) return 0.f;
        if (t > duration) return duration;
        return t;
    }

    void evaluateClip(int clipIndex, float sampleTime, LocalPose& out, bool loop = true) const {
        makeRestPose(out);
        if (!valid() || clipIndex < 0 || clipIndex >= (int)animations.size()) return;

        const Animation& anim = animations[clipIndex];
        const float t = wrappedTime(sampleTime, anim.duration, loop);
        const int nb = (int)bones.size();

        for (const AnimChannel& ch : anim.channels) {
            if (ch.boneIndex < 0 || ch.boneIndex >= nb) continue;

            const int n = (int)ch.times.size();
            if (n <= 0) continue;

            int k = 0;
            while (k < n - 1 && ch.times[k + 1] < t) k++;

            float alpha = 0.f;
            if (k < n - 1) {
                const float span = ch.times[k + 1] - ch.times[k];
                alpha = span > 1e-9f ? (t - ch.times[k]) / span : 0.f;
                if (alpha < 0.f) alpha = 0.f;
                if (alpha > 1.f) alpha = 1.f;
            }
            if (ch.interpolation == AnimInterpolation::Step) alpha = 0.f;

            if (ch.target == AnimTarget::Translation) {
                if ((int)ch.values.size() < (k + 1) * 3) continue;
                Vec3f a = { ch.values[k * 3 + 0], ch.values[k * 3 + 1], ch.values[k * 3 + 2] };
                Vec3f b = a;
                if (k < n - 1 && (int)ch.values.size() >= (k + 2) * 3) {
                    b = { ch.values[(k + 1) * 3 + 0], ch.values[(k + 1) * 3 + 1], ch.values[(k + 1) * 3 + 2] };
                }
                out.T[ch.boneIndex] = {
                    a.x + alpha * (b.x - a.x),
                    a.y + alpha * (b.y - a.y),
                    a.z + alpha * (b.z - a.z)
                };
            } else if (ch.target == AnimTarget::Rotation) {
                if ((int)ch.values.size() < (k + 1) * 4) continue;
                Quat a = { ch.values[k * 4 + 0], ch.values[k * 4 + 1], ch.values[k * 4 + 2], ch.values[k * 4 + 3] };
                Quat b = a;
                if (k < n - 1 && (int)ch.values.size() >= (k + 2) * 4) {
                    b = { ch.values[(k + 1) * 4 + 0], ch.values[(k + 1) * 4 + 1], ch.values[(k + 1) * 4 + 2], ch.values[(k + 1) * 4 + 3] };
                }
                out.R[ch.boneIndex] = Quat::slerp(a, b, alpha).normalized();
            } else {
                if ((int)ch.values.size() < (k + 1) * 3) continue;
                Vec3f a = { ch.values[k * 3 + 0], ch.values[k * 3 + 1], ch.values[k * 3 + 2] };
                Vec3f b = a;
                if (k < n - 1 && (int)ch.values.size() >= (k + 2) * 3) {
                    b = { ch.values[(k + 1) * 3 + 0], ch.values[(k + 1) * 3 + 1], ch.values[(k + 1) * 3 + 2] };
                }
                out.S[ch.boneIndex] = {
                    a.x + alpha * (b.x - a.x),
                    a.y + alpha * (b.y - a.y),
                    a.z + alpha * (b.z - a.z)
                };
            }
        }
    }

    static void blendPoses(const LocalPose& a, const LocalPose& b, float alpha, LocalPose& out) {
        if (alpha < 0.f) alpha = 0.f;
        if (alpha > 1.f) alpha = 1.f;

        const size_t n = std::min(a.T.size(), b.T.size());
        out.resize(n);
        for (size_t i = 0; i < n; i++) {
            out.T[i] = {
                a.T[i].x + alpha * (b.T[i].x - a.T[i].x),
                a.T[i].y + alpha * (b.T[i].y - a.T[i].y),
                a.T[i].z + alpha * (b.T[i].z - a.T[i].z)
            };
            out.R[i] = Quat::slerp(a.R[i], b.R[i], alpha).normalized();
            out.S[i] = {
                a.S[i].x + alpha * (b.S[i].x - a.S[i].x),
                a.S[i].y + alpha * (b.S[i].y - a.S[i].y),
                a.S[i].z + alpha * (b.S[i].z - a.S[i].z)
            };
        }
    }

    void buildSkinMatricesFromPose(const LocalPose& pose) {
        const int nb = (int)bones.size();
        if (nb <= 0 || (int)pose.T.size() < nb || (int)pose.R.size() < nb || (int)pose.S.size() < nb) return;

        std::vector<Mat4> global(nb);
        for (int i = 0; i < nb; i++) {
            Mat4 local = Mat4::fromTRS(pose.T[i], pose.R[i], pose.S[i]);
            global[i] = (bones[i].parent >= 0) ? global[bones[i].parent] * local : local;
        }

        skinMatrices.resize(nb);
        for (int i = 0; i < nb; i++) {
            skinMatrices[i] = global[i] * bones[i].invBindMatrix;
        }
    }

    // Backward-compatible single-clip update.
    void update(float dt, float speed = 1.f) {
        if (!valid() || animations.empty()) return;
        activeAnim = activeAnim % (int)animations.size();
        if (activeAnim < 0) activeAnim = 0;
        time += dt * speed;

        LocalPose pose;
        evaluateClip(activeAnim, time, pose, true);
        buildSkinMatricesFromPose(pose);
    }
};

// ── AnimationController: per-mesh playback, named clips, crossfades ─────────
struct AnimationController {
    Skeleton* skeleton = nullptr;

    AnimPlayback current;
    AnimPlayback previous;

    bool  fading       = false;
    float fadeTime     = 0.f;
    float fadeDuration = 0.f;

    std::string currentName;

    void stop() {
        current = AnimPlayback{};
        previous = AnimPlayback{};
        fading = false;
        fadeTime = 0.f;
        fadeDuration = 0.f;
        currentName.clear();
    }

    bool valid() const {
        return skeleton && skeleton->valid() && !skeleton->animations.empty();
    }

    bool isPlaying(const std::string& name) const {
        return currentName == name && current.clip >= 0;
    }

    bool play(const std::string& name, bool loop = true, float speed = 1.f) {
        if (!valid()) return false;
        int clip = skeleton->findAnimation(name);
        if (clip < 0) return false;

        current = { clip, 0.f, speed, loop };
        previous = {};
        fading = false;
        fadeTime = 0.f;
        fadeDuration = 0.f;
        currentName = name;
        return true;
    }

    bool playIndex(int clip, bool loop = true, float speed = 1.f) {
        if (!valid() || clip < 0 || clip >= (int)skeleton->animations.size()) return false;
        return play(skeleton->animations[clip].name, loop, speed);
    }

    bool crossFade(const std::string& name, float duration, bool loop = true, float speed = 1.f) {
        if (!valid()) return false;
        int nextClip = skeleton->findAnimation(name);
        if (nextClip < 0) return false;

        // Important: this prevents resetting "walk" every frame while velocity != 0.
        if (current.clip == nextClip && currentName == name) {
            current.speed = speed;
            current.loop = loop;
            return true;
        }

        if (current.clip < 0 || duration <= 1e-5f) {
            return play(name, loop, speed);
        }

        previous = current;
        current = { nextClip, 0.f, speed, loop };
        currentName = name;

        fading = true;
        fadeTime = 0.f;
        fadeDuration = duration;
        return true;
    }

    void update(float dt, float speed = 1.f) {
        if (!valid()) return;

        if (current.clip < 0) {
            playIndex(0);
            if (current.clip < 0) return;
        }

        current.time += dt * current.speed * speed;
        if (fading && previous.clip >= 0) {
            previous.time += dt * previous.speed * speed;
            fadeTime += dt * speed;
        }

        LocalPose currentPose;
        skeleton->evaluateClip(current.clip, current.time, currentPose, current.loop);

        if (fading && previous.clip >= 0 && fadeDuration > 1e-5f && fadeTime < fadeDuration) {
            LocalPose previousPose;
            LocalPose blendedPose;
            skeleton->evaluateClip(previous.clip, previous.time, previousPose, previous.loop);
            const float alpha = fadeTime / fadeDuration;
            Skeleton::blendPoses(previousPose, currentPose, alpha, blendedPose);
            skeleton->buildSkinMatricesFromPose(blendedPose);
        } else {
            fading = false;
            previous = {};
            skeleton->buildSkinMatricesFromPose(currentPose);
        }
    }
};

// ── GLB parsing helpers ──────────────────────────────────────────────────────
namespace AnimParser {

// Read raw float accessor into a vector<float>
static std::vector<float> readFloats(const tinygltf::Model& model, int acc) {
    const auto& a=model.accessors[acc];
    const auto& bv=model.bufferViews[a.bufferView];
    const auto& buf=model.buffers[bv.buffer];
    size_t stride=a.ByteStride(bv);
    int comp=tinygltf::GetNumComponentsInType(a.type);
    if (stride==0) stride=comp*sizeof(float);
    std::vector<float> out; out.reserve(a.count*comp);
    const uint8_t* ptr=buf.data.data()+bv.byteOffset+a.byteOffset;
    for (size_t i=0;i<a.count;i++) {
        const float* f=reinterpret_cast<const float*>(ptr+i*stride);
        for (int c=0;c<comp;c++) out.push_back(f[c]);
    }
    return out;
}

static std::vector<uint16_t> readJoints(const tinygltf::Model& model, int acc) {
    const auto& a  = model.accessors[acc];
    const auto& bv = model.bufferViews[a.bufferView];
    const auto& buf = model.buffers[bv.buffer];

    int comp = tinygltf::GetNumComponentsInType(a.type);
    size_t elemSize = 0;

    if (a.componentType == TINYGLTF_COMPONENT_TYPE_UNSIGNED_BYTE) {
        elemSize = 1;
    } else if (a.componentType == TINYGLTF_COMPONENT_TYPE_UNSIGNED_SHORT) {
        elemSize = 2;
    } else {
        std::cerr << "[AnimParser] Unsupported JOINTS_0 component type: "
                  << a.componentType << "\n";
        return {};
    }

    size_t stride = a.ByteStride(bv);
    if (stride == 0) stride = comp * elemSize;

    std::vector<uint16_t> out;
    out.reserve(a.count * comp);

    const uint8_t* ptr = buf.data.data() + bv.byteOffset + a.byteOffset;

    for (size_t i = 0; i < a.count; i++) {
        const uint8_t* p = ptr + i * stride;

        for (int c = 0; c < comp; c++) {
            if (a.componentType == TINYGLTF_COMPONENT_TYPE_UNSIGNED_BYTE) {
                out.push_back((uint16_t)p[c]);
            } else {
                const uint16_t* u = reinterpret_cast<const uint16_t*>(p);
                out.push_back(u[c]);
            }
        }
    }

    return out;
}

// Parse skeleton + animations from a loaded tinygltf::Model
// Returns false if no skin found.
static bool parse(const tinygltf::Model& model, Skeleton& skel,
                  std::vector<SkinVertex>& skinVerts)
{
    if (model.skins.empty()) return false;
    const auto& skin = model.skins[0];
    int nb = (int)skin.joints.size();
    skel.bones.resize(nb);

    // Build node→bone index map
    std::unordered_map<int,int> nodeToBone;
    for (int i=0;i<nb;i++) nodeToBone[skin.joints[i]]=i;

    // Inverse bind matrices
    std::vector<float> ibm;
    if (skin.inverseBindMatrices>=0) ibm=readFloats(model,skin.inverseBindMatrices);

    for (int i=0;i<nb;i++) {
        int nodeIdx=skin.joints[i];
        const auto& node=model.nodes[nodeIdx];
        skel.bones[i].name=node.name;
        // Parent
        skel.bones[i].parent=-1;
        for (int j=0;j<nb;j++) {
            const auto& pn=model.nodes[skin.joints[j]];
            for (int ch:pn.children) if (ch==nodeIdx) skel.bones[i].parent=j;
        }
        // Rest pose
        if (!node.translation.empty()) skel.bones[i].restT={float(node.translation[0]),float(node.translation[1]),float(node.translation[2])};
        if (!node.rotation.empty())    skel.bones[i].restR={float(node.rotation[0]),float(node.rotation[1]),float(node.rotation[2]),float(node.rotation[3])};
        if (!node.scale.empty())       skel.bones[i].restS={float(node.scale[0]),float(node.scale[1]),float(node.scale[2])};
        // Inv bind
        if (ibm.size()>=size_t((i+1)*16)) {
            const float* src=&ibm[i*16];
            for (int r=0;r<4;r++) for (int c=0;c<4;c++)
                skel.bones[i].invBindMatrix.m[r][c]=src[r+c*4]; // column-major
        }
    }

    // Skin vertex data — find JOINTS_0 / WEIGHTS_0 in first skinned primitive
    skinVerts.clear();

    for (const auto& mesh : model.meshes) {
        for (const auto& prim : mesh.primitives) {
            auto jit = prim.attributes.find("JOINTS_0");
            auto wit = prim.attributes.find("WEIGHTS_0");
            auto pit = prim.attributes.find("POSITION");

            if (pit == prim.attributes.end()) continue;

            const auto& posAcc = model.accessors[pit->second];
            uint32_t vertexCount = (uint32_t)posAcc.count;

            size_t base = skinVerts.size();
            skinVerts.resize(base + vertexCount);

            for (uint32_t i = 0; i < vertexCount; i++) {
                skinVerts[base + i] = {{0,0,0,0}, {1,0,0,0}};
            }

            if (jit == prim.attributes.end() || wit == prim.attributes.end())
                continue;

            auto joints  = readJoints(model, jit->second);
            auto weights = readFloats(model, wit->second);

            uint32_t vcount = std::min(vertexCount, (uint32_t)(joints.size() / 4));

            for (uint32_t v = 0; v < vcount; v++) {
                SkinVertex& sv = skinVerts[base + v];

                sv.joints[0] = joints[v * 4 + 0];
                sv.joints[1] = joints[v * 4 + 1];
                sv.joints[2] = joints[v * 4 + 2];
                sv.joints[3] = joints[v * 4 + 3];

                sv.weights[0] = weights[v * 4 + 0];
                sv.weights[1] = weights[v * 4 + 1];
                sv.weights[2] = weights[v * 4 + 2];
                sv.weights[3] = weights[v * 4 + 3];
            }
        }
    }

    // Animations: keep every GLB clip and index it by name for selective triggering.
    skel.animations.clear();
    skel.animationByName.clear();

    int unnamedIndex = 0;
    for (const auto& anim : model.animations) {
        Animation a;
        a.name = anim.name.empty()
            ? ("Animation_" + std::to_string(unnamedIndex++))
            : anim.name;

        for (const auto& ch : anim.channels) {
            auto it = nodeToBone.find(ch.target_node);
            if (it == nodeToBone.end()) continue;
            if (ch.sampler < 0 || ch.sampler >= (int)anim.samplers.size()) continue;

            const auto& samp = anim.samplers[ch.sampler];
            if (!samp.interpolation.empty() &&
                samp.interpolation != "LINEAR" &&
                samp.interpolation != "STEP") {
                std::cerr << "[AnimParser] Animation '" << a.name
                          << "' uses unsupported interpolation '" << samp.interpolation
                          << "'. Falling back to linear sampling.\n";
            }

            AnimChannel ac;
            ac.boneIndex = it->second;
            if (samp.interpolation == "STEP") ac.interpolation = AnimInterpolation::Step;
            ac.times = readFloats(model, samp.input);
            ac.values = readFloats(model, samp.output);
            if (!ac.times.empty()) a.duration = std::max(a.duration, ac.times.back());

            if      (ch.target_path == "translation") ac.target = AnimTarget::Translation;
            else if (ch.target_path == "rotation")    ac.target = AnimTarget::Rotation;
            else if (ch.target_path == "scale")       ac.target = AnimTarget::Scale;
            else continue;

            a.channels.push_back(std::move(ac));
        }

        // Ensure duplicate/empty names do not overwrite each other in the map.
        std::string baseName = a.name.empty() ? ("Animation_" + std::to_string(unnamedIndex++)) : a.name;
        std::string finalName = baseName;
        int suffix = 1;
        while (skel.animationByName.find(finalName) != skel.animationByName.end()) {
            finalName = baseName + "_" + std::to_string(suffix++);
        }
        a.name = finalName;

        const int index = (int)skel.animations.size();
        skel.animationByName[a.name] = index;
        skel.animations.push_back(std::move(a));
    }

    if (!skel.animations.empty()) {
        std::cout << "[AnimParser] animations parsed:";
        for (const Animation& a : skel.animations) {
            std::cout << " " << a.name << "(" << a.duration << "s)";
        }
        std::cout << "\n";
    }

    return true;
}

} // namespace AnimParser