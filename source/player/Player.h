#pragma once
#include "Vec2f.h"
#include "Vec3f.h"
#include "Triangle.h"
#include "Mesh.h"
#include "Mat3.h"

class Map;
class InputHandler;

// ---------------------------------------------------------------------------
// Player
//
// World position is now 3-D:
//   pos.x / pos.y  — tile coordinates (same as before, used by DDA)
//   pos.z          — camera height in world units (0 = floor level)
//
// Orientation:
//   dir            — unit XY look direction (unchanged, drives DDA)
//   plane          — camera XY plane vector (unchanged, drives DDA)
//   pitch          — vertical tilt in radians; 0 = level, + = up, - = down
//                    Clamped to ±MAX_PITCH so you can never flip upside-down.
//
// The raycaster reads pos.xy(), dir, and plane exactly as before.
// The renderer additionally reads pos.z and pitch to shift the horizon and
// apply a vertical ray angle for height-aware rendering.
// ---------------------------------------------------------------------------

class Player
{
public:
    // -----------------------------------------------------------------------
    // Tuning constants
    // -----------------------------------------------------------------------
    static constexpr float ContactOffsetHorizontal   = 0.3f;
    static constexpr float ContactOffsetVertical   = 0.02f;

    static constexpr bool FLY  = false;

    static constexpr float MoveSpeedFront   = 3.0f;
    static constexpr float MoveSpeedBack    = 1.5f;
    static constexpr float MoveSpeedStrafe  = 2.0f;


    static constexpr float CrouchSpeedFactor= 50.0f; // in % of speed when crouching
    static constexpr float SprintSpeedFactor= 300.0f; // in % of speed when sprinting

    static constexpr float SprintFOVFactor  = 100.0f; // in % of fov when sprinting

    static constexpr float CrouchHeightFactor = 75.0f; // in % of normal height when crouching


    static constexpr float RotSpeed         = 2.0f;   // radians per second
    static constexpr float PitchSpeed       = 1.5f;   // radians per second


    static constexpr float Height = 1.85f - 0.25f;       // camera height in world units (0 = floor level) | adjust for half screen height (1.0f)
    static constexpr float Gravity = 9.8f;      // gravity strength for jumping/falling (units/s^2)
    static constexpr float Weight = 65.0f;       // player weight for physics interactions (kg)

    static constexpr float MaxStepHeight = 50.0f; // maximum height of climbable surfaces (% of player height)

    static constexpr Vec3f MESH_OFFSET = { 0, 0, 0};
    static constexpr Vec3f MESH_SCALE = { 1.8, 1.9, 0.65};
    //static constexpr float MAX_PITCH   = 1.2f;   // ~69 degrees up/down

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------
    Player() = default;
    Player(Vec3f pos,
           Vec3f initialDir = { 1.0f, 0.0f, 0.0f },
           float planeLen   = 0.66f);

    // -----------------------------------------------------------------------
    // Per-frame update
    // -----------------------------------------------------------------------
    void update(float dt, const InputHandler& input, const Map& map, bool move = true);

    void setFlyEnabled(bool enabled);
    bool isFlyEnabled() const { return m_flyEnabled; }

    // -----------------------------------------------------------------------
    // Accessors — 2-D subset (used by existing raycaster code, unchanged)
    // -----------------------------------------------------------------------
    Vec3f getPos()   const;   // XY tile position
    Vec3f getDir()   const;   // XY unit direction

    // -----------------------------------------------------------------------
    // Fine-grained controls (also used by future AI / cutscenes)
    // -----------------------------------------------------------------------
    void moveForward (float speed, const Map& map);
    void moveBackward(float speed, const Map& map);
    void strafeLeft  (float speed, const Map& map);
    void strafeRight (float speed, const Map& map);
    void rotate(float angle);          // yaw  — positive = left / CCW
    void tilt(float angle);            // pitch — positive = up

    void fall(float dt, const Map& map);

    Vec3f m_plane;
    Vec3f m_plane_up = Vec3f{0, 1, 0};

    void setSpawn(Vec3f pos, Vec3f dir, float fov = 0.66f);
    void setPosition(Vec3f pos);

    float height;

    float speedFactor;

    Vec3f m_velocity{0.0f, 0.0f, 0.0f};



    Mesh* mesh;

    bool light_on = true;

    static constexpr float LIGHT_INTENSITY = 50;
    static constexpr float LIGHT_ANGLE = 8;
    static constexpr Vec3f LIGHT_COLOR = {0.65f, 0.82f, 1.0f};
    static constexpr Vec3f LIGHT_OFFSET = {0.15f, 0.0f, 0.0f};

private:
    // XY position and orientation (keep Vec2f types so DDA code is untouched)

    bool m_flyEnabled = FLY;

    Vec3f m_pos;
    Vec3f m_dir;
    float m_fov;

    float m_yaw = 0.0f;
    float m_pitch = 0.0f;

    //accelerated fall
    float m_fallTime = 0.f;
    float m_verticalVelocity = 0.f;
    bool m_grounded = false;
    // Helpers
    static Vec3f perp(Vec3f v);
    
    void rebuildCameraBasis();

    void tryMove(Vec3f newPos, float speed, const Map& map);
};
