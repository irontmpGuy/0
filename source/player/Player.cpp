#include "Player.h"
#include "Map.h"
#include "InputHandler.h"
#include <algorithm>   // std::clamp

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------
Player::Player(Vec3f pos, Vec3f initialDir, float fov)
    : m_pos(pos)
    , m_dir(initialDir.normalized())
    , m_fov(fov)
    , m_plane(perp(initialDir.normalized()) * m_fov)
    , m_pitch(0.f)
    , m_grounded(false)
    , m_verticalVelocity(0.0f)
    , speedFactor(1.0f)
    , height(Height)
{
    std::cout << "[Player] Spawned at (" << pos.x << ", " << pos.y << ", " << pos.z 
              << ") facing (" << m_dir.x << ", " << m_dir.y << ")" << std::endl;
}

void Player::setSpawn(Vec3f pos, Vec3f dir, float fov) {
    m_pos   = pos;
    m_dir   = dir.normalized();
    m_fov = fov;
    m_plane = perp(dir.normalized()) * m_fov;
}

void Player::setPosition(Vec3f pos) {
    m_pos = pos;
    m_velocity = {0.0f, 0.0f, 0.0f};
    m_verticalVelocity = 0.0f;
    m_grounded = false;
}

// ---------------------------------------------------------------------------
// Per-frame update
// ---------------------------------------------------------------------------
void Player::update(float dt, const InputHandler& input, const Map& map, bool move)
{
    Vec3f oldPos = m_pos;
    const bool fly = m_flyEnabled;

    if (!fly) fall(dt, map);

    if (move) {
        using A = InputHandler::Action;

        // --- Horizontal movement -----------------------------------------------
        if (input.isDown(A::MoveForward))  moveForward (MoveSpeedFront * dt, map);
        if (input.isDown(A::MoveBackward)) moveBackward(MoveSpeedBack * dt, map);
        if (input.isDown(A::StrafeLeft))   strafeLeft  (MoveSpeedStrafe * dt, map);
        if (input.isDown(A::StrafeRight))  strafeRight (MoveSpeedStrafe * dt, map);

        if (input.isDown(A::Sprint)) { speedFactor = SprintSpeedFactor / 100.0f; m_plane = ( m_plane/m_fov ) * ( m_fov * (SprintFOVFactor / 100.0f) );}
        if (input.isDown(A::Crouch)) { speedFactor = CrouchSpeedFactor / 100.0f; height = Height * CrouchHeightFactor / 100.0f; if (fly) m_pos.y -= 0.1f;}

        if (input.isReleased(A::Sprint)) { speedFactor = 1.0f; m_plane = perp(m_dir.normalized()) * m_fov;}
        if (input.isReleased(A::Crouch)) { speedFactor = 1.0f; height = Height;}

        if (input.isDown(A::Up)) if (fly) m_pos.y += 0.1f;
        // --- Yaw (keyboard) ----------------------------------------------------
        if (input.isDown(A::TurnLeft))  rotate( RotSpeed * dt);
        if (input.isDown(A::TurnRight)) rotate(-RotSpeed * dt);

        if (input.isDown(A::Space)) light_on = true;
        if (input.isReleased(A::Space)) light_on = false;

        // --- Mouse look --------------------------------------------------------
        float mX = input.getMouseDeltaX();

        if (mX != 0.f)
            rotate(mX * 0.002f);           // yaw

        float mY = input.getMouseDeltaY();
        if (mY != 0.f)
            tilt(-mY * 0.002f);             // pitch (inverted: mouse up = look up)

        if (mesh)
            mesh->rot = Mat3::fromYawDirection(m_dir);
    }
    
    if (dt > 0.0f)
        m_velocity = (m_pos - oldPos) / dt;
    else
        m_velocity = {0.0f, 0.0f, 0.0f};
}


void Player::setFlyEnabled(bool enabled)
{
    if (m_flyEnabled == enabled) return;
    m_flyEnabled = enabled;

    // When entering/leaving editor fly mode, kill accumulated gravity so the
    // player does not suddenly snap/fall with old vertical velocity.
    m_verticalVelocity = 0.0f;
    m_grounded = enabled ? false : m_grounded;
}


Vec3f Player::getDir()   const { return m_dir;   }

Vec3f Player::getPos() const { return m_pos; }

// ---------------------------------------------------------------------------
// controls
// ---------------------------------------------------------------------------
void Player::moveForward (float speed, const Map& map) { tryMove(Vec3f{m_dir.x, m_dir.y, m_dir.z}.normalized(), speed * speedFactor, map); }
void Player::moveBackward(float speed, const Map& map) { tryMove(Vec3f{m_dir.x, m_dir.y, m_dir.z}.normalized() * -1.0f, speed * speedFactor, map); }
void Player::strafeLeft  (float speed, const Map& map) { tryMove(perp(Vec3f{m_dir.x, m_dir.y, m_dir.z}.normalized() * -1.0f), speed * speedFactor, map); }
void Player::strafeRight (float speed, const Map& map) { tryMove(perp(Vec3f{m_dir.x, m_dir.y, m_dir.z}.normalized()), speed * speedFactor, map); }

void Player::rotate(float angle)
{
    m_dir   = m_dir.rotatedY(-angle);
    m_plane = m_plane.rotatedY(-angle);   // must stay in sync
}

void Player::tilt(float angle) {
    // 1. Update the pitch value and clamp it
    m_pitch = std::clamp(m_pitch + angle, -1.5f, 1.5f);

    // 2. Rebuild the Direction vector from the pitch and current horizontal heading
    // We get the horizontal direction by ignoring Y and normalizing
    Vec3f horizontalDir = Vec3f{m_dir.x, 0, m_dir.z}.normalized();
    
    // The 'Right' vector is always horizontal and perpendicular to the heading
    Vec3f right = perp(horizontalDir).normalized();

    // 3. Rotate the horizontal direction around the 'Right' axis by the total pitch
    // Tip: Use the original horizontal direction as the base to prevent "drift"
    m_dir = horizontalDir.rotatedAroundAxis(right, m_pitch).normalized();

    // 4. Rebuild Plane_Up and Plane to be perfectly square
    // m_plane_up should be perpendicular to both Dir and Right
    m_plane_up = m_dir.cross(right).normalized() * -1; 
    
    // m_plane (horizontal FOV) should be 'right' scaled by FOV
    m_plane = right * m_fov;
}

void Player::fall(float dt, const Map& map) {
    m_verticalVelocity -= Gravity * dt;
    float moveY = m_verticalVelocity * dt;
    
    Vec3f diff = { 0, moveY, 0 };
    float planeY = std::nanf("");

    float distance = 0.f;

    if (m_grounded) {
        if (map.collides({0, -ContactOffsetVertical - 1e-6f, 0}, m_pos)) {
            m_verticalVelocity = 0.0f;
            return;
        }
    }

    if (map.collides(diff, m_pos, &distance, &planeY)) {
        if (!std::isnan(planeY) && planeY <= m_pos.y) {
            m_pos.y = planeY + ContactOffsetVertical;
            m_verticalVelocity = 0.0f;
            m_grounded = true;
            return; 
        }
    }

    // If it was a wall (planeY > m_pos.y) or no collision at all:
    m_pos.y += moveY;
    m_grounded = false;
}
//------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------
Vec3f Player::perp(Vec3f v) { return { -v.z, 0, v.x }; }

void Player::tryMove(Vec3f moveDir, float speed, const Map& map) {
    Vec3f newPos = m_pos + moveDir * speed;
    if (m_flyEnabled) { m_pos = newPos; return; }
    float stepHeight = height * MaxStepHeight / 100.0f; // 10% of player height
    float planeY = std::nanf("");
    float distance = 0.f;

    Vec3f checkX = { (moveDir * speed).x, 0, 0 };
    if (moveDir.x > 0) checkX.x += ContactOffsetHorizontal;
    else if (moveDir.x < 0) checkX.x -= ContactOffsetHorizontal;

    Vec3f checkZ = { 0, 0, (moveDir * speed).z };
    if (moveDir.z > 0) checkZ.z += ContactOffsetHorizontal;
    else if (moveDir.z < 0) checkZ.z -= ContactOffsetHorizontal;

    // mid and head: simple block — if either hits, no X movement at all
    Vec3f midPos  = { m_pos.x, m_pos.y + height * 0.5f, m_pos.z };
    Vec3f headPos = { m_pos.x, m_pos.y + height,         m_pos.z };
    bool midBlockX  = map.collides(checkX, midPos);
    bool headBlockX = map.collides(checkX, headPos);

    if (!midBlockX && !headBlockX) {
        if (map.collides(checkX, m_pos, &distance, &planeY)) {
            checkX = { (moveDir * speed).x, 0, 0 };
            if (!std::isnan(planeY) && m_grounded) {
                if (planeY + ContactOffsetVertical <= m_pos.y) {
                    m_pos.x = newPos.x; // It's a drop, allow moving off the edge
                } else {
                    // Let guy step up
                    float newPlaneY = std::nanf("");
                    Plane* p = nullptr;
                    if (map.collides(checkX, m_pos, &distance, &newPlaneY, &p)) { // check at actual move distance, not just contact offset
                        if (!std::isnan(newPlaneY) && p && newPlaneY - m_pos.y <= stepHeight) {
                            if (moveDir.dot2D(p->normal) <= 0) { // only step up if we're moving towards the plane, not away from it
                                m_pos = { newPos.x, (newPlaneY + ContactOffsetVertical), m_pos.z };
                            }
                        } else if (!std::isnan(newPlaneY) && newPlaneY - m_pos.y <= stepHeight) {
                            m_pos = { newPos.x, (newPlaneY + ContactOffsetVertical), m_pos.z };
                        }
                    } else if (planeY - m_pos.y <= stepHeight) {
                        m_pos.x = newPos.x;
                    }
                }
            }
        } else { m_pos.x = newPos.x; }
    }

    planeY = std::nanf("");

    bool midBlockZ  = map.collides(checkZ, midPos);
    bool headBlockZ = map.collides(checkZ, headPos);

    if (!midBlockZ && !headBlockZ) {
        if (map.collides(checkZ, m_pos, &distance, &planeY)) {
            checkZ = { 0, 0, (moveDir * speed).z };
            if (!std::isnan(planeY) && m_grounded) {
                if (planeY + ContactOffsetVertical <= m_pos.y) {
                    m_pos.z = newPos.z; // It's a drop, allow moving off the edge
                } else {
                    // Let guy step up
                    float newPlaneY = std::nanf("");
                    Plane* p = nullptr;
                    if (map.collides(checkZ, m_pos, &distance, &newPlaneY, &p)) { // check at actual move distance, not just contact offset
                        if (!std::isnan(newPlaneY) && p && newPlaneY - m_pos.y <= stepHeight) {
                            if (moveDir.dot2D(p->normal) <= 0) { // only step up if we're moving towards the plane, not away from it
                                m_pos = { m_pos.x, (newPlaneY + ContactOffsetVertical), newPos.z };
                            }
                        } else if (!std::isnan(newPlaneY) && newPlaneY - m_pos.y <= stepHeight) {
                            m_pos = { m_pos.x, (newPlaneY + ContactOffsetVertical), newPos.z };
                        }
                    } else if (planeY - m_pos.y <= stepHeight) {
                        m_pos.z = newPos.z;
                    }
                }
            }
        } else { m_pos.z = newPos.z; }
    }
}