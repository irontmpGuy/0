#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// ---------------------------------------------------------------------------
// InputHandler
// Per-frame keyboard snapshot using GetAsyncKeyState (Windows only).
//
// Usage:
//   InputHandler input;
//   // each frame:
//   input.update();
//   if (input.isDown(Action::MoveForward)) { ... }
//
// When a windowing library is added later, replace update() internals only —
// the Action enum and isDown/isPressed interface stay identical.
// ---------------------------------------------------------------------------

class InputHandler
{
public:
    enum class Action
    {
        MoveForward,
        MoveBackward,
        StrafeLeft,
        StrafeRight,
        TurnLeft,
        TurnRight,
        Sprint,
        Crouch,
        Up,
        Escape,
        Space,

        COUNT   // keep last — used for array sizing
    };

    InputHandler();

    // Call once per frame before reading any state.
    void update(HWND hwnd, bool paused, bool editorMode = false); 

    // True every frame the key is held down.
    bool isDown(Action a)     const;

    // True only on the frame the key first went down.
    bool isPressed(Action a)  const;

    // True only on the frame the key was released.
    bool isReleased(Action a) const;

    float getMouseDeltaX() const { return m_mouseDeltaX; }
    float getMouseDeltaY() const { return m_mouseDeltaY; }

private:
    static constexpr int N = static_cast<int>(Action::COUNT);

    bool m_curr[N] = {};    // state this frame
    bool m_prev[N] = {};    // state last frame

    // Returns true if the virtual key is currently held.
    static bool poll(int vk);

    // Maps each Action to its virtual key code(s).
    // Returns true if ANY of the bound keys for that action are held.
    static bool pollAction(Action a);

    float m_mouseDeltaX = 0.0f;
    float m_mouseDeltaY = 0.0f;
    bool m_windowFocused = false;

    bool m_firstFrame = true;
    bool m_editorMouseInitialized = false;
    POINT m_lastEditorMousePos{};
};
