#include "InputHandler.h"

InputHandler::InputHandler()
    : m_mouseDeltaX(0.0f), 
      m_mouseDeltaY(0.0f)
{
    // Zero-initialise both state arrays (already done by default member init,
    // but explicit here for clarity).
    for (int i = 0; i < N; ++i)
        m_curr[i] = m_prev[i] = false;
}

void InputHandler::update(HWND hwnd, bool paused, bool editorMode)
{
    bool focused = (GetForegroundWindow() == hwnd);

    auto updateKeyboardStates = [&](bool allowGameplayInput) {
        for (int i = 0; i < N; ++i) {
            const Action action = static_cast<Action>(i);
            m_prev[i] = m_curr[i];

            if (!focused) {
                m_curr[i] = false;
            } else if (action == Action::Escape) {
                m_curr[i] = pollAction(action);
            } else {
                m_curr[i] = allowGameplayInput ? pollAction(action) : false;
            }
        }
    };

    // Do not capture mouse while unfocused or paused. During pause, keep only
    // Escape live so normal menu toggling cannot leave movement keys stuck.
    if (!focused || paused) {
        if (m_windowFocused) {
            ShowCursor(TRUE);
            m_windowFocused = false;
        }

        m_mouseDeltaX = 0.0f;
        m_mouseDeltaY = 0.0f;
        updateKeyboardStates(false);

        m_firstFrame = true;
        m_editorMouseInitialized = false;
        return;
    }

    if (editorMode) {
        // Editor mode never locks/hides the cursor. Gameplay-style input is
        // only active while RMB is held; Escape remains usable at all times.
        if (m_windowFocused) {
            ShowCursor(TRUE);
            m_windowFocused = false;
        }

        const bool rightMouseDown = (GetAsyncKeyState(VK_RBUTTON) & 0x8000) != 0;
        POINT currentPos{};
        GetCursorPos(&currentPos);

        if (rightMouseDown) {
            if (!m_editorMouseInitialized) {
                m_mouseDeltaX = 0.0f;
                m_mouseDeltaY = 0.0f;
                m_editorMouseInitialized = true;
            } else {
                m_mouseDeltaX = static_cast<float>(currentPos.x - m_lastEditorMousePos.x);
                m_mouseDeltaY = static_cast<float>(currentPos.y - m_lastEditorMousePos.y);
            }
            m_lastEditorMousePos = currentPos;
        } else {
            m_mouseDeltaX = 0.0f;
            m_mouseDeltaY = 0.0f;
            m_lastEditorMousePos = currentPos;
            m_editorMouseInitialized = false;
        }

        updateKeyboardStates(rightMouseDown);
        m_firstFrame = true;
        return;
    }

    m_editorMouseInitialized = false;

    if (!m_windowFocused) {
        ShowCursor(FALSE);
        m_windowFocused = true;
        m_firstFrame = true;
    }

    int centerX = GetSystemMetrics(SM_CXSCREEN) / 2;
    int centerY = GetSystemMetrics(SM_CYSCREEN) / 2;

    if (m_firstFrame) {
        SetCursorPos(centerX, centerY);
        m_mouseDeltaX = 0.0f;
        m_mouseDeltaY = 0.0f;
        m_firstFrame = false;

        updateKeyboardStates(true);
        return;
    }

    POINT currentPos;
    GetCursorPos(&currentPos);

    m_mouseDeltaX = static_cast<float>(currentPos.x - centerX);
    m_mouseDeltaY = static_cast<float>(currentPos.y - centerY);

    SetCursorPos(centerX, centerY);

    updateKeyboardStates(true);
}

bool InputHandler::isDown(Action a)     const { return m_curr[static_cast<int>(a)]; }
bool InputHandler::isPressed(Action a)  const { return  m_curr[static_cast<int>(a)] && !m_prev[static_cast<int>(a)]; }
bool InputHandler::isReleased(Action a) const { return !m_curr[static_cast<int>(a)] &&  m_prev[static_cast<int>(a)]; }

// --- Private ----------------------------------------------------------------

bool InputHandler::poll(int vk)
{
    // High-order bit set = key is down.
    return (GetAsyncKeyState(vk) & 0x8000) != 0;
}

bool InputHandler::pollAction(Action a)
{
    switch (a)
    {
        case Action::MoveForward:   return poll('W') || poll(VK_UP);
        case Action::MoveBackward:  return poll('S') || poll(VK_DOWN);
        case Action::StrafeLeft:    return poll('A');
        case Action::StrafeRight:   return poll('D');
        case Action::Sprint:        return poll(VK_SHIFT);
        case Action::Crouch:        return poll(VK_CONTROL);
        case Action::Up:   return poll(VK_SPACE);
        case Action::TurnLeft:      return poll(VK_LEFT)  || poll('Q');
        case Action::TurnRight:     return poll(VK_RIGHT) || poll('E');
        case Action::Escape:          return poll(VK_ESCAPE);
        case Action::Space:          return poll(VK_SPACE);
        default:                    return false;
    }
}
