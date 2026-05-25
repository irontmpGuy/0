#include "MapEditorOverlay.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <commdlg.h>
#include <commctrl.h>

#ifdef _MSC_VER
#pragma comment(lib, "Comdlg32.lib")
#pragma comment(lib, "Comctl32.lib")
#endif

namespace {
constexpr uint32_t C_BUTTON     = 0xFF4A4A4Au;
constexpr uint32_t C_BUTTON_ON  = 0xFF2E7D32u;
constexpr uint32_t C_BOX        = 0xFFE6E6E6u;
constexpr uint32_t C_BOX_DARK   = 0xFF202020u;
constexpr uint32_t C_TEXT       = 0xFFFFFFFFu;

constexpr int TOGGLE_X = 32;
constexpr int TOGGLE_Y = 32;
constexpr int TOGGLE_W = 168;
constexpr int TOGGLE_H = 36;

static const char* glyphRows(char c, int row)
{
    static const char* blank[7] = {"00000","00000","00000","00000","00000","00000","00000"};
    static const char* A[7] = {"01110","10001","10001","11111","10001","10001","10001"};
    static const char* B[7] = {"11110","10001","10001","11110","10001","10001","11110"};
    static const char* C[7] = {"01111","10000","10000","10000","10000","10000","01111"};
    static const char* D[7] = {"11110","10001","10001","10001","10001","10001","11110"};
    static const char* E[7] = {"11111","10000","10000","11110","10000","10000","11111"};
    static const char* F[7] = {"11111","10000","10000","11110","10000","10000","10000"};
    static const char* G[7] = {"01111","10000","10000","10111","10001","10001","01111"};
    static const char* H[7] = {"10001","10001","10001","11111","10001","10001","10001"};
    static const char* I[7] = {"11111","00100","00100","00100","00100","00100","11111"};
    static const char* J[7] = {"00111","00010","00010","00010","10010","10010","01100"};
    static const char* K[7] = {"10001","10010","10100","11000","10100","10010","10001"};
    static const char* L[7] = {"10000","10000","10000","10000","10000","10000","11111"};
    static const char* M[7] = {"10001","11011","10101","10101","10001","10001","10001"};
    static const char* N[7] = {"10001","11001","10101","10011","10001","10001","10001"};
    static const char* O[7] = {"01110","10001","10001","10001","10001","10001","01110"};
    static const char* P[7] = {"11110","10001","10001","11110","10000","10000","10000"};
    static const char* Q[7] = {"01110","10001","10001","10001","10101","10010","01101"};
    static const char* R[7] = {"11110","10001","10001","11110","10100","10010","10001"};
    static const char* S[7] = {"01111","10000","10000","01110","00001","00001","11110"};
    static const char* T[7] = {"11111","00100","00100","00100","00100","00100","00100"};
    static const char* U[7] = {"10001","10001","10001","10001","10001","10001","01110"};
    static const char* V[7] = {"10001","10001","10001","10001","10001","01010","00100"};
    static const char* W[7] = {"10001","10001","10001","10101","10101","10101","01010"};
    static const char* X[7] = {"10001","10001","01010","00100","01010","10001","10001"};
    static const char* Y[7] = {"10001","10001","01010","00100","00100","00100","00100"};
    static const char* Z[7] = {"11111","00001","00010","00100","01000","10000","11111"};
    const char* const* g = blank;
    if (c >= 'a' && c <= 'z') c = char(c - 'a' + 'A');
    switch (c) {
    case 'A': g = A; break; case 'B': g = B; break; case 'C': g = C; break; case 'D': g = D; break;
    case 'E': g = E; break; case 'F': g = F; break; case 'G': g = G; break; case 'H': g = H; break;
    case 'I': g = I; break; case 'J': g = J; break; case 'K': g = K; break; case 'L': g = L; break;
    case 'M': g = M; break; case 'N': g = N; break; case 'O': g = O; break; case 'P': g = P; break;
    case 'Q': g = Q; break; case 'R': g = R; break; case 'S': g = S; break; case 'T': g = T; break;
    case 'U': g = U; break; case 'V': g = V; break; case 'W': g = W; break; case 'X': g = X; break;
    case 'Y': g = Y; break; case 'Z': g = Z; break;
    default: g = blank; break;
    }
    return g[row];
}
}

bool MapEditorOverlay::create(HWND owner)
{
    m_owner = owner;
    return createNativeWindow(owner);
}

void MapEditorOverlay::destroy()
{
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
    if (m_idErrorBrush) {
        DeleteObject(m_idErrorBrush);
        m_idErrorBrush = nullptr;
    }
    m_controlsCreated = false;
    m_sliderBindings.clear();
}


void MapEditorOverlay::keepOnTop(HWND owner)
{
    if (owner) m_owner = owner;
    if (!m_hwnd || !m_editEnabled) return;

    SetWindowPos(m_hwnd,
                 HWND_TOPMOST,
                 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
}

void MapEditorOverlay::setPauseVisible(bool paused, HWND owner)
{
    if (owner) m_owner = owner;
    m_pauseVisible = paused;
    if (m_editEnabled) keepOnTop(owner);
}

void MapEditorOverlay::pumpMessages()
{
    if (!m_hwnd) return;

    // Pump the modeless popup and its child EDIT/COMBOBOX/BUTTON controls.
    // Filtering only by m_hwnd can miss child-control messages on some Win32
    // message loops, so this keeps the native builder responsive even if the
    // main game window pumps only its own HWND.
    MSG msg{};
    while (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE)) {
        if (msg.message == WM_QUIT) {
            PostQuitMessage((int)msg.wParam);
            break;
        }

        if (IsWindow(m_hwnd) && IsDialogMessageA(m_hwnd, &msg)) {
            continue;
        }

        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
}

void MapEditorOverlay::setCurrentPlayerPosition(const Vec3f& playerPos)
{
    m_currentPlayerPos = playerPos;
    applyPendingSpawnAtPlayer();
}

void MapEditorOverlay::setEditEnabled(bool enabled, HWND owner)
{
    if (owner) m_owner = owner;
    if (m_editEnabled == enabled) {
        showNativeWindow(enabled);
        refreshValidationUi();
        if (enabled) keepOnTop(owner ? owner : m_owner);
        return;
    }

    m_editEnabled = enabled;
    showNativeWindow(enabled);
    refreshValidationUi();

    if (enabled) {
        // Opening the builder immediately previews the current field values.
        // The engine supplies the current player position on the next builder
        // tick; then the initial mesh preview is placed there.
        m_spawnAtPlayerPending = true;
        applyPendingSpawnAtPlayer();
        markPreviewDirty();
        keepOnTop(owner ? owner : m_owner);
    } else {
        // Turning Edit off or closing the popup removes the transient preview.
        requestPreviewRemove();
    }
}

bool MapEditorOverlay::createNativeWindow(HWND owner)
{
    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_BAR_CLASSES;
    InitCommonControlsEx(&icc);

    HINSTANCE instance = GetModuleHandleA(nullptr);

    WNDCLASSA wc{};
    wc.lpfnWndProc = MapEditorOverlay::windowProc;
    wc.hInstance = instance;
    wc.lpszClassName = "MapBuilderNativePopup";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    RegisterClassA(&wc);

    m_hwnd = CreateWindowExA(
        WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
        wc.lpszClassName,
        "Map Builder",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        80, 80, 980, 700,
        owner,
        nullptr,
        instance,
        this
    );

    if (!m_hwnd) return false;
    ShowWindow(m_hwnd, SW_HIDE);
    return true;
}

LRESULT CALLBACK MapEditorOverlay::windowProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    MapEditorOverlay* self = nullptr;

    if (msg == WM_NCCREATE) {
        CREATESTRUCTA* cs = reinterpret_cast<CREATESTRUCTA*>(lp);
        self = reinterpret_cast<MapEditorOverlay*>(cs->lpCreateParams);
        SetWindowLongPtrA(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        if (self) self->m_hwnd = hwnd;
    } else {
        self = reinterpret_cast<MapEditorOverlay*>(GetWindowLongPtrA(hwnd, GWLP_USERDATA));
    }

    if (!self) return DefWindowProcA(hwnd, msg, wp, lp);

    switch (msg) {
    case WM_CREATE:
        self->createControls();
        self->setDefaultControlValues();
        return 0;

    case WM_COMMAND:
        self->handleNativeCommand(LOWORD(wp), HIWORD(wp));
        return 0;

    case WM_HSCROLL:
        if (self->handleSliderScroll(wp, (HWND)lp)) return 0;
        break;

    case WM_CTLCOLOREDIT:
        if ((HWND)lp == self->m_objectIdEdit && self->m_objectIdTaken) {
            if (!self->m_idErrorBrush) self->m_idErrorBrush = CreateSolidBrush(RGB(255, 210, 210));
            SetBkColor((HDC)wp, RGB(255, 210, 210));
            SetTextColor((HDC)wp, RGB(120, 0, 0));
            return (LRESULT)self->m_idErrorBrush;
        }
        break;

    case WM_CLOSE:
        self->setEditEnabled(false, self->m_owner);
        return 0;

    case WM_DESTROY:
        self->m_hwnd = nullptr;
        return 0;
    }

    return DefWindowProcA(hwnd, msg, wp, lp);
}

HWND MapEditorOverlay::createLabel(const char* text, int x, int y, int w, int h)
{
    HWND ctrl = CreateWindowExA(0, "STATIC", text,
                               WS_CHILD | WS_VISIBLE,
                               x, y, w, h,
                               m_hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
    if (ctrl && m_font) SendMessageA(ctrl, WM_SETFONT, (WPARAM)m_font, TRUE);
    return ctrl;
}

HWND MapEditorOverlay::createEditBox(int id, int x, int y, int w, int h, const char* text)
{
    HWND ctrl = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", text,
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                               x, y, w, h,
                               m_hwnd, (HMENU)(INT_PTR)id, GetModuleHandleA(nullptr), nullptr);
    if (ctrl && m_font) SendMessageA(ctrl, WM_SETFONT, (WPARAM)m_font, TRUE);
    return ctrl;
}

HWND MapEditorOverlay::createButton(int id, const char* text, int x, int y, int w, int h)
{
    HWND ctrl = CreateWindowExA(0, "BUTTON", text,
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                               x, y, w, h,
                               m_hwnd, (HMENU)(INT_PTR)id, GetModuleHandleA(nullptr), nullptr);
    if (ctrl && m_font) SendMessageA(ctrl, WM_SETFONT, (WPARAM)m_font, TRUE);
    return ctrl;
}

HWND MapEditorOverlay::createCombo(int id, int x, int y, int w, int h, const char* const* values, int count, int selected)
{
    HWND ctrl = CreateWindowExA(0, "COMBOBOX", "",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
                               x, y, w, h,
                               m_hwnd, (HMENU)(INT_PTR)id, GetModuleHandleA(nullptr), nullptr);
    if (ctrl && m_font) SendMessageA(ctrl, WM_SETFONT, (WPARAM)m_font, TRUE);
    for (int i = 0; i < count; ++i) SendMessageA(ctrl, CB_ADDSTRING, 0, (LPARAM)values[i]);
    SendMessageA(ctrl, CB_SETCURSEL, selected, 0);
    return ctrl;
}

HWND MapEditorOverlay::createSliderForEdit(int editId, HWND edit, int x, int y, int w, int h, float stepScale)
{
    if (stepScale <= 0.f) stepScale = 1.f;

    // Sliders are relative nudge controls now. They always rest at the center;
    // moving right adds to the typed value, moving left subtracts from it.
    constexpr int kNudgeRange = 500;
    constexpr int kCenter = 0;

    HWND slider = CreateWindowExA(0, "msctls_trackbar32", "",
                                  WS_CHILD | WS_VISIBLE | WS_TABSTOP | TBS_HORZ | TBS_NOTICKS,
                                  x, y, w, h,
                                  m_hwnd, (HMENU)(INT_PTR)(ID_SLIDER_BASE + editId),
                                  GetModuleHandleA(nullptr), nullptr);
    if (!slider) return nullptr;

    SendMessageA(slider, TBM_SETRANGEMIN, FALSE, (LPARAM)-kNudgeRange);
    SendMessageA(slider, TBM_SETRANGEMAX, TRUE, (LPARAM)kNudgeRange);
    SendMessageA(slider, TBM_SETLINESIZE, 0, 1);
    SendMessageA(slider, TBM_SETPAGESIZE, 0, 10);
    SendMessageA(slider, TBM_SETPOS, TRUE, kCenter);

    m_sliderBindings.push_back({editId, edit, slider, stepScale, kCenter, kCenter, 0});
    return slider;
}

HWND MapEditorOverlay::createAtPlayerButtonForEdit(int editId, HWND edit, int playerAxis, int x, int y, int w, int h)
{
    if (playerAxis < 0) playerAxis = 0;
    if (playerAxis > 2) playerAxis = 2;

    HWND button = createButton(ID_AT_PLAYER_BASE + editId, "At P", x, y, w, h);
    for (SliderBinding& binding : m_sliderBindings) {
        if (binding.editId == editId && binding.edit == edit) {
            binding.playerAxis = playerAxis;
            break;
        }
    }
    return button;
}

void MapEditorOverlay::applyPlayerPositionToEdit(int editId)
{
    for (const SliderBinding& binding : m_sliderBindings) {
        if (binding.editId != editId || !binding.edit) continue;

        const int axis = binding.playerAxis;
        float playerValue = m_currentPlayerPos.x;
        if (axis == 1) playerValue = m_currentPlayerPos.y;
        else if (axis == 2) playerValue = m_currentPlayerPos.z;

        float value = playerValue;

        // Scale fields are semantic extents, not a player-scale value.
        // Pressing "At P" on Scale means: internally set corner1 on that
        // axis to the player's coordinate, then show the required extent
        // from the current Position/corner0 in the editor field.
        if (editId >= ID_SCALE_X && editId <= ID_SCALE_Z) {
            HWND originEdit = m_position[axis];
            const float origin = readFloat(originEdit, 0.f);
            value = playerValue - origin;

            const int type = m_typeCombo ? (int)SendMessageA(m_typeCombo, CB_GETCURSEL, 0, 0) : -1;
            if (type == (int)MapEditObjectType::Plane) {
                // Plane Position remains the plane point/center. Its c1 is
                // reconstructed as position + scale * 0.5, so hitting the
                // player's c1 coordinate requires a doubled displayed extent.
                value *= 2.f;
            }
        }

        char buf[64]{};
        std::snprintf(buf, sizeof(buf), "%.6g", value);
        SetWindowTextA(binding.edit, buf);
        syncSliderFromEdit(binding.edit);
        markPreviewDirty();
        refreshValidationUi();
        return;
    }
}

void MapEditorOverlay::applyPendingSpawnAtPlayer()
{
    if (!m_spawnAtPlayerPending || !m_controlsCreated) return;

    SendMessageA(m_typeCombo, CB_SETCURSEL, (WPARAM)static_cast<int>(MapEditObjectType::Mesh), 0);

    auto setPlayerFloatText = [&](HWND hwnd, float value) {
        char buf[64]{};
        std::snprintf(buf, sizeof(buf), "%.6g", value);
        setWindowTextAString(hwnd, buf);
    };

    setPlayerFloatText(m_position[0], m_currentPlayerPos.x);
    setPlayerFloatText(m_position[1], m_currentPlayerPos.y);
    setPlayerFloatText(m_position[2], m_currentPlayerPos.z);
    syncSliderFromEdit(m_position[0]);
    syncSliderFromEdit(m_position[1]);
    syncSliderFromEdit(m_position[2]);

    m_spawnAtPlayerPending = false;
    markPreviewDirty();
}

void MapEditorOverlay::syncSliderFromEditId(int editId)
{
    for (const SliderBinding& binding : m_sliderBindings) {
        if (binding.editId == editId) {
            syncSliderFromEdit(binding.edit);
            return;
        }
    }
}

void MapEditorOverlay::syncSliderFromEdit(HWND edit)
{
    if (!edit) return;
    for (SliderBinding& binding : m_sliderBindings) {
        if (binding.edit != edit || !binding.slider) continue;
        binding.lastPos = binding.centerPos;
        SendMessageA(binding.slider, TBM_SETPOS, TRUE, binding.centerPos);
        return;
    }
}

void MapEditorOverlay::syncAllSlidersFromEdits()
{
    for (const SliderBinding& binding : m_sliderBindings) {
        syncSliderFromEdit(binding.edit);
    }
}

bool MapEditorOverlay::handleSliderScroll(WPARAM scrollCode, HWND slider)
{
    if (!slider) return false;
    for (SliderBinding& binding : m_sliderBindings) {
        if (binding.slider != slider || !binding.edit) continue;

        const int pos = (int)SendMessageA(slider, TBM_GETPOS, 0, 0);
        const int delta = pos - binding.lastPos;

        if (delta != 0) {
            const float currentValue = readFloat(binding.edit, 0.f);
            const float value = currentValue + ((float)delta / binding.stepScale);

            char buf[64]{};
            std::snprintf(buf, sizeof(buf), "%.6g", value);

            m_syncingSliderText = true;
            SetWindowTextA(binding.edit, buf);
            m_syncingSliderText = false;

            binding.lastPos = pos;
            markPreviewDirty();
            refreshValidationUi();
        }

        const int code = LOWORD(scrollCode);
        if (code == TB_ENDTRACK || code == TB_THUMBPOSITION) {
            binding.lastPos = binding.centerPos;
            SendMessageA(binding.slider, TBM_SETPOS, TRUE, binding.centerPos);
        }

        return true;
    }
    return false;
}

void MapEditorOverlay::createControls()
{
    if (m_controlsCreated) return;
    m_font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    const int lx = 12;
    const int x0 = 104;
    const int fieldW = 58;
    const int sliderW = 170;
    const int atPlayerW = 46;
    const int fieldSliderGap = 4;
    const int atPlayerGap = 4;
    const int groupGap = 10;
    const int groupW = fieldW + fieldSliderGap + sliderW + atPlayerGap + atPlayerW + groupGap;
    const int h = 22;
    int y = 10;

    struct SliderSpec { float stepScale; };
    const SliderSpec worldSpec  {100.f};   // 0.01 units per slider tick
    const SliderSpec colorSpec  {1000.f};  // 0.001 units per slider tick
    const SliderSpec rotSpec    {10.f};    // 0.1 degrees per slider tick
    const SliderSpec scaleSpec  {100.f};   // 0.01 units per slider tick
    const SliderSpec normalSpec {1000.f};  // 0.001 units per slider tick
    const SliderSpec lightSpec  {100.f};   // 0.01 units per slider tick
    const SliderSpec angleSpec  {10.f};    // 0.1 degrees per slider tick

    createLabel("Type", lx, y + 3, 84, h);
    static const char* types[] = {"AABB", "Plane", "Mesh", "Light"};
    m_typeCombo = createCombo(ID_TYPE, x0, y, 160, 250, types, 4, 2);

    y += 30;
    createLabel("Object ID", lx, y + 3, 84, h);
    m_objectIdEdit = createEditBox(ID_OBJECT_ID, x0, y, 170, h, "");
    createButton(ID_CHECK, "Check", x0 + 180, y - 1, 62, h + 2);
    m_idErrorLabel = createLabel("", x0 + 252, y + 3, 170, h);

    y += 30;
    createLabel("Mesh path", lx, y + 3, 84, h);
    m_pathEdit = createEditBox(ID_PATH, x0, y, 285, h, "assets/box.glb");
    createButton(ID_BROWSE_PATH, "Browse...", x0 + 295, y - 1, 84, h + 2);

    y += 30;
    createLabel("Texture", lx, y + 3, 84, h);
    m_textureEdit = createEditBox(ID_TEXTURE, x0, y, 285, h, "");
    createButton(ID_BROWSE_TEXTURE, "Browse...", x0 + 295, y - 1, 84, h + 2);

    auto header = [&](const char* text) {
        y += 32;
        createLabel(text, lx, y + 3, 84, h);
        createLabel("X", x0 + 18, y + 3, 18, h);
        createLabel("Y", x0 + groupW + 18, y + 3, 18, h);
        createLabel("Z", x0 + groupW * 2 + 18, y + 3, 18, h);
        y += 22;
    };

    auto numericField = [&](int id, int x, const char* value, SliderSpec spec, int playerAxis) -> HWND {
        HWND edit = createEditBox(id, x, y, fieldW, h, value);
        const int sliderX = x + fieldW + fieldSliderGap;
        createSliderForEdit(id, edit, sliderX, y + 1, sliderW, h, spec.stepScale);
        createAtPlayerButtonForEdit(id, edit, playerAxis, sliderX + sliderW + atPlayerGap, y - 1, atPlayerW, h + 2);
        return edit;
    };

    auto vecRow = [&](HWND out[3], int firstId, const char* a, const char* b, const char* c, SliderSpec spec) {
        out[0] = numericField(firstId + 0, x0, a, spec, 0);
        out[1] = numericField(firstId + 1, x0 + groupW, b, spec, 1);
        out[2] = numericField(firstId + 2, x0 + groupW * 2, c, spec, 2);
    };

    header("Position");
    vecRow(m_position, ID_POSITION_X, "0", "2", "0", worldSpec);

    y += 30;
    createLabel("Color", lx, y + 3, 84, h);
    vecRow(m_color, ID_COLOR_X, "1", "0.75", "0.35", colorSpec);

    y += 30;
    createLabel("Rotation", lx, y + 3, 84, h);
    vecRow(m_rotation, ID_ROT_X, "0", "0", "0", rotSpec);

    y += 30;
    createLabel("Scale", lx, y + 3, 84, h);
    vecRow(m_scale, ID_SCALE_X, "1", "1", "1", scaleSpec);

    y += 30;
    createLabel("Intensity", lx, y + 3, 84, h);
    m_intensity = numericField(ID_INTENSITY, x0, "4", lightSpec, 0);
    createLabel("Radius", x0 + groupW, y + 3, 60, h);
    m_radius = numericField(ID_RADIUS, x0 + groupW + 62, "10", lightSpec, 0);

    y += 30;
    createLabel("Light normal", lx, y + 3, 84, h);
    vecRow(m_lightNormal, ID_LIGHT_NORMAL_X, "0", "-1", "0", normalSpec);

    y += 30;
    createLabel("Angle", lx, y + 3, 84, h);
    m_lightAngle = numericField(ID_LIGHT_ANGLE, x0, "0", angleSpec, 0);

    y += 36;
    m_createButton = createButton(ID_CREATE, "Create", lx, y, 150, 28);

    y += 44;
    createLabel("Remove ID", lx, y + 3, 84, h);
    m_removeIdEdit = createEditBox(ID_REMOVE_ID, x0, y, 210, h, "");

    y += 32;
    createButton(ID_REMOVE, "Remove ID", lx, y, 120, 28);
    createButton(ID_REMOVE_LAST, "Remove last", lx + 130, y, 120, 28);

    m_controlsCreated = true;
    syncAllSlidersFromEdits();
    refreshValidationUi();
    markPreviewDirty();
}

void MapEditorOverlay::setDefaultControlValues()
{
    if (!m_typeCombo) return;
    SendMessageA(m_typeCombo, CB_SETCURSEL, 2, 0);
    syncAllSlidersFromEdits();
}

void MapEditorOverlay::markPreviewDirty()
{
    if (!m_controlsCreated) return;
    m_previewDirty = true;
}

void MapEditorOverlay::requestPreviewRemove()
{
    if (m_previewActive || m_previewDirty) {
        m_previewRemoveRequested = true;
    }
    m_previewDirty = false;
}

void MapEditorOverlay::handleNativeCommand(int id, int code)
{
    const bool fromBuilderField =
        (id == ID_TYPE || id == ID_OBJECT_ID || id == ID_PATH || id == ID_TEXTURE ||
         (id >= ID_POSITION_X && id <= ID_LIGHT_ANGLE));

    if (m_controlsCreated && fromBuilderField &&
        (code == EN_CHANGE || code == CBN_SELCHANGE)) {
        if (id == ID_OBJECT_ID && code == EN_CHANGE) {
            m_statusText.clear();
        }
        if (!m_syncingSliderText && id >= ID_POSITION_X && id <= ID_LIGHT_ANGLE) {
            syncSliderFromEditId(id);
        }
        markPreviewDirty();
        refreshValidationUi();
    }

    if (code == BN_CLICKED && id >= ID_AT_PLAYER_BASE + ID_POSITION_X && id <= ID_AT_PLAYER_BASE + ID_LIGHT_ANGLE) {
        applyPlayerPositionToEdit(id - ID_AT_PLAYER_BASE);
        return;
    }

    if (code != BN_CLICKED && code != CBN_SELCHANGE) return;

    switch (id) {
    case ID_CREATE:
        if (!createAllowed()) {
            MessageBeep(MB_ICONWARNING);
            break;
        }
        m_addRequested = true;
        requestPreviewRemove();
        break;

    case ID_CHECK:
        m_pendingRemoveId = getWindowTextAString(m_objectIdEdit);
        m_checkRequested = !m_pendingRemoveId.empty();
        if (!m_checkRequested) {
            setStatusText("Enter an ID first");
            MessageBeep(MB_ICONWARNING);
        }
        break;

    case ID_BROWSE_PATH: {
        const std::string selected = openFileDialog(
            m_hwnd,
            "Select mesh/model file",
            "Model files (*.glb;*.gltf;*.obj)\0*.glb;*.gltf;*.obj\0All files (*.*)\0*.*\0"
        );
        if (!selected.empty()) {
            setWindowTextAString(m_pathEdit, selected);
            markPreviewDirty();
        }
        break;
    }

    case ID_BROWSE_TEXTURE: {
        const std::string selected = openFileDialog(
            m_hwnd,
            "Select texture file",
            "Texture files (*.png;*.jpg;*.jpeg;*.bmp;*.tga)\0*.png;*.jpg;*.jpeg;*.bmp;*.tga\0All files (*.*)\0*.*\0"
        );
        if (!selected.empty()) {
            setWindowTextAString(m_textureEdit, selected);
            markPreviewDirty();
        }
        break;
    }

    case ID_REMOVE: {
        m_pendingRemoveId = getWindowTextAString(m_removeIdEdit);
        if (m_pendingRemoveId.empty()) m_pendingRemoveId = m_lastObjectId;
        m_removeRequested = !m_pendingRemoveId.empty();
        break;
    }

    case ID_REMOVE_LAST:
        m_pendingRemoveId = m_lastObjectId;
        if (!m_pendingRemoveId.empty()) {
            setWindowTextAString(m_removeIdEdit, m_pendingRemoveId);
            m_removeRequested = true;
        }
        break;

    default:
        break;
    }
}

void MapEditorOverlay::showNativeWindow(bool show)
{
    if (!m_hwnd) return;

    if (show) {
        ShowWindow(m_hwnd, SW_SHOW);
        SetWindowPos(m_hwnd,
                     HWND_TOPMOST,
                     0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    } else {
        ShowWindow(m_hwnd, SW_HIDE);
    }
}

std::string MapEditorOverlay::getWindowTextAString(HWND hwnd)
{
    if (!hwnd) return {};
    const int len = GetWindowTextLengthA(hwnd);
    if (len <= 0) return {};
    std::string result((size_t)len + 1, '\0');
    GetWindowTextA(hwnd, &result[0], len + 1);
    result.resize((size_t)len);
    return result;
}

void MapEditorOverlay::setWindowTextAString(HWND hwnd, const std::string& value)
{
    if (!hwnd) return;
    SetWindowTextA(hwnd, value.c_str());
}

float MapEditorOverlay::readFloat(HWND hwnd, float fallback)
{
    const std::string s = getWindowTextAString(hwnd);
    if (s.empty()) return fallback;
    char* end = nullptr;
    const float v = std::strtof(s.c_str(), &end);
    if (end == s.c_str()) return fallback;
    if (!std::isfinite(v)) return fallback;
    return v;
}

std::string MapEditorOverlay::openFileDialog(HWND owner, const char* title, const char* filter)
{
    char fileName[MAX_PATH]{};
    OPENFILENAMEA ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = sizeof(fileName);
    ofn.lpstrFilter = filter;
    ofn.nFilterIndex = 1;
    ofn.lpstrTitle = title;
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

    char initialDir[MAX_PATH]{};
    if (GetFullPathNameA("assets", MAX_PATH, initialDir, nullptr) > 0) {
        ofn.lpstrInitialDir = initialDir;
    }

    if (!GetOpenFileNameA(&ofn)) return {};
    return normalizeSelectedPath(fileName);
}

std::string MapEditorOverlay::normalizeSelectedPath(const std::string& path)
{
    std::string selected = path;
    std::replace(selected.begin(), selected.end(), '\\', '/');

    char cwdBuf[MAX_PATH]{};
    if (GetCurrentDirectoryA(MAX_PATH, cwdBuf) > 0) {
        std::string cwd = cwdBuf;
        std::replace(cwd.begin(), cwd.end(), '\\', '/');
        if (!cwd.empty() && cwd.back() != '/') cwd.push_back('/');

        if (selected.size() > cwd.size() &&
            _strnicmp(selected.c_str(), cwd.c_str(), cwd.size()) == 0) {
            return selected.substr(cwd.size());
        }
    }

    return selected;
}

void MapEditorOverlay::writeVec(float dst[3], float x, float y, float z)
{
    dst[0] = x;
    dst[1] = y;
    dst[2] = z;
}


std::string MapEditorOverlay::getRequestedObjectId() const
{
    return getWindowTextAString(m_objectIdEdit);
}

void MapEditorOverlay::setObjectIdTaken(bool taken)
{
    if (m_objectIdTaken == taken) {
        refreshValidationUi();
        return;
    }
    m_objectIdTaken = taken;
    if (taken && m_statusText.empty()) m_statusText = "ID already exists";
    if (!taken && m_statusText == "ID already exists") m_statusText.clear();
    refreshValidationUi();
    if (m_objectIdEdit) InvalidateRect(m_objectIdEdit, nullptr, TRUE);
}

void MapEditorOverlay::setStatusText(const std::string& text)
{
    m_statusText = text;
    refreshValidationUi();
}

void MapEditorOverlay::refreshValidationUi()
{
    if (m_idErrorLabel) {
        setWindowTextAString(m_idErrorLabel, !m_statusText.empty() ? m_statusText : (m_objectIdTaken ? "ID already exists" : ""));
    }
    if (m_createButton) {
        EnableWindow(m_createButton, (createAllowed() && m_editEnabled) ? TRUE : FALSE);
    }
}

static void setFloatText(HWND hwnd, float value)
{
    char buf[64]{};
    std::snprintf(buf, sizeof(buf), "%.6g", value);
    SetWindowTextA(hwnd, buf);
}

void MapEditorOverlay::loadEditIntoControls(const MapObjectEdit& edit)
{
    if (!m_controlsCreated) return;

    int type = (int)edit.objectType;
    if (type < 0 || type > 3) type = 2;
    SendMessageA(m_typeCombo, CB_SETCURSEL, type, 0);

    setWindowTextAString(m_objectIdEdit, mapEditGetString(edit.id, sizeof(edit.id)));
    setWindowTextAString(m_pathEdit, mapEditGetString(edit.path, sizeof(edit.path)));
    setWindowTextAString(m_textureEdit, mapEditGetString(edit.texture, sizeof(edit.texture)));

    Vec3f semanticPosition{edit.position[0], edit.position[1], edit.position[2]};
    const Vec3f corner0{edit.corner0[0], edit.corner0[1], edit.corner0[2]};
    const Vec3f corner1{edit.corner1[0], edit.corner1[1], edit.corner1[2]};

    if (type == (int)MapEditObjectType::Aabb || type == (int)MapEditObjectType::Mesh) {
        // AABB and Mesh do not need a separate JSON position. The editor's
        // Position fields therefore represent corner0 directly.
        semanticPosition = corner0;
    }

    Vec3f semanticScale{corner1.x - corner0.x, corner1.y - corner0.y, corner1.z - corner0.z};
    if (type == (int)MapEditObjectType::Light &&
        std::abs(semanticScale.x) < 1e-6f &&
        std::abs(semanticScale.y) < 1e-6f &&
        std::abs(semanticScale.z) < 1e-6f) {
        semanticScale = {1.f, 1.f, 1.f};
    }

    for (int i = 0; i < 3; ++i) {
        const float posValue[3] = {semanticPosition.x, semanticPosition.y, semanticPosition.z};
        const float scaleValue[3] = {semanticScale.x, semanticScale.y, semanticScale.z};
        setFloatText(m_position[i], posValue[i]);
        setFloatText(m_color[i], edit.color[i]);
        setFloatText(m_rotation[i], edit.rotation[i]);
        setFloatText(m_scale[i], scaleValue[i]);
    }
    setFloatText(m_intensity, edit.intensity);
    setFloatText(m_radius, edit.radius);
    for (int i = 0; i < 3; ++i) {
        setFloatText(m_lightNormal[i], edit.normal[i]);
    }
    setFloatText(m_lightAngle, edit.angle);
    syncAllSlidersFromEdits();

    m_objectIdTaken = true;
    setStatusText("Loaded existing ID");
    requestPreviewRemove();
}

void MapEditorOverlay::setCheckedObjectFound(const MapObjectEdit& edit)
{
    loadEditIntoControls(edit);
}

void MapEditorOverlay::setCheckedObjectAvailable(const std::string& id)
{
    if (!id.empty()) setWindowTextAString(m_objectIdEdit, id);
    m_objectIdTaken = false;
    setStatusText("ID available");
    if (m_objectIdEdit) InvalidateRect(m_objectIdEdit, nullptr, TRUE);
    markPreviewDirty();
}

Vec3f MapEditorOverlay::normalFromPlaneRotation(Vec3f rotationDeg)
{
    constexpr float kPi = 3.14159265358979323846f;
    const float rx = rotationDeg.x * kPi / 180.0f;
    const float ry = rotationDeg.y * kPi / 180.0f;
    const float rz = rotationDeg.z * kPi / 180.0f;

    // Same Euler order used by mesh JSON loading: Ry * Rx * Rz.
    // Start with a horizontal plane normal. With zero rotation, c0/c1 are the
    // diagonal bounds of a normal floor/ceiling-style plane.
    Vec3f n{0.f, 1.f, 0.f};

    // Rz
    {
        const float c = std::cos(rz), s = std::sin(rz);
        n = {n.x * c - n.y * s, n.x * s + n.y * c, n.z};
    }
    // Rx
    {
        const float c = std::cos(rx), s = std::sin(rx);
        n = {n.x, n.y * c - n.z * s, n.y * s + n.z * c};
    }
    // Ry
    {
        const float c = std::cos(ry), s = std::sin(ry);
        n = {n.x * c + n.z * s, n.y, -n.x * s + n.z * c};
    }

    const float len = std::sqrt(n.x * n.x + n.y * n.y + n.z * n.z);
    if (len <= 1e-6f) return {0.f, 1.f, 0.f};
    return {n.x / len, n.y / len, n.z / len};
}

bool MapEditorOverlay::readControlsToEdit(MapObjectEdit& edit, bool updateLastObject)
{
    std::memset(&edit, 0, sizeof(edit));

    int type = (int)SendMessageA(m_typeCombo, CB_GETCURSEL, 0, 0);
    if (type < 0 || type > 3) type = 2;
    edit.objectType = (uint8_t)type;
    edit.persistToJson = 0;

    std::string id = getWindowTextAString(m_objectIdEdit);
    if (id.empty() && updateLastObject) {
        id = makeObjectId();
        setWindowTextAString(m_objectIdEdit, id);
    }

    mapEditSetString(edit.id, sizeof(edit.id), id);
    mapEditSetString(edit.path, sizeof(edit.path), getWindowTextAString(m_pathEdit));
    mapEditSetString(edit.texture, sizeof(edit.texture), getWindowTextAString(m_textureEdit));

    // Collision is no longer exposed in the editor UI. Leaving it empty keeps
    // the existing MapData default: meshes collide unless map JSON explicitly
    // says otherwise.
    mapEditSetString(edit.collision, sizeof(edit.collision), "");

    Vec3f position{
        readFloat(m_position[0], 0.f),
        readFloat(m_position[1], 2.f),
        readFloat(m_position[2], 0.f)
    };
    Vec3f semanticScale{
        readFloat(m_scale[0], 1.f),
        readFloat(m_scale[1], 1.f),
        readFloat(m_scale[2], 1.f)
    };

    // The editor no longer exposes raw c0/c1. Position is the semantic anchor.
    // For AABB/Mesh, Position becomes corner0 and Scale is the displayed extent
    // to corner1. For Plane, Position remains the plane point/center, so c0/c1
    // are reconstructed symmetrically around it. Lights use Position directly.
    Vec3f corner0 = position;
    Vec3f corner1 = {
        position.x + semanticScale.x,
        position.y + semanticScale.y,
        position.z + semanticScale.z
    };
    if (type == (int)MapEditObjectType::Plane) {
        corner0 = {
            position.x - semanticScale.x * 0.5f,
            position.y - semanticScale.y * 0.5f,
            position.z - semanticScale.z * 0.5f
        };
        corner1 = {
            position.x + semanticScale.x * 0.5f,
            position.y + semanticScale.y * 0.5f,
            position.z + semanticScale.z * 0.5f
        };
    }
    writeVec(edit.corner0, corner0.x, corner0.y, corner0.z);
    writeVec(edit.corner1, corner1.x, corner1.y, corner1.z);

    Vec3f rotation{
        readFloat(m_rotation[0], 0.f),
        readFloat(m_rotation[1], 0.f),
        readFloat(m_rotation[2], 0.f)
    };
    writeVec(edit.rotation, rotation.x, rotation.y, rotation.z);

    if (type == (int)MapEditObjectType::Plane) {
        const Vec3f n = normalFromPlaneRotation(rotation);
        writeVec(edit.normal, n.x, n.y, n.z);
    } else if (type == (int)MapEditObjectType::Light) {
        Vec3f lightNormal{
            readFloat(m_lightNormal[0], 0.f),
            readFloat(m_lightNormal[1], -1.f),
            readFloat(m_lightNormal[2], 0.f)
        };
        const float nLen = std::sqrt(lightNormal.x * lightNormal.x +
                                     lightNormal.y * lightNormal.y +
                                     lightNormal.z * lightNormal.z);
        if (nLen > 1e-6f) {
            lightNormal = {lightNormal.x / nLen, lightNormal.y / nLen, lightNormal.z / nLen};
        } else {
            lightNormal = {0.f, -1.f, 0.f};
        }
        writeVec(edit.normal, lightNormal.x, lightNormal.y, lightNormal.z);
    } else {
        writeVec(edit.normal, 0.f, 1.f, 0.f);
    }

    writeVec(edit.position, position.x, position.y, position.z);

    writeVec(edit.color,
             readFloat(m_color[0], 1.f),
             readFloat(m_color[1], 0.75f),
             readFloat(m_color[2], 0.35f));

    // Scale UI is now an editor-side extent-to-corner1 control. Keep the
    // protocol mesh scale override empty so MapData derives mesh scaling from
    // corner0/corner1 instead of applying this extent a second time.
    writeVec(edit.scale, 0.f, 0.f, 0.f);

    edit.intensity = readFloat(m_intensity, 4.f);
    edit.radius = readFloat(m_radius, 10.f);
    edit.angle = readFloat(m_lightAngle, 0.f);

    if (updateLastObject) {
        m_lastObjectId = id;
        m_pendingRemoveId = id;
        setWindowTextAString(m_removeIdEdit, id);
    }
    return true;
}

void MapEditorOverlay::addRect(std::vector<MenuOverlayRect>& rects, int x, int y, int w, int h, uint32_t color)
{
    if (w <= 0 || h <= 0) return;
    rects.push_back({x, y, w, h, color});
}

void MapEditorOverlay::addFrame(std::vector<MenuOverlayRect>& rects, int x, int y, int w, int h, uint32_t color)
{
    addRect(rects, x, y, w, 2, color);
    addRect(rects, x, y + h - 2, w, 2, color);
    addRect(rects, x, y, 2, h, color);
    addRect(rects, x + w - 2, y, 2, h, color);
}

void MapEditorOverlay::addText(std::vector<MenuOverlayRect>& rects, const char* text, int x, int y, int scale, uint32_t color)
{
    if (!text || scale <= 0) return;
    int cx = x;
    for (const char* p = text; *p; ++p) {
        char ch = *p;
        if (ch == ' ') { cx += 4 * scale; continue; }
        for (int yy = 0; yy < 7; ++yy) {
            const char* row = glyphRows(ch, yy);
            for (int xx = 0; xx < 5; ++xx) {
                if (row[xx] == '1') addRect(rects, cx + xx * scale, y + yy * scale, scale, scale, color);
            }
        }
        cx += 6 * scale;
    }
}

void MapEditorOverlay::appendOverlay(std::vector<MenuOverlayRect>& rects, int, int) const
{
    addRect(rects, TOGGLE_X, TOGGLE_Y, TOGGLE_W, TOGGLE_H, m_editEnabled ? C_BUTTON_ON : C_BUTTON);
    addFrame(rects, TOGGLE_X, TOGGLE_Y, TOGGLE_W, TOGGLE_H, 0xFFFFFFFFu);
    addRect(rects, TOGGLE_X + 8, TOGGLE_Y + 8, 20, 20, C_BOX);
    addRect(rects, TOGGLE_X + 12, TOGGLE_Y + 12, 12, 12, m_editEnabled ? C_BUTTON_ON : C_BOX_DARK);
    addText(rects, "EDIT", TOGGLE_X + 42, TOGGLE_Y + 10, 2, C_TEXT);
}

MapEditorOverlay::ControlId MapEditorOverlay::hitTest(int px, int py) const
{
    if (px >= TOGGLE_X && px < TOGGLE_X + TOGGLE_W &&
        py >= TOGGLE_Y && py < TOGGLE_Y + TOGGLE_H) {
        return ControlId::EditToggle;
    }
    return ControlId::None;
}

bool MapEditorOverlay::handleOverlayInput(HWND hwnd, int, int)
{
    const bool down = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
    const bool clicked = down && !m_prevMouseDown;
    m_prevMouseDown = down;
    if (!clicked) return false;

    POINT p{};
    if (!GetCursorPos(&p)) return false;
    if (!ScreenToClient(hwnd, &p)) return false;

    if (hitTest(p.x, p.y) != ControlId::EditToggle) return false;
    setEditEnabled(!m_editEnabled, hwnd);
    return true;
}

bool MapEditorOverlay::consumePreviewUpdate(MapObjectEdit& outEdit, std::string& outObjectIdToReplace)
{
    if (!m_editEnabled || !m_previewDirty || m_objectIdTaken) return false;
    m_previewDirty = false;

    if (!readControlsToEdit(outEdit, false)) return false;

    outObjectIdToReplace = m_previewObjectId;
    mapEditSetString(outEdit.id, sizeof(outEdit.id), m_previewObjectId);
    outEdit.persistToJson = 0;
    m_previewActive = true;
    return true;
}

bool MapEditorOverlay::consumePreviewRemove(std::string& outObjectId)
{
    if (!m_previewRemoveRequested) return false;
    m_previewRemoveRequested = false;
    m_previewActive = false;
    outObjectId = m_previewObjectId;
    return !outObjectId.empty();
}

bool MapEditorOverlay::consumeCheckRequest(std::string& outObjectId)
{
    if (!m_checkRequested) return false;
    m_checkRequested = false;
    outObjectId = m_pendingRemoveId.empty() ? getWindowTextAString(m_objectIdEdit) : m_pendingRemoveId;
    return !outObjectId.empty();
}

void MapEditorOverlay::notePreviewRemoved()
{
    m_previewActive = false;
    m_previewDirty = false;
    m_previewRemoveRequested = false;
}

bool MapEditorOverlay::consumeAddRequest(MapObjectEdit& outEdit, const Vec3f&)
{
    if (!m_addRequested) return false;
    m_addRequested = false;
    if (!createAllowed()) return false;

    if (!readControlsToEdit(outEdit, true)) return false;

    outEdit.persistToJson = 1;
    setStatusText("Created");
    return true;
}

bool MapEditorOverlay::consumeRemoveRequest(std::string& outObjectId)
{
    if (!m_removeRequested) return false;
    m_removeRequested = false;

    outObjectId = m_pendingRemoveId.empty() ? getWindowTextAString(m_removeIdEdit) : m_pendingRemoveId;
    return !outObjectId.empty();
}

std::string MapEditorOverlay::makeObjectId()
{
    char buf[64]{};
    std::snprintf(buf, sizeof(buf), "editor_%llu", (unsigned long long)m_nextId++);
    return std::string(buf);
}
