#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include <cmath>

#include "MapEditProtocol.h"
#include "Vec3f.h"
#include "VulkanOverlay.h"

class MapEditorOverlay {
public:
    // Creates the native, always-on-top builder popup. The popup is shown only
    // while Edit mode is enabled from the in-game overlay checkbox.
    bool create(HWND owner);
    void destroy();
    void keepOnTop(HWND owner);
    void setPauseVisible(bool paused, HWND owner);
    void pumpMessages();
    void setCurrentPlayerPosition(const Vec3f& playerPos);

    void setEditEnabled(bool enabled, HWND owner = nullptr);
    bool isEditEnabled() const { return m_editEnabled; }

    // Engine overlay integration API: these methods are required by Engine.cpp.
    // Draws only the Edit checkbox into the existing in-game pause overlay.
    // The full builder controls live in the native popup window.
    void appendOverlay(std::vector<MenuOverlayRect>& rects, int windowW, int windowH) const;

    // Handles mouse clicks against the in-game Edit checkbox.
    bool handleOverlayInput(HWND hwnd, int windowW, int windowH);

    // One transient preview object is kept in the live map while the native
    // builder popup is open. It is never persisted or networked.
    bool consumePreviewUpdate(MapObjectEdit& outEdit, std::string& outObjectIdToReplace);
    bool consumePreviewRemove(std::string& outObjectId);

    // Engine supplies this from MapData::hasRuntimeObjectId(). The preview
    // itself uses an internal id, so this validation only protects the future
    // real Create action from overwriting an existing object id.
    std::string getRequestedObjectId() const;
    void setObjectIdTaken(bool taken);
    void setCheckedObjectFound(const MapObjectEdit& edit);
    void setCheckedObjectAvailable(const std::string& id);
    bool createAllowed() const { return !m_objectIdTaken && !getRequestedObjectId().empty(); }

    bool consumeCheckRequest(std::string& outObjectId);
    bool consumeAddRequest(MapObjectEdit& outEdit, const Vec3f& playerPos);
    bool consumeRemoveRequest(std::string& outObjectId);
    const std::string& previewObjectId() const { return m_previewObjectId; }
    void notePreviewRemoved();

private:
    enum class ControlId : int {
        None = 0,
        EditToggle
    };

    struct Rect { int x, y, w, h; };

    enum NativeId : int {
        ID_TYPE = 1000,
        ID_OBJECT_ID,
        ID_CHECK,
        ID_PATH,
        ID_BROWSE_PATH,
        ID_TEXTURE,
        ID_BROWSE_TEXTURE,

        ID_POSITION_X, ID_POSITION_Y, ID_POSITION_Z,
        ID_COLOR_X, ID_COLOR_Y, ID_COLOR_Z,
        ID_ROT_X, ID_ROT_Y, ID_ROT_Z,
        ID_SCALE_X, ID_SCALE_Y, ID_SCALE_Z,
        ID_INTENSITY,
        ID_RADIUS,
        ID_LIGHT_NORMAL_X, ID_LIGHT_NORMAL_Y, ID_LIGHT_NORMAL_Z,
        ID_LIGHT_ANGLE,

        ID_SLIDER_BASE = 2000,
        ID_AT_PLAYER_BASE = 5000,

        ID_CREATE,
        ID_ERROR_LABEL,
        ID_REMOVE_ID,
        ID_REMOVE,
        ID_REMOVE_LAST
    };

    static LRESULT CALLBACK windowProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);

    bool createNativeWindow(HWND owner);
    void createControls();
    void setDefaultControlValues();
    void handleNativeCommand(int id, int code);
    void showNativeWindow(bool show);
    bool readControlsToEdit(MapObjectEdit& edit, bool updateLastObject);
    void refreshValidationUi();
    void loadEditIntoControls(const MapObjectEdit& edit);
    void setStatusText(const std::string& text);
    static Vec3f normalFromPlaneRotation(Vec3f rotationDeg);
    void markPreviewDirty();
    void requestPreviewRemove();

    HWND createLabel(const char* text, int x, int y, int w, int h);
    HWND createEditBox(int id, int x, int y, int w, int h, const char* text = "");
    HWND createButton(int id, const char* text, int x, int y, int w, int h);
    HWND createCombo(int id, int x, int y, int w, int h, const char* const* values, int count, int selected);
    HWND createSliderForEdit(int editId, HWND edit, int x, int y, int w, int h, float stepScale);
    HWND createAtPlayerButtonForEdit(int editId, HWND edit, int playerAxis, int x, int y, int w, int h);
    void applyPlayerPositionToEdit(int editId);
    void applyPendingSpawnAtPlayer();
    void syncSliderFromEditId(int editId);
    void syncSliderFromEdit(HWND edit);
    void syncAllSlidersFromEdits();
    bool handleSliderScroll(WPARAM scrollCode, HWND slider);

    static std::string getWindowTextAString(HWND hwnd);
    static void setWindowTextAString(HWND hwnd, const std::string& value);
    static float readFloat(HWND hwnd, float fallback);
    static std::string openFileDialog(HWND owner, const char* title, const char* filter);
    static std::string normalizeSelectedPath(const std::string& path);
    static void writeVec(float dst[3], float x, float y, float z);
    static void addRect(std::vector<MenuOverlayRect>& rects, int x, int y, int w, int h, uint32_t color);
    static void addFrame(std::vector<MenuOverlayRect>& rects, int x, int y, int w, int h, uint32_t color);
    static void addText(std::vector<MenuOverlayRect>& rects, const char* text, int x, int y, int scale, uint32_t color);

    ControlId hitTest(int px, int py) const;
    std::string makeObjectId();

private:
    HWND m_owner = nullptr;
    HWND m_hwnd = nullptr;
    HFONT m_font = nullptr;
    bool m_controlsCreated = false;

    bool m_editEnabled = false;
    bool m_pauseVisible = false;
    bool m_prevMouseDown = false;

    bool m_addRequested = false;
    bool m_removeRequested = false;
    bool m_checkRequested = false;
    bool m_previewDirty = false;
    bool m_previewActive = false;
    bool m_previewRemoveRequested = false;
    bool m_objectIdTaken = false;
    std::string m_statusText;
    uint64_t m_nextId = 1;
    std::string m_lastObjectId;
    std::string m_pendingRemoveId;
    std::string m_previewObjectId = "__map_builder_preview__";

    HBRUSH m_idErrorBrush = nullptr;

    struct SliderBinding {
        int editId = 0;
        HWND edit = nullptr;
        HWND slider = nullptr;
        float stepScale = 1.f;
        int centerPos = 0;
        int lastPos = 0;
        int playerAxis = 0;
    };
    std::vector<SliderBinding> m_sliderBindings;
    bool m_syncingSliderText = false;
    bool m_spawnAtPlayerPending = false;
    Vec3f m_currentPlayerPos{0.f, 0.f, 0.f};

    HWND m_typeCombo = nullptr;
    HWND m_objectIdEdit = nullptr;
    HWND m_idErrorLabel = nullptr;
    HWND m_createButton = nullptr;
    HWND m_pathEdit = nullptr;
    HWND m_textureEdit = nullptr;

    HWND m_position[3]{};
    HWND m_color[3]{};
    HWND m_rotation[3]{};
    HWND m_scale[3]{};
    HWND m_intensity = nullptr;
    HWND m_radius = nullptr;
    HWND m_lightNormal[3]{};
    HWND m_lightAngle = nullptr;
    HWND m_removeIdEdit = nullptr;
};
