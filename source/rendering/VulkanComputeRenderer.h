#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#ifndef VK_USE_PLATFORM_WIN32_KHR
#define VK_USE_PLATFORM_WIN32_KHR
#endif
#include <windows.h>
#include <vulkan/vulkan.h>

#include "GpuScene.h"
#include "VulkanOverlay.h"
#include "Vec3f.h"

class Player;
class Map;
class MapData;
struct Mesh;

class VulkanComputeRenderer {
public:
    VulkanComputeRenderer() = default;
    ~VulkanComputeRenderer();

    bool init(HWND hwnd, int width, int height, const char* shaderPath = "raycast.comp.spv");
    void shutdown();
    bool resize(int width, int height);

    // Existing path: one compute-shader raycast per pixel. Kept intact.
    bool render(const Player& player,
                const Map& map,
                const GpuRemotePlayer* remotePlayers,
                const Mesh* const* remoteMeshes,
                int numRemotePlayers,
                uint32_t* dstPixels,
                const MenuOverlayRect* overlayRects,
                uint32_t overlayRectCount,
                bool overlayEnabled,
                uint32_t overlayWindowW,
                uint32_t overlayWindowH);

    // New path: hardware rasterisation. Uses the same uploaded scene/texture/camera
    // data as render(), but records a graphics pass instead of dispatching raycast.comp.
    bool rasterize(const Player& player,
                   const Map& map,
                   const GpuRemotePlayer* remotePlayers,
                   const Mesh* const* remoteMeshes,
                   int numRemotePlayers,
                   uint32_t* dstPixels,
                   const MenuOverlayRect* overlayRects,
                   uint32_t overlayRectCount,
                   bool overlayEnabled,
                   uint32_t overlayWindowW,
                   uint32_t overlayWindowH);

    // UI-controlled experimental RT-lighting settings. The renderer still works
    // when RT shaders are missing/disabled; use logs to verify which path runs.
    void setRaytracingSettings(bool enabled, int qualityPercent);
    // Legacy parameter names kept for compatibility: dustDensityPercent = particle count, dustBrightnessPercent = particle size.
    void setRaytracingSettings(bool enabled, int qualityPercent, int dustDensityPercent, int dustBrightnessPercent);
    void setEditorMode(bool enabled);

    const std::string& lastError() const { return m_lastError; }

private:
    struct Buffer {
        VkBuffer buffer = VK_NULL_HANDLE;
        VkDeviceMemory memory = VK_NULL_HANDLE;
        VkDeviceSize size = 0;
    };

    struct RtImage {
        VkImage image = VK_NULL_HANDLE;
        VkDeviceMemory memory = VK_NULL_HANDLE;
        VkImageView view = VK_NULL_HANDLE;
        VkFormat format = VK_FORMAT_UNDEFINED;
    };

    struct RasterVertex {
        float px = 0.f, py = 0.f, pz = 0.f;
        float nx = 0.f, ny = 1.f, nz = 0.f;
        float u = 0.f, v = 0.f;
        uint32_t textureIndex = 0xFFFFFFFFu;
        uint32_t color = 0u; // 0xAARRGGBB for screen overlay vertices.
        uint32_t mode = 0u;  // 0 = projected world vertex, 1 = screen-space overlay vertex.
    };

    void setError(const std::string& msg);

    bool createInstance();
    bool createSurface(HWND hwnd);
    bool pickPhysicalDevice();
    bool createDevice();
    bool createCommandObjects();
    bool createDescriptorObjects();
    bool createPipeline(const char* shaderPath);
    bool createRasterPipeline(const char* vertPath = "raster.vert.spv",
                              const char* fragPath = "gbuffer.frag.spv");
    bool createDirectRasterPipeline(const char* vertPath = "raster.vert.spv",
                                    const char* fragPath = "raster.frag.spv");
    bool createRtPipelines();
    bool createComputePipelineFromSpv(const char* shaderPath, VkPipeline& outPipeline);
    void destroyRasterPipeline();
    void destroyDirectRasterPipeline();
    bool createOrResizeRasterTargets();
    void destroyRasterTargets();
    bool createRtImage(RtImage& out, VkFormat format, VkImageUsageFlags usage, const char* debugName,
                       uint32_t width = 0, uint32_t height = 0);
    void updateRtResolution();
    void destroyRtImage(RtImage& img);
    bool uploadRtSettings(const Player& player, const Map& map);
    bool uploadLights(const MapData& md, const Player& player,const GpuRemotePlayer* remotePlayers,int numRemotePlayers);
    bool createImageView(VkImage image, VkFormat format, VkImageAspectFlags aspect,
                         VkImageView& outView);
    bool createOrResizePixelBuffer();
    bool createOrResizeRenderImage();
    bool createOrResizeSwapchain();
    void destroyImage(VkImage& image, VkDeviceMemory& memory);
    void destroySwapchain();
    bool recreatePresentationResources();
    bool recordAndSubmit();
    bool recordAndSubmitPresent();
    bool recordAndSubmitRaster();
    bool recordAndSubmitRasterDirect();
    bool recordAndSubmitRasterRtComposite();

    uint32_t findMemoryType(uint32_t typeBits, VkMemoryPropertyFlags props) const;
    bool createBuffer(VkDeviceSize size, VkBufferUsageFlags usage,
                      VkMemoryPropertyFlags properties, Buffer& out);
    void destroyBuffer(Buffer& b);
    bool mapCopy(Buffer& b, const void* data, VkDeviceSize size);
    bool uploadBuffer(Buffer& b, const void* data, VkDeviceSize size,
                      VkBufferUsageFlags usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT);
    bool readBuffer(const Buffer& b, void* dst, VkDeviceSize size);

    bool uploadSceneIfNeeded(const Map& map, const Player& player,
                             const Mesh* const* remoteMeshes, int numRemotePlayers);
    bool uploadCamera(const Player& player, const Map& map);
    bool uploadRasterDynamicGeometry(const GpuRemotePlayer* remotePlayers,
                                     const Mesh* const* remoteMeshes,
                                     int numRemotePlayers);
    bool uploadRasterOverlayGeometry(const MenuOverlayRect* overlayRects,
                                     uint32_t overlayRectCount,
                                     bool overlayEnabled,
                                     uint32_t overlayWindowW,
                                     uint32_t overlayWindowH);
    bool uploadRasterDustGeometry(const Player& player, const Map& map);
    void updateDescriptorSet();

    int m_width = 0;
    int m_height = 0;
    bool m_ready = false;
    std::string m_lastError;

    HWND m_hwnd = nullptr;

    VkInstance m_instance = VK_NULL_HANDLE;
    VkPhysicalDevice m_physicalDevice = VK_NULL_HANDLE;
    VkDevice m_device = VK_NULL_HANDLE;
    VkQueue m_queue = VK_NULL_HANDLE;
    uint32_t m_queueFamily = 0;

    VkSurfaceKHR m_surface = VK_NULL_HANDLE;
    VkSwapchainKHR m_swapchain = VK_NULL_HANDLE;
    VkFormat m_swapchainFormat = VK_FORMAT_UNDEFINED;
    VkExtent2D m_swapchainExtent = {0, 0};
    std::vector<VkImage> m_swapchainImages;
    std::vector<VkImageView> m_swapchainImageViews;
    std::vector<VkFramebuffer> m_rasterFramebuffers;

    VkImage m_renderImage = VK_NULL_HANDLE;
    VkDeviceMemory m_renderImageMemory = VK_NULL_HANDLE;
    VkImageView m_renderImageView = VK_NULL_HANDLE;
    VkImage m_depthImage = VK_NULL_HANDLE;
    VkDeviceMemory m_depthImageMemory = VK_NULL_HANDLE;
    VkImageView m_depthImageView = VK_NULL_HANDLE;
    VkFormat m_depthFormat = VK_FORMAT_D32_SFLOAT;

    VkFramebuffer m_gbufferFramebuffer = VK_NULL_HANDLE;
    VkFramebuffer m_directRasterFramebuffer = VK_NULL_HANDLE;
    VkFramebuffer m_particleOverlayFramebuffer = VK_NULL_HANDLE;
    RtImage m_gbufferAlbedo;
    RtImage m_gbufferNormal;
    RtImage m_gbufferDepth;
    RtImage m_rtLightingRaw;
    RtImage m_rtLightingFiltered;
    RtImage m_rtHistoryA;
    RtImage m_rtHistoryB;
    RtImage m_rtComposite;
    bool m_rtHistoryPing = false;
    bool m_rtImagesInitialized = false;

    VkCommandPool m_commandPool = VK_NULL_HANDLE;
    VkCommandBuffer m_commandBuffer = VK_NULL_HANDLE;
    VkFence m_fence = VK_NULL_HANDLE;
    VkSemaphore m_imageAvailable = VK_NULL_HANDLE;
    VkSemaphore m_renderFinished = VK_NULL_HANDLE;

    VkDescriptorSetLayout m_descLayout = VK_NULL_HANDLE;
    VkDescriptorPool m_descPool = VK_NULL_HANDLE;
    VkDescriptorSet m_descSet = VK_NULL_HANDLE;
    VkPipelineLayout m_pipelineLayout = VK_NULL_HANDLE;
    VkPipeline m_pipeline = VK_NULL_HANDLE;

    // G-buffer raster pipeline used only when RT lighting is active.
    VkRenderPass m_rasterRenderPass = VK_NULL_HANDLE;
    VkPipelineLayout m_rasterPipelineLayout = VK_NULL_HANDLE;
    VkPipeline m_rasterPipeline = VK_NULL_HANDLE;
    VkPipeline m_rasterOverlayPipeline = VK_NULL_HANDLE;

    // Direct swapchain raster pipeline used when RT is OFF. This is the old
    // raster path: raster.frag -> applyFog() -> swapchain, no RT images/history.
    VkRenderPass m_directRasterRenderPass = VK_NULL_HANDLE;
    VkRenderPass m_particleOverlayRenderPass = VK_NULL_HANDLE;
    VkPipelineLayout m_directRasterPipelineLayout = VK_NULL_HANDLE;
    VkPipeline m_directRasterPipeline = VK_NULL_HANDLE;
    VkPipeline m_directRasterOverlayPipeline = VK_NULL_HANDLE;
    VkPipeline m_directRasterDustPipeline = VK_NULL_HANDLE;
    VkPipeline m_particleOverlayDustPipeline = VK_NULL_HANDLE;
    VkPipeline m_rtLightingPipeline = VK_NULL_HANDLE;
    VkPipeline m_rtSpatialPipeline = VK_NULL_HANDLE;
    VkPipeline m_rtTemporalPipeline = VK_NULL_HANDLE;
    VkPipeline m_rtCompositePipeline = VK_NULL_HANDLE;

    Buffer m_pixels;
    Buffer m_camera;
    Buffer m_cells;
    Buffer m_items;
    Buffer m_boxes;
    Buffer m_planes;
    Buffer m_texInfos;
    Buffer m_texPixels;
    Buffer m_meshes;
    Buffer m_meshCells;
    Buffer m_triangles;
    Buffer m_bvhNodes;
    Buffer m_triIndices;
    Buffer m_remotePlayers;
    Buffer m_playerMesh;
    Buffer m_overlayRects;
    Buffer m_overlayState;
    Buffer m_Lights;
    Buffer m_rtSettings;

    Buffer m_rasterStaticVertices;
    Buffer m_rasterStaticIndices;
    Buffer m_rasterDynamicVertices;
    Buffer m_rasterDynamicIndices;
    Buffer m_rasterOverlayVertices;
    Buffer m_rasterOverlayIndices;
    Buffer m_rasterDustVertices;
    Buffer m_rasterDustIndices;
    uint32_t m_rasterStaticIndexCount = 0;
    uint32_t m_rasterDynamicIndexCount = 0;
    uint32_t m_rasterOverlayIndexCount = 0;
    uint32_t m_rasterDustIndexCount = 0;

    // Descriptor sets only need to be rewritten when a buffer object is
    // created/recreated. Per-frame buffer content updates do not require it.
    bool m_descriptorSetDirty = true;

    // Small cache keys for per-frame raster-only geometry. They avoid
    // rebuilding/reallocating overlay/dynamic buffers when inputs did not change.
    uint64_t m_rasterOverlayHash = 0;
    uint64_t m_rasterDynamicHash = 0;
    uint64_t m_rasterDustHash = 0;

    // Built-in raster performance diagnostics, printed every 60 raster frames.
    bool m_lastSceneUploadRebuilt = false;
    const char* m_lastSceneUploadReason = "not-run";
    double m_lastRasterAcquireMs = 0.0;
    double m_lastRasterRecordMs = 0.0;
    double m_lastRasterSubmitWaitMs = 0.0;
    double m_lastRasterPresentMs = 0.0;
    double m_lastRtLightingMs = 0.0;
    double m_lastRtCompositeMs = 0.0;

    bool m_raytracingEnabled = false;
    int m_raytracingQualityPercent = 100;
    // Legacy names kept for compatibility with existing UI calls:
    //   m_dustDensityPercent    -> particle count (500% stronger scale)
    //   m_dustBrightnessPercent -> particle size
    int m_dustDensityPercent = 10;
    int m_dustBrightnessPercent = 22;
    bool m_editorMode = false;
    uint32_t m_rtFrameIndex = 0;
    int m_rtWidth = 1;
    int m_rtHeight = 1;
    bool m_rtHistoryValid = false;
    std::chrono::steady_clock::time_point m_dustStartTime{};
    uint64_t m_rtLastMapVersion = 0;
    int m_rtLastWidth = 0;
    int m_rtLastHeight = 0;
    Vec3f m_rtLastCameraPos = {0.f, 0.f, 0.f};
    Vec3f m_rtLastCameraDir = {0.f, 0.f, 1.f};
    uint32_t m_uploadedLightCount = 0;
    std::vector<GpuLight> m_cpuLights;

    MapData* m_uploadedMap = nullptr;
    uint64_t m_uploadedMapVersion = 0;
    Mesh* m_uploadedPlayerMesh = nullptr;
    int m_uploadedRemoteMeshCount = 0;
    std::vector<const Mesh*> m_uploadedRemoteMeshes;
    int m_numRemotePlayers = 0;
    std::vector<GpuUVec4> m_remoteMeshRanges;

    // CPU copy of the packed triangle array. The compute renderer still owns
    // the GPU buffer; rasterisation needs this copy only to recover the already
    // globalised texture index for dynamic remote-player triangles.
    std::vector<GpuTriangle> m_cpuTriangles;
};
