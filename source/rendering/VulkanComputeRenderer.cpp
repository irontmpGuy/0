#include "VulkanComputeRenderer.h"

#include "Map.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstring>
#include <chrono>
#include <fstream>
#include <iostream>
#include <unordered_map>

#include "Box.h"
#include "Plane.h"
#include "Mesh.h"
#include "Texture.h"
#include "Cell.h"

static GpuVec4 gv4(float x, float y, float z, float w = 0.f) { return {x,y,z,w}; }
static GpuVec4 gv4(const Vec3f& v, float w = 0.f) { return {v.x, v.y, v.z, w}; }

static constexpr VkFormat RT_ALBEDO_FORMAT = VK_FORMAT_R8G8B8A8_UNORM;
static constexpr VkFormat RT_NORMAL_FORMAT = VK_FORMAT_R16G16B16A16_SFLOAT;
static constexpr VkFormat RT_DEPTH_FORMAT  = VK_FORMAT_R32_SFLOAT;
static constexpr VkFormat RT_LIGHT_FORMAT  = VK_FORMAT_R16G16B16A16_SFLOAT;

static Vec3f add3(const Vec3f& a, const Vec3f& b) { return {a.x+b.x, a.y+b.y, a.z+b.z}; }
static Vec3f sub3(const Vec3f& a, const Vec3f& b) { return {a.x-b.x, a.y-b.y, a.z-b.z}; }
static Vec3f cross3(const Vec3f& a, const Vec3f& b) {
    return {a.y*b.z - a.z*b.y, a.z*b.x - a.x*b.z, a.x*b.y - a.y*b.x};
}
static float dot3(const Vec3f& a, const Vec3f& b) {
    return a.x*b.x + a.y*b.y + a.z*b.z;
}
static Vec3f scale3(const Vec3f& v, float s) {
    return {v.x*s, v.y*s, v.z*s};
}
static Vec3f rejectFrom3(const Vec3f& v, const Vec3f& axis) {
    const float d = dot3(v, axis);
    return {v.x - axis.x*d, v.y - axis.y*d, v.z - axis.z*d};
}
static Vec3f norm3(const Vec3f& v) {
    const float len = std::sqrt(v.x*v.x + v.y*v.y + v.z*v.z);
    if (len < 1e-8f) return {0.f, 1.f, 0.f};
    return {v.x/len, v.y/len, v.z/len};
}
static Vec3f triNormal(const Vec3f& a, const Vec3f& b, const Vec3f& c) {
    return norm3(cross3(sub3(b, a), sub3(c, a)));
}

struct GpuOverlayRectCPU {
    int32_t x, y, w, h;
    uint32_t color[4];
};

struct GpuOverlayStateCPU {
    uint32_t info[4];
};

static double elapsedMs(std::chrono::high_resolution_clock::time_point a,
                        std::chrono::high_resolution_clock::time_point b)
{
    return std::chrono::duration<double, std::milli>(b - a).count();
}

static const char* presentModeName(VkPresentModeKHR mode)
{
    switch (mode) {
        case VK_PRESENT_MODE_IMMEDIATE_KHR: return "IMMEDIATE";
        case VK_PRESENT_MODE_MAILBOX_KHR:   return "MAILBOX";
        case VK_PRESENT_MODE_FIFO_KHR:      return "FIFO";
        case VK_PRESENT_MODE_FIFO_RELAXED_KHR: return "FIFO_RELAXED";
        default: return "UNKNOWN";
    }
}

static uint64_t fnv1aAppend(uint64_t h, const void* data, size_t size)
{
    const uint8_t* p = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < size; ++i) {
        h ^= (uint64_t)p[i];
        h *= 1099511628211ull;
    }
    return h;
}

template <class T>
static uint64_t fnv1aAppendValue(uint64_t h, const T& v)
{
    return fnv1aAppend(h, &v, sizeof(T));
}

static std::vector<char> readBinaryFile(const char* path)
{
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    std::streamsize size = f.tellg();
    if (size <= 0) return {};
    f.seekg(0, std::ios::beg);
    std::vector<char> data((size_t)size);
    if (!f.read(data.data(), size)) return {};
    return data;
}

VulkanComputeRenderer::~VulkanComputeRenderer() { shutdown(); }

void VulkanComputeRenderer::setError(const std::string& msg)
{
    m_lastError = msg;
    std::cerr << "[VulkanComputeRenderer] " << msg << "\n";
}

void VulkanComputeRenderer::updateRtResolution()
{
    const int fullW = std::max(1, m_width);
    const int fullH = std::max(1, m_height);

    // RT quality now controls RT render resolution by area:
    //   100% -> full internal render resolution
    //    25% -> half width/height, i.e. quarter ray pixels
    //     1% -> about 10% width/height, i.e. ~1% ray pixels
    float q = 100.0f;
    if (m_raytracingEnabled && m_raytracingQualityPercent > 0) {
        q = std::clamp((float)m_raytracingQualityPercent, 1.0f, 100.0f);
    }
    const float scale = std::sqrt(q / 100.0f);
    m_rtWidth = std::max(1, (int)std::lround((float)fullW * scale));
    m_rtHeight = std::max(1, (int)std::lround((float)fullH * scale));

    if (q >= 99.5f) {
        m_rtWidth = fullW;
        m_rtHeight = fullH;
    }
}

void VulkanComputeRenderer::setRaytracingSettings(bool enabled, int qualityPercent)
{
    setRaytracingSettings(enabled, qualityPercent, m_dustDensityPercent, m_dustBrightnessPercent);
}

void VulkanComputeRenderer::setRaytracingSettings(bool enabled, int qualityPercent, int dustDensityPercent, int dustBrightnessPercent)
{
    qualityPercent = std::clamp(qualityPercent, 0, 100);
    dustDensityPercent = std::clamp(dustDensityPercent, 0, 100);
    dustBrightnessPercent = std::clamp(dustBrightnessPercent, 0, 100);

    const bool oldEnabled = m_raytracingEnabled;
    const int oldQuality = m_raytracingQualityPercent;
    const int oldDustDensity = m_dustDensityPercent;
    const int oldDustBrightness = m_dustBrightnessPercent;
    const int oldRtW = m_rtWidth;
    const int oldRtH = m_rtHeight;

    m_raytracingEnabled = enabled;
    m_raytracingQualityPercent = qualityPercent;
    m_dustDensityPercent = dustDensityPercent;
    m_dustBrightnessPercent = dustBrightnessPercent;
    updateRtResolution();

    const bool rtChanged = (oldEnabled != enabled) || (oldQuality != qualityPercent);
    const bool dustChanged = (oldDustDensity != dustDensityPercent) || (oldDustBrightness != dustBrightnessPercent);
    const bool rtSizeChanged = (oldRtW != m_rtWidth) || (oldRtH != m_rtHeight);
    if (rtChanged || dustChanged) {
        std::cout << "[RT] settings changed: enabled=" << (enabled ? "true" : "false")
                  << " quality=" << qualityPercent << "% rt=" << m_rtWidth << "x" << m_rtHeight
                  << " dustDensity=" << dustDensityPercent << "%"
                  << " dustBrightness=" << dustBrightnessPercent << "%"
                  << " -> history reset\n";
        m_rtHistoryValid = false;
        m_rtImagesInitialized = false;
        m_rasterDustHash = 0;
    }

    // Rebuild only the internal RT/G-buffer targets when quality changes the RT
    // resolution. Do not touch the swapchain/window.
    if (m_ready && rtSizeChanged) {
        vkDeviceWaitIdle(m_device);
        destroyRasterTargets();
        if (!createOrResizeRasterTargets()) {
            std::cerr << "[RT] failed to recreate RT targets after quality change: " << m_lastError << "\n";
            return;
        }
        updateDescriptorSet();
    }
}

void VulkanComputeRenderer::setEditorMode(bool enabled)
{
    if (m_editorMode == enabled) return;
    m_editorMode = enabled;
    m_rtHistoryValid = false;
    ++m_rtFrameIndex;
}

bool VulkanComputeRenderer::init(HWND hwnd, int width, int height, const char* shaderPath)
{
    m_hwnd = hwnd;
    m_width = std::max(1, width);
    m_height = std::max(1, height);
    updateRtResolution();
    m_dustStartTime = std::chrono::steady_clock::now();

    if (!m_hwnd) { setError("HWND is null"); return false; }
    if (!createInstance()) return false;
    if (!createSurface(hwnd)) return false;
    if (!pickPhysicalDevice()) return false;
    if (!createDevice()) return false;
    if (!createCommandObjects()) return false;
    if (!createDescriptorObjects()) return false;
    if (!createOrResizePixelBuffer()) return false;
    if (!createOrResizeRenderImage()) return false;
    if (!createOrResizeSwapchain()) return false;
    if (!createPipeline(shaderPath)) return false;
    if (!createRtPipelines()) return false;
    if (!createRasterPipeline()) return false;
    if (!createDirectRasterPipeline()) return false;
    if (!createOrResizeRasterTargets()) return false;

    m_ready = true;
    return true;
}

void VulkanComputeRenderer::shutdown()
{
    if (m_device != VK_NULL_HANDLE) vkDeviceWaitIdle(m_device);

    destroyRasterTargets();
    destroySwapchain();
    if (m_renderImageView) vkDestroyImageView(m_device, m_renderImageView, nullptr);
    m_renderImageView = VK_NULL_HANDLE;
    destroyImage(m_renderImage, m_renderImageMemory);
    destroyDirectRasterPipeline();
    destroyRasterPipeline();

    destroyBuffer(m_pixels);
    destroyBuffer(m_camera);
    destroyBuffer(m_cells);
    destroyBuffer(m_items);
    destroyBuffer(m_boxes);
    destroyBuffer(m_planes);
    destroyBuffer(m_texInfos);
    destroyBuffer(m_texPixels);
    destroyBuffer(m_meshes);
    destroyBuffer(m_meshCells);
    destroyBuffer(m_triangles);
    destroyBuffer(m_bvhNodes);
    destroyBuffer(m_triIndices);
    destroyBuffer(m_remotePlayers);
    destroyBuffer(m_playerMesh);
    destroyBuffer(m_overlayRects);
    destroyBuffer(m_overlayState);
    destroyBuffer(m_Lights);
    destroyBuffer(m_rtSettings);
    destroyBuffer(m_rasterStaticVertices);
    destroyBuffer(m_rasterStaticIndices);
    destroyBuffer(m_rasterDynamicVertices);
    destroyBuffer(m_rasterDynamicIndices);
    destroyBuffer(m_rasterOverlayVertices);
    destroyBuffer(m_rasterOverlayIndices);
    destroyBuffer(m_rasterDustVertices);
    destroyBuffer(m_rasterDustIndices);

    if (m_particleOverlayDustPipeline) vkDestroyPipeline(m_device, m_particleOverlayDustPipeline, nullptr);
    if (m_directRasterDustPipeline) vkDestroyPipeline(m_device, m_directRasterDustPipeline, nullptr);
    if (m_rtCompositePipeline) vkDestroyPipeline(m_device, m_rtCompositePipeline, nullptr);
    if (m_rtTemporalPipeline) vkDestroyPipeline(m_device, m_rtTemporalPipeline, nullptr);
    if (m_rtSpatialPipeline) vkDestroyPipeline(m_device, m_rtSpatialPipeline, nullptr);
    if (m_rtLightingPipeline) vkDestroyPipeline(m_device, m_rtLightingPipeline, nullptr);
    if (m_pipeline) vkDestroyPipeline(m_device, m_pipeline, nullptr);
    if (m_pipelineLayout) vkDestroyPipelineLayout(m_device, m_pipelineLayout, nullptr);
    if (m_descPool) vkDestroyDescriptorPool(m_device, m_descPool, nullptr);
    if (m_descLayout) vkDestroyDescriptorSetLayout(m_device, m_descLayout, nullptr);
    if (m_renderFinished) vkDestroySemaphore(m_device, m_renderFinished, nullptr);
    if (m_imageAvailable) vkDestroySemaphore(m_device, m_imageAvailable, nullptr);
    if (m_fence) vkDestroyFence(m_device, m_fence, nullptr);
    if (m_commandPool) vkDestroyCommandPool(m_device, m_commandPool, nullptr);
    if (m_device) vkDestroyDevice(m_device, nullptr);
    if (m_surface) vkDestroySurfaceKHR(m_instance, m_surface, nullptr);
    if (m_instance) vkDestroyInstance(m_instance, nullptr);

    m_rtLightingPipeline = VK_NULL_HANDLE;
    m_rtSpatialPipeline = VK_NULL_HANDLE;
    m_rtTemporalPipeline = VK_NULL_HANDLE;
    m_rtCompositePipeline = VK_NULL_HANDLE;
    m_pipeline = VK_NULL_HANDLE;
    m_pipelineLayout = VK_NULL_HANDLE;
    m_rasterPipeline = VK_NULL_HANDLE;
    m_rasterOverlayPipeline = VK_NULL_HANDLE;
    m_rasterPipelineLayout = VK_NULL_HANDLE;
    m_rasterRenderPass = VK_NULL_HANDLE;
    m_directRasterPipeline = VK_NULL_HANDLE;
    m_directRasterOverlayPipeline = VK_NULL_HANDLE;
    m_directRasterDustPipeline = VK_NULL_HANDLE;
    m_particleOverlayDustPipeline = VK_NULL_HANDLE;
    m_directRasterPipelineLayout = VK_NULL_HANDLE;
    m_directRasterRenderPass = VK_NULL_HANDLE;
    m_particleOverlayRenderPass = VK_NULL_HANDLE;
    m_descPool = VK_NULL_HANDLE;
    m_descLayout = VK_NULL_HANDLE;
    m_fence = VK_NULL_HANDLE;
    m_imageAvailable = VK_NULL_HANDLE;
    m_renderFinished = VK_NULL_HANDLE;
    m_commandPool = VK_NULL_HANDLE;
    m_device = VK_NULL_HANDLE;
    m_surface = VK_NULL_HANDLE;
    m_swapchain = VK_NULL_HANDLE;
    m_renderImage = VK_NULL_HANDLE;
    m_renderImageMemory = VK_NULL_HANDLE;
    m_instance = VK_NULL_HANDLE;
    m_ready = false;
    m_uploadedMap = nullptr;
    m_uploadedMapVersion = 0;
}

bool VulkanComputeRenderer::resize(int width, int height)
{
    width = std::max(1, width);
    height = std::max(1, height);
    if (width == m_width && height == m_height) return true;

    m_width = width;
    m_height = height;
    updateRtResolution();
    m_rtHistoryValid = false;
    m_rtImagesInitialized = false;

    if (!m_ready) return true;

    // Resolution slider = internal render resolution only.
    // Do NOT recreate the swapchain here: doing so makes the HWND visibly flash
    // while dragging. Keep the window/swapchain fixed and only rebuild the
    // offscreen render/G-buffer/depth images that depend on m_width/m_height.
    vkDeviceWaitIdle(m_device);
    destroyRasterTargets();
    if (!createOrResizePixelBuffer()) return false;
    if (!createOrResizeRenderImage()) return false;
    if (!createOrResizeRasterTargets()) return false;
    updateDescriptorSet();
    return true;
}

bool VulkanComputeRenderer::createInstance()
{
    VkApplicationInfo app{VK_STRUCTURE_TYPE_APPLICATION_INFO};
    app.pApplicationName = "ComputeRaycaster";
    app.apiVersion = VK_API_VERSION_1_1;

    const char* exts[] = {
        VK_KHR_SURFACE_EXTENSION_NAME,
        VK_KHR_WIN32_SURFACE_EXTENSION_NAME
    };

    VkInstanceCreateInfo ci{VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO};
    ci.pApplicationInfo = &app;
    ci.enabledExtensionCount = 2;
    ci.ppEnabledExtensionNames = exts;

    VkResult r = vkCreateInstance(&ci, nullptr, &m_instance);
    if (r != VK_SUCCESS) { setError("vkCreateInstance failed"); return false; }
    return true;
}

bool VulkanComputeRenderer::createSurface(HWND hwnd)
{
    VkWin32SurfaceCreateInfoKHR sci{VK_STRUCTURE_TYPE_WIN32_SURFACE_CREATE_INFO_KHR};
    sci.hinstance = GetModuleHandleA(nullptr);
    sci.hwnd = hwnd;
    if (vkCreateWin32SurfaceKHR(m_instance, &sci, nullptr, &m_surface) != VK_SUCCESS) {
        setError("vkCreateWin32SurfaceKHR failed");
        return false;
    }
    return true;
}

bool VulkanComputeRenderer::pickPhysicalDevice()
{
    uint32_t count = 0;
    vkEnumeratePhysicalDevices(m_instance, &count, nullptr);
    if (count == 0) { setError("No Vulkan physical device found"); return false; }
    std::vector<VkPhysicalDevice> devices(count);
    vkEnumeratePhysicalDevices(m_instance, &count, devices.data());

    for (VkPhysicalDevice dev : devices) {
        uint32_t qCount = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(dev, &qCount, nullptr);
        std::vector<VkQueueFamilyProperties> queues(qCount);
        vkGetPhysicalDeviceQueueFamilyProperties(dev, &qCount, queues.data());
        for (uint32_t i = 0; i < qCount; ++i) {
            VkBool32 present = VK_FALSE;
            vkGetPhysicalDeviceSurfaceSupportKHR(dev, i, m_surface, &present);
            const bool goodQueue = (queues[i].queueFlags & VK_QUEUE_COMPUTE_BIT) &&
                                   (queues[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) && present;
            if (!goodQueue) continue;

            uint32_t fmtCount = 0;
            vkGetPhysicalDeviceSurfaceFormatsKHR(dev, m_surface, &fmtCount, nullptr);
            uint32_t modeCount = 0;
            vkGetPhysicalDeviceSurfacePresentModesKHR(dev, m_surface, &modeCount, nullptr);
            if (fmtCount == 0 || modeCount == 0) continue;

            m_physicalDevice = dev;
            m_queueFamily = i;
            return true;
        }
    }
    setError("No Vulkan queue supports compute + graphics + present");
    return false;
}

bool VulkanComputeRenderer::createDevice()
{
    float prio = 1.f;
    VkDeviceQueueCreateInfo qci{VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO};
    qci.queueFamilyIndex = m_queueFamily;
    qci.queueCount = 1;
    qci.pQueuePriorities = &prio;

    const char* exts[] = { VK_KHR_SWAPCHAIN_EXTENSION_NAME };

    VkDeviceCreateInfo dci{VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO};
    dci.queueCreateInfoCount = 1;
    dci.pQueueCreateInfos = &qci;
    dci.enabledExtensionCount = 1;
    dci.ppEnabledExtensionNames = exts;

    VkResult r = vkCreateDevice(m_physicalDevice, &dci, nullptr, &m_device);
    if (r != VK_SUCCESS) { setError("vkCreateDevice failed"); return false; }
    vkGetDeviceQueue(m_device, m_queueFamily, 0, &m_queue);
    return true;
}

bool VulkanComputeRenderer::createCommandObjects()
{
    VkCommandPoolCreateInfo pci{VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO};
    pci.queueFamilyIndex = m_queueFamily;
    pci.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    if (vkCreateCommandPool(m_device, &pci, nullptr, &m_commandPool) != VK_SUCCESS) {
        setError("vkCreateCommandPool failed"); return false;
    }

    VkCommandBufferAllocateInfo ai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
    ai.commandPool = m_commandPool;
    ai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    ai.commandBufferCount = 1;
    if (vkAllocateCommandBuffers(m_device, &ai, &m_commandBuffer) != VK_SUCCESS) {
        setError("vkAllocateCommandBuffers failed"); return false;
    }

    VkFenceCreateInfo fi{VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
    if (vkCreateFence(m_device, &fi, nullptr, &m_fence) != VK_SUCCESS) {
        setError("vkCreateFence failed"); return false;
    }
    VkSemaphoreCreateInfo sci{VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO};
    if (vkCreateSemaphore(m_device, &sci, nullptr, &m_imageAvailable) != VK_SUCCESS ||
        vkCreateSemaphore(m_device, &sci, nullptr, &m_renderFinished) != VK_SUCCESS) {
        setError("vkCreateSemaphore failed"); return false;
    }
    return true;
}

bool VulkanComputeRenderer::createDescriptorObjects()
{
    std::vector<VkDescriptorSetLayoutBinding> bindings;
    // 0..18 are SSBOs. 19..26 are storage images for the G-buffer/RT pipeline.
    for (uint32_t i = 0; i <= 18; ++i) {
        VkDescriptorSetLayoutBinding b{};
        b.binding = i;
        b.descriptorCount = 1;
        b.descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        b.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT | VK_SHADER_STAGE_VERTEX_BIT | VK_SHADER_STAGE_FRAGMENT_BIT;
        bindings.push_back(b);
    }
    for (uint32_t i = 19; i <= 26; ++i) {
        VkDescriptorSetLayoutBinding b{};
        b.binding = i;
        b.descriptorCount = 1;
        b.descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_IMAGE;
        b.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
        bindings.push_back(b);
    }

    VkDescriptorSetLayoutCreateInfo lci{VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO};
    lci.bindingCount = (uint32_t)bindings.size();
    lci.pBindings = bindings.data();
    if (vkCreateDescriptorSetLayout(m_device, &lci, nullptr, &m_descLayout) != VK_SUCCESS) {
        setError("vkCreateDescriptorSetLayout failed"); return false;
    }

    std::array<VkDescriptorPoolSize, 2> poolSizes{};
    poolSizes[0].type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSizes[0].descriptorCount = 19;
    poolSizes[1].type = VK_DESCRIPTOR_TYPE_STORAGE_IMAGE;
    poolSizes[1].descriptorCount = 8;

    VkDescriptorPoolCreateInfo pci{VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO};
    pci.maxSets = 1;
    pci.poolSizeCount = (uint32_t)poolSizes.size();
    pci.pPoolSizes = poolSizes.data();
    if (vkCreateDescriptorPool(m_device, &pci, nullptr, &m_descPool) != VK_SUCCESS) {
        setError("vkCreateDescriptorPool failed"); return false;
    }

    VkDescriptorSetAllocateInfo ai{VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO};
    ai.descriptorPool = m_descPool;
    ai.descriptorSetCount = 1;
    ai.pSetLayouts = &m_descLayout;
    if (vkAllocateDescriptorSets(m_device, &ai, &m_descSet) != VK_SUCCESS) {
        setError("vkAllocateDescriptorSets failed"); return false;
    }
    return true;
}

bool VulkanComputeRenderer::createPipeline(const char* shaderPath)
{
    std::vector<char> code = readBinaryFile(shaderPath);
    if (code.empty()) {
        code = readBinaryFile("raycast.comp.spv");
    }
    if (code.empty()) {
        setError("Missing raycast.comp.spv. Compile with: glslc shaders/raycast.comp -o shaders/raycast.comp.spv");
        return false;
    }

    VkShaderModuleCreateInfo smci{VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO};
    smci.codeSize = code.size();
    smci.pCode = reinterpret_cast<const uint32_t*>(code.data());
    VkShaderModule module = VK_NULL_HANDLE;
    if (vkCreateShaderModule(m_device, &smci, nullptr, &module) != VK_SUCCESS) {
        setError("vkCreateShaderModule failed"); return false;
    }

    VkPipelineLayoutCreateInfo plci{VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO};
    plci.setLayoutCount = 1;
    plci.pSetLayouts = &m_descLayout;
    if (vkCreatePipelineLayout(m_device, &plci, nullptr, &m_pipelineLayout) != VK_SUCCESS) {
        vkDestroyShaderModule(m_device, module, nullptr);
        setError("vkCreatePipelineLayout failed"); return false;
    }

    VkComputePipelineCreateInfo cpci{VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO};
    cpci.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    cpci.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    cpci.stage.module = module;
    cpci.stage.pName = "main";
    cpci.layout = m_pipelineLayout;

    VkResult r = vkCreateComputePipelines(m_device, VK_NULL_HANDLE, 1, &cpci, nullptr, &m_pipeline);
    vkDestroyShaderModule(m_device, module, nullptr);
    if (r != VK_SUCCESS) { setError("vkCreateComputePipelines failed"); return false; }
    return true;
}


bool VulkanComputeRenderer::createComputePipelineFromSpv(const char* shaderPath, VkPipeline& outPipeline)
{
    std::vector<char> code = readBinaryFile(shaderPath);
    if (code.empty()) {
        std::string alt = std::string("shaders/") + shaderPath;
        code = readBinaryFile(alt.c_str());
    }
    if (code.empty()) {
        setError(std::string("Missing ") + shaderPath + ". Compile with glslc before running.");
        return false;
    }

    VkShaderModuleCreateInfo smci{VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO};
    smci.codeSize = code.size();
    smci.pCode = reinterpret_cast<const uint32_t*>(code.data());
    VkShaderModule module = VK_NULL_HANDLE;
    if (vkCreateShaderModule(m_device, &smci, nullptr, &module) != VK_SUCCESS) {
        setError(std::string("vkCreateShaderModule failed for ") + shaderPath);
        return false;
    }

    VkComputePipelineCreateInfo cpci{VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO};
    cpci.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    cpci.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    cpci.stage.module = module;
    cpci.stage.pName = "main";
    cpci.layout = m_pipelineLayout;

    VkResult r = vkCreateComputePipelines(m_device, VK_NULL_HANDLE, 1, &cpci, nullptr, &outPipeline);
    vkDestroyShaderModule(m_device, module, nullptr);
    if (r != VK_SUCCESS) {
        setError(std::string("vkCreateComputePipelines failed for ") + shaderPath);
        return false;
    }
    return true;
}

bool VulkanComputeRenderer::createRtPipelines()
{
    if (!m_pipelineLayout) { setError("RT pipelines need m_pipelineLayout first"); return false; }
    if (!createComputePipelineFromSpv("rt_lighting.comp.spv",  m_rtLightingPipeline)) return false;
    if (!createComputePipelineFromSpv("rt_spatial.comp.spv",   m_rtSpatialPipeline)) return false;
    if (!createComputePipelineFromSpv("rt_temporal.comp.spv",  m_rtTemporalPipeline)) return false;
    if (!createComputePipelineFromSpv("rt_composite.comp.spv", m_rtCompositePipeline)) return false;
    std::cout << "[RT] Lighting/spatial/temporal/composite pipelines created.\n";
    return true;
}


static bool loadShaderModule(VkDevice device, const char* path, VkShaderModule& module)
{
    std::vector<char> code = readBinaryFile(path);
    if (code.empty()) return false;
    VkShaderModuleCreateInfo smci{VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO};
    smci.codeSize = code.size();
    smci.pCode = reinterpret_cast<const uint32_t*>(code.data());
    return vkCreateShaderModule(device, &smci, nullptr, &module) == VK_SUCCESS;
}

void VulkanComputeRenderer::destroyRasterPipeline()
{
    if (m_device == VK_NULL_HANDLE) return;
    if (m_rasterOverlayPipeline) vkDestroyPipeline(m_device, m_rasterOverlayPipeline, nullptr);
    if (m_rasterPipeline) vkDestroyPipeline(m_device, m_rasterPipeline, nullptr);
    if (m_rasterPipelineLayout) vkDestroyPipelineLayout(m_device, m_rasterPipelineLayout, nullptr);
    if (m_rasterRenderPass) vkDestroyRenderPass(m_device, m_rasterRenderPass, nullptr);
    m_rasterOverlayPipeline = VK_NULL_HANDLE;
    m_rasterPipeline = VK_NULL_HANDLE;
    m_rasterPipelineLayout = VK_NULL_HANDLE;
    m_rasterRenderPass = VK_NULL_HANDLE;
}

bool VulkanComputeRenderer::createRasterPipeline(const char* vertPath, const char* fragPath)
{
    if (m_swapchainFormat == VK_FORMAT_UNDEFINED) {
        setError("Cannot create raster pipeline before swapchain format is known");
        return false;
    }

    VkAttachmentDescription albedo{};
    albedo.format = RT_ALBEDO_FORMAT;
    albedo.samples = VK_SAMPLE_COUNT_1_BIT;
    albedo.loadOp = VK_ATTACHMENT_LOAD_OP_CLEAR;
    albedo.storeOp = VK_ATTACHMENT_STORE_OP_STORE;
    albedo.stencilLoadOp = VK_ATTACHMENT_LOAD_OP_DONT_CARE;
    albedo.stencilStoreOp = VK_ATTACHMENT_STORE_OP_DONT_CARE;
    albedo.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    albedo.finalLayout = VK_IMAGE_LAYOUT_GENERAL;

    VkAttachmentDescription normal = albedo;
    normal.format = RT_NORMAL_FORMAT;

    VkAttachmentDescription depthCopy = albedo;
    depthCopy.format = RT_DEPTH_FORMAT;

    VkAttachmentDescription depth{};
    depth.format = m_depthFormat;
    depth.samples = VK_SAMPLE_COUNT_1_BIT;
    depth.loadOp = VK_ATTACHMENT_LOAD_OP_CLEAR;
    // The RT dust overlay pass loads this depth attachment later, so it must be stored.
    depth.storeOp = VK_ATTACHMENT_STORE_OP_STORE;
    depth.stencilLoadOp = VK_ATTACHMENT_LOAD_OP_DONT_CARE;
    depth.stencilStoreOp = VK_ATTACHMENT_STORE_OP_DONT_CARE;
    depth.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    depth.finalLayout = VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL;

    std::array<VkAttachmentDescription, 4> attachments = { albedo, normal, depthCopy, depth };
    std::array<VkAttachmentReference, 3> colorRefs{};
    colorRefs[0] = {0, VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL};
    colorRefs[1] = {1, VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL};
    colorRefs[2] = {2, VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL};
    VkAttachmentReference depthRef{};
    depthRef.attachment = 3;
    depthRef.layout = VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL;

    VkSubpassDescription subpass{};
    subpass.pipelineBindPoint = VK_PIPELINE_BIND_POINT_GRAPHICS;
    subpass.colorAttachmentCount = (uint32_t)colorRefs.size();
    subpass.pColorAttachments = colorRefs.data();
    subpass.pDepthStencilAttachment = &depthRef;

    VkSubpassDependency dep{};
    dep.srcSubpass = VK_SUBPASS_EXTERNAL;
    dep.dstSubpass = 0;
    dep.srcStageMask = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT | VK_PIPELINE_STAGE_EARLY_FRAGMENT_TESTS_BIT;
    dep.dstStageMask = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT | VK_PIPELINE_STAGE_EARLY_FRAGMENT_TESTS_BIT;
    dep.srcAccessMask = 0;
    dep.dstAccessMask = VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT | VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT;

    VkRenderPassCreateInfo rpci{VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO};
    rpci.attachmentCount = (uint32_t)attachments.size();
    rpci.pAttachments = attachments.data();
    rpci.subpassCount = 1;
    rpci.pSubpasses = &subpass;
    rpci.dependencyCount = 1;
    rpci.pDependencies = &dep;
    if (vkCreateRenderPass(m_device, &rpci, nullptr, &m_rasterRenderPass) != VK_SUCCESS) {
        setError("vkCreateRenderPass raster failed");
        return false;
    }

    VkShaderModule vert = VK_NULL_HANDLE;
    VkShaderModule frag = VK_NULL_HANDLE;
    if (!loadShaderModule(m_device, vertPath, vert)) {
        vertPath = "shaders/raster.vert.spv";
        if (!loadShaderModule(m_device, vertPath, vert)) {
            setError("Missing raster.vert.spv. Compile raster.vert with glslc.");
            return false;
        }
    }
    if (!loadShaderModule(m_device, fragPath, frag)) {
        fragPath = "shaders/gbuffer.frag.spv";
        if (!loadShaderModule(m_device, fragPath, frag)) {
            if (vert) vkDestroyShaderModule(m_device, vert, nullptr);
            setError("Missing gbuffer.frag.spv. Compile gbuffer.frag with glslc.");
            return false;
        }
    }

    std::array<VkPipelineShaderStageCreateInfo, 2> stages{};
    stages[0].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[0].stage = VK_SHADER_STAGE_VERTEX_BIT;
    stages[0].module = vert;
    stages[0].pName = "main";
    stages[1].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[1].stage = VK_SHADER_STAGE_FRAGMENT_BIT;
    stages[1].module = frag;
    stages[1].pName = "main";

    VkVertexInputBindingDescription binding{};
    binding.binding = 0;
    binding.stride = sizeof(RasterVertex);
    binding.inputRate = VK_VERTEX_INPUT_RATE_VERTEX;

    std::array<VkVertexInputAttributeDescription, 6> attrs{};
    attrs[0] = {0, 0, VK_FORMAT_R32G32B32_SFLOAT, (uint32_t)offsetof(RasterVertex, px)};
    attrs[1] = {1, 0, VK_FORMAT_R32G32_SFLOAT,    (uint32_t)offsetof(RasterVertex, u)};
    attrs[2] = {2, 0, VK_FORMAT_R32_UINT,          (uint32_t)offsetof(RasterVertex, textureIndex)};
    attrs[3] = {3, 0, VK_FORMAT_R32_UINT,          (uint32_t)offsetof(RasterVertex, color)};
    attrs[4] = {4, 0, VK_FORMAT_R32_UINT,          (uint32_t)offsetof(RasterVertex, mode)};
    attrs[5] = {5, 0, VK_FORMAT_R32G32B32_SFLOAT, (uint32_t)offsetof(RasterVertex, nx)};

    VkPipelineVertexInputStateCreateInfo vis{VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO};
    vis.vertexBindingDescriptionCount = 1;
    vis.pVertexBindingDescriptions = &binding;
    vis.vertexAttributeDescriptionCount = (uint32_t)attrs.size();
    vis.pVertexAttributeDescriptions = attrs.data();

    VkPipelineInputAssemblyStateCreateInfo ia{VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO};
    ia.topology = VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;

    VkPipelineViewportStateCreateInfo vp{VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO};
    vp.viewportCount = 1;
    vp.scissorCount = 1;

    VkPipelineRasterizationStateCreateInfo rs{VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO};
    rs.polygonMode = VK_POLYGON_MODE_FILL;
    rs.cullMode = VK_CULL_MODE_NONE;
    rs.frontFace = VK_FRONT_FACE_COUNTER_CLOCKWISE;
    rs.lineWidth = 1.0f;

    VkPipelineMultisampleStateCreateInfo ms{VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO};
    ms.rasterizationSamples = VK_SAMPLE_COUNT_1_BIT;

    VkPipelineColorBlendAttachmentState blendOff{};
    blendOff.colorWriteMask = VK_COLOR_COMPONENT_R_BIT | VK_COLOR_COMPONENT_G_BIT |
                              VK_COLOR_COMPONENT_B_BIT | VK_COLOR_COMPONENT_A_BIT;
    blendOff.blendEnable = VK_FALSE;

    std::array<VkPipelineColorBlendAttachmentState, 3> blendOffAttachments = {blendOff, blendOff, blendOff};
    VkPipelineColorBlendStateCreateInfo cb{VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO};
    cb.attachmentCount = (uint32_t)blendOffAttachments.size();
    cb.pAttachments = blendOffAttachments.data();

    VkPipelineDepthStencilStateCreateInfo ds{VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO};
    ds.depthTestEnable = VK_TRUE;
    ds.depthWriteEnable = VK_TRUE;
    ds.depthCompareOp = VK_COMPARE_OP_LESS;

    std::array<VkDynamicState, 2> dyn = {VK_DYNAMIC_STATE_VIEWPORT, VK_DYNAMIC_STATE_SCISSOR};
    VkPipelineDynamicStateCreateInfo dynInfo{VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO};
    dynInfo.dynamicStateCount = (uint32_t)dyn.size();
    dynInfo.pDynamicStates = dyn.data();

    VkPipelineLayoutCreateInfo plci{VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO};
    plci.setLayoutCount = 1;
    plci.pSetLayouts = &m_descLayout;
    if (vkCreatePipelineLayout(m_device, &plci, nullptr, &m_rasterPipelineLayout) != VK_SUCCESS) {
        vkDestroyShaderModule(m_device, vert, nullptr);
        vkDestroyShaderModule(m_device, frag, nullptr);
        setError("vkCreatePipelineLayout raster failed");
        return false;
    }

    VkGraphicsPipelineCreateInfo gpci{VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO};
    gpci.stageCount = (uint32_t)stages.size();
    gpci.pStages = stages.data();
    gpci.pVertexInputState = &vis;
    gpci.pInputAssemblyState = &ia;
    gpci.pViewportState = &vp;
    gpci.pRasterizationState = &rs;
    gpci.pMultisampleState = &ms;
    gpci.pDepthStencilState = &ds;
    gpci.pColorBlendState = &cb;
    gpci.pDynamicState = &dynInfo;
    gpci.layout = m_rasterPipelineLayout;
    gpci.renderPass = m_rasterRenderPass;
    gpci.subpass = 0;

    VkResult r = vkCreateGraphicsPipelines(m_device, VK_NULL_HANDLE, 1, &gpci, nullptr, &m_rasterPipeline);
    if (r != VK_SUCCESS) {
        vkDestroyShaderModule(m_device, vert, nullptr);
        vkDestroyShaderModule(m_device, frag, nullptr);
        setError("vkCreateGraphicsPipelines raster scene failed");
        return false;
    }

    VkPipelineColorBlendAttachmentState blendOn = blendOff;
    blendOn.blendEnable = VK_TRUE;
    blendOn.srcColorBlendFactor = VK_BLEND_FACTOR_SRC_ALPHA;
    blendOn.dstColorBlendFactor = VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA;
    blendOn.colorBlendOp = VK_BLEND_OP_ADD;
    blendOn.srcAlphaBlendFactor = VK_BLEND_FACTOR_ONE;
    blendOn.dstAlphaBlendFactor = VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA;
    blendOn.alphaBlendOp = VK_BLEND_OP_ADD;
    std::array<VkPipelineColorBlendAttachmentState, 3> blendOnAttachments = {blendOn, blendOff, blendOff};
    cb.pAttachments = blendOnAttachments.data();

    VkPipelineDepthStencilStateCreateInfo overlayDs{VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO};
    overlayDs.depthTestEnable = VK_FALSE;
    overlayDs.depthWriteEnable = VK_FALSE;
    overlayDs.depthCompareOp = VK_COMPARE_OP_ALWAYS;
    gpci.pDepthStencilState = &overlayDs;
    r = vkCreateGraphicsPipelines(m_device, VK_NULL_HANDLE, 1, &gpci, nullptr, &m_rasterOverlayPipeline);

    vkDestroyShaderModule(m_device, vert, nullptr);
    vkDestroyShaderModule(m_device, frag, nullptr);

    if (r != VK_SUCCESS) {
        setError("vkCreateGraphicsPipelines raster overlay failed");
        return false;
    }
    return true;
}

void VulkanComputeRenderer::destroyDirectRasterPipeline()
{
    if (m_device == VK_NULL_HANDLE) return;
    if (m_particleOverlayDustPipeline) vkDestroyPipeline(m_device, m_particleOverlayDustPipeline, nullptr);
    if (m_directRasterDustPipeline) vkDestroyPipeline(m_device, m_directRasterDustPipeline, nullptr);
    if (m_directRasterOverlayPipeline) vkDestroyPipeline(m_device, m_directRasterOverlayPipeline, nullptr);
    if (m_directRasterPipeline) vkDestroyPipeline(m_device, m_directRasterPipeline, nullptr);
    if (m_directRasterPipelineLayout) vkDestroyPipelineLayout(m_device, m_directRasterPipelineLayout, nullptr);
    if (m_particleOverlayRenderPass) vkDestroyRenderPass(m_device, m_particleOverlayRenderPass, nullptr);
    if (m_directRasterRenderPass) vkDestroyRenderPass(m_device, m_directRasterRenderPass, nullptr);
    m_particleOverlayDustPipeline = VK_NULL_HANDLE;
    m_directRasterDustPipeline = VK_NULL_HANDLE;
    m_directRasterOverlayPipeline = VK_NULL_HANDLE;
    m_directRasterPipeline = VK_NULL_HANDLE;
    m_directRasterPipelineLayout = VK_NULL_HANDLE;
    m_particleOverlayRenderPass = VK_NULL_HANDLE;
    m_directRasterRenderPass = VK_NULL_HANDLE;
}

bool VulkanComputeRenderer::createDirectRasterPipeline(const char* vertPath, const char* fragPath)
{
    if (m_swapchainFormat == VK_FORMAT_UNDEFINED) {
        setError("Cannot create direct raster pipeline before swapchain format is known");
        return false;
    }

    VkAttachmentDescription color{};
    color.format = m_swapchainFormat;
    color.samples = VK_SAMPLE_COUNT_1_BIT;
    color.loadOp = VK_ATTACHMENT_LOAD_OP_CLEAR;
    color.storeOp = VK_ATTACHMENT_STORE_OP_STORE;
    color.stencilLoadOp = VK_ATTACHMENT_LOAD_OP_DONT_CARE;
    color.stencilStoreOp = VK_ATTACHMENT_STORE_OP_DONT_CARE;
    // Direct RT-OFF path now renders into an internal offscreen image and then
    // blits that image to the swapchain.
    color.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    color.finalLayout = VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;

    VkAttachmentDescription depth{};
    depth.format = m_depthFormat;
    depth.samples = VK_SAMPLE_COUNT_1_BIT;
    depth.loadOp = VK_ATTACHMENT_LOAD_OP_CLEAR;
    depth.storeOp = VK_ATTACHMENT_STORE_OP_DONT_CARE;
    depth.stencilLoadOp = VK_ATTACHMENT_LOAD_OP_DONT_CARE;
    depth.stencilStoreOp = VK_ATTACHMENT_STORE_OP_DONT_CARE;
    depth.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    depth.finalLayout = VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL;

    std::array<VkAttachmentDescription, 2> attachments = { color, depth };
    VkAttachmentReference colorRef{0, VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL};
    VkAttachmentReference depthRef{1, VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL};

    VkSubpassDescription subpass{};
    subpass.pipelineBindPoint = VK_PIPELINE_BIND_POINT_GRAPHICS;
    subpass.colorAttachmentCount = 1;
    subpass.pColorAttachments = &colorRef;
    subpass.pDepthStencilAttachment = &depthRef;

    std::array<VkSubpassDependency, 2> deps{};
    deps[0].srcSubpass = VK_SUBPASS_EXTERNAL;
    deps[0].dstSubpass = 0;
    deps[0].srcStageMask = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT | VK_PIPELINE_STAGE_EARLY_FRAGMENT_TESTS_BIT;
    deps[0].dstStageMask = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT | VK_PIPELINE_STAGE_EARLY_FRAGMENT_TESTS_BIT;
    deps[0].srcAccessMask = 0;
    deps[0].dstAccessMask = VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT | VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT;

    deps[1].srcSubpass = 0;
    deps[1].dstSubpass = VK_SUBPASS_EXTERNAL;
    deps[1].srcStageMask = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    deps[1].dstStageMask = VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT;
    deps[1].srcAccessMask = VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT;
    deps[1].dstAccessMask = 0;

    VkRenderPassCreateInfo rpci{VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO};
    rpci.attachmentCount = (uint32_t)attachments.size();
    rpci.pAttachments = attachments.data();
    rpci.subpassCount = 1;
    rpci.pSubpasses = &subpass;
    rpci.dependencyCount = (uint32_t)deps.size();
    rpci.pDependencies = deps.data();
    if (vkCreateRenderPass(m_device, &rpci, nullptr, &m_directRasterRenderPass) != VK_SUCCESS) {
        setError("vkCreateRenderPass direct raster failed");
        return false;
    }

    // RT mode composes into m_renderImage, then this pass loads that color and
    // draws only the cheap game-style dust motes over it.  Depth is loaded from
    // the scene depth attachment so motes fade/reject correctly behind walls.
    VkAttachmentDescription particleColor = color;
    particleColor.loadOp = VK_ATTACHMENT_LOAD_OP_LOAD;
    particleColor.initialLayout = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;
    particleColor.finalLayout = VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;

    VkAttachmentDescription particleDepth = depth;
    particleDepth.loadOp = VK_ATTACHMENT_LOAD_OP_LOAD;
    particleDepth.storeOp = VK_ATTACHMENT_STORE_OP_DONT_CARE;
    particleDepth.initialLayout = VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL;
    particleDepth.finalLayout = VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL;

    std::array<VkAttachmentDescription, 2> particleAttachments = { particleColor, particleDepth };
    VkSubpassDescription particleSubpass = subpass;
    std::array<VkSubpassDependency, 2> particleDeps{};
    particleDeps[0].srcSubpass = VK_SUBPASS_EXTERNAL;
    particleDeps[0].dstSubpass = 0;
    particleDeps[0].srcStageMask = VK_PIPELINE_STAGE_TRANSFER_BIT | VK_PIPELINE_STAGE_EARLY_FRAGMENT_TESTS_BIT | VK_PIPELINE_STAGE_LATE_FRAGMENT_TESTS_BIT;
    particleDeps[0].dstStageMask = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT | VK_PIPELINE_STAGE_EARLY_FRAGMENT_TESTS_BIT;
    particleDeps[0].srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT | VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_WRITE_BIT;
    particleDeps[0].dstAccessMask = VK_ACCESS_COLOR_ATTACHMENT_READ_BIT | VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT | VK_ACCESS_DEPTH_STENCIL_ATTACHMENT_READ_BIT;
    particleDeps[1].srcSubpass = 0;
    particleDeps[1].dstSubpass = VK_SUBPASS_EXTERNAL;
    particleDeps[1].srcStageMask = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    particleDeps[1].dstStageMask = VK_PIPELINE_STAGE_TRANSFER_BIT;
    particleDeps[1].srcAccessMask = VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT;
    particleDeps[1].dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT;

    VkRenderPassCreateInfo prpci{VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO};
    prpci.attachmentCount = (uint32_t)particleAttachments.size();
    prpci.pAttachments = particleAttachments.data();
    prpci.subpassCount = 1;
    prpci.pSubpasses = &particleSubpass;
    prpci.dependencyCount = (uint32_t)particleDeps.size();
    prpci.pDependencies = particleDeps.data();
    if (vkCreateRenderPass(m_device, &prpci, nullptr, &m_particleOverlayRenderPass) != VK_SUCCESS) {
        setError("vkCreateRenderPass particle overlay failed");
        return false;
    }

    VkShaderModule vert = VK_NULL_HANDLE;
    VkShaderModule frag = VK_NULL_HANDLE;
    if (!loadShaderModule(m_device, vertPath, vert)) {
        vertPath = "shaders/raster.vert.spv";
        if (!loadShaderModule(m_device, vertPath, vert)) {
            setError("Missing raster.vert.spv. Compile raster.vert with glslc.");
            return false;
        }
    }
    if (!loadShaderModule(m_device, fragPath, frag)) {
        fragPath = "shaders/raster.frag.spv";
        if (!loadShaderModule(m_device, fragPath, frag)) {
            if (vert) vkDestroyShaderModule(m_device, vert, nullptr);
            setError("Missing raster.frag.spv. Compile raster.frag with glslc.");
            return false;
        }
    }

    std::array<VkPipelineShaderStageCreateInfo, 2> stages{};
    stages[0].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[0].stage = VK_SHADER_STAGE_VERTEX_BIT;
    stages[0].module = vert;
    stages[0].pName = "main";
    stages[1].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[1].stage = VK_SHADER_STAGE_FRAGMENT_BIT;
    stages[1].module = frag;
    stages[1].pName = "main";

    VkVertexInputBindingDescription binding{};
    binding.binding = 0;
    binding.stride = sizeof(RasterVertex);
    binding.inputRate = VK_VERTEX_INPUT_RATE_VERTEX;

    std::array<VkVertexInputAttributeDescription, 6> attrs{};
    attrs[0] = {0, 0, VK_FORMAT_R32G32B32_SFLOAT, (uint32_t)offsetof(RasterVertex, px)};
    attrs[1] = {1, 0, VK_FORMAT_R32G32_SFLOAT,    (uint32_t)offsetof(RasterVertex, u)};
    attrs[2] = {2, 0, VK_FORMAT_R32_UINT,          (uint32_t)offsetof(RasterVertex, textureIndex)};
    attrs[3] = {3, 0, VK_FORMAT_R32_UINT,          (uint32_t)offsetof(RasterVertex, color)};
    attrs[4] = {4, 0, VK_FORMAT_R32_UINT,          (uint32_t)offsetof(RasterVertex, mode)};
    attrs[5] = {5, 0, VK_FORMAT_R32G32B32_SFLOAT, (uint32_t)offsetof(RasterVertex, nx)};

    VkPipelineVertexInputStateCreateInfo vis{VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO};
    vis.vertexBindingDescriptionCount = 1;
    vis.pVertexBindingDescriptions = &binding;
    vis.vertexAttributeDescriptionCount = (uint32_t)attrs.size();
    vis.pVertexAttributeDescriptions = attrs.data();

    VkPipelineInputAssemblyStateCreateInfo ia{VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO};
    ia.topology = VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;

    VkPipelineViewportStateCreateInfo vp{VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO};
    vp.viewportCount = 1;
    vp.scissorCount = 1;

    VkPipelineRasterizationStateCreateInfo rs{VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO};
    rs.polygonMode = VK_POLYGON_MODE_FILL;
    rs.cullMode = VK_CULL_MODE_NONE;
    rs.frontFace = VK_FRONT_FACE_COUNTER_CLOCKWISE;
    rs.lineWidth = 1.0f;

    VkPipelineMultisampleStateCreateInfo ms{VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO};
    ms.rasterizationSamples = VK_SAMPLE_COUNT_1_BIT;

    VkPipelineColorBlendAttachmentState blendOff{};
    blendOff.colorWriteMask = VK_COLOR_COMPONENT_R_BIT | VK_COLOR_COMPONENT_G_BIT |
                              VK_COLOR_COMPONENT_B_BIT | VK_COLOR_COMPONENT_A_BIT;
    blendOff.blendEnable = VK_FALSE;

    VkPipelineColorBlendStateCreateInfo cb{VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO};
    cb.attachmentCount = 1;
    cb.pAttachments = &blendOff;

    VkPipelineDepthStencilStateCreateInfo ds{VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO};
    ds.depthTestEnable = VK_TRUE;
    ds.depthWriteEnable = VK_TRUE;
    ds.depthCompareOp = VK_COMPARE_OP_LESS;

    std::array<VkDynamicState, 2> dyn = {VK_DYNAMIC_STATE_VIEWPORT, VK_DYNAMIC_STATE_SCISSOR};
    VkPipelineDynamicStateCreateInfo dynInfo{VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO};
    dynInfo.dynamicStateCount = (uint32_t)dyn.size();
    dynInfo.pDynamicStates = dyn.data();

    VkPipelineLayoutCreateInfo plci{VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO};
    plci.setLayoutCount = 1;
    plci.pSetLayouts = &m_descLayout;
    if (vkCreatePipelineLayout(m_device, &plci, nullptr, &m_directRasterPipelineLayout) != VK_SUCCESS) {
        vkDestroyShaderModule(m_device, vert, nullptr);
        vkDestroyShaderModule(m_device, frag, nullptr);
        setError("vkCreatePipelineLayout direct raster failed");
        return false;
    }

    VkGraphicsPipelineCreateInfo gpci{VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO};
    gpci.stageCount = (uint32_t)stages.size();
    gpci.pStages = stages.data();
    gpci.pVertexInputState = &vis;
    gpci.pInputAssemblyState = &ia;
    gpci.pViewportState = &vp;
    gpci.pRasterizationState = &rs;
    gpci.pMultisampleState = &ms;
    gpci.pDepthStencilState = &ds;
    gpci.pColorBlendState = &cb;
    gpci.pDynamicState = &dynInfo;
    gpci.layout = m_directRasterPipelineLayout;
    gpci.renderPass = m_directRasterRenderPass;
    gpci.subpass = 0;

    VkResult r = vkCreateGraphicsPipelines(m_device, VK_NULL_HANDLE, 1, &gpci, nullptr, &m_directRasterPipeline);
    if (r != VK_SUCCESS) {
        vkDestroyShaderModule(m_device, vert, nullptr);
        vkDestroyShaderModule(m_device, frag, nullptr);
        setError("vkCreateGraphicsPipelines direct raster scene failed");
        return false;
    }

    VkPipelineColorBlendAttachmentState blendOn = blendOff;
    blendOn.blendEnable = VK_TRUE;
    blendOn.srcColorBlendFactor = VK_BLEND_FACTOR_SRC_ALPHA;
    blendOn.dstColorBlendFactor = VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA;
    blendOn.colorBlendOp = VK_BLEND_OP_ADD;
    blendOn.srcAlphaBlendFactor = VK_BLEND_FACTOR_ONE;
    blendOn.dstAlphaBlendFactor = VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA;
    blendOn.alphaBlendOp = VK_BLEND_OP_ADD;
    cb.pAttachments = &blendOn;

    VkPipelineDepthStencilStateCreateInfo overlayDs{VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO};
    overlayDs.depthTestEnable = VK_FALSE;
    overlayDs.depthWriteEnable = VK_FALSE;
    overlayDs.depthCompareOp = VK_COMPARE_OP_ALWAYS;
    gpci.pDepthStencilState = &overlayDs;
    r = vkCreateGraphicsPipelines(m_device, VK_NULL_HANDLE, 1, &gpci, nullptr, &m_directRasterOverlayPipeline);
    if (r != VK_SUCCESS) {
        vkDestroyShaderModule(m_device, vert, nullptr);
        vkDestroyShaderModule(m_device, frag, nullptr);
        setError("vkCreateGraphicsPipelines direct raster overlay failed");
        return false;
    }

    // Cheap dust motes: additive, depth-tested, no depth writes.  These are
    // tiny camera-facing triangles, not full volumetric grid rendering.
    VkPipelineColorBlendAttachmentState dustBlend = blendOff;
    dustBlend.blendEnable = VK_TRUE;
    dustBlend.srcColorBlendFactor = VK_BLEND_FACTOR_SRC_ALPHA;
    dustBlend.dstColorBlendFactor = VK_BLEND_FACTOR_ONE;
    dustBlend.colorBlendOp = VK_BLEND_OP_ADD;
    dustBlend.srcAlphaBlendFactor = VK_BLEND_FACTOR_ONE;
    dustBlend.dstAlphaBlendFactor = VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA;
    dustBlend.alphaBlendOp = VK_BLEND_OP_ADD;
    cb.pAttachments = &dustBlend;

    VkPipelineDepthStencilStateCreateInfo dustDs{VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO};
    dustDs.depthTestEnable = VK_TRUE;
    dustDs.depthWriteEnable = VK_FALSE;
    dustDs.depthCompareOp = VK_COMPARE_OP_LESS_OR_EQUAL;
    gpci.pDepthStencilState = &dustDs;

    gpci.renderPass = m_directRasterRenderPass;
    r = vkCreateGraphicsPipelines(m_device, VK_NULL_HANDLE, 1, &gpci, nullptr, &m_directRasterDustPipeline);
    if (r != VK_SUCCESS) {
        vkDestroyShaderModule(m_device, vert, nullptr);
        vkDestroyShaderModule(m_device, frag, nullptr);
        setError("vkCreateGraphicsPipelines direct raster dust failed");
        return false;
    }

    gpci.renderPass = m_particleOverlayRenderPass;
    r = vkCreateGraphicsPipelines(m_device, VK_NULL_HANDLE, 1, &gpci, nullptr, &m_particleOverlayDustPipeline);

    vkDestroyShaderModule(m_device, vert, nullptr);
    vkDestroyShaderModule(m_device, frag, nullptr);

    if (r != VK_SUCCESS) {
        setError("vkCreateGraphicsPipelines particle overlay dust failed");
        return false;
    }

    std::cout << "[RasterDirect] direct raster + light-cone dust pipelines ready;\n";
    return true;
}

bool VulkanComputeRenderer::createImageView(VkImage image, VkFormat format, VkImageAspectFlags aspect,
                                            VkImageView& outView)
{
    VkImageViewCreateInfo ivci{VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO};
    ivci.image = image;
    ivci.viewType = VK_IMAGE_VIEW_TYPE_2D;
    ivci.format = format;
    ivci.subresourceRange.aspectMask = aspect;
    ivci.subresourceRange.baseMipLevel = 0;
    ivci.subresourceRange.levelCount = 1;
    ivci.subresourceRange.baseArrayLayer = 0;
    ivci.subresourceRange.layerCount = 1;
    if (vkCreateImageView(m_device, &ivci, nullptr, &outView) != VK_SUCCESS) {
        setError("vkCreateImageView failed");
        return false;
    }
    return true;
}

void VulkanComputeRenderer::destroyRtImage(RtImage& img)
{
    if (m_device == VK_NULL_HANDLE) return;
    if (img.view) vkDestroyImageView(m_device, img.view, nullptr);
    img.view = VK_NULL_HANDLE;
    destroyImage(img.image, img.memory);
    img.format = VK_FORMAT_UNDEFINED;
}

bool VulkanComputeRenderer::createRtImage(RtImage& out, VkFormat format, VkImageUsageFlags usage, const char* debugName,
                                           uint32_t width, uint32_t height)
{
    destroyRtImage(out);
    out.format = format;

    const uint32_t imageW = width ? width : (uint32_t)std::max(1, m_width);
    const uint32_t imageH = height ? height : (uint32_t)std::max(1, m_height);

    VkImageCreateInfo ici{VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO};
    ici.imageType = VK_IMAGE_TYPE_2D;
    ici.format = format;
    ici.extent = { imageW, imageH, 1 };
    ici.mipLevels = 1;
    ici.arrayLayers = 1;
    ici.samples = VK_SAMPLE_COUNT_1_BIT;
    ici.tiling = VK_IMAGE_TILING_OPTIMAL;
    ici.usage = usage;
    ici.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    ici.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;

    if (vkCreateImage(m_device, &ici, nullptr, &out.image) != VK_SUCCESS) {
        setError(std::string("vkCreateImage failed for ") + debugName);
        return false;
    }
    VkMemoryRequirements req{};
    vkGetImageMemoryRequirements(m_device, out.image, &req);
    uint32_t mt = findMemoryType(req.memoryTypeBits, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
    if (mt == UINT32_MAX) { setError(std::string("No device-local memory for ") + debugName); return false; }
    VkMemoryAllocateInfo mai{VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO};
    mai.allocationSize = req.size;
    mai.memoryTypeIndex = mt;
    if (vkAllocateMemory(m_device, &mai, nullptr, &out.memory) != VK_SUCCESS) {
        setError(std::string("vkAllocateMemory failed for ") + debugName);
        return false;
    }
    if (vkBindImageMemory(m_device, out.image, out.memory, 0) != VK_SUCCESS) {
        setError(std::string("vkBindImageMemory failed for ") + debugName);
        return false;
    }
    if (!createImageView(out.image, format, VK_IMAGE_ASPECT_COLOR_BIT, out.view)) {
        setError(std::string("vkCreateImageView failed for ") + debugName);
        return false;
    }
    std::cout << "[RT] image " << debugName << " created "
              << ici.extent.width << "x" << ici.extent.height << " format=" << (int)format << "\n";
    m_descriptorSetDirty = true;
    return true;
}

void VulkanComputeRenderer::destroyRasterTargets()
{
    if (m_device == VK_NULL_HANDLE) return;
    for (VkFramebuffer fb : m_rasterFramebuffers) {
        if (fb && fb != m_gbufferFramebuffer && fb != m_directRasterFramebuffer && fb != m_particleOverlayFramebuffer) vkDestroyFramebuffer(m_device, fb, nullptr);
    }
    m_rasterFramebuffers.clear();

    if (m_directRasterFramebuffer) vkDestroyFramebuffer(m_device, m_directRasterFramebuffer, nullptr);
    m_directRasterFramebuffer = VK_NULL_HANDLE;

    if (m_particleOverlayFramebuffer) vkDestroyFramebuffer(m_device, m_particleOverlayFramebuffer, nullptr);
    m_particleOverlayFramebuffer = VK_NULL_HANDLE;

    if (m_gbufferFramebuffer) vkDestroyFramebuffer(m_device, m_gbufferFramebuffer, nullptr);
    m_gbufferFramebuffer = VK_NULL_HANDLE;

    for (VkImageView view : m_swapchainImageViews) {
        if (view) vkDestroyImageView(m_device, view, nullptr);
    }
    m_swapchainImageViews.clear();

    destroyRtImage(m_gbufferAlbedo);
    destroyRtImage(m_gbufferNormal);
    destroyRtImage(m_gbufferDepth);
    destroyRtImage(m_rtLightingRaw);
    destroyRtImage(m_rtLightingFiltered);
    destroyRtImage(m_rtHistoryA);
    destroyRtImage(m_rtHistoryB);
    destroyRtImage(m_rtComposite);

    if (m_depthImageView) vkDestroyImageView(m_device, m_depthImageView, nullptr);
    m_depthImageView = VK_NULL_HANDLE;
    destroyImage(m_depthImage, m_depthImageMemory);
    m_rtHistoryValid = false;
    m_rtImagesInitialized = false;
    m_descriptorSetDirty = true;
}

bool VulkanComputeRenderer::createOrResizeRasterTargets()
{
    if (!m_rasterRenderPass || !m_directRasterRenderPass || !m_swapchain || m_swapchainImages.empty()) return true;

    updateRtResolution();
    const uint32_t fullW = (uint32_t)std::max(1, m_width);
    const uint32_t fullH = (uint32_t)std::max(1, m_height);
    const uint32_t rtW = (uint32_t)std::max(1, m_rtWidth);
    const uint32_t rtH = (uint32_t)std::max(1, m_rtHeight);

    destroyRasterTargets();

    const VkImageUsageFlags gbufferUsage =
        VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | VK_IMAGE_USAGE_STORAGE_BIT |
        VK_IMAGE_USAGE_TRANSFER_SRC_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT;
    const VkImageUsageFlags rtUsage =
        VK_IMAGE_USAGE_STORAGE_BIT | VK_IMAGE_USAGE_TRANSFER_SRC_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT;

    // G-buffer stays at real internal render resolution.  Only the expensive
    // RT lighting images are scaled by the RT quality slider.
    if (!createRtImage(m_gbufferAlbedo, RT_ALBEDO_FORMAT, gbufferUsage, "gbufferAlbedo", fullW, fullH)) return false;
    if (!createRtImage(m_gbufferNormal, RT_NORMAL_FORMAT, gbufferUsage, "gbufferNormal", fullW, fullH)) return false;
    if (!createRtImage(m_gbufferDepth,  RT_DEPTH_FORMAT,  gbufferUsage, "gbufferDepth",  fullW, fullH)) return false;
    if (!createRtImage(m_rtLightingRaw,      RT_LIGHT_FORMAT, rtUsage, "rtLightingRaw",      rtW, rtH)) return false;
    if (!createRtImage(m_rtLightingFiltered, RT_LIGHT_FORMAT, rtUsage, "rtLightingFiltered", rtW, rtH)) return false;
    if (!createRtImage(m_rtHistoryA,         RT_LIGHT_FORMAT, rtUsage, "rtHistoryA",         rtW, rtH)) return false;
    if (!createRtImage(m_rtHistoryB,         RT_LIGHT_FORMAT, rtUsage, "rtHistoryB",         rtW, rtH)) return false;
    if (!createRtImage(m_rtComposite,        RT_ALBEDO_FORMAT, rtUsage, "rtComposite",        fullW, fullH)) return false;

    VkImageCreateInfo dici{VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO};
    dici.imageType = VK_IMAGE_TYPE_2D;
    dici.format = m_depthFormat;
    dici.extent = {fullW, fullH, 1};
    dici.mipLevels = 1;
    dici.arrayLayers = 1;
    dici.samples = VK_SAMPLE_COUNT_1_BIT;
    dici.tiling = VK_IMAGE_TILING_OPTIMAL;
    dici.usage = VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT;
    dici.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    dici.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;

    if (vkCreateImage(m_device, &dici, nullptr, &m_depthImage) != VK_SUCCESS) {
        setError("vkCreateImage depth failed");
        return false;
    }
    VkMemoryRequirements req{};
    vkGetImageMemoryRequirements(m_device, m_depthImage, &req);
    uint32_t mt = findMemoryType(req.memoryTypeBits, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
    if (mt == UINT32_MAX) { setError("No device-local depth memory type"); return false; }
    VkMemoryAllocateInfo mai{VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO};
    mai.allocationSize = req.size;
    mai.memoryTypeIndex = mt;
    if (vkAllocateMemory(m_device, &mai, nullptr, &m_depthImageMemory) != VK_SUCCESS) {
        setError("vkAllocateMemory depth failed");
        return false;
    }
    if (vkBindImageMemory(m_device, m_depthImage, m_depthImageMemory, 0) != VK_SUCCESS) {
        setError("vkBindImageMemory depth failed");
        return false;
    }
    if (!createImageView(m_depthImage, m_depthFormat, VK_IMAGE_ASPECT_DEPTH_BIT, m_depthImageView)) return false;

    std::array<VkImageView, 4> atts = {m_gbufferAlbedo.view, m_gbufferNormal.view, m_gbufferDepth.view, m_depthImageView};
    VkFramebufferCreateInfo fbci{VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO};
    fbci.renderPass = m_rasterRenderPass;
    fbci.attachmentCount = (uint32_t)atts.size();
    fbci.pAttachments = atts.data();
    fbci.width = fullW;
    fbci.height = fullH;
    fbci.layers = 1;
    if (vkCreateFramebuffer(m_device, &fbci, nullptr, &m_gbufferFramebuffer) != VK_SUCCESS) {
        setError("vkCreateFramebuffer gbuffer failed");
        return false;
    }

    std::array<VkImageView, 2> directAtts = {m_renderImageView, m_depthImageView};
    VkFramebufferCreateInfo directFbci{VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO};
    directFbci.renderPass = m_directRasterRenderPass;
    directFbci.attachmentCount = (uint32_t)directAtts.size();
    directFbci.pAttachments = directAtts.data();
    directFbci.width = fullW;
    directFbci.height = fullH;
    directFbci.layers = 1;
    if (vkCreateFramebuffer(m_device, &directFbci, nullptr, &m_directRasterFramebuffer) != VK_SUCCESS) {
        setError("vkCreateFramebuffer direct raster failed");
        return false;
    }

    if (m_particleOverlayRenderPass != VK_NULL_HANDLE) {
        std::array<VkImageView, 2> particleAtts = {m_renderImageView, m_depthImageView};
        VkFramebufferCreateInfo particleFbci{VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO};
        particleFbci.renderPass = m_particleOverlayRenderPass;
        particleFbci.attachmentCount = (uint32_t)particleAtts.size();
        particleFbci.pAttachments = particleAtts.data();
        particleFbci.width = fullW;
        particleFbci.height = fullH;
        particleFbci.layers = 1;
        if (vkCreateFramebuffer(m_device, &particleFbci, nullptr, &m_particleOverlayFramebuffer) != VK_SUCCESS) {
            setError("vkCreateFramebuffer particle overlay failed");
            return false;
        }
    }

    m_rtHistoryValid = false;
    m_rtLastWidth = m_rtWidth;
    m_rtLastHeight = m_rtHeight;
    m_descriptorSetDirty = true;
    std::cout << "[Raster] internal targets ready for " << fullW << "x" << fullH
              << ", RT lighting " << rtW << "x" << rtH
              << " -> swapchain " << m_swapchainExtent.width << "x" << m_swapchainExtent.height << "\n";
    return true;
}

uint32_t VulkanComputeRenderer::findMemoryType(uint32_t typeBits, VkMemoryPropertyFlags props) const
{
    VkPhysicalDeviceMemoryProperties mem{};
    vkGetPhysicalDeviceMemoryProperties(m_physicalDevice, &mem);
    for (uint32_t i = 0; i < mem.memoryTypeCount; ++i) {
        if ((typeBits & (1u << i)) && ((mem.memoryTypes[i].propertyFlags & props) == props)) return i;
    }
    return UINT32_MAX;
}

bool VulkanComputeRenderer::createBuffer(VkDeviceSize size, VkBufferUsageFlags usage,
                                         VkMemoryPropertyFlags properties, Buffer& out)
{
    if (size == 0) size = 16;
    destroyBuffer(out);

    VkBufferCreateInfo bci{VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO};
    bci.size = size;
    bci.usage = usage;
    bci.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    if (vkCreateBuffer(m_device, &bci, nullptr, &out.buffer) != VK_SUCCESS) {
        setError("vkCreateBuffer failed"); return false;
    }

    VkMemoryRequirements req{};
    vkGetBufferMemoryRequirements(m_device, out.buffer, &req);
    uint32_t mt = findMemoryType(req.memoryTypeBits, properties);
    if (mt == UINT32_MAX) { setError("No suitable Vulkan memory type"); return false; }

    VkMemoryAllocateInfo mai{VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO};
    mai.allocationSize = req.size;
    mai.memoryTypeIndex = mt;
    if (vkAllocateMemory(m_device, &mai, nullptr, &out.memory) != VK_SUCCESS) {
        setError("vkAllocateMemory failed"); return false;
    }
    if (vkBindBufferMemory(m_device, out.buffer, out.memory, 0) != VK_SUCCESS) {
        setError("vkBindBufferMemory failed"); return false;
    }
    out.size = size;
    m_descriptorSetDirty = true;
    return true;
}

void VulkanComputeRenderer::destroyBuffer(Buffer& b)
{
    if (m_device == VK_NULL_HANDLE) return;
    if (b.buffer) vkDestroyBuffer(m_device, b.buffer, nullptr);
    if (b.memory) vkFreeMemory(m_device, b.memory, nullptr);
    b.buffer = VK_NULL_HANDLE;
    b.memory = VK_NULL_HANDLE;
    b.size = 0;
}

bool VulkanComputeRenderer::mapCopy(Buffer& b, const void* data, VkDeviceSize size)
{
    if (size == 0) size = 16;
    void* ptr = nullptr;
    if (vkMapMemory(m_device, b.memory, 0, size, 0, &ptr) != VK_SUCCESS) {
        setError("vkMapMemory failed"); return false;
    }
    if (data) std::memcpy(ptr, data, (size_t)size);
    else std::memset(ptr, 0, (size_t)size);
    vkUnmapMemory(m_device, b.memory);
    return true;
}

bool VulkanComputeRenderer::uploadBuffer(Buffer& b, const void* data, VkDeviceSize size,
                                         VkBufferUsageFlags usage)
{
    if (size == 0) size = 16;
    // Do not destroy/recreate the buffer just because this frame writes fewer
    // bytes than a previous frame. Reallocation every frame is extremely visible
    // in raster benchmarks. Keep the larger allocation and update only the
    // written prefix.
    if (b.buffer == VK_NULL_HANDLE || b.size < size) {
        if (!createBuffer(size, usage,
            VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, b)) return false;
    }
    return mapCopy(b, data, size);
}

bool VulkanComputeRenderer::readBuffer(const Buffer& b, void* dst, VkDeviceSize size)
{
    void* ptr = nullptr;
    if (vkMapMemory(m_device, b.memory, 0, size, 0, &ptr) != VK_SUCCESS) {
        setError("vkMapMemory read failed"); return false;
    }
    std::memcpy(dst, ptr, (size_t)size);
    vkUnmapMemory(m_device, b.memory);
    return true;
}

bool VulkanComputeRenderer::createOrResizePixelBuffer()
{
    const VkDeviceSize bytes = (VkDeviceSize)m_width * (VkDeviceSize)m_height * sizeof(uint32_t);
    bool ok = createBuffer(bytes,
        VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
        VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,
        m_pixels);
    if (ok) updateDescriptorSet();
    return ok;
}

void VulkanComputeRenderer::destroyImage(VkImage& image, VkDeviceMemory& memory)
{
    if (m_device == VK_NULL_HANDLE) return;
    if (image) vkDestroyImage(m_device, image, nullptr);
    if (memory) vkFreeMemory(m_device, memory, nullptr);
    image = VK_NULL_HANDLE;
    memory = VK_NULL_HANDLE;
}

bool VulkanComputeRenderer::createOrResizeRenderImage()
{
    if (m_renderImageView) vkDestroyImageView(m_device, m_renderImageView, nullptr);
    m_renderImageView = VK_NULL_HANDLE;
    destroyImage(m_renderImage, m_renderImageMemory);

    VkImageCreateInfo ici{VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO};
    ici.imageType = VK_IMAGE_TYPE_2D;
    ici.format = VK_FORMAT_B8G8R8A8_UNORM;
    ici.extent = { (uint32_t)std::max(1, m_width), (uint32_t)std::max(1, m_height), 1 };
    ici.mipLevels = 1;
    ici.arrayLayers = 1;
    ici.samples = VK_SAMPLE_COUNT_1_BIT;
    ici.tiling = VK_IMAGE_TILING_OPTIMAL;
    ici.usage = VK_IMAGE_USAGE_TRANSFER_DST_BIT | VK_IMAGE_USAGE_TRANSFER_SRC_BIT | VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT;
    ici.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    ici.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;

    if (vkCreateImage(m_device, &ici, nullptr, &m_renderImage) != VK_SUCCESS) {
        setError("vkCreateImage render image failed");
        return false;
    }

    VkMemoryRequirements req{};
    vkGetImageMemoryRequirements(m_device, m_renderImage, &req);
    uint32_t mt = findMemoryType(req.memoryTypeBits, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
    if (mt == UINT32_MAX) { setError("No device-local image memory type"); return false; }

    VkMemoryAllocateInfo mai{VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO};
    mai.allocationSize = req.size;
    mai.memoryTypeIndex = mt;
    if (vkAllocateMemory(m_device, &mai, nullptr, &m_renderImageMemory) != VK_SUCCESS) {
        setError("vkAllocateMemory render image failed");
        return false;
    }
    if (vkBindImageMemory(m_device, m_renderImage, m_renderImageMemory, 0) != VK_SUCCESS) {
        setError("vkBindImageMemory render image failed");
        return false;
    }
    if (!createImageView(m_renderImage, VK_FORMAT_B8G8R8A8_UNORM, VK_IMAGE_ASPECT_COLOR_BIT, m_renderImageView)) {
        setError("vkCreateImageView render image failed");
        return false;
    }
    return true;
}

void VulkanComputeRenderer::destroySwapchain()
{
    if (m_device == VK_NULL_HANDLE) return;
    if (m_swapchain) vkDestroySwapchainKHR(m_device, m_swapchain, nullptr);
    m_swapchain = VK_NULL_HANDLE;
    m_swapchainImages.clear();
    m_swapchainExtent = {0, 0};
}

bool VulkanComputeRenderer::createOrResizeSwapchain()
{
    RECT rc{};
    GetClientRect(m_hwnd, &rc);
    uint32_t winW = (uint32_t)std::max<LONG>(1, rc.right - rc.left);
    uint32_t winH = (uint32_t)std::max<LONG>(1, rc.bottom - rc.top);

    VkSurfaceCapabilitiesKHR caps{};
    vkGetPhysicalDeviceSurfaceCapabilitiesKHR(m_physicalDevice, m_surface, &caps);

    VkExtent2D extent{};
    if (caps.currentExtent.width != UINT32_MAX) {
        extent = caps.currentExtent;
    } else {
        extent.width = std::max(caps.minImageExtent.width, std::min(caps.maxImageExtent.width, winW));
        extent.height = std::max(caps.minImageExtent.height, std::min(caps.maxImageExtent.height, winH));
    }
    if (extent.width == 0 || extent.height == 0) extent = {1, 1};

    uint32_t fmtCount = 0;
    vkGetPhysicalDeviceSurfaceFormatsKHR(m_physicalDevice, m_surface, &fmtCount, nullptr);
    std::vector<VkSurfaceFormatKHR> formats(fmtCount);
    vkGetPhysicalDeviceSurfaceFormatsKHR(m_physicalDevice, m_surface, &fmtCount, formats.data());

    VkSurfaceFormatKHR chosen = formats[0];
    for (const auto& f : formats) {
        if (f.format == VK_FORMAT_B8G8R8A8_UNORM && f.colorSpace == VK_COLOR_SPACE_SRGB_NONLINEAR_KHR) {
            chosen = f;
            break;
        }
    }

    uint32_t modeCount = 0;
    vkGetPhysicalDeviceSurfacePresentModesKHR(m_physicalDevice, m_surface, &modeCount, nullptr);
    std::vector<VkPresentModeKHR> modes(modeCount);
    vkGetPhysicalDeviceSurfacePresentModesKHR(m_physicalDevice, m_surface, &modeCount, modes.data());
    // For performance testing/gameplay, prefer an uncapped present mode.
    // FIFO is v-sync and will make vkAcquireNextImageKHR block around one
    // refresh interval, which was the measured ~11-13 ms bottleneck at 4K.
    VkPresentModeKHR presentMode = VK_PRESENT_MODE_FIFO_KHR;
    for (VkPresentModeKHR m : modes) {
        if (m == VK_PRESENT_MODE_IMMEDIATE_KHR) { presentMode = m; break; }
    }
    if (presentMode != VK_PRESENT_MODE_IMMEDIATE_KHR) {
        for (VkPresentModeKHR m : modes) {
            if (m == VK_PRESENT_MODE_MAILBOX_KHR) { presentMode = m; break; }
        }
    }

    // Request one extra swapchain image where possible. This does not bypass
    // FIFO/v-sync, but it reduces avoidable acquire stalls caused by too few
    // presentable images.
    uint32_t imageCount = caps.minImageCount + 2;
    if (caps.maxImageCount > 0 && imageCount > caps.maxImageCount) imageCount = caps.maxImageCount;

    VkSwapchainCreateInfoKHR sci{VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR};
    sci.surface = m_surface;
    sci.minImageCount = imageCount;
    sci.imageFormat = chosen.format;
    sci.imageColorSpace = chosen.colorSpace;
    sci.imageExtent = extent;
    sci.imageArrayLayers = 1;
    sci.imageUsage = VK_IMAGE_USAGE_TRANSFER_DST_BIT | VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT;
    sci.imageSharingMode = VK_SHARING_MODE_EXCLUSIVE;
    sci.preTransform = caps.currentTransform;
    sci.compositeAlpha = VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR;
    sci.presentMode = presentMode;
    sci.clipped = VK_TRUE;
    sci.oldSwapchain = m_swapchain;

    VkSwapchainKHR old = m_swapchain;
    VkSwapchainKHR created = VK_NULL_HANDLE;
    VkResult r = vkCreateSwapchainKHR(m_device, &sci, nullptr, &created);
    if (r != VK_SUCCESS) { setError("vkCreateSwapchainKHR failed"); return false; }
    if (old) vkDestroySwapchainKHR(m_device, old, nullptr);
    m_swapchain = created;
    m_swapchainFormat = chosen.format;
    m_swapchainExtent = extent;

    uint32_t scCount = 0;
    vkGetSwapchainImagesKHR(m_device, m_swapchain, &scCount, nullptr);
    m_swapchainImages.resize(scCount);
    vkGetSwapchainImagesKHR(m_device, m_swapchain, &scCount, m_swapchainImages.data());

    std::cout << "[Vulkan] Swapchain presentMode=" << presentModeName(presentMode)
              << " images=" << scCount
              << " extent=" << m_swapchainExtent.width << "x" << m_swapchainExtent.height
              << "\n";
    return true;
}

bool VulkanComputeRenderer::recreatePresentationResources()
{
    // Framebuffers/image views reference old swapchain images, so they must go
    // before vkCreateSwapchainKHR destroys/replaces the old swapchain.
    destroyRasterTargets();

    if (!createOrResizePixelBuffer()) return false;
    if (!createOrResizeRenderImage()) return false;
    if (!createOrResizeSwapchain()) return false;

    // Swapchain image format/extent are part of the graphics render pass/framebuffers.
    // Recreate the small raster objects here; compute/raytracing objects stay intact.
    destroyRasterPipeline();
    destroyDirectRasterPipeline();
    if (!createRasterPipeline()) return false;
    if (!createDirectRasterPipeline()) return false;
    if (!createOrResizeRasterTargets()) return false;
    return true;
}

static uint32_t addTexture(Texture* tex,
                           std::unordered_map<Texture*, uint32_t>& map,
                           std::vector<GpuTextureInfo>& infos,
                           std::vector<uint32_t>& pixels)
{
    if (!tex || !tex->pixels || tex->width <= 0 || tex->height <= 0) return 0xFFFFFFFFu;
    auto it = map.find(tex);
    if (it != map.end()) return it->second;

    GpuTextureInfo info;
    info.offset = (uint32_t)pixels.size();
    info.width = (uint32_t)tex->width;
    info.height = (uint32_t)tex->height;
    const size_t count = (size_t)tex->width * (size_t)tex->height;
    pixels.insert(pixels.end(), tex->pixels, tex->pixels + count);

    uint32_t id = (uint32_t)infos.size();
    infos.push_back(info);
    map[tex] = id;
    return id;
}

bool VulkanComputeRenderer::uploadSceneIfNeeded(const Map& map, const Player& player,
                                                const Mesh* const* remoteMeshes,
                                                int numRemotePlayers)
{
    MapData* md = map.mapData;
    if (!md || !md->grid) { setError("MapData/grid is null"); return false; }
    // IMPORTANT: the scene upload cache is not disabled merely because a mesh
    // has skeleton/skin data. Animated vertex positions belong in the dynamic
    // raster geometry path; rebuilding the whole map/BVH/texture upload every
    // frame defeats the purpose of the cache.
    m_lastSceneUploadRebuilt = false;
    m_lastSceneUploadReason = "cache-hit";

    bool remoteMeshSetChanged = (m_uploadedRemoteMeshCount != numRemotePlayers);
    if (!remoteMeshSetChanged) {
        for (int i = 0; remoteMeshes && i < numRemotePlayers; ++i) {
            if ((size_t)i >= m_uploadedRemoteMeshes.size() || m_uploadedRemoteMeshes[(size_t)i] != remoteMeshes[i]) {
                remoteMeshSetChanged = true;
                break;
            }
        }
    }

    const bool cacheHit =
        m_uploadedMap == md &&
        m_uploadedMapVersion == md->version &&
        m_uploadedPlayerMesh == player.mesh &&
        !remoteMeshSetChanged &&
        m_cells.buffer != VK_NULL_HANDLE;

    if (cacheHit) {
        return true;
    }

    m_lastSceneUploadRebuilt = true;
    if (m_cells.buffer == VK_NULL_HANDLE) {
        m_lastSceneUploadReason = "first-upload";
    } else if (m_uploadedMap != md) {
        m_lastSceneUploadReason = "map-pointer-changed";
    } else if (m_uploadedMapVersion != md->version) {
        m_lastSceneUploadReason = "map-version-changed";
    } else if (m_uploadedPlayerMesh != player.mesh) {
        m_lastSceneUploadReason = "player-mesh-changed";
    } else if (remoteMeshSetChanged) {
        m_lastSceneUploadReason = "remote-mesh-set-changed";
    } else {
        m_lastSceneUploadReason = "unknown";
    }

    std::unordered_map<Texture*, uint32_t> textureMap;
    std::unordered_map<Mesh*, uint32_t> meshMap;
    std::vector<GpuCell> cells((size_t)md->sizeX * (size_t)md->sizeY * (size_t)md->sizeZ);
    std::vector<GpuCellItem> items;
    std::vector<GpuBox> boxes;
    std::vector<GpuPlane> planes;
    std::vector<GpuTextureInfo> texInfos;
    std::vector<uint32_t> texPixels;
    std::vector<GpuMesh> meshes;
    std::vector<GpuMeshCell> meshCells;
    std::vector<GpuTriangle> triangles;
    std::vector<GpuBVHNode> nodes;
    std::vector<uint32_t> triIndices;

    std::vector<RasterVertex> rasterVerts;
    std::vector<uint32_t> rasterIndices;

    auto gridIndex = [md](int x, int y, int z) { return x + y * md->sizeX + z * md->sizeX * md->sizeY; };

    auto rasterPushVertex = [&](const Vec3f& p, const Vec3f& n, float u, float v, uint32_t tex) -> uint32_t {
        RasterVertex rv{};
        rv.px = p.x; rv.py = p.y; rv.pz = p.z;
        rv.nx = n.x; rv.ny = n.y; rv.nz = n.z;
        rv.u = u; rv.v = v;
        rv.textureIndex = tex;
        rv.color = 0u;
        rv.mode = 0u;
        rasterVerts.push_back(rv);
        return (uint32_t)rasterVerts.size() - 1u;
    };

    auto rasterEmitTriWithNormal = [&](const Vec3f& n,
                                       const Vec3f& a, float au, float av,
                                       const Vec3f& b, float bu, float bv,
                                       const Vec3f& c, float cu, float cv,
                                       uint32_t tex) {
        uint32_t base = (uint32_t)rasterVerts.size();
        rasterPushVertex(a, n, au, av, tex);
        rasterPushVertex(b, n, bu, bv, tex);
        rasterPushVertex(c, n, cu, cv, tex);
        rasterIndices.push_back(base + 0u);
        rasterIndices.push_back(base + 1u);
        rasterIndices.push_back(base + 2u);
    };

    auto rasterEmitTri = [&](const Vec3f& a, float au, float av,
                             const Vec3f& b, float bu, float bv,
                             const Vec3f& c, float cu, float cv,
                             uint32_t tex) {
        rasterEmitTriWithNormal(triNormal(a, b, c), a, au, av, b, bu, bv, c, cu, cv, tex);
    };

    auto rasterEmitQuad = [&](const Vec3f& a, const Vec3f& b, const Vec3f& c, const Vec3f& d,
                              float au, float av, float bu, float bv,
                              float cu, float cv, float du, float dv,
                              uint32_t tex) {
        const Vec3f n = triNormal(a, b, c);
        uint32_t base = (uint32_t)rasterVerts.size();
        rasterPushVertex(a, n, au, av, tex);
        rasterPushVertex(b, n, bu, bv, tex);
        rasterPushVertex(c, n, cu, cv, tex);
        rasterPushVertex(d, n, du, dv, tex);
        rasterIndices.push_back(base + 0u);
        rasterIndices.push_back(base + 1u);
        rasterIndices.push_back(base + 2u);
        rasterIndices.push_back(base + 0u);
        rasterIndices.push_back(base + 2u);
        rasterIndices.push_back(base + 3u);
    };

    auto cellHasBox = [&](int x, int y, int z) -> bool {
        if (x < 0 || y < 0 || z < 0 || x >= md->sizeX || y >= md->sizeY || z >= md->sizeZ) return false;
        const Cell& nc = md->grid[gridIndex(x, y, z)];
        for (uint32_t ii = 0; ii < nc.count; ++ii) {
            void* obj = nc.items[ii];
            if (obj && *(int*)obj == 0) return true;
        }
        return false;
    };

    auto cellHasEquivalentPlane = [&](int x, int y, int z, const Plane* srcPlane) -> bool {
        if (!srcPlane) return false;
        if (x < 0 || y < 0 || z < 0 || x >= md->sizeX || y >= md->sizeY || z >= md->sizeZ) return false;
        const Vec3f srcN = norm3(srcPlane->normal);
        const Cell& nc = md->grid[gridIndex(x, y, z)];
        for (uint32_t ii = 0; ii < nc.count; ++ii) {
            void* obj = nc.items[ii];
            if (!obj || *(int*)obj != 1) continue;
            const Plane* other = static_cast<const Plane*>(obj);
            if (other == srcPlane) return true;

            const Vec3f otherN = norm3(other->normal);
            if (std::abs(dot3(srcN, otherN)) < 0.999f) continue;

            const Vec3f d = sub3(other->position, srcPlane->position);
            if (std::abs(dot3(d, srcN)) > 1e-4f) continue;

            // If two cells carry separate but coplanar floor/ceiling plane objects,
            // they would rasterize into the exact same depth values and z-fight.
            // Treat them as one plane for boundary de-duplication.
            return true;
        }
        return false;
    };

    auto emitBoxCell = [&](int x, int y, int z, uint32_t tex) {
        const float x0 = (float)x, x1 = (float)x + 1.f;
        const float y0 = (float)y, y1 = (float)y + 1.f;
        const float z0 = (float)z, z1 = (float)z + 1.f;

        // Only emit exposed voxel faces. This is the first large raster win over
        // brute-force raycasting: solid interiors produce zero triangles.
        if (!cellHasBox(x - 1, y, z)) { // -X, uv = z/y like raycast side 0
            rasterEmitQuad({x0,y0,z1}, {x0,y1,z1}, {x0,y1,z0}, {x0,y0,z0},
                           z1,y0, z1,y1, z0,y1, z0,y0, tex);
        }
        if (!cellHasBox(x + 1, y, z)) { // +X
            rasterEmitQuad({x1,y0,z0}, {x1,y1,z0}, {x1,y1,z1}, {x1,y0,z1},
                           z0,y0, z0,y1, z1,y1, z1,y0, tex);
        }
        if (!cellHasBox(x, y - 1, z)) { // -Y, uv = x/z like raycast side 1
            rasterEmitQuad({x0,y0,z0}, {x1,y0,z0}, {x1,y0,z1}, {x0,y0,z1},
                           x0,z0, x1,z0, x1,z1, x0,z1, tex);
        }
        if (!cellHasBox(x, y + 1, z)) { // +Y
            rasterEmitQuad({x0,y1,z1}, {x1,y1,z1}, {x1,y1,z0}, {x0,y1,z0},
                           x0,z1, x1,z1, x1,z0, x0,z0, tex);
        }
        if (!cellHasBox(x, y, z - 1)) { // -Z, uv = x/y like raycast side 2
            rasterEmitQuad({x1,y0,z0}, {x0,y0,z0}, {x0,y1,z0}, {x1,y1,z0},
                           x1,y0, x0,y0, x0,y1, x1,y1, tex);
        }
        if (!cellHasBox(x, y, z + 1)) { // +Z
            rasterEmitQuad({x0,y0,z1}, {x1,y0,z1}, {x1,y1,z1}, {x0,y1,z1},
                           x0,y0, x1,y0, x1,y1, x0,y1, tex);
        }
    };

    auto emitPlaneCell = [&](int x, int y, int z, const GpuPlane& plane, const Plane* srcPlane) {
        Vec3f n{plane.normal.x, plane.normal.y, plane.normal.z};
        float nLen = std::sqrt(n.x*n.x + n.y*n.y + n.z*n.z);
        if (nLen < 1e-6f) return;
        n = {n.x / nLen, n.y / nLen, n.z / nLen};
        Vec3f p0{plane.position.x, plane.position.y, plane.position.z};

        // Avoid rasterizing the same infinite-thin plane from both cells when
        // the plane lies exactly on a grid-cell boundary. That produces classic
        // coplanar z-fighting: tiny view/basis changes look like a small camera
        // roll and create view-dependent dark floor/ceiling patches in the G-buffer.
        const float ax = std::abs(n.x), ay = std::abs(n.y), az = std::abs(n.z);
        int dominantAxis = 0;
        float dominantAbs = ax;
        if (ay > dominantAbs) { dominantAxis = 1; dominantAbs = ay; }
        if (az > dominantAbs) { dominantAxis = 2; dominantAbs = az; }
        if (dominantAbs > 0.999f) {
            const float coord = (dominantAxis == 0) ? p0.x : ((dominantAxis == 1) ? p0.y : p0.z);
            const float cellMin = (dominantAxis == 0) ? float(x) : ((dominantAxis == 1) ? float(y) : float(z));
            if (std::abs(coord - cellMin) <= 1e-4f) {
                int nx = x, ny = y, nz = z;
                if (dominantAxis == 0) --nx;
                else if (dominantAxis == 1) --ny;
                else --nz;
                if (cellHasEquivalentPlane(nx, ny, nz, srcPlane)) return;
            }
        }

        const Vec3f c[8] = {
            {(float)x,     (float)y,     (float)z    },
            {(float)x + 1, (float)y,     (float)z    },
            {(float)x,     (float)y + 1, (float)z    },
            {(float)x + 1, (float)y + 1, (float)z    },
            {(float)x,     (float)y,     (float)z + 1},
            {(float)x + 1, (float)y,     (float)z + 1},
            {(float)x,     (float)y + 1, (float)z + 1},
            {(float)x + 1, (float)y + 1, (float)z + 1},
        };
        const int edges[12][2] = {
            {0,1},{0,2},{1,3},{2,3}, {4,5},{4,6},{5,7},{6,7}, {0,4},{1,5},{2,6},{3,7}
        };
        auto signedDist = [&](const Vec3f& p) {
            return (p.x - p0.x)*n.x + (p.y - p0.y)*n.y + (p.z - p0.z)*n.z;
        };
        std::vector<Vec3f> pts;
        auto addUnique = [&](const Vec3f& p) {
            for (const Vec3f& q : pts) {
                float dx = p.x-q.x, dy = p.y-q.y, dz = p.z-q.z;
                if (dx*dx + dy*dy + dz*dz < 1e-10f) return;
            }
            pts.push_back(p);
        };
        const float EPS = 1e-5f;
        for (const auto& e : edges) {
            Vec3f a = c[e[0]], b = c[e[1]];
            float da = signedDist(a);
            float db = signedDist(b);
            if (std::abs(da) <= EPS) addUnique(a);
            if (std::abs(db) <= EPS) addUnique(b);
            if ((da < -EPS && db > EPS) || (da > EPS && db < -EPS)) {
                float t = da / (da - db);
                addUnique({a.x + (b.x-a.x)*t, a.y + (b.y-a.y)*t, a.z + (b.z-a.z)*t});
            }
        }
        if (pts.size() < 3) return;

        Vec3f center{0,0,0};
        for (const Vec3f& p : pts) { center.x += p.x; center.y += p.y; center.z += p.z; }
        center = {center.x / (float)pts.size(), center.y / (float)pts.size(), center.z / (float)pts.size()};

        Vec3f ref = (std::abs(n.y) < 0.9f) ? Vec3f{0,1,0} : Vec3f{1,0,0};
        Vec3f tangent{ ref.y*n.z - ref.z*n.y, ref.z*n.x - ref.x*n.z, ref.x*n.y - ref.y*n.x };
        float tLen = std::sqrt(tangent.x*tangent.x + tangent.y*tangent.y + tangent.z*tangent.z);
        if (tLen < 1e-6f) return;
        tangent = {tangent.x/tLen, tangent.y/tLen, tangent.z/tLen};
        Vec3f bitangent{ n.y*tangent.z - n.z*tangent.y,
                         n.z*tangent.x - n.x*tangent.z,
                         n.x*tangent.y - n.y*tangent.x };

        std::sort(pts.begin(), pts.end(), [&](const Vec3f& a, const Vec3f& b) {
            Vec3f da{a.x-center.x, a.y-center.y, a.z-center.z};
            Vec3f db{b.x-center.x, b.y-center.y, b.z-center.z};
            float aa = std::atan2(da.x*bitangent.x + da.y*bitangent.y + da.z*bitangent.z,
                                  da.x*tangent.x   + da.y*tangent.y   + da.z*tangent.z);
            float ab = std::atan2(db.x*bitangent.x + db.y*bitangent.y + db.z*bitangent.z,
                                  db.x*tangent.x   + db.y*tangent.y   + db.z*tangent.z);
            return aa < ab;
        });

        auto planeUV = [&](const Vec3f& p, float& u, float& v) {
            if (std::abs(n.y) > 0.5f) { u = p.x; v = p.z; }
            else if (std::abs(n.x) > 0.5f) { u = p.y; v = p.z; }
            else { u = p.x; v = p.y; }
        };
        float cu, cv; planeUV(center, cu, cv);
        for (size_t i = 1; i + 1 < pts.size(); ++i) {
            float u0,v0,u1,v1,u2,v2;
            planeUV(pts[0], u0, v0);
            planeUV(pts[i], u1, v1);
            planeUV(pts[i+1], u2, v2);

            // Plane cells are infinitely thin and their polygon winding can flip
            // depending on the clipped intersection polygon. Use the authoritative
            // Plane.normal for the G-buffer instead of a winding-derived normal;
            // otherwise floor/ceiling fragments can receive opposite normals and
            // become dark or self-shadowed only from some view angles.
            rasterEmitTriWithNormal(n, pts[0], u0, v0, pts[i], u1, v1, pts[i+1], u2, v2, plane.textureIndex);
        }
    };

    auto meshPointToGrid = [](const Mesh* mesh, const Vec3f& p) -> Vec3f {
        const Vec3f& mn = mesh->modelMin;
        const Vec3f& sc = mesh->scale;
        const Vec3f& pv = mesh->pivot;
        Vec3f s{(p.x - mn.x) * sc.x - pv.x,
                (p.y - mn.y) * sc.y - pv.y,
                (p.z - mn.z) * sc.z - pv.z};
        Vec3f r = mesh->rot.mul(s);
        return {r.x + pv.x + mesh->offset.x,
                r.y + pv.y + mesh->offset.y,
                r.z + pv.z + mesh->offset.z};
    };

    auto addMesh = [&](Mesh* mesh, bool emitRasterGeometry = true) -> uint32_t {
        auto it = meshMap.find(mesh);
        if (it != meshMap.end()) return it->second;

        mesh->flattenForGPU();
        GpuMesh gm;
        gm.modelMin = gv4(mesh->modelMin);
        gm.scale = gv4(mesh->scale);
        gm.offset = gv4(mesh->offset);
        gm.modelCenter = gv4(mesh->modelCenter);
        gm.pivot = gv4(mesh->pivot);
        gm.rot0 = gv4(mesh->rot.m[0], mesh->rot.m[1], mesh->rot.m[2], 0.f);
        gm.rot1 = gv4(mesh->rot.m[3], mesh->rot.m[4], mesh->rot.m[5], 0.f);
        gm.rot2 = gv4(mesh->rot.m[6], mesh->rot.m[7], mesh->rot.m[8], 0.f);
        gm.ranges.x = (uint32_t)triangles.size();
        gm.ranges.y = mesh->tris ? (uint32_t)mesh->tris->size() : 0u;

        std::vector<uint32_t> localTextureToGlobal(mesh->numTextures, 0xFFFFFFFFu);
        for (uint32_t ti = 0; ti < mesh->numTextures; ++ti) {
            localTextureToGlobal[ti] = addTexture(mesh->d_textures ? mesh->d_textures[ti] : nullptr, textureMap, texInfos, texPixels);
        }

        if (mesh->d_tris && mesh->tris) {
            for (size_t i = 0; i < mesh->tris->size(); ++i) {
                const Triangle& t = mesh->d_tris[i];
                GpuTriangle gt;
                gt.p1 = gv4(t.v1.pos);
                gt.p2 = gv4(t.v2.pos);
                gt.p3 = gv4(t.v3.pos);
                gt.uv12 = gv4(t.v1.uv.x, t.v1.uv.y, t.v2.uv.x, t.v2.uv.y);
                gt.uv3 = gv4(t.v3.uv.x, t.v3.uv.y, 0.f, 0.f);
                if (t.textureID >= 0 && (uint32_t)t.textureID < localTextureToGlobal.size()) {
                    gt.meta.x = localTextureToGlobal[(uint32_t)t.textureID];
                } else if (!localTextureToGlobal.empty()) {
                    // Fallback for untextured GLBs or JSON-supplied mesh textures.
                    gt.meta.x = localTextureToGlobal[0];
                } else {
                    gt.meta.x = 0xFFFFFFFFu;
                }
                triangles.push_back(gt);

                if (emitRasterGeometry) {
                    // Static raster geometry for this map mesh instance. Texture indices are
                    // already converted from mesh-local to global atlas indices above.
                    const Vec3f p1 = meshPointToGrid(mesh, t.v1.pos);
                    const Vec3f p2 = meshPointToGrid(mesh, t.v2.pos);
                    const Vec3f p3 = meshPointToGrid(mesh, t.v3.pos);
                    rasterEmitTri(p1, t.v1.uv.x, 1.0f - t.v1.uv.y,
                                  p2, t.v2.uv.x, 1.0f - t.v2.uv.y,
                                  p3, t.v3.uv.x, 1.0f - t.v3.uv.y,
                                  gt.meta.x);
                }
            }
        }

        uint32_t meshIndex = (uint32_t)meshes.size();
        meshes.push_back(gm);
        meshMap[mesh] = meshIndex;
        return meshIndex;
    };

    for (int z = 0; z < md->sizeZ; ++z)
    for (int y = 0; y < md->sizeY; ++y)
    for (int x = 0; x < md->sizeX; ++x) {
        const int ci = gridIndex(x,y,z);
        Cell& c = md->grid[ci];
        cells[ci].firstItem = (uint32_t)items.size();

        for (uint32_t i = 0; i < c.count; ++i) {
            void* obj = c.items[i];
            if (!obj) continue;
            const int type = *(int*)obj;
            if (type == 0) {
                Box* b = (Box*)obj;
                GpuBox gb;
                gb.textureIndex = addTexture(b->texture, textureMap, texInfos, texPixels);
                emitBoxCell(x, y, z, gb.textureIndex);
                uint32_t bi = (uint32_t)boxes.size();
                boxes.push_back(gb);
                items.push_back({0u, bi, 0u, 0u});
            } else if (type == 1) {
                Plane* p = (Plane*)obj;
                GpuPlane gp;
                gp.position = gv4(p->position);
                gp.normal = gv4(p->normal);
                gp.textureIndex = addTexture(p->texture, textureMap, texInfos, texPixels);
                emitPlaneCell(x, y, z, gp, p);
                uint32_t pi = (uint32_t)planes.size();
                planes.push_back(gp);
                items.push_back({1u, pi, 0u, 0u});
            } else if (type == 2) {
                Mesh* mesh = (Mesh*)obj;
                if (!mesh) continue;
                uint32_t meshIndex = addMesh(mesh);

                const FlatCellBVH* entry = nullptr;
                if (mesh->d_cellBVHIndex && mesh->numCellBVHs > 0) {
                    int lo = 0, hi = (int)mesh->numCellBVHs - 1;
                    while (lo <= hi) {
                        int mid = (lo + hi) >> 1;
                        int k = mesh->d_cellBVHIndex[mid].key;
                        if (k == ci) { entry = &mesh->d_cellBVHIndex[mid]; break; }
                        if (k < ci) lo = mid + 1; else hi = mid - 1;
                    }
                }
                if (!entry || !mesh->d_flatNodes || !mesh->d_flatTriIdx) continue;

                const uint32_t nodeStart = entry->nodeOffset;
                const uint32_t triStart  = entry->triIdxOffset;
                uint32_t nodeEnd = mesh->numFlatNodes;
                uint32_t triEnd  = mesh->numFlatTriIdx;
                for (uint32_t ei = 0; ei < mesh->numCellBVHs; ++ei) {
                    const FlatCellBVH& e = mesh->d_cellBVHIndex[ei];
                    if (e.nodeOffset > nodeStart) nodeEnd = std::min(nodeEnd, e.nodeOffset);
                    if (e.triIdxOffset > triStart) triEnd = std::min(triEnd, e.triIdxOffset);
                }
                if (nodeStart >= nodeEnd || triStart >= triEnd) continue;

                const uint32_t nodeBase = (uint32_t)nodes.size();
                const uint32_t triIdxBase = (uint32_t)triIndices.size();

                for (uint32_t ni = nodeStart; ni < nodeEnd; ++ni) {
                    const BVHNode& n = mesh->d_flatNodes[ni];
                    GpuBVHNode gn;
                    gn.aabbMin = gv4(n.aabbMin);
                    gn.aabbMax = gv4(n.aabbMax);
                    gn.data.x = n.leftFirst;
                    gn.data.y = n.triCount;
                    if (n.triCount == 0) {
                        gn.data.x = nodeBase + (n.leftFirst - nodeStart);
                    }
                    nodes.push_back(gn);
                }
                for (uint32_t ti = triStart; ti < triEnd; ++ti) {
                    triIndices.push_back(mesh->d_flatTriIdx[ti]);
                }

                GpuMeshCell mc;
                mc.meshIndex = meshIndex;
                mc.nodeRoot = nodeBase;
                mc.triIdxBase = triIdxBase;
                uint32_t mci = (uint32_t)meshCells.size();
                meshCells.push_back(mc);
                items.push_back({2u, mci, 0u, 0u});
            }
        }
        cells[ci].itemCount = (uint32_t)items.size() - cells[ci].firstItem;
    }

    auto addFullMeshRanges = [&](const Mesh* srcMesh) -> GpuUVec4 {
        GpuUVec4 out{};
        Mesh* pm = const_cast<Mesh*>(srcMesh);
        if (!pm) return out;

        const uint32_t meshIndex = addMesh(pm, false);
        if (!pm->d_fullNodes || !pm->d_fullTriIdx || pm->numFullNodes == 0 || pm->numFullTriIdx == 0) {
            return out;
        }

        const uint32_t nodeBase = (uint32_t)nodes.size();
        const uint32_t triIdxBase = (uint32_t)triIndices.size();
        for (uint32_t ni = 0; ni < pm->numFullNodes; ++ni) {
            const BVHNode& n = pm->d_fullNodes[ni];
            GpuBVHNode gn;
            gn.aabbMin = gv4(n.aabbMin);
            gn.aabbMax = gv4(n.aabbMax);
            gn.data.x = n.leftFirst;
            gn.data.y = n.triCount;
            if (n.triCount == 0) gn.data.x = nodeBase + n.leftFirst;
            nodes.push_back(gn);
        }
        for (uint32_t ti = 0; ti < pm->numFullTriIdx; ++ti) {
            triIndices.push_back(pm->d_fullTriIdx[ti]);
        }

        const GpuMesh& gm = meshes[meshIndex];
        out = {gm.ranges.x, gm.ranges.y, nodeBase, triIdxBase};
        return out;
    };

    GpuPlayerMesh playerMeshGpu{};
    if (player.mesh) {
        playerMeshGpu.modelMin = gv4(player.mesh->modelMin);
        playerMeshGpu.modelCenter = gv4(player.mesh->modelCenter);
        playerMeshGpu.ranges = addFullMeshRanges(player.mesh);
    }

    m_remoteMeshRanges.assign(numRemotePlayers > 0 ? (size_t)numRemotePlayers : 0u, GpuUVec4{});
    for (int i = 0; remoteMeshes && i < numRemotePlayers; ++i) {
        const Mesh* rm = remoteMeshes[i];
        if (!rm) continue;
        m_remoteMeshRanges[(size_t)i] = addFullMeshRanges(rm);
    }

    // Dummy entries keep descriptor bindings valid even for empty scenes.
    if (items.empty()) items.push_back({});
    if (boxes.empty()) boxes.push_back({});
    if (planes.empty()) planes.push_back({});
    if (texInfos.empty()) texInfos.push_back({});
    if (texPixels.empty()) texPixels.push_back(0);
    if (meshes.empty()) meshes.push_back({});
    if (meshCells.empty()) meshCells.push_back({});
    if (triangles.empty()) triangles.push_back({});
    if (nodes.empty()) nodes.push_back({});
    if (triIndices.empty()) triIndices.push_back(0);

    if (!uploadBuffer(m_cells, cells.data(), cells.size() * sizeof(GpuCell))) return false;
    if (!uploadBuffer(m_items, items.data(), items.size() * sizeof(GpuCellItem))) return false;
    if (!uploadBuffer(m_boxes, boxes.data(), boxes.size() * sizeof(GpuBox))) return false;
    if (!uploadBuffer(m_planes, planes.data(), planes.size() * sizeof(GpuPlane))) return false;
    if (!uploadBuffer(m_texInfos, texInfos.data(), texInfos.size() * sizeof(GpuTextureInfo))) return false;
    if (!uploadBuffer(m_texPixels, texPixels.data(), texPixels.size() * sizeof(uint32_t))) return false;
    if (!uploadBuffer(m_meshes, meshes.data(), meshes.size() * sizeof(GpuMesh))) return false;
    if (!uploadBuffer(m_meshCells, meshCells.data(), meshCells.size() * sizeof(GpuMeshCell))) return false;
    if (!uploadBuffer(m_triangles, triangles.data(), triangles.size() * sizeof(GpuTriangle))) return false;
    if (!uploadBuffer(m_bvhNodes, nodes.data(), nodes.size() * sizeof(GpuBVHNode))) return false;
    if (!uploadBuffer(m_triIndices, triIndices.data(), triIndices.size() * sizeof(uint32_t))) return false;
    if (!uploadBuffer(m_playerMesh, &playerMeshGpu, sizeof(GpuPlayerMesh))) return false;

    m_cpuTriangles = triangles;
    // Scene rebuild may change the global texture indices stored in
    // m_cpuTriangles. Force one dynamic-geometry rebuild so remote/player
    // raster vertices pick up the new texture IDs.
    m_rasterDynamicHash = 0;

    m_rasterStaticIndexCount = (uint32_t)rasterIndices.size();
    if (!rasterVerts.empty() && !rasterIndices.empty()) {
        if (!uploadBuffer(m_rasterStaticVertices, rasterVerts.data(),
            (VkDeviceSize)rasterVerts.size() * sizeof(RasterVertex),
            VK_BUFFER_USAGE_VERTEX_BUFFER_BIT | VK_BUFFER_USAGE_STORAGE_BUFFER_BIT)) return false;
        if (!uploadBuffer(m_rasterStaticIndices, rasterIndices.data(),
            (VkDeviceSize)rasterIndices.size() * sizeof(uint32_t),
            VK_BUFFER_USAGE_INDEX_BUFFER_BIT | VK_BUFFER_USAGE_STORAGE_BUFFER_BIT)) return false;
    } else {
        destroyBuffer(m_rasterStaticVertices);
        destroyBuffer(m_rasterStaticIndices);
        m_rasterStaticIndexCount = 0;
    }

    m_uploadedMap = md;
    m_uploadedMapVersion = md->version;
    m_uploadedPlayerMesh = player.mesh;
    m_uploadedRemoteMeshCount = numRemotePlayers;
    m_uploadedRemoteMeshes.assign(numRemotePlayers > 0 ? (size_t)numRemotePlayers : 0u, nullptr);
    for (int i = 0; remoteMeshes && i < numRemotePlayers; ++i) {
        m_uploadedRemoteMeshes[(size_t)i] = remoteMeshes[i];
    }
    return true;
}


bool VulkanComputeRenderer::uploadRasterDynamicGeometry(const GpuRemotePlayer* remotePlayers,
                                                        const Mesh* const* remoteMeshes,
                                                        int numRemotePlayers)
{
    uint64_t hash = 1469598103934665603ull;
    hash = fnv1aAppendValue(hash, numRemotePlayers);
    for (int i = 0; remoteMeshes && i < numRemotePlayers; ++i) {
        uintptr_t meshPtr = reinterpret_cast<uintptr_t>(remoteMeshes[i]);
        hash = fnv1aAppendValue(hash, meshPtr);
    }
    if (remotePlayers && numRemotePlayers > 0) {
        hash = fnv1aAppend(hash, remotePlayers, sizeof(GpuRemotePlayer) * (size_t)numRemotePlayers);
    }

    if ((!remotePlayers || !remoteMeshes || numRemotePlayers <= 0)) {
        m_rasterDynamicHash = hash;
        m_rasterDynamicIndexCount = 0;
        return true;
    }

    if (hash == m_rasterDynamicHash) {
        return true;
    }

    std::vector<RasterVertex> verts;
    std::vector<uint32_t> indices;

    auto pushVertex = [&](const Vec3f& p, const Vec3f& n, float u, float v, uint32_t tex) -> uint32_t {
        RasterVertex rv{};
        rv.px = p.x; rv.py = p.y; rv.pz = p.z;
        rv.nx = n.x; rv.ny = n.y; rv.nz = n.z;
        rv.u = u; rv.v = v;
        rv.textureIndex = tex;
        rv.color = 0u;
        rv.mode = 0u;
        verts.push_back(rv);
        return (uint32_t)verts.size() - 1u;
    };

    auto mulRows = [](const GpuVec4& r0, const GpuVec4& r1, const GpuVec4& r2, const Vec3f& v) -> Vec3f {
        return {r0.x*v.x + r0.y*v.y + r0.z*v.z,
                r1.x*v.x + r1.y*v.y + r1.z*v.z,
                r2.x*v.x + r2.y*v.y + r2.z*v.z};
    };

    auto transformRemotePoint = [&](const GpuRemotePlayer& rp, const Vec3f& p) -> Vec3f {
        Vec3f mn{rp.modelMin.x, rp.modelMin.y, rp.modelMin.z};
        Vec3f sc{rp.scale.x, rp.scale.y, rp.scale.z};
        Vec3f pv{rp.pivot.x, rp.pivot.y, rp.pivot.z};
        Vec3f off{rp.offset.x, rp.offset.y, rp.offset.z};
        Vec3f s{(p.x - mn.x) * sc.x - pv.x,
                (p.y - mn.y) * sc.y - pv.y,
                (p.z - mn.z) * sc.z - pv.z};
        Vec3f r = mulRows(rp.rot0, rp.rot1, rp.rot2, s);
        return {r.x + pv.x + off.x, r.y + pv.y + off.y, r.z + pv.z + off.z};
    };

    if (remotePlayers && remoteMeshes && numRemotePlayers > 0) {
        for (int i = 0; i < numRemotePlayers; ++i) {
            const GpuRemotePlayer& rp = remotePlayers[i];
            const Mesh* mesh = remoteMeshes[i];
            if (rp.meta.x == 0u || !mesh || !mesh->d_tris || !mesh->tris || rp.ranges.y == 0u) continue;

            const uint32_t triBase = rp.ranges.x;
            const uint32_t triCount = std::min<uint32_t>(rp.ranges.y, (uint32_t)mesh->tris->size());
            for (uint32_t ti = 0; ti < triCount; ++ti) {
                const Triangle& t = mesh->d_tris[ti];
                uint32_t tex = 0xFFFFFFFFu;
                if ((size_t)triBase + ti < m_cpuTriangles.size()) tex = m_cpuTriangles[(size_t)triBase + ti].meta.x;

                const Vec3f p1 = transformRemotePoint(rp, t.v1.pos);
                const Vec3f p2 = transformRemotePoint(rp, t.v2.pos);
                const Vec3f p3 = transformRemotePoint(rp, t.v3.pos);
                const Vec3f n = triNormal(p1, p2, p3);
                const uint32_t base = (uint32_t)verts.size();
                pushVertex(p1, n, t.v1.uv.x, 1.0f - t.v1.uv.y, tex);
                pushVertex(p2, n, t.v2.uv.x, 1.0f - t.v2.uv.y, tex);
                pushVertex(p3, n, t.v3.uv.x, 1.0f - t.v3.uv.y, tex);
                indices.push_back(base + 0u);
                indices.push_back(base + 1u);
                indices.push_back(base + 2u);
            }
        }
    }

    m_rasterDynamicIndexCount = (uint32_t)indices.size();
    if (!verts.empty() && !indices.empty()) {
        if (!uploadBuffer(m_rasterDynamicVertices, verts.data(),
            (VkDeviceSize)verts.size() * sizeof(RasterVertex),
            VK_BUFFER_USAGE_VERTEX_BUFFER_BIT | VK_BUFFER_USAGE_STORAGE_BUFFER_BIT)) return false;
        if (!uploadBuffer(m_rasterDynamicIndices, indices.data(),
            (VkDeviceSize)indices.size() * sizeof(uint32_t),
            VK_BUFFER_USAGE_INDEX_BUFFER_BIT | VK_BUFFER_USAGE_STORAGE_BUFFER_BIT)) return false;
    } else {
        // Keep existing allocations. There is no reason to free/recreate them
        // just because this frame has no dynamic geometry.
        m_rasterDynamicIndexCount = 0;
    }
    m_rasterDynamicHash = hash;
    return true;
}

bool VulkanComputeRenderer::uploadRasterOverlayGeometry(const MenuOverlayRect* overlayRects,
                                                        uint32_t overlayRectCount,
                                                        bool overlayEnabled,
                                                        uint32_t overlayWindowW,
                                                        uint32_t overlayWindowH)
{
    uint64_t hash = 1469598103934665603ull;
    hash = fnv1aAppendValue(hash, overlayEnabled);
    hash = fnv1aAppendValue(hash, overlayWindowW);
    hash = fnv1aAppendValue(hash, overlayWindowH);
    const uint32_t cappedRectCount = std::min<uint32_t>(overlayRectCount, 1024u);
    hash = fnv1aAppendValue(hash, cappedRectCount);
    if (overlayEnabled && overlayRects && cappedRectCount > 0) {
        hash = fnv1aAppend(hash, overlayRects, sizeof(MenuOverlayRect) * (size_t)cappedRectCount);
    }

    if (!overlayEnabled) {
        m_rasterOverlayHash = hash;
        m_rasterOverlayIndexCount = 0;
        return true;
    }

    if (hash == m_rasterOverlayHash) {
        return true;
    }

    std::vector<RasterVertex> verts;
    std::vector<uint32_t> indices;

    auto push = [&](float x, float y, uint32_t color) -> uint32_t {
        RasterVertex rv{};
        rv.px = x; rv.py = y; rv.pz = 0.0f;
        rv.u = 0.f; rv.v = 0.f;
        rv.textureIndex = 0xFFFFFFFFu;
        rv.color = color;
        rv.mode = 1u;
        verts.push_back(rv);
        return (uint32_t)verts.size() - 1u;
    };
    auto quad = [&](float x0, float y0, float x1, float y1, uint32_t color) {
        const uint32_t base = (uint32_t)verts.size();
        push(x0, y0, color);
        push(x1, y0, color);
        push(x1, y1, color);
        push(x0, y1, color);
        indices.push_back(base + 0u);
        indices.push_back(base + 1u);
        indices.push_back(base + 2u);
        indices.push_back(base + 0u);
        indices.push_back(base + 2u);
        indices.push_back(base + 3u);
    };

    if (overlayEnabled) {
        // Same effect as the compute path's darkenPacked(color, 0.35): draw a
        // translucent black fullscreen quad over the scene.
        quad(-1.f, -1.f, 1.f, 1.f, 0xA6000000u); // alpha ~= 65%

        const float ww = (float)(overlayWindowW ? overlayWindowW : 1u);
        const float wh = (float)(overlayWindowH ? overlayWindowH : 1u);
        const uint32_t count = cappedRectCount;
        for (uint32_t i = 0; overlayRects && i < count; ++i) {
            const MenuOverlayRect& r = overlayRects[i];
            if (r.w <= 0 || r.h <= 0) continue;
            float x0 = 2.0f * (float)r.x / ww - 1.0f;
            float x1 = 2.0f * (float)(r.x + r.w) / ww - 1.0f;
            // Vulkan positive-height viewport: screen y=0 maps to NDC y=-1.
            // The previous OpenGL-style conversion made the pause overlay upside down.
            float y0 = 2.0f * (float)r.y / wh - 1.0f;
            float y1 = 2.0f * (float)(r.y + r.h) / wh - 1.0f;
            uint32_t c = r.color;
            if ((c & 0xFF000000u) == 0u) c |= 0xFF000000u;
            quad(x0, y0, x1, y1, c);
        }
    }

    m_rasterOverlayIndexCount = (uint32_t)indices.size();
    if (!verts.empty() && !indices.empty()) {
        if (!uploadBuffer(m_rasterOverlayVertices, verts.data(),
            (VkDeviceSize)verts.size() * sizeof(RasterVertex),
            VK_BUFFER_USAGE_VERTEX_BUFFER_BIT)) return false;
        if (!uploadBuffer(m_rasterOverlayIndices, indices.data(),
            (VkDeviceSize)indices.size() * sizeof(uint32_t),
            VK_BUFFER_USAGE_INDEX_BUFFER_BIT)) return false;
    } else {
        // Keep existing allocations. Reusing the buffer avoids allocator churn
        // when the overlay is toggled on/off.
        m_rasterOverlayIndexCount = 0;
    }
    m_rasterOverlayHash = hash;
    return true;
}

bool VulkanComputeRenderer::uploadCamera(const Player& player, const Map& map)
{
    const Vec3f cPosWorld = player.getPos();
    Vec3f cPos = cPosWorld;
    cPos.y += player.height;

    // Stabilise the raster camera without changing its historical screen signs.
    // The old incremental player plane vectors can contain a tiny depth-axis
    // roll; on very large floor/ceiling planes that shows up as view-dependent
    // G-buffer depth/normal shifts and therefore dark RT-lighting patches.
    //
    // Important: do NOT rebuild both axes only from cross products. Depending
    // on the handedness of player.m_plane this can invert cam.upPlane and make
    // the floor become the ceiling. Instead, remove roll, but keep the sign of
    // the player's existing horizontal and vertical camera axes.
    const Vec3f cDir = norm3(player.getDir());
    const Vec3f worldUp{0.f, 1.f, 0.f};
    const Vec3f rawRight = rejectFrom3(player.m_plane, cDir);
    const Vec3f rawUp = rejectFrom3(player.m_plane_up, cDir);

    float planeLen = player.m_plane.length();
    if (!std::isfinite(planeLen) || planeLen < 1e-4f) planeLen = 0.66f;

    Vec3f up = rejectFrom3(worldUp, cDir);
    if (dot3(up, up) < 1e-8f) up = rawUp;
    if (dot3(up, up) < 1e-8f) up = {0.f, 1.f, 0.f};
    up = norm3(up);
    if (dot3(rawUp, rawUp) > 1e-8f && dot3(up, rawUp) < 0.f) {
        up = scale3(up, -1.f);
    }

    Vec3f right = rawRight;
    right = rejectFrom3(right, cDir);
    right = {right.x - up.x * dot3(right, up),
             right.y - up.y * dot3(right, up),
             right.z - up.z * dot3(right, up)};
    if (dot3(right, right) < 1e-8f) {
        right = cross3(up, cDir);
        if (dot3(rawRight, rawRight) > 1e-8f && dot3(right, rawRight) < 0.f) {
            right = scale3(right, -1.f);
        }
    }
    if (dot3(right, right) < 1e-8f) right = {1.f, 0.f, 0.f};
    right = norm3(right);
    if (dot3(rawRight, rawRight) > 1e-8f && dot3(right, rawRight) < 0.f) {
        right = scale3(right, -1.f);
    }

    const float aspectY = (float)std::max(1, m_height) / (float)std::max(1, m_width);
    const Vec3f cPlane = scale3(right, planeLen);
    const Vec3f cUpPlane = scale3(up, planeLen * aspectY);

    MapData* md = map.mapData;
    GpuCamera cam;
    cam.pos = gv4(cPos.x - md->minX, cPos.y - md->minY, cPos.z - md->minZ, 0.f);
    cam.dir = gv4(cDir);
    cam.plane = gv4(cPlane);
    cam.upPlane = gv4(cUpPlane);
    #ifdef RENDER_DISTANCE
    const float renderDistance = m_editorMode ? 10000.f : (float)RENDER_DISTANCE;
#else
    const float renderDistance = m_editorMode ? 10000.f : 20.f;
#endif
#ifdef FOGMAX
    const float fogMax = m_editorMode ? 10000.f : (float)FOGMAX;
#else
    const float fogMax = m_editorMode ? 10000.f : 20.f;
#endif
#ifdef FOGFACTOR
    const float fogFactor = m_editorMode ? 0.f : (float)FOGFACTOR;
#else
    const float fogFactor = m_editorMode ? 0.f : 100.f;
#endif
#ifdef MINFOG
    const float minFog = m_editorMode ? 0.f : (float)MINFOG;
#else
    const float minFog = m_editorMode ? 0.f : 50.f;
#endif
#ifdef FOGSTART
    const float fogStart = m_editorMode ? 10000.f : (float)FOGSTART;
#else
    const float fogStart = m_editorMode ? 10000.f : 0.f;
#endif
    cam.fog = gv4(renderDistance, fogMax, fogFactor, minFog);
    cam.gridMin = gv4(md->minX, md->minY, md->minZ, fogStart);
    cam.screen = {(uint32_t)m_width, (uint32_t)m_height, (uint32_t)m_numRemotePlayers, m_editorMode ? 1u : 0u};
    cam.gridSize = {(uint32_t)md->sizeX, (uint32_t)md->sizeY, (uint32_t)md->sizeZ,
                    (uint32_t)(md->sizeX * md->sizeY * md->sizeZ)};

    return uploadBuffer(m_camera, &cam, sizeof(GpuCamera));
}

bool VulkanComputeRenderer::uploadLights(const MapData& md,
                                         const Player& player,
                                         const GpuRemotePlayer* remotePlayers,
                                         int numRemotePlayers)
{
    std::vector<GpuLight> lights;
    lights.reserve(md.lights.size() + 1u + (numRemotePlayers > 0 ? (size_t)numRemotePlayers : 0u));

    static constexpr float kMinVisibleLight = 0.015f;

    auto derivedRange = [&](float intensity) -> float {
        return std::sqrt(std::max(intensity / kMinVisibleLight - 1.0f, 0.25f));
    };

    auto makeBasisOffset = [](const Vec3f& forward, const Vec3f& localOffset) -> Vec3f {
        Vec3f f = norm3(forward);

        Vec3f worldUp{0.f, 1.f, 0.f};
        Vec3f right = cross3(worldUp, f);
        if (dot3(right, right) < 1e-8f) {
            right = {1.f, 0.f, 0.f};
        }
        right = norm3(right);

        Vec3f up = cross3(f, right);
        up = norm3(up);

        return {
            right.x * localOffset.x + up.x * localOffset.y + f.x * localOffset.z,
            right.y * localOffset.x + up.y * localOffset.y + f.y * localOffset.z,
            right.z * localOffset.x + up.z * localOffset.y + f.z * localOffset.z
        };
    };

    auto appendPlayerSpotlight = [&](const Vec3f& basePosAtPlayerHeight, const Vec3f& dir) {
        const float intensity = std::max(0.f, player.LIGHT_INTENSITY);
        if (intensity <= 0.0f) return;

        Vec3f n = norm3(dir);
        Vec3f lightOffset = makeBasisOffset(n, player.LIGHT_OFFSET);

        Vec3f lightPos {
            basePosAtPlayerHeight.x + lightOffset.x,
            basePosAtPlayerHeight.y + lightOffset.y,
            basePosAtPlayerHeight.z + lightOffset.z
        };

        GpuLight gl{};
        gl.position = gv4(lightPos.x, lightPos.y, lightPos.z, derivedRange(intensity));
        gl.color = gv4(
            std::max(0.f, player.LIGHT_COLOR.x),
            std::max(0.f, player.LIGHT_COLOR.y),
            std::max(0.f, player.LIGHT_COLOR.z),
            intensity
        );
        gl.normal = { n.x, n.y, n.z };
        gl.angle = (uint32_t)std::clamp((int)std::lround(player.LIGHT_ANGLE), 0, 180);

        lights.push_back(gl);
    };

    // Static map lights.
    for (const Light& l : md.lights) {
        if (l.intensity <= 0.0f) continue;

        const float intensity = std::max(0.f, l.intensity);
        const float visibleRange = (l.radius > 0.0f) ? l.radius : derivedRange(intensity);

        GpuLight gl{};
        gl.position = gv4(l.position.x, l.position.y, l.position.z, visibleRange);
        gl.color = gv4(
            std::max(0.f, l.color.x),
            std::max(0.f, l.color.y),
            std::max(0.f, l.color.z),
            intensity
        );
        gl.normal = { l.normal.x, l.normal.y, l.normal.z };
        gl.angle = (uint32_t)std::clamp((int)std::lround(l.angle), 0, 180);

        lights.push_back(gl);
    }

    // Local player flashlight.
    if (player.light_on) {
        Vec3f p = player.getPos();
        p.y += player.height;

        Vec3f localPos {
            p.x - md.minX,
            p.y - md.minY,
            p.z - md.minZ
        };

        appendPlayerSpotlight(localPos, player.getDir());
    }

    // Remote player flashlights.
    for (int i = 0; remotePlayers && i < numRemotePlayers; ++i) {
        const GpuRemotePlayer& rp = remotePlayers[i];

        if (rp.meta.x == 0u) continue;
        if (rp.light.x == 0u) continue;

        // Remote player forward direction: local +Z transformed by the uploaded rotation.
        Vec3f dir {
            rp.rot0.z,
            rp.rot1.z,
            rp.rot2.z
        };

        // Approximate remote eye/player-height position in grid-local coordinates.
        Vec3f basePosAtPlayerHeight {
            rp.offset.x + rp.pivot.x - player.MESH_OFFSET.x,
            rp.offset.y - player.MESH_OFFSET.y + player.height,
            rp.offset.z + rp.pivot.z - player.MESH_OFFSET.z
        };

        appendPlayerSpotlight(basePosAtPlayerHeight, dir);
    }

    m_uploadedLightCount = (uint32_t)lights.size();
    m_cpuLights = lights;

    if (lights.empty()) {
        lights.push_back({});
    }

    return uploadBuffer(m_Lights, lights.data(),
        (VkDeviceSize)lights.size() * sizeof(GpuLight));
}

bool VulkanComputeRenderer::uploadRasterDustGeometry(const Player& player, const Map& map)
{
    MapData* md = map.mapData;
    if (!md || m_dustDensityPercent <= 0 || m_dustBrightnessPercent <= 0 || m_cpuLights.empty()) {
        m_rasterDustIndexCount = 0;
        return true;
    }

    struct SpotLightCPU {
        Vec3f pos;
        Vec3f dir;
        Vec3f color;
        float intensity;
        float range;
        float cutoff;
    };

    std::vector<SpotLightCPU> spots;
    spots.reserve(m_cpuLights.size());
    for (const GpuLight& l : m_cpuLights) {
        // Game-style dust is intentionally limited to cones/shafts.  Plain
        // point lights do not spawn a room-filling dust cloud.
        if (l.angle == 0u || l.angle >= 179u) continue;
        if (l.color.w <= 0.0f || l.position.w <= 0.05f) continue;
        SpotLightCPU s{};
        s.pos = {l.position.x, l.position.y, l.position.z};
        s.dir = norm3({l.normal.x, l.normal.y, l.normal.z});
        s.color = {std::max(0.0f, l.color.x), std::max(0.0f, l.color.y), std::max(0.0f, l.color.z)};
        s.intensity = std::max(0.0f, l.color.w);
        s.range = std::max(0.1f, l.position.w);
        s.cutoff = std::cos((float)l.angle * 0.01745329251994329577f);
        spots.push_back(s);
    }

    if (spots.empty()) {
        m_rasterDustIndexCount = 0;
        return true;
    }

    const Vec3f cPosWorld = player.getPos();
    Vec3f cPos = cPosWorld;
    cPos.y += player.height;
    cPos = {cPos.x - md->minX, cPos.y - md->minY, cPos.z - md->minZ};

    const Vec3f cDir = norm3(player.getDir());
    const Vec3f worldUp{0.f, 1.f, 0.f};
    const Vec3f rawRight = rejectFrom3(player.m_plane, cDir);
    const Vec3f rawUp = rejectFrom3(player.m_plane_up, cDir);

    float planeLen = player.m_plane.length();
    if (!std::isfinite(planeLen) || planeLen < 1e-4f) planeLen = 0.66f;

    Vec3f camUp = rejectFrom3(worldUp, cDir);
    if (dot3(camUp, camUp) < 1e-8f) camUp = rawUp;
    if (dot3(camUp, camUp) < 1e-8f) camUp = {0.f, 1.f, 0.f};
    camUp = norm3(camUp);
    if (dot3(rawUp, rawUp) > 1e-8f && dot3(camUp, rawUp) < 0.f) camUp = scale3(camUp, -1.f);

    Vec3f camRight = rejectFrom3(rawRight, cDir);
    camRight = {camRight.x - camUp.x * dot3(camRight, camUp),
                camRight.y - camUp.y * dot3(camRight, camUp),
                camRight.z - camUp.z * dot3(camRight, camUp)};
    if (dot3(camRight, camRight) < 1e-8f) camRight = cross3(camUp, cDir);
    if (dot3(camRight, camRight) < 1e-8f) camRight = {1.f, 0.f, 0.f};
    camRight = norm3(camRight);
    if (dot3(rawRight, rawRight) > 1e-8f && dot3(camRight, rawRight) < 0.f) camRight = scale3(camRight, -1.f);

    const float aspectY = (float)std::max(1, m_height) / (float)std::max(1, m_width);
    const float rightLen = std::max(planeLen, 1e-4f);
    const float upLen = std::max(planeLen * aspectY, 1e-4f);

    auto hashU = [](int x, int y, int z, uint32_t salt) -> uint32_t {
        uint32_t h = 2166136261u;
        auto mix = [&](uint32_t v) { h ^= v; h *= 16777619u; };
        mix((uint32_t)x * 73856093u);
        mix((uint32_t)y * 19349663u);
        mix((uint32_t)z * 83492791u);
        mix(salt * 2654435761u);
        h ^= h >> 16;
        h *= 2246822519u;
        h ^= h >> 13;
        h *= 3266489917u;
        h ^= h >> 16;
        return h;
    };
    auto hash01 = [&](int x, int y, int z, uint32_t salt) -> float {
        return (float)(hashU(x, y, z, salt) & 0x00FFFFFFu) / 16777215.0f;
    };
    auto packArgb = [](float a, float r, float g, float b) -> uint32_t {
        auto to8 = [](float v) -> uint32_t { return (uint32_t)std::clamp((int)std::lround(std::clamp(v, 0.0f, 1.0f) * 255.0f), 0, 255); };
        return (to8(a) << 24) | (to8(r) << 16) | (to8(g) << 8) | to8(b);
    };
    auto pushVertex = [](std::vector<RasterVertex>& verts, const Vec3f& p, uint32_t color) {
        RasterVertex rv{};
        rv.px = p.x; rv.py = p.y; rv.pz = p.z;
        rv.nx = 0.f; rv.ny = 1.f; rv.nz = 0.f;
        rv.u = 0.f; rv.v = 0.f;
        rv.textureIndex = 0xFFFFFFFFu;
        rv.color = color;
        rv.mode = 2u; // light-cone dust mote
        verts.push_back(rv);
    };

    auto coneLightAt = [&](const Vec3f& p, Vec3f& outRgb, float& outStrength) -> bool {
        outRgb = {0.f, 0.f, 0.f};
        outStrength = 0.f;
        for (const SpotLightCPU& l : spots) {
            Vec3f lp = sub3(p, l.pos);
            const float d2 = dot3(lp, lp);
            if (d2 <= 1e-8f) continue;
            const float dist = std::sqrt(d2);
            if (dist >= l.range) continue;
            const Vec3f lightToP = scale3(lp, 1.0f / dist);
            const float cone = dot3(lightToP, l.dir);
            if (cone <= l.cutoff) continue;

            const float edge = std::max(0.035f, (1.0f - l.cutoff) * 0.22f);
            const float coneFade = std::clamp((cone - l.cutoff) / edge, 0.0f, 1.0f);
            const float rangeFade = std::clamp(1.0f - dist / l.range, 0.0f, 1.0f);
            const float atten = l.intensity / (1.0f + d2);
            const float strength = atten * coneFade * rangeFade;
            if (strength <= 0.00001f) continue;
            outRgb.x += l.color.x * strength;
            outRgb.y += l.color.y * strength;
            outRgb.z += l.color.z * strength;
            outStrength += strength;
        }
        return outStrength > 0.00002f;
    };

    // Legacy slider mapping:
    //   m_dustDensityPercent    = particle count; 10% still equals at least the old 100% count,
    //                              but the whole slider is now scaled up by another 500%.
    //   m_dustBrightnessPercent = particle size
    static constexpr float kCell = 0.20f;
    static constexpr uint32_t kMaxMotes = 210000u;
    const float radius = std::clamp(m_editorMode ? 10.0f : 7.0f, 3.5f, 10.0f);
    const float countUi = std::clamp((float)m_dustDensityPercent, 0.0f, 100.0f);
    const float occupancy = (countUi <= 0.0f) ? 0.0f : std::clamp(countUi * 0.280f, 0.0f, 1.0f);
    const float sizeUi = std::clamp((float)m_dustBrightnessPercent, 0.0f, 100.0f);
    const float sizeBase = 0.00055f + (sizeUi / 100.0f) * 0.00220f;
    const float timeSec = std::chrono::duration<float>(std::chrono::steady_clock::now() - m_dustStartTime).count();

    std::vector<RasterVertex> verts;
    std::vector<uint32_t> indices;
    verts.reserve(kMaxMotes * 3u);
    indices.reserve(kMaxMotes * 3u);

    const int ix0 = (int)std::floor((cPos.x - radius) / kCell);
    const int ix1 = (int)std::ceil ((cPos.x + radius) / kCell);
    const int iy0 = (int)std::floor((cPos.y - radius) / kCell);
    const int iy1 = (int)std::ceil ((cPos.y + radius) / kCell);
    const int iz0 = (int)std::floor((cPos.z - radius) / kCell);
    const int iz1 = (int)std::ceil ((cPos.z + radius) / kCell);

    for (int z = iz0; z <= iz1 && (indices.size() / 3u) < kMaxMotes; ++z) {
        for (int y = iy0; y <= iy1 && (indices.size() / 3u) < kMaxMotes; ++y) {
            for (int x = ix0; x <= ix1 && (indices.size() / 3u) < kMaxMotes; ++x) {
                if (hash01(x, y, z, 0u) > occupancy) continue;

                Vec3f p{
                    ((float)x + 0.12f + 0.76f * hash01(x, y, z, 1u)) * kCell,
                    ((float)y + 0.12f + 0.76f * hash01(x, y, z, 2u)) * kCell,
                    ((float)z + 0.12f + 0.76f * hash01(x, y, z, 3u)) * kCell
                };

                // Gentle world-space drift. The cell remains fixed in the room;
                // only the mote floats slightly inside it.
                const float phase = 6.2831853f * hash01(x, y, z, 4u);
                const float amp = 0.010f + 0.015f * hash01(x, y, z, 5u);
                p.x += std::sin(timeSec * (0.19f + 0.07f * hash01(x, y, z, 6u)) + phase) * amp;
                p.y += std::sin(timeSec * (0.13f + 0.06f * hash01(x, y, z, 7u)) + phase * 1.7f) * amp * 0.7f;
                p.z += std::cos(timeSec * (0.17f + 0.08f * hash01(x, y, z, 8u)) + phase * 1.3f) * amp;

                if (p.x < 0.f || p.y < 0.f || p.z < 0.f ||
                    p.x > (float)md->sizeX || p.y > (float)md->sizeY || p.z > (float)md->sizeZ) continue;

                Vec3f toP = sub3(p, cPos);
                const float dist2 = dot3(toP, toP);
                if (dist2 < 0.16f || dist2 > radius * radius) continue;
                const float fwd = dot3(toP, cDir);
                if (fwd <= 0.08f || fwd > radius) continue;

                // Coarse frustum reject. Slightly loose so motes can drift in at edges.
                const float ndcX = dot3(toP, camRight) / (fwd * rightLen);
                const float ndcY = -dot3(toP, camUp) / (fwd * upLen);
                if (std::abs(ndcX) > 1.14f || std::abs(ndcY) > 1.14f) continue;

                Vec3f lit;
                float strength = 0.0f;
                if (!coneLightAt(p, lit, strength)) continue;

                const float lum = lit.x * 0.2126f + lit.y * 0.7152f + lit.z * 0.0722f;
                if (lum <= 0.00002f) continue;

                const float nearFade = std::clamp((fwd - 0.35f) / 1.2f, 0.0f, 1.0f);
                const float farFade = std::clamp((radius - fwd) / std::max(radius * 0.35f, 1.0f), 0.0f, 1.0f);
                const float flicker = 0.65f + 0.35f * hash01(x, y, z, 9u);
                const float lightStrength = std::clamp(strength * 1.7f, 0.0f, 1.0f);
                const float alpha = std::clamp((0.010f + lightStrength * 0.080f) * nearFade * farFade * flicker,
                                               0.0f, 0.20f);
                if (alpha <= 0.0030f) continue;

                const float invLum = 1.0f / std::max(lum, 1e-4f);
                const float colorBoost = 1.0f + lightStrength * 0.65f;
                const float r = std::clamp(lit.x * invLum * colorBoost, 0.0f, 1.0f);
                const float g = std::clamp(lit.y * invLum * colorBoost, 0.0f, 1.0f);
                const float b = std::clamp(lit.z * invLum * colorBoost, 0.0f, 1.0f);
                const uint32_t color = packArgb(alpha, r, g, b);

                // Very tiny dust motes. The particle-size slider controls the average,
                // while each mote still varies randomly around that target size.
                const float randomScale = 0.55f + 0.90f * hash01(x, y, z, 10u);
                const float s = sizeBase * randomScale * std::clamp(fwd * 0.26f, 0.65f, 1.55f);
                const Vec3f v0 = add3(p, scale3(camUp, s));
                const Vec3f v1 = add3(add3(p, scale3(camUp, -0.5f * s)), scale3(camRight, 0.866f * s));
                const Vec3f v2 = add3(add3(p, scale3(camUp, -0.5f * s)), scale3(camRight, -0.866f * s));

                const uint32_t base = (uint32_t)verts.size();
                pushVertex(verts, v0, color);
                pushVertex(verts, v1, color);
                pushVertex(verts, v2, color);
                indices.push_back(base + 0u);
                indices.push_back(base + 1u);
                indices.push_back(base + 2u);
            }
        }
    }

    m_rasterDustIndexCount = (uint32_t)indices.size();
    if (!verts.empty() && !indices.empty()) {
        if (!uploadBuffer(m_rasterDustVertices, verts.data(),
                          (VkDeviceSize)verts.size() * sizeof(RasterVertex),
                          VK_BUFFER_USAGE_VERTEX_BUFFER_BIT)) return false;
        if (!uploadBuffer(m_rasterDustIndices, indices.data(),
                          (VkDeviceSize)indices.size() * sizeof(uint32_t),
                          VK_BUFFER_USAGE_INDEX_BUFFER_BIT)) return false;
    }
    return true;
}

bool VulkanComputeRenderer::uploadRtSettings(const Player& player, const Map& map)
{
    MapData* md = map.mapData;
    if (!md) return false;

    const Vec3f cPosWorld = player.getPos();
    Vec3f cPos = cPosWorld;
    cPos.y += player.height;
    cPos = {cPos.x - md->minX, cPos.y - md->minY, cPos.z - md->minZ};
    Vec3f cDir = player.getDir().normalized();

    const float dPosX = cPos.x - m_rtLastCameraPos.x;
    const float dPosY = cPos.y - m_rtLastCameraPos.y;
    const float dPosZ = cPos.z - m_rtLastCameraPos.z;
    const float posMove2 = dPosX*dPosX + dPosY*dPosY + dPosZ*dPosZ;
    const float dirDot = cDir.x*m_rtLastCameraDir.x + cDir.y*m_rtLastCameraDir.y + cDir.z*m_rtLastCameraDir.z;

    updateRtResolution();

    bool reset = false;
    if (m_rtLastMapVersion != md->version) reset = true;
    if (m_rtLastWidth != m_rtWidth || m_rtLastHeight != m_rtHeight) reset = true;
    if (posMove2 > 0.0025f) reset = true;             // more than ~5cm
    if (dirDot < 0.9995f) reset = true;               // camera turned enough to ghost
    if (!m_raytracingEnabled || m_raytracingQualityPercent <= 0) reset = true;

    if (reset && m_rtHistoryValid) {
        std::cout << "[RT/History] reset mapVersion=" << md->version
                  << " rtSize=" << m_rtWidth << "x" << m_rtHeight
                  << " fullSize=" << m_width << "x" << m_height
                  << " posMove2=" << posMove2 << " dirDot=" << dirDot << "\n";
    }
    if (reset) m_rtHistoryValid = false;

    uint32_t samplesPer64 = 0u;
    if (m_raytracingEnabled) {
        // Quality is now a real sampling budget.  100% traces every pixel;
        // 1% traces exactly one pixel per 8x8 tile.  Intermediate values map
        // linearly to 1..64 traced pixels per tile.
        const float q = std::clamp((float)m_raytracingQualityPercent, 1.0f, 100.0f);
        samplesPer64 = std::clamp((uint32_t)std::lround(q * 64.0f / 100.0f), 1u, 64u);
    }

    GpuRtSettings st{};
    st.flags = {samplesPer64 ? 1u : 0u, (uint32_t)m_raytracingQualityPercent, m_rtFrameIndex, m_uploadedLightCount};
    // SAFE RT bring-up mode: temporal/history is hard disabled until the
    // G-buffer -> RT lighting -> spatial -> composite path is stable.
    // modes.x = samples per 8x8 tile at RT resolution.
    // modes.y = historyValid, modes.z/modes.w = current low-res RT dimensions.
    st.modes = {samplesPer64, 0u, (uint32_t)m_rtWidth, (uint32_t)m_rtHeight};
    st.params = gv4((float)m_uploadedLightCount, 0.025f, 0.18f, 0.0f);

    m_rtLastMapVersion = md->version;
    m_rtLastWidth = m_rtWidth;
    m_rtLastHeight = m_rtHeight;
    m_rtLastCameraPos = cPos;
    m_rtLastCameraDir = cDir;

    return uploadBuffer(m_rtSettings, &st, sizeof(GpuRtSettings));
}

void VulkanComputeRenderer::updateDescriptorSet()
{
    if (!m_descriptorSetDirty) return;
    if (!m_device || !m_descSet || !m_pixels.buffer) return;

    Buffer* bufs[19] = { &m_pixels, &m_camera, &m_cells, &m_items, &m_boxes, &m_planes,
                         &m_texInfos, &m_texPixels, &m_meshes, &m_meshCells,
                         &m_triangles, &m_bvhNodes, &m_triIndices,
                         &m_remotePlayers, &m_playerMesh, &m_overlayRects,
                         &m_overlayState, &m_Lights, &m_rtSettings };

    VkDescriptorBufferInfo bufferInfos[19]{};
    std::vector<VkWriteDescriptorSet> writes;
    writes.reserve(27);
    for (uint32_t i = 0; i < 19; ++i) {
        if (!bufs[i]->buffer) continue;
        bufferInfos[i].buffer = bufs[i]->buffer;
        bufferInfos[i].offset = 0;
        bufferInfos[i].range = bufs[i]->size;

        VkWriteDescriptorSet w{VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET};
        w.dstSet = m_descSet;
        w.dstBinding = i;
        w.descriptorCount = 1;
        w.descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        w.pBufferInfo = &bufferInfos[i];
        writes.push_back(w);
    }

    RtImage* imgs[8] = { &m_gbufferAlbedo, &m_gbufferNormal, &m_gbufferDepth,
                         &m_rtLightingRaw, &m_rtLightingFiltered,
                         &m_rtHistoryA, &m_rtHistoryB, &m_rtComposite };
    VkDescriptorImageInfo imageInfos[8]{};
    for (uint32_t i = 0; i < 8; ++i) {
        if (!imgs[i]->view) continue;
        imageInfos[i].imageLayout = VK_IMAGE_LAYOUT_GENERAL;
        imageInfos[i].imageView = imgs[i]->view;
        imageInfos[i].sampler = VK_NULL_HANDLE;

        VkWriteDescriptorSet w{VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET};
        w.dstSet = m_descSet;
        w.dstBinding = 19u + i;
        w.descriptorCount = 1;
        w.descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_IMAGE;
        w.pImageInfo = &imageInfos[i];
        writes.push_back(w);
    }

    if (!writes.empty()) {
        vkUpdateDescriptorSets(m_device, (uint32_t)writes.size(), writes.data(), 0, nullptr);
    }
    std::cout << "[RT/Descriptors] rewrote descriptor set: writes=" << writes.size()
              << " buffers+images, lightCount=" << m_uploadedLightCount << "\n";
    m_descriptorSetDirty = false;
}


static void imageBarrierCmd(VkCommandBuffer cmd,
                            VkImage image,
                            VkImageLayout oldLayout,
                            VkImageLayout newLayout,
                            VkAccessFlags srcAccess,
                            VkAccessFlags dstAccess,
                            VkPipelineStageFlags srcStage,
                            VkPipelineStageFlags dstStage)
{
    VkImageMemoryBarrier b{VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER};
    b.oldLayout = oldLayout;
    b.newLayout = newLayout;
    b.srcAccessMask = srcAccess;
    b.dstAccessMask = dstAccess;
    b.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    b.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    b.image = image;
    b.subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    b.subresourceRange.baseMipLevel = 0;
    b.subresourceRange.levelCount = 1;
    b.subresourceRange.baseArrayLayer = 0;
    b.subresourceRange.layerCount = 1;
    vkCmdPipelineBarrier(cmd, srcStage, dstStage, 0, 0, nullptr, 0, nullptr, 1, &b);
}

bool VulkanComputeRenderer::recordAndSubmit()
{
    return recordAndSubmitPresent();
}

bool VulkanComputeRenderer::recordAndSubmitPresent()
{
    if (!m_swapchain || m_swapchainImages.empty()) {
        if (!recreatePresentationResources()) return false;
    }

    RECT rc{};
    GetClientRect(m_hwnd, &rc);
    const uint32_t clientW = (uint32_t)std::max<LONG>(1, rc.right - rc.left);
    const uint32_t clientH = (uint32_t)std::max<LONG>(1, rc.bottom - rc.top);
    if (clientW != m_swapchainExtent.width || clientH != m_swapchainExtent.height) {
        vkDeviceWaitIdle(m_device);
        if (!recreatePresentationResources()) return false;
    }

    uint32_t imageIndex = 0;
    VkResult ar = vkAcquireNextImageKHR(m_device, m_swapchain, UINT64_MAX, m_imageAvailable, VK_NULL_HANDLE, &imageIndex);
    if (ar == VK_ERROR_OUT_OF_DATE_KHR || ar == VK_SUBOPTIMAL_KHR) {
        vkDeviceWaitIdle(m_device);
        return recreatePresentationResources();
    }
    if (ar != VK_SUCCESS) {
        setError("vkAcquireNextImageKHR failed");
        return false;
    }

    vkResetFences(m_device, 1, &m_fence);
    vkResetCommandBuffer(m_commandBuffer, 0);

    VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    if (vkBeginCommandBuffer(m_commandBuffer, &bi) != VK_SUCCESS) {
        setError("vkBeginCommandBuffer failed"); return false;
    }

    vkCmdBindPipeline(m_commandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, m_pipeline);
    vkCmdBindDescriptorSets(m_commandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE,
        m_pipelineLayout, 0, 1, &m_descSet, 0, nullptr);
    vkCmdDispatch(m_commandBuffer, (uint32_t)((m_width + 7) / 8), (uint32_t)((m_height + 7) / 8), 1);

    VkBufferMemoryBarrier pixBarrier{VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER};
    pixBarrier.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
    pixBarrier.dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT;
    pixBarrier.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    pixBarrier.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    pixBarrier.buffer = m_pixels.buffer;
    pixBarrier.offset = 0;
    pixBarrier.size = VK_WHOLE_SIZE;
    vkCmdPipelineBarrier(m_commandBuffer,
        VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
        VK_PIPELINE_STAGE_TRANSFER_BIT,
        0, 0, nullptr, 1, &pixBarrier, 0, nullptr);

    imageBarrierCmd(m_commandBuffer, m_renderImage,
        VK_IMAGE_LAYOUT_UNDEFINED, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
        0, VK_ACCESS_TRANSFER_WRITE_BIT,
        VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT);

    VkBufferImageCopy bic{};
    bic.bufferOffset = 0;
    bic.bufferRowLength = 0;
    bic.bufferImageHeight = 0;
    bic.imageSubresource.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    bic.imageSubresource.mipLevel = 0;
    bic.imageSubresource.baseArrayLayer = 0;
    bic.imageSubresource.layerCount = 1;
    bic.imageOffset = {0, 0, 0};
    bic.imageExtent = {(uint32_t)m_width, (uint32_t)m_height, 1};
    vkCmdCopyBufferToImage(m_commandBuffer, m_pixels.buffer, m_renderImage,
        VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, 1, &bic);

    imageBarrierCmd(m_commandBuffer, m_renderImage,
        VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
        VK_ACCESS_TRANSFER_WRITE_BIT, VK_ACCESS_TRANSFER_READ_BIT,
        VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT);

    VkImage swapImg = m_swapchainImages[imageIndex];
    imageBarrierCmd(m_commandBuffer, swapImg,
        VK_IMAGE_LAYOUT_UNDEFINED, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
        0, VK_ACCESS_TRANSFER_WRITE_BIT,
        VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT);

    VkImageBlit blit{};
    blit.srcSubresource.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    blit.srcSubresource.mipLevel = 0;
    blit.srcSubresource.baseArrayLayer = 0;
    blit.srcSubresource.layerCount = 1;
    blit.srcOffsets[0] = {0, 0, 0};
    blit.srcOffsets[1] = {m_width, m_height, 1};
    blit.dstSubresource.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    blit.dstSubresource.mipLevel = 0;
    blit.dstSubresource.baseArrayLayer = 0;
    blit.dstSubresource.layerCount = 1;
    blit.dstOffsets[0] = {0, 0, 0};
    blit.dstOffsets[1] = {(int32_t)m_swapchainExtent.width, (int32_t)m_swapchainExtent.height, 1};
    vkCmdBlitImage(m_commandBuffer,
        m_renderImage, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
        swapImg, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
        1, &blit, VK_FILTER_NEAREST);

    imageBarrierCmd(m_commandBuffer, swapImg,
        VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, VK_IMAGE_LAYOUT_PRESENT_SRC_KHR,
        VK_ACCESS_TRANSFER_WRITE_BIT, 0,
        VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT);

    if (vkEndCommandBuffer(m_commandBuffer) != VK_SUCCESS) {
        setError("vkEndCommandBuffer failed"); return false;
    }

    VkPipelineStageFlags waitStage = VK_PIPELINE_STAGE_TRANSFER_BIT;
    VkSubmitInfo si{VK_STRUCTURE_TYPE_SUBMIT_INFO};
    si.waitSemaphoreCount = 1;
    si.pWaitSemaphores = &m_imageAvailable;
    si.pWaitDstStageMask = &waitStage;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &m_commandBuffer;
    si.signalSemaphoreCount = 1;
    si.pSignalSemaphores = &m_renderFinished;
    if (vkQueueSubmit(m_queue, 1, &si, m_fence) != VK_SUCCESS) {
        setError("vkQueueSubmit failed"); return false;
    }
    if (vkWaitForFences(m_device, 1, &m_fence, VK_TRUE, UINT64_MAX) != VK_SUCCESS) {
        setError("vkWaitForFences failed"); return false;
    }

    VkPresentInfoKHR pi{VK_STRUCTURE_TYPE_PRESENT_INFO_KHR};
    pi.waitSemaphoreCount = 1;
    pi.pWaitSemaphores = &m_renderFinished;
    pi.swapchainCount = 1;
    pi.pSwapchains = &m_swapchain;
    pi.pImageIndices = &imageIndex;
    VkResult pr = vkQueuePresentKHR(m_queue, &pi);
    if (pr == VK_ERROR_OUT_OF_DATE_KHR || pr == VK_SUBOPTIMAL_KHR) {
        vkDeviceWaitIdle(m_device);
        return recreatePresentationResources();
    }
    if (pr != VK_SUCCESS) {
        setError("vkQueuePresentKHR failed");
        return false;
    }
    return true;
}


bool VulkanComputeRenderer::recordAndSubmitRaster()
{
    const bool rtActive = m_raytracingEnabled;

    if (!rtActive) {
        return recordAndSubmitRasterDirect();
    }

    return recordAndSubmitRasterRtComposite();
}

bool VulkanComputeRenderer::recordAndSubmitRasterDirect()
{
    using Clock = std::chrono::high_resolution_clock;
    const auto t0 = Clock::now();
    m_lastRasterAcquireMs = 0.0;
    m_lastRasterRecordMs = 0.0;
    m_lastRasterSubmitWaitMs = 0.0;
    m_lastRasterPresentMs = 0.0;
    m_lastRtLightingMs = 0.0;
    m_lastRtCompositeMs = 0.0;

    if (!m_swapchain || m_swapchainImages.empty() || !m_directRasterFramebuffer) {
        if (!recreatePresentationResources()) return false;
    }

    RECT rc{};
    GetClientRect(m_hwnd, &rc);
    const uint32_t clientW = (uint32_t)std::max<LONG>(1, rc.right - rc.left);
    const uint32_t clientH = (uint32_t)std::max<LONG>(1, rc.bottom - rc.top);
    if (clientW != m_swapchainExtent.width || clientH != m_swapchainExtent.height) {
        vkDeviceWaitIdle(m_device);
        if (!recreatePresentationResources()) return false;
    }

    uint32_t imageIndex = 0;
    VkResult ar = vkAcquireNextImageKHR(m_device, m_swapchain, UINT64_MAX, m_imageAvailable, VK_NULL_HANDLE, &imageIndex);
    if (ar == VK_ERROR_OUT_OF_DATE_KHR || ar == VK_SUBOPTIMAL_KHR) {
        vkDeviceWaitIdle(m_device);
        return recreatePresentationResources();
    }
    if (ar != VK_SUCCESS) {
        setError("vkAcquireNextImageKHR direct raster failed");
        return false;
    }
    const auto tAcquireDone = Clock::now();

    vkResetFences(m_device, 1, &m_fence);
    vkResetCommandBuffer(m_commandBuffer, 0);

    VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    if (vkBeginCommandBuffer(m_commandBuffer, &bi) != VK_SUCCESS) {
        setError("vkBeginCommandBuffer direct raster failed");
        return false;
    }

    std::array<VkClearValue, 2> clears{};
    clears[0].color = {{0.f, 0.f, 0.f, 1.f}};
    clears[1].depthStencil = {1.f, 0};

    VkRenderPassBeginInfo rpbi{VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO};
    rpbi.renderPass = m_directRasterRenderPass;
    rpbi.framebuffer = m_directRasterFramebuffer;
    rpbi.renderArea.offset = {0, 0};
    rpbi.renderArea.extent = {(uint32_t)std::max(1, m_width), (uint32_t)std::max(1, m_height)};
    rpbi.clearValueCount = (uint32_t)clears.size();
    rpbi.pClearValues = clears.data();

    vkCmdBeginRenderPass(m_commandBuffer, &rpbi, VK_SUBPASS_CONTENTS_INLINE);

    VkViewport viewport{};
    viewport.x = 0.f;
    viewport.y = 0.f;
    viewport.width = (float)std::max(1, m_width);
    viewport.height = (float)std::max(1, m_height);
    viewport.minDepth = 0.f;
    viewport.maxDepth = 1.f;
    VkRect2D scissor{{0,0}, {(uint32_t)std::max(1, m_width), (uint32_t)std::max(1, m_height)}};
    vkCmdSetViewport(m_commandBuffer, 0, 1, &viewport);
    vkCmdSetScissor(m_commandBuffer, 0, 1, &scissor);

    auto drawIndexedBuffer = [&](const Buffer& vb, const Buffer& ib, uint32_t indexCount) {
        if (indexCount == 0 || !vb.buffer || !ib.buffer) return;
        VkDeviceSize off = 0;
        vkCmdBindVertexBuffers(m_commandBuffer, 0, 1, &vb.buffer, &off);
        vkCmdBindIndexBuffer(m_commandBuffer, ib.buffer, 0, VK_INDEX_TYPE_UINT32);
        vkCmdDrawIndexed(m_commandBuffer, indexCount, 1, 0, 0, 0);
    };

    vkCmdBindDescriptorSets(m_commandBuffer, VK_PIPELINE_BIND_POINT_GRAPHICS,
        m_directRasterPipelineLayout, 0, 1, &m_descSet, 0, nullptr);

    vkCmdBindPipeline(m_commandBuffer, VK_PIPELINE_BIND_POINT_GRAPHICS, m_directRasterPipeline);
    drawIndexedBuffer(m_rasterStaticVertices, m_rasterStaticIndices, m_rasterStaticIndexCount);
    drawIndexedBuffer(m_rasterDynamicVertices, m_rasterDynamicIndices, m_rasterDynamicIndexCount);

    if (m_rasterDustIndexCount > 0 && m_directRasterDustPipeline != VK_NULL_HANDLE) {
        vkCmdBindPipeline(m_commandBuffer, VK_PIPELINE_BIND_POINT_GRAPHICS, m_directRasterDustPipeline);
        drawIndexedBuffer(m_rasterDustVertices, m_rasterDustIndices, m_rasterDustIndexCount);
    }

    if (m_rasterOverlayIndexCount > 0) {
        vkCmdBindPipeline(m_commandBuffer, VK_PIPELINE_BIND_POINT_GRAPHICS, m_directRasterOverlayPipeline);
        drawIndexedBuffer(m_rasterOverlayVertices, m_rasterOverlayIndices, m_rasterOverlayIndexCount);
    }

    vkCmdEndRenderPass(m_commandBuffer);

    imageBarrierCmd(m_commandBuffer, m_renderImage,
        VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
        VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT, VK_ACCESS_TRANSFER_READ_BIT,
        VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT);

    VkImage swapImg = m_swapchainImages[imageIndex];
    imageBarrierCmd(m_commandBuffer, swapImg,
        VK_IMAGE_LAYOUT_UNDEFINED, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
        0, VK_ACCESS_TRANSFER_WRITE_BIT,
        VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT);

    VkImageBlit blit{};
    blit.srcSubresource.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    blit.srcSubresource.mipLevel = 0;
    blit.srcSubresource.baseArrayLayer = 0;
    blit.srcSubresource.layerCount = 1;
    blit.srcOffsets[0] = {0, 0, 0};
    blit.srcOffsets[1] = {std::max(1, m_width), std::max(1, m_height), 1};
    blit.dstSubresource.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    blit.dstSubresource.mipLevel = 0;
    blit.dstSubresource.baseArrayLayer = 0;
    blit.dstSubresource.layerCount = 1;
    blit.dstOffsets[0] = {0, 0, 0};
    blit.dstOffsets[1] = {(int32_t)m_swapchainExtent.width, (int32_t)m_swapchainExtent.height, 1};
    vkCmdBlitImage(m_commandBuffer,
        m_renderImage, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
        swapImg, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
        1, &blit, VK_FILTER_NEAREST);

    imageBarrierCmd(m_commandBuffer, swapImg,
        VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, VK_IMAGE_LAYOUT_PRESENT_SRC_KHR,
        VK_ACCESS_TRANSFER_WRITE_BIT, 0,
        VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT);

    if (vkEndCommandBuffer(m_commandBuffer) != VK_SUCCESS) {
        setError("vkEndCommandBuffer direct raster failed");
        return false;
    }
    const auto tRecordDone = Clock::now();

    VkPipelineStageFlags waitStage = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    VkSubmitInfo si{VK_STRUCTURE_TYPE_SUBMIT_INFO};
    si.waitSemaphoreCount = 1;
    si.pWaitSemaphores = &m_imageAvailable;
    si.pWaitDstStageMask = &waitStage;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &m_commandBuffer;
    si.signalSemaphoreCount = 1;
    si.pSignalSemaphores = &m_renderFinished;
    VkResult sr = vkQueueSubmit(m_queue, 1, &si, m_fence);
    if (sr != VK_SUCCESS) {
        setError(std::string("vkQueueSubmit direct raster failed VkResult=") + std::to_string((int)sr));
        return false;
    }
    VkResult wr = vkWaitForFences(m_device, 1, &m_fence, VK_TRUE, UINT64_MAX);
    if (wr != VK_SUCCESS) {
        setError(std::string("vkWaitForFences direct raster failed VkResult=") + std::to_string((int)wr));
        return false;
    }
    const auto tSubmitWaitDone = Clock::now();

    VkPresentInfoKHR pi{VK_STRUCTURE_TYPE_PRESENT_INFO_KHR};
    pi.waitSemaphoreCount = 1;
    pi.pWaitSemaphores = &m_renderFinished;
    pi.swapchainCount = 1;
    pi.pSwapchains = &m_swapchain;
    pi.pImageIndices = &imageIndex;
    VkResult pr = vkQueuePresentKHR(m_queue, &pi);
    if (pr == VK_ERROR_OUT_OF_DATE_KHR || pr == VK_SUBOPTIMAL_KHR) {
        vkDeviceWaitIdle(m_device);
        return recreatePresentationResources();
    }
    if (pr != VK_SUCCESS) {
        setError(std::string("vkQueuePresentKHR direct raster failed VkResult=") + std::to_string((int)pr));
        return false;
    }
    const auto tPresentDone = Clock::now();

    m_lastRasterAcquireMs = elapsedMs(t0, tAcquireDone);
    m_lastRasterRecordMs = elapsedMs(tAcquireDone, tRecordDone);
    m_lastRasterSubmitWaitMs = elapsedMs(tRecordDone, tSubmitWaitDone);
    m_lastRasterPresentMs = elapsedMs(tSubmitWaitDone, tPresentDone);
    return true;
}

bool VulkanComputeRenderer::recordAndSubmitRasterRtComposite()
{
    using Clock = std::chrono::high_resolution_clock;
    const auto t0 = Clock::now();
    m_lastRasterAcquireMs = 0.0;
    m_lastRasterRecordMs = 0.0;
    m_lastRasterSubmitWaitMs = 0.0;
    m_lastRasterPresentMs = 0.0;
    m_lastRtLightingMs = 0.0;
    m_lastRtCompositeMs = 0.0;

    if (!m_swapchain || m_swapchainImages.empty() || !m_gbufferFramebuffer) {
        if (!recreatePresentationResources()) return false;
    }

    RECT rc{};
    GetClientRect(m_hwnd, &rc);
    const uint32_t clientW = (uint32_t)std::max<LONG>(1, rc.right - rc.left);
    const uint32_t clientH = (uint32_t)std::max<LONG>(1, rc.bottom - rc.top);
    if (clientW != m_swapchainExtent.width || clientH != m_swapchainExtent.height) {
        vkDeviceWaitIdle(m_device);
        if (!recreatePresentationResources()) return false;
    }

    uint32_t imageIndex = 0;
    VkResult ar = vkAcquireNextImageKHR(m_device, m_swapchain, UINT64_MAX, m_imageAvailable, VK_NULL_HANDLE, &imageIndex);
    if (ar == VK_ERROR_OUT_OF_DATE_KHR || ar == VK_SUBOPTIMAL_KHR) {
        vkDeviceWaitIdle(m_device);
        return recreatePresentationResources();
    }
    if (ar != VK_SUCCESS) {
        setError("vkAcquireNextImageKHR raster/rt failed");
        return false;
    }
    const auto tAcquireDone = Clock::now();

    vkResetFences(m_device, 1, &m_fence);
    vkResetCommandBuffer(m_commandBuffer, 0);

    VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    if (vkBeginCommandBuffer(m_commandBuffer, &bi) != VK_SUCCESS) {
        setError("vkBeginCommandBuffer raster/rt failed"); return false;
    }

    if (!m_rtImagesInitialized) {
        auto initRtImage = [&](RtImage& img) {
            if (!img.image) return;
            imageBarrierCmd(m_commandBuffer, img.image,
                VK_IMAGE_LAYOUT_UNDEFINED, VK_IMAGE_LAYOUT_GENERAL,
                0, VK_ACCESS_SHADER_READ_BIT | VK_ACCESS_SHADER_WRITE_BIT,
                VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT);
        };
        initRtImage(m_rtLightingRaw);
        initRtImage(m_rtLightingFiltered);
        initRtImage(m_rtHistoryA);
        initRtImage(m_rtHistoryB);
        initRtImage(m_rtComposite);
    }

    std::array<VkClearValue, 4> clears{};
    clears[0].color = {{0.f, 0.f, 0.f, 1.f}};
    clears[1].color = {{0.5f, 1.f, 0.5f, 1.f}};
    clears[2].color = {{1.f, 0.f, 0.f, 1.f}};
    clears[3].depthStencil = {1.f, 0};

    VkRenderPassBeginInfo rpbi{VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO};
    rpbi.renderPass = m_rasterRenderPass;
    rpbi.framebuffer = m_gbufferFramebuffer;
    rpbi.renderArea.offset = {0, 0};
    rpbi.renderArea.extent = {(uint32_t)std::max(1, m_width), (uint32_t)std::max(1, m_height)};
    rpbi.clearValueCount = (uint32_t)clears.size();
    rpbi.pClearValues = clears.data();

    vkCmdBeginRenderPass(m_commandBuffer, &rpbi, VK_SUBPASS_CONTENTS_INLINE);

    VkViewport viewport{};
    viewport.x = 0.f;
    viewport.y = 0.f;
    viewport.width = (float)std::max(1, m_width);
    viewport.height = (float)std::max(1, m_height);
    viewport.minDepth = 0.f;
    viewport.maxDepth = 1.f;
    VkRect2D scissor{{0,0}, {(uint32_t)std::max(1, m_width), (uint32_t)std::max(1, m_height)}};
    vkCmdSetViewport(m_commandBuffer, 0, 1, &viewport);
    vkCmdSetScissor(m_commandBuffer, 0, 1, &scissor);

    auto drawIndexedBuffer = [&](const Buffer& vb, const Buffer& ib, uint32_t indexCount) {
        if (indexCount == 0 || !vb.buffer || !ib.buffer) return;
        VkDeviceSize off = 0;
        vkCmdBindVertexBuffers(m_commandBuffer, 0, 1, &vb.buffer, &off);
        vkCmdBindIndexBuffer(m_commandBuffer, ib.buffer, 0, VK_INDEX_TYPE_UINT32);
        vkCmdDrawIndexed(m_commandBuffer, indexCount, 1, 0, 0, 0);
    };

    vkCmdBindPipeline(m_commandBuffer, VK_PIPELINE_BIND_POINT_GRAPHICS, m_rasterPipeline);
    vkCmdBindDescriptorSets(m_commandBuffer, VK_PIPELINE_BIND_POINT_GRAPHICS,
        m_rasterPipelineLayout, 0, 1, &m_descSet, 0, nullptr);
    drawIndexedBuffer(m_rasterStaticVertices, m_rasterStaticIndices, m_rasterStaticIndexCount);
    drawIndexedBuffer(m_rasterDynamicVertices, m_rasterDynamicIndices, m_rasterDynamicIndexCount);
    vkCmdEndRenderPass(m_commandBuffer);

    const auto tGBufferDone = Clock::now();

    auto shaderBarrier = [&](RtImage& img, VkAccessFlags src, VkAccessFlags dst,
                             VkPipelineStageFlags srcStage, VkPipelineStageFlags dstStage) {
        if (!img.image) return;
        imageBarrierCmd(m_commandBuffer, img.image, VK_IMAGE_LAYOUT_GENERAL, VK_IMAGE_LAYOUT_GENERAL,
                        src, dst, srcStage, dstStage);
    };

    shaderBarrier(m_gbufferAlbedo, VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT, VK_ACCESS_SHADER_READ_BIT,
                  VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT);
    shaderBarrier(m_gbufferNormal, VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT, VK_ACCESS_SHADER_READ_BIT,
                  VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT);
    shaderBarrier(m_gbufferDepth, VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT, VK_ACCESS_SHADER_READ_BIT,
                  VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT);

    const uint32_t fullGroupsX = ((uint32_t)std::max(1, m_width) + 7u) / 8u;
    const uint32_t fullGroupsY = ((uint32_t)std::max(1, m_height) + 7u) / 8u;
    const uint32_t rtGroupsX = ((uint32_t)std::max(1, m_rtWidth) + 7u) / 8u;
    const uint32_t rtGroupsY = ((uint32_t)std::max(1, m_rtHeight) + 7u) / 8u;

    vkCmdBindDescriptorSets(m_commandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE,
        m_pipelineLayout, 0, 1, &m_descSet, 0, nullptr);

    vkCmdBindPipeline(m_commandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, m_rtLightingPipeline);
    vkCmdDispatch(m_commandBuffer, rtGroupsX, rtGroupsY, 1);
    shaderBarrier(m_rtLightingRaw, VK_ACCESS_SHADER_WRITE_BIT, VK_ACCESS_SHADER_READ_BIT,
                  VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT);

    vkCmdBindPipeline(m_commandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, m_rtSpatialPipeline);
    vkCmdDispatch(m_commandBuffer, rtGroupsX, rtGroupsY, 1);
    shaderBarrier(m_rtLightingFiltered, VK_ACCESS_SHADER_WRITE_BIT, VK_ACCESS_SHADER_READ_BIT,
                  VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT);

    // Temporal accumulation is intentionally bypassed in this crash-fix patch.
    // This removes all history ping-pong reads/writes from the first stable RT test.
    const auto tRtDone = Clock::now();

    vkCmdBindPipeline(m_commandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, m_rtCompositePipeline);
    vkCmdDispatch(m_commandBuffer, fullGroupsX, fullGroupsY, 1);
    shaderBarrier(m_rtComposite, VK_ACCESS_SHADER_WRITE_BIT, VK_ACCESS_TRANSFER_READ_BIT,
                  VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT);

    imageBarrierCmd(m_commandBuffer, m_renderImage,
        VK_IMAGE_LAYOUT_UNDEFINED, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
        0, VK_ACCESS_TRANSFER_WRITE_BIT,
        VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT);

    VkImageBlit blit{};
    blit.srcSubresource.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    blit.srcSubresource.mipLevel = 0;
    blit.srcSubresource.baseArrayLayer = 0;
    blit.srcSubresource.layerCount = 1;
    blit.srcOffsets[0] = {0, 0, 0};
    blit.srcOffsets[1] = {std::max(1, m_width), std::max(1, m_height), 1};
    blit.dstSubresource.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    blit.dstSubresource.mipLevel = 0;
    blit.dstSubresource.baseArrayLayer = 0;
    blit.dstSubresource.layerCount = 1;
    blit.dstOffsets[0] = {0, 0, 0};
    blit.dstOffsets[1] = {std::max(1, m_width), std::max(1, m_height), 1};
    vkCmdBlitImage(m_commandBuffer,
        m_rtComposite.image, VK_IMAGE_LAYOUT_GENERAL,
        m_renderImage, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
        1, &blit, VK_FILTER_NEAREST);

    if (m_rasterDustIndexCount > 0 && m_particleOverlayFramebuffer != VK_NULL_HANDLE &&
        m_particleOverlayDustPipeline != VK_NULL_HANDLE) {
        imageBarrierCmd(m_commandBuffer, m_renderImage,
            VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL,
            VK_ACCESS_TRANSFER_WRITE_BIT, VK_ACCESS_COLOR_ATTACHMENT_READ_BIT | VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT,
            VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT);

        std::array<VkClearValue, 2> dustClears{};
        dustClears[0].color = {{0.f, 0.f, 0.f, 1.f}}; // ignored: color attachment is LOAD
        dustClears[1].depthStencil = {1.f, 0};        // ignored: depth attachment is LOAD

        VkRenderPassBeginInfo dustRp{VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO};
        dustRp.renderPass = m_particleOverlayRenderPass;
        dustRp.framebuffer = m_particleOverlayFramebuffer;
        dustRp.renderArea.offset = {0, 0};
        dustRp.renderArea.extent = {(uint32_t)std::max(1, m_width), (uint32_t)std::max(1, m_height)};
        dustRp.clearValueCount = (uint32_t)dustClears.size();
        dustRp.pClearValues = dustClears.data();

        vkCmdBeginRenderPass(m_commandBuffer, &dustRp, VK_SUBPASS_CONTENTS_INLINE);
        vkCmdSetViewport(m_commandBuffer, 0, 1, &viewport);
        vkCmdSetScissor(m_commandBuffer, 0, 1, &scissor);
        vkCmdBindDescriptorSets(m_commandBuffer, VK_PIPELINE_BIND_POINT_GRAPHICS,
            m_directRasterPipelineLayout, 0, 1, &m_descSet, 0, nullptr);
        vkCmdBindPipeline(m_commandBuffer, VK_PIPELINE_BIND_POINT_GRAPHICS, m_particleOverlayDustPipeline);
        drawIndexedBuffer(m_rasterDustVertices, m_rasterDustIndices, m_rasterDustIndexCount);
        vkCmdEndRenderPass(m_commandBuffer);
    } else {
        imageBarrierCmd(m_commandBuffer, m_renderImage,
            VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
            VK_ACCESS_TRANSFER_WRITE_BIT, VK_ACCESS_TRANSFER_READ_BIT,
            VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT);
    }

    VkImage swapImg = m_swapchainImages[imageIndex];
    imageBarrierCmd(m_commandBuffer, swapImg,
        VK_IMAGE_LAYOUT_UNDEFINED, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
        0, VK_ACCESS_TRANSFER_WRITE_BIT,
        VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT);

    blit.dstOffsets[1] = {(int32_t)m_swapchainExtent.width, (int32_t)m_swapchainExtent.height, 1};
    vkCmdBlitImage(m_commandBuffer,
        m_renderImage, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
        swapImg, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
        1, &blit, VK_FILTER_NEAREST);

    imageBarrierCmd(m_commandBuffer, swapImg,
        VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, VK_IMAGE_LAYOUT_PRESENT_SRC_KHR,
        VK_ACCESS_TRANSFER_WRITE_BIT, 0,
        VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT);

    if (vkEndCommandBuffer(m_commandBuffer) != VK_SUCCESS) {
        setError("vkEndCommandBuffer raster/rt failed"); return false;
    }
    const auto tRecordDone = Clock::now();

    VkPipelineStageFlags waitStage = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    VkSubmitInfo si{VK_STRUCTURE_TYPE_SUBMIT_INFO};
    si.waitSemaphoreCount = 1;
    si.pWaitSemaphores = &m_imageAvailable;
    si.pWaitDstStageMask = &waitStage;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &m_commandBuffer;
    si.signalSemaphoreCount = 1;
    si.pSignalSemaphores = &m_renderFinished;
    VkResult submitResult = vkQueueSubmit(m_queue, 1, &si, m_fence);
    if (submitResult != VK_SUCCESS) {
        setError(std::string("vkQueueSubmit raster/rt failed VkResult=") + std::to_string((int)submitResult));
        return false;
    }
    if (vkWaitForFences(m_device, 1, &m_fence, VK_TRUE, UINT64_MAX) != VK_SUCCESS) {
        setError("vkWaitForFences raster/rt failed"); return false;
    }
    const auto tSubmitWaitDone = Clock::now();

    VkPresentInfoKHR pi{VK_STRUCTURE_TYPE_PRESENT_INFO_KHR};
    pi.waitSemaphoreCount = 1;
    pi.pWaitSemaphores = &m_renderFinished;
    pi.swapchainCount = 1;
    pi.pSwapchains = &m_swapchain;
    pi.pImageIndices = &imageIndex;
    VkResult pr = vkQueuePresentKHR(m_queue, &pi);
    if (pr == VK_ERROR_OUT_OF_DATE_KHR || pr == VK_SUBOPTIMAL_KHR) {
        vkDeviceWaitIdle(m_device);
        return recreatePresentationResources();
    }
    if (pr != VK_SUCCESS) {
        setError(std::string("vkQueuePresentKHR raster/rt failed VkResult=") + std::to_string((int)pr));
        return false;
    }

    // Debug serialization for RT bring-up. This removes semaphore/present reuse
    // as a possible source while the RT command sequence is still being stabilized.
    VkResult idleResult = vkQueueWaitIdle(m_queue);
    if (idleResult != VK_SUCCESS) {
        setError(std::string("vkQueueWaitIdle raster/rt failed VkResult=") + std::to_string((int)idleResult));
        return false;
    }

    const auto tPresentDone = Clock::now();
    m_lastRasterAcquireMs = elapsedMs(t0, tAcquireDone);
    m_lastRasterRecordMs = elapsedMs(tAcquireDone, tRecordDone);
    m_lastRasterSubmitWaitMs = elapsedMs(tRecordDone, tSubmitWaitDone);
    m_lastRasterPresentMs = elapsedMs(tSubmitWaitDone, tPresentDone);
    m_lastRtLightingMs = elapsedMs(tGBufferDone, tRtDone);
    m_lastRtCompositeMs = elapsedMs(tRtDone, tRecordDone);

    m_rtImagesInitialized = true;
    m_rtHistoryValid = false;
    m_rtHistoryPing = false;
    ++m_rtFrameIndex;

    return true;
}

bool VulkanComputeRenderer::render(const Player& player,
                                   const Map& map,
                                   const GpuRemotePlayer* remotePlayers,
                                   const Mesh* const* remoteMeshes,
                                   int numRemotePlayers,
                                   uint32_t* dstPixels,
                                   const MenuOverlayRect* overlayRects,
                                   uint32_t overlayRectCount,
                                   bool overlayEnabled,
                                   uint32_t overlayWindowW,
                                   uint32_t overlayWindowH)
{
    (void)dstPixels; // GPU presentation path: no per-frame CPU readback.
    if (!m_ready) return false;
    m_numRemotePlayers = std::max(0, numRemotePlayers);

    if (!uploadSceneIfNeeded(map, player, remoteMeshes, m_numRemotePlayers)) return false;

    if (m_numRemotePlayers > 0 && remotePlayers) {
        std::vector<GpuRemotePlayer> remoteCopy(remotePlayers, remotePlayers + m_numRemotePlayers);
        for (int i = 0; i < m_numRemotePlayers && i < (int)m_remoteMeshRanges.size(); ++i) {
            if (remoteCopy[(size_t)i].meta.x != 0u) {
                remoteCopy[(size_t)i].ranges = m_remoteMeshRanges[(size_t)i];
                if (remoteMeshes && remoteMeshes[i]) {
                    remoteCopy[(size_t)i].modelMin = gv4(remoteMeshes[i]->modelMin);
                    remoteCopy[(size_t)i].modelCenter = gv4(remoteMeshes[i]->modelCenter);
                }
            }
        }
        if (!uploadBuffer(m_remotePlayers, remoteCopy.data(),
            (VkDeviceSize)m_numRemotePlayers * sizeof(GpuRemotePlayer))) return false;
    } else {
        GpuRemotePlayer dummy{};
        if (!uploadBuffer(m_remotePlayers, &dummy, sizeof(GpuRemotePlayer))) return false;
        m_numRemotePlayers = 0;
    }

    GpuOverlayStateCPU overlayState{};
    overlayState.info[0] = overlayEnabled ? 1u : 0u;
    overlayState.info[1] = overlayRectCount;
    overlayState.info[2] = overlayWindowW ? overlayWindowW : 1u;
    overlayState.info[3] = overlayWindowH ? overlayWindowH : 1u;

    if (!uploadBuffer(m_overlayState, &overlayState, sizeof(overlayState))) return false;

    if (overlayEnabled && overlayRects && overlayRectCount > 0) {
        std::vector<GpuOverlayRectCPU> gpuRects;
        gpuRects.reserve(overlayRectCount);
        for (uint32_t i = 0; i < overlayRectCount; ++i) {
            GpuOverlayRectCPU r{};
            r.x = overlayRects[i].x;
            r.y = overlayRects[i].y;
            r.w = overlayRects[i].w;
            r.h = overlayRects[i].h;
            r.color[0] = overlayRects[i].color;
            r.color[1] = r.color[2] = r.color[3] = 0u;
            gpuRects.push_back(r);
        }
        if (!uploadBuffer(m_overlayRects, gpuRects.data(),
            (VkDeviceSize)gpuRects.size() * sizeof(GpuOverlayRectCPU))) return false;
    } else {
        GpuOverlayRectCPU dummy{};
        if (!uploadBuffer(m_overlayRects, &dummy, sizeof(dummy))) return false;
    }

    if (!uploadCamera(player, map)) return false;
    if (!uploadLights(*map.mapData, player, remotePlayers, m_numRemotePlayers)) return false;
    if (!uploadRtSettings(player, map)) return false;
    updateDescriptorSet();
    
    return recordAndSubmitPresent();
}

bool VulkanComputeRenderer::rasterize(const Player& player,
                                      const Map& map,
                                      const GpuRemotePlayer* remotePlayers,
                                      const Mesh* const* remoteMeshes,
                                      int numRemotePlayers,
                                      uint32_t* dstPixels,
                                      const MenuOverlayRect* overlayRects,
                                      uint32_t overlayRectCount,
                                      bool overlayEnabled,
                                      uint32_t overlayWindowW,
                                      uint32_t overlayWindowH)
{
    using Clock = std::chrono::high_resolution_clock;
    const auto t0 = Clock::now();

    (void)dstPixels; // Direct Vulkan presentation path, same as render().
    if (!m_ready) return false;
    m_numRemotePlayers = std::max(0, numRemotePlayers);

    if (!uploadSceneIfNeeded(map, player, remoteMeshes, m_numRemotePlayers)) return false;
    const auto tScene = Clock::now();

    // Rasterisation does not need the compute-only remote-player/overlay SSBOs.
    // Keep only the CPU copy needed to build dynamic raster geometry. The old
    // raytracing path still uploads those buffers inside render().
    std::vector<GpuRemotePlayer> remoteCopy;
    if (m_numRemotePlayers > 0 && remotePlayers) {
        remoteCopy.assign(remotePlayers, remotePlayers + m_numRemotePlayers);
        for (int i = 0; i < m_numRemotePlayers && i < (int)m_remoteMeshRanges.size(); ++i) {
            if (remoteCopy[(size_t)i].meta.x != 0u) {
                remoteCopy[(size_t)i].ranges = m_remoteMeshRanges[(size_t)i];
                if (remoteMeshes && remoteMeshes[i]) {
                    remoteCopy[(size_t)i].modelMin = gv4(remoteMeshes[i]->modelMin);
                    remoteCopy[(size_t)i].modelCenter = gv4(remoteMeshes[i]->modelCenter);
                }
            }
        }
    } else {
        m_numRemotePlayers = 0;
    }
    const auto tRemotePrep = Clock::now();

    const GpuRemotePlayer* dynPlayers = remoteCopy.empty() ? nullptr : remoteCopy.data();
    if (!uploadRasterDynamicGeometry(dynPlayers, remoteMeshes, m_numRemotePlayers)) return false;
    const auto tDynamic = Clock::now();

    if (!uploadRasterOverlayGeometry(overlayRects, overlayRectCount, overlayEnabled,
                                     overlayWindowW, overlayWindowH)) return false;

    // RT/composite shaders use the compute-path SSBO descriptors as well.
    // The direct raster path did not need these, but RT ON must never leave
    // bindings 13/15/16 unbound. Always upload either real data or a dummy.
    if (m_numRemotePlayers > 0 && !remoteCopy.empty()) {
        if (!uploadBuffer(m_remotePlayers, remoteCopy.data(),
            (VkDeviceSize)remoteCopy.size() * sizeof(GpuRemotePlayer))) return false;
    } else {
        GpuRemotePlayer dummyRemote{};
        if (!uploadBuffer(m_remotePlayers, &dummyRemote, sizeof(dummyRemote))) return false;
    }

    GpuOverlayStateCPU overlayState{};
    overlayState.info[0] = overlayEnabled ? 1u : 0u;
    overlayState.info[1] = overlayRectCount;
    overlayState.info[2] = overlayWindowW ? overlayWindowW : 1u;
    overlayState.info[3] = overlayWindowH ? overlayWindowH : 1u;
    if (!uploadBuffer(m_overlayState, &overlayState, sizeof(overlayState))) return false;

    if (overlayEnabled && overlayRects && overlayRectCount > 0) {
        std::vector<GpuOverlayRectCPU> gpuRects;
        gpuRects.reserve(overlayRectCount);
        for (uint32_t i = 0; i < overlayRectCount; ++i) {
            GpuOverlayRectCPU r{};
            r.x = overlayRects[i].x;
            r.y = overlayRects[i].y;
            r.w = overlayRects[i].w;
            r.h = overlayRects[i].h;
            r.color[0] = overlayRects[i].color;
            r.color[1] = r.color[2] = r.color[3] = 0u;
            gpuRects.push_back(r);
        }
        if (!uploadBuffer(m_overlayRects, gpuRects.data(),
            (VkDeviceSize)gpuRects.size() * sizeof(GpuOverlayRectCPU))) return false;
    } else {
        GpuOverlayRectCPU dummyRect{};
        if (!uploadBuffer(m_overlayRects, &dummyRect, sizeof(dummyRect))) return false;
    }
    const auto tOverlay = Clock::now();

    if (!uploadCamera(player, map)) return false;
    if (!uploadLights(*map.mapData, player, dynPlayers, m_numRemotePlayers)) return false;
    if (!uploadRasterDustGeometry(player, map)) return false;
    if (!uploadRtSettings(player, map)) return false;
    const auto tCamera = Clock::now();

    updateDescriptorSet();
    const auto tDescriptors = Clock::now();

    const bool rtActiveForFrame = m_raytracingEnabled;
    const bool ok = recordAndSubmitRaster();
    const auto tSubmit = Clock::now();

    static uint32_t rasterRtFrame = 0;
    if ((rasterRtFrame++ % 60u) == 0u) {
        const int loggedSampleMode = rtActiveForFrame
            ? (m_raytracingQualityPercent < 35 ? 1 : (m_raytracingQualityPercent < 75 ? 2 : 3))
            : 0;
        // debug?
    }

    return ok;
}
