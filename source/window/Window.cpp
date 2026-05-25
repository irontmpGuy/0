#include "Window.h"
#include "Framebuffer.h"

// ---------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------
LRESULT CALLBACK Window::wndProc(HWND hwnd, UINT msg,
                                  WPARAM wParam, LPARAM lParam)
{
    Window* window = reinterpret_cast<Window*>(GetWindowLongPtrA(hwnd, GWLP_USERDATA));

    switch (msg)
    {
        case WM_NCCREATE:
        {
            CREATESTRUCTA* create = reinterpret_cast<CREATESTRUCTA*>(lParam);
            window = reinterpret_cast<Window*>(create->lpCreateParams);
            SetWindowLongPtrA(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(window));
            return TRUE;
        }

        case WM_SIZE:
            if (window && wParam != SIZE_MINIMIZED) {
                window->m_width  = LOWORD(lParam);
                window->m_height = HIWORD(lParam);
            }
            return 0;

        case WM_SYSKEYDOWN:
            if (window && wParam == VK_RETURN && (GetKeyState(VK_MENU) & 0x8000)) {
                window->toggleFullscreen();
                return 0;
            }
            break;

        case WM_KEYDOWN:
            if (window && wParam == VK_F11) {
                window->toggleFullscreen();
                return 0;
            }
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;

        case WM_SETCURSOR:
        {
            // Only force arrow inside the client area.
            // Let Windows handle resize borders, title bar, corners, etc.
            if (LOWORD(lParam) == HTCLIENT) {
                SetCursor(LoadCursor(nullptr, IDC_ARROW));
                return TRUE;
            }

            break; // DefWindowProc gives resize cursors on borders/corners
        }
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------
Window::Window(int width, int height, const std::string& title)
{
    m_width  = (width  > 0) ? width  : 1280;
    m_height = (height > 0) ? height : 720;

    const char* className = "RaycasterWindow";
    HINSTANCE hInstance   = GetModuleHandleA(nullptr);

    WNDCLASSEXA wc   = {};
    wc.cbSize        = sizeof(WNDCLASSEXA);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = wndProc;
    wc.hInstance     = hInstance;
    wc.hCursor       = nullptr;   // managed manually via WM_SETCURSOR
    wc.lpszClassName = className;
    RegisterClassExA(&wc);

    DWORD style = WS_OVERLAPPEDWINDOW;

    RECT rect = { 0, 0, m_width, m_height };
    AdjustWindowRect(&rect, style, FALSE);

    int windowW = rect.right - rect.left;
    int windowH = rect.bottom - rect.top;
    int x = (GetSystemMetrics(SM_CXSCREEN) - windowW) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - windowH) / 2;

    m_hwnd = CreateWindowExA(
        0,
        className,
        title.c_str(),
        style,
        x, y,
        windowW, windowH,
        nullptr, nullptr, hInstance, this);

    m_hdc = GetDC(m_hwnd);
    ShowWindow(m_hwnd, SW_SHOW);
    UpdateWindow(m_hwnd);
}

Window::~Window()
{
    if (m_hdc && m_hwnd) ReleaseDC(m_hwnd, m_hdc);
    if (m_hwnd)          DestroyWindow(m_hwnd);
}

// ---------------------------------------------------------------------------
// Per-frame
// ---------------------------------------------------------------------------
bool Window::processMessages()
{
    MSG msg;
    while (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE))
    {
        if (msg.message == WM_QUIT) return false;
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return true;
}

void Window::present(const Framebuffer& fb)
{
    if (m_width <= 0 || m_height <= 0) return;

    BITMAPINFO bmi = {};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = fb.getWidth();
    bmi.bmiHeader.biHeight = -fb.getHeight();
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    if (fb.getWidth() > m_width || fb.getHeight() > m_height) {
        SetStretchBltMode(m_hdc, HALFTONE);
        SetBrushOrgEx(m_hdc, 0, 0, nullptr);
    } else {
        SetStretchBltMode(m_hdc, COLORONCOLOR);
    }

    StretchDIBits(
        m_hdc,
        0, 0, m_width, m_height,
        0, 0, fb.getWidth(), fb.getHeight(),
        fb.getData(),
        &bmi,
        DIB_RGB_COLORS,
        SRCCOPY
    );
}

void Window::toggleFullscreen()
{
    if (!m_hwnd) return;

    DWORD style = static_cast<DWORD>(GetWindowLongPtrA(m_hwnd, GWL_STYLE));

    if (!m_isFullscreen) {
        GetWindowRect(m_hwnd, &m_windowedRect);

        MONITORINFO monitorInfo = {};
        monitorInfo.cbSize = sizeof(MONITORINFO);
        GetMonitorInfoA(MonitorFromWindow(m_hwnd, MONITOR_DEFAULTTONEAREST), &monitorInfo);

        SetWindowLongPtrA(m_hwnd, GWL_STYLE, style & ~WS_OVERLAPPEDWINDOW);
        SetWindowPos(
            m_hwnd, HWND_TOP,
            monitorInfo.rcMonitor.left,
            monitorInfo.rcMonitor.top,
            monitorInfo.rcMonitor.right - monitorInfo.rcMonitor.left,
            monitorInfo.rcMonitor.bottom - monitorInfo.rcMonitor.top,
            SWP_FRAMECHANGED | SWP_NOOWNERZORDER);

        m_isFullscreen = true;
    } else {
        SetWindowLongPtrA(m_hwnd, GWL_STYLE, style | WS_OVERLAPPEDWINDOW);
        SetWindowPos(
            m_hwnd, nullptr,
            m_windowedRect.left,
            m_windowedRect.top,
            m_windowedRect.right - m_windowedRect.left,
            m_windowedRect.bottom - m_windowedRect.top,
            SWP_FRAMECHANGED | SWP_NOOWNERZORDER | SWP_NOZORDER);

        m_isFullscreen = false;
    }
}

int Window::getWidth()  const { return m_width;  }
int Window::getHeight() const { return m_height; }
