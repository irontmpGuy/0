#include <windows.h>
#include <string>
#include <chrono>
#include <thread>
#include <cstdlib>

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    if (uMsg == WM_DESTROY)
    {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void ShowBouncingWindow(const std::string& text, const std::string& title)
{
    HINSTANCE hInstance = GetModuleHandle(nullptr);
    const char* className = "CustomMsgBox";

    WNDCLASSA wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = className;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    RegisterClassA(&wc);

    int width = 300;
    int height = 150;
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    while (true)
    {
        HWND hwnd = CreateWindowExA(
            WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
            className,
            title.c_str(),
            WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME,
            (screenW - width) / 2,
            (screenH - height) / 2,
            width,
            height,
            nullptr,
            nullptr,
            hInstance,
            nullptr
        );

        ShowWindow(hwnd, SW_SHOW);

        // Add a static text control
        CreateWindowA(
            "STATIC",
            text.c_str(),
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            10, 40, width - 20, 80,
            hwnd,
            nullptr,
            hInstance,
            nullptr
        );

        int x = (screenW - width) / 2;
        int y = (screenH - height) / 2;
        int dx = (rand() % 3 + 10) * (rand() % 2 ? 1 : -1);
        int dy = (rand() % 3 + 10) * (rand() % 2 ? 1 : -1);

        MSG msg = {};
        while (IsWindow(hwnd))
        {
            while (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE))
            {
                TranslateMessage(&msg);
                DispatchMessageA(&msg);
            }

            x += dx;
            y += dy;

            if (x <= 0 || x + width >= screenW) dx = -dx;
            if (y <= 0 || y + height >= screenH) dy = -dy;

            SetWindowPos(hwnd, HWND_TOPMOST, x, y, width, height, SWP_NOZORDER | SWP_NOACTIVATE);
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }

        // Window closed by user, loop will recreate it
    }
}

extern "C" __declspec(dllexport)
int main_func()
{
    srand((unsigned int)GetTickCount() ^ (unsigned int)GetCurrentThreadId());
    ShowBouncingWindow("You are now serving Obama. The Prism thanks for your service.", "Obama");
    return 0;
}

BOOL WINAPI DllMain(HMODULE hModule,
                    DWORD  ul_reason_for_call,
                    LPVOID lpReserved)
{
    return TRUE;
}
