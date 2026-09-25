/**
 * check_env.c - 系统环境检查工具
 *
 * 功能:
 *   - Windows 7: 检查SHA2代码签名补丁 (KB4474419/KB4490628)
 *   - Windows 10+: 检查Microsoft Edge WebView2运行时
 *   - GUI窗口显示检测结果，提供可点击的下载链接
 *
 * 编译:
 *   MSVC:  cl check_env.c /MT /Fe:check_env.exe advapi32.lib version.lib shell32.lib comctl32.lib resource.res
 *   MinGW: windres resource.rc -o resource.o && gcc check_env.c resource.o -static -mwindows -o check_env.exe -ladvapi32 -lversion -lshell32 -lcomctl32
 */

#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* MSVC兼容性 */
#ifndef _NTDEF_
typedef LONG NTSTATUS;
#endif

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#endif

/* ===== 下载链接 ===== */
#define URL_SHA2_CATALOG  L"https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB4474419"
#define URL_SHA2_X64      L"https://mnl.lanzouc.com/i2ULP49qiqla"
#define URL_SHA2_X86      L"https://mnl.lanzouc.com/iWzXt49qiptc"
#define URL_WEBVIEW2      L"https://developer.microsoft.com/zh-cn/microsoft-edge/webview2/#download-section"
#define URL_WEBVIEW2_DL   L"https://go.microsoft.com/fwlink/p/?LinkId=2124703"

/* ===== 注册表路径 ===== */
#define HOTFIX_KEY_BASE   L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\HotFix\\"
#define KB4474419_KEY     HOTFIX_KEY_BASE L"KB4474419"
#define KB4490628_KEY     HOTFIX_KEY_BASE L"KB4490628"

#define WV2_EG1_KEY       L"SOFTWARE\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
#define WV2_EG1_WOW_KEY   L"SOFTWARE\\WOW6432Node\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
#define WV2_EG2_KEY       L"SOFTWARE\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BEB-673F7D8AED47}"
#define WV2_EG2_WOW_KEY   L"SOFTWARE\\WOW6432Node\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BEB-673F7D8AED47}"
#define WV2_FX_KEY        L"SOFTWARE\\Microsoft\\EdgeUpdate\\Clients\\{F20586C8-705C-474E-BA42-7E975B87D44B}"
#define WV2_FX_WOW_KEY    L"SOFTWARE\\WOW6432Node\\Microsoft\\EdgeUpdate\\Clients\\{F20586C8-705C-474E-BA42-7E975B87D44B}"

/* ===== 控件ID ===== */
#define ID_STATIC_BASE      1000
#define ID_LINK_BASE        2000
#define IDC_CLOSE_BTN       9000
#define IDC_ICON_PASS       9001
#define IDC_ICON_FAIL       9002

/* ===== 全局变量 ===== */
static BOOL g_is64bit = FALSE;
static HINSTANCE g_hInst = NULL;
static HWND g_hWndMain = NULL;

/* ===== 辅助函数 ===== */

static const char* GetArchStringA(void) {
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    g_is64bit = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
                 si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: return "x64";
        case PROCESSOR_ARCHITECTURE_ARM64: return "ARM64";
        case PROCESSOR_ARCHITECTURE_INTEL:  return "x86";
        default: return "Unknown";
    }
}

static BOOL RegKeyExists(HKEY root, LPCWSTR subKey, REGSAM access) {
    HKEY hKey;
    LONG result = RegOpenKeyExW(root, subKey, 0, KEY_READ | access, &hKey);
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    return FALSE;
}

static BOOL RegQueryStringValue(HKEY root, LPCWSTR subKey, LPCWSTR valueName,
                                 wchar_t *buffer, DWORD bufChars) {
    HKEY hKey;
    DWORD type = 0;
    DWORD dataSize = bufChars * sizeof(wchar_t);
    if (RegOpenKeyExW(root, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return FALSE;
    LONG result = RegQueryValueExW(hKey, valueName, NULL, &type, (LPBYTE)buffer, &dataSize);
    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS && type == REG_SZ);
}

static BOOL FileExistsW(LPCWSTR path) {
    DWORD attrs = GetFileAttributesW(path);
    return (attrs != INVALID_FILE_ATTRIBUTES &&
            !(attrs & FILE_ATTRIBUTE_DIRECTORY));
}

static BOOL ExpandAndCheckFile(LPCWSTR pathTemplate) {
    WCHAR path[MAX_PATH] = {0};
    ExpandEnvironmentStringsW(pathTemplate, path, MAX_PATH);
    return FileExistsW(path);
}

/* ===== SHA2补丁检测 ===== */

static BOOL CheckSHA2ByRegistry(void) {
    if (RegKeyExists(HKEY_LOCAL_MACHINE, KB4474419_KEY, 0)) return TRUE;
    if (RegKeyExists(HKEY_LOCAL_MACHINE, KB4474419_KEY, KEY_WOW64_64KEY)) return TRUE;
    if (RegKeyExists(HKEY_LOCAL_MACHINE, KB4490628_KEY, 0)) return TRUE;
    if (RegKeyExists(HKEY_LOCAL_MACHINE, KB4490628_KEY, KEY_WOW64_64KEY)) return TRUE;
    return FALSE;
}

static BOOL CheckSHA2ByCrypt32(void) {
    WCHAR path[MAX_PATH] = {0};
    GetSystemDirectoryW(path, MAX_PATH);
    wcscat(path, L"\\crypt32.dll");

    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(path, &handle);
    if (size == 0) return FALSE;

    BYTE *buffer = (BYTE*)malloc(size);
    if (!buffer) return FALSE;

    if (!GetFileVersionInfoW(path, handle, size, buffer)) {
        free(buffer);
        return FALSE;
    }

    VS_FIXEDFILEINFO *ffi = NULL;
    UINT ffiSize = 0;
    if (!VerQueryValueW(buffer, L"\\", (LPVOID*)&ffi, &ffiSize) ||
        ffiSize < sizeof(VS_FIXEDFILEINFO)) {
        free(buffer);
        return FALSE;
    }

    DWORD major   = HIWORD(ffi->dwFileVersionMS);
    DWORD minor   = LOWORD(ffi->dwFileVersionMS);
    DWORD build   = HIWORD(ffi->dwFileVersionLS);
    DWORD private = LOWORD(ffi->dwFileVersionLS);

    BOOL result = FALSE;
    if (major == 6 && minor == 1 && build == 7601 && private >= 23473) {
        result = TRUE;
    }

    free(buffer);
    return result;
}

static BOOL CheckSHA2Patch(void) {
    if (CheckSHA2ByRegistry()) return TRUE;
    if (CheckSHA2ByCrypt32()) return TRUE;
    return FALSE;
}

/* ===== WebView2检测 ===== */

static BOOL CheckWebView2ByRegistry(wchar_t *version, DWORD size) {
    if (RegKeyExists(HKEY_LOCAL_MACHINE, WV2_EG1_KEY, 0)) {
        RegQueryStringValue(HKEY_LOCAL_MACHINE, WV2_EG1_KEY, L"pv", version, size);
        return TRUE;
    }
    if (RegKeyExists(HKEY_LOCAL_MACHINE, WV2_EG1_WOW_KEY, 0)) {
        RegQueryStringValue(HKEY_LOCAL_MACHINE, WV2_EG1_WOW_KEY, L"pv", version, size);
        return TRUE;
    }
    if (RegKeyExists(HKEY_LOCAL_MACHINE, WV2_EG2_KEY, 0)) {
        RegQueryStringValue(HKEY_LOCAL_MACHINE, WV2_EG2_KEY, L"pv", version, size);
        return TRUE;
    }
    if (RegKeyExists(HKEY_LOCAL_MACHINE, WV2_EG2_WOW_KEY, 0)) {
        RegQueryStringValue(HKEY_LOCAL_MACHINE, WV2_EG2_WOW_KEY, L"pv", version, size);
        return TRUE;
    }
    if (RegKeyExists(HKEY_LOCAL_MACHINE, WV2_FX_KEY, 0)) {
        RegQueryStringValue(HKEY_LOCAL_MACHINE, WV2_FX_KEY, L"pv", version, size);
        return TRUE;
    }
    if (RegKeyExists(HKEY_LOCAL_MACHINE, WV2_FX_WOW_KEY, 0)) {
        RegQueryStringValue(HKEY_LOCAL_MACHINE, WV2_FX_WOW_KEY, L"pv", version, size);
        return TRUE;
    }
    /* KEY_WOW64_64KEY */
    if (RegKeyExists(HKEY_LOCAL_MACHINE, WV2_EG1_KEY, KEY_WOW64_64KEY)) {
        RegQueryStringValue(HKEY_LOCAL_MACHINE, WV2_EG1_KEY, L"pv", version, size);
        return TRUE;
    }
    if (RegKeyExists(HKEY_LOCAL_MACHINE, WV2_EG2_KEY, KEY_WOW64_64KEY)) {
        RegQueryStringValue(HKEY_LOCAL_MACHINE, WV2_EG2_KEY, L"pv", version, size);
        return TRUE;
    }
    if (RegKeyExists(HKEY_LOCAL_MACHINE, WV2_FX_KEY, KEY_WOW64_64KEY)) {
        RegQueryStringValue(HKEY_LOCAL_MACHINE, WV2_FX_KEY, L"pv", version, size);
        return TRUE;
    }
    return FALSE;
}

static BOOL CheckWebView2ByFiles(void) {
    if (ExpandAndCheckFile(L"%SystemRoot%\\System32\\MicrosoftEdgeWebView2\\EdgeWebView2.exe")) return TRUE;
    if (ExpandAndCheckFile(L"%SystemRoot%\\SysWOW64\\MicrosoftEdgeWebView2\\EdgeWebView2.exe")) return TRUE;
    if (ExpandAndCheckFile(L"%LOCALAPPDATA%\\Microsoft\\EdgeWebView\\Application\\EdgeWebView2.exe")) return TRUE;
    if (ExpandAndCheckFile(L"%LOCALAPPDATA%\\Microsoft\\Edge\\Application\\msedgewebview2.exe")) return TRUE;
    if (ExpandAndCheckFile(L"%ProgramFiles%\\Microsoft\\Edge\\Application\\msedgewebview2.exe")) return TRUE;
    if (ExpandAndCheckFile(L"%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedgewebview2.exe")) return TRUE;
    return FALSE;
}

static BOOL CheckWebView2(wchar_t *version, DWORD size) {
    if (CheckWebView2ByRegistry(version, size)) return TRUE;
    if (CheckWebView2ByFiles()) return TRUE;
    return FALSE;
}

/* ===== GUI ===== */

/* 检测结果结构 */
typedef struct {
    BOOL sha2_ok;
    BOOL wv2_ok;
    wchar_t wv2_version[64];
    char arch[16];
    DWORD win_ver_major;
    DWORD win_ver_minor;
    DWORD win_build;
} CheckResult;

/* 计算所需窗口高度 */
static int CalcWindowHeight(const CheckResult *r) {
    int lines = 4; /* 标题 + OS行 + 架构行 + 空行 */
    if (r->win_ver_major < 10) {
        lines += 2; /* SHA2状态 + SHA2链接 */
    }
    lines += 2; /* WebView2状态 + WebView2链接 */
    lines += 2; /* 空行 + 关闭按钮 */
    return lines * 28 + 40;
}

/* 打开URL */
static void OpenURL(LPCWSTR url) {
    ShellExecuteW(NULL, L"open", url, NULL, NULL, SW_SHOWNORMAL);
}

/* 创建图标 - 绿色对勾 / 红色叉号 */
static HICON CreateStatusIcon(BOOL pass) {
    int size = GetSystemMetrics(SM_CXSMICON);
    HDC screenDC = GetDC(NULL);
    HDC memDC = CreateCompatibleDC(screenDC);
    HBITMAP bmp = CreateCompatibleBitmap(screenDC, size, size);
    HBITMAP oldBmp = (HBITMAP)SelectObject(memDC, bmp);

    HBRUSH bgBrush = GetSysColorBrush(COLOR_WINDOW);
    FillRect(memDC, &(RECT){0, 0, size, size}, bgBrush);

    HPEN pen = CreatePen(PS_SOLID, 2, pass ? RGB(0, 160, 0) : RGB(220, 0, 0));
    HPEN oldPen = (HPEN)SelectObject(memDC, pen);
    HBRUSH brush = (HBRUSH)GetStockObject(NULL_BRUSH);
    HBRUSH oldBrush = (HBRUSH)SelectObject(memDC, brush);

    int m = 2;
    Ellipse(memDC, m, m, size - m, size - m);

    if (pass) {
        /* 对勾 */
        MoveToEx(memDC, size * 2 / 8, size * 5 / 8, NULL);
        LineTo(memDC, size * 4 / 8, size * 7 / 8 - 1);
        LineTo(memDC, size * 6 / 8 + 1, size * 2 / 8);
    } else {
        /* 叉号 */
        MoveToEx(memDC, size * 3 / 8, size * 3 / 8, NULL);
        LineTo(memDC, size * 5 / 8 + 1, size * 5 / 8 + 1);
        MoveToEx(memDC, size * 5 / 8 + 1, size * 3 / 8, NULL);
        LineTo(memDC, size * 3 / 8, size * 5 / 8 + 1);
    }

    SelectObject(memDC, oldPen);
    SelectObject(memDC, oldBrush);
    SelectObject(memDC, oldBmp);
    DeleteObject(pen);
    DeleteObject(bmp);
    DeleteDC(memDC);
    ReleaseDC(NULL, screenDC);

    ICONINFO ii = {0};
    ii.fIcon = TRUE;
    ii.hbmColor = bmp;
    ii.hbmMask = bmp;
    /* CreateIconIndirect takes ownership of bitmaps */
    HICON icon = CreateIconIndirect(&ii);
    return icon;
}

/* 窗口过程 */
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        /* 存储CheckResult指针 */
        CREATESTRUCTW *cs = (CREATESTRUCTW*)lParam;
        CheckResult *result = (CheckResult*)cs->lpCreateParams;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)result);

        HFONT hFont = CreateFontW(
            -MulDiv(9, GetDeviceCaps(GetDC(hwnd), LOGPIXELSY), 72),
            0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI"
        );
        HFONT hFontBold = CreateFontW(
            -MulDiv(10, GetDeviceCaps(GetDC(hwnd), LOGPIXELSY), 72),
            0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI"
        );

        int y = 12;
        int xIcon = 16;
        int xText = 48;
        int xLink = 48;
        int staticId = ID_STATIC_BASE;
        int linkId = ID_LINK_BASE;

        /* 标题 */
        HWND hTitle = CreateWindowW(L"STATIC", L"系统环境检查结果",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            xIcon, y, 400, 24, hwnd, (HMENU)(INT_PTR)staticId++, cs->hInstance, NULL);
        SendMessageW(hTitle, WM_SETFONT, (WPARAM)hFontBold, TRUE);
        y += 32;

        /* OS版本 */
        char osText[256];
        const char *edition = "";
        if (result->win_ver_major == 6 && result->win_ver_minor == 1)
            edition = "Windows 7";
        else if (result->win_ver_major == 6 && result->win_ver_minor == 3)
            edition = "Windows 8.1";
        else if (result->win_ver_major == 10)
            edition = "Windows 10";
        else if (result->win_ver_major == 11)
            edition = "Windows 11";
        else
            edition = "Windows";

        snprintf(osText, sizeof(osText), "操作系统: %s (Build %lu)", edition, result->win_build);
        wchar_t osTextW[256];
        MultiByteToWideChar(CP_ACP, 0, osText, -1, osTextW, 256);

        HWND hOS = CreateWindowW(L"STATIC", osTextW,
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            xText, y, 400, 20, hwnd, (HMENU)(INT_PTR)staticId++, cs->hInstance, NULL);
        SendMessageW(hOS, WM_SETFONT, (WPARAM)hFont, TRUE);
        y += 24;

        /* 架构 */
        char archText[64];
        snprintf(archText, sizeof(archText), "系统架构: %s", result->arch);
        wchar_t archTextW[64];
        MultiByteToWideChar(CP_ACP, 0, archText, -1, archTextW, 64);

        HWND hArch = CreateWindowW(L"STATIC", archTextW,
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            xText, y, 400, 20, hwnd, (HMENU)(INT_PTR)staticId++, cs->hInstance, NULL);
        SendMessageW(hArch, WM_SETFONT, (WPARAM)hFont, TRUE);
        y += 32;

        /* SHA2补丁 (仅Win7) */
        if (result->win_ver_major < 10) {
            /* 图标 */
            HICON hIcon = CreateStatusIcon(result->sha2_ok);
            HWND hIconCtrl = CreateWindowW(L"STATIC", L"",
                WS_CHILD | WS_VISIBLE | SS_ICON | SS_CENTERIMAGE,
                xIcon, y - 2, 20, 20, hwnd, (HMENU)IDC_ICON_PASS, cs->hInstance, NULL);
            SendMessageW(hIconCtrl, STM_SETICON, (WPARAM)hIcon, 0);

            /* 状态文字 */
            const char *sha2Status = result->sha2_ok ?
                "SHA2代码签名补丁: 已安装 ✓" : "SHA2代码签名补丁: 未安装 ✗";
            wchar_t sha2StatusW[128];
            MultiByteToWideChar(CP_ACP, 0, sha2Status, -1, sha2StatusW, 128);

            HWND hSha2 = CreateWindowW(L"STATIC", sha2StatusW,
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                xText, y, 400, 20, hwnd, (HMENU)(INT_PTR)staticId++, cs->hInstance, NULL);
            SendMessageW(hSha2, WM_SETFONT, (WPARAM)hFont, TRUE);
            y += 24;

            /* 下载链接 */
            if (!result->sha2_ok) {
                wchar_t linkText[512];
                if (g_is64bit) {
                    swprintf(linkText, 512,
                        L"<a href=\"%s\">下载 SHA2补丁 (x64)</a>  "
                        L"<a href=\"%s\">微软更新目录</a>",
                        URL_SHA2_X64, URL_SHA2_CATALOG);
                } else {
                    swprintf(linkText, 512,
                        L"<a href=\"%s\">下载 SHA2补丁 (x86)</a>  "
                        L"<a href=\"%s\">微软更新目录</a>",
                        URL_SHA2_X86, URL_SHA2_CATALOG);
                }

                HWND hLink = CreateWindowW(L"LINK", linkText,
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                    xLink, y, 450, 20, hwnd, (HMENU)(INT_PTR)linkId++, cs->hInstance, NULL);
                SendMessageW(hLink, WM_SETFONT, (WPARAM)hFont, TRUE);
                y += 28;
            }
        }

        /* WebView2 */
        {
            HICON hIcon = CreateStatusIcon(result->wv2_ok);
            HWND hIconCtrl = CreateWindowW(L"STATIC", L"",
                WS_CHILD | WS_VISIBLE | SS_ICON | SS_CENTERIMAGE,
                xIcon, y - 2, 20, 20, hwnd, (HMENU)IDC_ICON_FAIL, cs->hInstance, NULL);
            SendMessageW(hIconCtrl, STM_SETICON, (WPARAM)hIcon, 0);

            char wv2Text[256];
            if (result->wv2_ok && result->wv2_version[0]) {
                char verA[64];
                WideCharToMultiByte(CP_ACP, 0, result->wv2_version, -1, verA, 64, NULL, NULL);
                snprintf(wv2Text, sizeof(wv2Text), "WebView2运行时: 已安装 (版本 %s) ✓", verA);
            } else if (result->wv2_ok) {
                snprintf(wv2Text, sizeof(wv2Text), "WebView2运行时: 已安装 ✓");
            } else {
                snprintf(wv2Text, sizeof(wv2Text), "WebView2运行时: 未安装 ✗");
            }
            wchar_t wv2TextW[256];
            MultiByteToWideChar(CP_ACP, 0, wv2Text, -1, wv2TextW, 256);

            HWND hWV2 = CreateWindowW(L"STATIC", wv2TextW,
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                xText, y, 400, 20, hwnd, (HMENU)(INT_PTR)staticId++, cs->hInstance, NULL);
            SendMessageW(hWV2, WM_SETFONT, (WPARAM)hFont, TRUE);
            y += 24;

            if (!result->wv2_ok) {
                wchar_t linkText[512];
                swprintf(linkText, 512,
                    L"<a href=\"%s\">下载 WebView2运行时</a>  "
                    L"<a href=\"%s\">官方下载页面</a>",
                    URL_WEBVIEW2_DL, URL_WEBVIEW2);

                HWND hLink = CreateWindowW(L"LINK", linkText,
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                    xLink, y, 450, 20, hwnd, (HMENU)(INT_PTR)linkId++, cs->hInstance, NULL);
                SendMessageW(hLink, WM_SETFONT, (WPARAM)hFont, TRUE);
                y += 28;
            }
        }

        y += 8;

        /* 关闭按钮 */
        HWND hBtn = CreateWindowW(L"BUTTON", L"关闭",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            180, y, 120, 30, hwnd, (HMENU)IDC_CLOSE_BTN, cs->hInstance, NULL);
        SendMessageW(hBtn, WM_SETFONT, (WPARAM)hFont, TRUE);

        /* 调整窗口高度以适应内容 */
        int totalH = y + 44;
        RECT rc;
        GetWindowRect(hwnd, &rc);
        SetWindowPos(hwnd, NULL, 0, 0, rc.right - rc.left, totalH,
                     SWP_NOMOVE | SWP_NOZORDER);

        break;
    }

    case WM_NOTIFY: {
        NMHDR *nmhdr = (NMHDR*)lParam;
        if (nmhdr->code == NM_CLICK || nmhdr->code == NM_RETURN) {
            NMLINK *nmlink = (NMLINK*)lParam;
            LPCWSTR url = nmlink->item.szUrl;
            if (url && *url) {
                OpenURL(url);
            }
        }
        break;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_CLOSE_BTN) {
            DestroyWindow(hwnd);
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

/* ===== 入口 ===== */

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    (void)hPrevInstance;
    (void)lpCmdLine;
    (void)nCmdShow;

    g_hInst = hInstance;

    /* 初始化Common Controls */
    INITCOMMONCONTROLSEX icc = {
        sizeof(INITCOMMONCONTROLSEX),
        ICC_LINK_CLASS | ICC_WIN95_CLASSES
    };
    InitCommonControlsEx(&icc);

    /* 获取Windows版本 */
    OSVERSIONINFOEXW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);

    /* 使用RtlGetVersion绕过兼容性垫片 */
    typedef NTSTATUS (WINAPI *RtlGetVersionPtr)(POSVERSIONINFOEXW);
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    RtlGetVersionPtr RtlGetVersion = NULL;
    if (hNtDll) {
        RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hNtDll, "RtlGetVersion");
    }

    if (RtlGetVersion) {
        RtlGetVersion(&osvi);
    } else {
        /* 回退到VerifyVersionInfo方式 */
        osvi.dwMajorVersion = 10;
        osvi.dwMinorVersion = 0;
        osvi.dwBuildNumber = 0;
    }

    /* 执行检测 */
    CheckResult result = {0};
    result.win_ver_major = osvi.dwMajorVersion;
    result.win_ver_minor = osvi.dwMinorVersion;
    result.win_build = osvi.dwBuildNumber;

    const char *arch = GetArchStringA();
    strncpy(result.arch, arch, sizeof(result.arch) - 1);

    if (osvi.dwMajorVersion < 10) {
        result.sha2_ok = CheckSHA2Patch();
    }

    result.wv2_ok = CheckWebView2(result.wv2_version, sizeof(result.wv2_version) / sizeof(wchar_t));

    /* 注册窗口类 */
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"CheckEnvWnd";
    RegisterClassExW(&wc);

    /* 计算窗口尺寸 */
    int winW = 500;
    int winH = CalcWindowHeight(&result);

    /* 居中 */
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    int x = (screenW - winW) / 2;
    int y = (screenH - winH) / 2;

    /* 创建窗口 */
    g_hWndMain = CreateWindowExW(
        0, L"CheckEnvWnd", L"系统环境检查",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        x, y, winW, winH,
        NULL, NULL, hInstance, &result
    );

    if (!g_hWndMain) {
        MessageBoxW(NULL, L"创建窗口失败", L"错误", MB_OK | MB_ICONERROR);
        return 1;
    }

    ShowWindow(g_hWndMain, SW_SHOW);
    UpdateWindow(g_hWndMain);

    /* 消息循环 */
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return (int)msg.wParam;
}