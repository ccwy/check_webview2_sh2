/**
 * check_env.c - 系统环境检查工具 (GUI版本)
 *
 * 功能:
 *   - Windows 7: 检查SHA2代码签名补丁 (KB4474419/KB4490628)
 *   - Windows 10+: 检查Microsoft Edge WebView2运行时
 *   - GUI窗口显示检测结果，提供可点击的下载链接
 *   - 支持复制检测结果到剪贴板
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

#ifndef _NTDEF_
typedef LONG NTSTATUS;
#endif

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#endif

/* swprintf统一使用C99签名 (buf, size, fmt, ...) - MSVC 2015+和MinGW均支持 */
#define SWPRINTF(buf, bufsz, fmt, ...) swprintf(buf, bufsz, fmt, __VA_ARGS__)

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
#define IDC_COPY_BTN        9001

/* ===== 全局变量 ===== */
static BOOL g_is64bit = FALSE;
static HINSTANCE g_hInst = NULL;
static HWND g_hWndMain = NULL;
static wchar_t g_resultText[2048];

/* ===== 辅助函数 ===== */

static const wchar_t* GetArchStringW(void) {
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    g_is64bit = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
                 si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: return L"x64";
        case PROCESSOR_ARCHITECTURE_ARM64: return L"ARM64";
        case PROCESSOR_ARCHITECTURE_INTEL:  return L"x86";
        default: return L"Unknown";
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
        free(buffer); return FALSE;
    }
    VS_FIXEDFILEINFO *ffi = NULL;
    UINT ffiSize = 0;
    if (!VerQueryValueW(buffer, L"\\", (LPVOID*)&ffi, &ffiSize) ||
        ffiSize < sizeof(VS_FIXEDFILEINFO)) {
        free(buffer); return FALSE;
    }
    DWORD major   = HIWORD(ffi->dwFileVersionMS);
    DWORD minor   = LOWORD(ffi->dwFileVersionMS);
    DWORD build   = HIWORD(ffi->dwFileVersionLS);
    DWORD private = LOWORD(ffi->dwFileVersionLS);
    BOOL result = (major == 6 && minor == 1 && build == 7601 && private >= 23473);
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

typedef struct {
    BOOL sha2_ok;
    BOOL wv2_ok;
    wchar_t wv2_version[64];
    wchar_t arch[16];
    DWORD win_ver_major;
    DWORD win_ver_minor;
    DWORD win_build;
} CheckResult;

static void OpenURL(LPCWSTR url) {
    ShellExecuteW(NULL, L"open", url, NULL, NULL, SW_SHOWNORMAL);
}

/* 构建纯文本结果用于剪贴板 */
static void BuildResultText(const CheckResult *r) {
    const wchar_t *ed = L"Windows";
    if (r->win_ver_major == 6 && r->win_ver_minor == 1) ed = L"Windows 7";
    else if (r->win_ver_major == 6 && r->win_ver_minor == 3) ed = L"Windows 8.1";
    else if (r->win_ver_major == 10 && r->win_build >= 22000) ed = L"Windows 11";
    else if (r->win_ver_major == 10) ed = L"Windows 10";

    int n = 0;
    int cap = (int)(sizeof(g_resultText) / sizeof(wchar_t)) - 1;
    n += SWPRINTF(g_resultText + n, cap - n,
        L"\x64CD\x4F5C\x7CFB\x7EDF: %s (Build %lu)\r\n", ed, r->win_build);
    n += SWPRINTF(g_resultText + n, cap - n,
        L"\x7CFB\x7EDF\x67B6\x6784: %s\r\n", r->arch);

    if (r->win_ver_major < 10) {
        if (r->sha2_ok)
            n += SWPRINTF(g_resultText + n, cap - n,
                L"SHA2\x4EE3\x7801\x7B7E\x540D\x8865\x4E01: \x5DF2\x5B89\x88C5 \x2713\r\n");
        else
            n += SWPRINTF(g_resultText + n, cap - n,
                L"SHA2\x4EE3\x7801\x7B7E\x540D\x8865\x4E01: \x672A\x5B89\x88C5 \x2717\r\n");
    }

    if (r->wv2_ok && r->wv2_version[0])
        n += SWPRINTF(g_resultText + n, cap - n,
            L"WebView2\x8FD0\x884C\x65F6: \x5DF2\x5B89\x88C5 (\x7248\x672C %s) \x2713\r\n", r->wv2_version);
    else if (r->wv2_ok)
        n += SWPRINTF(g_resultText + n, cap - n,
            L"WebView2\x8FD0\x884C\x65F6: \x5DF2\x5B89\x88C5 \x2713\r\n");
    else
        n += SWPRINTF(g_resultText + n, cap - n,
            L"WebView2\x8FD0\x884C\x65F6: \x672A\x5B89\x88C5 \x2717\r\n");
}

/* 复制到剪贴板 */
static void CopyToClipboard(HWND hwnd) {
    if (!g_resultText[0]) return;
    size_t len = wcslen(g_resultText);
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (len + 1) * sizeof(wchar_t));
    if (!hMem) return;
    wchar_t *p = (wchar_t*)GlobalLock(hMem);
    if (!p) { GlobalFree(hMem); return; }
    wcscpy(p, g_resultText);
    GlobalUnlock(hMem);
    if (OpenClipboard(hwnd)) {
        EmptyClipboard();
        SetClipboardData(CF_UNICODETEXT, hMem);
        CloseClipboard();
    } else {
        GlobalFree(hMem);
    }
}

/* 窗口过程 */
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCTW *cs = (CREATESTRUCTW*)lParam;
        CheckResult *result = (CheckResult*)cs->lpCreateParams;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)result);
        BuildResultText(result);

        HDC hdc = GetDC(hwnd);
        int dpi = GetDeviceCaps(hdc, LOGPIXELSY);
        ReleaseDC(hwnd, hdc);
        int scale = MulDiv(100, dpi, 96);

        /* 字体 */
        HFONT hFont = CreateFontW(
            -MulDiv(9, dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
        HFONT hFontBold = CreateFontW(
            -MulDiv(10, dpi, 72), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");

        /* DPI感知布局 - 加大控件宽度和行高避免截断 */
        int margin    = MulDiv(24, scale, 100);
        int xText     = margin;
        int xLink     = margin;
        int lineH     = MulDiv(34, scale, 100);   /* 行高 > 控件高度，防止重叠 */
        int ctrlH     = MulDiv(26, scale, 100);   /* 文本控件高度 */
        int linkH     = MulDiv(28, scale, 100);   /* 链接控件高度 */
        int ctrlW     = MulDiv(660, scale, 100);  /* 文本控件宽度 - 足够显示完整文字 */
        int linkW     = MulDiv(680, scale, 100);  /* 链接控件宽度 */
        int titleH    = MulDiv(34, scale, 100);
        int btnW      = MulDiv(120, scale, 100);
        int btnH      = MulDiv(34, scale, 100);
        int sectionGap = MulDiv(12, scale, 100);
        int indent     = MulDiv(20, scale, 100);  /* 链接缩进 */
        int staticId = ID_STATIC_BASE;
        int linkId = ID_LINK_BASE;
        int y = MulDiv(18, scale, 100);

        /* 标题 */
        HWND hTitle = CreateWindowW(L"STATIC",
            L"\x7CFB\x7EDF\x73AF\x5883\x68C0\x67E5\x7ED3\x679C",
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            xText, y, ctrlW, titleH, hwnd, (HMENU)(INT_PTR)staticId++, cs->hInstance, NULL);
        SendMessageW(hTitle, WM_SETFONT, (WPARAM)hFontBold, TRUE);
        y += titleH + MulDiv(6, scale, 100);

        /* 分隔线 */
        CreateWindowW(L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_ETCHEDHORZ,
            xText, y, ctrlW, 2, hwnd, (HMENU)(INT_PTR)staticId++, cs->hInstance, NULL);
        y += MulDiv(10, scale, 100);

        /* 操作系统 - Windows 11的RtlGetVersion返回dwMajorVersion=10, 需用Build号判断 */
        const wchar_t *edition = L"Windows";
        if (result->win_ver_major == 6 && result->win_ver_minor == 1)
            edition = L"Windows 7";
        else if (result->win_ver_major == 6 && result->win_ver_minor == 3)
            edition = L"Windows 8.1";
        else if (result->win_ver_major == 10 && result->win_build >= 22000)
            edition = L"Windows 11";
        else if (result->win_ver_major == 10)
            edition = L"Windows 10";

        wchar_t osText[512];
        SWPRINTF(osText, 512,
            L"\x64CD\x4F5C\x7CFB\x7EDF:  %s (Build %lu)", edition, result->win_build);
        HWND hOS = CreateWindowW(L"STATIC", osText,
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            xText, y, ctrlW, ctrlH, hwnd, (HMENU)(INT_PTR)staticId++, cs->hInstance, NULL);
        SendMessageW(hOS, WM_SETFONT, (WPARAM)hFont, TRUE);
        y += lineH;

        /* 系统架构 */
        wchar_t archText[128];
        SWPRINTF(archText, 128, L"\x7CFB\x7EDF\x67B6\x6784:  %s", result->arch);
        HWND hArch = CreateWindowW(L"STATIC", archText,
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            xText, y, ctrlW, ctrlH, hwnd, (HMENU)(INT_PTR)staticId++, cs->hInstance, NULL);
        SendMessageW(hArch, WM_SETFONT, (WPARAM)hFont, TRUE);
        y += lineH + sectionGap;

        /* SHA2补丁 (仅Win7) */
        if (result->win_ver_major < 10) {
            const wchar_t *sha2Text = result->sha2_ok ?
                L"SHA2\x4EE3\x7801\x7B7E\x540D\x8865\x4E01:  \x5DF2\x5B89\x88C5  \x2713" :
                L"SHA2\x4EE3\x7801\x7B7E\x540D\x8865\x4E01:  \x672A\x5B89\x88C5  \x2717";

            HWND hSha2 = CreateWindowW(L"STATIC", sha2Text,
                WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
                xText, y, ctrlW, ctrlH, hwnd, (HMENU)(INT_PTR)staticId++, cs->hInstance, NULL);
            SendMessageW(hSha2, WM_SETFONT, (WPARAM)hFont, TRUE);
            y += lineH;

            if (!result->sha2_ok) {
                wchar_t linkText[600];
                if (g_is64bit) {
                    SWPRINTF(linkText, 600,
                        L"<a href=\"%s\">\x4E0B\x8F7D SHA2\x8865\x4E01 (x64)</a>    "
                        L"<a href=\"%s\">\x5FAE\x8F6F\x66F4\x65B0\x76EE\x5F55</a>",
                        URL_SHA2_X64, URL_SHA2_CATALOG);
                } else {
                    SWPRINTF(linkText, 600,
                        L"<a href=\"%s\">\x4E0B\x8F7D SHA2\x8865\x4E01 (x86)</a>    "
                        L"<a href=\"%s\">\x5FAE\x8F6F\x66F4\x65B0\x76EE\x5F55</a>",
                        URL_SHA2_X86, URL_SHA2_CATALOG);
                }
                HWND hLink = CreateWindowW(L"LINK", linkText,
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                    xLink + indent, y, linkW, linkH, hwnd,
                    (HMENU)(INT_PTR)linkId++, cs->hInstance, NULL);
                SendMessageW(hLink, WM_SETFONT, (WPARAM)hFont, TRUE);
                y += linkH + MulDiv(4, scale, 100);
            }
            y += sectionGap;
        }

        /* WebView2 */
        {
            wchar_t wv2Text[512];
            if (result->wv2_ok && result->wv2_version[0]) {
                SWPRINTF(wv2Text, 512,
                    L"WebView2\x8FD0\x884C\x65F6:  \x5DF2\x5B89\x88C5  (\x7248\x672C %s)  \x2713",
                    result->wv2_version);
            } else if (result->wv2_ok) {
                SWPRINTF(wv2Text, 512,
                    L"WebView2\x8FD0\x884C\x65F6:  \x5DF2\x5B89\x88C5  \x2713");
            } else {
                SWPRINTF(wv2Text, 512,
                    L"WebView2\x8FD0\x884C\x65F6:  \x672A\x5B89\x88C5  \x2717");
            }

            HWND hWV2 = CreateWindowW(L"STATIC", wv2Text,
                WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
                xText, y, ctrlW, ctrlH, hwnd, (HMENU)(INT_PTR)staticId++, cs->hInstance, NULL);
            SendMessageW(hWV2, WM_SETFONT, (WPARAM)hFont, TRUE);
            y += lineH;

            if (!result->wv2_ok) {
                wchar_t linkText[600];
                SWPRINTF(linkText, 600,
                    L"<a href=\"%s\">\x4E0B\x8F7D WebView2\x8FD0\x884C\x65F6</a>    "
                    L"<a href=\"%s\">\x5B98\x65B9\x4E0B\x8F7D\x9875\x9762</a>",
                    URL_WEBVIEW2_DL, URL_WEBVIEW2);

                HWND hLink = CreateWindowW(L"LINK", linkText,
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                    xLink + indent, y, linkW, linkH, hwnd,
                    (HMENU)(INT_PTR)linkId++, cs->hInstance, NULL);
                SendMessageW(hLink, WM_SETFONT, (WPARAM)hFont, TRUE);
                y += linkH + MulDiv(4, scale, 100);
            }
        }

        y += sectionGap + MulDiv(8, scale, 100);

        /* 按钮: 复制结果 + 关闭 */
        int btnGap = MulDiv(16, scale, 100);
        int clientW = MulDiv(720, scale, 100);
        int totalBtnW = btnW * 2 + btnGap;
        int btnStartX = (clientW - totalBtnW) / 2;

        HWND hCopyBtn = CreateWindowW(L"BUTTON",
            L"\x590D\x5236\x7ED3\x679C",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            btnStartX, y, btnW, btnH, hwnd, (HMENU)IDC_COPY_BTN, cs->hInstance, NULL);
        SendMessageW(hCopyBtn, WM_SETFONT, (WPARAM)hFont, TRUE);

        HWND hCloseBtn = CreateWindowW(L"BUTTON",
            L"\x5173\x95ED",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            btnStartX + btnW + btnGap, y, btnW, btnH, hwnd, (HMENU)IDC_CLOSE_BTN, cs->hInstance, NULL);
        SendMessageW(hCloseBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
        y += btnH + MulDiv(16, scale, 100);

        /* 用AdjustWindowRect计算包含非客户区的正确窗口尺寸 */
        RECT rc = {0, 0, clientW, y};
        AdjustWindowRect(&rc, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE);
        SetWindowPos(hwnd, NULL, 0, 0, rc.right - rc.left, rc.bottom - rc.top,
                     SWP_NOMOVE | SWP_NOZORDER);

        /* 居中窗口 */
        int screenW = GetSystemMetrics(SM_CXSCREEN);
        int screenH = GetSystemMetrics(SM_CYSCREEN);
        int winW = rc.right - rc.left;
        int winH = rc.bottom - rc.top;
        SetWindowPos(hwnd, NULL, (screenW - winW) / 2, (screenH - winH) / 2, 0, 0,
                     SWP_NOSIZE | SWP_NOZORDER);
        break;
    }

    case WM_NOTIFY: {
        NMHDR *nmhdr = (NMHDR*)lParam;
        if (nmhdr->code == NM_CLICK || nmhdr->code == NM_RETURN) {
            NMLINK *nmlink = (NMLINK*)lParam;
            LPCWSTR url = nmlink->item.szUrl;
            if (url && *url) OpenURL(url);
        }
        break;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_CLOSE_BTN) {
            DestroyWindow(hwnd);
        } else if (LOWORD(wParam) == IDC_COPY_BTN) {
            CopyToClipboard(hwnd);
            MessageBoxW(hwnd,
                L"\x68C0\x67E5\x7ED3\x679C\x5DF2\x590D\x5236\x5230\x526A\x8D34\x677F",
                L"\x63D0\x793A",
                MB_OK | MB_ICONINFORMATION);
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
    (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;
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
    typedef LONG (WINAPI *RtlGetVersionPtr)(POSVERSIONINFOEXW);
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    RtlGetVersionPtr RtlGetVersion = NULL;
    if (hNtDll) {
        RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hNtDll, "RtlGetVersion");
    }
    if (RtlGetVersion) {
        RtlGetVersion(&osvi);
    } else {
        osvi.dwMajorVersion = 10;
        osvi.dwMinorVersion = 0;
        osvi.dwBuildNumber = 0;
    }

    /* 执行检测 */
    CheckResult result = {0};
    result.win_ver_major = osvi.dwMajorVersion;
    result.win_ver_minor = osvi.dwMinorVersion;
    result.win_build = osvi.dwBuildNumber;
    const wchar_t *arch = GetArchStringW();
    wcsncpy(result.arch, arch, sizeof(result.arch) / sizeof(wchar_t) - 1);
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

    /* 创建窗口 */
    g_hWndMain = CreateWindowExW(
        0, L"CheckEnvWnd", L"\x7CFB\x7EDF\x73AF\x5883\x68C0\x67E5",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        NULL, NULL, hInstance, &result
    );

    if (!g_hWndMain) {
        MessageBoxW(NULL, L"\x521B\x5EFA\x7A97\x53E3\x5931\x8D25", L"\x9519\x8BEF", MB_OK | MB_ICONERROR);
        return 1;
    }

    ShowWindow(g_hWndMain, nCmdShow);
    UpdateWindow(g_hWndMain);

    /* 消息循环 */
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}