/**
 * check_env.c - 系统环境检查工具
 *
 * 功能:
 *   - Windows 7: 检查SHA2代码签名补丁 (KB4474419/KB4490628)
 *   - Windows 10+: 检查Microsoft Edge WebView2运行时
 *
 * 检测方法参考: kb4474419_check.bat, pre_install_check.bat
 *
 * SHA2检测方法:
 *   1. 注册表检查 KB4474419 (默认视图 + 64位视图)
 *   2. 注册表检查 KB4490628 (默认视图 + 64位视图)
 *   3. crypt32.dll 文件版本检查 (>= 6.1.7601.23473)
 *
 * WebView2检测方法:
 *   1. 注册表 - Evergreen Runtime (原生 + WOW6432Node)
 *   2. 注册表 - Fixed Version (原生 + WOW6432Node)
 *   3. 文件路径检查 (6个常见安装路径)
 *
 * 编译:
 *   MSVC:  cl check_env.c /MT /Fe:check_env.exe advapi32.lib version.lib
 *   MinGW: gcc check_env.c -static -o check_env.exe -ladvapi32 -lversion
 *
 * 用法:
 *   check_env.exe          普通运行
 *   check_env.exe --iss    Inno Setup模式(不暂停等待按键)
 */

#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <string.h>
#include <stdlib.h>

/* MSVC兼容性: NTSTATUS类型定义 */
#ifndef _NTDEF_
typedef LONG NTSTATUS;
#endif

/* MSVC自动链接库 */
#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "version.lib")
#endif

/* ===== 下载链接 ===== */
#define URL_SHA2_CATALOG  "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB4474419"
#define URL_SHA2_X64      "https://mnl.lanzouc.com/i2ULP49qiqla"
#define URL_SHA2_X86      "https://mnl.lanzouc.com/iWzXt49qiptc"
#define URL_WEBVIEW2      "https://developer.microsoft.com/zh-cn/microsoft-edge/webview2/#download-section"
#define URL_WEBVIEW2_DL   "https://go.microsoft.com/fwlink/p/?LinkId=2124703"

/* ===== 注册表路径 - SHA2补丁 ===== */
#define HOTFIX_KEY_BASE   L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\HotFix\\"
#define KB4474419_KEY     HOTFIX_KEY_BASE L"KB4474419"
#define KB4490628_KEY     HOTFIX_KEY_BASE L"KB4490628"

/* ===== 注册表路径 - WebView2 ===== */
/* Evergreen Runtime (两个已知GUID) */
#define WV2_EG1_KEY       L"SOFTWARE\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
#define WV2_EG1_WOW_KEY   L"SOFTWARE\\WOW6432Node\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
#define WV2_EG2_KEY       L"SOFTWARE\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BEB-673F7D8AED47}"
#define WV2_EG2_WOW_KEY   L"SOFTWARE\\WOW6432Node\\Microsoft\\EdgeUpdate\\Clients\\{F3017226-FE2A-4295-8BEB-673F7D8AED47}"
/* Fixed Version */
#define WV2_FX_KEY        L"SOFTWARE\\Microsoft\\EdgeUpdate\\Clients\\{F20586C8-705C-474E-BA42-7E975B87D44B}"
#define WV2_FX_WOW_KEY    L"SOFTWARE\\WOW6432Node\\Microsoft\\EdgeUpdate\\Clients\\{F20586C8-705C-474E-BA42-7E975B87D44B}"

/* ===== 全局变量 ===== */
static BOOL g_issMode = FALSE;
static BOOL g_is64bit = FALSE;

/* ===== 辅助函数 ===== */

/* 获取系统架构字符串 */
static const char* GetArchString(void) {
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

/* 检查注册表键是否存在 */
static BOOL RegKeyExists(HKEY root, LPCWSTR subKey, REGSAM access) {
    HKEY hKey;
    LONG result = RegOpenKeyExW(root, subKey, 0, KEY_READ | access, &hKey);
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    return FALSE;
}

/* 查询注册表字符串值 */
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

/* 检查文件是否存在 */
static BOOL FileExistsW(LPCWSTR path) {
    DWORD attrs = GetFileAttributesW(path);
    return (attrs != INVALID_FILE_ATTRIBUTES &&
            !(attrs & FILE_ATTRIBUTE_DIRECTORY));
}

/* 展开环境变量并检查文件是否存在 */
static BOOL ExpandAndCheckFile(LPCWSTR pathTemplate) {
    WCHAR path[MAX_PATH] = {0};
    ExpandEnvironmentStringsW(pathTemplate, path, MAX_PATH);
    return FileExistsW(path);
}

/* 宽字符转UTF-8输出 */
static void WToUTF8(const wchar_t *wstr, char *buf, DWORD bufSize) {
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, buf, bufSize, NULL, NULL);
}

/* ===== SHA2补丁检测 ===== */

/**
 * 方法1-2: 注册表检查KB4474419和KB4490628
 * 同时检查默认视图和64位视图(兼容32位进程在64位系统上运行)
 */
static BOOL CheckSHA2ByRegistry(void) {
    /* KB4474419 - 默认视图 */
    if (RegKeyExists(HKEY_LOCAL_MACHINE, KB4474419_KEY, 0)) {
        printf("  [注册表] 检测到 KB4474419 已安装\n");
        return TRUE;
    }
    /* KB4474419 - 64位视图(32位进程在64位系统) */
    if (RegKeyExists(HKEY_LOCAL_MACHINE, KB4474419_KEY, KEY_WOW64_64KEY)) {
        printf("  [注册表] 检测到 KB4474419 已安装(64位视图)\n");
        return TRUE;
    }
    /* KB4490628 - 默认视图 */
    if (RegKeyExists(HKEY_LOCAL_MACHINE, KB4490628_KEY, 0)) {
        printf("  [注册表] 检测到 KB4490628 已安装(含KB4474419)\n");
        return TRUE;
    }
    /* KB4490628 - 64位视图 */
    if (RegKeyExists(HKEY_LOCAL_MACHINE, KB4490628_KEY, KEY_WOW64_64KEY)) {
        printf("  [注册表] 检测到 KB4490628 已安装(64位视图,含KB4474419)\n");
        return TRUE;
    }
    return FALSE;
}

/**
 * 方法3: crypt32.dll文件版本检查
 * Win7 SP1安装SHA-2支持后 crypt32.dll 版本 >= 6.1.7601.23473
 * 这是最可靠的文件级检测方式，即使KB补丁记录缺失也能反映SHA-2支持
 */
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

    printf("  [文件] crypt32.dll 版本: %lu.%lu.%lu.%lu\n",
           major, minor, build, private);

    BOOL result = FALSE;
    /* Win7 SP1 的 crypt32.dll 版本为 6.1.7601.x，第4段 >= 23473 表示支持SHA2 */
    if (major == 6 && minor == 1 && build == 7601 && private >= 23473) {
        result = TRUE;
    }

    free(buffer);
    return result;
}

/**
 * 综合SHA2检测 - 按优先级依次尝试所有方法
 */
static BOOL CheckSHA2Patch(void) {
    /* 方法1-2: 注册表检查KB补丁 */
    if (CheckSHA2ByRegistry()) {
        return TRUE;
    }

    /* 方法3: crypt32.dll版本检查(文件级检测，更可靠) */
    printf("  [注册表] 未检测到KB补丁记录，检查 crypt32.dll 版本...\n");
    if (CheckSHA2ByCrypt32()) {
        printf("  [文件] crypt32.dll 支持 SHA2 签名\n");
        return TRUE;
    }

    return FALSE;
}

/* ===== WebView2检测 ===== */

/**
 * 方法1: 注册表检查WebView2
 * 检查 Evergreen Runtime 和 Fixed Version 的注册表项
 * 同时检查原生路径和WOW6432Node路径(兼容32位程序)
 */
static BOOL CheckWebView2ByRegistry(wchar_t *version, DWORD size) {
    /* Evergreen Runtime GUID1 - 原生注册表 */
    if (RegKeyExists(HKEY_LOCAL_MACHINE, WV2_EG1_KEY, 0)) {
        RegQueryStringValue(HKEY_LOCAL_MACHINE, WV2_EG1_KEY, L"pv", version, size);
        printf("  [注册表] 检测到 WebView2 Evergreen Runtime (原生)\n");
        return TRUE;
    }
    /* Evergreen Runtime GUID1 - WOW6432Node */
    if (RegKeyExists(HKEY_LOCAL_MACHINE, WV2_EG1_WOW_KEY, 0)) {
        RegQueryStringValue(HKEY_LOCAL_MACHINE, WV2_EG1_WOW_KEY, L"pv", version, size);
        printf("  [注册表] 检测到 WebView2 Evergreen Runtime (WOW6432Node)\n");
        return TRUE;
    }
    /* Evergreen Runtime GUID2 - 原生注册表 */
    if (RegKeyExists(HKEY_LOCAL_MACHINE, WV2_EG2_KEY, 0)) {
        RegQueryStringValue(HKEY_LOCAL_MACHINE, WV2_EG2_KEY, L"pv", version, size);
        printf("  [注册表] 检测到 WebView2 Evergreen Runtime (原生,GUID2)\n");
        return TRUE;
    }
    /* Evergreen Runtime GUID2 - WOW6432Node */
    if (RegKeyExists(HKEY_LOCAL_MACHINE, WV2_EG2_WOW_KEY, 0)) {
        RegQueryStringValue(HKEY_LOCAL_MACHINE, WV2_EG2_WOW_KEY, L"pv", version, size);
        printf("  [注册表] 检测到 WebView2 Evergreen Runtime (WOW6432Node,GUID2)\n");
        return TRUE;
    }
    /* Fixed Version - 原生注册表 */
    if (RegKeyExists(HKEY_LOCAL_MACHINE, WV2_FX_KEY, 0)) {
        RegQueryStringValue(HKEY_LOCAL_MACHINE, WV2_FX_KEY, L"pv", version, size);
        printf("  [注册表] 检测到 WebView2 Fixed Version (原生)\n");
        return TRUE;
    }
    /* Fixed Version - WOW6432Node */
    if (RegKeyExists(HKEY_LOCAL_MACHINE, WV2_FX_WOW_KEY, 0)) {
        RegQueryStringValue(HKEY_LOCAL_MACHINE, WV2_FX_WOW_KEY, L"pv", version, size);
        printf("  [注册表] 检测到 WebView2 Fixed Version (WOW6432Node)\n");
        return TRUE;
    }

    /* 使用KEY_WOW64_64KEY再检查一次(32位进程在64位系统上访问原生注册表) */
    if (RegKeyExists(HKEY_LOCAL_MACHINE, WV2_EG1_KEY, KEY_WOW64_64KEY)) {
        RegQueryStringValue(HKEY_LOCAL_MACHINE, WV2_EG1_KEY, L"pv", version, size);
        printf("  [注册表] 检测到 WebView2 Evergreen Runtime (64位视图)\n");
        return TRUE;
    }
    if (RegKeyExists(HKEY_LOCAL_MACHINE, WV2_EG2_KEY, KEY_WOW64_64KEY)) {
        RegQueryStringValue(HKEY_LOCAL_MACHINE, WV2_EG2_KEY, L"pv", version, size);
        printf("  [注册表] 检测到 WebView2 Evergreen Runtime (64位视图,GUID2)\n");
        return TRUE;
    }
    if (RegKeyExists(HKEY_LOCAL_MACHINE, WV2_FX_KEY, KEY_WOW64_64KEY)) {
        RegQueryStringValue(HKEY_LOCAL_MACHINE, WV2_FX_KEY, L"pv", version, size);
        printf("  [注册表] 检测到 WebView2 Fixed Version (64位视图)\n");
        return TRUE;
    }

    return FALSE;
}

/**
 * 方法2: 文件路径检查WebView2
 * 检查6个常见的WebView2安装路径
 */
static BOOL CheckWebView2ByFiles(void) {
    /* 路径1: 系统目录 - 64位 */
    if (ExpandAndCheckFile(L"%SystemRoot%\\System32\\MicrosoftEdgeWebView2\\EdgeWebView2.exe")) {
        printf("  [文件] 系统目录(64位)检测到 WebView2\n");
        return TRUE;
    }
    /* 路径2: 系统目录 - 32位(SysWOW64) */
    if (ExpandAndCheckFile(L"%SystemRoot%\\SysWOW64\\MicrosoftEdgeWebView2\\EdgeWebView2.exe")) {
        printf("  [文件] 系统目录(32位)检测到 WebView2\n");
        return TRUE;
    }
    /* 路径3: 用户目录 - EdgeWebView */
    if (ExpandAndCheckFile(L"%LOCALAPPDATA%\\Microsoft\\EdgeWebView\\Application\\EdgeWebView2.exe")) {
        printf("  [文件] 用户EdgeWebView目录检测到 WebView2\n");
        return TRUE;
    }
    /* 路径4: 用户目录 - Edge浏览器自带 */
    if (ExpandAndCheckFile(L"%LOCALAPPDATA%\\Microsoft\\Edge\\Application\\msedgewebview2.exe")) {
        printf("  [文件] 用户Edge目录检测到 WebView2\n");
        return TRUE;
    }
    /* 路径5: Program Files - Edge浏览器自带 */
    if (ExpandAndCheckFile(L"%ProgramFiles%\\Microsoft\\Edge\\Application\\msedgewebview2.exe")) {
        printf("  [文件] Program Files Edge目录检测到 WebView2\n");
        return TRUE;
    }
    /* 路径6: Program Files (x86) - Edge浏览器自带 */
    if (ExpandAndCheckFile(L"%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedgewebview2.exe")) {
        printf("  [文件] Program Files (x86) Edge目录检测到 WebView2\n");
        return TRUE;
    }

    return FALSE;
}

/**
 * 综合WebView2检测 - 注册表优先，文件路径兜底
 */
static BOOL CheckWebView2(wchar_t *version, DWORD size) {
    /* 方法1: 注册表检查 */
    if (CheckWebView2ByRegistry(version, size)) {
        return TRUE;
    }
    /* 方法2: 文件路径检查 */
    if (CheckWebView2ByFiles()) {
        return TRUE;
    }
    return FALSE;
}

/* ===== 主函数 ===== */

int main(int argc, char *argv[]) {
    /* 检查命令行参数 */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--iss") == 0) {
            g_issMode = TRUE;
        }
    }

    /* 设置控制台为UTF-8输出 */
    SetConsoleOutputCP(65001);

    /* 获取系统版本 - 使用RtlGetVersion(不受兼容性清单影响) */
    OSVERSIONINFOEXW osvi;
    ZeroMemory(&osvi, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);

    typedef NTSTATUS(NTAPI *RtlGetVersionPtr)(POSVERSIONINFOEXW);
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        RtlGetVersionPtr fn = (RtlGetVersionPtr)GetProcAddress(hNtdll, "RtlGetVersion");
        if (fn) fn(&osvi);
    }

    /* 确定操作系统名称 */
    const char* osName;
    if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 0) {
        osName = "Windows Vista";
    } else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1) {
        osName = "Windows 7";
    } else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 2) {
        osName = "Windows 8";
    } else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 3) {
        osName = "Windows 8.1";
    } else if (osvi.dwMajorVersion == 10 && osvi.dwBuildNumber < 22000) {
        osName = "Windows 10";
    } else if (osvi.dwMajorVersion == 10 && osvi.dwBuildNumber >= 22000) {
        osName = "Windows 11";
    } else {
        osName = "Unknown Windows";
    }

    const char* arch = GetArchString();

    printf("========================================\n");
    printf("  系统环境检查工具\n");
    printf("========================================\n\n");
    printf("操作系统:   %s\n", osName);
    printf("系统版本:   %lu.%lu (Build %lu)\n",
           osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    printf("系统架构:   %s\n\n", arch);

    /* ---- Windows 7: 检查SHA2签名补丁 ---- */
    if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1) {
        printf("[检查] SHA2代码签名补丁\n");
        printf("  目标: KB4474419 / KB4490628\n");
        printf("  方法: 注册表检查 + crypt32.dll版本检查\n\n");

        BOOL hasSHA2 = CheckSHA2Patch();
        if (hasSHA2) {
            printf("\n[结果] 已安装 SHA2代码签名补丁，系统满足运行要求\n\n");
        } else {
            printf("\n[结果] 未安装 SHA2代码签名补丁\n\n");
            printf("========================================\n");
            printf("  重要提示\n");
            printf("========================================\n");
            printf("当前系统为 Windows 7，未检测到 SHA-2 代码签名支持！\n");
            printf("SHA-2 代码签名支持是 Windows 7 运行现代程序的必要条件\n");
            printf("缺少此支持会导致程序无法运行或报错\n\n");
            printf("请安装 KB4474419 以获取 SHA-2 支持:\n\n");
            printf("  官方下载: %s\n", URL_SHA2_CATALOG);
            if (g_is64bit) {
                printf("  x64 版本: %s\n", URL_SHA2_X64);
            } else {
                printf("  x86 版本: %s\n", URL_SHA2_X86);
            }
            printf("\n注意:\n");
            printf("  - 64位系统选择 x64 版本，32位系统选择 x86 版本\n");
            printf("  - 安装完成后需要重新启动计算机\n");
            printf("  - 安装前请确保系统已安装 SP1(服务包1)\n");
            printf("  - 若已安装 KB4490628 或 2019年9月之后的累积更新，\n");
            printf("    可能已包含 SHA-2 支持\n");
            printf("========================================\n\n");
        }
    }

    /* ---- Windows 10/11: 检查WebView2运行时 ---- */
    if (osvi.dwMajorVersion >= 10) {
        printf("[检查] Microsoft Edge WebView2 运行时\n");
        printf("  方法: 注册表检查 + 文件路径检查\n\n");

        wchar_t version[64] = {0};
        BOOL hasWebView2 = CheckWebView2(version, 64);
        if (hasWebView2) {
            char verA[64] = {0};
            if (version[0]) {
                WToUTF8(version, verA, 64);
                printf("\n[结果] 已安装 WebView2 运行时 (版本: %s)\n\n", verA);
            } else {
                printf("\n[结果] 已安装 WebView2 运行时\n\n");
            }
        } else {
            printf("\n[结果] 未安装 WebView2 运行时\n\n");
            printf("========================================\n");
            printf("  重要提示\n");
            printf("========================================\n");
            printf("当前系统未检测到 WebView2 运行时！\n");
            printf("WebView2 运行时是运行基于Edge内核程序的必要组件\n\n");
            printf("注意: Windows 10/11 通常预装 WebView2 运行时\n");
            printf("若已安装 Microsoft Edge 浏览器，系统很可能已包含 WebView2\n\n");
            printf("请下载安装 WebView2 运行时:\n");
            printf("  官方页面: %s\n", URL_WEBVIEW2);
            printf("  直接下载: %s\n", URL_WEBVIEW2_DL);
            printf("\n建议选择 \"Evergreen Bootstrapper\" 或\n");
            printf("        \"Evergreen Standalone Installer\" 版本\n");
            printf("安装完成后即可正常使用基于WebView2的程序\n");
            printf("========================================\n\n");
        }
    }

    /* ---- Windows 8/8.1: 不支持提示 ---- */
    if (osvi.dwMajorVersion == 6 && (osvi.dwMinorVersion == 2 || osvi.dwMinorVersion == 3)) {
        printf("[提示] Windows 8/8.1 不在支持范围内\n");
        printf("  请升级到 Windows 10 或更高版本\n\n");
    }

    /* ---- 更早的系统 ---- */
    if (osvi.dwMajorVersion < 6 ||
        (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 0)) {
        printf("[提示] 当前操作系统版本过低，不受支持\n\n");
    }

    printf("========================================\n");
    if (!g_issMode) {
        printf("按任意键退出...\n");
        _getch();
    }
    return 0;
}