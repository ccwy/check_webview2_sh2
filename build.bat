@echo off
REM 静态链接编译 check_env.exe
REM 需要安装 MinGW-w64 或 MSVC

where gcc >nul 2>nul
if %ERRORLEVEL%==0 (
    echo 使用 GCC 静态编译...
    gcc check_env.c -o check_env.exe -Wall -O2 -static -ladvapi32 -lversion
    if %ERRORLEVEL%==0 (
        echo 编译成功: check_env.exe
    ) else (
        echo 编译失败!
    )
    goto :end
)

where cl >nul 2>nul
if %ERRORLEVEL%==0 (
    echo 使用 MSVC 静态编译...
    cl check_env.c /MT /Fe:check_env.exe advapi32.lib version.lib
    if %ERRORLEVEL%==0 (
        echo 编译成功: check_env.exe
    ) else (
        echo 编译失败!
    )
    goto :end
)

echo 未找到 gcc 或 cl 编译器，请先安装 MinGW-w64 或 Visual Studio

:end
pause