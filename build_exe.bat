@echo off
echo ===================================
echo          TCP服务器程序打包工具
echo ===================================
echo.

REM 检查Python是否安装
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [错误] 未找到Python，请确保已安装Python并添加到PATH环境变量中。
    goto end
)

echo [信息] 开始构建EXE文件...
echo.

REM 执行打包脚本
python build_exe.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [错误] 构建过程中出现问题，请检查以上输出信息。
    goto end
)

echo.
echo [成功] EXE文件构建完成！
echo.

REM 检查dist目录是否存在
if exist dist (
    echo 打包文件位于 "%CD%\dist" 目录下
    echo.
    echo 是否打开此目录查看? [Y/N]
    choice /c YN /n
    if %ERRORLEVEL% EQU 1 start "" "dist"
)

:end
echo.
echo 按任意键退出...
pause > nul