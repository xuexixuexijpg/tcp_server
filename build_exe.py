import PyInstaller.__main__
import os

# 确保我们在正确的目录中
script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)

# 设置要打包的主程序文件
main_file = 'main.py'  # 替换为您项目的主入口文件名

# 配置PyInstaller参数
PyInstaller.__main__.run([
    main_file,
    '--name=TCP服务器',  # EXE文件名
    '--onefile',  # 生成单个EXE文件
    '--windowed',  # 对于GUI程序使用此选项，不显示控制台
    '--icon=app.ico',  # 如果您有图标文件，可以指定
    '--add-data=cert.pem;.',  # 添加证书文件
    '--add-data=key.pem;.',  # 添加密钥文件
    # 如果有其他需要的数据文件，也可以添加
    '--clean',  # 清理之前的构建文件
    '--noconfirm',  # 不确认覆盖
    # 在build_exe.py中添加
    '--hidden-import=cryptography',
])

print("打包完成！EXE文件位于dist目录中。")
