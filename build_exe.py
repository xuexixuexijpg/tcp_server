import PyInstaller.__main__
import os
import sys
import traceback
import datetime
import shutil


#在终端中直接输入即可生成exe  python build_exe.py

# 清理先前的构建文件
print("清理之前的构建文件...")
if os.path.exists("dist"):
    shutil.rmtree("dist")
if os.path.exists("build"):
    shutil.rmtree("build")

# 删除当前目录中的 exe 文件
for file in os.listdir("."):
    if file.endswith(".exe"):
        try:
            os.remove(file)
            print(f"已删除: {file}")
        except Exception as e:
            print(f"无法删除 {file}: {e}")

def create_shortcut(exe_path, shortcut_path):
    try:
        import win32com.client
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(shortcut_path)
        shortcut.Targetpath = exe_path
        shortcut.WorkingDirectory = os.path.dirname(exe_path)
        shortcut.save()
        return True
    except ImportError:
        print("未能创建快捷方式：缺少 win32com 模块。请安装 pywin32：pip install pywin32")
        return False
    except Exception as e:
        print(f"创建快捷方式时出错：{e}")
        return False

# 确保输出目录存在并清空
def prepare_output_dir(dir_name):
    if os.path.exists(dir_name):
        try:
            # 尝试删除目录内容而不是目录本身
            for item in os.listdir(dir_name):
                item_path = os.path.join(dir_name, item)
                if os.path.isfile(item_path):
                    os.unlink(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
            print(f"已清空目录: {dir_name}")
        except Exception as e:
            print(f"清空目录 {dir_name} 时发生错误: {str(e)}")
    else:
        try:
            os.makedirs(dir_name)
            print(f"已创建目录: {dir_name}")
        except Exception as e:
            print(f"创建目录 {dir_name} 时发生错误: {str(e)}")


# 创建日志目录
log_dir = "build_logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# 设置日志文件
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = os.path.join(log_dir, f"build_{timestamp}.log")

# 设置控制台编码
import codecs

sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')


# 复制输出到日志文件
class Logger:
    def __init__(self, log_file):
        self.terminal = sys.stdout
        self.log = open(log_file, "w", encoding="utf-8")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)
        self.log.flush()

    def flush(self):
        self.terminal.flush()
        self.log.flush()


sys.stdout = Logger(log_file)
sys.stderr = sys.stdout

print(f"构建日志开始时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"日志文件: {os.path.abspath(log_file)}")
print(f"Python版本: {sys.version}")
print(f"工作目录: {os.getcwd()}")

# 检查并确保输出目录准备就绪
prepare_output_dir("dist")
prepare_output_dir("build")

# 设置主程序文件
main_file = 'main.py'

# 检查主文件是否存在
if not os.path.exists(main_file):
    print(f"错误: 主文件 {main_file} 不存在!")
    files = os.listdir('.')
    print(f"目录中的文件: {files}")
    sys.exit(1)

# 基本参数
params = [
    main_file,
    '--name=TCP服务器',
    '--onefile',
    '--windowed',
    '--clean',
    '--log-level=DEBUG',  # 详细日志
]

# 如果需要图标但不存在，则跳过
if os.path.exists('app.ico'):
    params.append('--icon=app.ico')
else:
    print("警告: 未找到图标文件 app.ico，将使用默认图标")

# 如果证书文件存在则添加
if os.path.exists('cert.pem'):
    params.append('--add-data=cert.pem;.')
if os.path.exists('key.pem'):
    params.append('--add-data=key.pem;.')

# 添加常用隐式导入
params.extend([
    '--hidden-import=cryptography',
    '--hidden-import=tkinter',
    '--hidden-import=PIL',
])

print("开始打包，使用以下参数:")
for param in params:
    print(f"  - {param}")

try:
    print("\n执行PyInstaller...")
    PyInstaller.__main__.run(params)

    # 检查是否真的生成了EXE文件
    exe_path = os.path.join('dist', 'TCP服务器.exe')
    if os.path.exists(exe_path):
        size = os.path.getsize(exe_path)
        print(f"\n成功! EXE文件已创建:")
        print(f"路径: {os.path.abspath(exe_path)}")
        print(f"大小: {size / 1024 / 1024:.2f} MB")

        # 创建快捷方式到桌面
        try:
            import winshell
            from win32com.client import Dispatch

            desktop = winshell.desktop()
            shortcut_path = os.path.join(desktop, "TCP服务器.lnk")
            if create_shortcut(exe_path, shortcut_path):
                print(f"已在桌面创建快捷方式: {shortcut_path}")
            shell = Dispatch('WScript.Shell')
            shortcut = shell.CreateShortCut(shortcut_path)
            shortcut.Targetpath = os.path.abspath(exe_path)
            shortcut.WorkingDirectory = os.path.dirname(os.path.abspath(exe_path))
            shortcut.save()

            print(f"已在桌面创建快捷方式: {shortcut_path}")
        except Exception as e:
            print(f"创建快捷方式时出错: {str(e)}")
    else:
        print(f"\n警告: 未在预期位置找到EXE文件 {exe_path}")
        # 搜索其他可能的位置
        for root, dirs, files in os.walk('dist'):
            for file in files:
                if file.endswith('.exe'):
                    full_path = os.path.join(root, file)
                    print(f"找到EXE文件: {full_path} ({os.path.getsize(full_path) / 1024 / 1024:.2f} MB)")

        print("\n请检查上面列出的文件，或运行 python find_exe.py 来查找所有EXE文件")
        sys.exit(1)

except Exception as e:
    print(f"\n打包出错: {str(e)}")
    print("\n详细错误信息:")
    traceback.print_exc()
    sys.exit(1)

print(f"\n构建日志结束时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
