import os
import sys
import datetime
import traceback
import shutil
from PyInstaller.__main__ import run

def create_zip(source_dir, output_name):
    """将目录打包成zip文件"""
    try:
        # 创建release目录
        release_dir = "release"
        os.makedirs(release_dir, exist_ok=True)

        # 生成zip文件路径
        zip_path = os.path.join(release_dir, f"{output_name}.zip")

        # 创建zip文件
        shutil.make_archive(
            zip_path.replace('.zip', ''),
            'zip',
            source_dir
        )
        return zip_path
    except Exception as e:
        print(f"创建ZIP文件失败: {e}")
        return None

def clean_dir(dir_name):
    """清空或创建目录"""
    if os.path.exists(dir_name):
        try:
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

def create_shortcut(exe_path, shortcut_path,working_dir,icon_path):
    """创建快捷方式"""
    try:
        import win32com.client
        import tempfile
        from PIL import Image
        # 转换为绝对路径
        exe_path = os.path.abspath(exe_path)
        working_dir = os.path.abspath(working_dir)
        # 在 _internal 目录中查找图标
        # if getattr(sys, 'frozen', False):
        #     # 打包后的路径
        #     icon_path = os.path.join(sys._MEIPASS, 'resources', 'images', 'icons', 'app.png')
        # else:
            # 开发环境路径
        icon_path = os.path.abspath(os.path.join('resources', 'images', 'icons', 'app.png'))

        print(f"\n创建快捷方式:")
        print(f"目标程序: {exe_path}")
        print(f"工作目录: {working_dir}")
        print(f"快捷方式: {shortcut_path}")
        print(f"图标路径: {icon_path}")

        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(shortcut_path)
        shortcut.TargetPath = exe_path
        shortcut.WorkingDirectory = working_dir
        # if icon_path and os.path.exists(icon_path):
        #     shortcut.IconLocation = icon_path
        # else:
        #     如果找不到图标文件，使用exe自身的图标
            # shortcut.IconLocation = exe_path
        shortcut.save()
        success = os.path.exists(shortcut_path)
        return success

    except Exception as e:
        print(f"创建快捷方式失败: {e}")
        return False

def main():
    # 创建日志目录
    log_dir = "build_logs"
    os.makedirs(log_dir, exist_ok=True)

    # 清理之前的构建目录
    for dir_to_clean in ['build', 'dist', 'release']:
        clean_dir(dir_to_clean)

    # 设置日志文件
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"build_{timestamp}.log")

    # 检查spec文件
    spec_file = "TCP服务器.spec"
    if not os.path.exists(spec_file):
        print(f"错误: 未找到spec文件 {spec_file}")
        return

    try:
        print("\n执行PyInstaller...")
        run([
            spec_file,
            '--clean',
        ])

        # 检查构建结果
        dist_dir = os.path.abspath(os.path.join('dist', '工具集'))
        exe_name = '工具集.exe'
        exe_path = os.path.join(dist_dir, exe_name)
        icon_path = os.path.abspath(os.path.join('resources', 'images', 'icons', 'app.png'))

        if os.path.exists(exe_path):
            # 创建发布包
            release_name = f"工具集_v{datetime.datetime.now().strftime('%Y%m%d')}"
            zip_path = create_zip(dist_dir, release_name)

            if zip_path and os.path.exists(zip_path):
                print(f"\n成功创建发布包:")
                print(f"路径: {os.path.abspath(zip_path)}")
                print(f"大小: {os.path.getsize(zip_path) / 1024 / 1024:.2f} MB")

                # 在本地环境中创建快捷方式
                if not os.environ.get('GITHUB_ACTIONS'):
                    try:
                        import winshell
                        desktop = winshell.desktop()
                        shortcut_path = os.path.join(desktop, f"{exe_name.replace('.exe', '.lnk')}")
                        if create_shortcut(exe_path, shortcut_path,dist_dir,icon_path):
                            print(f"已在桌面创建快捷方式: {shortcut_path}")
                    except Exception as e:
                        print(f"创建快捷方式时出错: {str(e)}")
            else:
                print("\n创建ZIP文件失败")
                sys.exit(1)
        else:
            print(f"\n错误: 未找到构建后的EXE文件 {exe_path}")
            sys.exit(1)

    except Exception as e:
        print(f"\n打包出错: {str(e)}")
        print("\n详细错误信息:")
        traceback.print_exc()
        sys.exit(1)

    print(f"\n构建日志结束时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()