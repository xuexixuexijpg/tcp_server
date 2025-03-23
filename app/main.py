# from gui.gui  import run_gui
#
# if __name__ == "__main__":
#     run_gui()

#!/usr/bin/env python

from tools.tcp_server.gui.server_window import ServerWindow
from gui.main_window import MainWindow


def run_gui():
    """运行GUI"""
    app = MainWindow()
    try:
        app.run()
    except KeyboardInterrupt:
        print("程序被用户中断，正在安全退出...")
        # 这里可以添加任何清理代码
        # app.root.destroy()  # 确保窗口被正确关闭


if __name__ == "__main__":
    try:
        run_gui()
    except KeyboardInterrupt:
        print("程序在启动过程中被用户中断")


