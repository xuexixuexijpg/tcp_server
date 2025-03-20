import tkinter as tk
from tkinter import ttk


class CertificateGenerationDialog:
    """证书生成进度对话框"""

    def __init__(self, parent, ip_address):
        """
        初始化证书生成对话框

        参数:
            parent: 父窗口
            ip_address: 要生成证书的IP地址
        """
        self.parent = parent
        self.ip_address = ip_address
        self.window = None
        self.detail_label = None
        self.progress_bar = None

        # 创建并显示对话框
        self._create_dialog()

    def _create_dialog(self):
        """创建进度对话框"""
        # 创建进度窗口
        self.window = tk.Toplevel(self.parent)
        self.window.title("生成证书")
        self.window.geometry("350x150")
        self.window.resizable(False, False)
        self.window.transient(self.parent)  # 设置为父窗口的子窗口
        self.window.grab_set()  # 模态窗口

        # 窗口居中
        self._center_window()

        # 添加进度标签
        progress_label = tk.Label(self.window, text=f"正在为 {self.ip_address} 生成证书...", font=("Arial", 10))
        progress_label.pack(pady=(15, 5))

        # 添加详细进度信息
        self.detail_label = tk.Label(self.window, text="初始化...", font=("Arial", 9))
        self.detail_label.pack(pady=5)

        # 添加进度条
        self.progress_bar = ttk.Progressbar(self.window, mode="indeterminate")
        self.progress_bar.pack(fill=tk.X, padx=20, pady=10)
        self.progress_bar.start()

    def _center_window(self):
        """将窗口居中显示"""
        screen_width = self.parent.winfo_screenwidth()
        screen_height = self.parent.winfo_screenheight()
        window_width = 350
        window_height = 150
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.window.geometry(f"{window_width}x{window_height}+{x}+{y}")

    def update_progress(self, message):
        """更新进度信息

        参数:
            message: 进度信息
        """
        self.detail_label.config(text=message)

    def close(self):
        """关闭对话框"""
        self.window.destroy()
