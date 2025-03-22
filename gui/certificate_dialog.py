import tkinter as tk
from tkinter import ttk


class CertificateGenerationDialog(tk.Toplevel):
    """证书生成对话框"""

    def __init__(self, parent, ip_address):
        """
        初始化证书生成对话框

        参数:
            parent: 父窗口
            ip_address: 要生成证书的IP地址
        """
        super().__init__(parent)
        self.parent = parent
        self.ip_address = ip_address

        self.title("生成TLS证书")
        self.transient(parent)
        self.grab_set()
        self.resizable(False, False)

        # 结果变量
        self.generate_client_cert = tk.BooleanVar(value=True)

        # 创建对话框内容
        self._create_dialog()
        self._center_window()

    def _create_dialog(self):
        """创建对话框内容"""
        frame = ttk.Frame(self, padding="10")
        frame.pack(fill="both", expand=True)

        # 证书配置选项
        ttk.Label(frame, text="IP地址:").grid(row=0, column=0, sticky="w", pady=5)
        ttk.Label(frame, text=self.ip_address).grid(row=0, column=1, sticky="w", pady=5)

        # 生成客户端证书选项
        ttk.Checkbutton(
            frame,
            text="同时生成客户端证书（用于双向TLS认证）",
            variable=self.generate_client_cert
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=5)

        # 解释说明
        ttk.Label(
            frame,
            text="生成客户端证书可用于双向TLS认证，\n客户端需要安装证书才能连接到服务器。",
            foreground="gray"
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=5)

        # 按钮
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)

        ttk.Button(
            button_frame,
            text="生成证书",
            command=self._confirm
        ).pack(side="left", padx=5)

        ttk.Button(
            button_frame,
            text="取消",
            command=self.destroy
        ).pack(side="left", padx=5)

    def _center_window(self):
        """将窗口居中显示"""
        self.update_idletasks()

        width = 350
        height = 200

        x = self.parent.winfo_x() + (self.parent.winfo_width() // 2) - (width // 2)
        y = self.parent.winfo_y() + (self.parent.winfo_height() // 2) - (height // 2)

        self.geometry(f"{width}x{height}+{x}+{y}")

    def _confirm(self):
        """确认生成证书"""
        # 简单关闭对话框，实际的生成操作在server_window中处理
        self.destroy()
