import os
import sys
from tkinter import ttk
import tkinter as tk
from tools.tcp_server.gui.server_window import ServerWindow
from gui.widgets.tool_card import ToolCard
import uuid
import math

class MainWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Multi-Tool Suite")
        self.root.geometry("800x600")
        self.root.resizable(False, False)
        self.tool_windows = {
            'tcp_server': []
        }
        self._create_widgets()
        self.center_window()

    def _create_widgets(self):
        self.container = ttk.Frame(self.root)
        self.container.pack(fill="both", expand=True, padx=20, pady=20)

        # 创建滚动画布
        self.canvas = tk.Canvas(self.container)
        self.scrollbar = ttk.Scrollbar(self.container, orient="vertical", command=self.canvas.yview)
        self.scroll_frame = ttk.Frame(self.canvas)

        # 绑定配置更新
        self.scroll_frame.bind("<Configure>", self._on_frame_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        # 绑定鼠标滚轮事件
        self.canvas.bind("<MouseWheel>", self._on_mousewheel)  # Windows
        self.canvas.bind("<Button-4>", self._on_mousewheel)    # Linux
        self.canvas.bind("<Button-5>", self._on_mousewheel)    # Linux

        # 创建滚动窗口
        self.canvas_window = self.canvas.create_window((0, 0), window=self.scroll_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # 添加标题
        title_label = ttk.Label(self.scroll_frame, text="工具列表", font=("Helvetica", 14, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 10))

        self._create_tool_cards()

    def _on_mousewheel(self, event):
        """处理鼠标滚轮事件"""
        if event.num == 4 or event.delta > 0:
            self.canvas.yview_scroll(-1, "units")
        elif event.num == 5 or event.delta < 0:
            self.canvas.yview_scroll(1, "units")

    def _create_tool_cards(self):
        icon_path = self._get_resource_path("resources/images/icons/tool_tcp.png")
        tools = [
            {
                "title": "TCP/TLS Server",
                "description": "支持插件的高级TCP/TLS 服务器",
                "callback": self._open_tcp_server
            }
        ]

        # 添加示例工具
        for i in range(3):
            tools.append({
                "title": f"Tool {i+1}",
                "description": "Coming soon...",
                "callback": lambda: print("Tool not implemented")
            })

        # 计算列数（基于容器宽度）
        card_width = 220  # 卡片宽度 + padding
        columns = max(2, self.root.winfo_width() // card_width)

        # 创建卡片网格
        for index, tool in enumerate(tools, start=1):
            row = (index - 1) // columns + 1  # 从第1行开始（标题在第0行）
            col = (index - 1) % columns

            card = ToolCard(
                self.scroll_frame,
                title=tool["title"],
                description=tool["description"],
                icon_path=icon_path,
                callback=tool["callback"],
                width=200,
                height=250
            )
            card.grid(row=row, column=col, pady=10, padx=10, sticky="nsew")

        # 配置列权重
        for i in range(columns):
            self.scroll_frame.grid_columnconfigure(i, weight=1)

    def _get_resource_path(self, relative_path):
        """获取资源文件的绝对路径"""
        if getattr(sys, 'frozen', False):
            # 如果是打包后的可执行文件
            base_path = sys._MEIPASS
        else:
            # 如果是开发环境
            base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

        return os.path.join(base_path, relative_path)

    def _on_frame_configure(self, event=None):
        """当滚动框架大小改变时更新滚动区域"""
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        """当画布大小改变时调整内部窗口宽度"""
        width = event.width
        self.canvas.itemconfig(self.canvas_window, width=width)

    def _open_tcp_server(self):
        """打开TCP服务器窗口"""
        window_id = str(uuid.uuid4())
        # 计算窗口序号
        window_number = len(self.tool_windows['tcp_server']) + 1
        server_window = ServerWindow(master=self.root,window_number=window_number)  # 传入主窗口作为master
        self.tool_windows['tcp_server'].append((window_id, server_window))
        # 相对于主窗口定位新窗口
        x = self.root.winfo_x() + 50 + len(self.tool_windows['tcp_server']) * 30
        y = self.root.winfo_y() + 50 + len(self.tool_windows['tcp_server']) * 30
        server_window.root.geometry(f"+{x}+{y}")

    def center_window(self):
        """使窗口在屏幕中居中显示"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def run(self):
        """运行主窗口"""
        self.root.mainloop()