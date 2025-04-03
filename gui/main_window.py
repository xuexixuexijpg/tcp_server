import os
import sys
import tkinter as tk
import uuid
from tkinter import ttk

from gui.qt.qt_imports import qt_app
from gui.widgets.tool_card import ToolCard
from tools.lottie_converter.gui.converter_window import ConverterWindow
from tools.tcp_server.gui.server_window import ServerWindow
from tools.xml.gui.xml_window import XMLConverterWindow


class MainWindow:
    def __init__(self):
        # 初始化Qt应用(如果还没有初始化)
        self.root = tk.Tk()
        self.root.title("Multi-Tool Suite")
        self.root.geometry("800x600")
        self.root.resizable(False, False)
        self.tool_windows = {
            'tcp_server': [],
            'gif_converter': []
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
        self.canvas.bind("<Button-4>", self._on_mousewheel)  # Linux
        self.canvas.bind("<Button-5>", self._on_mousewheel)  # Linux

        self.scroll_frame.bind("<MouseWheel>", self._on_mousewheel)  # Windows
        self.scroll_frame.bind("<Button-4>", self._on_mousewheel)  # Linux
        self.scroll_frame.bind("<Button-5>", self._on_mousewheel)  # Linux

        # 绑定所有子组件的滚轮事件
        self._bind_mousewheel_to_children(self.scroll_frame)

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
        # 定义滚动单位
        scroll_amount = -1 if (event.num == 4 or event.delta > 0) else 1
        # 使用yview_scroll进行滚动
        try:
            self.canvas.yview_scroll(scroll_amount, "units")
        except tk.TclError:
            pass  # 忽略可能的滚动错误

    def _create_tool_cards(self):
        tools = [
            {
                "title": "TCP/TLS Server",
                "description": "支持插件的高级TCP/TLS 服务器",
                "callback": self._open_tcp_server,
                "icon_path": self._get_resource_path("resources/images/icons/tool_tcp.png")
            },
            {
                "title": "Lottie转换",
                "description": "将资源转换为Lottie格式，支持格式见lottie-py",
                "callback": self._open_gif_converter,
                "icon_path": self._get_resource_path("resources/images/icons/tool_an.png")
            },
            {
                "title": "XML转换",
                "description": "XML加解密/XML-EXCEL互转",
                "callback": self._open_xml_window,
                "icon_path": self._get_resource_path("resources/images/icons/tool_xml.png")
            }
        ]

        # 添加示例工具
        for i in range(3):
            tools.append({
                "title": f"Tool {i + 1}",
                "description": "Coming soon...",
                "callback": lambda: print("Tool not implemented"),
                "icon_path": self._get_resource_path("resources/images/icons/tool_default.png")
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
                icon_path=tool["icon_path"],
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
        server_window = ServerWindow(master=self.root, window_number=window_number)  # 传入主窗口作为master
        self.tool_windows['tcp_server'].append((window_id, server_window))
        # 相对于主窗口定位新窗口
        x = self.root.winfo_x() + 50 + len(self.tool_windows['tcp_server']) * 30
        y = self.root.winfo_y() + 50 + len(self.tool_windows['tcp_server']) * 30
        server_window.root.geometry(f"+{x}+{y}")

    def _open_gif_converter(self):
        """打开GIF转换器窗口"""
        window_id = str(uuid.uuid4())
        window_number = len(self.tool_windows['gif_converter']) + 1
        converter_window = ConverterWindow(master=self.root, window_number=window_number)
        self.tool_windows['gif_converter'].append((window_id, converter_window))

        # 相对于主窗口定位新窗口
        x = self.root.winfo_x() + 50 + len(self.tool_windows['gif_converter']) * 30
        y = self.root.winfo_y() + 50 + len(self.tool_windows['gif_converter']) * 30
        converter_window.root.geometry(f"+{x}+{y}")

    def _open_xml_window(self):
        """打开XML转换器窗口"""
        window_id = str(uuid.uuid4())
        window_number = len(self.tool_windows.get('xml_converter', [])) + 1

        # 初始化xml_converter键(如果不存在)
        if 'xml_converter' not in self.tool_windows:
            self.tool_windows['xml_converter'] = []

        # 创建Qt版本的XML转换器窗口
        xml_window = XMLConverterWindow(window_number=window_number)
        self.tool_windows['xml_converter'].append((window_id, xml_window))

        # 计算新窗口位置(相对于主窗口)
        x = self.root.winfo_x() + 50 + len(self.tool_windows['xml_converter']) * 30
        y = self.root.winfo_y() + 50 + len(self.tool_windows['xml_converter']) * 30

        # 设置Qt窗口位置
        xml_window.window.move(x, y)

    def center_window(self):
        """使窗口在屏幕中居中显示"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def _bind_mousewheel_to_children(self, widget):
        """递归绑定所有子组件的鼠标滚轮事件"""
        widget.bind("<MouseWheel>", self._on_mousewheel)  # Windows
        widget.bind("<Button-4>", self._on_mousewheel)  # Linux
        widget.bind("<Button-5>", self._on_mousewheel)  # Linux

        for child in widget.winfo_children():
            self._bind_mousewheel_to_children(child)

    def run(self):
        """运行主窗口"""

        def process_events():
            """处理Qt事件"""
            qt_app.process_events()
            self.root.after(10, process_events)

        # 启动事件处理
        process_events()
        self.root.mainloop()
