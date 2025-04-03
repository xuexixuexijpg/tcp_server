import tkinter as tk
from PIL import Image, ImageTk
from functools import lru_cache

class ToolCard(tk.Frame):
    def __init__(self, parent, title, description, icon_path, callback, width=200, height=250):
        super().__init__(
            parent,
            width=width,
            height=height,
            relief=tk.RAISED,
            borderwidth=1,
            bg="#f0f0f0"
        )

        # 绑定鼠标滚轮事件
        self.bind("<MouseWheel>", self._propagate_mousewheel)      # Windows
        self.bind("<Button-4>", self._propagate_mousewheel)        # Linux
        self.bind("<Button-5>", self._propagate_mousewheel)        # Linux

        # 为所有子组件也绑定事件
        for child in self.winfo_children():
            child.bind("<MouseWheel>", self._propagate_mousewheel)
            child.bind("<Button-4>", self._propagate_mousewheel)
            child.bind("<Button-5>", self._propagate_mousewheel)


        self.grid_propagate(False)
        self.pack_propagate(False)

        # 使用单一content_frame避免多层嵌套
        self.content_frame = tk.Frame(self, bg="#f0f0f0")
        self.content_frame.place(relx=0.5, rely=0.5, anchor="center")

        # 缓存图标加载
        self.icon = self._load_icon(icon_path)
        if self.icon:
            tk.Label(
                self.content_frame,
                image=self.icon,
                bg="#f0f0f0"
            ).pack(pady=(0, 10))

        # 直接创建控件而不存储引用
        tk.Label(
            self.content_frame,
            text=title,
            font=("Helvetica", 16, "bold"),
            bg="#f0f0f0"
        ).pack(pady=5)

        tk.Label(
            self.content_frame,
            text=description,
            wraplength=180,
            font=("Helvetica", 12),
            bg="#f0f0f0"
        ).pack(pady=5)

        tk.Button(
            self.content_frame,
            text="Open",
            command=callback,
            width=15,
            relief=tk.RAISED,
            bg="#e0e0e0",
            activebackground="#d0d0d0"
        ).pack(pady=10)

        # 使用单一标记来追踪状态
        self._hovered = False
        self.bind("<Enter>", self._on_hover_change)
        self.bind("<Leave>", self._on_hover_change)

    @staticmethod
    @lru_cache(maxsize=32)
    def _load_icon(icon_path):
        """缓存图标加载"""
        try:
            img = Image.open(icon_path)
            img = img.resize((64, 64), Image.Resampling.LANCZOS)
            return ImageTk.PhotoImage(img)
        except Exception as e:
            print(f"Failed to load icon {icon_path}: {e}")
            return None

    def _on_hover_change(self, event):
        """统一处理悬停状态变化"""
        new_bg = "#e0e0e0" if event.type == tk.EventType.Enter else "#f0f0f0"
        if self["bg"] != new_bg:  # 只在需要时更新
            self.configure(bg=new_bg)
            self.content_frame.configure(bg=new_bg)
            for widget in self.content_frame.winfo_children():
                widget.configure(bg=new_bg)



    def _propagate_mousewheel(self, event):
        """将滚轮事件传播到父组件"""
        parent = self.master
        while parent:
            if isinstance(parent, tk.Canvas):  # 直接检查是否为Canvas实例
                delta = -1 if event.num == 4 or event.delta > 0 else 1
                parent.yview_scroll(delta, "units")
                break
            parent = parent.master
        return "break"