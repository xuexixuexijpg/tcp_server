#!/usr/bin/env python
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import messagebox


class BaseWindow:
    """窗口基类"""

    def __init__(self, master=None, title="Window", geometry="800x600"):
        self.root = tk.Toplevel(master) if master else tk.Tk()
        self.root.title(title)
        self.root.geometry(geometry)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.master = master  # 保存对主窗口的引用

        # 添加对主窗口关闭事件的监听
        if master:
            master.bind('<Destroy>', self._on_master_destroy)

    def _on_master_destroy(self, event):
        """主窗口关闭时的处理"""
        if event.widget == self.master:
            try:
                # 调用资源清理
                self._cleanup()
                # 销毁当前窗口
                if self.root.winfo_exists():
                    self.root.destroy()
            except Exception as e:
                print(f"主窗口关闭时清理资源出错: {e}")

    def _cleanup(self):
        """资源清理方法，子类需要重写此方法"""
        pass
    def on_closing(self):
        """关闭窗口时的处理，子类需要重写此方法"""
        self.root.destroy()

    def center_window(self):
        """使窗口在屏幕中居中显示"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
