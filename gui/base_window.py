#!/usr/bin/env python
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import messagebox


class BaseWindow:
    """窗口基类"""

    def __init__(self, title="TCP服务器", geometry="900x600"):
        self.root = tk.Tk()
        self.root.title(title)
        self.root.geometry(geometry)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        """窗口关闭处理"""
        if messagebox.askokcancel("退出", "确定要关闭程序吗?"):
            self.root.destroy()
