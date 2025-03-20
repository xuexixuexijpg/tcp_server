#!/usr/bin/env python
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk
from datetime import datetime


class LogPanel(ttk.Frame):
    """日志显示面板"""

    def __init__(self, parent):
        super().__init__(parent)
        self._create_widgets()

    def _create_widgets(self):
        # 日志区域标题
        label_frame = ttk.LabelFrame(self, text="日志")
        label_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 滚动条
        scrollbar = ttk.Scrollbar(label_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 日志文本区域
        self.log_area = tk.Text(label_frame, height=8, width=60, state=tk.DISABLED)
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 连接滚动条
        self.log_area.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.log_area.yview)

        # 使用标签设置不同级别日志的颜色
        self.log_area.tag_config('INFO', foreground='black')
        self.log_area.tag_config('WARNING', foreground='orange')
        self.log_area.tag_config('ERROR', foreground='red')

    def log(self, message, level="INFO"):
        """添加日志消息"""
        if level not in ["INFO", "WARNING", "ERROR"]:
            level = "INFO"

        # 获取当前时间
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"[{timestamp}] [{level}] {message}\n"

        # 添加到日志区域
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, log_line, level)
        self.log_area.see(tk.END)  # 滚动到最新消息
        self.log_area.config(state=tk.DISABLED)

        # 打印到控制台
        print(f"[{level}] {message}")
