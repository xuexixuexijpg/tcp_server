#!/usr/bin/env python
# -*- coding: utf-8 -*-

import tkinter as tk
from threading import Lock
from tkinter import ttk
from datetime import datetime


class LogPanel(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self._create_widgets()

    def _create_widgets(self):
        # 创建文本框和滚动条
        self.log_text = tk.Text(self, wrap=tk.WORD, height=10)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)

        # 使用网格布局
        self.log_text.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        # 配置网格权重
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # 禁用文本框编辑
        self.log_text.configure(state="disabled")

        # 设置标签绑定，以处理自动滚动
        self.log_text.tag_configure("INFO", foreground="black")
        self.log_text.tag_configure("WARNING", foreground="orange")
        self.log_text.tag_configure("ERROR", foreground="red")
        self.log_text.tag_configure("DEBUG", foreground="gray")

    def add_log(self, message, level="INFO"):
        """添加日志消息"""
        def _do_add_log():
            try:
                if self.log_text.winfo_exists():
                    self.log_text.configure(state="normal")
                    current_time = datetime.now().strftime("%H:%M:%S")
                    log_text = f"[{current_time}] [{level}] {message}\n"
                    self.log_text.insert(tk.END, log_text)
                    self.log_text.configure(state="disabled")
                    self.log_text.see(tk.END)
            except tk.TclError:
                pass  # 忽略窗口已关闭的错误

            # 在主线程中执行UI更新
        if self.winfo_exists():
            self.after(0, _do_add_log)

    def clear(self):
        """清空日志"""
        self.log_text.configure(state="normal")
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state="disabled")