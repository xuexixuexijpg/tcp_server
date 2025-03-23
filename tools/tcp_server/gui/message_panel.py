#!/usr/bin/env python
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk
from datetime import datetime


class MessagingPanel(ttk.Frame):
    """消息发送和接收面板"""

    def __init__(self, parent, server_window):
        super().__init__(parent)
        self.server_window = server_window
        self.selected_client = None
        self._create_widgets()

    def _create_widgets(self):
        # 消息显示区域
        display_frame = ttk.LabelFrame(self, text="消息记录")
        display_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(display_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 消息显示区域
        self.receive_area = tk.Text(display_frame, height=15, width=60, state=tk.DISABLED)
        self.receive_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 连接滚动条
        self.receive_area.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.receive_area.yview)

        # 消息发送区域
        send_frame = ttk.LabelFrame(self, text="发送消息")
        send_frame.pack(fill=tk.BOTH, expand=False, padx=10, pady=5)

        # 客户端选择
        client_frame = ttk.Frame(send_frame)
        client_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(client_frame, text="发送给:").pack(side=tk.LEFT, padx=5)

        self.client_var = tk.StringVar(value="所有客户端")
        self.client_combo = ttk.Combobox(client_frame, textvariable=self.client_var)
        self.client_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # 消息输入区域
        self.send_area = tk.Text(send_frame, height=5, width=60)
        self.send_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 发送按钮
        button_frame = ttk.Frame(send_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)

        self.send_button = ttk.Button(button_frame, text="发送", command=self._send_message)
        self.send_button.pack(side=tk.RIGHT, padx=5)

    def receive_message(self, message):
        """显示接收到的消息"""
        self.receive_area.config(state=tk.NORMAL)
        self.receive_area.insert(tk.END, message + "\n")
        self.receive_area.see(tk.END)  # 滚动到最新消息
        self.receive_area.config(state=tk.DISABLED)

    def set_selected_client(self, client_id):
        """设置选择的客户端"""
        self.selected_client = client_id
        self.client_var.set(client_id)

        # 更新下拉列表
        self._update_client_list()

    def _update_client_list(self):
        """更新客户端下拉列表"""
        clients = ["所有客户端"] + list(self.server_window.client_sockets.keys())
        self.client_combo['values'] = clients

    def _send_message(self):
        """发送消息"""
        message = self.send_area.get("1.0", tk.END).strip()
        if not message:
            return

        target = self.client_var.get()
        sent = False

        if target == "所有客户端":
            # 发送给所有客户端
            sent = self.server_window.send_to_all_clients(message)
        else:
            # 发送给特定客户端
            sent = self.server_window.send_to_client(target, message)

        if sent:
            # 清空发送区域
            self.send_area.delete("1.0", tk.END)
