#!/usr/bin/env python
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, messagebox


class ClientManagerPanel(ttk.Frame):
    """客户端管理面板"""

    def __init__(self, parent, server_window):
        super().__init__(parent)
        self.server_window = server_window
        self._create_widgets()

    def _create_widgets(self):
        # 客户端列表框
        list_frame = ttk.LabelFrame(self, text="已连接客户端")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 创建带滚动条的列表框
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 创建列表框
        self.clients_listbox = tk.Listbox(list_frame, height=15, width=50)
        self.clients_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 连接滚动条
        self.clients_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.clients_listbox.yview)

        # 按钮区域
        button_frame = ttk.Frame(self)
        button_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(button_frame, text="发送消息", command=self._open_message_dialog).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="断开连接", command=self._disconnect_client).pack(side=tk.LEFT, padx=5)

    def add_client(self, client_id, address):
        """添加客户端到列表"""
        self.clients_listbox.insert(tk.END, client_id)

    def remove_client(self, client_id):
        """从列表移除客户端"""
        for i in range(self.clients_listbox.size()):
            if self.clients_listbox.get(i) == client_id:
                self.clients_listbox.delete(i)
                break

    def get_selected_client(self):
        """获取当前选中的客户端"""
        selected = self.clients_listbox.curselection()
        if not selected:
            messagebox.showinfo("提示", "请先选择客户端")
            return None

        return self.clients_listbox.get(selected[0])

    def _open_message_dialog(self):
        """打开消息发送对话框"""
        client_id = self.get_selected_client()
        if client_id:
            # 切换到消息选项卡并设置选中的客户端
            self.server_window.messaging_panel.set_selected_client(client_id)

    def _disconnect_client(self):
        """断开选中的客户端连接"""
        client_id = self.get_selected_client()
        if client_id and messagebox.askyesno("确认", f"确定要断开客户端 {client_id} 的连接吗?"):
            self.server_window.remove_client(client_id)
