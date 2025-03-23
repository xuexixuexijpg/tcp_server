#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog


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
        # 添加插件按钮
        ttk.Button(
            button_frame,
            text="选择插件",
            command=self._select_plugin
        ).pack(side=tk.LEFT, padx=5)

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

    def _select_plugin(self):
        """为选中的客户端选择插件"""
        client_id = self.get_selected_client()
        if not client_id:
            return

        # 打开文件选择对话框
        plugin_path = filedialog.askopenfilename(
            title="选择插件文件",
            filetypes=[("Python文件", "*.py")],
            initialdir=os.path.join(os.path.dirname(__file__), "../plugins")
        )

        if plugin_path:
            # 加载插件
            plugin_name = self.server_window.plugin_manager.load_plugin(plugin_path)
            if plugin_name:
                # 设置客户端插件
                if self.server_window.plugin_manager.set_client_plugin(client_id, plugin_name):
                    messagebox.showinfo("成功", f"已为客户端 {client_id} 设置插件 {plugin_name}")
                else:
                    messagebox.showerror("错误", "设置插件失败")