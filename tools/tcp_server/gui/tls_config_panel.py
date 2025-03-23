#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import tkinter as tk
from tkinter import ttk, filedialog


class TlsConfigPanel(ttk.Frame):
    """TLS证书配置面板"""

    def __init__(self, parent, cert_base_dir):
        super().__init__(parent)
        self.cert_base_dir = cert_base_dir

        # 初始化变量
        self.cert_path_var = tk.StringVar()
        self.key_path_var = tk.StringVar()

        self._create_widgets()

    def _create_widgets(self):
        # 证书文件路径
        cert_frame = ttk.Frame(self)
        cert_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(cert_frame, text="证书文件:").grid(row=0, column=0, sticky=tk.W, padx=5)
        cert_entry = ttk.Entry(cert_frame, textvariable=self.cert_path_var, width=40)
        cert_entry.grid(row=0, column=1, sticky=tk.W + tk.E, padx=5)

        cert_browse = ttk.Button(cert_frame, text="浏览...", command=self._browse_cert_file)
        cert_browse.grid(row=0, column=2, padx=5)

        # 密钥文件路径
        key_frame = ttk.Frame(self)
        key_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(key_frame, text="密钥文件:").grid(row=0, column=0, sticky=tk.W, padx=5)
        key_entry = ttk.Entry(key_frame, textvariable=self.key_path_var, width=40)
        key_entry.grid(row=0, column=1, sticky=tk.W + tk.E, padx=5)

        key_browse = ttk.Button(key_frame, text="浏览...", command=self._browse_key_file)
        key_browse.grid(row=0, column=2, padx=5)

    def _browse_cert_file(self):
        """浏览选择证书文件"""
        filename = filedialog.askopenfilename(
            title="选择证书文件",
            initialdir=self.cert_base_dir,
            filetypes=[
                ("证书文件", "*.crt;*.pem;*.cert"),
                ("所有文件", "*.*")
            ]
        )

        if filename:
            self.cert_path_var.set(filename)

    def _browse_key_file(self):
        """浏览选择密钥文件"""
        filename = filedialog.askopenfilename(
            title="选择密钥文件",
            initialdir=self.cert_base_dir,
            filetypes=[
                ("密钥文件", "*.key;*.pem"),
                ("所有文件", "*.*")
            ]
        )

        if filename:
            self.key_path_var.set(filename)
