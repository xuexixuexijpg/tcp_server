#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import threading
import ssl
import json
import time
from datetime import datetime
import ipaddress

from .base_window import BaseWindow
from .certificate_dialog import CertificateGenerationDialog
from .tls_config_panel import TlsConfigPanel
from .client_manager_panel import ClientManagerPanel
from .message_panel import MessagingPanel
from .log_panel import LogPanel
from server.server import TCPServer, TLSServer
from security.generate_tls_cert import generate_tls_cert

class ServerWindow(BaseWindow):
    def __init__(self):
        super().__init__(title="TCP服务器", geometry="900x600")

        # 服务器相关变量
        self.server = None
        self.server_thread = None
        self.client_sockets = {}  # {client_id: (socket, address)}

        # 创建证书目录
        self.cert_base_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "certs")
        os.makedirs(self.cert_base_dir, exist_ok=True)

        # 窗口初始化
        self._create_widgets()
        self.center_window()

    def _create_widgets(self):
        """创建GUI组件"""
        # 创建主框架
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 创建选项卡控件
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        # 创建三个选项卡页面
        server_tab = ttk.Frame(notebook)
        clients_tab = ttk.Frame(notebook)
        messages_tab = ttk.Frame(notebook)

        notebook.add(server_tab, text="服务器")
        notebook.add(clients_tab, text="客户端")
        notebook.add(messages_tab, text="消息")

        # 服务器选项卡 - 配置面板
        self._create_server_config(server_tab)

        # 客户端选项卡 - 客户端管理面板
        self.client_manager = ClientManagerPanel(clients_tab, self)
        self.client_manager.pack(fill=tk.BOTH, expand=True)

        # 消息选项卡 - 消息面板
        self.messaging_panel = MessagingPanel(messages_tab, self)
        self.messaging_panel.pack(fill=tk.BOTH, expand=True)

        # 日志面板 (所有选项卡下方)
        self.log_panel = LogPanel(main_frame)
        self.log_panel.pack(fill=tk.X, expand=False, pady=(10, 0))

    def _create_server_config(self, parent):
        """创建服务器配置面板"""
        config_frame = ttk.LabelFrame(parent, text="服务器设置")
        config_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # IP地址和端口设置
        ttk.Label(config_frame, text="IP地址:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.ip_var = tk.StringVar()

        # 获取本地IP列表
        local_ips = self._get_local_ips()
        self.ip_combo = ttk.Combobox(config_frame, textvariable=self.ip_var, values=local_ips)
        # 服务器类型选择 - 提前定义
        self.server_type = tk.StringVar(value="普通TCP")

        self.ip_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        if local_ips:
            self.ip_combo.current(0)
            self._on_ip_selected(None)  # 触发IP选择事件

        self.ip_combo.bind("<<ComboboxSelected>>", self._on_ip_selected)

        ttk.Label(config_frame, text="端口:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.port_var = tk.StringVar(value="8080")
        port_entry = ttk.Entry(config_frame, textvariable=self.port_var, width=10)
        port_entry.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)

        # 服务器类型选择
        ttk.Label(config_frame, text="服务器类型:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.server_type = tk.StringVar(value="普通TCP")

        tcp_radio = ttk.Radiobutton(config_frame, text="普通TCP", variable=self.server_type, value="普通TCP",
                                    command=self._on_server_type_changed)
        tcp_radio.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

        tls_radio = ttk.Radiobutton(config_frame, text="TLS加密", variable=self.server_type, value="TLS加密",
                                    command=self._on_server_type_changed)
        tls_radio.grid(row=1, column=2, columnspan=2, sticky=tk.W, padx=5, pady=5)

        # TLS设置区域
        self.tls_frame = ttk.LabelFrame(config_frame, text="TLS设置")
        self.tls_frame.grid(row=2, column=0, columnspan=4, sticky=tk.W + tk.E, padx=5, pady=10)
        self.tls_frame.grid_remove()  # 默认隐藏

        # 添加TLS配置面板
        self.tls_config = TlsConfigPanel(self.tls_frame, self.cert_base_dir)
        self.tls_config.pack(fill=tk.BOTH, expand=True)

        # 添加为选择的IP生成证书的按钮
        self.gen_cert_button = ttk.Button(self.tls_frame, text="为当前IP生成证书",
                                          command=self._generate_certificate_for_ip)
        self.gen_cert_button.pack(pady=10)

        # 证书文件路径
        self.cert_path_var = self.tls_config.cert_path_var
        self.key_path_var = self.tls_config.key_path_var

        # 控制按钮
        button_frame = ttk.Frame(config_frame)
        button_frame.grid(row=3, column=0, columnspan=4, pady=10)

        self.start_button = ttk.Button(button_frame, text="启动服务器", command=self.start_server)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(button_frame, text="停止服务器", command=self.stop_server, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

    def _toggle_tls_fields(self, show=False):
        """显示或隐藏TLS相关设置"""
        if show:
            self.tls_frame.grid()
            # 更新证书路径
            self._update_cert_paths_for_ip()
        else:
            self.tls_frame.grid_remove()

    def _get_local_ips(self):
        """获取本地所有IP地址"""
        ips = []

        # 首先添加localhost
        ips.append("127.0.0.1")
        ips.append("0.0.0.0")  # 所有接口

        try:
            # 获取主机名
            hostname = socket.gethostname()

            # 尝试获取与主机名关联的IP
            try:
                host_ip = socket.gethostbyname(hostname)
                if host_ip not in ips:
                    ips.append(host_ip)
            except:
                pass

            # 获取所有网络接口的IP
            for iface in socket.getaddrinfo(host=socket.gethostname(), port=None, family=socket.AF_INET):
                ip = iface[4][0]
                if ip not in ips:
                    ips.append(ip)
        except:
            pass

        # 非Windows系统上可以使用netifaces获取更多网络接口
        try:
            import netifaces
            for interface in netifaces.interfaces():
                try:
                    addresses = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addresses:
                        for link in addresses[netifaces.AF_INET]:
                            ip = link['addr']
                            if ip not in ips and ip != '127.0.0.1':
                                ips.append(ip)
                except:
                    pass
        except ImportError:
            pass

        return ips

    def log(self, message, level="INFO"):
        """记录日志"""
        self.log_panel.log(message, level)

    def _on_ip_selected(self, event):
        """当IP选择变化时更新证书路径"""
        if self.server_type.get() == "TLS加密":
            self._update_cert_paths_for_ip()

    def _on_server_type_changed(self):
        """处理服务器类型变更"""
        server_type = self.server_type.get()
        if server_type == "TLS加密":
            self._toggle_tls_fields(True)
        else:
            self._toggle_tls_fields(False)

    def _update_cert_paths_for_ip(self):
        """根据当前选择的IP更新证书路径"""
        # 获取当前IP
        ip = self.ip_var.get()
        if not ip or ip == "0.0.0.0":
            ip = "localhost"  # 默认使用localhost证书

        # 计算证书路径
        cert_file = os.path.join(self.cert_base_dir, f"{ip}.crt")
        key_file = os.path.join(self.cert_base_dir, f"{ip}.key")

        # 如果证书存在，设置路径变量
        if os.path.exists(cert_file) and os.path.exists(key_file):
            self.cert_path_var.set(cert_file)
            self.key_path_var.set(key_file)
        else:
            self.cert_path_var.set("")
            self.key_path_var.set("")
            self.log(f"没有找到IP {ip}的证书，请生成或选择证书", "WARNING")

    def _generate_certificate_for_ip(self, ip_address=None):
        """为当前选择的IP生成新的证书"""
        if not ip_address:
            ip_address = self.ip_var.get()

        if not ip_address:
            messagebox.showerror("错误", "请先选择一个IP地址")
            return
        # 禁用生成按钮，防止重复点击
        self.gen_cert_button.config(state=tk.DISABLED)
        # 在状态栏显示进度
        self.log(f"正在为 {ip_address} 生成证书，请稍候...")
        # 创建证书生成对话框
        dialog = CertificateGenerationDialog(self.root, ip_address)

        # 设置超时处理
        timeout_id = self.root.after(30000, lambda: self._cert_gen_timeout(dialog.window))
            # 定义回调函数
        def on_success(cert_file, key_file):
            # 取消超时
            self.root.after_cancel(timeout_id)

            # 关闭进度窗口
            self.root.after(0, dialog.close)

            # 更新UI
            self.cert_path_var.set(cert_file)
            self.key_path_var.set(key_file)
            self.gen_cert_button.config(state=tk.NORMAL)

            # 更新日志
            self.log(f"已为IP {ip_address} 生成TLS证书和私钥")

            # 显示成功消息
            messagebox.showinfo("证书生成成功",
                                f"TLS证书已保存到 {os.path.abspath(cert_file)}\n私钥已保存到 {os.path.abspath(key_file)}")
        def on_error(error_message):
            # 取消超时
            self.root.after_cancel(timeout_id)

            # 关闭进度窗口
            self.root.after(0, dialog.close)

            # 恢复UI状态
            self.gen_cert_button.config(state=tk.NORMAL)

            # 更新日志
            self.log(f"生成TLS证书失败: {error_message}")

            # 显示错误消息
            messagebox.showerror("错误", f"生成TLS证书失败: {error_message}")

        def on_progress(message):
            # 更新进度信息
            self.root.after(0, lambda: dialog.update_progress(message))
            # 启动证书生成线程
        from security.cert_generator import generate_cert_for_ip
        generate_cert_for_ip(
            ip_address,
            self.cert_base_dir,
            on_success=on_success,
            on_error=on_error,
            on_progress=on_progress
        )
    def _cert_gen_timeout(self, window):
        window.destroy()
        self.gen_cert_button.config(state=tk.NORMAL)
        self.log("生成证书超时，请重试")
        messagebox.showerror("超时", "生成证书操作超时，请重试")

    def start_server(self):
        """启动服务器"""
        try:
            if self.server:
                self.log("服务器已经在运行中", "WARNING")
                return

            ip = self.ip_var.get()
            try:
                port = int(self.port_var.get())
                if port < 1 or port > 65535:
                    raise ValueError("端口应为1-65535之间的数字")
            except ValueError as ve:
                self.log(f"端口设置错误: {str(ve)}", "ERROR")
                return

            server_type = self.server_type.get()

            # 根据服务器类型选择TLS或TCP
            if server_type == "TLS加密":
                cert_file = self.cert_path_var.get()
                key_file = self.key_path_var.get()

                if not cert_file or not os.path.exists(cert_file):
                    self.log("TLS证书文件不存在", "ERROR")
                    return

                if not key_file or not os.path.exists(key_file):
                    self.log("TLS密钥文件不存在", "ERROR")
                    return

                # 创建SSL上下文
                try:
                    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

                    self.server = TLSServer(ip, port, ssl_context)
                except Exception as e:
                    self.log(f"加载TLS证书失败: {str(e)}", "ERROR")
                    return
            else:
                self.server = TCPServer(ip, port)

            # 设置回调函数
            self.server.client_connected_callback = self.on_client_connected
            self.server.client_disconnected_callback = self.on_client_disconnected
            self.server.message_received_callback = self.on_message_received

            # 在后台线程启动服务器
            self.server_thread = threading.Thread(target=self.server.start, daemon=True)
            self.server_thread.start()

            # 更新UI状态
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.ip_combo.config(state=tk.DISABLED)

            # 记录日志
            server_mode = "TLS加密" if server_type == "TLS加密" else "普通TCP"
            self.log(f"服务器已启动 ({server_mode})，监听 {ip}:{port}")

        except Exception as e:
            self.log(f"启动服务器失败: {str(e)}", "ERROR")

    def stop_server(self):
        """停止服务器"""
        if not self.server:
            return

        try:
            # 停止服务器
            self.server.stop()

            # 等待服务器线程结束
            if self.server_thread and self.server_thread.is_alive():
                self.server_thread.join(2.0)  # 等待最多2秒

            # 断开所有客户端连接
            clients = list(self.client_sockets.keys())
            for client_id in clients:
                self.remove_client(client_id, notify=False)

            # 清理资源
            self.server = None
            self.server_thread = None

            # 更新UI状态
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.ip_combo.config(state=tk.NORMAL)

            self.log("服务器已停止")
        except Exception as e:
            self.log(f"停止服务器时出错: {str(e)}", "ERROR")

    def on_client_connected(self, client_socket, address):
        """当客户端连接时被调用"""
        client_id = f"{address[0]}:{address[1]}"
        self.client_sockets[client_id] = (client_socket, address)

        # 更新客户端列表
        self.client_manager.add_client(client_id, address)

        # 记录日志
        self.log(f"客户端 {client_id} 已连接")

    def on_client_disconnected(self, client_socket):
        """当客户端断开连接时被调用"""
        for client_id, (sock, _) in list(self.client_sockets.items()):
            if sock == client_socket:
                self.remove_client(client_id)
                break

    def on_message_received(self, client_socket, address, data):
        """当收到客户端消息时被调用"""
        client_id = f"{address[0]}:{address[1]}"

        try:
            # 尝试解码为字符串
            message = data.decode('utf-8')

            # 记录消息
            now = datetime.now().strftime("%H:%M:%S")
            self.messaging_panel.receive_message(f"[{now}] {client_id}: {message}")

        except UnicodeDecodeError:
            # 处理二进制数据
            self.log(f"收到来自 {client_id} 的二进制数据，长度: {len(data)} 字节", "INFO")

    def send_to_client(self, client_id, message):
        """发送消息到指定客户端"""
        if client_id not in self.client_sockets:
            self.log(f"客户端 {client_id} 不存在", "ERROR")
            return False

        if not message:
            return False

        try:
            client_socket, _ = self.client_sockets[client_id]
            #  直接发送二进制数据，不进行编码
            if isinstance(message, str):
                # 兼容处理，如果输入是字符串，转换为bytes
                binary_data = message.encode('utf-8')
            client_socket.sendall(message)
            # 记录日志
            now = datetime.now().strftime("%H:%M:%S")
            self.messaging_panel.receive_message(f"[{now}] 发送到 {client_id}: {message}")

            return True

        except Exception as e:
            self.log(f"发送消息到 {client_id} 失败: {str(e)}", "ERROR")

            # 如果是连接断开，删除客户端
            if isinstance(e, (ConnectionResetError, BrokenPipeError)):
                self.remove_client(client_id)

            return False

    def send_to_all_clients(self, message):
        """发送消息到所有客户端"""
        if not self.client_sockets:
            self.log("没有已连接的客户端", "WARNING")
            return False

        if not message:
            return False

        success = False
        for client_id in list(self.client_sockets.keys()):
            if self.send_to_client(client_id, message):
                success = True

        return success

    def remove_client(self, client_id, notify=True):
        """从列表中移除客户端"""
        if client_id not in self.client_sockets:
            return

        try:
            # 获取客户端socket并关闭连接
            client_socket, _ = self.client_sockets[client_id]

            try:
                client_socket.close()
            except:
                pass

            # 从字典中删除
            del self.client_sockets[client_id]

            # 更新客户端列表
            self.client_manager.remove_client(client_id)

            # 记录日志
            if notify:
                self.log(f"客户端 {client_id} 已断开连接")

        except Exception as e:
            self.log(f"移除客户端 {client_id} 时出错: {str(e)}", "ERROR")

    def on_closing(self):
        """关闭窗口时的处理"""
        if self.server:
            if not messagebox.askokcancel("退出", "服务器正在运行，确定要关闭吗?"):
                return
            # 停止服务器
            self.stop_server()

        self.root.destroy()

    def center_window(self):
        """使窗口在屏幕中居中显示"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
