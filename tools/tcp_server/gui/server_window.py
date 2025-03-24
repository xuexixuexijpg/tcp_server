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

from core.base_window import BaseWindow
from security.generate_tls_cert import generate_tls_cert

from .certificate_dialog import CertificateGenerationDialog
from .tls_config_panel import TlsConfigPanel
from .client_manager_panel import ClientManagerPanel
from .message_panel import MessagingPanel
from .log_panel import LogPanel
from ..core.server import TLSServer,TCPServer


class ServerWindow(BaseWindow):
    def __init__(self,master = None,window_number=None):
        self.window_number = window_number
        title = "TCP服务器"
        if window_number is not None:
            title = f"{title}-{window_number}"
        super().__init__(master=master, title=title, geometry="900x600")
        # 服务器相关变量
        self.server = None
        self.server_thread = None
        self.client_sockets = {}  # {client_id: (socket, address)}

        # 创建证书目录
        self.cert_base_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "certs")
        os.makedirs(self.cert_base_dir, exist_ok=True)
        # 添加对主窗口关闭事件的监听
        if master:
            master.bind('<Destroy>', self._on_master_destroy)
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
        self.log_panel.pack(fill=tk.BOTH, expand=False, pady=(10, 0))

    def _create_server_config(self, parent):
        """创建服务器配置面板"""
        config_frame = ttk.LabelFrame(parent, text="服务器设置")
        config_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.server_type = tk.StringVar(value="普通TCP")
        # IP地址和端口设置
        ttk.Label(config_frame, text="IP地址:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.ip_var = tk.StringVar()

        # 获取本地IP列表
        local_ips = self._get_local_ips()
        self.ip_combo = ttk.Combobox(config_frame, textvariable=self.ip_var, values=local_ips)

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
            self.tls_frame.grid(row=2, column=0, columnspan=4, sticky=tk.W + tk.E, padx=5, pady=10)
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
        prefix = f"[窗口-{self.window_number}] " if self.window_number else ""
        self.log_panel.log(f"{prefix}{message}", level)

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

    def _generate_certificate_for_ip(self):
        selected_ip = self.ip_var.get()
        if not selected_ip:
            messagebox.showerror("错误", "请先选择IP地址")
            return
        # 显示证书生成对话框
        # 使用主窗口或当前窗口作为父窗口
        # parent = self.master if self.master else self.root
        cert_dialog = CertificateGenerationDialog(self.root, selected_ip)
        # Make the dialog stay on top of ServerWindow
        cert_dialog.transient(self.root)
        cert_dialog.grab_set()
        self.root.wait_window(cert_dialog)
        # 检查用户是否确认生成证书
        if not hasattr(cert_dialog, 'result') or not cert_dialog.result:
            return

        # 如果用户关闭了对话框
        if not hasattr(cert_dialog, 'generate_client_cert'):
            return

        # 获取是否生成客户端证书的选项
        generate_client_cert = cert_dialog.generate_client_cert.get()

        # 设置证书目录和路径
        cert_dir = os.path.join(self.cert_base_dir, selected_ip)
        os.makedirs(cert_dir, exist_ok=True)

        cert_path = os.path.join(cert_dir, f"{selected_ip}.crt")
        key_path = os.path.join(cert_dir, f"{selected_ip}.key")

        # 客户端证书路径（如果需要生成）
        client_cert_path = os.path.join(cert_dir, "client.crt") if generate_client_cert else None
        client_key_path = os.path.join(cert_dir, "client.key") if generate_client_cert else None
        ca_cert_path = os.path.join(cert_dir, "ca.crt")
        ca_key_path = os.path.join(cert_dir, "ca.key")

        # 创建并显示进度对话框
        progress_dialog = tk.Toplevel(self.root)
        progress_dialog.title("生成证书")
        progress_dialog.transient(self.root)
        progress_dialog.grab_set()
        progress_dialog.resizable(False, False)
        # 添加以下代码使弹窗居中
        progress_dialog.update_idletasks()
        window_width = 300  # 设置窗口宽度
        window_height = 100  # 设置窗口高度
        x = (self.root.winfo_screenwidth() - window_width) // 2
        y = (self.root.winfo_screenheight() - window_height) // 2
        progress_dialog.geometry(f"{window_width}x{window_height}+{x}+{y}")

        progress_label = tk.Label(progress_dialog, text=f"正在为 {selected_ip} 生成证书...", font=("Arial", 10))
        progress_label.pack(pady=(15, 5))

        detail_label = tk.Label(progress_dialog, text="初始化...", font=("Arial", 9))
        detail_label.pack(pady=5)

        progress_bar = ttk.Progressbar(progress_dialog, mode="indeterminate")
        progress_bar.pack(fill=tk.X, padx=20, pady=10)
        progress_bar.start()

        # 更新进度信息的函数
        def update_progress(message):
            detail_label.config(text=message)

        # 证书生成线程
        def generate_cert_thread():
            try:
                update_progress("正在生成证书...")

                # 生成证书
                result = generate_tls_cert(
                    hostname=selected_ip,
                    cert_path=cert_path,
                    key_path=key_path,
                    generate_client_cert=generate_client_cert,
                    client_cert_path=client_cert_path,
                    client_key_path=client_key_path,
                    ca_cert_path=ca_cert_path,
                    ca_key_path=ca_key_path
                )

                update_progress("证书生成完成！")

                # 在主线程中更新UI
                self.root.after(500, lambda: finish_generation(result))

            except Exception as b:
                # 修复这一行 - 将 e 作为 lambda 的默认参数传递
                self.root.after(0, lambda e = b: handle_error(str(e)))

        # 完成生成后的处理
        def finish_generation(result):
            progress_dialog.destroy()

            # 更新证书路径
            self.cert_path_var.set(result["cert_path"])
            self.key_path_var.set(result["key_path"])

            # 保存客户端证书路径（如果有）
            if generate_client_cert:
                self.client_cert_path = result.get("client_cert_path", "")
                self.client_key_path = result.get("client_key_path", "")
                self.ca_cert_path = result.get("ca_cert_path", "")

                message = f"证书已成功生成！\n\n服务器证书: {result['cert_path']}\n服务器私钥: {result['key_path']}\n\n"
                message += f"同时生成了客户端证书:\n客户端证书: {result['client_cert_path']}\n客户端私钥: {result['client_key_path']}\nCA证书: {result['ca_cert_path']}"

                messagebox.showinfo("成功", message)
            else:
                messagebox.showinfo("成功",
                                    f"证书已成功生成！\n\n证书路径: {result['cert_path']}\n私钥路径: {result['key_path']}")

        # 错误处理
        def handle_error(error_msg):
            progress_dialog.destroy()
            messagebox.showerror("错误", f"生成证书时发生错误：\n{error_msg}")

        # 启动证书生成线程
        threading.Thread(target=generate_cert_thread, daemon=True).start()
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
            # 记录日志（在UI销毁前）
            try:
                self.log("正在停止服务器...")
            except:
                pass

            # 停止服务器
            self._cleanup()

            # 清理资源
            self.server = None
            self.server_thread = None

            # 如果UI组件仍然存在，更新状态
            try:
                if self.root.winfo_exists():
                    self.start_button.config(state=tk.NORMAL)
                    self.stop_button.config(state=tk.DISABLED)
                    self.ip_combo.config(state=tk.NORMAL)
                    self.log("服务器已停止")
            except:
                pass
            self.log("服务器已停止")
        except Exception as e:
            try:
                if self.root.winfo_exists():
                    self.log(f"停止服务器时出错: {str(e)}", "ERROR")
            except:
                print(f"停止服务器时出错: {str(e)}")

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
            # 首先打印客户端ID和客户端套接字字典，帮助调试
        print(f"正在尝试发送消息到客户端: {client_id}")
        print(f"客户端套接字字典键: {list(self.client_sockets.keys())}")

        # 确认客户端ID存在
        if client_id not in self.client_sockets:
            self.log(f"错误：找不到客户端 {client_id}")
            return False

        # 获取套接字并验证类型
        client_socket, address = self.client_sockets[client_id]
        print(f"客户端套接字类型: {type(client_socket)}")

        # 检查是否为有效的套接字对象
        import socket
        import ssl
        if not isinstance(client_socket, (socket.socket, ssl.SSLSocket)):
            self.log(f"错误：客户端 {client_id} 的连接对象不是有效的套接字，而是 {type(client_socket)}")
            self.remove_client(client_id)
            return False

        # 发送消息
        try:
            # 根据数据类型处理
            if isinstance(message, bytes):
                data_to_send = message
            else:
                data_to_send = message.encode('utf-8')

            client_socket.sendall(data_to_send)
            return True
        except Exception as e:
            self.log(f"发送消息到 {client_id} 失败: {e}")
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
                # 先发送断开连接的消息给客户端
                disconnect_message = json.dumps({
                    "type": "disconnect",
                    "message": "Server closing connection"
                })
                client_socket.sendall(disconnect_message.encode('utf-8'))
                # 等待一小段时间让客户端处理消息
                time.sleep(0.1)
                # 关闭连接
                client_socket.shutdown(socket.SHUT_RDWR)
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
        """重写父类的关闭处理方法"""
        window_id = f"窗口-{self.window_number}" if self.window_number else "窗口"
        if self.server:
            if not messagebox.askokcancel("退出", f"{window_id}服务器正在运行，确定要关闭吗?"):
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

    def _cleanup(self):
        """清理资源"""
        try:
            # 停止服务器
            if self.server:
                self.server.stop()
                self.server = None

            # 等待服务器线程结束
            if self.server_thread and self.server_thread.is_alive():
                self.server_thread.join(2.0)
                self.server_thread = None

            # 断开所有客户端连接
            for client_id in list(self.client_sockets.keys()):
                try:
                    client_socket, _ = self.client_sockets[client_id]
                    client_socket.close()
                except:
                    pass

            # 清理资源
            self.client_sockets.clear()

        except Exception as e:
            print(f"清理资源时出错: {e}")

    def _on_master_destroy(self, event):
        """主窗口关闭时的处理"""
        if event.widget == self.master:
            try:
                # 直接调用资源清理，不涉及UI更新
                self._cleanup()
            except Exception as e:
                print(f"主窗口关闭时清理资源出错: {e}")