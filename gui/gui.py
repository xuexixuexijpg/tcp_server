import os
import socket
import ssl
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

from server.server import TCPServer, TLSServer


class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("TCP/TLS 服务器")
        # 窗口居中显示
        self.center_window(800, 600)  # 假设窗口大小是800x600
        self.root.resizable(True, True)
        self.server = None
        self.server_thread = None
        self.client_sockets = {}  # {client_address: client_handler}
        # 添加证书基础目录
        # 修改证书基础目录，与generate_tls_cert保持一致
        self.cert_base_dir = os.path.join(os.path.expanduser('~'), 'Documents', 'TCP服务器', 'certificates')
        if not os.path.exists(self.cert_base_dir):
            os.makedirs(self.cert_base_dir)
        # 创建界面元素
        self._create_widgets()

        # 关闭窗口时的处理
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def center_window(self, width, height):
        """将窗口放置在屏幕中央"""
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        x = (screen_width - width) // 2
        y = (screen_height - height) // 2

        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def _create_widgets(self):
        # 创建标签框架
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 创建"服务器配置"标签页
        server_frame = ttk.Frame(notebook)
        notebook.add(server_frame, text="服务器配置")

        # 创建"客户端管理"标签页
        clients_frame = ttk.Frame(notebook)
        notebook.add(clients_frame, text="客户端管理")

        # 创建"消息"标签页
        messages_frame = ttk.Frame(notebook)
        notebook.add(messages_frame, text="消息")

        # 服务器配置页面内容
        # 创建左侧和右侧框架
        left_frame = ttk.LabelFrame(server_frame, text="服务器设置")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        right_frame = ttk.LabelFrame(server_frame, text="服务器日志")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 左侧设置区域 - IP选择
        ip_frame = ttk.Frame(left_frame)
        ip_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(ip_frame, text="IP地址:").pack(side=tk.LEFT)
        self.ip_var = tk.StringVar()
        self.ip_combo = ttk.Combobox(ip_frame, textvariable=self.ip_var, state="readonly")
        self.ip_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 填充IP地址
        local_ips = self._get_local_ips()
        if local_ips:
            self.ip_combo["values"] = local_ips
            self.ip_var.set(local_ips[0])
        # 2. 添加IP地址变更事件处理
        self.ip_combo.bind('<<ComboboxSelected>>', self._on_ip_selected)

        # 服务器类型选择
        server_type_frame = ttk.Frame(left_frame)
        server_type_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(server_type_frame, text="服务器类型:").pack(side=tk.LEFT)
        self.server_type = tk.StringVar(value="TCP")
        ttk.Radiobutton(server_type_frame, text="TCP", variable=self.server_type,
                        value="TCP").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(server_type_frame, text="TLS", variable=self.server_type,
                        value="TLS", command=self._on_server_type_changed).pack(side=tk.LEFT, padx=10)

        # TLS证书配置区
        self.tls_frame = ttk.LabelFrame(left_frame, text="TLS配置")
        self.tls_frame.pack(fill=tk.X, padx=5, pady=5)

        # 生成证书按钮
        # 4. 修改生成证书按钮的回调函数
        self.gen_cert_button = ttk.Button(
            self.tls_frame,
            text="生成自签名证书",
            command=self._generate_certificate_for_ip)
        self.gen_cert_button.pack(fill=tk.X, padx=5, pady=5)

        # 证书路径
        cert_frame = ttk.Frame(self.tls_frame)
        cert_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(cert_frame, text="证书路径:").pack(side=tk.LEFT)
        self.cert_path_var = tk.StringVar()
        ttk.Entry(cert_frame, textvariable=self.cert_path_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(cert_frame, text="浏览",
                   command=self._browse_cert_file).pack(side=tk.RIGHT)

        # 6. 修改私钥路径浏览按钮
        key_frame = ttk.Frame(self.tls_frame)
        key_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(key_frame, text="私钥路径:").pack(side=tk.LEFT)
        self.key_path_var = tk.StringVar()
        ttk.Entry(key_frame, textvariable=self.key_path_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(key_frame, text="浏览",
                   command=self._browse_key_file).pack(side=tk.RIGHT)

        # 默认关闭TLS配置
        self.tls_frame.pack_forget()

        # 端口配置
        port_frame = ttk.Frame(left_frame)
        port_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(port_frame, text="端口:").pack(side=tk.LEFT)
        self.port_var = tk.StringVar(value="8080")
        ttk.Entry(port_frame, textvariable=self.port_var, width=10).pack(side=tk.LEFT)

        # 启动停止按钮
        button_frame = ttk.Frame(left_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=10)

        self.start_button = ttk.Button(button_frame, text="启动服务器",
                                       command=self.start_server)
        self.start_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        self.stop_button = ttk.Button(button_frame, text="停止服务器",
                                      command=self.stop_server, state=tk.DISABLED)
        self.stop_button.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=5)

        # 右侧日志区域
        self.log_area = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD,
                                                  state="disabled", height=20)
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # ===== 客户端管理页面 =====
        # 客户端列表
        clients_list_frame = ttk.LabelFrame(clients_frame, text="已连接的客户端")
        clients_list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.clients_listbox = tk.Listbox(clients_list_frame)
        self.clients_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 客户端操作按钮
        client_buttons_frame = ttk.Frame(clients_list_frame)
        client_buttons_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(client_buttons_frame, text="断开选中客户端",
                   command=lambda: self.remove_client(
                       self.clients_listbox.get(self.clients_listbox.curselection())
                       if self.clients_listbox.curselection() else None
                   )).pack(side=tk.LEFT, padx=5)

        ttk.Button(client_buttons_frame, text="断开所有客户端",
                   command=lambda: [self.remove_client(client)
                                    for client in list(self.client_sockets.keys())]
                   ).pack(side=tk.RIGHT, padx=5)

        # ===== 消息页面 =====
        # 接收区域
        receive_frame = ttk.LabelFrame(messages_frame, text="接收的消息")
        receive_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.receive_area = scrolledtext.ScrolledText(receive_frame, wrap=tk.WORD,
                                                      state="disabled", height=10)
        self.receive_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 发送区域
        send_frame = ttk.LabelFrame(messages_frame, text="发送消息")
        send_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.send_area = scrolledtext.ScrolledText(send_frame, wrap=tk.WORD, height=5)
        self.send_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 发送按钮
        send_btn_frame = ttk.Frame(send_frame)
        send_btn_frame.pack(fill=tk.X, padx=5, pady=5)

        self.send_button = ttk.Button(send_btn_frame, text="发送到选中客户端",
                                      command=lambda: self.send_to_client(
                                          self.clients_listbox.get(self.clients_listbox.curselection())
                                          if self.clients_listbox.curselection() else None
                                      ))
        self.send_button.pack(side=tk.LEFT, padx=5)

        ttk.Button(send_btn_frame, text="发送到所有客户端",
                   command=lambda: [self.send_to_client(client)
                                    for client in self.client_sockets.keys()]
                   ).pack(side=tk.RIGHT, padx=5)

        # 初始时禁用消息发送功能
        self.send_button.config(state=tk.DISABLED)

    def _toggle_tls_fields(self):
        """根据选择的服务器类型切换TLS字段的可见性"""
        if self.server_type.get() == "TLS":
            self.tls_frame.pack(fill=tk.X, padx=5, pady=5)  # 去掉 after 参数
        else:
            self.tls_frame.pack_forget()

    def _get_local_ips(self):
        """获取本地IP地址列表"""
        ips = []
        try:
            # 获取本机名
            hostname = socket.gethostname()
            # 获取本机IP（首选IPv4地址）
            hostname_ip = socket.gethostbyname(hostname)
            ips.append(hostname_ip)

            # 获取所有IP地址
            for ip in socket.gethostbyname_ex(hostname)[2]:
                if ip != hostname_ip and not ip.startswith("127."):
                    ips.append(ip)

            # 添加回环地址
            if "127.0.0.1" not in ips:
                ips.append("127.0.0.1")

            # 添加任意地址
            if "0.0.0.0" not in ips:
                ips.append("0.0.0.0")
        except Exception as e:
            messagebox.showerror("错误", f"获取本地IP地址失败: {str(e)}")
            # 至少提供回环地址
            ips = ["127.0.0.1", "0.0.0.0"]

        return ips

    def log(self, message):
        """添加日志消息到日志区域"""
        self.log_area.config(state="normal")
        self.log_area.insert(tk.END, f"{message}\n")
        self.log_area.see(tk.END)
        self.log_area.config(state="disabled")

    def update_receive_area(self, message, client_address=None):
        """更新接收消息区域"""
        self.receive_area.config(state="normal")
        prefix = f"[{client_address}] " if client_address else ""
        self.receive_area.insert(tk.END, f"{prefix}{message}\n")
        self.receive_area.see(tk.END)
        self.receive_area.config(state="disabled")

    def add_client(self, client_address, client_handler):
        """添加新客户端到列表"""
        if client_address not in self.client_sockets:
            self.client_sockets[client_address] = client_handler
            self.clients_listbox.insert(tk.END, client_address)
            self.log(f"客户端连接: {client_address}")

            # 启用发送按钮
            self.send_button.config(state=tk.NORMAL)

    def remove_client(self, client_address):
        """移除客户端"""
        if not client_address:
            return

        if client_address in self.client_sockets:
            # 关闭连接
            try:
                self.client_sockets[client_address].close()
            except:
                pass

            # 从字典中移除
            del self.client_sockets[client_address]

            # 从UI列表中移除
            for i in range(self.clients_listbox.size()):
                if self.clients_listbox.get(i) == client_address:
                    self.clients_listbox.delete(i)
                    break

            self.log(f"客户端断开连接: {client_address}")

            # 如果没有客户端，禁用发送按钮
            if not self.client_sockets:
                self.send_button.config(state=tk.DISABLED)

    def start_server(self):
        """启动服务器"""
        try:
            # 获取服务器参数
            ip = self.ip_var.get()
            port = int(self.port_var.get())
            server_type = self.server_type.get()

            # 验证端口
            if not (1 <= port <= 65535):
                messagebox.showerror("错误", "无效的端口号。端口必须在1-65535之间。")
                return

            if server_type == "TLS":
                cert_file = self.cert_path_var.get()
                key_file = self.key_path_var.get()

                # 检查证书文件是否存在
                if not os.path.isfile(cert_file):
                    self.log(f"错误: 找不到证书文件: {cert_file}")
                    messagebox.showerror("错误", f"找不到证书文件: {cert_file}")
                    return

                if not os.path.isfile(key_file):
                    self.log(f"错误: 找不到密钥文件: {key_file}")
                    messagebox.showerror("错误", f"找不到密钥文件: {key_file}")
                    return

                # 创建 SSL 上下文
                ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                # 显式配置只支持TLS 1.2和TLS 1.3 (如果您的Python版本支持)
                ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
                # 使用实际的证书文件路径
                ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
                self.server = TLSServer(
                    ssl_context=ssl_context,
                    host=ip,
                    port=port,
                    log_callback=self.log,
                    client_connected_callback=self.add_client,
                    client_disconnected_callback=self.remove_client,
                    message_received_callback=self.update_receive_area
                )

            else:
                self.server = TCPServer(
                    host=ip,
                    port=port,
                    log_callback=self.log,
                    client_connected_callback=self.add_client,
                    client_disconnected_callback=self.remove_client,
                    message_received_callback=self.update_receive_area
                )

            # 在单独的线程中启动服务器
            self.server_thread = threading.Thread(target=self.server.start, daemon=True)
            self.server_thread.start()

            # 更新UI状态
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.ip_combo.config(state=tk.DISABLED)
            self.port_var.set(str(port))  # 确保显示实际使用的端口

            # 记录日志
            self.log(f"服务器已启动: {ip}:{port} ({server_type})")

        except Exception as e:
            messagebox.showerror("错误", f"启动服务器失败: {str(e)}")
            self.log(f"启动服务器失败: {str(e)}")

    def stop_server(self):
        """停止服务器"""
        if self.server:
            try:
                # 关闭所有客户端连接
                for client_address in list(self.client_sockets.keys()):
                    self.remove_client(client_address)

                # 停止服务器
                self.server.stop()
                self.server = None

                # 如果线程在运行，等待结束
                if self.server_thread and self.server_thread.is_alive():
                    self.server_thread.join(timeout=2.0)

                self.server_thread = None

                # 更新UI状态
                self.start_button.config(state=tk.NORMAL)
                self.stop_button.config(state=tk.DISABLED)
                self.ip_combo.config(state="readonly")

                # 清空客户端列表
                self.clients_listbox.delete(0, tk.END)

                # 记录日志
                self.log("服务器已停止")

            except Exception as e:
                messagebox.showerror("错误", f"停止服务器失败: {str(e)}")
                self.log(f"停止服务器失败: {str(e)}")

        else:
            self.log("服务器未在运行")

    def send_to_client(self, client_address=None):
        """发送消息到指定客户端或所有客户端"""
        message = self.send_area.get("1.0", tk.END).strip()

        if not message:
            messagebox.showwarning("警告", "消息内容不能为空")
            return

        if not self.server or not self.server.is_running:
            messagebox.showwarning("警告", "服务器未运行")
            return

        # 发送到特定客户端
        if client_address:
            if client_address in self.client_sockets:
                try:
                    client_handler = self.client_sockets[client_address]
                    client_handler.send_message(message)
                    self.log(f"消息已发送到 {client_address}")
                    self.update_receive_area(f"[发送到 {client_address}] {message}")
                except Exception as e:
                    messagebox.showerror("错误", f"发送消息失败: {str(e)}")
                    self.log(f"发送消息失败: {str(e)}")
            else:
                messagebox.showwarning("警告", f"客户端 {client_address} 不存在或已断开连接")

        # 发送到所有客户端
        else:
            if not self.client_sockets:
                messagebox.showwarning("警告", "没有连接的客户端")
                return

            for addr, client_handler in self.client_sockets.items():
                try:
                    client_handler.send_message(message)
                except Exception as e:
                    self.log(f"发送消息到 {addr} 失败: {str(e)}")

            self.log("消息已发送到所有客户端")
            self.update_receive_area(f"[广播] {message}")

        # 清空发送区域
        self.send_area.delete("1.0", tk.END)

    def on_closing(self):
        """关闭窗口时的处理"""
        if self.server and self.server.is_running:
            if messagebox.askyesno("确认", "服务器正在运行。确定要退出吗？"):
                self.stop_server()
                self.root.destroy()
        else:
            self.root.destroy()
    def _on_ip_selected(self, event=None):
        """当IP地址变更时调用，自动查找对应的证书"""
        if self.server_type.get() == "TLS":
            selected_ip = self.ip_var.get()
            self._update_cert_paths_for_ip(selected_ip)


    def _on_server_type_changed(self):
        """当服务器类型变更时调用"""
        is_tls = self.server_type.get() == "TLS"
        self._toggle_tls_fields()  # 使用现有的方法切换TLS字段显示
        # 如果选择TLS服务器，自动查找证书
        if is_tls:
            selected_ip = self.ip_var.get()
            self._update_cert_paths_for_ip(selected_ip)

    def _update_cert_paths_for_ip(self, ip):
        """根据IP地址更新证书和密钥路径"""
        if not ip:
            return
        # 使用与generate_tls_cert.py相同的路径逻辑
        data_dir = os.path.join(os.path.expanduser('~'), 'Documents', 'TCP服务器', 'certificates')
        ip_filename = ip.replace('.', '_')
        # 检查是否存在证书文件
        cert_file = os.path.join(data_dir, f"cert_{ip_filename}.pem")
        key_file = os.path.join(data_dir, f"key_{ip_filename}.pem")
        # 如果文件存在，自动设置路径
        if os.path.isfile(cert_file):
            self.cert_path_var.set(cert_file)

        if os.path.isfile(key_file):
            self.key_path_var.set(key_file)


    def _browse_cert_file(self):
        """浏览证书文件，默认打开当前IP对应目录"""
        # 使用与generate_tls_cert.py相同的基础目录
        data_dir = os.path.join(os.path.expanduser('~'), 'Documents', 'TCP服务器', 'certificates')
        # 确保目录存在
        os.makedirs(data_dir, exist_ok=True)
        filename = filedialog.askopenfilename(
            initialdir=data_dir,
            title="选择证书文件",
            filetypes=[("PEM文件", "*.pem"), ("所有文件", "*.*")]
        )
        if filename:
            self.cert_path_var.set(filename)


    def _browse_key_file(self):
        """浏览密钥文件，默认打开当前IP对应目录"""
        data_dir = os.path.join(os.path.expanduser('~'), 'Documents', 'TCP服务器', 'certificates')
        # 确保目录存在
        os.makedirs(data_dir, exist_ok=True)

        filename = filedialog.askopenfilename(
            initialdir=data_dir,
            title="选择密钥文件",
            filetypes=[("PEM文件", "*.pem"), ("所有文件", "*.*")]
        )
        if filename:
            self.key_path_var.set(filename)

    def _generate_certificate_for_ip(self):
        """为当前选择的IP生成证书"""
        selected_ip = self.ip_var.get()
        if not selected_ip:
            messagebox.showerror("错误", "请先选择IP地址")
            return
        try:
            # 调用已有的证书生成函数 - 传递self对象
            from security.generate_tls_cert import generate_tls_cert
            generate_tls_cert(self)
        except Exception as e:
            messagebox.showerror("错误", f"生成证书时出错: {str(e)}")


def run_gui():
    """启动GUI应用程序"""
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()
