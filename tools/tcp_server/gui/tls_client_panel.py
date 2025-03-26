import tkinter as tk
from tkinter import ttk
import socket
import ssl
import threading
from datetime import datetime

class TlsClientPanel(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.client_socket = None
        self.receive_thread = None
        self.running = False
        self._create_widgets()

    def _create_widgets(self):
        # Connection settings
        settings_frame = ttk.LabelFrame(self, text="连接设置")
        settings_frame.pack(fill=tk.X, padx=5, pady=5)

        # IP address with combobox
        ttk.Label(settings_frame, text="服务器IP:").grid(row=0, column=0, padx=5, pady=5)
        self.ip_var = tk.StringVar(value="127.0.0.1")

        # Get local IPs for combobox
        ip_list = self._get_local_ips()
        self.ip_combo = ttk.Combobox(settings_frame, textvariable=self.ip_var, values=ip_list)
        self.ip_combo.grid(row=0, column=1, padx=5, pady=5)

        # Allow manual input
        self.ip_combo.configure(state='normal')
        if ip_list:
            self.ip_combo.current(0)

        # Port
        ttk.Label(settings_frame, text="端口:").grid(row=0, column=2, padx=5, pady=5)
        self.port_var = tk.StringVar(value="8080")
        self.port_entry = ttk.Entry(settings_frame, textvariable=self.port_var, width=10)
        self.port_entry.grid(row=0, column=3, padx=5, pady=5)

        # Connect button
        self.connect_btn = ttk.Button(settings_frame, text="连接", command=self.connect)
        self.connect_btn.grid(row=0, column=4, padx=5, pady=5)

        # Message area
        msg_frame = ttk.LabelFrame(self, text="消息")
        msg_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Message display
        self.msg_text = tk.Text(msg_frame, height=10, wrap=tk.WORD)
        msg_scroll = ttk.Scrollbar(msg_frame, command=self.msg_text.yview)
        self.msg_text.configure(yscrollcommand=msg_scroll.set)

        self.msg_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        msg_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Message input
        input_frame = ttk.Frame(self)
        input_frame.pack(fill=tk.X, padx=5, pady=5)

        self.input_text = tk.Text(input_frame, height=3)
        self.input_text.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.send_btn = ttk.Button(input_frame, text="发送", command=self.send_message)
        self.send_btn.pack(side=tk.BOTTOM, padx=5)

        self.send_astm_btn = ttk.Button(input_frame, text="发送ASTM", command=self.send_astm_message)
        self.send_astm_btn.pack(side=tk.BOTTOM, pady=2)

    def _get_local_ips(self):
        """Get list of local IP addresses"""
        ips = []
        ips.append("127.0.0.1")
        ips.append("0.0.0.0")

        try:
            # Get hostname IP
            hostname = socket.gethostname()
            try:
                host_ip = socket.gethostbyname(hostname)
                if host_ip not in ips:
                    ips.append(host_ip)
            except:
                pass

            # Get all interface IPs
            for iface in socket.getaddrinfo(host=socket.gethostname(), port=None, family=socket.AF_INET):
                ip = iface[4][0]
                if ip not in ips:
                    ips.append(ip)
        except:
            pass

        # Try to get more network interfaces on non-Windows systems
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

    def connect(self):
        if self.client_socket:
            self.disconnect()
            return

        # Disable connect button during connection attempt
        self.connect_btn.config(state=tk.DISABLED)

        # Start connection in background thread
        threading.Thread(target=self._connect_thread, daemon=True).start()

    def _connect_thread(self):
        try:
            # Store current socket for proper cleanup
            if self.client_socket:
                try:
                    self.client_socket.close()
                except:
                    pass
                self.client_socket = None

            # Create SSL context that trusts all certificates
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Create socket and wrap with SSL
            plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            plain_socket.settimeout(5)  # Add timeout
            self.client_socket = context.wrap_socket(plain_socket)

            # Connect to server
            ip = self.ip_var.get().strip()
            port = int(self.port_var.get().strip())
            self.client_socket.connect((ip, port))

            # Update GUI in main thread
            self.after(0, self._connect_success)
        except Exception as e:
            # Update GUI in main thread
            self.after(0, lambda: self._handle_connection_error(str(e)))

    def _connect_success(self):
        self.running = True
        self.connect_btn.config(text="断开", state=tk.NORMAL)
        self.ip_combo.config(state='disabled')
        self.port_entry.config(state='disabled')
        self.log("已连接到服务器")

        # Start receive thread
        self.receive_thread = threading.Thread(target=self._receive_messages, daemon=True)
        self.receive_thread.start()

    def _connect_error(self, error):
        self.disconnect()
        self.connect_btn.config(state=tk.NORMAL)
        self.log(f"连接失败: {error}")

    def _handle_connection_error(self, error):
        """Safely handle connection errors"""
        try:
            error_msg = str(error) if error else "Unknown connection error"
            self._connect_error(error_msg)
        except Exception as e:
            print(f"Error handling connection failure: {e}")

    def disconnect(self):
        self.running = False
        if self.client_socket:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except:
                pass
            try:
                self.client_socket.close()
            except:
                pass
            self.client_socket = None
            # Update GUI
            self.after(0, self._update_gui_disconnect)

        # Update GUI
        self.connect_btn.config(text="连接")
        self.ip_combo.config(state='normal')
        self.port_entry.config(state='normal')
        self.log("已断开连接")
    def send_message(self):
        if not self.client_socket:
            self.log("未连接到服务器")
            return

        message = self.input_text.get("1.0", tk.END).strip()
        if not message:
            return

        try:
            self.client_socket.send(message.encode())
            self.log(f">>> {message}")
            self.input_text.delete("1.0", tk.END)
        except Exception as e:
            self.log(f"发送失败: {e}")
            self.disconnect()

    def _receive_messages(self):
        while self.running and self.client_socket:
            try:
                data = self.client_socket.recv(1024)
                if not data:
                    break
                # Update GUI in main thread
                self.after(0, lambda d=data: self.log(f"<<< {d.decode()}"))
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.after(0, lambda: self.log(f"接收错误: {e}"))
                break
        # Disconnect in main thread if still running
        if self.running:
            self.after(0, self.disconnect)

    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.msg_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.msg_text.see(tk.END)

    def _on_closing(self):
        """Handle window closing"""
        self.running = False
        if self.client_socket:
            self.disconnect()
        # Wait for receive thread with timeout
        if self.receive_thread and self.receive_thread.is_alive():
            self.receive_thread.join(timeout=1.0)
        self.root.destroy()

    def _update_gui_disconnect(self):
        """Update GUI elements after disconnect"""
        self.connect_btn.config(text="连接", state=tk.NORMAL)
        self.ip_combo.config(state='normal')
        self.port_entry.config(state='normal')
        self.log("已断开连接")

    def send_astm_message(self):
        """发送ASTM格式的消息"""
        if not self.client_socket:
            self.log("未连接到服务器")
            return

        message = self.input_text.get("1.0", tk.END).strip()
        if not message:
            return

        try:
            # ASTM 控制字符
            ENQ = b'\x05'  # 询问
            STX = b'\x02'  # 开始传输
            ETX = b'\x03'  # 结束传输
            EOT = b'\x04'  # 传输结束

            # 发送顺序：ENQ -> 等待ACK -> 发送数据帧 -> 等待ACK -> 发送EOT
            # 1. 发送 ENQ
            self.client_socket.send(ENQ)
            self.log("已发送 ENQ")

            # 2. 等待 ACK
            response = self.client_socket.recv(1024)
            if response != b'\x06':  # ACK
                self.log("未收到 ACK，发送取消")
                return

            # 3. 发送数据帧
            frame = STX + message.encode('ascii', errors='ignore') + ETX
            self.client_socket.send(frame)
            self.log(f"已发送数据帧: {message}")

            # 4. 等待 ACK
            response = self.client_socket.recv(1024)
            if response != b'\x06':  # ACK
                self.log("未收到数据帧 ACK，发送取消")
                return

            # 5. 发送 EOT
            self.client_socket.send(EOT)
            self.log("已发送 EOT")

            # 清空输入框
            self.input_text.delete("1.0", tk.END)

        except Exception as e:
            self.log(f"发送ASTM消息失败: {str(e)}")
            self.disconnect()