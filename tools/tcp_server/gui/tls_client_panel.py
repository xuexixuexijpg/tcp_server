import random
import time
import tkinter as tk
from tkinter import ttk
import socket
import ssl
import threading
from datetime import datetime

import select

from tools.tcp_server.core.logger import LogManager


class TlsClientPanel(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.client_socket = None
        self.receive_thread = None
        self.running = False
        self.send_lock = threading.Lock()
        self.sending = False
        self.logger = LogManager()
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
        self.port_var = tk.StringVar(value="8222")
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
            # 创建 SSL 上下文
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # 配置 TLS 版本
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            # 禁用证书验证（仅测试用）
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            # 配置密码套件
            context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256')

            # 创建普通 socket
            ip = self.ip_var.get().strip()
            port = int(self.port_var.get().strip())
            plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            plain_socket.settimeout(5)

            # 先建立 TCP 连接
            plain_socket.connect((ip, port))

            # 包装 socket 并进行 TLS 握手
            self.client_socket = context.wrap_socket(
                plain_socket,
                server_hostname=ip,
                do_handshake_on_connect=True
            )
            try:
                self.client_socket.do_handshake()
            except ssl.SSLError as ssl_err:
                self.after(0, self._connect_error, f"TLS握手失败: {ssl_err}")
                return

            self.client_socket.setblocking(True)
            self.client_socket.settimeout(5)
            # 获取并显示 TLS 信息
            cipher = self.client_socket.cipher()
            version = self.client_socket.version()
            self.after(0, lambda: self.log(f"TLS连接成功 - 版本:{version} 加密套件:{cipher[0]}"))

            # 更新 GUI
            self.after(0, self._connect_success)
        except ssl.SSLError as ssl_err:
            error_msg = f"SSL错误: {ssl_err}"
            self.after(0, self._connect_error, error_msg)
        except Exception as err:
            error_msg = str(err)
            self.after(0, self._connect_error, error_msg)
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
        self.sending = False
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

        # 使用after_idle代替直接调用
        self.after(0,self._update_gui_disconnect)

        # Update GUI

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

    def _safe_update_gui(self, func):
        """安全地在主线程中执行GUI更新"""
        try:
            if self.winfo_exists():
                if isinstance(func, str):
                    # 如果是字符串，则作为消息记录
                    self.after(0, lambda: self.log(func))
                else:
                    # 如果是函数，则执行函数
                    self.after(0, func)
        except tk.TclError:
            pass

    def _receive_messages(self):
        while self.running and self.client_socket:
            try:
                # 使用select避免阻塞
                ready = select.select([self.client_socket], [], [], 0.1)
                if not ready[0]:
                    continue

                data = self.client_socket.recv(1024)
                if not data:
                    break

                # 使用队列而不是直接调用after
                if len(data) == 1 and data[0] in [0x02, 0x03, 0x04, 0x05, 0x06, 0x15, 0x17]:
                    self._safe_update_gui(f"<<< {data!r}")
                else:
                    self._safe_update_gui(f"<<< {data.decode('ascii', errors='ignore')}")

            except ssl.SSLWantReadError:
                time.sleep(0.01)
                continue
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self._safe_update_gui(f"接收错误: {e}")
                break
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
        try:
            if self.connect_btn:
                self.connect_btn.config(text="连接", state=tk.NORMAL)
            if self.ip_combo:
                self.ip_combo.config(state='normal')
            if self.port_entry:
                self.port_entry.config(state='normal')
            self.log("已断开连接")
        except tk.TclError:
            # 窗口可能已经关闭
            pass

    def _safe_log(self, message):
        """安全的日志记录"""
        if self.running:
            self.log(message)

    def send_astm_message(self):
        """发送ASTM格式的消息"""
        if not self.client_socket:
            self.log("未连接到服务器")
            return
        if self.sending:
            self.log("正在处理上一条消息，请稍后再试")
            return
        sample_id = self.input_text.get("1.0", tk.END).strip()
        if not sample_id:
            self.log("请输入样本号")
            return

        # 禁用发送按钮
        self.send_astm_btn.config(state=tk.DISABLED)
        self.send_btn.config(state=tk.DISABLED)
        self.sending = True
        threading.Thread(target=self._send_astm_async,
                         args=(sample_id,),
                         daemon=True).start()
    def _send_astm_async(self, sample_id):
        """异步发送ASTM消息"""
        try:
            # ASTM 控制字符定义
            ENQ = b'\x05'
            STX = b'\x02'
            ETX = b'\x03'
            EOT = b'\x04'
            ACK = b'\x06'

            # 构建HQL消息序列
            now = datetime.now().strftime("%Y%m%d%H%M%S")
            message = [
                f"H|\\^&|||Client^1|||||||||{now}",
                f"Q|1|{sample_id}||^^^ALL||||||||N",
                "L|1|N"
            ]
            frame_data = '\r'.join(message)

            def receive_with_timeout(timeout=5):
                """带超时的接收函数"""
                start_time = time.time()
                buffer = bytearray()

                try:
                    while time.time() - start_time < timeout and self.running:
                        ready = select.select([self.client_socket], [], [], 0.1)
                        if not ready[0]:
                            # 已有数据则返回
                            if buffer:
                                return bytes(buffer)
                            continue

                        chunk = self.client_socket.recv(1024)
                        if not chunk:
                            break

                        buffer.extend(chunk)

                        # 对于控制字符，收到1字节就返回
                        if len(buffer) == 1 and buffer[0] in [0x06, 0x15]:
                            return bytes(buffer)

                except (socket.error, ssl.SSLError) as e:
                    self.after(0, lambda: self.log(f"接收错误: {e}"))
                    if buffer:
                        return bytes(buffer)

                return bytes(buffer) if buffer else None

            def send_with_retry(data, max_retries=3):
                """带重试的发送函数"""
                for _ in range(max_retries):
                    try:
                        sent = self.client_socket.send(data)
                        if sent == len(data):
                            return True
                    except (ssl.SSLWantWriteError, BlockingIOError):
                        time.sleep(0.1)
                        continue
                    except Exception as e:
                        self.after(0, lambda: self.log(f"发送错误: {e}"))
                        return False
                return False

            # 1. 发送 ENQ
            if not send_with_retry(ENQ):
                self.after(0, lambda: self.log("发送 ENQ 失败"))
                return
            self.after(0, lambda: self.log("已发送 ENQ"))

            # 2. 等待 ACK
            response = receive_with_timeout()
            if response is None:
                self.after(0, lambda: self.log("未收到响应"))
                return
            # 将接收到的数据转换为字节并比较
            if isinstance(response, str):
                response = response.encode('ascii')

            if response != ACK:
                self.after(0, lambda: self.log(f"预期 ACK (\\x06)，实际收到: {response!r}"))
                return

            # 3. 随机选择发送模式：完整帧或分帧发送
            is_split_frame = random.choice([True, False])
            self.after(0, lambda: self.log(f"选择{'分帧' if is_split_frame else '完整帧'}发送模式"))

            if is_split_frame:
                # 分帧发送
                # 3.1 发送STX
                if not send_with_retry(STX):
                    self.after(0, lambda: self.log("发送 STX 失败"))
                    return
                self.after(0, lambda: self.log("已发送 STX"))
                time.sleep(0.1)

                # 3.2 发送消息内容
                content = frame_data.encode('ascii', errors='ignore')
                if not send_with_retry(content):
                    self.after(0, lambda: self.log("发送消息内容失败"))
                    return
                self.after(0, lambda: self.log(f"已发送消息内容: \n{frame_data}"))
                time.sleep(0.1)

                # 3.3 发送ETX
                if not send_with_retry(ETX):
                    self.after(0, lambda: self.log("发送 ETX 失败"))
                    return
                self.after(0, lambda: self.log("已发送 ETX"))
                time.sleep(0.1)
            else:
                # 完整帧发送
                frame = STX + frame_data.encode('ascii', errors='ignore') + ETX
                if not send_with_retry(frame):
                    self.after(0, lambda: self.log("发送数据帧失败"))
                    return
                self.after(0, lambda: self.log(f"已发送完整帧: \n{frame_data}"))
                time.sleep(0.1)
            # 4. 直接发送 EOT，无需等待ACK
            if not send_with_retry(EOT):
                self.after(0, lambda: self.log("发送 EOT 失败"))
                return
            self.after(0, lambda: self.log("已发送 EOT"))

            # 清空输入框
            self.after(0, lambda: self.input_text.delete("1.0", tk.END))
        except Exception as e:
            self.after(0, lambda err=e: self.log(f"错误: {str(err)}"))
            self.after(0, self.disconnect)
        finally:
            # 重新启用发送按钮
            self.after(0, lambda: self.send_astm_btn.config(state=tk.NORMAL))
            self.after(0, lambda: self.send_btn.config(state=tk.NORMAL))
            self.sending = False