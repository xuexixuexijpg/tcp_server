import queue
import socket
import threading
import time
import ssl
from queue import Queue

from tools.tcp_server.model.Message import Message
from tools.tcp_server.plugins.base import PluginManager


class BaseServer:
    """服务器基类"""

    def __init__(self, host, port, backlog=5, timeout=1.0,
                 log_callback=None, client_connected_callback=None,
                 client_disconnected_callback=None, message_received_callback=None,
                 plugin_manager=None
                 ):
        self.host = str(host)  # 确保 host 是字符串
        self.port = port
        self.backlog = backlog
        self.timeout = timeout
        self.server_socket = None
        self.running = False
        self.active_threads = []
        self.client_handlers = {}  # 保存客户端地址和处理程序的映射

        # 回调函数
        self.log_callback = log_callback
        self.client_connected_callback = client_connected_callback
        self.client_disconnected_callback = client_disconnected_callback
        self.message_received_callback = message_received_callback
        self.plugin_manager =  plugin_manager or PluginManager()
        # 添加消息队列和发送线程
        self.client_sockets = {}  # 移到基类
        self.message_queue = Queue()
        self.send_thread = threading.Thread(target=self._message_sender, daemon=True)
        self.send_lock = threading.Lock()  # 用于线程安全的客户端操作


    def log(self, message):
        """记录日志"""
        print(message)
        if self.log_callback:
            self.log_callback(message)

    def setup_server(self):
        """设置服务器socket"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(self.backlog)
        self.server_socket.settimeout(self.timeout)

    def start(self):
        """启动服务器"""
        raise NotImplementedError("子类必须实现start方法")

    def stop(self):
        """停止服务器"""
        if not self.running:
            return
        try:
            self.running = False
            # 2. 创建临时连接来打破 accept() 阻塞
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tmp_sock:
                    tmp_sock.settimeout(0.1)
                    tmp_sock.connect((self.host, self.port))
            except:
                pass
            # 3. 关闭服务器 socket，不管是否成功
            if self.server_socket:
                try:
                    self.server_socket.close()
                except:
                    pass
                self.server_socket = None
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"停止服务器时出错: {str(e)}")

    def shutdown(self):
        """关闭服务器并清理资源"""
        self.running = False  # First stop the main loop
        try:
            # Force close all client connections
            if hasattr(self, 'client_sockets'):
                for client_id, sock in list(self.client_sockets.items()):
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                        sock.close()
                    except:
                        pass
                    if hasattr(self, 'remove_client'):
                        self.remove_client(client_id)

            # Close server socket
            if self.server_socket:
                try:
                    self.server_socket.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                self.server_socket.close()
                self.log("服务器套接字已关闭")

        except Exception as e:
            self.log(f"关闭服务器时出错: {str(e)}")
        finally:
            # Wait for threads with timeout
            for thread in self.active_threads:
                if thread.is_alive():
                    thread.join(timeout=0.5)  # Shorter timeout per thread
        self.log("服务器已关闭")

    def send_to_client(self, client_id, data):
        """向指定客户端发送消息"""
        """将消息加入发送队列"""
        if not self.running:
            return False
        try:
            message = Message(data=data, client_id=client_id)
            self.message_queue.put(message)
            return True
        except Exception as e:
            self.log(f"加入消息队列失败: {e}")
            return False

    def process_message(self, client_socket, address, data):
        """处理收到的消息"""
        client_id = f"{address[0]}:{address[1]}"
        # 检查是否为TLS加密连接
        is_encrypted = self.is_tls_socket(client_socket)
        encryption_status = "TLS加密" if is_encrypted else "未加密"

        try:
            # 检查数据是否为空
            if not data:
                return
            # 在日志中显示加密状态
            self.log(f"收到来自 {client_id} 的{encryption_status}消息")

            # 先通知UI显示原始消息
            if self.message_received_callback:
                display_data = str(data)
                client_socket.master.after(0, self.message_received_callback, client_socket, address, display_data)


            # 当没有配置插件时，直接显示原始数据
            if not hasattr(self, 'plugin_manager') or not self.plugin_manager.client_plugins.get(client_id):
                # 尝试解码为字符串
                display_data = str(data)
                if self.message_received_callback:
                    # 使用 tkinter 的 after 方法将 UI 更新调度到主线程
                    client_socket.master.after(0, self.message_received_callback, client_socket, address, display_data)
                return
            # 使用插件处理数据
            response = self.plugin_manager.process_data(client_id, data, 'incoming')
            # 如果收到响应数据，直接发送给客户端
            if response:
                self.log(f"插件处理结果:{response}")
                # 使用消息队列发送响应
                self.send_to_client(client_id, response)
        except Exception as e:
            self.log(f"处理消息时出错: {str(e)}")

    @staticmethod
    def is_tls_socket(socket_obj):
        """检查是否为TLS加密套接字"""
        import ssl
        return isinstance(socket_obj, ssl.SSLSocket)

    def _message_sender(self):
        """消息发送线程"""
        while self.running:
            try:
                message = self.message_queue.get(timeout=0.1)
                if message.client_id is None:
                    # 发送给所有客户端
                    with self.send_lock:
                        clients = list(self.client_sockets.items())
                    for client_id, client_socket in clients:
                        self._send_message_to_client(client_id, client_socket, message.data)
                else:
                    # 发送给特定客户端
                    with self.send_lock:
                        client_socket = self.client_sockets.get(message.client_id)
                        if client_socket:
                            self._send_message_to_client(message.client_id, client_socket, message.data)
            except queue.Empty:
                continue
            except Exception as e:
                self.log(f"消息发送线程错误: {e}")


    def broadcast(self, data):
        """广播消息给所有客户端"""
        if not self.running:
            return False
        try:
            message = Message(data=data, client_id=None)  # None表示广播
            self.message_queue.put(message)
            return True
        except Exception as e:
            self.log(f"加入广播消息队列失败: {e}")
            return False

    def start_message_thread(self):
        """启动消息发送线程"""
        self.send_thread.start()

    def _send_message_to_client(self, client_id, client_socket, data):
        """实际发送消息的方法"""
        raise NotImplementedError("子类必须实现_send_message_to_client方法")
class TCPServer(BaseServer):
    """TCP服务器实现"""

    def __init__(self, host, port, backlog=5, timeout=1.0,
                 log_callback=None, client_connected_callback=None,
                 client_disconnected_callback=None, message_received_callback=None,
                 plugin_manager=None,master=None):
        super().__init__(host, port, backlog, timeout,
                         log_callback, client_connected_callback,
                         client_disconnected_callback, message_received_callback,plugin_manager)
        self.master = master

    def start(self):
        """启动TCP服务器"""
        from .client_handler import handle_client_tcp
        self.setup_server()
        self.start_message_thread()
        self.running = True
        self.log(f"TCP服务端已启动，监听 {(self.host, self.port)}...")

        try:
            while self.running:
                try:
                    # 接受客户端连接
                    client_socket, addr = self.server_socket.accept()
                    client_id = f"{addr[0]}:{addr[1]}"
                    self.log(f"接受来自 {addr} 的连接")

                    # 保存客户端socket
                    self.client_sockets[client_id] = client_socket
                    client_socket.master = self.master
                    # 为每个客户端创建新线程处理
                    client_thread = threading.Thread(
                        target=handle_client_tcp,
                        args=(client_socket, addr, self),
                        name=f"ClientThread-{client_id}",  # 添加线程名称
                        daemon= True
                    )
                    self.active_threads.append(client_thread)
                    client_thread.start()

                    # 通知UI有新客户端连接
                    if self.client_connected_callback:
                        self.client_connected_callback(client_socket, addr)

                    # 清理已完成的线程
                    self.active_threads = [t for t in self.active_threads if t.is_alive()]

                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:  # 只在仍然运行时记录错误
                        self.log(f"接受连接时发生错误: {e}")
                        time.sleep(0.1)

        finally:
            self.shutdown()

    def _send_message_to_client(self, client_id, client_socket, data):
        """实际发送消息给TCP客户端"""
        try:
            if isinstance(data, str):
                data = data.encode()
            elif not isinstance(data, bytes):
                data = str(data).encode()

            client_socket.settimeout(1.0)
            try:
                client_socket.sendall(data)
                self.log(f"成功发送消息到 {client_id}")
            except socket.timeout:
                self.log(f"发送消息到 {client_id} 超时")
                self.remove_client(client_id)
            except Exception as e:
                self.log(f"发送消息到 {client_id} 失败: {e}")
                self.remove_client(client_id)
            finally:
                client_socket.settimeout(None)
        except Exception as e:
            self.log(f"处理发送消息时出错: {str(e)}")

    def remove_client(self, client_id):
        """移除客户端连接"""
        if client_id in self.client_sockets:
            del self.client_sockets[client_id]

        if self.client_disconnected_callback:
            self.client_disconnected_callback(client_id)


class TLSServer(BaseServer):
    """TLS服务器实现"""

    def __init__(self, host, port, ssl_context, backlog=5, timeout=1.0,
                 log_callback=None, client_connected_callback=None,
                 client_disconnected_callback=None,
                 message_received_callback=None,plugin_manager=None, master=None):
        super().__init__(host, port, backlog, timeout,
                         log_callback, client_connected_callback,
                         client_disconnected_callback,
                         message_received_callback,plugin_manager)
        self.ssl_context = ssl_context
        self.master = master
    def setup_server(self):
        """设置TLS服务器socket"""
        # 先创建普通的socket
        plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #允许端口快速重用
        plain_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        plain_socket.bind((self.host, self.port))
        plain_socket.listen(self.backlog)
        plain_socket.settimeout(self.timeout)
        # 设置最低 TLS 版本为 1.2
        self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        # 禁用低版本 TLS
        self.ssl_context.options |= ssl.OP_NO_TLSv1
        self.ssl_context.options |= ssl.OP_NO_TLSv1_1
        # 可选：设置首选加密套件
        self.ssl_context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256')
        #启用证书验证：要求客户端提供证书（双向 TLS）
        # self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        # self.ssl_context.load_verify_locations(cafile="ca.crt")
        # 设置验证模式
        # self.ssl_context.verify_mode = ssl.CERT_OPTIONAL  # 或使用 CERT_REQUIRED 强制要求客户端证书


        # 不需要在这里包装SSL，接受连接后再包装
        self.server_socket = plain_socket
        # self.server_socket = self.ssl_context.wrap_socket(
        #     plain_socket,
        #     server_side=True,
        #     do_handshake_on_connect=True  # 连接时立即进行握手
        # )
    def start(self):
        """启动TLS服务器"""
        import ssl
        from .client_handler import handle_client_tls
        self.setup_server()
        self.start_message_thread()
        self.running = True
        self.log(f"TLS服务端已启动，监听 {(self.host, self.port)}...")

        try:
            while self.running:
                try:
                    # 接受客户端连接
                    client_socket, addr = self.server_socket.accept()
                    client_id = f"{addr[0]}:{addr[1]}"
                    self.log(f"接受来自 {addr} 的连接")

                    try:
                        # 直接在这里进行 TLS 握手，而不是在单独的线程中
                        client_socket.settimeout(1)  # 设置较短的超时时间用于握手
                        tls_socket = self.ssl_context.wrap_socket(
                            client_socket,
                            server_side=True
                        )
                        # 验证TLS连接是否成功建立
                        cipher = tls_socket.cipher()
                        if not cipher:
                            raise ssl.SSLError("TLS连接未能建立加密通道")
                        # 打印TLS连接信息
                        self.log(f"TLS连接成功建立 - 使用加密套件: {cipher[0]}")
                        self.log(f"当前连接协议版本 {tls_socket.version()}")
                        # 恢复原始超时设置
                        # tls_socket.settimeout(self.timeout)
                        # tls_socket.settimeout(None) # 永不超时
                        # 注册客户端套接字
                        self.register_client_socket(tls_socket, client_id)
                        tls_socket.master = self.master
                        # 为每个客户端创建新线程处理
                        client_thread = threading.Thread(
                            target=handle_client_tls,
                            args=(tls_socket, addr, self.ssl_context, self),
                            name=f"TLSClientThread-{client_id}",  # 添加线程名称
                            daemon= True
                        )
                        self.active_threads.append(client_thread)
                        client_thread.start()
                        # 通知UI有新客户端连接
                        if self.client_connected_callback:
                                self.client_connected_callback(tls_socket, addr)
                    except ssl.SSLError as e:
                        # 捕获 TLS 握手失败
                        self.log(f"TLS 握手失败，拒绝来自 {addr} 的连接: {e}")
                        client_socket.close()
                    except Exception as e:
                        self.log(f"处理客户端 {addr} 时发生错误: {e}")
                        client_socket.close()

                    # 清理已完成的线程
                    self.active_threads = [t for t in self.active_threads if t.is_alive()]

                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:  # 只在仍然运行时记录错误
                        self.log(f"接受连接时发生错误: {e}")
                        time.sleep(0.1)

        finally:
            self.shutdown()

    def _send_message_to_client(self, client_id, client_socket, data):
        """实际发送消息给TLS客户端"""
        try:
            if isinstance(data, str):
                data = data.encode()
            elif not isinstance(data, bytes):
                data = str(data).encode()

            client_socket.settimeout(1.0)
            try:
                total_sent = 0
                msg_len = len(data)
                while total_sent < msg_len:
                    sent = client_socket.send(data[total_sent:])
                    if sent == 0:
                        raise BrokenPipeError("连接已关闭")
                    total_sent += sent
                self.log(f"成功发送消息到 {client_id}")
            except (socket.timeout, ssl.SSLError):
                self.log(f"发送消息到 {client_id} 超时")
                self.remove_client(client_id)
            except Exception as e:
                self.log(f"发送消息到 {client_id} 失败: {e}")
                self.remove_client(client_id)
            finally:
                client_socket.settimeout(None)
        except Exception as e:
            self.log(f"处理发送消息时出错: {str(e)}")

    def register_client_socket(self, ssl_socket,client_id):
        """注册客户端SSL套接字"""
        import ssl
        # 验证是否为有效的 SSL 套接字
        if not isinstance(ssl_socket, ssl.SSLSocket):
            self.log(f"错误：尝试注册非 TLS 套接字，客户端 {client_id}")
            if hasattr(ssl_socket, 'close'):
                ssl_socket.close()
            return False
        # 验证TLS连接
        try:
            # 获取加密信息
            cipher = ssl_socket.cipher()
            if cipher:
                self.log(f"客户端 {client_id} TLS连接信息:")
                self.log(f"- 加密套件: {cipher[0]}")
                self.log(f"- TLS版本: {ssl_socket.version()}")
                self.log(f"- 协议: {ssl_socket.selected_alpn_protocol() or '未使用ALPN'}")
            else:
                raise ssl.SSLError("未建立加密连接")

            self.client_sockets[client_id] = ssl_socket
            return True
        except Exception as e:
            self.log(f"验证TLS连接失败: {e}")
            ssl_socket.close()
            return False

    def remove_client(self, client_id):
        """移除客户端连接"""
        if client_id in self.client_sockets:
            del self.client_sockets[client_id]

        if self.client_disconnected_callback:
            self.client_disconnected_callback(client_id)
