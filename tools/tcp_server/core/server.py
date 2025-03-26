import socket
import threading
import time
import ssl

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
        self.running = False

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

    def send_to_client(self, client_addr, message):
        """向指定客户端发送消息"""
        raise NotImplementedError("子类必须实现send_to_client方法")

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
            # 当没有配置插件时，直接显示原始数据
            if not hasattr(self, 'plugin_manager') or not self.plugin_manager.client_plugins.get(client_id):
                # 尝试解码为字符串
                display_data = str(data)
                if self.message_received_callback:
                    self.message_received_callback(client_socket, address, display_data)
                return

            self.log("使用插件处理消息")
            # 使用插件处理数据
            display_data = self.plugin_manager.process_data(
                client_id, data, 'incoming'
            )

            # 通知UI显示消息
            if display_data and self.message_received_callback:
                self.message_received_callback(client_socket, address, str(display_data))

            # 处理要发送的响应数据
            response_data = self.plugin_manager.process_data(
                client_id, data, 'outgoing'
            )

            # 发送响应数据
            if response_data:
                self.send_to_client(client_id, response_data)
        except Exception as e:
            self.log(f"处理消息时出错: {str(e)}")

    @staticmethod
    def is_tls_socket(socket_obj):
        """检查是否为TLS加密套接字"""
        import ssl
        return isinstance(socket_obj, ssl.SSLSocket)
class TCPServer(BaseServer):
    """TCP服务器实现"""

    def __init__(self, host, port, backlog=5, timeout=1.0,
                 log_callback=None, client_connected_callback=None,
                 client_disconnected_callback=None, message_received_callback=None,
                 plugin_manager=None):
        super().__init__(host, port, backlog, timeout,
                         log_callback, client_connected_callback,
                         client_disconnected_callback, message_received_callback,plugin_manager)
        # 保存客户端socket的映射
        self.client_sockets = {}

    def start(self):
        """启动TCP服务器"""
        from .client_handler import handle_client_tcp

        self.setup_server()
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

                    # 为每个客户端创建新线程处理
                    client_thread = threading.Thread(
                        target=handle_client_tcp,
                        args=(client_socket, addr, self),
                        name=f"ClientThread-{client_id}"  # 添加线程名称
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    self.active_threads.append(client_thread)

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

    def send_to_client(self, client_addr, message):
        """向指定客户端发送消息"""
        try:
            client_socket = self.client_sockets.get(client_addr)
            if client_socket:
                # 直接转换为字节，不指定编码
                if isinstance(message, str):
                    message = message.encode()
                elif not isinstance(message, bytes):
                    message = str(message).encode()
                client_socket.sendall(message)
                return True
            return False
        except:
            return False

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
                 message_received_callback=None,plugin_manager=None):
        super().__init__(host, port, backlog, timeout,
                         log_callback, client_connected_callback,
                         client_disconnected_callback,
                         message_received_callback,plugin_manager)
        self.ssl_context = ssl_context
        self.client_sockets = {}

    def setup_server(self):
        """设置TLS服务器socket"""
        # 先创建普通的socket
        plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
        self.ssl_context.verify_mode = ssl.CERT_OPTIONAL  # 或使用 CERT_REQUIRED 强制要求客户端证书


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

                        # 为每个客户端创建新线程处理
                        client_thread = threading.Thread(
                            target=handle_client_tls,
                            args=(tls_socket, addr, self.ssl_context, self),
                            name=f"TLSClientThread-{client_id}"  # 添加线程名称
                        )
                        client_thread.daemon = True
                        client_thread.start()
                        self.active_threads.append(client_thread)
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

    def send_to_client(self, client_id, message):
        """向指定客户端发送消息"""
        import ssl
        if client_id not in self.client_sockets:
            self.log(f"发送失败：找不到客户端 {client_id}")
            return False

        client_socket = self.client_sockets[client_id]

        # 添加类型检查
        if not isinstance(client_socket, ssl.SSLSocket):
            self.log(f"发送失败：客户端 {client_id} 的连接对象不是有效的 TLS 套接字 ({type(client_socket)})")
            self.remove_client(client_id)
            return False

        try:
            # 直接转换为字节，不指定编码
            if isinstance(message, str):
                message = message.encode()
            elif not isinstance(message, bytes):
                message = str(message).encode()

            # 发送数据
            client_socket.sendall(message)
            return True

        except (BrokenPipeError, ConnectionResetError) as e:
            self.log(f"发送失败：连接已断开 {client_id}: {e}")
            self.remove_client(client_id)
            return False

        except Exception as e:
            self.log(f"发送失败：向 {client_id} 发送消息时出错: {e}")
            return False


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
