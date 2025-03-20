import socket
import threading
import time
import ssl


class BaseServer:
    """服务器基类"""

    def __init__(self, host, port, backlog=5, timeout=1.0,
                 log_callback=None, client_connected_callback=None,
                 client_disconnected_callback=None, message_received_callback=None):
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
        try:
            if self.server_socket:
                self.server_socket.close()
                self.log("服务器套接字已关闭")
        except:
            pass

        # 等待所有活跃线程完成
        for thread in self.active_threads:
            if thread.is_alive():
                thread.join(1.0)

        self.log("服务器已关闭")

    def send_to_client(self, client_addr, message):
        """向指定客户端发送消息"""
        raise NotImplementedError("子类必须实现send_to_client方法")


class TCPServer(BaseServer):
    """TCP服务器实现"""

    def __init__(self, host, port, backlog=5, timeout=1.0,
                 log_callback=None, client_connected_callback=None,
                 client_disconnected_callback=None, message_received_callback=None):
        super().__init__(host, port, backlog, timeout,
                         log_callback, client_connected_callback,
                         client_disconnected_callback, message_received_callback)
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
                        args=(client_socket, addr, self)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    self.active_threads.append(client_thread)

                    # 通知UI有新客户端连接
                    if self.client_connected_callback:
                        self.client_connected_callback(client_id, addr)

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
                client_socket.send(message.encode('utf-8'))
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
                 client_disconnected_callback=None, message_received_callback=None):
        super().__init__(host, port, backlog, timeout,
                         log_callback, client_connected_callback,
                         client_disconnected_callback, message_received_callback)
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

        # 不需要在这里包装SSL，接受连接后再包装
        self.server_socket = plain_socket

    def start(self):
        """启动TLS服务器"""
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

                    # 为每个客户端创建新线程处理
                    client_thread = threading.Thread(
                        target=handle_client_tls,
                        args=(client_socket, addr, self.ssl_context, self)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    self.active_threads.append(client_thread)

                    # 通知UI有新客户端连接
                    if self.client_connected_callback:
                        self.client_connected_callback(client_id, addr)

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
            ssl_socket = self.client_sockets.get(client_addr)
            if ssl_socket:
                ssl_socket.send(message.encode('utf-8'))
                return True
            return False
        except:
            return False

    def register_client_socket(self, client_id, ssl_socket):
        """注册客户端SSL套接字"""
        self.client_sockets[client_id] = ssl_socket

    def remove_client(self, client_id):
        """移除客户端连接"""
        if client_id in self.client_sockets:
            del self.client_sockets[client_id]

        if self.client_disconnected_callback:
            self.client_disconnected_callback(client_id)
