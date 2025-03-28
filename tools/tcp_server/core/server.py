import os
import queue
import selectors
import socket
import threading
import time
import ssl
from queue import Queue

from tools.tcp_server.core.client_handler import handle_client_tls
from tools.tcp_server.core.logger import LogManager
from tools.tcp_server.model.Message import Message
from tools.tcp_server.plugins.base import PluginManager
from typing import Union

class BaseServer:
    """服务器基类"""

    def __init__(self, host, port, backlog=5, timeout=1.0,
                 log_callback=None, client_connected_callback=None,
                 client_disconnected_callback=None, message_received_callback=None,
                 plugin_manager=None
                 ):
        self.selector = selectors.DefaultSelector()
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
        self.send_lock = threading.Lock()  # 用于线程安全的客户端操作
        # 添加写缓冲区
        self.write_buffers = {}  # {client_id: [data1, data2, ...]}
        self.log_manager = LogManager()
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
            if hasattr(self, 'selector'):
                for key in list(self.selector.get_map().values()):
                    try:
                        self.selector.unregister(key.fileobj)
                        key.fileobj.close()
                    except Exception as e:
                        self.log(f"清理socket时出错: {e}")
                self.selector.close()
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
        if not self.running:
            return False
        try:
            client_socket = self.client_sockets.get(client_id)
            if not client_socket:
                self.log(f"客户端 {client_id} 不存在")
                return False
            self._send_message_to_client(client_id, client_socket, data)
            return True
        except Exception as e:
            self.log(f"加入消息队列失败: {e}")
            return False

    def process_message(self, client_socket, address, data):
        """处理收到的消息"""
        try:
            client_id = f"{address[0]}:{address[1]}"
            # 检查数据是否为空
            if not data:
                return
            # 检查是否为TLS加密连接
            is_encrypted = self.is_tls_socket(client_socket)
            encryption_status = "TLS加密" if is_encrypted else "未加密"
            # 在日志中显示加密状态
            self.log(f"收到来自 {client_id} 的{encryption_status}消息")

            # 先通知UI显示原始消息
            try:
                if self.message_received_callback:
                    if hasattr(client_socket, 'master'):
                        client_socket.master.after(0, self.message_received_callback,
                                                   client_socket, address, str(data))
            except Exception as e:
                self.log(f"回调处理错误: {e}")
            # 当没有配置插件时，直接显示原始数据
            try:
                if hasattr(self, 'plugin_manager') and self.plugin_manager.client_plugins.get(client_id):
                    response = self.plugin_manager.process_data(client_id, data, 'incoming')
                    if response is not None:
                        self.log_manager.log(f"插件处理结果:{response}")
                        self._send_message_to_client(client_id, client_socket, response)
                    else:
                        self.log_manager.log("插件未返回数据，跳过发送")
                else:
                    self.log_manager.log(f"没有插件处理消息，返回原数据 {str(data)}")
                    self._send_message_to_client(client_id, client_socket, data)
            except Exception as e:
                self.log(f"消息处理错误: {e}")
        except Exception as e:
                self.log(f"处理消息时出错: {str(e)}")

    @staticmethod
    def is_tls_socket(socket_obj):
        """检查是否为TLS加密套接字"""
        import ssl
        return isinstance(socket_obj, ssl.SSLSocket)

    def broadcast(self, data):
        """广播消息给所有客户端"""
        if not self.running:
            return False
        try:
            # 遍历所有客户端发送消息
            success = False
            with self.send_lock:
                for client_id, client_socket in list(self.client_sockets.items()):
                    try:
                        self._send_message_to_client(client_id, client_socket, data)
                        success = True
                    except Exception as e:
                        self.log(f"广播消息到客户端 {client_id} 失败: {e}")
            return success
        except Exception as e:
            self.log(f"广播消息失败: {e}")
        return False


    def _send_message_to_client(self, client_id, client_socket, data):
        """实际发送消息的方法"""
        try:
            if isinstance(data, str):
                data = data.encode()
            elif not isinstance(data, bytes):
                data = str(data).encode()

            # 直接发送数据
            total_sent = 0
            data_len = len(data)
            while total_sent < data_len:
                try:
                    sent = client_socket.send(data[total_sent:])
                    if sent == 0:
                        raise ConnectionError("连接已断开")
                    total_sent += sent
                    self.log(f"已发送 {total_sent}/{data_len} 字节到客户端 {client_id}")
                except (ssl.SSLWantWriteError, BlockingIOError):
                    # SSL缓冲区满或非阻塞socket暂时不可写
                    time.sleep(0.01)
                    continue
                except Exception as e:
                    self.log(f"发送数据到客户端 {client_id} 失败: {e}")
                    self.handle_disconnect(client_socket, client_id)
                    return False
            return True
        except Exception as e:
            self.log(f"发送消息失败: {e}")
            return False

    def handle_write(self, sock, client_id):
        """处理写事件"""
        if client_id in self.write_buffers and self.write_buffers[client_id]:
            data = self.write_buffers[client_id][0]
            try:
                sent = sock.send(data)
                if sent < len(data):
                    # 部分发送,保留剩余数据
                    self.write_buffers[client_id][0] = data[sent:]
                else:
                    # 完全发送,移除已发送的数据
                    self.write_buffers[client_id].pop(0)

                # 如果没有更多数据要发送,取消写事件监听
                if not self.write_buffers[client_id]:
                    self.selector.modify(sock, selectors.EVENT_READ,
                                         {"addr": sock.getpeername()})
                    del self.write_buffers[client_id]

            except (BlockingIOError, ssl.SSLWantWriteError):
                # 资源暂时不可用,下次再试
                return
            except Exception as e:
                self.log(f"发送数据到 {client_id} 失败: {e}")
                self.handle_disconnect(sock, client_id)

    def handle_disconnect(self, sock, client_id):
        """处理断开连接"""
        try:
            self.selector.unregister(sock)
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
        if client_id in self.write_buffers:
            del self.write_buffers[client_id]
        self.remove_client(client_id)

    def remove_client(self, client_id):
        """移除客户端连接"""
        if client_id not in self.client_sockets:
            return
        try:
            # 从 selector 中注销
            client_socket = self.client_sockets[client_id]
            try:
                self.selector.unregister(client_socket)
            except Exception as e:
                self.log(f"从 selector 注销客户端 {client_id} 时出错: {e}")

            # 关闭连接
            try:
                if isinstance(client_socket, ssl.SSLSocket):  # 如果是SSL socket
                    client_socket.shutdown(socket.SHUT_RDWR)  # 安全关闭SSL层
                client_socket.close()
            except Exception as e:
                self.log(f"关闭客户端 {client_id} socket 时出错: {e}")

            # 清理写缓冲区
            if client_id in self.write_buffers:
                del self.write_buffers[client_id]

            # 从客户端字典中删除
            del self.client_sockets[client_id]

            # 通知断开连接回调
            if self.client_disconnected_callback:
                self.client_disconnected_callback(client_id)

            self.log(f"客户端 {client_id} 已移除")

        except Exception as e:
            self.log(f"移除客户端 {client_id} 时出错: {e}")
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
        self.setup_server()
        self.running = True
        # 创建selector实例
        # 注册服务器socket
        self.server_socket.setblocking(False)
        self.selector.register(self.server_socket, selectors.EVENT_READ)
        self.log(f"TCP服务端已启动，监听 {(self.host, self.port)}...")

        try:
            while self.running:
                # 使用selector等待事件
                events = self.selector.select(timeout=0.1)
                for key, mask in events:
                    if key.fileobj is self.server_socket:
                        # 处理新的客户端连接
                        client_socket, addr = self.server_socket.accept()
                        client_id = f"{addr[0]}:{addr[1]}"
                        self.log(f"接受来自 {addr} 的连接")

                        # 设置非阻塞模式
                        client_socket.setblocking(False)
                        # 注册客户端socket到selector
                        self.selector.register(client_socket, selectors.EVENT_READ, {"addr": addr})

                        # 保存客户端socket
                        self.client_sockets[client_id] = client_socket
                        client_socket.master = self.master

                        # 通知UI更新
                        if self.client_connected_callback:
                            self.client_connected_callback(client_socket, addr)

                    else:
                        # 处理已连接客户端的数据
                        sock : socket.socket | ssl.SSLSocket= key.fileobj
                        data = key.data
                        addr = data["addr"]
                        client_id = f"{addr[0]}:{addr[1]}"

                        # 处理读事件
                        # if mask & selectors.EVENT_READ:
                        try:
                            recv_data = sock.recv(1024)
                            if recv_data:
                                self.process_message(sock, addr, recv_data)
                            else:
                                self.handle_disconnect(sock, client_id)
                        except (ssl.SSLWantReadError, BlockingIOError):
                            continue
                        except Exception as e:
                            self.handle_disconnect(sock, client_id)
                        # 处理写事件
                        # if mask & selectors.EVENT_WRITE:
                        #     self.handle_write(sock, client_id)
        except Exception as e:
            self.log(f"服务器运行错误: {e}")
        finally:
            self.selector.close()
            self.shutdown()

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
        self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
        # 禁用低版本 TLS
        self.ssl_context.options |= ssl.OP_NO_TLSv1
        self.ssl_context.options |= ssl.OP_NO_TLSv1_1
        # 可选：设置首选加密套件
        self.ssl_context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256')
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
        self.running = True
        # 注册服务器socket
        self.server_socket.setblocking(False)
        self.selector.register(self.server_socket, selectors.EVENT_READ)
        self.log(f"TLS服务端已启动，监听 {(self.host, self.port)}...")

        try:
            while self.running:
                # 使用selector等待事件
                try:
                    events = self.selector.select(timeout=0.1)
                    for key, mask in events:
                        if key.fileobj is self.server_socket:
                            # 处理新的客户端连接
                            try:
                                client_socket, addr = self.server_socket.accept()
                                client_id = f"{addr[0]}:{addr[1]}"
                                self.log(f"接受来自 {addr} 的连接")
                                # TLS握手
                                client_socket.settimeout(5)
                                try:
                                    tls_socket = self.ssl_context.wrap_socket(
                                        client_socket,
                                        server_side=True,
                                        do_handshake_on_connect=True
                                    )

                                    # 完成握手后再设置非阻塞
                                    tls_socket.setblocking(False)
                                    self.selector.register(tls_socket, selectors.EVENT_READ, {"addr": addr})
                                    self.register_client_socket(tls_socket, client_id)
                                    tls_socket.master = self.master

                                    if self.client_connected_callback:
                                        self.client_connected_callback(tls_socket, addr)

                                except ssl.SSLError as e:
                                    self.log(f"TLS握手失败: {e}")
                                    client_socket.close()
                                    continue
                                except Exception as e:
                                    self.log(f"处理新连接时出错: {e}")
                                    client_socket.close()
                                    continue
                            except ssl.SSLError as e:
                                self.log(f"TLS握手失败: {e}")

                        else:
                            # 处理已连接客户端的数据
                            sock : socket.socket | ssl.SSLSocket = key.fileobj
                            data = key.data
                            addr = data["addr"]
                            client_id = f"{addr[0]}:{addr[1]}"

                            if mask & selectors.EVENT_READ:
                                try:
                                    recv_data = sock.recv(1024)
                                    if recv_data:
                                        self.process_message(sock, addr, recv_data)
                                    else:
                                        raise ConnectionError("连接已关闭")
                                except (ssl.SSLWantReadError, BlockingIOError):
                                    continue
                                except Exception as e:
                                    self.log(f"读取数据时出错: {e}")
                                    self.handle_disconnect(sock, client_id)
                                    continue
                except Exception as e:
                    self.log(f"主循环处理错误: {e}")
                    if not self.running:
                        break
                    time.sleep(0.1)  # 避免CPU过载

        except Exception as e:
            self.log(f"服务器运行错误: {e}")
        finally:
            self.selector.close()
            self.shutdown()

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

    def get_cert_paths(self):
        """获取证书文件路径"""
        import os
        cert_dir = os.path.join(os.path.dirname(__file__), "..", "certs")
        cert_file = os.path.join(cert_dir, "server.crt")
        key_file = os.path.join(cert_dir, "server.key")
        return cert_dir, cert_file, key_file

    def load_existing_cert(self):
        """尝试加载已存在的证书"""
        try:
            cert_dir, cert_file, key_file = self.get_cert_paths()

            # 检查证书文件是否存在
            if not os.path.exists(cert_file):
                self.log("未找到证书文件")
                return None

            if not os.path.exists(key_file):
                self.log("未找到密钥文件")
                return None

            # 尝试加载证书
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=cert_file, keyfile=key_file)
            self.log("成功加载已存在的证书")
            return context

        except Exception as e:
            self.log(f"加载证书失败: {e}")
            return None