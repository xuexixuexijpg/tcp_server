# client_handler.py
import socket
import ssl


def handle_client_tls(client_socket, addr, context, server):
    """处理TLS客户端连接的函数"""
    ssl_socket = None
    client_id = f"{addr[0]}:{addr[1]}"

    try:
        # 包装为SSL Socket
        ssl_socket = context.wrap_socket(client_socket, server_side=True)
        server.log(f"来自 {addr} 的安全连接，协议版本：{ssl_socket.version()}")

        # 注册SSL套接字
        server.register_client_socket(client_id, ssl_socket)

        # 通信循环
        while server.running:
            try:
                data = ssl_socket.recv(1024)
                if not data:
                    break

                message = data.decode('utf-8', errors='replace')
                server.log(f"从 {addr} 收到数据: {message}")

                if server.message_received_callback:
                    server.message_received_callback(f"[{client_id}] {message}")
            except socket.timeout:
                continue
            except:
                break

    except ssl.SSLError as e:
        server.log(f"与 {addr} 的SSL握手失败: {e}")
    except socket.timeout:
        server.log(f"与 {addr} 的连接超时")
    except ConnectionResetError:
        server.log(f"与 {addr} 的连接被重置")
    except Exception as e:
        server.log(f"处理 {addr} 时发生错误: {type(e).__name__}: {e}")
    finally:
        # 确保连接关闭
        if ssl_socket:
            try:
                ssl_socket.close()
            except:
                pass
        else:
            try:
                client_socket.close()
            except:
                pass

        # 从服务器中移除客户端
        server.remove_client(client_id)
        server.log(f"与 {addr} 的连接已关闭")


def handle_client_tcp(client_socket, addr, server):
    """处理TCP客户端连接的函数"""
    client_id = f"{addr[0]}:{addr[1]}"

    try:
        server.log(f"来自 {addr} 的TCP连接")

        # 通信循环
        while server.running:
            try:
                data = client_socket.recv(1024)
                if not data:
                    break

                message = data.decode('utf-8', errors='replace')
                server.log(f"从 {addr} 收到数据: {message}")

                if server.message_received_callback:
                    server.message_received_callback(f"[{client_id}] {message}")
            except socket.timeout:
                continue
            except:
                break

    except socket.timeout:
        server.log(f"与 {addr} 的连接超时")
    except ConnectionResetError:
        server.log(f"与 {addr} 的连接被重置")
    except Exception as e:
        server.log(f"处理 {addr} 时发生错误: {type(e).__name__}: {e}")
    finally:
        # 确保连接关闭
        try:
            client_socket.close()
        except:
            pass

        # 从服务器中移除客户端
        server.remove_client(client_id)
        server.log(f"与 {addr} 的连接已关闭")
