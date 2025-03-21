# client_handler.py
import socket
import ssl


def handle_client_tls(tls_socket, addr, context, server):
    """处理TLS客户端连接的函数"""
    client_id = f"{addr[0]}:{addr[1]}"
    try:
        # 直接使用传入的 TLS 套接字进行通信
        # 不需要再进行 TLS 包装，因为已经在主线程中完成了
        while True:
            try:
                # 接收数据
                data = tls_socket.recv(1024)
                if not data:
                    break

                # 处理接收到的消息
                if server.message_received_callback:
                    server.message_received_callback(client_id, data)

            except ssl.SSLError as e:
                server.log(f"TLS 连接错误 {client_id}: {e}")
                break
            except Exception as e:
                server.log(f"处理客户端 {client_id} 消息时出错: {e}")
                break

    except Exception as e:
        server.log(f"客户端线程发生异常 {client_id}: {e}")
    finally:
        # 清理连接
        server.remove_client(client_id)



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
