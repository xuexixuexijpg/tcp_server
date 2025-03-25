# client_handler.py
import socket
import ssl
import time


def handle_client_tls(tls_socket, addr, context, server):
    """处理TLS客户端连接的函数"""
    client_id = f"{addr[0]}:{addr[1]}"
    try:
        # 直接使用传入的 TLS 套接字进行通信
        # 不需要再进行 TLS 包装，因为已经在主线程中完成了
        while server.running:
            try:
                # 接收数据
                data = tls_socket.recv(1024)
                if not data:
                    server.log(f"客户端 {client_id} 断开连接")
                    break
                # 添加数据处理判断
                if len(data.strip()) > 0:
                    server.log(f"从 {client_id} 接收数据: {data}")
                    server.process_message(tls_socket, addr, data)
                # 添加短暂延时
                time.sleep(0.1)
            except ssl.SSLWantReadError:
                # TLS 需要更多数据才能完成操作
                continue
            except ssl.SSLError as e:
                server.log(f"TLS 连接错误 {client_id}: {e}")
                break
            except socket.timeout:
                continue
            except ConnectionResetError:
                server.log(f"客户端 {client_id} 重置连接")
                break
            except Exception as e:
                server.log(f"处理客户端 {client_id} 消息时出错: {e}")
                break
        # 处理断开连接
        # server.client_disconnected_callback(client_id)
    except Exception as e:
        server.log(f"客户端线程发生异常 {client_id}: {e}")
    finally:
        try:
            tls_socket.close()
        except:
            pass
        server.remove_client(client_id)
        server.log(f"TLS客户端 {client_id} 已断开连接")



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
                # 使用新的消息处理方法
                server.process_message(client_socket, addr, data)
            except socket.timeout:
                continue
            except:
                break

        # 处理断开连接
        # server.client_disconnected_callback(client_id)
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
