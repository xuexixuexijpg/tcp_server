# plugins/default_protobuf.py
from .base import PluginBase
import time
from .proto import message_pb2

class Plugin(PluginBase):
    """默认的Protobuf插件"""
    # 将 name 改为属性装饰器
    @property
    def name(self) -> str:
        """插件名称"""
        return "示例插件"

    def process_incoming(self, data: bytes) -> str:
        """处理接收到的数据，返回用于显示的字符串"""
        try:
            # 尝试解析为Message
            message = message_pb2.Message()
            message.ParseFromString(data)

            # 获取消息类型
            msg_type = message_pb2.Message.Type.Name(message.type)

            # 如果是文本类型，解码数据
            if message.type == message_pb2.Message.Type.TEXT:
                content = message.data.decode()
            else:
                content = f"<二进制数据: {len(message.data)} 字节>"

            # 返回格式化的消息
            return (f"类型: {msg_type}\n"
                    f"时间戳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(message.timestamp))}\n"
                    f"内容: {content}")

        except Exception as e:
            # 如果不是protobuf消息，返回原始数据
            try:
                return data.decode()
            except:
                return f"HEX: {data.hex()}"

    def process_outgoing(self, data: bytes) -> bytes:
        """处理要发送的数据"""
        try:
            # 创建Message
            message = message_pb2.Message()
            message.timestamp = int(time.time())

            # 尝试解析为文本
            try:
                text = data.decode()
                message.type = message_pb2.Message.Type.TEXT
                message.data = text.encode()
            except:
                message.type = message_pb2.Message.Type.BINARY
                message.data = data

            return message.SerializeToString()

        except Exception as e:
            # 发生错误时返回原始数据
            return data