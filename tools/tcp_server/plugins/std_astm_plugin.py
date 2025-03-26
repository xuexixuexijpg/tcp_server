#!/usr/bin/env python
# -*- coding: utf-8 -*-
from datetime import datetime
from tools.tcp_server.plugins.base import PluginBase

class Plugin(PluginBase):
    """ASTM协议处理插件"""

    @property
    def name(self) -> str:
        """插件名称"""
        return "ASTM项目请求处理插件"

    def __init__(self):
        # 测试项目映射表
        self.test_items = ["Na", "ALT", "AST", "HGB", "WBC", "K", "CRP", "PCT"]
        # ASTM 控制字符
        self.ENQ = b'\x05'  # 询问
        self.ACK = b'\x06'  # 确认
        self.NAK = b'\x15'  # 否认
        self.STX = b'\x02'  # 开始传输
        self.ETX = b'\x03'  # 结束传输
        self.EOT = b'\x04'  # 传输结束
        self.ETB = b'\x17'  # 块结束
        # 添加消息缓冲和状态跟踪
        self.message_buffer = []
        self.current_frame = []
        self.expecting_eot = False

    def process_incoming(self, data: bytes) -> bytes:
        """处理接收到的数据"""
        try:
            # 检查是否为 ENQ
            if data == self.ENQ:
                self.message_buffer.clear()
                self.current_frame.clear()
                self.expecting_eot = False
                return self.ACK

            # EOT 处理
            if data == self.EOT:
                if self.message_buffer:
                    # 处理完整的消息序列
                    response = self._process_complete_message()
                    self.message_buffer.clear()
                    self.current_frame.clear()
                    self.expecting_eot = False
                    return response
                return self.ACK

            # 检查是否为普通 ASTM 消息
            if isinstance(data, bytes) and len(data) > 2:
                if data.startswith(self.STX):
                    if data.endswith(self.ETX) or data.endswith(self.ETB):
                        # 提取消息内容
                        msg_content = data[1:-1].decode('ascii', errors='ignore')
                        self.current_frame.append(msg_content)

                        # 如果是 ETX 结尾，说明是完整帧
                        if data.endswith(self.ETX):
                            self.message_buffer.extend(self.current_frame)
                            self.current_frame.clear()
                            self.expecting_eot = True

                        return self.ACK

            return self.NAK

        except Exception as e:
            return f"Error processing message: {str(e)}".encode()
    def _process_complete_message(self) -> bytes:
        """处理完整的消息序列"""
        try:
            # 合并所有消息
            full_message = '\r'.join(self.message_buffer)

            # 解析消息类型
            message_lines = full_message.split('\r')
            for line in message_lines:
                # 查找查询记录 (Q|1|...)
                if line.startswith('Q|'):
                    sample_id = self._extract_sample_id(line)
                    if sample_id:
                        return self._create_result_response(sample_id, self.test_items)
                    else:
                        return self._create_error_response("无效的样本ID")

            # 如果没有找到查询记录，返回NAK
            return self.NAK

        except Exception as e:
            return self._create_error_response(str(e))

    def _extract_sample_id(self, message):
        """从ASTM消息提取样本ID"""
        try:
            fields = message.split('|')
            if len(fields) >= 3:
                sample_data = fields[2].split('^')
                if len(sample_data) >= 2:
                    return sample_data[1]
        except:
            pass
        return None

    def process_outgoing(self, data: bytes) -> bytes:
            """处理要发送的数据"""
            try:
                if isinstance(data, str):
                    return data.encode('ascii')
                return data
            except Exception as e:
                return str(e).encode()

    def _create_result_response(self, sample_id, items):
        """创建ASTM响应消息"""
        now = datetime.now().strftime("%Y%m%d%H%M%S")
        response = [
            self.STX,
            f"H|\\^&|||Host^1|||||||||{now}\r".encode('ascii'),
            f"P|1||||{sample_id}|||||\r".encode('ascii'),
            f"O|1|{sample_id}||{'^'.join(items)}|||||||N||||||||||||Q\r".encode('ascii'),
            f"L|1|N\r".encode('ascii'),
            self.ETX
        ]
        return b''.join(response)

    def _create_error_response(self, error_msg):
        """创建错误响应"""
        now = datetime.now().strftime("%Y%m%d%H%M%S")
        response = [
            self.STX,
            f"H|\\^&|||Host^1|||||||||{now}\r".encode('ascii'),
            f"Q|1|E|{error_msg}\r".encode('ascii'),
            f"L|1|N\r".encode('ascii'),
            self.ETX
        ]
        return b''.join(response)

def create_plugin():
    return Plugin()