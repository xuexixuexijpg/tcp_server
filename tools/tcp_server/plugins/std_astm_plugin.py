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
        # 消息缓冲和状态跟踪
        self.message_buffer = []
        self.current_frame = []
        self.expecting_eot = False

    def process_incoming(self, data: bytes) -> bytes:
        """处理接收到的数据"""
        try:
            # ENQ处理
            if data == self.ENQ:
                self.log("收到 ENQ")
                self.message_buffer.clear()
                self.current_frame.clear()
                self.expecting_eot = False
                return self.ACK

            # 普通消息处理
            if isinstance(data, bytes) and len(data) > 2:
                if data.startswith(self.STX):
                    if data.endswith(self.ETX) or data.endswith(self.ETB):
                        msg_content = data[1:-1].decode('ascii', errors='ignore')
                        self.log(f"收到消息帧: {msg_content}")
                        self.current_frame.append(msg_content)

                        if data.endswith(self.ETX):
                            self.message_buffer.extend(self.current_frame)
                            self.current_frame.clear()
                            self.expecting_eot = True

                        return self.ACK

            # EOT处理
            if data == self.EOT:
                self.log("收到 EOT")
                if self.message_buffer and self.expecting_eot:
                    response = self._process_complete_message()
                    self.log(f"发送响应: {response}")
                    # 处理完成后清空缓冲
                    self.message_buffer.clear()
                    self.current_frame.clear()
                    self.expecting_eot = False
                    return response
                return self.ACK

            self.log(f"收到无效消息: {data}")
            return self.NAK

        except Exception as e:
            self.log(f"处理消息时出错: {str(e)}")
            return self.NAK

    def _process_complete_message(self) -> bytes:
        """处理完整的消息序列"""
        try:
            full_message = '\r'.join(self.message_buffer)
            self.log(f"处理完整消息: {full_message}")
            message_lines = full_message.split('\r')
            for line in message_lines:
                if line.startswith('Q|'):
                    self.log(f"解析查询消息: {line}")
                    sample_id = self._extract_sample_id(line)
                    if sample_id:
                        self.log(f"提取到样本号: {sample_id}")
                        return self._create_result_response(sample_id, self.test_items)
                    else:
                        self.log("未能提取到有效的样本号")
                        return self._create_error_response("Invalid sample ID")
            self.log("未找到查询记录")
            return self.NAK

        except Exception as e:
            self.log(f"处理完整消息时出错: {str(e)}")
            return self._create_error_response(str(e))

    def _extract_sample_id(self, message):
        """从ASTM消息提取样本ID"""
        self.log(f"提取样本ID: {message}")
        try:
            fields = message.split('|')
            if len(fields) >= 3:
                if fields[0] == 'Q' and fields[1] == '1':
                    sample_data = fields[2].split('^')
                    if len(sample_data) >= 2:
                        return sample_data[1]
                    return fields[2] if fields[2] else None
        except Exception as e:
            self.log(f"提取样本号时出错: {str(e)}")
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