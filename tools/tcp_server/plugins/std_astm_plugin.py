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

    def process_incoming(self, data: bytes) -> bytes:
        """处理接收到的数据"""
        try:
            # 检查是否为 ENQ
            if data == self.ENQ:
                return self.ACK

            # 检查是否为普通 ASTM 消息
            if isinstance(data, bytes) and len(data) > 2:
                if data.startswith(self.STX) and (data.endswith(self.ETX) or data.endswith(self.ETB)):
                    # 处理 ASTM 消息
                    msg_content = data[1:-1].decode('ascii', errors='ignore')

                    # 处理查询记录
                    if msg_content.startswith('Q|'):
                        sample_id = self._extract_sample_id(msg_content)
                        if not sample_id:
                            return self._create_error_response("无效的样本ID")
                        return self._create_result_response(sample_id, self.test_items)

                    # 回复 ACK
                    return self.ACK

            return data

        except Exception as e:
            return f"Error processing message: {str(e)}".encode()

    def process_outgoing(self, data: bytes) -> bytes:
        """处理要发送的数据"""
        try:
            if isinstance(data, str):
                return data.encode('ascii')
            return data
        except Exception as e:
            return str(e).encode()

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