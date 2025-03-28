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
        self.test_items = ["Na", "ALT", "AST", "Cl", "K"]
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
        self.expecting_eot = False
        self.frame_buffer = bytearray()
        self.is_collecting = False
        self.frame_complete = False      # 当前帧是否完整

    def process_incoming(self, data: bytes) -> bytes | None:
        """处理接收到的数据"""
        try:
            self.log(f"接收到数据: {data!r}")
            # ENQ处理
            if data == self.ENQ:
                # self.log("收到 ENQ")
                self._reset_all_buffers()
                return self.ACK

            # EOT处理
            if data == self.EOT:
                self.log("收到 EOT")
                if not self.message_buffer:  # 增加缓冲区检查
                    return None
                if self.message_buffer and self.expecting_eot:
                    try:
                        return self._process_complete_message()
                    except Exception as e:
                        self.log(f"处理消息出错: {e}")
                self._reset_all_buffers()
                return None

            # 3. 完整帧处理(一次性发送的情况)
            if len(data) > 1 and data.startswith(self.STX) and (data.endswith(self.ETX) or data.endswith(self.ETB)):
                return self._process_complete_frame(data)

            # STX开始收集数据
            if data.startswith(self.STX):
                self.frame_buffer.clear()  # 清空旧数据
                self.frame_buffer = bytearray(data)
                self.is_collecting = True
                return None

            # 普通消息处理
            # 累积帧数据
            if self.is_collecting:
                self.frame_buffer.extend(data)

                # 检查帧是否完整
                if self.ETX in self.frame_buffer or self.ETB in self.frame_buffer:
                    return self._process_complete_frame(bytes(self.frame_buffer))

            self.log(f"收到无效消息: {data}")
            return None
        except Exception as e:
            self.log(f"处理消息时出错: {str(e)}")
            print(f"数据处理错误: {e}")
            self._reset_all_buffers()
            return None

    def _process_complete_message(self) -> bytes | None:
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
            return None

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
                    else:
                        return sample_data[0]
                    # return fields[2] if fields[2] else None
        except Exception as e:
            self.log(f"提取样本号时出错: {str(e)}")
        return None

    def _process_complete_frame(self, frame: bytes) -> bytes | None:
        """处理完整的帧数据"""
        try:
            if frame.startswith(self.STX) and (frame.endswith(self.ETX) or frame.endswith(self.ETB)):
                # 解析帧内容(去掉STX和ETX/ETB)
                content = frame[1:-1].decode('ascii', errors='ignore')
                messages = [m for m in content.split('\r') if m]

                self.log(f"解析帧内容: {messages}")

                # 验证消息格式
                if not messages:
                    self.log("空消息帧")
                    return self.NAK

                # 处理每条消息
                for msg in messages:
                    if msg.startswith(('H|', 'P|', 'Q|', 'L|')):
                        self.message_buffer.append(msg)
                        self.expecting_eot = True
                    else:
                        self.log(f"无效消息格式: {msg}")
                        return self.NAK

                # 重置帧缓冲区
                self.frame_buffer = bytearray()
                self.is_collecting = False

                return self.ACK

            return self.NAK

        except Exception as e:
            self.log(f"处理帧数据出错: {e}")
            self._reset_all_buffers()
            return self.NAK

    def _reset_all_buffers(self):
        """重置所有缓冲区和状态"""
        self.message_buffer = []
        self.frame_buffer.clear()
        self.frame_buffer = bytearray()
        self.is_collecting = False
        self.expecting_eot = False
        self.frame_complete = False

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
            f"P|1||||{sample_id}|||||\r".encode('ascii')
        ]
        # 为每个项目创建单独的O字段
        for seq, item in enumerate(items, 1):
            # 使用项目代码作为结果字段，后缀R表示结果字段
            response.append(f"O|{seq}|{sample_id}||^^^{item}|R\r".encode('ascii'))

        response.extend([
            f"L|1|N\r".encode('ascii'),
            self.ETX,
            self.EOT
        ])
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