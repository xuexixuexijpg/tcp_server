#!/usr/bin/env python
# -*- coding: utf-8 -*-
from datetime import datetime
from tools.tcp_server.plugins.base import PluginBase

class Plugin(PluginBase):
    """HL7协议处理插件"""

    @property
    def name(self) -> str:
        """插件名称"""
        return "HL7消息处理插件"

    def __init__(self):
        # MLLP 控制字符
        self.VT = b'\x0B'    # vertical tab - 消息开始
        self.FS = b'\x1C'    # file separator - 消息结束
        self.CR = b'\x0D'    # carriage return

        # HL7 分隔符
        self.FIELD_SEP = '|'         # 字段分隔符
        self.COMPONENT_SEP = '^'     # 组件分隔符
        self.REPEAT_SEP = '~'        # 重复分隔符
        self.ESCAPE_CHAR = '\\'      # 转义字符
        self.SUBCOMPONENT_SEP = '&'  # 子组件分隔符

        # 消息类型映射
        self.msg_types = {
            'QRY^A19': self._handle_patient_query,
            'ADT^A01': self._handle_admission,
            'ORU^R01': self._handle_observation
        }

    def process_incoming(self, data: bytes) -> bytes:
        """处理接收到的数据"""
        try:
            # 验证MLLP格式
            if not (data.startswith(self.VT) and data.endswith(self.CR + self.FS)):
                return self._create_nack("Invalid MLLP format")

            # 提取HL7消息内容（去除MLLP包装）
            hl7_msg = data[1:-2].decode()

            # ��析消息类型
            segments = hl7_msg.split('\r')
            if not segments or not segments[0].startswith('MSH'):
                return self._create_nack("Invalid HL7 message format")

            # 获取消息类型
            msg_type = self._get_message_type(segments[0])
            if not msg_type:
                return self._create_nack("Unable to determine message type")

            # 处理消息
            handler = self.msg_types.get(msg_type)
            if handler:
                response = handler(segments)
            else:
                response = self._create_nack(f"Unsupported message type: {msg_type}")

            # 添加MLLP包装
            return self.VT + response.encode() + self.CR + self.FS

        except Exception as e:
            return self._create_nack(f"Error processing message: {str(e)}")

    def process_outgoing(self, data: bytes) -> bytes:
        """处理要发送的数据"""
        try:
            if isinstance(data, str):
                # 添加MLLP包装
                return self.VT + data.encode() + self.CR + self.FS
            return data
        except Exception as e:
            return str(e).encode()

    def _get_message_type(self, msh_segment: str) -> str:
        """从MSH段提取消息类型"""
        try:
            fields = msh_segment.split(self.FIELD_SEP)
            if len(fields) >= 9:
                return fields[8]
        except:
            pass
        return None

    def _create_ack(self, msh_segment: str) -> str:
        """创建确认消息"""
        now = datetime.now().strftime("%Y%m%d%H%M%S")
        fields = msh_segment.split(self.FIELD_SEP)

        # 构建ACK消息
        ack = [
            f"MSH|^~\\&|{fields[5]}|{fields[4]}|{fields[2]}|{fields[3]}|{now}||ACK^A01|{now}|P|2.4",
            f"MSA|AA|{fields[9]}|Message accepted|||0"
        ]
        return '\r'.join(ack)

    def _create_nack(self, error_msg: str) -> bytes:
        """创建否定确认消息"""
        now = datetime.now().strftime("%Y%m%d%H%M%S")
        nack = [
            "MSH|^~\\&|SERVER|FACILITY|CLIENT|FACILITY|" + now + "||ACK^A01|" + now + "|P|2.4",
            "MSA|AE|" + now + "|" + error_msg + "|||0"
        ]
        return self.VT + '\r'.join(nack).encode() + self.CR + self.FS

    def _handle_patient_query(self, segments: list) -> str:
        """处理患者查询消息"""
        # 示例患者数据
        patient_data = [
            f"MSH|^~\\&|SERVER|FACILITY|CLIENT|FACILITY|{datetime.now().strftime('%Y%m%d%H%M%S')}||ADT^A01|{datetime.now().strftime('%Y%m%d%H%M%S')}|P|2.4",
            "PID|1||12345^^^MRN||DOE^JOHN^^^^||19700101|M|||123 MAIN ST^^ANYTOWN^ST^12345||555-555-5555|||S|||\r"
        ]
        return '\r'.join(patient_data)

    def _handle_admission(self, segments: list) -> str:
        """处理入院消息"""
        return self._create_ack(segments[0])

    def _handle_observation(self, segments: list) -> str:
        """处理检验结果消息"""
        return self._create_ack(segments[0])

def create_plugin():
    return Plugin()