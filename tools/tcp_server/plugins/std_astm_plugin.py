#!/usr/bin/env python
# -*- coding: utf-8 -*-
from datetime import datetime
from tools.tcp_server.plugins.base import PluginBase

class Plugin(PluginBase):
    """ASTM协议处理插件"""

    # 将 name 改为属性装饰器
    @property
    def name(self) -> str:
        """插件名称"""
        return "ASTM项目请求处理插件"

    def __init__(self):
        # 测试项目映射表
        self.test_items = {
            "A0001": ["GLU", "ALT", "AST"],
            "A0002": ["HGB", "WBC", "PLT"],
            "A0003": ["CRP", "PCT"]
        }

    def process_incoming(self, data: bytes) -> str:
        """处理接收到的数据
        Args:
            data: 接收到的原始字节数据
        Returns:
            str: 处理后的消息或None
        """
        try:
            # 将字节数据转换为字符串
            message = str(data)

            # 检查ASTM格式
            if not message.startswith('\x02') or not message.endswith('\x03'):
                return data

            # 解析消息内容
            msg_content = message[1:-1]  # 移除STX/ETX

            # 处理查询记录
            if msg_content.startswith('Q|'):
                sample_id = self._extract_sample_id(msg_content)
                if not sample_id:
                    return self._create_error_response("无效的样本ID")

                items = self.test_items.get(sample_id, [])
                if not items:
                    return self._create_error_response(f"未找到样本 {sample_id} 的测试项目")

                return self._create_result_response(sample_id, items)

            return message

        except Exception as e:
            return f"Error processing message: {str(e)}"

    def process_outgoing(self, data: str) -> bytes:
        """处理要发送的数据
        Args:
            data: 要发送的数据
        Returns:
            bytes: 处理后的字节数据
        """
        try:
            if isinstance(data, str):
                return data.encode()
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
            f"\x02H|\\^&|||Host^1|||||||||{now}\x0D",
            f"P|1||||{sample_id}|||||\x0D",
            f"O|1|{sample_id}||{'^'.join(items)}|||||||N||||||||||||Q\x0D",
            f"L|1|N\x0D\x03"
        ]
        return ''.join(response)

    def _create_error_response(self, error_msg):
        """创建错误响应"""
        now = datetime.now().strftime("%Y%m%d%H%M%S")
        response = [
            f"\x02H|\\^&|||Host^1|||||||||{now}\x0D",
            f"Q|1|E|{error_msg}\x0D",
            f"L|1|N\x0D\x03"
        ]
        return ''.join(response)

# 创建插件实例的工厂函数
def create_plugin():
    return Plugin()