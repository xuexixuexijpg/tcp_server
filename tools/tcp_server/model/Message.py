from dataclasses import dataclass
from typing import Union, Optional

@dataclass
class Message:
    """消息对象"""
    data: Union[str, bytes]  # 消息内容
    client_id: Optional[str] = None  # None表示发送给所有客户端