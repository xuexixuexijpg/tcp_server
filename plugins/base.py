# plugins/base.py
import os
import sys
import importlib.util
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any

class PluginBase(ABC):
    """插件基类"""

    @abstractmethod
    def process_incoming(self, data: bytes) -> Any:
        """处理接收到的数据"""
        pass

    @abstractmethod
    def process_outgoing(self, data: Any) -> bytes:
        """处理要发送的数据"""
        pass

class PluginManager:
    """插件管理器"""
    def __init__(self):
        self.plugins: Dict[str, Dict] = {}
        self.client_plugins: Dict[str, str] = {}

    def load_plugin(self, plugin_path: str) -> Optional[str]:
        """从指定路径加载插件"""
        try:
            # 获取插件目录和文件名
            plugin_dir = os.path.dirname(plugin_path)
            plugin_file = os.path.basename(plugin_path)
            plugin_name = os.path.splitext(plugin_file)[0]

            # 添加插件目录到Python路径
            if plugin_dir not in sys.path:
                sys.path.append(plugin_dir)

            # 加载插件模块
            spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
            if not spec or not spec.loader:
                return None

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # 实例化插件
            plugin = module.Plugin()

            # 存储插件信息
            self.plugins[plugin_name] = {
                'instance': plugin,
                'path': plugin_path
            }

            return plugin_name

        except Exception as e:
            print(f"加载插件失败 {plugin_path}: {e}")
            return None

    def set_client_plugin(self, client_id: str, plugin_name: str) -> bool:
        """为客户端设置插件"""
        if plugin_name in self.plugins:
            self.client_plugins[client_id] = plugin_name
            return True
        return False

    def process_data(self, client_id: str, data: bytes, direction: str = 'incoming') -> Any:
        """处理数据"""
        plugin_name = self.client_plugins.get(client_id)
        if not plugin_name or plugin_name not in self.plugins:
            return data

        plugin = self.plugins[plugin_name]['instance']
        try:
            if direction == 'incoming':
                return plugin.process_incoming(data)
            else:
                return plugin.process_outgoing(data)
        except Exception as e:
            print(f"插件处理数据失败 {plugin_name}: {e}")
            return data