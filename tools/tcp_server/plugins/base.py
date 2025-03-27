# plugins/base.py
import os
import sys
import importlib.util
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, Dict, Any

class PluginBase(ABC):
    """插件基类"""
    def __init__(self):
        """初始化插件基类"""
        self._log_callback = None

    def set_log_callback(self, callback):
        """设置日志回调函数"""
        self._log_callback = callback

    def log(self, message):
        """记录日志，通过回调函数将日志放入队列"""
        if self._log_callback:
            self._log_callback(f"{self.name}: {message}")

    @property
    @abstractmethod
    def name(self) -> str:
        """插件名称"""
        pass


    @abstractmethod
    def process_incoming(self, data: bytes) -> Any:
        """处理接收到的数据"""
        pass

    @abstractmethod
    def process_outgoing(self, data: Any) -> bytes:
        """处理要发送的数据"""
        pass

    def validate(self) -> bool:
        """验证插件是否可用"""
        try:
            return True
            # 基础功能测试
            # test_data = b"test"
            # processed = self.process_incoming(test_data)
            # if processed is None:
            #     return False
            # result = self.process_outgoing(processed)
            # return isinstance(result, bytes)
        except Exception:
            return False

class PluginManager:
    """插件管理器"""
    def __init__(self,log_callback=None):
        self.plugins: Dict[str, Dict] = {}
        self.client_plugins: Dict[str, str] = {}
        self._log_callback = log_callback


    def unload_client_plugin(self, client_id):
        """卸载客户端的插件"""
        if client_id in self.client_plugins:
            del self.client_plugins[client_id]
            return True
        return False

    def load_plugin(self, plugin_path: str) -> Optional[str]:
        """从指定路径加载插件"""
        try:
            # 检查文件是否存在
            if not os.path.exists(plugin_path):
                raise FileNotFoundError(f"插件文件不存在: {plugin_path}")

            plugin_dir = os.path.dirname(plugin_path)
            plugin_file = os.path.basename(plugin_path)
            plugin_name = os.path.splitext(plugin_file)[0]

            # 检查插件是否已加载
            if plugin_name in self.plugins:
                self.plugins[plugin_name]['instance'].set_log_callback(self._log_callback)
                return plugin_name

            if plugin_dir not in sys.path:
                sys.path.append(plugin_dir)

            spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
            if not spec or not spec.loader:
                raise ImportError("无法加载插件模块")

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # 检查create_plugin函数是否存在
            if not hasattr(module, 'create_plugin'):
                raise AttributeError("插件缺少create_plugin函数")

            # 创建插件实例
            plugin = module.create_plugin()
            if self._log_callback:
                plugin.set_log_callback(self._log_callback)

            # 验证插件类型
            if not isinstance(plugin, PluginBase):
                raise TypeError("插件必须继承PluginBase")

            # 验证插件功能
            if not plugin.validate():
                raise RuntimeError("插件功能验证失败")

            # 存储插件信息
            self.plugins[plugin_name] = {
                'instance': plugin,
                'path': plugin_path,
                'name': plugin.name,
                'loaded_time': datetime.now()
            }

            return plugin_name

        except Exception as e:
            print(f"加载插件失败 {plugin_path}: {str(e)}")
            return None


    def set_client_plugin(self, client_id: str, plugin_name: str) -> bool:
        """为客户端设置插件"""
        try:
            if not plugin_name in self.plugins:
                raise KeyError(f"插件 {plugin_name} 未加载")

            # 先卸载旧插件
            self.unload_client_plugin(client_id)

            plugin = self.plugins[plugin_name]['instance']
            if not plugin.validate():
                raise RuntimeError(f"插件 {plugin_name} 验证失败")

            self.client_plugins[client_id] = plugin_name
            return True

        except Exception as e:
            print(f"设置客户端插件失败: {str(e)}")
            return False

    def process_data(self, client_id: str, data: bytes, direction: str = 'incoming') -> Any:
        """处理数据"""
        try:
            plugin_name = self.client_plugins.get(client_id)
            if not plugin_name:
                return data

            plugin = self.plugins.get(plugin_name, {}).get('instance')
            if not plugin:
                raise KeyError(f"找不到插件 {plugin_name}")

            if not plugin.validate():
                raise RuntimeError(f"插件 {plugin_name} 验证失败")

            if direction == 'incoming':
                return plugin.process_incoming(data)
            else:
                return plugin.process_outgoing(data)

        except Exception as e:
            print(f"插件处理数据失败: {str(e)}")
            return data