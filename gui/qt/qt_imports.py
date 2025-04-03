"""Qt统一导入管理"""
from PyQt6.QtWidgets import (
    QMainWindow,
    QWidget,
    QApplication
)

from PyQt6.QtCore import (
    Qt,
    QPoint,
    QSize,
    QRect,
    QTimer
)

from PyQt6.QtGui import (
    QScreen
)

# 统一导出
__all__ = [
    'QMainWindow',
    'QWidget',
    'QApplication',
    'Qt',
    'QPoint',
    'QSize',
    'QRect',
    'QScreen',
    'QTimer'
]

class QtApp:
    """Qt应用管理器"""
    _instance = None
    _app = None

    @classmethod
    def instance(cls):
        """获取Qt应用实例"""
        if not cls._instance:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        """初始化Qt应用"""
        if not QtApp._app:
            import sys
            QtApp._app = QApplication(sys.argv)

    @property
    def app(self):
        """获取QApplication实例"""
        return QtApp._app

    def process_events(self):
        """处理Qt事件"""
        if self.app:
            self.app.processEvents()

# 创建命名空间类来提供简化的别名访问
class Widgets:
    QMainWindow = QMainWindow
    QWidget = QWidget
    QApplication = QApplication

class Core:
    Qt = Qt
    QPoint = QPoint
    QSize = QSize
    QRect = QRect
    QTimer = QTimer

class Gui:
    QScreen = QScreen

# 提供简化的别名访问
widgets = Widgets()
core = Core()
gui = Gui()
qt_app = QtApp.instance()