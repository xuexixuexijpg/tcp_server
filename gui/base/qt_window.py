from gui.base.window_base import WindowBase
from gui.qt.qt_imports import widgets


class QtWindowBase(WindowBase):
    """Qt窗口基类"""
    def __init__(self):
        super().__init__()
        self.window = widgets.QMainWindow()

    def center_window(self):
        frame = self.window.frameGeometry()
        screen = self.window.screen().availableGeometry()
        frame.moveCenter(screen.center())
        self.window.move(frame.topLeft())