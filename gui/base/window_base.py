class WindowBase:
    """GUI窗口基类，定义通用方法"""
    def __init__(self, title="Window", size=(800, 600)):
        self.title = title
        self.size = size

    def create_widgets(self):
        """创建窗口组件"""
        raise NotImplementedError

    def center_window(self):
        """居中窗口"""
        raise NotImplementedError

    def show(self):
        """显示窗口"""
        raise NotImplementedError