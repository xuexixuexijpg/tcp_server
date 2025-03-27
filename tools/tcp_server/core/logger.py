# tools/tcp_server/core/logger.py
import logging
import queue
import threading
import tkinter as tk
from logging.handlers import QueueHandler, QueueListener
from datetime import datetime
from queue import Queue
from typing import Optional, Dict
from weakref import WeakKeyDictionary

class TkinterHandler(logging.Handler):
    """支持多窗口的日志处理器"""
    def __init__(self):
        super().__init__()
        self.text_widgets = WeakKeyDictionary()  # 使用弱引用字典存储文本组件

    def add_widget(self, text_widget: tk.Text):
        """添加文本组件"""
        self.text_widgets[text_widget] = True

    def remove_widget(self, text_widget: tk.Text):
        """移除文本组件"""
        if text_widget in self.text_widgets:
            del self.text_widgets[text_widget]

    def emit(self, record):
        msg = self.format(record)
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {msg}\n"

        # 遍历所有文本组件进行更新
        for text_widget in list(self.text_widgets.keys()):
            try:
                text_widget.after(0, lambda w=text_widget: self._update_widget(w, log_entry))
            except Exception:
                # 如果更新失败，移除失效的组件
                self.remove_widget(text_widget)

    def _update_widget(self, widget: tk.Text, message: str):
        """更新单个文本组件"""
        try:
            widget.insert(tk.END, message)
            widget.see(tk.END)
        except tk.TclError:
            # 如果组件已被销毁，移除它
            self.remove_widget(widget)

class LogManager:
    """线程安全的日志管理器"""
    _instance: Optional['LogManager'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(LogManager, cls).__new__(cls)
            cls._instance.text_widgets = []
            cls._instance.log_queue = Queue()
            cls._instance._start_log_thread()
        return cls._instance

    def _start_log_thread(self):
        """启动日志处理线程"""
        def process_logs():
            while True:
                try:
                    message = self.log_queue.get()
                    if message is None:  # 退出信号
                        break
                    # 在主线程中更新文本控件
                    for widget in self.text_widgets:
                        if widget.winfo_exists():  # 检查控件是否存在
                            widget.after(0, self._update_text_widget, widget, message)
                    self.log_queue.task_done()
                except Exception as e:
                    print(f"处理日志时出错: {e}")
                    self.log_queue.task_done()

        self.log_thread = threading.Thread(target=process_logs, daemon=True)
        self.log_thread.start()

    def _update_text_widget(self, widget, message):
        """在主线程中更新文本控件"""
        try:
            widget.configure(state='normal')
            widget.insert('end', f"{message}\n")
            widget.see('end')
            widget.configure(state='disabled')
        except Exception as e:
            print(f"更新文本控件时出错: {e}")

    def add_text_widget(self, widget):
        """添加文本控件"""
        if widget not in self.text_widgets:
            self.text_widgets.append(widget)
            # 配置文本控件
            widget.configure(state='disabled')  # 初始状态设为只读

    def log(self, message):
        """添加日志消息到队列"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        formatted_message = f"[{timestamp}] {message}"
        self.log_queue.put(formatted_message)

    def remove_text_widget(self, widget):
        """移除文本控件"""
        if widget in self.text_widgets:
            self.text_widgets.remove(widget)