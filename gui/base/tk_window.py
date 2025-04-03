import tkinter as tk
from tkinter import ttk
from .window_base import WindowBase

class TkWindowBase(WindowBase):
    """Tkinter窗口基类"""
    def __init__(self, master=None, window_number=None):
        super().__init__()
        self.master = master
        self.window_number = window_number
        self.root = tk.Toplevel(master)

    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')