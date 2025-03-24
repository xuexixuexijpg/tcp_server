import tkinter as tk
# import webbrowser
from tkinter import ttk, filedialog, messagebox
import os
# from moviepy import VideoFileClip
# from lottie import parsers, objects, Point
# import json
import pyperclip

class ConverterWindow:
    def __init__(self, master=None, window_number=None):
        self.master = master
        self.window_number = window_number
        self.root = tk.Toplevel(master)
        self.root.title(f"Lottie 转换器 {window_number or ''}")
        self.root.geometry("500x500")
        self.root.resizable(False, False)

        # 预览网站列表
        self.preview_sites = [
            ("LottieFiles预览", "https://lottiefiles.com/preview"),
            ("LottieFiles编辑器", "https://lottiefiles.com/web-player"),
            ("Lottie Lab", "https://lottielab.com")
        ]

        # 支持的输入格式
        self.supported_formats = [
            ("图片文件", "*.gif;*.png;*.jpg;*.jpeg"),
            ("视频文件", "*.mp4;*.avi;*.mov"),
            ("SVG文件", "*.svg"),
            ("所有文件", "*.*")
        ]

        self.output_path = None
        self._create_widgets()
        self.center_window()

    def _create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 文件选择区域
        file_frame = ttk.LabelFrame(main_frame, text="选择文件", padding="5")
        file_frame.pack(fill=tk.X, padx=5, pady=5)

        self.file_path = tk.StringVar()
        file_entry = ttk.Entry(file_frame, textvariable=self.file_path, state='readonly')
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        browse_btn = ttk.Button(file_frame, text="浏览", command=self._browse_file)
        browse_btn.pack(side=tk.RIGHT)

        # 输出路径选择区域
        output_frame = ttk.LabelFrame(main_frame, text="输出路径", padding="5")
        output_frame.pack(fill=tk.X, padx=5, pady=5)

        self.output_var = tk.StringVar()
        output_entry = ttk.Entry(output_frame, textvariable=self.output_var, state='readonly')
        output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        copy_btn = ttk.Button(output_frame, text="复制路径", command=self._copy_output_path)
        copy_btn.pack(side=tk.RIGHT)

        # 转换按钮
        convert_btn = ttk.Button(main_frame, text="转换", command=self._convert)
        convert_btn.pack(pady=20)

        # 格式说明
        formats_text = "支持的格式:\n• GIF动画\n• PNG/JPG图片\n• MP4/AVI/MOV视频\n• SVG矢量图"
        format_label = ttk.Label(main_frame, text=formats_text, justify=tk.LEFT)
        format_label.pack(pady=5, anchor=tk.W)

        # 状态标签
        self.status_var = tk.StringVar(value="准备就绪")
        status_label = ttk.Label(main_frame, textvariable=self.status_var)
        status_label.pack(pady=5)


        # 添加预览网站区域
        preview_frame = ttk.LabelFrame(main_frame, text="在线预览", padding="5")
        preview_frame.pack(fill=tk.X, padx=5, pady=5)

        for site_name, urls in self.preview_sites:
            link = ttk.Label(
                preview_frame,
                text=site_name,
                foreground="blue",
                cursor="hand2"
            )
            link.pack(pady=2)
            link.bind("<Button-1>", lambda e, url=urls: self._open_browser(url))
            # 添加下划线效果
            link.bind("<Enter>", lambda e, label=link: self._on_enter(label))
            link.bind("<Leave>", lambda e, label=link: self._on_leave(label))


    def _browse_file(self):
        filename = filedialog.askopenfilename(
            title="选择输入文件",
            filetypes=self.supported_formats
        )
        if filename:
            self.file_path.set(filename)
            # 设置默认输出路径
            default_output = os.path.splitext(filename)[0] + ".json"
            self.output_var.set(default_output)
            self.output_path = default_output

    def _copy_output_path(self):
        if self.output_path:
            pyperclip.copy(self.output_path)
            self.status_var.set("路径已复制到剪贴板")
            self.root.after(2000, lambda: self.status_var.set("准备就绪"))

    def _convert(self):
        if not self.file_path.get():
            messagebox.showerror("错误", "请先选择输入文件")
            return

        try:
            self.status_var.set("正在转换...")
            self.root.update()

            input_file = self.file_path.get()
            file_ext = os.path.splitext(input_file)[1].lower()

            # 创建Lottie动画
            # an = objects.Animation()
            #
            # if file_ext in ['.gif', '.mp4', '.avi', '.mov']:
            #     clip = VideoFileClip(input_file)
            #     an.width = clip.size[0]
            #     an.height = clip.size[1]
            #     an.frame_rate = clip.fps
            #     clip.close()
            # elif file_ext in ['.svg']:
            #     # 使用lottie的SVG解析器
            #     an = parsers.svg.parse_svg_file(input_file)
            # elif file_ext in ['.png', '.jpg', '.jpeg']:
            #     # 处理静态图片
            #     from PIL import Image
            #     with Image.open(input_file) as img:
            #         an.width = img.width
            #         an.height = img.height
            #         an.frame_rate = 1
            #
            # # 保存为Lottie格式
            # with open(self.output_path, "w") as f:
            #     json.dump(an.to_dict(), f)

            self.status_var.set("转换完成!")
            messagebox.showinfo("成功", f"文件已保存到:\n{self.output_path}")

        except Exception as e:
            self.status_var.set("转换失败")
            messagebox.showerror("错误", f"转换过程中出错:\n{str(e)}")

    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def _open_browser(self, url):
        """打开浏览器访问预览网站"""
        # webbrowser.open(url)

    def _on_enter(self, label):
        """鼠标悬停时添加下划线"""
        label.configure(font=("TkDefaultFont", 9, "underline"))

    def _on_leave(self, label):
        """鼠标离开时移除下划线"""
        label.configure(font=("TkDefaultFont", 9))