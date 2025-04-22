#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import threading
import tkinter as tk
from datetime import datetime
from tkinter import ttk, filedialog, messagebox
import subprocess
import json
import sys
from pathlib import Path

# Import base window from core
from core.base_window import BaseWindow
from ..core.scanner import CVEScanner

class ScannerWindow(BaseWindow):
    def __init__(self, master=None, window_number=None):
        self.window_number = window_number
        title = "CVE扫描工具"
        if window_number is not None:
            title = f"{title}-{window_number}"
        super().__init__(master=master, title=title, geometry="900x600")

        # 扫描相关变量
        self.scanner = CVEScanner()
        self.scan_thread = None
        self.target_file = None
        self.target_dir = None
        self.is_scanning = False
        self.is_initializing_db = False
        self.report_file = None
        self.tool_version = "未知"
        self.tool_help = ""

        # 检查工具版本
        self._check_tool_version()

        # 创建报告目录
        self.reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
        os.makedirs(self.reports_dir, exist_ok=True)

        # 检查Windows平台
        if sys.platform == 'win32':
            self.log("检测到Windows平台，已启用兼容性优化", "INFO")
            self._check_windows_dependencies()

        # 添加对主窗口关闭事件的监听
        if master:
            master.bind('<Destroy>', self._on_master_destroy)

        # 窗口初始化
        self._create_widgets()
        self.center_window()

    def _create_widgets(self):
        """创建GUI组件"""
        # 创建主框架
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 创建选项卡控件
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        # 创建选项卡页面
        scan_tab = ttk.Frame(notebook)
        report_tab = ttk.Frame(notebook)
        log_tab = ttk.Frame(notebook)

        notebook.add(scan_tab, text="扫描")
        notebook.add(report_tab, text="报告")
        notebook.add(log_tab, text="日志")

        # 扫描选项卡 - 配置面板
        self._create_scan_config(scan_tab)

        # 报告选项卡 - 报告显示
        self._create_report_view(report_tab)

        # 日志选项卡 - 日志显示
        self._create_log_view(log_tab)

        # 底部状态栏
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=(10, 0))

        self.status_var = tk.StringVar(value="就绪")
        status_label = ttk.Label(status_frame, textvariable=self.status_var, anchor=tk.W)
        status_label.pack(side=tk.LEFT, padx=5)

        self.progress_bar = ttk.Progressbar(status_frame, mode="indeterminate", length=200)
        self.progress_bar.pack(side=tk.RIGHT, padx=5)

    def _create_scan_config(self, parent):
        """创建扫描配置面板"""
        # 工具信息区域
        info_frame = ttk.Frame(parent)
        info_frame.pack(fill=tk.X, expand=False, padx=10, pady=(10, 0))

        version_label = ttk.Label(info_frame, text=f"CVE-Bin-Tool 版本: {self.tool_version}")
        version_label.pack(side=tk.LEFT)

        # 获取并显示数据库路径
        db_path = self.scanner.db_path if hasattr(self.scanner, 'db_path') else "未知"
        if db_path:
            self.log(f"数据库路径: {db_path}")

        # Windows平台添加工具安装帮助按钮
        if sys.platform == 'win32':
            win_help_btn = ttk.Button(info_frame, text="Windows工具安装", command=self._show_windows_help)
            win_help_btn.pack(side=tk.RIGHT, padx=5)

        reset_db_btn = ttk.Button(info_frame, text="重置数据库", command=self._reset_database)
        reset_db_btn.pack(side=tk.RIGHT, padx=5)

        help_btn = ttk.Button(info_frame, text="查看帮助", command=self._show_tool_help)
        help_btn.pack(side=tk.RIGHT, padx=5)

        init_db_btn = ttk.Button(info_frame, text="初始化数据库", command=self._initialize_database)
        init_db_btn.pack(side=tk.RIGHT, padx=5)

        # 如果未安装显示警告
        if self.tool_version == "未安装":
            warning_label = ttk.Label(info_frame, text="工具未安装! 请先安装 cve-bin-tool", foreground="red")
            warning_label.pack(side=tk.RIGHT, padx=5)

        # 文件选择区域
        file_frame = ttk.LabelFrame(parent, text="选择扫描目标")
        file_frame.pack(fill=tk.X, expand=False, padx=10, pady=10)

        # 选择扫描类型
        self.scan_type = tk.StringVar(value="file")
        file_radio = ttk.Radiobutton(file_frame, text="扫描单个文件", variable=self.scan_type,
                                     value="file", command=self._on_scan_type_changed)
        file_radio.grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)

        dir_radio = ttk.Radiobutton(file_frame, text="扫描目录", variable=self.scan_type,
                                    value="directory", command=self._on_scan_type_changed)
        dir_radio.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)

        # 文件路径
        ttk.Label(file_frame, text="路径:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.file_path_var = tk.StringVar()
        file_entry = ttk.Entry(file_frame, textvariable=self.file_path_var, width=50)
        file_entry.grid(row=1, column=1, sticky=tk.W+tk.E, padx=5, pady=5)

        browse_btn = ttk.Button(file_frame, text="浏览...", command=self._browse_target)
        browse_btn.grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)

        # 扫描选项区域
        options_frame = ttk.LabelFrame(parent, text="扫描选项")
        options_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 扫描级别
        ttk.Label(options_frame, text="扫描级别:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.scan_level = tk.StringVar(value="default")
        level_combo = ttk.Combobox(options_frame, textvariable=self.scan_level,
                                 values=["default", "detailed"])
        level_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        level_combo.current(0)

        # 是否跳过更新
        self.skip_update_var = tk.BooleanVar(value=True)
        skip_update_check = ttk.Checkbutton(options_frame, text="跳过NVD数据库更新",
                                          variable=self.skip_update_var)
        skip_update_check.grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)

        # 是否生成报告
        self.generate_report_var = tk.BooleanVar(value=True)
        gen_report_check = ttk.Checkbutton(options_frame, text="生成JSON报告",
                                         variable=self.generate_report_var)
        gen_report_check.grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)

        # 是否跳过数据库检查
        self.skip_db_check_var = tk.BooleanVar(value=False)
        skip_db_check = ttk.Checkbutton(options_frame, text="跳过数据库检查（避免编码问题）",
                                     variable=self.skip_db_check_var)
        skip_db_check.grid(row=3, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)

        # 控制按钮
        button_frame = ttk.Frame(parent)
        button_frame.pack(pady=10)

        self.scan_button = ttk.Button(button_frame, text="开始扫描", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(button_frame, text="停止扫描", command=self.stop_scan,
                                    state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

    def _create_report_view(self, parent):
        """创建报告显示面板"""
        # 报告选择区域
        report_select_frame = ttk.Frame(parent)
        report_select_frame.pack(fill=tk.X, padx=10, pady=(10, 0))

        ttk.Label(report_select_frame, text="选择报告:").pack(side=tk.LEFT, padx=(0, 5))

        self.report_list_var = tk.StringVar()
        self.report_combo = ttk.Combobox(report_select_frame, textvariable=self.report_list_var, width=50)
        self.report_combo.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.report_combo.bind("<<ComboboxSelected>>", self._on_report_selected)

        refresh_btn = ttk.Button(report_select_frame, text="刷新", command=self._refresh_reports)
        refresh_btn.pack(side=tk.LEFT, padx=5)

        open_folder_btn = ttk.Button(report_select_frame, text="打开报告目录", command=self._open_reports_folder)
        open_folder_btn.pack(side=tk.LEFT, padx=5)

        # 报告内容区域
        report_frame = ttk.LabelFrame(parent, text="报告内容")
        report_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 创建报告树状视图
        columns = ("component", "version", "cve_id", "severity", "description")
        self.report_tree = ttk.Treeview(report_frame, columns=columns, show="headings")

        # 定义列标题
        self.report_tree.heading("component", text="组件")
        self.report_tree.heading("version", text="版本")
        self.report_tree.heading("cve_id", text="CVE ID")
        self.report_tree.heading("severity", text="严重性")
        self.report_tree.heading("description", text="描述")

        # 定义列宽
        self.report_tree.column("component", width=120)
        self.report_tree.column("version", width=80)
        self.report_tree.column("cve_id", width=120)
        self.report_tree.column("severity", width=80)
        self.report_tree.column("description", width=300)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(report_frame, orient=tk.VERTICAL, command=self.report_tree.yview)
        self.report_tree.configure(yscrollcommand=scrollbar.set)

        self.report_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 统计信息区域
        stats_frame = ttk.Frame(parent)
        stats_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        self.stats_var = tk.StringVar(value="没有扫描结果")
        stats_label = ttk.Label(stats_frame, textvariable=self.stats_var)
        stats_label.pack(anchor=tk.W)

    def _create_log_view(self, parent):
        """创建日志显示面板"""
        log_frame = ttk.Frame(parent)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 日志文本框
        self.log_text = tk.Text(log_frame, wrap=tk.WORD, height=20)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 滚动条
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 按钮区域
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        clear_btn = ttk.Button(button_frame, text="清除日志", command=self._clear_log)
        clear_btn.pack(side=tk.RIGHT, padx=5)

    def _on_scan_type_changed(self):
        """处理扫描类型变更"""
        self.file_path_var.set("")  # 清除已选择的路径

    def _browse_target(self):
        """浏览并选择扫描目标"""
        if self.scan_type.get() == "file":
            filenames = filedialog.askopenfilenames(
                title="选择要扫描的文件",
                filetypes=(("安装包", "*.apk *.deb *.rpm *.pkg *.exe"),
                           ("可执行文件", "*.exe *.dll *.so *.dylib"),
                           ("安卓应用", "*.apk"),
                           ("压缩包", "*.zip *.jar *.war"),
                           ("所有文件", "*.*"))
            )
            if filenames:
                # 将多个文件路径转为一个字符串，以分号分隔
                files_str = "; ".join(filenames)
                self.file_path_var.set(files_str if len(files_str) < 100 else f"{len(filenames)}个文件已选择")
                self.target_file = list(filenames)  # 将元组转换为列表
                self.target_dir = None
                self.log(f"已选择{len(filenames)}个文件进行扫描")
        else:  # directory
            dirname = filedialog.askdirectory(title="选择要扫描的目录")
            if dirname:
                self.file_path_var.set(dirname)
                self.target_dir = dirname
                self.target_file = None
                self.log(f"已选择目录进行扫描: {dirname}")

    def _refresh_reports(self):
        """刷新报告列表"""
        try:
            reports = []
            for file in os.listdir(self.reports_dir):
                if file.endswith(".json"):
                    reports.append(file)

            self.report_combo["values"] = reports
            if reports:
                self.report_combo.current(0)
                self._on_report_selected(None)
            else:
                self.stats_var.set("没有可用的报告")
                self._clear_report_tree()
        except Exception as e:
            self.log(f"刷新报告列表出错: {str(e)}", "ERROR")

    def _on_report_selected(self, event):
        """处理报告选择事件"""
        selected_report = self.report_list_var.get()
        if selected_report:
            report_path = os.path.join(self.reports_dir, selected_report)
            self._load_report(report_path)

    def _load_report(self, report_path):
        """加载并显示所选报告"""
        try:
            with open(report_path, 'r', encoding='utf-8') as f:
                report_data = json.load(f)

            self._clear_report_tree()

            # 处理报告数据
            cve_count = 0
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "": 0}

            if "results" in report_data:
                for product in report_data["results"]:
                    for cve in product.get("cves", []):
                        cve_id = cve.get("cve_number", "")
                        severity = cve.get("severity", "").lower()

                        if severity in severity_counts:
                            severity_counts[severity] += 1
                        else:
                            severity_counts[""] += 1

                        cve_count += 1

                        # 添加到树视图
                        self.report_tree.insert("", tk.END, values=(
                            product.get("product", ""),
                            product.get("version", ""),
                            cve_id,
                            severity.capitalize(),
                            cve.get("description", "")[:100] + "..." if len(cve.get("description", "")) > 100 else cve.get("description", "")
                        ))

            # 更新统计信息
            stats_text = f"总计 {cve_count} 个CVE漏洞 "
            if cve_count > 0:
                stats_text += f"(严重: {severity_counts['critical']}, 高危: {severity_counts['high']}, "
                stats_text += f"中危: {severity_counts['medium']}, 低危: {severity_counts['low']})"

            self.stats_var.set(stats_text)

            # 记录日志
            self.log(f"已加载报告: {os.path.basename(report_path)}")

        except Exception as e:
            self.log(f"加载报告出错: {str(e)}", "ERROR")
            messagebox.showerror("错误", f"无法加载报告: {str(e)}")

    def _clear_report_tree(self):
        """清空报告树状视图"""
        for item in self.report_tree.get_children():
            self.report_tree.delete(item)

    def _clear_log(self):
        """清空日志文本框"""
        self.log_text.delete(1.0, tk.END)

    def log(self, message, level="INFO"):
        """向日志文本框添加消息"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] [{level}] {message}\n"

        # 在UI线程上更新日志
        self.root.after(0, lambda: self._append_to_log(log_message))

    def _append_to_log(self, message):
        """将消息追加到日志文本框中"""
        self.log_text.insert(tk.END, message)
        self.log_text.see(tk.END)  # 滚动到底部

    def start_scan(self):
        """开始CVE扫描"""
        if self.is_scanning or self.is_initializing_db:
            return

        # 检查是否已选择目标
        if not self.target_file and not self.target_dir:
            if not self.file_path_var.get():
                messagebox.showwarning("警告", "请先选择要扫描的文件或目录")
                return

            # 如果有路径但未更新target_file或target_dir
            path = self.file_path_var.get()
            if self.scan_type.get() == "file":
                # 检查是否有多个文件（以分号分隔）
                if ";" in path:
                    self.target_file = [p.strip() for p in path.split(";")]
                else:
                    self.target_file = path
                self.target_dir = None
            else:
                self.target_file = None
                self.target_dir = path

        # 获取扫描选项
        scan_target = self.target_file if self.target_file else self.target_dir
        scan_options = {
            'skip_update': self.skip_update_var.get(),
            'report': self.generate_report_var.get(),
            'level': self.scan_level.get(),
            'skip_db_check': self.skip_db_check_var.get()
        }

        # 生成报告文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if isinstance(scan_target, list):  # 多文件
            target_name = f"multiple_files_{len(scan_target)}"
        else:  # 单文件或目录
            target_name = os.path.basename(scan_target)
            if not target_name:  # 如果是根目录
                target_name = "directory"

        self.report_file = os.path.join(self.reports_dir, f"scan_{target_name}_{timestamp}.json")

        # 更新UI状态
        self.is_scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress_bar.start(10)
        self.status_var.set("正在扫描...")

        # 在新线程中运行扫描
        self.scan_thread = threading.Thread(
            target=self._run_scan,
            args=(scan_target, scan_options)
        )
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def _run_scan(self, target, options):
        """在后台线程中运行CVE扫描"""
        try:
            self.log(f"开始扫描: {target}")

            # 设置扫描参数
            self.scanner.set_target(target)
            self.scanner.set_options(options)
            self.scanner.set_report_file(self.report_file)

            # 注册回调函数
            self.scanner.set_log_callback(self.log)

            # 执行扫描
            result = self.scanner.scan()

            # 检查是否有数据库错误且用户未选择跳过数据库检查
            should_try_fix = False
            if not result and not self.skip_db_check_var.get():
                if hasattr(self.scanner, 'last_error') and self.scanner.last_error:
                    last_error = self.scanner.last_error
                    if 'no such table:' in last_error or 'database is locked' in last_error:
                        should_try_fix = True

            # 如果需要尝试修复数据库
            if should_try_fix:
                self.log("检测到数据库错误，尝试自动修复...", "WARNING")

                # 在UI线程上显示数据库修复中
                self.root.after(0, lambda: self.status_var.set("正在修复数据库..."))

                # 尝试初始化数据库
                db_init_result = self.scanner.initialize_database()

                # 如果初始化失败，尝试重置数据库
                if not db_init_result and hasattr(self.scanner, 'reset_database'):
                    self.log("初始化失败，尝试重置数据库...", "WARNING")
                    self.root.after(0, lambda: self.status_var.set("正在重置数据库..."))
                    db_init_result = self.scanner.reset_database()

                if db_init_result:
                    self.log("数据库修复成功，重新开始扫描", "INFO")
                    # 重新执行扫描
                    result = self.scanner.scan()
                else:
                    self.log("数据库修复失败", "ERROR")
                    # 如果自动修复失败，提示用户使用离线模式
                    def show_error_message():
                        messagebox.showinfo(
                            "提示",
                            "由于数据库初始化失败，建议勾选\"跳过数据库检查\"选项进行扫描，或手动重置数据库。"
                        )
                    self.root.after(0, show_error_message)

            # 处理扫描完成
            self.root.after(0, lambda: self._on_scan_completed(result))

        except Exception as e:
            error_msg = str(e)
            self.log(f"扫描错误: {error_msg}", "ERROR")
            self.root.after(0, lambda: self._on_scan_error(error_msg))

    def _on_scan_completed(self, result):
        """扫描完成后的处理"""
        self.is_scanning = False
        self.progress_bar.stop()
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

        if result:
            self.status_var.set("扫描完成")

            # 刷新报告列表并自动选择新生成的报告
            self._refresh_reports()
            if self.report_file:
                report_filename = os.path.basename(self.report_file)
                if report_filename in self.report_combo["values"]:
                    self.report_list_var.set(report_filename)
                    self._on_report_selected(None)

            self.log("扫描完成，结果已保存")
        else:
            self.status_var.set("扫描未完成")

    def _on_scan_error(self, error_msg):
        """处理扫描错误"""
        self.is_scanning = False
        self.progress_bar.stop()
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set("扫描出错")

        messagebox.showerror("扫描错误", f"扫描过程中发生错误:\n{error_msg}")

    def stop_scan(self):
        """停止正在进行的扫描或数据库初始化"""
        if not self.is_scanning and not self.is_initializing_db:
            return

        try:
            # 告知扫描器停止
            if self.scanner:
                self.scanner.stop()

            # 状态更新
            if self.is_scanning:
                self.log("用户请求停止扫描")
                self.status_var.set("正在停止扫描...")
            else:
                self.log("用户请求停止数据库初始化")
                self.status_var.set("正在停止数据库初始化...")

        except Exception as e:
            self.log(f"停止操作出错: {str(e)}", "ERROR")

    def on_closing(self):
        """窗口关闭事件处理"""
        if self.is_scanning:
            if messagebox.askyesno("确认", "正在进行扫描，确定要关闭窗口吗？"):
                self.stop_scan()
                self._cleanup()
                self.root.destroy()
        elif self.is_initializing_db:
            if messagebox.askyesno("确认", "正在初始化数据库，确定要关闭窗口吗？"):
                self.stop_scan()
                self._cleanup()
                self.root.destroy()
        else:
            self._cleanup()
            self.root.destroy()

    def center_window(self):
        """使窗口在屏幕中居中显示"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def _cleanup(self):
        """清理资源"""
        if self.is_scanning or self.is_initializing_db:
            try:
                self.scanner.stop()
            except:
                pass

        self.is_scanning = False
        self.is_initializing_db = False

    def _on_master_destroy(self, event):
        """主窗口关闭时的处理"""
        if event.widget == self.root.master:
            self._cleanup()
            self.root.destroy()

    def _check_tool_version(self):
        """检查cve-bin-tool版本"""
        try:
            result = subprocess.run(
                ["cve-bin-tool", "-V"],
                capture_output=True,
                text=True,
                check=False
            )
            if result.returncode == 0:
                # 尝试从输出中提取版本号
                output = result.stdout.strip()
                import re
                version_match = re.search(r'(\d+\.\d+\.\d+)', output)
                if version_match:
                    self.tool_version = version_match.group(1)
                else:
                    self.tool_version = output

                # 日志记录版本信息
                self.log(f"检测到cve-bin-tool版本: {self.tool_version}")

                # 获取帮助信息用于UI显示
                self._get_tool_help()

                # 检查命令行格式
                try:
                    help_result = subprocess.run(
                        ["cve-bin-tool", "-h"],
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    if "Please specify a directory to scan" in help_result.stdout:
                        self.log("检测到cve-bin-tool命令格式: 目录参数在命令行开头", "INFO")
                    elif "directory" in help_result.stdout and help_result.stdout.strip().endswith("[directory]"):
                        self.log("检测到cve-bin-tool命令格式: 目录参数在命令行末尾", "INFO")
                except:
                    pass
            else:
                self.tool_version = "未安装"
                self.log("未检测到cve-bin-tool，请先安装此工具", "ERROR")
        except FileNotFoundError:
            self.tool_version = "未安装"
            self.log("未找到cve-bin-tool命令，请确保已正确安装", "ERROR")
        except Exception as e:
            self.tool_version = f"错误: {str(e)}"
            self.log(f"检查工具版本出错: {str(e)}", "ERROR")

    def _get_tool_help(self):
        """获取工具帮助信息用于展示"""
        try:
            result = subprocess.run(
                ["cve-bin-tool", "-h"],
                capture_output=True,
                text=True,
                check=False
            )
            if result.returncode == 0:
                # 存储帮助信息
                self.tool_help = result.stdout.strip()

                # 记录帮助信息到日志
                self.log("已加载cve-bin-tool帮助信息")
            else:
                self.tool_help = "无法获取帮助信息"
        except Exception:
            self.tool_help = "无法获取帮助信息"

    def _open_reports_folder(self):
        """打开报告目录"""
        try:
            if sys.platform == 'win32':
                os.startfile(self.reports_dir)
            elif sys.platform == 'darwin':  # macOS
                subprocess.call(['open', self.reports_dir])
            else:  # linux
                subprocess.call(['xdg-open', self.reports_dir])

            self.log(f"已打开报告目录: {self.reports_dir}")
        except Exception as e:
            self.log(f"打开报告目录失败: {str(e)}", "ERROR")
            messagebox.showerror("错误", f"无法打开报告目录: {str(e)}")

    def _show_tool_help(self):
        """显示工具帮助信息对话框"""
        help_window = tk.Toplevel(self.root)
        help_window.title("CVE-Bin-Tool 帮助信息")
        help_window.geometry("800x600")

        # 为对话框添加图标
        if hasattr(self.root, 'iconbitmap') and hasattr(self.root, '_w'):
            try:
                help_window.iconbitmap(self.root.iconbitmap())
            except:
                pass

        # 创建文本区域
        text_frame = ttk.Frame(help_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        help_text = tk.Text(text_frame, wrap=tk.WORD)
        help_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 滚动条
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=help_text.yview)
        help_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 插入帮助信息
        help_text.insert(tk.END, self.tool_help if self.tool_help else "无法获取帮助信息")
        help_text.config(state=tk.DISABLED)  # 设置为只读

        # 关闭按钮
        close_btn = ttk.Button(help_window, text="关闭", command=help_window.destroy)
        close_btn.pack(pady=10)

        # 使对话框成为模态对话框
        help_window.transient(self.root)
        help_window.grab_set()

        # 居中显示
        help_window.update_idletasks()
        width = help_window.winfo_width()
        height = help_window.winfo_height()
        x = (help_window.winfo_screenwidth() // 2) - (width // 2)
        y = (help_window.winfo_screenheight() // 2) - (height // 2)
        help_window.geometry(f'{width}x{height}+{x}+{y}')

    def _initialize_database(self):
        """初始化CVE数据库"""
        if self.is_scanning:
            messagebox.showwarning("警告", "正在进行扫描，请等待扫描完成后再初始化数据库")
            return

        if self.is_initializing_db:
            messagebox.showwarning("警告", "数据库初始化已在进行中")
            return

        answer = messagebox.askyesno("确认", "初始化数据库将会下载最新的CVE数据，这可能需要一些时间。继续操作?")
        if not answer:
            return

        # 禁用按钮，显示进度条
        self.is_initializing_db = True
        self.status_var.set("正在初始化数据库...")
        self.progress_bar.start(10)
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        # 在新线程中运行初始化
        threading.Thread(target=self._run_db_initialization, daemon=True).start()

    def _run_db_initialization(self):
        """在后台线程中运行数据库初始化"""
        try:
            result = self.scanner.initialize_database()

            # 在UI线程中处理结果
            self.root.after(0, lambda: self._on_db_initialization_completed(result))
        except Exception as e:
            error_msg = str(e)
            self.log(f"数据库初始化错误: {error_msg}", "ERROR")
            self.root.after(0, lambda: self._on_db_initialization_error(error_msg))

    def _on_db_initialization_completed(self, result):
        """数据库初始化完成后的处理"""
        self.is_initializing_db = False
        self.progress_bar.stop()
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

        if result:
            self.status_var.set("数据库初始化成功")
            messagebox.showinfo("成功", "CVE数据库已成功初始化，现在可以进行扫描了")
        else:
            self.status_var.set("数据库初始化失败")
            messagebox.showerror("错误", "CVE数据库初始化失败，请查看日志了解详情")

    def _on_db_initialization_error(self, error_msg):
        """数据库初始化错误处理"""
        self.is_initializing_db = False
        self.progress_bar.stop()
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set("数据库初始化错误")
        messagebox.showerror("错误", f"初始化数据库时出错:\n{error_msg}")

    def _reset_database(self):
        """完全重置CVE数据库"""
        if self.is_scanning or self.is_initializing_db:
            messagebox.showwarning("警告", "请先停止当前操作")
            return

        answer = messagebox.askyesno("警告",
            "这将完全删除并重建CVE数据库！\n" +
            "这个操作可能需要较长时间，并会从网络下载CVE数据。\n\n" +
            "确定要继续吗?",
            icon='warning')

        if not answer:
            return

        # 更新UI状态
        self.is_initializing_db = True
        self.status_var.set("正在重置数据库...")
        self.progress_bar.start(10)
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        # 在新线程中运行重置操作
        threading.Thread(target=self._run_db_reset, daemon=True).start()

    def _run_db_reset(self):
        """在后台线程中运行数据库重置"""
        try:
            self.log("开始重置数据库...", "WARNING")
            result = self.scanner.reset_database()

            # 通知UI更新
            self.root.after(0, lambda: self._on_db_reset_completed(result))
        except Exception as e:
            error_msg = str(e)
            self.log(f"重置数据库出错: {error_msg}", "ERROR")
            self.root.after(0, lambda: self._on_db_initialization_error(error_msg))

    def _on_db_reset_completed(self, result):
        """数据库重置完成后的处理"""
        self.is_initializing_db = False
        self.progress_bar.stop()
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

        if result:
            self.status_var.set("数据库重置成功")
            messagebox.showinfo("成功", "CVE数据库已成功重置并初始化")
        else:
            self.status_var.set("数据库重置失败")
            messagebox.showerror(
                "错误",
                "CVE数据库重置失败。\n" +
                "如果持续出现问题，请尝试手动删除数据库目录或勾选\"跳过数据库检查\"选项。"
            )

    def _check_windows_dependencies(self):
        """检查Windows下所需的依赖"""
        try:
            # 需要检查的命令
            commands_to_check = [
                "file",     # 用于识别文件类型
                "strings",  # 用于提取二进制文件中的字符串
                "objdump"   # 用于分析二进制文件
            ]

            missing_commands = []

            # 检查命令是否可用
            for cmd in commands_to_check:
                try:
                    result = subprocess.run(
                        [cmd, "--version"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=2
                    )
                    if result.returncode != 0:
                        missing_commands.append(cmd)
                except:
                    missing_commands.append(cmd)

            if missing_commands:
                self.log(f"警告: 以下工具在Windows上不可用: {', '.join(missing_commands)}", "WARNING")
                self.log("这些工具通常在Linux环境中使用，可能会影响部分扫描功能", "WARNING")
                self.log("建议安装Windows版本的这些工具或使用WSL/MinGW", "WARNING")
            else:
                self.log("Windows兼容性检查通过，所有需要的工具都已安装", "INFO")

        except Exception as e:
            self.log(f"Windows依赖检查失败: {str(e)}", "WARNING")

    def _show_windows_help(self):
        """显示Windows系统下的工具安装帮助"""
        help_window = tk.Toplevel(self.root)
        help_window.title("Windows工具安装帮助")
        help_window.geometry("800x600")

        # 为对话框添加图标
        if hasattr(self.root, 'iconbitmap') and hasattr(self.root, '_w'):
            try:
                help_window.iconbitmap(self.root.iconbitmap())
            except:
                pass

        # 创建文本区域
        text_frame = ttk.Frame(help_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        help_text = tk.Text(text_frame, wrap=tk.WORD)
        help_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 滚动条
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=help_text.yview)
        help_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 帮助内容
        windows_help = """## Windows平台工具安装指南

cve-bin-tool最初是为Linux设计的，在Windows上运行可能需要安装一些额外的工具。以下是几种获取所需工具的方法：

### 1. 安装Windows版本的Unix工具

您需要以下工具:
- file - 用于文件类型识别
- strings - 用于从二进制文件中提取字符串
- objdump - 用于分析可执行文件

### 安装方法:

#### 选项A: 使用MinGW或MSYS2
1. 下载并安装MSYS2: https://www.msys2.org/
2. 打开MSYS2终端，运行:
   ```
   pacman -S mingw-w64-x86_64-binutils
   ```
3. 将MSYS2的bin目录添加到PATH环境变量

#### 选项B: 使用Cygwin
1. 下载并安装Cygwin: https://www.cygwin.com/
2. 在安装过程中选择binutils包
3. 将Cygwin的bin目录添加到PATH环境变量

#### 选项C: 使用WSL (Windows Subsystem for Linux)
1. 安装WSL: https://docs.microsoft.com/en-us/windows/wsl/install
2. 在WSL中运行CVE扫描

### 2. 使用跳过依赖检查选项

如果无法安装这些工具，可以勾选"跳过数据库检查"选项，这将减少对这些工具的依赖，但可能会影响部分扫描功能。

### 3. 使用离线模式

CVE扫描始终会在离线模式下运行，以提高稳定性。如果需要更新CVE数据库，可以使用"初始化数据库"按钮。

如需更多帮助，请参考cve-bin-tool官方文档: https://github.com/intel/cve-bin-tool
"""

        help_text.insert(tk.END, windows_help)
        help_text.config(state=tk.DISABLED)  # 设置为只读

        # 打开网站按钮
        button_frame = ttk.Frame(help_window)
        button_frame.pack(fill=tk.X, padx=10, pady=10)

        msys2_btn = ttk.Button(button_frame, text="访问MSYS2网站",
                              command=lambda: self._open_url("https://www.msys2.org/"))
        msys2_btn.pack(side=tk.LEFT, padx=5)

        cygwin_btn = ttk.Button(button_frame, text="访问Cygwin网站",
                               command=lambda: self._open_url("https://www.cygwin.com/"))
        cygwin_btn.pack(side=tk.LEFT, padx=5)

        wsl_btn = ttk.Button(button_frame, text="WSL安装指南",
                            command=lambda: self._open_url("https://docs.microsoft.com/en-us/windows/wsl/install"))
        wsl_btn.pack(side=tk.LEFT, padx=5)

        # 关闭按钮
        close_btn = ttk.Button(button_frame, text="关闭", command=help_window.destroy)
        close_btn.pack(side=tk.RIGHT, padx=5)

        # 使对话框成为模态对话框
        help_window.transient(self.root)
        help_window.grab_set()

        # 居中显示
        help_window.update_idletasks()
        width = help_window.winfo_width()
        height = help_window.winfo_height()
        x = (help_window.winfo_screenwidth() // 2) - (width // 2)
        y = (help_window.winfo_screenheight() // 2) - (height // 2)
        help_window.geometry(f'{width}x{height}+{x}+{y}')

    def _open_url(self, url):
        """打开URL链接"""
        import webbrowser
        webbrowser.open(url)