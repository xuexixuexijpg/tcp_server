#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import json
import threading
import tempfile
import shutil
from datetime import datetime
from pathlib import Path

class CVEScanner:
    """CVE扫描器核心类，封装cve-bin-tool功能"""

    def __init__(self):
        self.target = None
        self.options = {
            'skip_update': True,
            'report': True,
            'level': 'default'
        }
        self.report_file = None
        self.process = None
        self.should_stop = False
        self.log_callback = None
        self.last_error = None  # 存储最后一次错误信息

        # 获取数据库目录路径
        self.db_path = self._get_cve_db_path()

    def _get_cve_db_path(self):
        """获取cve-bin-tool数据库目录路径"""
        try:
            # 不同操作系统的缓存目录
            if sys.platform == 'win32':
                base_dir = os.path.join(os.environ.get('LOCALAPPDATA',
                            os.path.expanduser('~\\AppData\\Local')))
            else:
                base_dir = os.path.expanduser('~/.cache')

            return os.path.join(base_dir, 'cvedb')
        except Exception:
            return None

    def reset_database(self):
        """完全重置CVE数据库，删除现有的数据库文件并重新初始化"""
        try:
            self._log("正在重置CVE数据库...")

            # 检查数据库路径
            if not self.db_path or not os.path.exists(self.db_path):
                self._log("无法找到数据库目录，尝试直接初始化", "WARNING")
                return self.initialize_database()

            # 停止任何正在运行的进程
            if self.process:
                try:
                    self.process.terminate()
                    self._log("终止现有进程...", "WARNING")
                except:
                    pass
                self.process = None

            # 备份原始数据库目录（如果需要恢复）
            backup_path = f"{self.db_path}_backup_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            try:
                shutil.copytree(self.db_path, backup_path)
                self._log(f"已创建数据库备份: {backup_path}")
            except Exception as e:
                self._log(f"创建备份失败: {str(e)}", "WARNING")

            # 删除数据库目录
            try:
                shutil.rmtree(self.db_path)
                self._log("已删除现有数据库")
            except Exception as e:
                self._log(f"删除数据库失败: {str(e)}", "ERROR")
                return False

            # 重新创建数据库目录
            os.makedirs(self.db_path, exist_ok=True)

            # 尝试多种方法初始化数据库
            result = self.initialize_database()  # 先尝试主方法
            if not result:
                self._log("主方法初始化失败，尝试备用方法", "WARNING")
                result = self._initialize_database_alt()  # 失败时尝试备用方法

            return result

        except Exception as e:
            self._log(f"重置数据库出错: {str(e)}", "ERROR")
            return False

    def initialize_database(self):
        """初始化CVE数据库，确保数据库结构正确"""
        try:
            self._log("正在初始化CVE数据库...")

            # 重置停止标志
            self.should_stop = False

            # 设置环境变量以确保UTF-8编码
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'
            if os.name == 'nt':  # Windows系统
                env['PYTHONUTF8'] = '1'

            # 创建临时目录作为扫描目标
            temp_dir = tempfile.mkdtemp()
            self._log(f"创建临时目录作为扫描目标: {temp_dir}")

            try:
                # 构建命令 - 包含临时目录参数和更新参数
                cmd = ["cve-bin-tool", temp_dir, "-u", "now"]

                # 启动进程
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                    bufsize=1,
                    encoding='utf-8',  # 明确指定UTF-8编码
                    errors='replace',   # 处理无法解码的字符
                    env=env             # 使用修改后的环境变量
                )

                # 读取输出
                output_lines = []
                for line in iter(self.process.stdout.readline, ''):
                    line = line.strip()
                    if line:
                        self._log(line)
                        output_lines.append(line)

                    # 检查是否应该停止
                    if self.should_stop:
                        self.process.terminate()
                        self._log("数据库初始化已被用户中断", "WARNING")
                        return False

                # 等待进程完成
                return_code = self.process.wait()

                if return_code == 0:
                    self._log("CVE数据库初始化成功")
                    return True
                else:
                    self._log(f"CVE数据库初始化失败，退出代码: {return_code}", "ERROR")

                    # 检查是否是由于缺少参数导致的错误
                    if any("Please specify a directory to scan" in line for line in output_lines):
                        self._log("尝试使用备用方法初始化数据库...", "WARNING")
                        return self._initialize_database_alt()

                    return False
            finally:
                # 清理临时目录
                try:
                    shutil.rmtree(temp_dir)
                    self._log("已清理临时目录")
                except Exception as e:
                    self._log(f"清理临时目录失败: {str(e)}", "WARNING")

        except Exception as e:
            self._log(f"初始化数据库出错: {str(e)}", "ERROR")
            return False
        finally:
            self.process = None

    def _initialize_database_alt(self):
        """使用备用方法初始化数据库（专为新版cve-bin-tool设计）"""
        try:
            self._log("使用备用方法初始化数据库...")

            # 设置环境变量以确保UTF-8编码
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'
            if os.name == 'nt':  # Windows系统
                env['PYTHONUTF8'] = '1'

            # 创建临时文件作为输入文件
            with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.txt') as temp_file:
                temp_file.write("dummy_package 1.0.0")
                temp_file_path = temp_file.name

            try:
                # 使用-i参数指定输入文件，强制更新数据库
                cmd = ["cve-bin-tool", "-i", temp_file_path, "-u", "now"]

                # 启动进程
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                    bufsize=1,
                    encoding='utf-8',
                    errors='replace',
                    env=env
                )

                # 读取输出
                for line in iter(self.process.stdout.readline, ''):
                    line = line.strip()
                    if line:
                        self._log(line)

                    # 检查是否应该停止
                    if self.should_stop:
                        self.process.terminate()
                        self._log("数据库初始化已被用户中断", "WARNING")
                        return False

                # 等待进程完成
                return_code = self.process.wait()

                if return_code == 0:
                    self._log("CVE数据库初始化成功（备用方法）")
                    return True
                else:
                    self._log(f"CVE数据库初始化失败（备用方法），退出代码: {return_code}", "ERROR")
                    return False

            finally:
                # 清理临时文件
                try:
                    os.unlink(temp_file_path)
                except Exception:
                    pass

        except Exception as e:
            self._log(f"备用初始化方法失败: {str(e)}", "ERROR")
            return False
        finally:
            self.process = None

    def set_target(self, target):
        """设置扫描目标"""
        self.target = target

    def set_options(self, options):
        """设置扫描选项"""
        self.options.update(options)

    def set_report_file(self, report_file):
        """设置报告文件路径"""
        self.report_file = report_file

    def set_log_callback(self, callback):
        """设置日志回调函数"""
        self.log_callback = callback

    def _log(self, message, level="INFO"):
        """记录日志"""
        if self.log_callback:
            self.log_callback(message, level)

        # 保存错误信息
        if level == "ERROR":
            self.last_error = message

    def scan(self):
        """执行CVE扫描"""
        # 重置上次错误
        self.last_error = None

        if not self.target:
            self._log("扫描目标未设置", "ERROR")
            return False

        # 检查目标是否存在
        if isinstance(self.target, list):  # 多文件
            missing_files = []
            for file_path in self.target:
                if not os.path.exists(file_path):
                    missing_files.append(file_path)

            if missing_files:
                self._log(f"以下文件不存在: {', '.join(missing_files)}", "ERROR")
                return False
        elif not os.path.exists(self.target):  # 单文件或目录
            self._log(f"扫描目标不存在: {self.target}", "ERROR")
            return False

        # 重置停止标志
        self.should_stop = False

        try:
            # 设置环境变量以确保UTF-8编码
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'
            if os.name == 'nt':  # Windows系统
                env['PYTHONUTF8'] = '1'

            # 构建命令
            cmd = ["cve-bin-tool"]

            # 添加选项 - 选项必须在目标之前添加
            if self.options.get("skip_update", True):
                cmd.extend(["-u", "never"])  # 使用 -u never 替代 --skip-update

            if self.options.get("level") == "detailed":
                cmd.append("--detailed")  # 使用 --detailed 替代 --verbose

            # 强制离线模式，避免数据库问题
            cmd.append("--offline")

            # 如果用户选择了跳过数据库检查，添加额外参数
            if self.options.get("skip_db_check", False):
                cmd.append("--disable-validation-check")

            # Windows系统下增加扫描稳定性的选项
            if sys.platform == 'win32':
                cmd.append("--ignore-sig")  # 忽略签名检查，避免Windows下的错误
                cmd.append("--log-signature-error")  # 仅记录签名错误而非停止扫描

            # 报告文件
            if self.options.get("report", True) and self.report_file:
                cmd.extend(["-f", "json", "-o", self.report_file])

            # 添加扫描目标 - 尝试使用-d参数（适合旧版），如果失败将在运行后重试
            use_d_param = True
            if isinstance(self.target, list):  # 多文件
                if use_d_param:
                    cmd.append("-d")
                for file_path in self.target:
                    cmd.append(file_path)
                self._log(f"正在扫描 {len(self.target)} 个文件...")
            elif os.path.isfile(self.target):  # 单文件
                if use_d_param:
                    cmd.extend(["-d", self.target])
                else:
                    cmd.append(self.target)
                self._log(f"正在扫描文件: {self.target}")
            else:  # 目录
                if use_d_param:
                    cmd.extend(["-d", self.target])
                else:
                    cmd.append(self.target)
                self._log(f"正在扫描目录: {self.target}")

            # 记录命令
            cmd_str = " ".join(cmd)
            self._log(f"执行命令: {cmd_str}")

            # 创建临时文件用于捕获输出
            with tempfile.NamedTemporaryFile(delete=False, mode='w+t', encoding='utf-8') as tmp_out:
                tmp_out_path = tmp_out.name

            # 启动进程
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                encoding='utf-8',  # 明确指定UTF-8编码
                errors='replace',   # 处理无法解码的字符
                env=env             # 使用修改后的环境变量
            )

            # 读取输出
            output_lines = []
            for line in iter(self.process.stdout.readline, ''):
                line = line.strip()
                if line:
                    self._log(line)
                    output_lines.append(line)

                # 检查是否应该停止
                if self.should_stop:
                    self.process.terminate()
                    self._log("扫描已被用户中断", "WARNING")
                    return False

            # 等待进程完成
            return_code = self.process.wait()

            # 处理可能的参数错误 - 如果是参数错误并且我们第一次尝试使用了-d参数，那么尝试不使用-d参数
            if return_code != 0 and use_d_param:
                if any("InsufficientArgs" in line for line in output_lines):
                    self._log("检测到参数错误，尝试使用备用命令格式...", "WARNING")

                    # 重建命令，将目标参数放在最后
                    new_cmd = ["cve-bin-tool"]

                    # 添加选项
                    if self.options.get("skip_update", True):
                        new_cmd.extend(["-u", "never"])

                    if self.options.get("level") == "detailed":
                        new_cmd.append("--detailed")

                    new_cmd.append("--offline")

                    if self.options.get("skip_db_check", False):
                        new_cmd.append("--disable-validation-check")

                    if sys.platform == 'win32':
                        new_cmd.append("--ignore-sig")
                        new_cmd.append("--log-signature-error")

                    if self.options.get("report", True) and self.report_file:
                        new_cmd.extend(["-f", "json", "-o", self.report_file])

                    # 添加扫描目标 (不使用-d参数)
                    if isinstance(self.target, list):
                        for file_path in self.target:
                            new_cmd.append(file_path)
                    else:
                        new_cmd.append(self.target)

                    # 记录新命令
                    new_cmd_str = " ".join(new_cmd)
                    self._log(f"尝试备用命令: {new_cmd_str}")

                    # 启动新进程
                    self.process = subprocess.Popen(
                        new_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        universal_newlines=True,
                        bufsize=1,
                        encoding='utf-8',
                        errors='replace',
                        env=env
                    )

                    # 读取输出
                    output_lines = []
                    for line in iter(self.process.stdout.readline, ''):
                        line = line.strip()
                        if line:
                            self._log(line)
                            output_lines.append(line)

                        if self.should_stop:
                            self.process.terminate()
                            self._log("扫描已被用户中断", "WARNING")
                            return False

                    # 等待进程完成
                    return_code = self.process.wait()

            if return_code == 0:
                self._log("扫描完成")

                # 检查报告文件是否生成
                if self.report_file and os.path.exists(self.report_file):
                    try:
                        with open(self.report_file, 'r', encoding='utf-8') as f:
                            report_data = json.load(f)

                        # 获取CVE统计
                        cve_count = 0
                        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

                        if "results" in report_data:
                            for product in report_data["results"]:
                                cve_count += len(product.get("cves", []))
                                for cve in product.get("cves", []):
                                    severity = cve.get("severity", "").lower()
                                    if severity in severity_counts:
                                        severity_counts[severity] += 1

                        # 记录统计信息
                        self._log(f"扫描发现 {cve_count} 个CVE漏洞")
                        if cve_count > 0:
                            self._log(f"严重性分布: 严重: {severity_counts['critical']}, 高危: {severity_counts['high']}, "
                                   f"中危: {severity_counts['medium']}, 低危: {severity_counts['low']}")
                    except Exception as e:
                        self._log(f"读取报告文件出错: {str(e)}", "ERROR")

                return True
            else:
                error_msg = f"扫描失败，退出代码: {return_code}"
                full_output = "\n".join(output_lines)
                self._log(error_msg, "ERROR")

                # 检查是否有数据库错误
                if "no such table:" in full_output or "database is locked" in full_output:
                    self.last_error = full_output

                return False

        except Exception as e:
            self._log(f"执行扫描时出错: {str(e)}", "ERROR")
            return False
        finally:
            self.process = None

    def stop(self):
        """停止正在进行的扫描"""
        self.should_stop = True
        if self.process:
            try:
                self.process.terminate()
                self._log("正在终止扫描进程...", "WARNING")
            except:
                pass


# 直接运行测试
if __name__ == "__main__":
    def log_callback(message, level="INFO"):
        print(f"[{level}] {message}")

    scanner = CVEScanner()
    scanner.set_log_callback(log_callback)

    # 设置测试目标
    scanner.set_target(sys.argv[1] if len(sys.argv) > 1 else ".")

    # 设置报告文件
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scanner.set_report_file(f"cve_scan_report_{timestamp}.json")

    # 执行扫描
    result = scanner.scan()

    print(f"扫描结果: {'成功' if result else '失败'}")