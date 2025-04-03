from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QFrame, QTreeWidget, QTreeWidgetItem, QComboBox, QListWidget,
    QLineEdit, QGroupBox, QFileDialog, QMessageBox
)
from PyQt6.QtCore import QSize, Qt
from gui.base.window_base import WindowBase
import os
from datetime import datetime

class XMLConverterWindow(WindowBase):
    def __init__(self, window_number=None):
        super().__init__()
        # 创建主窗口
        self.window = QMainWindow()
        self.window_number = window_number
        self.window.setWindowTitle(f"XML 工具 {window_number or ''}")
        self.window.resize(800, 600)
        self.window.setMinimumSize(QSize(600, 400))

        # 初始化变量
        self.files = []
        self.encryption_steps = []

        # 创建中央部件
        self.central_widget = QWidget()
        self.window.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        self._create_widgets()
        self.center_window()
        self.window.show()

    def _create_widgets(self):
        # 创建选项卡
        self.notebook = QTabWidget()
        self.main_layout.addWidget(self.notebook)

        # 创建文件处理选项卡
        self.file_tab = QWidget()
        self.notebook.addTab(self.file_tab, "文件处理")
        self._create_file_tab()

        # 创建加密选项卡
        self.encrypt_tab = QWidget()
        self.notebook.addTab(self.encrypt_tab, "加密处理")
        self._create_encrypt_tab()

    def _create_file_tab(self):
        layout = QVBoxLayout(self.file_tab)

        # 文件列表区域
        files_group = QGroupBox("文件列表")
        files_layout = QVBoxLayout(files_group)

        # 文件树形列表
        self.files_tree = QTreeWidget()
        self.files_tree.setHeaderLabels(["文件路径", "大小", "修改日期"])
        self.files_tree.setColumnWidth(0, 400)
        self.files_tree.setColumnWidth(1, 100)
        self.files_tree.setColumnWidth(2, 150)
        files_layout.addWidget(self.files_tree)

        # 按钮区域
        btn_layout = QHBoxLayout()
        add_file_btn = QPushButton("添加文件")
        add_folder_btn = QPushButton("添加文件夹")
        clear_btn = QPushButton("清空列表")

        add_file_btn.clicked.connect(self._add_files)
        add_folder_btn.clicked.connect(self._add_folder)
        clear_btn.clicked.connect(self._clear_files)

        btn_layout.addWidget(add_file_btn)
        btn_layout.addWidget(add_folder_btn)
        btn_layout.addWidget(clear_btn)
        btn_layout.addStretch()
        files_layout.addLayout(btn_layout)

        layout.addWidget(files_group)

        # 提示信息
        hint_label = QLabel("支持拖拽文件或文件夹到此窗口")
        hint_label.setStyleSheet("color: gray")
        layout.addWidget(hint_label)

    def _create_encrypt_tab(self):
        layout = QVBoxLayout(self.encrypt_tab)

        # 加密设置区域
        encrypt_group = QGroupBox("加密设置")
        encrypt_layout = QVBoxLayout(encrypt_group)

        # 加密算法选择
        algo_layout = QHBoxLayout()
        algo_label = QLabel("加密算法:")
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(["base64", "fernet", "sha256"])
        algo_layout.addWidget(algo_label)
        algo_layout.addWidget(self.algo_combo)
        algo_layout.addStretch()
        encrypt_layout.addLayout(algo_layout)

        # 加密步骤列表
        steps_group = QGroupBox("加密步骤")
        steps_layout = QVBoxLayout(steps_group)
        self.steps_list = QListWidget()
        steps_layout.addWidget(self.steps_list)

        # 步骤操作按钮
        steps_btn_layout = QHBoxLayout()
        add_step_btn = QPushButton("添加步骤")
        remove_step_btn = QPushButton("删除步骤")
        clear_steps_btn = QPushButton("清空步骤")

        add_step_btn.clicked.connect(self._add_step)
        remove_step_btn.clicked.connect(self._remove_step)
        clear_steps_btn.clicked.connect(self._clear_steps)

        steps_btn_layout.addWidget(add_step_btn)
        steps_btn_layout.addWidget(remove_step_btn)
        steps_btn_layout.addWidget(clear_steps_btn)
        steps_btn_layout.addStretch()
        steps_layout.addLayout(steps_btn_layout)
        encrypt_layout.addWidget(steps_group)

        # 密钥输入
        key_layout = QHBoxLayout()
        key_label = QLabel("密钥:")
        self.key_input = QLineEdit()
        self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
        key_layout.addWidget(key_label)
        key_layout.addWidget(self.key_input)
        encrypt_layout.addLayout(key_layout)

        # 输出后缀
        suffix_layout = QHBoxLayout()
        suffix_label = QLabel("输出后缀:")
        self.suffix_input = QLineEdit()
        self.suffix_input.setText('.enc')
        suffix_layout.addWidget(suffix_label)
        suffix_layout.addWidget(self.suffix_input)
        encrypt_layout.addLayout(suffix_layout)

        # 加解密按钮
        btn_layout = QHBoxLayout()
        encrypt_btn = QPushButton("加密")
        decrypt_btn = QPushButton("解密")

        encrypt_btn.clicked.connect(self._encrypt_files)
        decrypt_btn.clicked.connect(self._decrypt_files)

        btn_layout.addWidget(encrypt_btn)
        btn_layout.addWidget(decrypt_btn)
        btn_layout.addStretch()
        encrypt_layout.addLayout(btn_layout)

        layout.addWidget(encrypt_group)

    def _add_files(self):
        """添加文件"""
        files, _ = QFileDialog.getOpenFileNames(
            self.window,
            "选择文件",
            "",
            "XML Files (*.xml);;All Files (*.*)"
        )
        self._add_files_to_tree(files)

    def _add_folder(self):
        """添加文件夹"""
        folder = QFileDialog.getExistingDirectory(
            self.window,
            "选择文件夹"
        )
        if folder:
            files = []
            for root, _, filenames in os.walk(folder):
                for filename in filenames:
                    if filename.endswith('.xml'):
                        files.append(os.path.join(root, filename))
            self._add_files_to_tree(files)

    def _add_files_to_tree(self, files):
        """将文件添加到树形列表"""
        for file_path in files:
            if file_path not in self.files:
                self.files.append(file_path)
                file_info = os.stat(file_path)
                size = f"{file_info.st_size / 1024:.2f} KB"
                modified = datetime.fromtimestamp(file_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')

                item = QTreeWidgetItem([file_path, size, modified])
                self.files_tree.addTopLevelItem(item)

    def _clear_files(self):
        """清空文件列表"""
        self.files.clear()
        self.files_tree.clear()

    def _add_step(self):
        """添加加密步骤"""
        algo = self.algo_combo.currentText()
        if algo not in self.encryption_steps:
            self.encryption_steps.append(algo)
            self.steps_list.addItem(algo)

    def _remove_step(self):
        """删除选中的加密步骤"""
        current_row = self.steps_list.currentRow()
        if current_row >= 0:
            item = self.steps_list.takeItem(current_row)
            self.encryption_steps.remove(item.text())

    def _clear_steps(self):
        """清空加密步骤"""
        self.encryption_steps.clear()
        self.steps_list.clear()

    def _encrypt_files(self):
        """加密文件"""
        if not self.files:
            QMessageBox.warning(self.window, "警告", "请先添加文件")
            return
        if not self.encryption_steps:
            QMessageBox.warning(self.window, "警告", "请添加加密步骤")
            return
        QMessageBox.information(self.window, "提示", "加密功能开发中")

    def _decrypt_files(self):
        """解密文件"""
        if not self.files:
            QMessageBox.warning(self.window, "警告", "请先添加文件")
            return
        if not self.encryption_steps:
            QMessageBox.warning(self.window, "警告", "请添加解密步骤")
            return
        QMessageBox.information(self.window, "提示", "解密功能开发中")

    def center_window(self):
        """窗口居中显示"""
        frame = self.window.frameGeometry()
        screen = self.window.screen().availableGeometry().center()
        frame.moveCenter(screen)
        self.window.move(frame.topLeft())

    def close(self):
        """关闭窗口"""
        self.window.close()