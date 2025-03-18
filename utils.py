import os


def load_certificates(context):
    """加载证书文件"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cert_path = os.path.join(script_dir, "server.crt")
    key_path = os.path.join(script_dir, "server.key")

    # 验证文件存在性
    if not all(os.path.exists(p) for p in [cert_path, key_path]):
        raise FileNotFoundError("证书或密钥文件缺失")

    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return context


def browse_file(self, file_type):
    """浏览并选择证书或密钥文件"""
    from tkinter import filedialog

    file_path = filedialog.askopenfilename(
        title=f"选择{'证书' if file_type == 'cert' else '密钥'}文件",
        filetypes=[("PEM 文件", "*.pem"), ("全部文件", "*.*")]
    )

    if file_path:
        if file_type == "cert":
            self.cert_path_var.set(file_path)
        else:
            self.key_path_var.set(file_path)
