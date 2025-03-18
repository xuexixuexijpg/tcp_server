import datetime
import ipaddress
import os
import sys
from tkinter import messagebox

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa


def resource_path(relative_path):
    try:
        # 这行代码尝试访问 PyInstaller 创建的临时文件夹路径
        base_path = sys._MEIPASS  # 这是变量，不是函数调用
    except Exception:
        # 如果 sys._MEIPASS 不存在（普通 Python 运行环境），
        # 则使用当前目录作为基础路径
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


# 为写入文件定义一个数据目录（持久存储）
def get_data_dir():
    """获取数据保存目录"""
    user_docs = os.path.join(os.path.expanduser('~'), 'Documents', 'TCP服务器')
    os.makedirs(user_docs, exist_ok=True)
    return user_docs


def generate_tls_cert(self):
    """生成自签名TLS证书"""
    try:
        # 获取当前选择的IP地址
        ip_address = self.ip_var.get()

        # 生成私钥
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # 构建证书
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"自签名TLS证书"),
            x509.NameAttribute(NameOID.COMMON_NAME, ip_address),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # 有效期一年
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address(ip_address))]),
            critical=False
        ).sign(private_key, hashes.SHA256())

        # 创建数据目录
        data_dir = os.path.join(os.path.expanduser('~'), 'Documents', 'TCP服务器', 'certificates')
        os.makedirs(data_dir, exist_ok=True)

        # 使用IP地址作为文件名的一部分
        ip_filename = ip_address.replace('.', '_')  # 将点替换为下划线以便用作文件名
        cert_path = os.path.join(data_dir, f"cert_{ip_filename}.pem")
        key_path = os.path.join(data_dir, f"key_{ip_filename}.pem")

        # 保存证书和私钥
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # 更新证书路径
        self.cert_path_var.set(cert_path)
        self.key_path_var.set(key_path)

        self.log(f"已为IP {ip_address} 生成TLS证书和私钥")
        messagebox.showinfo("证书生成成功",
                            f"TLS证书已保存到 {os.path.abspath(cert_path)}\n私钥已保存到 {os.path.abspath(key_path)}")

    except Exception as e:
        self.log(f"生成TLS证书失败: {str(e)}")
        messagebox.showerror("错误", f"生成TLS证书失败: {str(e)}")
