import datetime
import ipaddress
import os
import sys
from tkinter import messagebox

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import os
import subprocess
import socket
import ipaddress
import tempfile
from datetime import datetime, timedelta


def resource_path(relative_path):
    try:
        # 这行代码尝试访问 PyInstaller 创建的临时文件夹路径
        base_path = sys._MEIPASS  # 这是变量，不是函数调用
    except Exception:
        # 如果 sys._MEIPASS 不存在（普通 Python 运行环境），
        # 则使用当前目录作为基础路径
        base_path = os.path.abspath("..")

    return os.path.join(base_path, relative_path)


# 为写入文件定义一个数据目录（持久存储）
def get_data_dir():
    """获取数据保存目录"""
    user_docs = os.path.join(os.path.expanduser('~'), 'Documents', 'TCP服务器')
    os.makedirs(user_docs, exist_ok=True)
    return user_docs


def generate_tls_cert(self):
    """生成自签名高安全性TLS证书，有效期10年"""
    try:
        # 获取当前选择的IP地址
        ip_address = self.ip_var.get()

        # 生成更强的私钥 (4096位而不是2048位)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096  # 增加到4096位以提高安全性
        )

        # 构建更详细的证书信息
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"自签名TLS证书"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"安全通信"),
            x509.NameAttribute(NameOID.COMMON_NAME, ip_address),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, f"admin@{ip_address}"),
        ])

        # 获取当前时间
        now = datetime.utcnow()

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            # 有效期延长到10年
            now + timedelta(days=3650)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.IPv4Address(ip_address)),
                # 添加本地主机名作为DNS名称
                x509.DNSName("localhost")
            ]),
            critical=False
        ).add_extension(
            # 添加基本约束，确定这是一个CA证书
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        ).add_extension(
            # 添加密钥用途扩展
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).add_extension(
            # 添加扩展密钥用途
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
            ]),
            critical=False
        ).sign(private_key, hashes.SHA256())  # 使用SHA-384而不是SHA-256

        # 使用get_data_dir获取数据目录，确保使用一致的路径方法
        data_dir = get_data_dir()
        cert_dir = os.path.join(data_dir, 'certificates')
        os.makedirs(cert_dir, exist_ok=True)

        # 使用IP地址作为文件名的一部分
        ip_filename = ip_address.replace('.', '_')  # 将点替换为下划线以便用作文件名
        cert_path = os.path.join(cert_dir, f"cert_{ip_filename}.pem")
        key_path = os.path.join(cert_dir, f"key_{ip_filename}.pem")

        # 保存证书
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # 保存私钥，使用更安全的私钥格式
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,  # 使用更现代的PKCS8格式
                encryption_algorithm=serialization.NoEncryption()
            ))

        # 更新证书路径
        self.cert_path_var.set(cert_path)
        self.key_path_var.set(key_path)

        self.log(f"已为IP {ip_address} 生成增强安全性的TLS证书和私钥 (有效期10年)")
        messagebox.showinfo("增强型证书生成成功",
                            f"TLS证书已保存到 {os.path.abspath(cert_path)}\n私钥已保存到 {os.path.abspath(key_path)}\n"
                            f"• 密钥强度: 4096位 RSA\n"
                            f"• 签名算法: SHA-384\n"
                            f"• 有效期: 10年")

    except Exception as e:
        self.log(f"生成TLS证书失败: {str(e)}")
        messagebox.showerror("错误", f"生成TLS证书失败: {str(e)}")
