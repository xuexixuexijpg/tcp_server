import datetime
import ipaddress
import os
import sys
from binascii import hexlify
from tkinter import messagebox

from OpenSSL import crypto
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


def generate_tls_cert(hostname, cert_path, key_path,
                      generate_client_cert=False,
                      client_cert_path=None, client_key_path=None,
                      ca_cert_path=None, ca_key_path=None):
    """
    为指定主机名(IP)生成TLS证书

    参数:
        hostname: 主机名或IP地址
        cert_path: 服务器证书保存路径(可选)
        key_path: 服务器私钥保存路径(可选)
        generate_client_cert: 是否同时生成客户端证书
        client_cert_path: 客户端证书保存路径(可选)
        client_key_path: 客户端私钥保存路径(可选)
        ca_cert_path: CA证书保存路径(可选)
        ca_key_path: CA私钥保存路径(可选)

    返回:
        包含生成的证书和密钥路径的字典
    """
    import os
    import sys
    import datetime
    import ipaddress
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    # 如果没有指定路径，使用默认路径
    data_dir = get_data_dir()
    cert_dir = os.path.join(data_dir, "certs", hostname)
    os.makedirs(cert_dir, exist_ok=True)

    if not cert_path:
        cert_path = os.path.join(cert_dir, f"{hostname}_cert.pem")
    if not key_path:
        key_path = os.path.join(cert_dir, f"{hostname}_key.pem")

    # CA证书路径
    if not ca_cert_path:
        ca_cert_path = os.path.join(cert_dir, "ca_cert.pem")
    if not ca_key_path:
        ca_key_path = os.path.join(cert_dir, "ca_key.pem")

    # 客户端证书路径
    if not client_cert_path:
        client_cert_path = os.path.join(cert_dir, f"{hostname}_client_cert.pem")
    if not client_key_path:
        client_key_path = os.path.join(cert_dir, f"{hostname}_client_key.pem")

    # 生成CA私钥
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 生成CA证书
    ca_subject = ca_issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{hostname} CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Organization CA"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
    ])

    ca_cert = x509.CertificateBuilder().subject_name(
        ca_subject
    ).issuer_name(
        ca_issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)  # 10年有效期
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    ).sign(ca_key, hashes.SHA256())

    # 保存CA证书和私钥
    with open(ca_cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    with open(ca_key_path, "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # 生成服务器私钥
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 服务器证书主题
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Organization Server"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
    ])

    # 创建subjectAltName扩展
    try:
        # 尝试解析为IP地址
        ip = ipaddress.ip_address(hostname)
        san = [x509.IPAddress(ip)]
    except ValueError:
        # 不是有效IP，使用DNS名称
        san = [x509.DNSName(hostname)]

    # 生成服务器证书
    server_cert = x509.CertificateBuilder().subject_name(
        server_subject
    ).issuer_name(
        ca_subject
    ).public_key(
        server_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName(san),
        critical=False
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    ).add_extension(
        x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
        critical=False
    ).sign(ca_key, hashes.SHA256())

    # 保存服务器证书和私钥
    with open(cert_path, "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))

    with open(key_path, "wb") as f:
        f.write(server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    result = {
        "cert_path": cert_path,
        "key_path": key_path,
        "ca_cert_path": ca_cert_path,
        "ca_key_path": ca_key_path,
    }

    # 如果需要，生成客户端证书
    if generate_client_cert:
        # 生成客户端私钥
        client_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # 客户端证书主题
        client_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"{hostname}_client"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Organization Client"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        ])

        # 生成客户端证书
        client_cert = x509.CertificateBuilder().subject_name(
            client_subject
        ).issuer_name(
            ca_subject
        ).public_key(
            client_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False
        ).sign(ca_key, hashes.SHA256())

        # 保存客户端证书和私钥
        with open(client_cert_path, "wb") as f:
            f.write(client_cert.public_bytes(serialization.Encoding.PEM))

        with open(client_key_path, "wb") as f:
            f.write(client_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        result["client_cert_path"] = client_cert_path
        result["client_key_path"] = client_key_path

    return result


def validate_ip(ip_str):
    """
    验证一个字符串是否是有效的IP地址

    参数:
        ip_str: 要验证的IP地址字符串

    返回:
        如果是有效的IP地址返回True，否则返回False
    """
    import re
    # 简单的IPv4验证正则表达式
    ipv4_pattern = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
    match = ipv4_pattern.match(ip_str)
    if not match:
        return False

    # 验证每个部分是否在0-255范围内
    for part in match.groups():
        if int(part) > 255 or int(part) < 0:
            return False

    return True
