import os
import socket
import ipaddress
import threading
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# 用于在线程之间通信的回调函数类型
"""
回调函数格式:
- on_success(cert_path, key_path): 证书生成成功时调用
- on_error(error_message): 发生错误时调用
- on_progress(message): 生成过程中的进度更新
"""


def is_ip_address(value):
    """
    检查给定的值是否为有效的IP地址

    参数:
    - value: 要检查的字符串

    返回:
    - bool: 如果是有效的IPv4或IPv6地址则返回True，否则返回False
    """
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def generate_cert_for_ip(ip_or_hostname, output_dir, on_success=None, on_error=None, on_progress=None):
    """
    为IP地址或主机名生成自签名证书（后台线程版本）

    参数:
    - ip_or_hostname: IP地址或主机名
    - output_dir: 输出目录
    - on_success: 成功回调函数 - on_success(cert_file, key_file)
    - on_error: 错误回调函数 - on_error(error_message)
    - on_progress: 进度更新回调函数 - on_progress(message)
    """
    # 创建一个后台线程执行生成操作
    thread = threading.Thread(
        target=_generate_cert_thread,
        args=(ip_or_hostname, output_dir, on_success, on_error, on_progress)
    )
    thread.daemon = True
    thread.start()
    return thread


def _generate_cert_thread(ip_or_hostname, output_dir, on_success, on_error, on_progress):
    """在线程中执行证书生成操作"""
    try:
        if on_progress:
            on_progress(f"开始为 {ip_or_hostname} 生成证书...")

        # 确保输出目录存在
        os.makedirs(output_dir, exist_ok=True)

        # 确定证书和密钥文件名 - 保持原有的命名方式
        cert_file = os.path.join(output_dir, f"{ip_or_hostname}.crt")
        key_file = os.path.join(output_dir, f"{ip_or_hostname}.key")

        if on_progress:
            on_progress("生成私钥...")

        # 生成私钥
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        if on_progress:
            on_progress("准备证书主题信息...")

        # 准备SAN扩展内容
        alt_names = []

        # 添加IP地址或DNS名称
        if is_ip_address(ip_or_hostname):
            alt_names.append(x509.IPAddress(ipaddress.ip_address(ip_or_hostname)))
            # 如果是IP，也尝试添加对应的主机名
            if ip_or_hostname != "127.0.0.1":
                try:
                    if on_progress:
                        on_progress("解析主机名...")
                    hostname = socket.gethostbyaddr(ip_or_hostname)[0]
                    alt_names.append(x509.DNSName(hostname))
                except:
                    if on_progress:
                        on_progress("无法解析主机名，仅使用IP地址")
                    pass
        else:
            alt_names.append(x509.DNSName(ip_or_hostname))

        # 总是添加localhost和127.0.0.1
        if ip_or_hostname != "localhost":
            alt_names.append(x509.DNSName("localhost"))
        if ip_or_hostname != "127.0.0.1":
            alt_names.append(x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")))

        if on_progress:
            on_progress("构建证书...")

        # 构建证书
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"自签名TLS证书"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"IT Department"),
            x509.NameAttribute(NameOID.COMMON_NAME, ip_or_hostname),
        ])

        cert_builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            # 有效期一年
            datetime.utcnow() + timedelta(days=365)
        )

        # 添加SAN扩展
        if alt_names:
            if on_progress:
                on_progress("添加主体备用名称扩展...")
            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName(alt_names),
                critical=False
            )

        # 添加密钥用途扩展
        if on_progress:
            on_progress("添加密钥用途扩展...")
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )

        # 添加扩展密钥用途
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False
        )

        # 签署证书
        if on_progress:
            on_progress("签署证书...")
        certificate = cert_builder.sign(private_key, hashes.SHA256())

        # 保存证书到文件
        if on_progress:
            on_progress("保存证书到文件...")
        with open(cert_file, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

        # 保存私钥到文件
        if on_progress:
            on_progress("保存私钥到文件...")
        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        if on_progress:
            on_progress(f"证书生成完成: {cert_file}")

        # 调用成功回调
        if on_success:
            on_success(cert_file, key_file)

    except Exception as e:
        # 调用错误回调
        if on_error:
            on_error(str(e))
        else:
            print(f"证书生成失败: {e}")


def generate_cert_sync(ip_or_hostname, output_dir):
    """
    同步版本的证书生成函数（用于需要立即获取结果的场景）

    参数:
    - ip_or_hostname: IP地址或主机名
    - output_dir: 输出目录

    返回:
    - (cert_file, key_file): 证书文件和密钥文件的路径，失败则返回(None, None)
    """
    result = {"cert": None, "key": None, "error": None}

    def on_success(cert_file, key_file):
        result["cert"] = cert_file
        result["key"] = key_file

    def on_error(error_message):
        result["error"] = error_message

    # 创建线程并等待完成
    thread = _generate_cert_thread(ip_or_hostname, output_dir, on_success, on_error, None)
    thread.join()  # 等待线程完成

    if result["error"]:
        raise Exception(result["error"])

    return result["cert"], result["key"]


# 测试函数
if __name__ == "__main__":
    # 示例用法
    def success_callback(cert, key):
        print(f"证书生成成功！\n证书: {cert}\n密钥: {key}")


    def error_callback(error):
        print(f"生成失败: {error}")


    def progress_callback(message):
        print(f"进度: {message}")


    # 测试异步生成
    generate_cert_for_ip(
        "127.0.0.1",
        "./certificates",
        on_success=success_callback,
        on_error=error_callback,
        on_progress=progress_callback
    )

    # 等待测试完成
    import time

    time.sleep(10)
