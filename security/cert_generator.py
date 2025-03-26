import ipaddress
import os

from OpenSSL import crypto

def generate_tls_cert_openssl(hostname, cert_path, key_path,
                      generate_client_cert=False,
                      client_cert_path=None, client_key_path=None,
                      ca_cert_path=None, ca_key_path=None):
    """使用 OpenSSL crypto 生成 TLS 证书"""
    try:
        # 创建证书目录
        os.makedirs(os.path.dirname(cert_path), exist_ok=True)

        # 生成 CA 密钥
        ca_key = crypto.PKey()
        ca_key.generate_key(crypto.TYPE_RSA, 4096)

        # 生成 CA 证书
        ca_cert = crypto.X509()
        ca_cert.get_subject().C = "CN"
        ca_cert.get_subject().ST = "State"
        ca_cert.get_subject().L = "City"
        ca_cert.get_subject().O = "TCP Server CA"
        ca_cert.get_subject().CN = hostname
        ca_cert.set_serial_number(0)
        ca_cert.gmtime_adj_notBefore(0)
        ca_cert.gmtime_adj_notAfter(365*24*60*60*10)  # 10年有效期
        ca_cert.set_issuer(ca_cert.get_subject())
        ca_cert.set_pubkey(ca_key)
        ca_cert.add_extensions([
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert)
        ])
        ca_cert.sign(ca_key, 'sha256')

        # 生成服务器密钥
        server_key = crypto.PKey()
        server_key.generate_key(crypto.TYPE_RSA, 2048)

        # 生成服务器证书
        server_cert = crypto.X509()
        server_cert.get_subject().C = "CN"
        server_cert.get_subject().ST = "State"
        server_cert.get_subject().L = "City"
        server_cert.get_subject().O = "TCP Server"
        server_cert.get_subject().CN = hostname
        server_cert.set_serial_number(1)
        server_cert.gmtime_adj_notBefore(0)
        server_cert.gmtime_adj_notAfter(365*24*60*60*10)  # 10年有效期
        server_cert.set_issuer(ca_cert.get_subject())
        server_cert.set_pubkey(server_key)

        # 添加 SAN 扩展
        alt_names = [b"DNS:" + hostname.encode()]
        try:
            ip = ipaddress.ip_address(hostname)
            alt_names.append(b"IP:" + str(ip).encode())
        except ValueError:
            pass

        server_cert.add_extensions([
            crypto.X509Extension(b"basicConstraints", True, b"CA:FALSE"),
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=server_cert),
            crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert),
            crypto.X509Extension(b"subjectAltName", False, b", ".join(alt_names))
        ])
        server_cert.sign(ca_key, 'sha256')

        # 保存证书和私钥
        with open(cert_path, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, server_cert))
        with open(key_path, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, server_key))
        with open(ca_cert_path, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))
        with open(ca_key_path, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))

        result = {
            "cert_path": cert_path,
            "key_path": key_path,
            "ca_cert_path": ca_cert_path,
            "ca_key_path": ca_key_path
        }

        # 如果需要生成客户端证书
        if generate_client_cert:
            # 生成客户端密钥
            client_key = crypto.PKey()
            client_key.generate_key(crypto.TYPE_RSA, 2048)

            # 生成客户端证书
            client_cert = crypto.X509()
            client_cert.get_subject().C = "CN"
            client_cert.get_subject().ST = "State"
            client_cert.get_subject().L = "City"
            client_cert.get_subject().O = "TCP Client"
            client_cert.get_subject().CN = "client"
            client_cert.set_serial_number(2)
            client_cert.gmtime_adj_notBefore(0)
            client_cert.gmtime_adj_notAfter(365*24*60*60*10)  # 10年有效期
            client_cert.set_issuer(ca_cert.get_subject())
            client_cert.set_pubkey(client_key)
            client_cert.add_extensions([
                crypto.X509Extension(b"basicConstraints", True, b"CA:FALSE"),
                crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=client_cert),
                crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert)
            ])
            client_cert.sign(ca_key, 'sha256')

            # 保存客户端证书和私钥
            with open(client_cert_path, "wb") as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, client_cert))
            with open(client_key_path, "wb") as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, client_key))

            result.update({
                "client_cert_path": client_cert_path,
                "client_key_path": client_key_path
            })

        return result

    except Exception as e:
        raise Exception(f"生成证书时出错: {str(e)}")