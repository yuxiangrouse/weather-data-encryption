"""
加密工具模块 - DES、RSA、HMAC、DH密钥协商
"""

import os
import hmac
import hashlib
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import json
import base64


class RSAKeyManager:
    """RSA密钥管理类"""
    
    @staticmethod
    def generate_rsa_keys(key_length=1024):
        """
        生成RSA密钥对
        参数:
            key_length: 密钥长度（比特）
        返回:
            (private_key, public_key): RSA密钥对
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_length,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def save_private_key(private_key, file_path, password=None):
        """
        保存私钥到文件
        参数:
            private_key: RSA私钥对象
            file_path: 文件路径
            password: 私钥密码（可选）
        """
        encryption_algorithm = serialization.NoEncryption()
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        with open(file_path, 'wb') as f:
            f.write(pem)
    
    @staticmethod
    def save_public_key(public_key, file_path):
        """
        保存公钥到文件
        参数:
            public_key: RSA公钥对象
            file_path: 文件路径
        """
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(file_path, 'wb') as f:
            f.write(pem)
    
    @staticmethod
    def load_private_key(file_path, password=None):
        """
        从文件加载私钥
        参数:
            file_path: 文件路径
            password: 私钥密码（可选）
        返回:
            RSA私钥对象
        """
        with open(file_path, 'rb') as f:
            pem = f.read()
        password_bytes = password.encode() if password else None
        return serialization.load_pem_private_key(
            pem,
            password=password_bytes,
            backend=default_backend()
        )
    
    @staticmethod
    def load_public_key(file_path):
        """
        从文件加载公钥
        参数:
            file_path: 文件路径
        返回:
            RSA公钥对象
        """
        with open(file_path, 'rb') as f:
            pem = f.read()
        return serialization.load_pem_public_key(
            pem,
            backend=default_backend()
        )
    
    @staticmethod
    def rsa_sign(private_key, data):
        """
        RSA签名
        参数:
            private_key: RSA私钥对象
            data: 待签名数据（字节）
        返回:
            签名（字节）
        """
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    @staticmethod
    def rsa_verify(public_key, data, signature):
        """
        RSA验证签名
        参数:
            public_key: RSA公钥对象
            data: 原始数据（字节）
            signature: 签名（字节）
        返回:
            True/False: 验证结果
        """
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"签名验证失败: {e}")
            return False
    
    @staticmethod
    def rsa_encrypt(public_key, data):
        """
        RSA公钥加密
        参数:
            public_key: RSA公钥对象
            data: 待加密数据（字节）
        返回:
            加密数据（字节）
        """
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    
    @staticmethod
    def rsa_decrypt(private_key, ciphertext):
        """
        RSA私钥解密
        参数:
            private_key: RSA私钥对象
            ciphertext: 待解密数据（字节）
        返回:
            解密数据（字节）
        """
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext


class DESCipher:
    """DES加密/解密类"""
    
    @staticmethod
    def generate_key():
        """
        生成DES密钥（8字节）
        返回:
            密钥（字节）
        """
        return get_random_bytes(8)
    
    @staticmethod
    def encrypt(plaintext, key):
        """
        DES加密（CBC模式）
        参数:
            plaintext: 明文（字符串或字节）
            key: DES密钥（8字节）
        返回:
            {
                'iv': IV值（Base64），
                'ciphertext': 密文（Base64）
            }
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        iv = get_random_bytes(8)
        cipher = DES.new(key, DES.MODE_CBC, iv)
        padded_plaintext = pad(plaintext, DES.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        
        return {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }
    
    @staticmethod
    def decrypt(encrypted_data, key):
        """
        DES解密（CBC模式）
        参数:
            encrypted_data: {'iv': ..., 'ciphertext': ...}
            key: DES密钥（8字节）
        返回:
            明文（字符串）
        """
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        
        cipher = DES.new(key, DES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, DES.block_size)
        
        return plaintext.decode('utf-8')


class HMACAuth:
    """HMAC消息认证类"""
    
    @staticmethod
    def generate_hmac(data, key):
        """
        生成HMAC验证码
        参数:
            data: 数据（字节或字符串）
            key: HMAC密钥（字节或字符串）
        返回:
            HMAC值（十六进制字符串）
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        h = hmac.new(key, data, hashlib.sha256)
        return h.hexdigest()
    
    @staticmethod
    def verify_hmac(data, key, hmac_value):
        """
        验证HMAC值
        参数:
            data: 原始数据
            key: HMAC密钥
            hmac_value: 待验证的HMAC值
        返回:
            True/False
        """
        computed_hmac = HMACAuth.generate_hmac(data, key)
        return hmac.compare_digest(computed_hmac, hmac_value)


class DHKeyExchange:
    """DH密钥协商类"""
    
    # 使用标准的DH参数（IETF RFC 3526）
    # 这里使用简化版本用于演示
    DH_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
    DH_G = 2
    
    @staticmethod
    def generate_private_key():
        """
        生成DH私钥
        返回:
            私钥（整数）
        """
        import secrets
        return secrets.randbelow(DHKeyExchange.DH_P - 1) + 1
    
    @staticmethod
    def generate_public_key(private_key):
        """
        生成DH公钥
        参数:
            private_key: 私钥（整数）
        返回:
            公钥（整数）
        """
        return pow(DHKeyExchange.DH_G, private_key, DHKeyExchange.DH_P)
    
    @staticmethod
    def compute_shared_secret(private_key, peer_public_key):
        """
        计算共享密钥
        参数:
            private_key: 本方私钥
            peer_public_key: 对方公钥
        返回:
            共享密钥（字节）
        """
        shared_secret_int = pow(peer_public_key, private_key, DHKeyExchange.DH_P)
        # 将共享密钥转换为字节，并截取前8字节作为DES密钥
        shared_secret_bytes = shared_secret_int.to_bytes(128, byteorder='big')
        # 使用SHA256生成确定性的8字节密钥
        import hashlib
        des_key = hashlib.sha256(shared_secret_bytes).digest()[:8]
        return des_key


class MessageProtocol:
    """消息协议类 - 打包/解包"""
    
    @staticmethod
    def pack_message(msg_type, content, hmac_key=None):
        """
        打包消息
        参数:
            msg_type: 消息类型（'dh_pub', 'encrypted_data', 'auth', 等）
            content: 消息内容（字典）
            hmac_key: HMAC密钥（用于添加完整性校验）
        返回:
            JSON字符串
        """
        message = {
            'type': msg_type,
            'content': content
        }
        
        json_str = json.dumps(message, default=str)
        
        if hmac_key:
            hmac_value = HMACAuth.generate_hmac(json_str, hmac_key)
            message['hmac'] = hmac_value
            json_str = json.dumps(message, default=str)
        
        return json_str
    
    @staticmethod
    def unpack_message(json_str, hmac_key=None):
        """
        解包消息
        参数:
            json_str: JSON字符串
            hmac_key: HMAC密钥（用于验证）
        返回:
            {'type': ..., 'content': ...}
        """
        message = json.loads(json_str)
        
        if hmac_key and 'hmac' in message:
            hmac_value = message.pop('hmac')
            json_check = json.dumps(message, default=str)
            if not HMACAuth.verify_hmac(json_check, hmac_key):
                raise ValueError("消息HMAC验证失败，消息可能被篡改")
        
        return {'type': message['type'], 'content': message['content']}
