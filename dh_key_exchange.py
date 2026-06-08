"""
DH密钥协商模块 - 包含客户端和服务端的密钥交换逻辑
"""

import json
import base64
from crypto_utils import DHKeyExchange, RSAKeyManager, HMACAuth, MessageProtocol


class DHKeyExchangeClient:
    """客户端DH密钥协商"""
    
    def __init__(self, client_private_key):
        """
        初始化客户端
        参数:
            client_private_key: 客户端RSA私钥对象
        """
        self.client_private_key = client_private_key
        self.dh_private_key = None
        self.dh_public_key = None
        self.server_dh_public_key = None
        self.shared_des_key = None
    
    def step1_generate_dh_keys(self):
        """
        第1步：生成DH密钥对
        返回:
            DH公钥（整数）
        """
        self.dh_private_key = DHKeyExchange.generate_private_key()
        self.dh_public_key = DHKeyExchange.generate_public_key(self.dh_private_key)
        return self.dh_public_key
    
    def step2_sign_dh_public_key(self):
        """
        第2步：对DH公钥进行RSA签名
        返回:
            签名数据（Base64字符串）
        """
        dh_pub_str = str(self.dh_public_key)
        signature = RSAKeyManager.rsa_sign(self.client_private_key, dh_pub_str.encode())
        return base64.b64encode(signature).decode('utf-8')
    
    def step3_receive_server_dh_public_key(self, server_dh_public_key_str):
        """
        第3步：接收服务端的DH公钥
        参数:
            server_dh_public_key_str: 服务端DH公钥（字符串）
        返回:
            成功返回True
        """
        self.server_dh_public_key = int(server_dh_public_key_str)
        return True
    
    def step4_compute_shared_key(self):
        """
        第4步：计算共享的DES密钥
        返回:
            DES密钥（字节）
        """
        self.shared_des_key = DHKeyExchange.compute_shared_secret(
            self.dh_private_key,
            self.server_dh_public_key
        )
        return self.shared_des_key
    
    def get_key_exchange_message(self):
        """
        生成密钥交换消息
        返回:
            JSON格式的消息字符串
        """
        signature = self.step2_sign_dh_public_key()
        return MessageProtocol.pack_message('dh_request', {
            'client_dh_public_key': str(self.dh_public_key),
            'client_dh_signature': signature,
            'timestamp': str(__import__('time').time())
        })


class DHKeyExchangeServer:
    """服务端DH密钥协商"""
    
    def __init__(self, server_private_key, client_public_key):
        """
        初始化服务端
        参数:
            server_private_key: 服务端RSA私钥对象
            client_public_key: 客户端RSA公钥对象
        """
        self.server_private_key = server_private_key
        self.client_public_key = client_public_key
        self.dh_private_key = None
        self.dh_public_key = None
        self.client_dh_public_key = None
        self.shared_des_key = None
    
    def step1_generate_dh_keys(self):
        """
        第1步：生成DH密钥对
        返回:
            DH公钥（整数）
        """
        self.dh_private_key = DHKeyExchange.generate_private_key()
        self.dh_public_key = DHKeyExchange.generate_public_key(self.dh_private_key)
        return self.dh_public_key
    
    def step2_verify_client_dh_public_key(self, client_dh_public_key_str, client_signature_b64):
        """
        第2步：验证客户端DH公钥的RSA签名
        参数:
            client_dh_public_key_str: 客户端DH公钥（字符串）
            client_signature_b64: 客户端签名（Base64）
        返回:
            True/False
        """
        try:
            signature = base64.b64decode(client_signature_b64)
            result = RSAKeyManager.rsa_verify(
                self.client_public_key,
                client_dh_public_key_str.encode(),
                signature
            )
            if result:
                self.client_dh_public_key = int(client_dh_public_key_str)
            return result
        except Exception as e:
            print(f"客户端认证失败: {e}")
            return False
    
    def step3_sign_server_dh_public_key(self):
        """
        第3步：对服务端DH公钥进行RSA签名
        返回:
            签名数据（Base64字符串）
        """
        dh_pub_str = str(self.dh_public_key)
        signature = RSAKeyManager.rsa_sign(self.server_private_key, dh_pub_str.encode())
        return base64.b64encode(signature).decode('utf-8')
    
    def step4_compute_shared_key(self):
        """
        第4步：计算共享的DES密钥
        返回:
            DES密钥（字节）
        """
        self.shared_des_key = DHKeyExchange.compute_shared_secret(
            self.dh_private_key,
            self.client_dh_public_key
        )
        return self.shared_des_key
    
    def get_key_exchange_response(self):
        """
        生成密钥交换响应消息
        返回:
            JSON格式的消息字符串
        """
        signature = self.step3_sign_server_dh_public_key()
        return MessageProtocol.pack_message('dh_response', {
            'server_dh_public_key': str(self.dh_public_key),
            'server_dh_signature': signature,
            'timestamp': str(__import__('time').time())
        })
    
    def verify_and_complete_exchange(self, client_message_json, client_public_key):
        """
        验证并完成密钥交换
        参数:
            client_message_json: 客户端的JSON消息
            client_public_key: 客户端公钥
        返回:
            {'success': True/False, 'message': ...}
        """
        try:
            msg = MessageProtocol.unpack_message(client_message_json)
            
            if msg['type'] != 'dh_request':
                return {'success': False, 'message': '无效的消息类型'}
            
            client_dh_pub = msg['content']['client_dh_public_key']
            client_sig = msg['content']['client_dh_signature']
            
            # 验证客户端签名
            if not self.step2_verify_client_dh_public_key(client_dh_pub, client_sig):
                return {'success': False, 'message': '客户端身份认证失败'}
            
            # 计算共享密钥
            self.step4_compute_shared_key()
            
            return {'success': True, 'message': '密钥协商成功'}
        
        except Exception as e:
            return {'success': False, 'message': f'错误: {str(e)}'}
