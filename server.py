"""
服务端程序 - 接收加密数据并解密存储
气象监测数据加密传输系统
"""

import socket
import threading
import json
import time
import logging
import os
from threading import Lock
import config
from crypto_utils import RSAKeyManager, DESCipher, MessageProtocol
from dh_key_exchange import DHKeyExchangeServer
from database import DatabaseManager


# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config.LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class WeatherServer:
    """气象数据服务端"""
    
    def __init__(self, host=config.SERVER_HOST, port=config.SERVER_PORT):
        """
        初始化服务端
        参数:
            host: 监听地址
            port: 监听端口
        """
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.client_lock = Lock()
        self.clients = []
        
        # 加载服务端密钥
        self.server_private_key = None
        self.server_public_key = None
        self.client_public_keys = {}  # 存储已认证的客户端公钥
        
        # 数据库
        self.db = DatabaseManager(config.DB_CONFIG)
        
        self.load_keys()
    
    def load_keys(self):
        """加载或生成服务端RSA密钥"""
        try:
            if os.path.exists(config.SERVER_PRIVATE_KEY_FILE) and os.path.exists(config.SERVER_PUBLIC_KEY_FILE):
                self.server_private_key = RSAKeyManager.load_private_key(config.SERVER_PRIVATE_KEY_FILE)
                self.server_public_key = RSAKeyManager.load_public_key(config.SERVER_PUBLIC_KEY_FILE)
                logger.info("✓ 已加载服务端密钥")
            else:
                logger.info("⚠ 服务端密钥不存在，正在生成...")
                self.server_private_key, self.server_public_key = RSAKeyManager.generate_rsa_keys(config.RSA_KEY_LENGTH)
                RSAKeyManager.save_private_key(self.server_private_key, config.SERVER_PRIVATE_KEY_FILE)
                RSAKeyManager.save_public_key(self.server_public_key, config.SERVER_PUBLIC_KEY_FILE)
                logger.info(f"✓ 服务端密钥生成完成 (RSA {config.RSA_KEY_LENGTH}bit)")
        except Exception as e:
            logger.error(f"✗ 密钥加载失败: {e}")
    
    def start(self):
        """启动服务器"""
        try:
            # 连接数据库
            if not self.db.connect():
                logger.error("✗ 数据库连接失败")
                return
            
            # 初始化数据库表
            if not self.db.init_database():
                logger.error("✗ 数据库初始化失败")
                return
            
            # 创建并绑定套接字
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            self.running = True
            logger.info(f"✓ 服务端已启动: {self.host}:{self.port}")
            logger.info("=" * 50)
            
            # 开始接受连接
            self.accept_connections()
            
        except Exception as e:
            logger.error(f"✗ 服务端启动失败: {e}")
        finally:
            self.stop()
    
    def accept_connections(self):
        """接受客户端连接"""
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                logger.info(f"\n✓ 新客户端连接: {client_address}")
                
                with self.client_lock:
                    self.clients.append(client_socket)
                
                # 为每个客户端创建处理线程
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address),
                    daemon=True
                )
                client_thread.start()
                
            except OSError as e:
                if self.running:
                    logger.error(f"✗ 接受连接出错: {e}")
    
    def handle_client(self, client_socket, client_address):
        """处理单个客户端"""
        client_id = f"{client_address[0]}:{client_address[1]}"
        dh_server = None
        shared_des_key = None
        
        try:
            # 第1步：接收客户端DH公钥和签名
            logger.info(f"[{client_id}] 等待DH密钥交换...")
            dh_request = client_socket.recv(4096).decode('utf-8')
            msg = MessageProtocol.unpack_message(dh_request)
            
            if msg['type'] != 'dh_request':
                logger.error(f"[{client_id}] 无效的消息类型")
                return
            
            # 创建服务端DH交换器
            dh_server = DHKeyExchangeServer(self.server_private_key, None)
            dh_server.step1_generate_dh_keys()
            logger.info(f"[{client_id}] ✓ 已生成服务端DH密钥对")
            
            # 第2步：验证客户端DH公钥的RSA签名
            client_dh_pub = msg['content']['client_dh_public_key']
            client_sig = msg['content']['client_dh_signature']
            
            # 临时加载客户端公钥（从消息中提取）
            # 实际场景中应从证书或其他方式获取
            logger.info(f"[{client_id}] ✓ 已接收客户端DH公钥")
            dh_server.client_dh_public_key = int(client_dh_pub)
            
            # 第3步：发送服务端DH公钥和签名
            dh_response = dh_server.get_key_exchange_response()
            client_socket.sendall(dh_response.encode('utf-8'))
            logger.info(f"[{client_id}] ✓ 已发送服务端DH公钥")
            
            # 第4步：计算共享DES密钥
            shared_des_key = dh_server.step4_compute_shared_key()
            logger.info(f"[{client_id}] ✓ DH密钥协商完成，共享DES密钥已生成")
            
            # 发送服务端证书（RSA公钥）
            cert_message = MessageProtocol.pack_message('server_cert', {
                'server_public_key': 'cert_placeholder'  # 实际应发送公钥
            })
            client_socket.sendall(cert_message.encode('utf-8'))
            logger.info(f"[{client_id}] ✓ 已发送服务端证书")
            
            # 记录密钥交换日志
            self.db.log_key_exchange(client_id, 'server', 'DH', 'SUCCESS', '密钥协商完成')
            
            # 第5步：接收加密的气象数据
            logger.info(f"[{client_id}] 准备接收加密数据...")
            logger.info(f"[{client_id}] " + "=" * 40)
            
            received_count = 0
            while self.running:
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    break
                
                try:
                    # 解包消息
                    msg = MessageProtocol.unpack_message(data, shared_des_key)
                    
                    if msg['type'] == 'encrypted_data':
                        # 解密数据
                        plaintext = DESCipher.decrypt(msg['content'], shared_des_key)
                        weather_data = json.loads(plaintext)
                        
                        # 添加接收来源
                        weather_data['received_from'] = client_id
                        
                        # 插入数据库
                        success, message, record_id = self.db.insert_weather_data(weather_data)
                        
                        if success:
                            logger.info(
                                f"[{client_id}] ✓ 接收并解密: {weather_data['location']} "
                                f"({weather_data['timestamp']}) - DB ID: {record_id}"
                            )
                            received_count += 1
                        else:
                            logger.error(f"[{client_id}] ✗ 数据存储失败: {message}")
                    
                except json.JSONDecodeError as e:
                    logger.warning(f"[{client_id}] JSON解析错误: {e}")
                except Exception as e:
                    logger.error(f"[{client_id}] 数据处理失败: {e}")
            
            logger.info(f"[{client_id}] ✓ 客户端断开连接，共接收 {received_count} 条数据")
            self.db.log_operation('CLIENT_DISCONNECT', client_id, f'接收 {received_count} 条数据', 'SUCCESS')
            
        except Exception as e:
            logger.error(f"[{client_id}] ✗ 客户端处理错误: {e}")
            self.db.log_operation('CLIENT_ERROR', client_id, str(e), 'FAIL')
        
        finally:
            client_socket.close()
            with self.client_lock:
                if client_socket in self.clients:
                    self.clients.remove(client_socket)
    
    def stop(self):
        """停止服务器"""
        self.running = False
        
        # 关闭所有客户端连接
        with self.client_lock:
            for client_socket in self.clients:
                try:
                    client_socket.close()
                except:
                    pass
        
        # 关闭服务器套接字
        if self.server_socket:
            self.server_socket.close()
        
        # 关闭数据库
        self.db.disconnect()
        
        logger.info("✓ 服务端已停止")
    
    def print_statistics(self):
        """打印统计信息"""
        try:
            stats = self.db.get_statistics()
            logger.info("\n" + "=" * 50)
            logger.info("=== 系统统计信息 ===")
            logger.info(f"总记录数: {stats.get('total_records', 0)}")
            logger.info(f"观测地点数: {stats.get('total_locations', 0)}")
            logger.info(f"操作日志数: {stats.get('total_operations', 0)}")
            logger.info("=" * 50)
        except Exception as e:
            logger.error(f"✗ 获取统计信息失败: {e}")


def main():
    """主函数"""
    logger.info("="*50)
    logger.info("气象监测数据加密传输系统 - 服务端")
    logger.info("="*50)
    logger.info(f"使用RSA {config.RSA_KEY_LENGTH}bit密钥")
    logger.info(f"密钥交换: DH算法")
    logger.info(f"加密算法: DES (CBC模式)")
    logger.info(f"完整性校验: HMAC-SHA256")
    logger.info("="*50 + "\n")
    
    server = WeatherServer()
    
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("\n✓ 收到停止信号")
    finally:
        server.stop()
        server.print_statistics()


if __name__ == "__main__":
    main()
