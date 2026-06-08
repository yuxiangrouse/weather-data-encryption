"""
配置文件 - 气象数据加密传输系统
"""

# ============ 服务器配置 ============
SERVER_HOST = 'localhost'
SERVER_PORT = 9999

# ============ MySQL数据库配置 ============
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '123456',  # 请修改为您的MySQL密码
    'database': 'weather_db',
    'port': 3306
}

# ============ RSA密钥配置 ============
RSA_KEY_LENGTH = 1024  # RSA密钥长度：1024比特

# ============ DES密钥配置 ============
DES_BLOCK_SIZE = 8  # DES块大小

# ============ 超时配置 ============
SOCKET_TIMEOUT = 30  # 套接字超时（秒）

# ============ 日志配置 ============
LOG_LEVEL = 'INFO'
LOG_FILE = 'weather_system.log'

# ============ 密钥文件路径 ============
CLIENT_PRIVATE_KEY_FILE = 'client_private.pem'
CLIENT_PUBLIC_KEY_FILE = 'client_public.pem'
SERVER_PRIVATE_KEY_FILE = 'server_private.pem'
SERVER_PUBLIC_KEY_FILE = 'server_public.pem'

# ============ GUI配置 ============
WINDOW_WIDTH = 900
WINDOW_HEIGHT = 700
WINDOW_TITLE = '气象监测数据加密传输系统 - 客户端'

# ============ CSV配置 ============
CSV_ENCODING = 'utf-8'
CSV_DELIMITER = ','
