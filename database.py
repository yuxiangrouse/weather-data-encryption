"""
数据库模块 - MySQL操作
"""

import mysql.connector
from mysql.connector import Error
import datetime
import logging

logger = logging.getLogger(__name__)


class DatabaseManager:
    """MySQL数据库管理类"""
    
    def __init__(self, config):
        """
        初始化数据库连接
        参数:
            config: 数据库配置字典
        """
        self.config = config
        self.connection = None
        self.cursor = None
    
    def connect(self):
        """
        连接到数据库
        返回:
            True/False
        """
        try:
            self.connection = mysql.connector.connect(**self.config)
            self.cursor = self.connection.cursor()
            print("✓ 数据库连接成功")
            return True
        except Error as e:
            print(f"✗ 数据库连接失败: {e}")
            return False
    
    def disconnect(self):
        """
        断开数据库连接
        """
        if self.connection and self.connection.is_connected():
            self.cursor.close()
            self.connection.close()
            print("✓ 数据库连接已关闭")
    
    def init_database(self):
        """
        初始化数据库表
        返回:
            True/False
        """
        try:
            # 创建数据库
            self.cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.config['database']}")
            self.connection.database = self.config['database']
            
            # 创建气象数据表
            weather_table = """
            CREATE TABLE IF NOT EXISTS weather_data (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp DATETIME NOT NULL,
                location VARCHAR(100) NOT NULL,
                temperature FLOAT NOT NULL,
                humidity FLOAT NOT NULL,
                pressure FLOAT NOT NULL,
                wind_speed FLOAT NOT NULL,
                wind_direction VARCHAR(50),
                precipitation FLOAT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                received_from VARCHAR(50),
                UNIQUE KEY unique_record (timestamp, location)
            )
            """
            self.cursor.execute(weather_table)
            
            # 创建操作日志表
            log_table = """
            CREATE TABLE IF NOT EXISTS operation_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                operation_type VARCHAR(50) NOT NULL,
                operator VARCHAR(50),
                details TEXT,
                status VARCHAR(20),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
            self.cursor.execute(log_table)
            
            # 创建密钥交换日志表
            key_exchange_log = """
            CREATE TABLE IF NOT EXISTS key_exchange_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                client_id VARCHAR(50),
                server_id VARCHAR(50),
                exchange_time DATETIME,
                method VARCHAR(50),
                status VARCHAR(20),
                details TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
            self.cursor.execute(key_exchange_log)
            
            self.connection.commit()
            print("✓ 数据库表初始化成功")
            return True
        except Error as e:
            print(f"✗ 数据库初始化失败: {e}")
            return False
    
    def insert_weather_data(self, data_dict):
        """
        插入气象数据
        参数:
            data_dict: {
                'timestamp': '2024-01-15 10:30:00',
                'location': '北京',
                'temperature': 5.2,
                'humidity': 45.0,
                'pressure': 1013.25,
                'wind_speed': 3.5,
                'wind_direction': '北风',
                'precipitation': 0.0,
                'received_from': '客户端IP'
            }
        返回:
            (success: bool, message: str, record_id: int or None)
        """
        try:
            sql = """
            INSERT INTO weather_data (
                timestamp, location, temperature, humidity, 
                pressure, wind_speed, wind_direction, precipitation, received_from
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            values = (
                data_dict['timestamp'],
                data_dict['location'],
                data_dict['temperature'],
                data_dict['humidity'],
                data_dict['pressure'],
                data_dict['wind_speed'],
                data_dict.get('wind_direction', ''),
                data_dict.get('precipitation', 0),
                data_dict.get('received_from', 'Unknown')
            )
            
            self.cursor.execute(sql, values)
            self.connection.commit()
            record_id = self.cursor.lastrowid
            
            self.log_operation('INSERT_DATA', data_dict.get('received_from', 'Unknown'), 
                             f"插入气象数据: {data_dict['location']}", 'SUCCESS')
            
            return True, f"数据插入成功 (ID: {record_id})", record_id
        except Error as e:
            return False, f"数据插入失败: {str(e)}", None
    
    def query_weather_data(self, location=None, limit=100):
        """
        查询气象数据
        参数:
            location: 位置（可选）
            limit: 查询数量限制
        返回:
            数据列表
        """
        try:
            if location:
                sql = f"SELECT * FROM weather_data WHERE location = %s ORDER BY timestamp DESC LIMIT {limit}"
                self.cursor.execute(sql, (location,))
            else:
                sql = f"SELECT * FROM weather_data ORDER BY timestamp DESC LIMIT {limit}"
                self.cursor.execute(sql)
            
            results = self.cursor.fetchall()
            return results
        except Error as e:
            print(f"查询失败: {e}")
            return []
    
    def log_operation(self, operation_type, operator, details, status):
        """
        记录操作日志
        参数:
            operation_type: 操作类型
            operator: 操作人/操作源
            details: 详细信息
            status: 状态（SUCCESS/FAIL）
        返回:
            True/False
        """
        try:
            sql = """
            INSERT INTO operation_logs (operation_type, operator, details, status)
            VALUES (%s, %s, %s, %s)
            """
            self.cursor.execute(sql, (operation_type, operator, details, status))
            self.connection.commit()
            return True
        except Error as e:
            print(f"日志记录失败: {e}")
            return False
    
    def log_key_exchange(self, client_id, server_id, method, status, details):
        """
        记录密钥交换日志
        参数:
            client_id: 客户端标识
            server_id: 服务端标识
            method: 密钥交换方法（DH、RSA等）
            status: 状态
            details: 详细信息
        返回:
            True/False
        """
        try:
            sql = """
            INSERT INTO key_exchange_logs (client_id, server_id, exchange_time, method, status, details)
            VALUES (%s, %s, %s, %s, %s, %s)
            """
            exchange_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.cursor.execute(sql, (client_id, server_id, exchange_time, method, status, details))
            self.connection.commit()
            return True
        except Error as e:
            print(f"密钥交换日志记录失败: {e}")
            return False
    
    def get_statistics(self):
        """
        获取统计信息
        返回:
            统计数据字典
        """
        try:
            self.cursor.execute("SELECT COUNT(*) FROM weather_data")
            total_records = self.cursor.fetchone()[0]
            
            self.cursor.execute("SELECT COUNT(DISTINCT location) FROM weather_data")
            total_locations = self.cursor.fetchone()[0]
            
            self.cursor.execute("SELECT COUNT(*) FROM operation_logs")
            total_operations = self.cursor.fetchone()[0]
            
            return {
                'total_records': total_records,
                'total_locations': total_locations,
                'total_operations': total_operations
            }
        except Error as e:
            print(f"统计失败: {e}")
            return {}
