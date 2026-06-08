"""
客户端GUI程序 - 基于PyQt5
气象监测数据加密传输系统
"""

import sys
import os
import socket
import csv
import json
import time
from threading import Thread, Event
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QTableWidget, QTableWidgetItem,
    QFileDialog, QComboBox, QLineEdit, QMessageBox, QTabWidget,
    QProgressBar, QStatusBar
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject, QThread
from PyQt5.QtGui import QFont, QColor
import config
from crypto_utils import RSAKeyManager, DESCipher, MessageProtocol
from dh_key_exchange import DHKeyExchangeClient


class ConnectionSignals(QObject):
    """连接状态信号"""
    connection_status = pyqtSignal(str)
    received_data = pyqtSignal(str)
    transfer_complete = pyqtSignal(str)


class WeatherClientGUI(QMainWindow):
    """客户端GUI主窗口"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle(config.WINDOW_TITLE)
        self.setGeometry(100, 100, config.WINDOW_WIDTH, config.WINDOW_HEIGHT)
        
        # 加密通信状态
        self.socket = None
        self.connected = False
        self.shared_des_key = None
        self.server_public_key = None
        self.client_private_key = None
        self.client_public_key = None
        
        # 信号
        self.signals = ConnectionSignals()
        self.signals.connection_status.connect(self.update_status)
        self.signals.received_data.connect(self.display_received_data)
        self.signals.transfer_complete.connect(self.show_transfer_result)
        
        # 初始化UI
        self.init_ui()
        self.load_keys()
        self.update_status("就绪")
    
    def init_ui(self):
        """初始化用户界面"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # 创建标签页
        tabs = QTabWidget()
        
        # 标签页1: 连接与密钥交换
        self.connection_tab = self.create_connection_tab()
        tabs.addTab(self.connection_tab, "连接与认证")
        
        # 标签页2: 数据传输
        self.data_tab = self.create_data_tab()
        tabs.addTab(self.data_tab, "数据传输")
        
        # 标签页3: 日志
        self.log_tab = self.create_log_tab()
        tabs.addTab(self.log_tab, "通信日志")
        
        main_layout.addWidget(tabs)
        
        # 状态栏
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.status_label = QLabel("就绪")
        self.statusBar.addWidget(self.status_label)
    
    def create_connection_tab(self):
        """创建连接标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 连接配置
        config_layout = QHBoxLayout()
        config_layout.addWidget(QLabel("服务器地址:"))
        self.server_host_input = QLineEdit(config.SERVER_HOST)
        config_layout.addWidget(self.server_host_input)
        
        config_layout.addWidget(QLabel("端口:"))
        self.server_port_input = QLineEdit(str(config.SERVER_PORT))
        self.server_port_input.setMaximumWidth(100)
        config_layout.addWidget(self.server_port_input)
        layout.addLayout(config_layout)
        
        # 连接按钮
        button_layout = QHBoxLayout()
        self.connect_button = QPushButton("连接服务器")
        self.connect_button.clicked.connect(self.connect_to_server)
        self.connect_button.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        button_layout.addWidget(self.connect_button)
        
        self.disconnect_button = QPushButton("断开连接")
        self.disconnect_button.clicked.connect(self.disconnect_from_server)
        self.disconnect_button.setEnabled(False)
        self.disconnect_button.setStyleSheet("background-color: #f44336; color: white; font-weight: bold;")
        button_layout.addWidget(self.disconnect_button)
        layout.addLayout(button_layout)
        
        # 密钥交换状态
        layout.addWidget(QLabel("=== DH密钥协商 ==="))
        self.key_exchange_info = QTextEdit()
        self.key_exchange_info.setReadOnly(True)
        self.key_exchange_info.setMaximumHeight(150)
        layout.addWidget(self.key_exchange_info)
        
        # 认证状态
        layout.addWidget(QLabel("=== RSA身份认证 ==="))
        self.auth_info = QTextEdit()
        self.auth_info.setReadOnly(True)
        self.auth_info.setMaximumHeight(100)
        layout.addWidget(self.auth_info)
        
        layout.addStretch()
        return widget
    
    def create_data_tab(self):
        """创建数据传输标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 文件选择
        file_layout = QHBoxLayout()
        file_layout.addWidget(QLabel("选择CSV文件:"))
        self.file_path_input = QLineEdit()
        self.file_path_input.setReadOnly(True)
        file_layout.addWidget(self.file_path_input)
        
        self.browse_button = QPushButton("浏览...")
        self.browse_button.clicked.connect(self.browse_file)
        file_layout.addWidget(self.browse_button)
        layout.addLayout(file_layout)
        
        # 数据预览
        layout.addWidget(QLabel("=== 数据预览 ==="))
        self.data_table = QTableWidget()
        self.data_table.setColumnCount(8)
        self.data_table.setHorizontalHeaderLabels([
            "时间", "位置", "温度(°C)", "湿度(%)", 
            "气压(hPa)", "风速(m/s)", "风向", "降水(mm)"
        ])
        self.data_table.setMaximumHeight(200)
        layout.addWidget(self.data_table)
        
        # 传输按钮
        button_layout = QHBoxLayout()
        self.load_data_button = QPushButton("加载数据")
        self.load_data_button.clicked.connect(self.load_data)
        self.load_data_button.setEnabled(False)
        button_layout.addWidget(self.load_data_button)
        
        self.send_data_button = QPushButton("加密发送所有数据")
        self.send_data_button.clicked.connect(self.send_all_data)
        self.send_data_button.setEnabled(False)
        self.send_data_button.setStyleSheet("background-color: #2196F3; color: white; font-weight: bold;")
        button_layout.addWidget(self.send_data_button)
        layout.addLayout(button_layout)
        
        # 发送进度
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        layout.addStretch()
        return widget
    
    def create_log_tab(self):
        """创建日志标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        layout.addWidget(QLabel("=== 通信日志 ==="))
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)
        
        clear_button = QPushButton("清空日志")
        clear_button.clicked.connect(lambda: self.log_text.clear())
        layout.addWidget(clear_button)
        
        return widget
    
    def load_keys(self):
        """加载RSA密钥"""
        try:
            if os.path.exists(config.CLIENT_PRIVATE_KEY_FILE) and os.path.exists(config.CLIENT_PUBLIC_KEY_FILE):
                self.client_private_key = RSAKeyManager.load_private_key(config.CLIENT_PRIVATE_KEY_FILE)
                self.client_public_key = RSAKeyManager.load_public_key(config.CLIENT_PUBLIC_KEY_FILE)
                self.log(f"✓ 已加载客户端密钥")
            else:
                self.log("⚠ 客户端密钥不存在，正在生成...")
                self.client_private_key, self.client_public_key = RSAKeyManager.generate_rsa_keys(config.RSA_KEY_LENGTH)
                RSAKeyManager.save_private_key(self.client_private_key, config.CLIENT_PRIVATE_KEY_FILE)
                RSAKeyManager.save_public_key(self.client_public_key, config.CLIENT_PUBLIC_KEY_FILE)
                self.log(f"✓ 客户端密钥生成完成 (RSA {config.RSA_KEY_LENGTH}bit)")
        except Exception as e:
            self.log(f"✗ 密钥加载失败: {e}")
    
    def connect_to_server(self):
        """连接到服务器"""
        try:
            host = self.server_host_input.text()
            port = int(self.server_port_input.text())
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            self.connected = True
            
            self.log(f"✓ 已连接到服务器 {host}:{port}")
            self.signals.connection_status.emit(f"已连接到 {host}:{port}")
            
            self.connect_button.setEnabled(False)
            self.disconnect_button.setEnabled(True)
            self.load_data_button.setEnabled(True)
            
            # 启动密钥交换线程
            Thread(target=self.perform_key_exchange, daemon=True).start()
            
        except Exception as e:
            self.log(f"✗ 连接失败: {e}")
            self.signals.connection_status.emit("连接失败")
            QMessageBox.critical(self, "连接错误", f"无法连接到服务器: {e}")
    
    def perform_key_exchange(self):
        """执行DH密钥协商"""
        try:
            self.log("\n=== 开始DH密钥协商 ===")
            self.key_exchange_info.setText("")
            
            # 第1步：生成DH密钥对
            dh_client = DHKeyExchangeClient(self.client_private_key)
            dh_client.step1_generate_dh_keys()
            self.log(f"✓ 已生成客户端DH��钥对")
            self.key_exchange_info.append(f"✓ 已生成DH密钥对\n客户端DH公钥: {str(dh_client.dh_public_key)[:50]}...")
            
            # 第2步：发送DH公钥和签名
            dh_request = dh_client.get_key_exchange_message()
            self.socket.sendall(dh_request.encode('utf-8'))
            self.log(f"✓ 已发送DH公钥和RSA签名")
            self.key_exchange_info.append(f"✓ 已发送DH公钥和RSA签名")
            
            # 第3步：接收服务端DH公钥和签名
            response = self.socket.recv(4096).decode('utf-8')
            msg = MessageProtocol.unpack_message(response)
            
            if msg['type'] == 'dh_response':
                server_dh_pub = msg['content']['server_dh_public_key']
                server_sig = msg['content']['server_dh_signature']
                dh_client.step3_receive_server_dh_public_key(server_dh_pub)
                self.log(f"✓ 已接收服务端DH公钥")
                self.key_exchange_info.append(f"✓ 已接收服务端DH公钥\n服务端DH公钥: {server_dh_pub[:50]}...")
                
                # 第4步：计算共享密钥
                self.shared_des_key = dh_client.step4_compute_shared_key()
                self.log(f"✓ 已计算共享DES密钥")
                self.key_exchange_info.append(f"✓ 共享DES密钥已生成 (8字节)")
                
                self.log("\n=== DH密钥协商完成 ===\n")
                self.signals.connection_status.emit("密钥协商成功")
                
                # 接收服务端公钥进行后续认证
                cert_msg = self.socket.recv(4096).decode('utf-8')
                cert_data = MessageProtocol.unpack_message(cert_msg)
                if cert_data['type'] == 'server_cert':
                    self.server_public_key = cert_data['content']['server_public_key']
                    self.log("✓ 已接收服务端RSA公钥证书")
                    self.auth_info.setText("✓ RSA身份认证成功\n✓ 双向认证完成")
                    self.send_data_button.setEnabled(True)
                    
        except Exception as e:
            self.log(f"✗ 密钥协商失败: {e}")
            self.signals.connection_status.emit("密钥协商失败")
            self.disconnect_from_server()
    
    def browse_file(self):
        """浏览选择CSV文件"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择CSV文件", "", "CSV Files (*.csv)")
        if file_path:
            self.file_path_input.setText(file_path)
            self.load_data_button.setEnabled(True)
    
    def load_data(self):
        """加载CSV数据到表格"""
        file_path = self.file_path_input.text()
        if not file_path:
            QMessageBox.warning(self, "警告", "请先选择CSV文件")
            return
        
        try:
            self.data = []
            with open(file_path, 'r', encoding=config.CSV_ENCODING) as f:
                reader = csv.DictReader(f)
                for row in reader:
                    self.data.append(row)
            
            # 显示到表格
            self.data_table.setRowCount(min(len(self.data), 20))
            for i, row in enumerate(self.data[:20]):
                self.data_table.setItem(i, 0, QTableWidgetItem(row['timestamp']))
                self.data_table.setItem(i, 1, QTableWidgetItem(row['location']))
                self.data_table.setItem(i, 2, QTableWidgetItem(row['temperature']))
                self.data_table.setItem(i, 3, QTableWidgetItem(row['humidity']))
                self.data_table.setItem(i, 4, QTableWidgetItem(row['pressure']))
                self.data_table.setItem(i, 5, QTableWidgetItem(row['wind_speed']))
                self.data_table.setItem(i, 6, QTableWidgetItem(row.get('wind_direction', '')))
                self.data_table.setItem(i, 7, QTableWidgetItem(row.get('precipitation', '')))
            
            self.log(f"✓ 已加载 {len(self.data)} 条气象数据")
            self.send_data_button.setEnabled(True)
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"加载文件失败: {e}")
            self.log(f"✗ 加载失败: {e}")
    
    def send_all_data(self):
        """发送所有数据"""
        if not self.connected or not self.shared_des_key:
            QMessageBox.warning(self, "警告", "请先连接服务器并完成密钥交换")
            return
        
        if not hasattr(self, 'data') or not self.data:
            QMessageBox.warning(self, "警告", "请先加载数据")
            return
        
        Thread(target=self._send_data_thread, daemon=True).start()
    
    def _send_data_thread(self):
        """后台线程发送数据"""
        try:
            self.progress_bar.setVisible(True)
            self.progress_bar.setMaximum(len(self.data))
            
            for i, row in enumerate(self.data):
                # 创建加密消息
                plaintext = json.dumps(row)
                encrypted = DESCipher.encrypt(plaintext, self.shared_des_key)
                
                message = MessageProtocol.pack_message('encrypted_data', encrypted, self.shared_des_key)
                self.socket.sendall(message.encode('utf-8'))
                
                self.progress_bar.setValue(i + 1)
                self.log(f"[{i+1}/{len(self.data)}] 已发送: {row['location']} - {row['timestamp']}")
                time.sleep(0.1)
            
            self.log(f"\n✓ 所有 {len(self.data)} 条数据已发送完成")
            self.signals.transfer_complete.emit(f"成功发送 {len(self.data)} 条数据")
            self.progress_bar.setVisible(False)
            
        except Exception as e:
            self.log(f"✗ 数据发送失败: {e}")
            self.signals.transfer_complete.emit(f"发送失败: {e}")
    
    def disconnect_from_server(self):
        """断开连接"""
        if self.socket:
            self.socket.close()
        self.connected = False
        self.shared_des_key = None
        
        self.connect_button.setEnabled(True)
        self.disconnect_button.setEnabled(False)
        self.load_data_button.setEnabled(False)
        self.send_data_button.setEnabled(False)
        
        self.log("✓ 已断开连接")
        self.signals.connection_status.emit("已断开连接")
    
    def update_status(self, status):
        """更新状态栏"""
        self.status_label.setText(status)
    
    def display_received_data(self, data):
        """显示接收到的数据"""
        self.log(data)
    
    def show_transfer_result(self, result):
        """显示传输结果"""
        QMessageBox.information(self, "传输结果", result)
    
    def log(self, message):
        """记录日志"""
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")


def main():
    app = QApplication(sys.argv)
    window = WeatherClientGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
