# 气象监测数据加密传输系统

## 📋 项目概述

一个完整的**C/S架构气象数据加密传输系统**，基于Python实现，采用DES、RSA、DH等密码学算法，保障数据的**机密性、完整性和身份认证**。

### 核心功能
- ✅ **DES加密通信** - CBC模式，8字节分组
- ✅ **RSA身份认证** - 1024bit密钥，PSS签名
- ✅ **DH密钥协商** - RFC 3526标准参数，自动生成DES密钥
- ✅ **HMAC完整性校验** - SHA256算法
- ✅ **MySQL数据持久化** - 完整的数据库操作
- ✅ **PyQt5图形界面** - 客户端可视化
- ✅ **双向身份认证** - RSA签名验证
- ✅ **操作审计日志** - 完整的安全日志记录

---

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────────┐
│          气象监测数据加密传输系统                │
├──────────────────┬──────────────────────────────┤
│                  │                              │
│  客户端 (Client) │       服务端 (Server)       │
│  ├─ PyQt5 GUI    │       ├─ Socket Server      │
│  ├─ CSV读取      │       ├─ DES解密            │
│  ├─ DES加密      │       ├─ 数据验证           │
│  ├─ DH协商       │       ├─ MySQL存储          │
│  └─ RSA签名      │       ├─ 审计日志           │
│                  │       └─ 多线程处理         │
└──────────────────┴──────────────────────────────┘

        ↓ DES加密通信 + HMAC校验 ↓
```

---

## 🔐 密码学算法详解

### 1. RSA (1024bit)
- **用途**: 身份认证、密钥交换中的签名
- **参数**: 
  - 模数长度: 1024 bit
  - 公钥指数: 65537
  - 签名方案: PSS (Probabilistic Signature Scheme)
  - 哈希函数: SHA-256

### 2. DH (Diffie-Hellman)
- **用途**: 双方协商共享DES密钥，前向保密
- **参数**:
  - P: RFC 3526 2048-bit 素数
  - G: 生成元 (2)
  - 密钥长度: 128 byte

### 3. DES (分组密码)
- **用途**: 加密所有传输数据
- **参数**:
  - 密钥长度: 8 byte (56 bit)
  - 块大小: 8 byte
  - 模式: CBC (密码分组链接)
  - 填充: PKCS#7

### 4. HMAC-SHA256
- **用途**: 消息完整性验证，防止篡改
- **参数**:
  - 哈希函数: SHA-256
  - 密钥: 共享DES密钥

---

## 📦 项目结构

```
weather-data-encryption/
├─ config.py                    # 配置文件
├─ crypto_utils.py              # 加密工具库
├─ dh_key_exchange.py           # DH密钥协商
├─ database.py                  # MySQL数据库操作
├─ client_gui.py                # 客户端GUI程序
├─ server.py                    # 服务端程序
├─ weather_sample.csv           # 气象数据样本
├─ requirements.txt             # 依赖清单
└─ README.md                    # 本文件
```

---

## 🚀 快速开始

### 1. 环境配置

#### 安装Python依赖
```bash
pip install -r requirements.txt
```

#### 创建MySQL数据库
```bash
mysql -u root -p

# 在MySQL中执行：
CREATE USER 'weather_user'@'localhost' IDENTIFIED BY '123456';
GRANT ALL PRIVILEGES ON weather_db.* TO 'weather_user'@'localhost';
FLUSH PRIVILEGES;
```

#### 修改配置文件 (config.py)
```python
DB_CONFIG = {
    'host': 'localhost',
    'user': 'weather_user',
    'password': '123456',  # ← 修改为您的MySQL密码
    'database': 'weather_db',
    'port': 3306
}
```

### 2. 启动服务端

```bash
python server.py
```

**预期输出：**
```
==================================================
气象监测数据加密传输系统 - 服务端
==================================================
使用RSA 1024bit密钥
密钥交换: DH算法
加密算法: DES (CBC模式)
完整性校验: HMAC-SHA256
==================================================

✓ 数据库连接成功
✓ 数据库表初始化成功
✓ 已加载服务端密钥
✓ 服务端已启动: localhost:9999
```

### 3. 启动客户端

```bash
python client_gui.py
```

**GUI界面包含：**
- 🔗 连接标签页：连接服务器、DH密钥协商、RSA身份认证
- 📊 数据传输标签页：加载CSV、预览数据、加密发送
- 📝 通信日志标签页：实时显示所有通信日志

### 4. 操作流程

#### 步骤1：连接服务器
- 输入服务器地址（默认 localhost）
- 输入端口（默认 9999）
- 点击 **"连接服务器"**

#### 步骤2：密钥交换（自动进行）
- 客户端生成DH密钥对
- 发送DH公钥+RSA签名
- 接收服务端DH公钥+验证
- 计算共享DES密钥
- 完成双向认证

#### 步骤3：加载气象数据
- 点击 **"浏览..."** 选择 `weather_sample.csv`
- 点击 **"加载数据"** 预览30条数据

#### 步骤4：加密发送
- 点击 **"加密发送所有数据"**
- 观察进度条和日志
- 所有数据被DES加密后逐条发送

#### 步骤5：验证数据
- 查询MySQL数据库
- 检查 `weather_data` 表确认数据完整

---

## 🔍 数据库表结构

### weather_data 表（气象数据）
```sql
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
);
```

### operation_logs 表（操作审计）
```sql
CREATE TABLE IF NOT EXISTS operation_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    operation_type VARCHAR(50) NOT NULL,
    operator VARCHAR(50),
    details TEXT,
    status VARCHAR(20),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### key_exchange_logs 表（密钥交换审计）
```sql
CREATE TABLE IF NOT EXISTS key_exchange_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(50),
    server_id VARCHAR(50),
    exchange_time DATETIME,
    method VARCHAR(50),
    status VARCHAR(20),
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

---

## 📊 查询数据库示例

### 查看所有气象数据
```sql
SELECT * FROM weather_db.weather_data LIMIT 10;
```

### 按地点统计
```sql
SELECT location, COUNT(*) as count, 
       AVG(temperature) as avg_temp,
       MAX(humidity) as max_humidity
FROM weather_db.weather_data
GROUP BY location;
```

### 查看密钥交换日志
```sql
SELECT * FROM weather_db.key_exchange_logs ORDER BY created_at DESC;
```

### 查看操作审计
```sql
SELECT * FROM weather_db.operation_logs ORDER BY created_at DESC;
```

---

## 🔒 安全特性分析

### 1. 数据机密性
- ✅ 使用DES加密所有传输数据
- ✅ 密钥通过DH协商，不在网络上传输
- ✅ 支持前向保密（Forward Secrecy）

### 2. 数据完整性
- ✅ HMAC-SHA256验证消息完整性
- ✅ 检测任何传输过程中的篡改

### 3. 身份认证
- ✅ RSA签名验证客户端身份
- ✅ 服务端证书认证
- ✅ 双向认证机制

### 4. 不可否认性
- ✅ 完整的操作审计日志
- ✅ 密钥交换过程记录
- ✅ 数据来源跟踪 (received_from)

---

## 🐛 故障排除

### 问题1：MySQL连接失败
```
✗ 数据库连接失败: Access denied for user 'root'@'localhost'
```
**解决**：检查config.py中的密码是否正确

### 问题2：端口被占用
```
✗ 服务端启动失败: Address already in use
```
**解决**：
```bash
# 查找占用端口的进程
lsof -i :9999
# 杀死进程或修改config.py中的端口
```

### 问题3：CSV读取乱码
```python
# 在client_gui.py中修改编码
CSV_ENCODING = 'gbk'  # 改为'gbk'或其他编码
```

### 问题4：PyQt5安装失败
```bash
# 使用pip源
pip install PyQt5 -i https://pypi.tsinghua.edu.cn/simple
```

---

## 📚 参考资源

- [RSA密钥 - 维基百科](https://en.wikipedia.org/wiki/RSA)
- [Diffie-Hellman密钥交换 - RFC 3526](https://tools.ietf.org/html/rfc3526)
- [DES加密标准 - FIPS 46-3](https://nvlpubs.nist.gov/nistpubs/Legacy/FIPS/nistfips46-3.pdf)
- [HMAC - RFC 2104](https://tools.ietf.org/html/rfc2104)
- [PyCryptodome文档](https://pycryptodome.readthedocs.io/)
- [cryptography库文档](https://cryptography.io/)

---

## 📄 许可证

MIT License

---

## ✨ 项目亮点

1. **完整的密码学实现** - DES、RSA、DH、HMAC全覆盖
2. **双向身份认证** - 客户端和服务端互相验证
3. **企业级审计日志** - 完整的操作和密钥交换记录
4. **生产就绪** - 错误处理、多线程、数据持久化
5. **友好的图形界面** - PyQt5可视化操作
6. **详细的文档** - 安全流程清晰易懂

---

**最后更新**: 2024年1月

**版本**: 1.0.0
