# readme

## **crypto.py**

- **加密**
    - **分离字母和数字**
        
        将消息中的字母部分和数字部分分离处理。
        
    - **字母部分** 使用**DH**协商密钥进行 **AES** 加密。
    - **数字部分** 转换为二进制后，使用 **GM** 加密。
- **解密**
    
    解密加密后的内容，并按照原始顺序重组消息
    
- **签名**

   - **NTRUsign**只了解到基本原理（指只会手算），代码部分中关于扩展欧几里得算法求多项式整数模的逆遇到了点困难，代码是描述给ai后生成的

## server_A.py

1. 配置日志通过 ：`logging` 模块将服务器活动记录到文件 `server_log.txt`
2. 生成服务端的私钥和公钥
3. 创建监听器
4. 接受客户端连接
5. 发送服务器公钥

### TSL第一次握手：服务端签名

- 对问候消息：生成哈希值
- 用私钥对消息哈希值加密
1. 发送服务端问候及其数字签名
2. 接受客户端公钥
3. 验证客户端签名
- 对问候消息生成哈希值
- 用公钥对签名进行解密
- 验证解密信息与原始哈希值是否相等
- 打印已确定客户端身份

### TSL第二次握手：DH密钥协商

1. 生成p，g
2. 发送DH参数
3. 用私钥计算公钥A
4. 发送公钥A
5. 接收公钥B
6. 用私钥和公钥B计算协商密钥

### TSL第三次握手：消息加密

AES+GM

### 验证消息完整性

验证加解密前后hash值是否一致

### connetion closed

## client_B.py

1. 配置日志：通过 `logging` 模块将服务器活动记录到文件 `client_log.txt`
2. 生成客户端的私钥和公钥
3. 连接服务器
4. 发送客户端公钥

### TSL第一次握手：客户端端签名

- 对问候消息生成哈希值
- 用私钥对消息哈希值加密
1. 发送客户端问候及其数字签名
2. 接收服务器公钥
3. 验证服务器签名
- 对问候消息生成哈希值
- 用公钥对签名进行解密
- 验证解密信息与原始哈希值是否相等
- 打印已确定服务器身份

### TSL第二次握手：DH密钥协商

1. 接受DH参数
2. 用私钥计算公钥B
3. 发送公钥B
4. 接收公钥A
5. 用私钥和公钥A计算协商密钥

### TSL第三次握手：消息加密

AES+GM

### 验证消息完整性

验证加解密前后hash值是否一致

### connetion closed
